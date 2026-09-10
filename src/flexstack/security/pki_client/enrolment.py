"""
pki_client/enrolment.py — S3 Enrolment protocol (ITS-S → EA).

Implements the full ITS-S side of ETSI TS 102 941 §6.2.3.2 enrolment,
building and sending an ``EnrolmentRequestMessage`` and decoding the
``EnrolmentResponseMessage`` returned by the EA service.

Wire structure built by :func:`enroll`
--------------------------------------
::

    Ieee1609Dot2Data (encryptedData)              ← ECIES to EA, certRecipInfo
      AesCcmCiphertext
        → Ieee1609Dot2Data (signedData)           ← signed by canonical/prior-EC key
            signer = ("certificate", [signer_cert_dict])
            tbsData.payload.data = ("unsecuredData", EtsiTs102941Data_bytes)
              EtsiTs102941Data
                version  = 1
                content  = ("enrolmentRequest", InnerECRequest)
                  InnerECRequest
                    itsId                    = 8-byte station identifier
                    certificateFormat        = 1  (ts103097v131)
                    publicKeys.verificationKey = Q_new (new EC public key)
                    requestedSubjectAttributes = {validityPeriod, appPermissions, …}

Response structure (pskRecipInfo — AES session key reused)
-----------------------------------------------------------
::

    Ieee1609Dot2Data (encryptedData)              ← pskRecipInfo(HashedId8(A))
      AesCcmCiphertext
        → Ieee1609Dot2Data (signedData)           ← signed by EA key
            tbsData.payload.data = ("unsecuredData", EtsiTs102941Data_bytes)
              EtsiTs102941Data
                content = ("enrolmentResponse", InnerECResponse)
                  InnerECResponse
                    version      = 1
                    responseCode = 0  (ok)
                    certificate  = EtsiTs103097Certificate (the issued EC)

Usage
-----
::

    from flexstack.security.certificate import Certificate, OwnCertificate
    from flexstack.security.ecdsa_backend import PythonECDSABackend
    from flexstack.security.pki_client.crypto import CryptographyECIESBackend  # re-used from pythonpki
    from flexstack.security.pki_client.enrolment import enroll

    ec_own, ec_key_id = await enroll(
        ea_url=\"http://localhost:8080\",
        ea_cert=ea_cert,
        signer_cert=canonical_own_cert,   # OwnCertificate with private key
        backend=ecdsa_backend,
        ecies_backend=ecies_backend,
        its_id=b\"\\x00\" * 8,
    )
"""
from __future__ import annotations

import logging
import os

import httpx

from flexstack.security.certificate import Certificate, OwnCertificate
from flexstack.security.ecdsa_backend import PythonECDSABackend

from flexstack.security.pki_client.crypto import (
    ecies_encrypt,
    psk_decrypt,
    now_time32,
)
from flexstack.security.pki_client.coder import PKI_CODER

log = logging.getLogger(__name__)

# PSID for secured certificate request messages (ITS-AID 623 = 0x26F)
_PSID_CERT_REQUEST: int = 623

# HTTP content-type for ITS PKI messages
_CT_REQUEST: str = "application/x-its-request"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class EnrolmentError(Exception):
    """Raised when the EA rejects the enrolment request or a protocol error occurs."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


async def enroll(
    ea_url: str,
    ea_cert: Certificate,
    signer_cert: OwnCertificate,
    backend: PythonECDSABackend,
    ecies_backend: object,
    its_id: bytes = b"\x00" * 8,
    requested_app_permissions: list[dict] | None = None,
    validity_years: int = 1,
    timeout: float = 30.0,
) -> OwnCertificate:
    """Perform the S3 enrolment protocol and return the issued EC as an OwnCertificate.

    Generates a fresh EC key pair, builds a complete ``EnrolmentRequestMessage``
    (signed by *signer_cert*, ECIES-encrypted to *ea_cert*), POSTs it to the EA,
    and decodes the ``EnrolmentResponseMessage`` to recover the issued
    ``EtsiTs103097Certificate``.

    Parameters
    ----------
    ea_url:
        Base URL of the EA service, e.g. ``"http://localhost:8080"``.
    ea_cert:
        Decoded EA certificate (``Certificate``).  Its ``encryptionKey``
        field is used for ECIES encryption.
    signer_cert:
        ``OwnCertificate`` used to sign the outer enrolment request.
        For initial bootstrap this is a canonical/self-signed cert;
        for renewal it is the previous EC.
    backend:
        ``PythonECDSABackend`` holding *signer_cert*'s private key.
        The newly generated EC key is also registered here.
    ecies_backend:
        ``CryptographyECIESBackend`` instance (from pki_client or pythonpki).
        Not used for encryption here (we use :func:`crypto.ecies_encrypt`
        directly); kept for future decryption use.
    its_id:
        8-byte ITS station identifier sent in ``InnerECRequest.itsId``.
        For initial enrolment use a canonical station ID (e.g. SHA-256 of
        device serial number, truncated to 8 bytes).  For renewal pass
        ``signer_cert.as_hashedid8()``.
    requested_app_permissions:
        List of ``{"psid": int}`` dicts for the requested EC permissions.
        Defaults to ``[{"psid": 623, "ssp": ("opaque", b"\\x01\\xc0")}]``
        (secured certificate request — EnrolmentRequest + AuthorizationRequest).
    validity_years:
        Requested validity period for the EC (years, default 1).
    timeout:
        HTTP request timeout in seconds.

    Returns
    -------
    OwnCertificate
        The issued Enrolment Credential with the new private key registered
        in *backend* under ``OwnCertificate.key_id``.

    Raises
    ------
    EnrolmentError
        If the EA returns a non-ok response code or any protocol step fails.
    httpx.HTTPError
        If the HTTP request itself fails.
    """
    # Default EC permissions: sign EnrolmentRequest + AuthorizationRequest (SSP 0xC0)
    if requested_app_permissions is None:
        requested_app_permissions = [
            {"psid": _PSID_CERT_REQUEST, "ssp": ("opaque", bytes([0x01, 0xC0]))}
        ]

    # ------------------------------------------------------------------
    # Step 1: generate new EC key pair
    # ------------------------------------------------------------------
    ec_key_id: int = backend.create_key()
    new_verify_key: tuple = backend.get_public_key(ec_key_id)
    log.debug("Generated new EC key pair (key_id=%d)", ec_key_id)

    # ------------------------------------------------------------------
    # Step 2: build InnerECRequest
    # ------------------------------------------------------------------
    start_time = now_time32()
    inner_ec_request: dict = {
        "itsId": its_id,
        "certificateFormat": 1,          # ts103097v131
        "publicKeys": {
            "verificationKey": new_verify_key,
        },
        "requestedSubjectAttributes": {
            "validityPeriod": {
                "start": start_time,
                "duration": ("years", validity_years),
            },
            "appPermissions": requested_app_permissions,
        },
    }

    # ------------------------------------------------------------------
    # Step 3-4: wrap InnerECRequest in EtsiTs102941Data, encode payload
    # ------------------------------------------------------------------
    payload_bytes: bytes = PKI_CODER.encode_etsi102941_data(
        "enrolmentRequest", inner_ec_request
    )

    # ------------------------------------------------------------------
    # Step 5: build and sign inner Ieee1609Dot2Data (outer signed layer)
    # signer = ("certificate", [signer_cert.certificate])
    # ------------------------------------------------------------------
    gen_time_us = start_time * 1_000_000   # Time32 → Time64 (µs)

    tbs_data: dict = {
        "payload": {
            "data": {
                "protocolVersion": 3,
                "content": ("unsecuredData", payload_bytes),
            }
        },
        "headerInfo": {
            "psid": _PSID_CERT_REQUEST,
            "generationTime": gen_time_us,
        },
    }

    tbs_bytes: bytes = PKI_CODER.encode_to_be_signed_data(tbs_data)
    signature: tuple = signer_cert.sign_message(backend, tbs_bytes)

    signed_ieee: dict = {
        "protocolVersion": 3,
        "content": (
            "signedData",
            {
                "hashId": "sha256",
                "tbsData": tbs_data,
                "signer": ("certificate", [signer_cert.certificate]),
                "signature": signature,
            },
        ),
    }
    signed_bytes: bytes = PKI_CODER.encode_ieee1609dot2_data(signed_ieee)

    # ------------------------------------------------------------------
    # Step 6: ECIES-encrypt to EA
    # ------------------------------------------------------------------
    ea_enc_key_tuple, ea_cert_coer = _extract_ea_enc_info(ea_cert)
    ecies_key_dict, aes_ccm_dict, session_key_a, session_key_hid8 = ecies_encrypt(
        plaintext=signed_bytes,
        recipient_enc_key_tuple=ea_enc_key_tuple,
        recipient_cert_coer=ea_cert_coer,
    )

    outer_encrypted: dict = {
        "protocolVersion": 3,
        "content": (
            "encryptedData",
            {
                "recipients": [
                    (
                        "certRecipInfo",
                        {
                            "recipientId": ea_cert.as_hashedid8(),
                            "encKey": ("eciesNistP256", ecies_key_dict),
                        },
                    )
                ],
                "ciphertext": ("aes128ccm", aes_ccm_dict),
            },
        ),
    }
    request_bytes: bytes = PKI_CODER.encode_ieee1609dot2_data(outer_encrypted)

    # ------------------------------------------------------------------
    # Step 7: POST to EA
    # ------------------------------------------------------------------
    enrolment_url = f"{ea_url.rstrip('/')}/ea/v1/enrolment"
    log.info("POSTing enrolment request to %s (%d bytes)", enrolment_url, len(request_bytes))

    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(
            enrolment_url,
            content=request_bytes,
            headers={"Content-Type": _CT_REQUEST},
        )

    if resp.status_code != 200:
        raise EnrolmentError(
            "http_error",
            f"EA returned HTTP {resp.status_code}: {resp.text[:200]}",
        )

    # ------------------------------------------------------------------
    # Step 8: decrypt pskRecipInfo response
    # ------------------------------------------------------------------
    inner_signed_bytes = _decrypt_psk_response(resp.content, session_key_a, session_key_hid8)

    # ------------------------------------------------------------------
    # Step 9: decode InnerECResponse
    # ------------------------------------------------------------------
    inner_ec_response = _decode_enrolment_response(inner_signed_bytes)

    response_code = inner_ec_response.get("responseCode")
    if response_code not in (0, "ok"):
        raise EnrolmentError(
            str(response_code),
            f"EA rejected enrolment with responseCode={response_code}",
        )

    # ------------------------------------------------------------------
    # Step 10: reconstruct OwnCertificate from issued EC
    # ------------------------------------------------------------------
    ec_cert_dict: dict = inner_ec_response["certificate"]
    ec_own = OwnCertificate(
        certificate=ec_cert_dict,
        issuer=ea_cert,
        key_id=ec_key_id,
    )
    log.info(
        "Enrolment successful — EC HashedId8: %s",
        ec_own.as_hashedid8().hex(),
    )
    return ec_own


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _extract_ea_enc_info(ea_cert: Certificate) -> tuple[tuple, bytes]:
    """Extract the EA's ECIES public key tuple and COER-encoded certificate.

    Returns
    -------
    (enc_key_tuple, ea_cert_coer):
        enc_key_tuple — value of ``encryptionKey.publicKey`` (ASN.1 decoded tuple).
        ea_cert_coer  — COER encoding of the EA certificate (for KDF2 P1).

    Raises
    ------
    EnrolmentError
        If the EA certificate has no ``encryptionKey``.
    """
    tbs = ea_cert.certificate.get("toBeSigned", {})
    enc_key = tbs.get("encryptionKey")
    if enc_key is None:
        raise EnrolmentError(
            "invalidea",
            "EA certificate has no encryptionKey — cannot perform ECIES encryption",
        )
    enc_key_tuple: tuple = enc_key["publicKey"]
    ea_cert_coer: bytes = ea_cert.encode()
    return enc_key_tuple, ea_cert_coer


def _decrypt_psk_response(
    resp_bytes: bytes,
    session_key_a: bytes,
    session_key_hid8: bytes,
) -> bytes:
    """Decrypt the EA's pskRecipInfo response and return the inner signed bytes.

    Parameters
    ----------
    resp_bytes:
        Raw COER response body from the EA.
    session_key_a:
        The 16-byte AES session key kept from the request.
    session_key_hid8:
        SHA-256(session_key_a)[-8:] — used to locate the pskRecipInfo entry.

    Returns
    -------
    bytes
        Inner ``Ieee1609Dot2Data`` (signed) bytes after AES-CCM decryption.

    Raises
    ------
    EnrolmentError
        If the response is not encrypted or the pskRecipInfo is not found.
    """
    try:
        outer_resp = PKI_CODER.decode_ieee1609dot2_data(resp_bytes)
    except Exception as exc:
        raise EnrolmentError("cantparse", f"Cannot decode EA response: {exc}") from exc

    content_choice, content_value = outer_resp.get("content", ("", {}))
    if content_choice != "encryptedData":
        raise EnrolmentError("badcontenttype", f"Expected encryptedData response, got {content_choice!r}")

    recipients: list = content_value.get("recipients", [])
    aes_ccm_choice, aes_ccm_dict = content_value.get("ciphertext", ("", {}))

    # Locate the pskRecipInfo entry matching our session key
    found = False
    for recip_choice, recip_value in recipients:
        if recip_choice == "pskRecipInfo" and recip_value == session_key_hid8:
            found = True
            break

    if not found:
        # Fallback: accept any pskRecipInfo (EA may use a slightly different HashedId8)
        for recip_choice, _ in recipients:
            if recip_choice == "pskRecipInfo":
                found = True
                break

    if not found:
        raise EnrolmentError(
            "badcontenttype",
            "Response has no pskRecipInfo — cannot decrypt with session key",
        )

    try:
        inner_bytes = psk_decrypt(session_key_a, aes_ccm_dict)
    except Exception as exc:
        raise EnrolmentError("decryptionfailed", f"AES-CCM decryption failed: {exc}") from exc

    return inner_bytes


def _decode_enrolment_response(inner_signed_bytes: bytes) -> dict:
    """Decode the inner signed ``Ieee1609Dot2Data`` and extract ``InnerECResponse``.

    Parameters
    ----------
    inner_signed_bytes:
        Decrypted inner layer bytes (``Ieee1609Dot2Data-Signed``).

    Returns
    -------
    dict
        Decoded ``InnerECResponse`` dict with keys ``version``, ``responseCode``,
        and ``certificate``.

    Raises
    ------
    EnrolmentError
        If any decoding step fails or the content type is unexpected.
    """
    try:
        inner_signed = PKI_CODER.decode_ieee1609dot2_data(inner_signed_bytes)
    except Exception as exc:
        raise EnrolmentError("cantparse", f"Cannot decode inner signed response: {exc}") from exc

    content_choice, inner_data = inner_signed.get("content", ("", {}))
    if content_choice != "signedData":
        raise EnrolmentError("badcontenttype", f"Expected signedData response, got {content_choice!r}")

    tbs_data = inner_data.get("tbsData", {})
    payload_choice, payload_value = tbs_data.get("payload", {}).get(
        "data", {"content": ("", b"")}
    ).get("content", ("", b""))

    if payload_choice != "unsecuredData":
        raise EnrolmentError("badcontenttype", f"Expected unsecuredData payload, got {payload_choice!r}")

    try:
        etsi_data = PKI_CODER.decode_etsi102941_data(payload_value)
    except Exception as exc:
        raise EnrolmentError("cantparse", f"Cannot decode EtsiTs102941Data: {exc}") from exc

    etsi_choice, etsi_value = etsi_data.get("content", ("", {}))
    if etsi_choice != "enrolmentResponse":
        raise EnrolmentError(
            "badcontenttype",
            f"Expected enrolmentResponse content, got {etsi_choice!r}",
        )

    # etsi_value IS the InnerECResponse dict
    return etsi_value
