"""
pki_client/authorization.py — S2 Authorization protocol (ITS-S → AA).

Implements ETSI TS 102 941 §6.2.3.3. Builds an ``AuthorizationRequestMessage``
(signed with EC key, ECIES-encrypted to AA) and decodes the issued AT from
the ``AuthorizationResponseMessage``.

Wire structure
--------------
::

    Ieee1609Dot2Data (encryptedData)          ← ECIES to AA, certRecipInfo
      AesCcmCiphertext
        → Ieee1609Dot2Data (signedData)       ← signed by EC key
            signer = ("certificate", [ec_cert_dict])
            tbsData.payload = EtsiTs102941Data_bytes
              EtsiTs102941Data
                content = ("authorizationRequest", InnerAtRequest)
                  InnerAtRequest
                    publicKeys.verificationKey  = Q_at (new AT key)
                    hmacKey                     = 32-byte random key
                    sharedAtRequest
                      eaId                      = HashedId8(EA cert)
                      keyTag                    = HMAC-SHA256(hmacKey, COER(PublicKeys))[:16]
                      certificateFormat         = 1
                      requestedSubjectAttributes
                    ecSignature = ("encryptedEcSignature", ECIES(Q_EA, signed_SharedAtReq))

Privacy: the ecSignature is ECIES-encrypted to the EA so the AA cannot
identify the ITS-S (it forwards the encrypted blob to the EA for validation).
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import logging
import os

import httpx

from flexstack.security.certificate import Certificate, OwnCertificate
from flexstack.security.ecdsa_backend import PythonECDSABackend

from flexstack.security.pki_client.crypto import (
    ecies_encrypt,
    psk_decrypt,
    now_time32,
    compute_hmac_key_tag,
)
from flexstack.security.pki_client.coder import PKI_CODER

log = logging.getLogger(__name__)

_PSID_CERT_REQUEST: int = 623
_CT_REQUEST: str = "application/x-its-request"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class AuthorizationError(Exception):
    """Raised when the AA rejects the AT request or a protocol error occurs."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


async def authorize(
    aa_url: str,
    aa_cert: Certificate,
    ea_cert: Certificate,
    ec_own: OwnCertificate,
    backend: PythonECDSABackend,
    requested_app_permissions: list[dict] | None = None,
    validity_hours: int = 504,
    timeout: float = 30.0,
) -> OwnCertificate:
    """Perform the S2 authorization protocol and return the issued AT.

    Parameters
    ----------
    aa_url:
        Base URL of the AA service, e.g. ``"http://localhost:8081"``.
    aa_cert:
        Decoded AA certificate. Its ``encryptionKey`` is used for ECIES.
    ea_cert:
        Decoded EA certificate. Its ``encryptionKey`` is used to encrypt
        the ``ecSignature`` (privacy: AA cannot see the EC identity).
    ec_own:
        ``OwnCertificate`` for the Enrolment Credential (from :func:`enroll`).
        Used to sign the authorization request and build ``ecSignature``.
    backend:
        ``PythonECDSABackend`` holding *ec_own*'s private key.
        The new AT key pair is also registered here.
    requested_app_permissions:
        List of ``{"psid": int, ...}`` dicts for the AT permissions.
        Defaults to CAM (36) + DENM (37).
    validity_hours:
        Requested AT validity in hours (default 504 = 3 weeks).
    timeout:
        HTTP timeout in seconds.

    Returns
    -------
    OwnCertificate
        The issued Authorization Ticket with the AT private key registered
        in *backend* under ``OwnCertificate.key_id``.
    """
    if requested_app_permissions is None:
        requested_app_permissions = [{"psid": 36}, {"psid": 37}]

    # ------------------------------------------------------------------
    # 1. Generate new AT key pair
    # ------------------------------------------------------------------
    at_key_id: int = backend.create_key()
    at_verify_key: tuple = backend.get_public_key(at_key_id)
    log.debug("Generated AT key pair (key_id=%d)", at_key_id)

    # ------------------------------------------------------------------
    # 2. Generate hmacKey and compute keyTag over PublicKeys COER
    # ------------------------------------------------------------------
    hmac_key: bytes = os.urandom(32)
    public_keys_dict: dict = {"verificationKey": at_verify_key}
    public_keys_coer: bytes = PKI_CODER.encode_public_keys(public_keys_dict)
    key_tag: bytes = compute_hmac_key_tag(hmac_key, public_keys_coer)

    # ------------------------------------------------------------------
    # 3. Build SharedAtRequest
    # ------------------------------------------------------------------
    start_time = now_time32()
    gen_time_us = start_time * 1_000_000

    shared_at_request: dict = {
        "eaId": ea_cert.as_hashedid8(),
        "keyTag": key_tag,
        "certificateFormat": 1,
        "requestedSubjectAttributes": {
            "validityPeriod": {
                "start": start_time,
                "duration": ("hours", validity_hours),
            },
            "appPermissions": requested_app_permissions,
        },
    }

    # ------------------------------------------------------------------
    # 4. Build ecSignature (privacy: EC sig on SharedAtRequest, encrypted to EA)
    # ------------------------------------------------------------------
    ec_signature_field = _build_ec_signature(
        shared_at_request=shared_at_request,
        ec_own=ec_own,
        ea_cert=ea_cert,
        backend=backend,
        gen_time_us=gen_time_us,
    )

    # ------------------------------------------------------------------
    # 5. Build InnerAtRequest
    # ------------------------------------------------------------------
    inner_at_request: dict = {
        "publicKeys": public_keys_dict,
        "hmacKey": hmac_key,
        "sharedAtRequest": shared_at_request,
        "ecSignature": ec_signature_field,
    }

    # ------------------------------------------------------------------
    # 6. Wrap in EtsiTs102941Data, sign with EC key, ECIES-encrypt to AA
    # ------------------------------------------------------------------
    payload_bytes: bytes = PKI_CODER.encode_etsi102941_data(
        "authorizationRequest", inner_at_request
    )

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
    ec_outer_sig: tuple = ec_own.sign_message(backend, tbs_bytes)

    signed_ieee: dict = {
        "protocolVersion": 3,
        "content": (
            "signedData",
            {
                "hashId": "sha256",
                "tbsData": tbs_data,
                "signer": ("certificate", [ec_own.certificate]),
                "signature": ec_outer_sig,
            },
        ),
    }
    signed_bytes: bytes = PKI_CODER.encode_ieee1609dot2_data(signed_ieee)

    # ECIES-encrypt to AA
    aa_enc_key_tuple, aa_cert_coer = _extract_enc_info(aa_cert, "AA")
    ecies_key, aes_ccm, session_key_a, session_key_hid8 = ecies_encrypt(
        plaintext=signed_bytes,
        recipient_enc_key_tuple=aa_enc_key_tuple,
        recipient_cert_coer=aa_cert_coer,
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
                            "recipientId": aa_cert.as_hashedid8(),
                            "encKey": ("eciesNistP256", ecies_key),
                        },
                    )
                ],
                "ciphertext": ("aes128ccm", aes_ccm),
            },
        ),
    }
    request_bytes: bytes = PKI_CODER.encode_ieee1609dot2_data(outer_encrypted)

    # ------------------------------------------------------------------
    # 7. POST to AA
    # ------------------------------------------------------------------
    auth_url = f"{aa_url.rstrip('/')}/aa/v1/authorization"
    log.info("POSTing authorization request to %s (%d bytes)", auth_url, len(request_bytes))

    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(
            auth_url,
            content=request_bytes,
            headers={"Content-Type": _CT_REQUEST},
        )

    if resp.status_code != 200:
        raise AuthorizationError(
            "http_error",
            f"AA returned HTTP {resp.status_code}: {resp.text[:200]}",
        )

    # ------------------------------------------------------------------
    # 8. Decrypt pskRecipInfo response
    # ------------------------------------------------------------------
    inner_signed_bytes = _decrypt_psk_response(resp.content, session_key_a, session_key_hid8)

    # ------------------------------------------------------------------
    # 9. Decode InnerAtResponse
    # ------------------------------------------------------------------
    inner_at_response = _decode_authorization_response(inner_signed_bytes)

    response_code = inner_at_response.get("responseCode")
    if response_code not in (0, "ok"):
        raise AuthorizationError(
            str(response_code),
            f"AA rejected authorization with responseCode={response_code}",
        )

    # ------------------------------------------------------------------
    # 10. Reconstruct AT as OwnCertificate
    # ------------------------------------------------------------------
    at_cert_dict: dict = inner_at_response["certificate"]
    at_own = OwnCertificate(
        certificate=at_cert_dict,
        issuer=aa_cert,
        key_id=at_key_id,
    )
    log.info("Authorization successful — AT HashedId8: %s", at_own.as_hashedid8().hex())
    return at_own


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _extract_enc_info(cert: Certificate, role: str) -> tuple[tuple, bytes]:
    """Extract ECIES encryption public key and COER bytes from a certificate."""
    tbs = cert.certificate.get("toBeSigned", {})
    enc_key = tbs.get("encryptionKey")
    if enc_key is None:
        raise AuthorizationError(
            "invalidcert",
            f"{role} certificate has no encryptionKey — cannot ECIES-encrypt",
        )
    return enc_key["publicKey"], cert.encode()


def _build_ec_signature(
    shared_at_request: dict,
    ec_own: OwnCertificate,
    ea_cert: Certificate,
    backend: PythonECDSABackend,
    gen_time_us: int,
) -> tuple:
    """Build the privacy-preserving ecSignature field for InnerAtRequest.

    Per TS 102 941 §6.2.3.3 and §13.2:
      1. Sign the COER(SharedAtRequest) with the EC private key.
      2. Wrap the signature in a signed Ieee1609Dot2Data (signer = EC digest).
      3. ECIES-encrypt the signed blob to the EA's encryption key.
      4. Return as ``("encryptedEcSignature", encrypted_ieee1609_dict)``.

    This ensures the AA cannot identify the ITS-S (only the EA can decrypt).
    """
    # Step 1: encode SharedAtRequest and sign it
    shared_at_coer: bytes = PKI_CODER.encode_shared_at_request(shared_at_request)

    tbs_ec_sig: dict = {
        "payload": {
            "data": {
                "protocolVersion": 3,
                "content": ("unsecuredData", shared_at_coer),
            }
        },
        "headerInfo": {
            "psid": _PSID_CERT_REQUEST,
            "generationTime": gen_time_us,
        },
    }
    tbs_ec_sig_bytes: bytes = PKI_CODER.encode_to_be_signed_data(tbs_ec_sig)
    ec_inner_sig: tuple = ec_own.sign_message(backend, tbs_ec_sig_bytes)

    # Step 2: wrap in signed Ieee1609Dot2Data (signer = digest of EC cert)
    ec_sig_signed: dict = {
        "protocolVersion": 3,
        "content": (
            "signedData",
            {
                "hashId": "sha256",
                "tbsData": tbs_ec_sig,
                "signer": ("digest", ec_own.as_hashedid8()),
                "signature": ec_inner_sig,
            },
        ),
    }
    ec_sig_signed_bytes: bytes = PKI_CODER.encode_ieee1609dot2_data(ec_sig_signed)

    # Step 3: ECIES-encrypt signed blob to EA
    ea_enc_key, ea_cert_coer = _extract_enc_info(ea_cert, "EA")
    ecies_key, aes_ccm, _, _ = ecies_encrypt(
        plaintext=ec_sig_signed_bytes,
        recipient_enc_key_tuple=ea_enc_key,
        recipient_cert_coer=ea_cert_coer,
    )

    encrypted_ec_sig: dict = {
        "protocolVersion": 3,
        "content": (
            "encryptedData",
            {
                "recipients": [
                    (
                        "certRecipInfo",
                        {
                            "recipientId": ea_cert.as_hashedid8(),
                            "encKey": ("eciesNistP256", ecies_key),
                        },
                    )
                ],
                "ciphertext": ("aes128ccm", aes_ccm),
            },
        ),
    }
    return ("encryptedEcSignature", encrypted_ec_sig)


def _decrypt_psk_response(
    resp_bytes: bytes,
    session_key_a: bytes,
    session_key_hid8: bytes,
) -> bytes:
    """Decrypt the AA's pskRecipInfo response; return inner signed bytes."""
    try:
        outer_resp = PKI_CODER.decode_ieee1609dot2_data(resp_bytes)
    except Exception as exc:
        raise AuthorizationError("cantparse", f"Cannot decode AA response: {exc}") from exc

    content_choice, content_value = outer_resp.get("content", ("", {}))
    if content_choice != "encryptedData":
        raise AuthorizationError(
            "badcontenttype",
            f"Expected encryptedData response, got {content_choice!r}",
        )

    _, aes_ccm_dict = content_value.get("ciphertext", ("", {}))

    try:
        return psk_decrypt(session_key_a, aes_ccm_dict)
    except Exception as exc:
        raise AuthorizationError("decryptionfailed", f"AES-CCM decryption failed: {exc}") from exc


def _decode_authorization_response(inner_signed_bytes: bytes) -> dict:
    """Decode the inner signed layer and return the ``InnerAtResponse`` dict."""
    try:
        inner_signed = PKI_CODER.decode_ieee1609dot2_data(inner_signed_bytes)
    except Exception as exc:
        raise AuthorizationError("cantparse", f"Cannot decode inner signed response: {exc}") from exc

    content_choice, inner_data = inner_signed.get("content", ("", {}))
    if content_choice != "signedData":
        raise AuthorizationError(
            "badcontenttype",
            f"Expected signedData response, got {content_choice!r}",
        )

    tbs_data = inner_data.get("tbsData", {})
    _, payload_data = tbs_data.get("payload", {}).get(
        "data", {"content": ("", b"")}
    ).get("content", ("", b""))

    try:
        etsi_data = PKI_CODER.decode_etsi102941_data(payload_data)
    except Exception as exc:
        raise AuthorizationError("cantparse", f"Cannot decode EtsiTs102941Data: {exc}") from exc

    etsi_choice, etsi_value = etsi_data.get("content", ("", {}))
    if etsi_choice != "authorizationResponse":
        raise AuthorizationError(
            "badcontenttype",
            f"Expected authorizationResponse, got {etsi_choice!r}",
        )
    return etsi_value
