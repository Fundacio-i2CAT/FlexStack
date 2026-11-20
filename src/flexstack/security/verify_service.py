"""
Verification of received secured messages (ETSI TS 103 097 V2.2.1 (2026-03),
clauses 5 and 7; IEEE Std 1609.2-2016, clauses 5.2.3.2.2 and 5.3.1).

Checks, in order (the first failing one gives the report):

1. decodable EtsiTs103097Data-Signed with protocolVersion 3 (clause 5.1);
2. signer identifier: certificate (exactly one) or digest; DENMs always use
   a certificate (clause 7.1.2);
3. the signer certificate is a known, valid authorization ticket;
4. headerInfo: generationTime present, p2pcdLearningRequest and
   missingCrlIdentifier absent (clause 5.2); CAM (clause 7.1.1) and DENM
   (clause 7.1.2) profiles;
5. the PSID is in the appPermissions of the AT (the SSP is returned);
6. the generationTime lies in the validity period of the AT chain;
7. the generationLocation, when present, lies in the region of the AT chain;
8. the signature, over Hash(Hash(tbsData) || Hash(AT)) (1609.2 clause 5.3.1),
   with an algorithm matching the verification key.

Mirrors ``rustflexstack::security::verify_service``.
"""

from __future__ import annotations
from typing import Callable

from .sn_sap import ReportVerify, SNVERIFYRequest, SNVERIFYConfirm
from .sign_service import ECDSABackend, SignService
from .certificate import SECURITY_CODER, Certificate, signing_input
from .certificate_library import CertificateLibrary
from .ecdsa_backend import hash_for_key
from .header_extensions import decode_requests
from .validity import app_permission, location_permitted, valid_at

PSID_CAM = 36
PSID_DENM = 37
PROTOCOL_VERSION = 3
# Clause 7.1.1: headerInfo fields a CAM shall not contain (besides those of clause 5.2).
_CAM_FORBIDDEN = ("generationLocation", "expiryTime", "encryptionKey")
# Clause 7.1.2: headerInfo fields a DENM shall not contain.
_DENM_FORBIDDEN = ("expiryTime", "encryptionKey", "inlineP2pcdRequest", "requestedCertificate")


def _psid_bytes(psid: int) -> bytes:
    return psid.to_bytes((psid.bit_length() + 7) // 8 or 1, "big")


def _confirm(report: ReportVerify, certificate: Certificate | None = None, psid: int | None = None,
             permissions: bytes = b"", plain_message: bytes = b"") -> SNVERIFYConfirm:
    its_aid = _psid_bytes(psid) if psid is not None else b""
    return SNVERIFYConfirm(
        report=report,
        certificate_id=certificate.as_hashedid8() if certificate is not None else b"",
        its_aid=its_aid,
        its_aid_length=len(its_aid),
        permissions=permissions,
        plain_message=plain_message,
    )


class VerifyService:
    """
    Class to verify the signature of a message
    """

    def __init__(
        self,
        backend: ECDSABackend,
        certificate_library: CertificateLibrary,
        sign_service: SignService | None = None,
    ):
        """
        Constructor

        Parameters
        ----------
        backend : ECDSABackend
            ECDSA backend to use for the verification of the signature.
        certificate_library : CertificateLibrary
            Certificate library to use for the verification of the signature.
        sign_service : SignService | None, optional
            Sign service to notify about P2PCD events (unknown certs, requests).
        """
        self.backend: ECDSABackend = backend
        self.certificate_library: CertificateLibrary = certificate_library
        self.sign_service: SignService | None = sign_service
        # Receiver of the P2P CRL / CTL requests of a verified message (ETSI TS 103
        # 601 V2.1.1 clause 5.3): called with the requests and the signing AT.
        self.trust_list_listener: Callable[[list[tuple[int, dict]], Certificate], None] | None = None

    def verify(self, request: SNVERIFYRequest) -> SNVERIFYConfirm:  # pylint: disable=too-many-return-statements,too-many-branches,too-many-locals
        """
        Verify a received secured message.

        Parameters
        ----------
        request : SNVERIFYRequest
            Request to verify the signature of a message.

        Returns
        -------
        SNVERIFYConfirm
            Report, signer certificate id, ITS-AID, SSP of the signer for that
            ITS-AID and, on success, the plain message.
        """
        # 1. Decoding and protocol version (clause 5.1)
        try:
            message = SECURITY_CODER.decode_etsi_ts_103097_data_signed(request.message)
            signed_data = message["content"][1]
            tbs_bytes = SECURITY_CODER.encode_to_be_signed_data(signed_data["tbsData"])
        except Exception:  # pylint: disable=broad-except
            return _confirm(ReportVerify.INCOMPATIBLE_PROTOCOL)
        inner = signed_data["tbsData"].get("payload", {}).get("data", {})
        if message.get("protocolVersion") != PROTOCOL_VERSION or (
                inner and inner.get("protocolVersion") != PROTOCOL_VERSION):
            return _confirm(ReportVerify.INCOMPATIBLE_PROTOCOL)
        header_info = signed_data["tbsData"].get("headerInfo", {})
        psid: int = header_info.get("psid", 0)
        signer = signed_data["signer"]
        # P2PCD response (IEEE 1609.2 clause 8.2.4, TS 103 097 clause 7.1.1): a
        # requested CA certificate is learned when it verifies under a known
        # issuer, before the chain of this message is checked (the answering
        # CAM may be signed by an AT of that CA).
        if "requestedCertificate" in header_info:
            self.certificate_library.learn_ca_certificate(header_info["requestedCertificate"])

        # 2-3. Signer identifier and authorization ticket
        if psid == PSID_DENM and signer[0] != "certificate":
            return _confirm(ReportVerify.UNSUPPORTED_SIGNER_IDENTIFIER_TYPE, psid=psid)
        if signer[0] == "certificate":
            if len(signer[1]) != 1:      # clause 5.2: exactly one certificate
                return _confirm(ReportVerify.UNSUPPORTED_SIGNER_IDENTIFIER_TYPE, psid=psid)
            at = self.certificate_library.verify_sequence_of_certificates(signer[1], self.backend)
            if not at:
                if self.sign_service is not None:
                    issuer = signer[1][0].get("issuer", ("self", None))
                    if issuer[0] in ("sha256AndDigest", "sha384AndDigest") and issuer[1] is not None:
                        self.sign_service.notify_unknown_at(issuer[1])
                return _confirm(ReportVerify.INCONSISTENT_CHAIN, psid=psid)
        elif signer[0] == "digest":
            at = self.certificate_library.get_authorization_ticket_by_hashedid8(signer[1])
            if not at:
                if self.sign_service is not None:
                    self.sign_service.notify_unknown_at(signer[1])
                return _confirm(ReportVerify.SIGNER_CERTIFICATE_NOT_FOUND, psid=psid)
        else:                            # 'self' is not allowed (clause 5.2)
            return _confirm(ReportVerify.UNSUPPORTED_SIGNER_IDENTIFIER_TYPE, psid=psid)
        # Verification key: explicit, or reconstructed from an implicit AT
        # (IEEE 1609.2 clause 5.3.2)
        key = at.verification_key() if at.certificate else None
        if key is None or not at.verify(self.backend) or not at.is_authorization_ticket():
            return _confirm(ReportVerify.INVALID_CERTIFICATE, psid=psid)

        # 4. headerInfo (clauses 5.2, 7.1.1, 7.1.2)
        if "generationTime" not in header_info:
            return _confirm(ReportVerify.INVALID_TIMESTAMP, at, psid)
        if "p2pcdLearningRequest" in header_info or "missingCrlIdentifier" in header_info:
            return _confirm(ReportVerify.INCOMPATIBLE_PROTOCOL, at, psid)
        if psid == PSID_CAM and any(f in header_info for f in _CAM_FORBIDDEN):
            return _confirm(ReportVerify.INCOMPATIBLE_PROTOCOL, at, psid)
        if psid == PSID_DENM and ("generationLocation" not in header_info
                                  or any(f in header_info for f in _DENM_FORBIDDEN)):
            return _confirm(ReportVerify.INCOMPATIBLE_PROTOCOL, at, psid)

        # 5. PSID permitted by the AT (IEEE 1609.2 clause 5.2.3.2.2)
        permitted, ssp = app_permission(at.certificate["toBeSigned"], psid)
        if not permitted:
            return _confirm(ReportVerify.INVALID_CERTIFICATE, at, psid)

        # 6-7. Time and region consistency with the certificate chain
        if not valid_at(at, header_info["generationTime"]):
            return _confirm(ReportVerify.INVALID_TIMESTAMP, at, psid)
        location = header_info.get("generationLocation")
        if location is not None and not location_permitted(
                at, location["latitude"], location["longitude"]):
            return _confirm(ReportVerify.INVALID_MOBILITY_DATA, at, psid)

        # 8. Signature over Hash(Hash(tbsData) || Hash(AT)) (IEEE 1609.2 clause 5.3.1)
        payload = signing_input(tbs_bytes, at.to_canonical().encode(), hash_for_key(key))
        if not self.backend.verify_with_pk(data=payload, signature=signed_data["signature"], pk=key):
            return _confirm(ReportVerify.FALSE_SIGNATURE, at, psid)

        if self.sign_service is not None:
            # An AT received as certificate signer is now known: it is no
            # longer requested in inlineP2pcdRequest (clause 7.1.1).
            if signer[0] == "certificate":
                self.sign_service.notify_known_at(at.as_hashedid8())
            if "inlineP2pcdRequest" in header_info:
                self.sign_service.notify_inline_p2pcd_request(header_info["inlineP2pcdRequest"])
            if "requestedCertificate" in header_info:
                self.sign_service.notify_received_ca_certificate(header_info["requestedCertificate"])
        listener = self.trust_list_listener
        if listener is not None and "contributedExtensions" in header_info:
            requests = decode_requests(header_info["contributedExtensions"])
            if requests:
                listener(requests, at)
        return _confirm(ReportVerify.SUCCESS, at, psid, ssp or b"", inner["content"][1])
