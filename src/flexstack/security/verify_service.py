from .sn_sap import ReportVerify, SNVERIFYRequest, SNVERIFYConfirm
from .sign_service import ECDSABackend, SignService
from .certificate import SECURITY_CODER
from .certificate_library import CertificateLibrary


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

    def verify(self, request: SNVERIFYRequest) -> SNVERIFYConfirm:
        """
        Verify the signature of a message
        
        Parameters
        ----------
        request : SNVERIFYRequest
            Request to verify the signature of a message.
        
        Returns
        -------
        SNVERIFYConfirm
            Confirmation of the verification of the signature of a message.
        """
        sec_header_decoded = SECURITY_CODER.decode_etsi_ts_103097_data_signed(
            request.message
        )
        signed_data = sec_header_decoded["content"][1]
        data = SECURITY_CODER.encode_to_be_signed_data(signed_data["tbsData"])
        signer = signed_data["signer"]
        # Determine the message profile early so per-profile signer constraints can be
        # checked before attempting certificate lookup.
        _header_info_early = signed_data["tbsData"].get("headerInfo", {})
        _psid_early: int = _header_info_early.get("psid", 0)
        # §7.1.2: DENMs (psid 37) SHALL use signer choice 'certificate', never 'digest'.
        if _psid_early == 37 and signer[0] != "certificate":
            return SNVERIFYConfirm(
                report=ReportVerify.UNSUPPORTED_SIGNER_IDENTIFIER_TYPE,
                certificate_id=b'',
                its_aid=b'',
                its_aid_length=0,
                permissions=b'',
            )
        authorization_ticket = None
        if signer[0] == "certificate":
            # §5.2: certificate choice constrained to exactly one entry
            if len(signer[1]) != 1:
                return SNVERIFYConfirm(
                    report=ReportVerify.UNSUPPORTED_SIGNER_IDENTIFIER_TYPE,
                    certificate_id=b'',
                    its_aid=b'',
                    its_aid_length=0,
                    permissions=b'',
                )
            authorization_ticket = (
                self.certificate_library.verify_sequence_of_certificates(
                    signer[1], self.backend
                )
            )
            if not authorization_ticket:
                if self.sign_service is not None:
                    cert_dict = signer[1][0]
                    issuer = cert_dict.get("issuer", ("self", None))
                    if issuer[0] in ("sha256AndDigest", "sha384AndDigest") and issuer[1] is not None:
                        self.sign_service.notify_unknown_at(issuer[1])
                return SNVERIFYConfirm(
                    report=ReportVerify.INCONSISTENT_CHAIN,
                    certificate_id=b'',
                    its_aid=b'',
                    its_aid_length=0,
                    permissions=b'',
                )
        elif signer[0] == "digest":
            authorization_ticket = (
                self.certificate_library.get_authorization_ticket_by_hashedid8(
                    signer[1]
                )
            )
            if not authorization_ticket:
                if self.sign_service is not None:
                    self.sign_service.notify_unknown_at(signer[1])
                return SNVERIFYConfirm(
                    report=ReportVerify.SIGNER_CERTIFICATE_NOT_FOUND,
                    certificate_id=b'',
                    its_aid=b'',
                    its_aid_length=0,
                    permissions=b'',
                )
        else:
            raise Exception("Unknown signer type")
        if (
            authorization_ticket is not None and authorization_ticket.certificate is not None
            and authorization_ticket.verify(self.backend)
            and authorization_ticket.is_authorization_ticket()
            and authorization_ticket.certificate["toBeSigned"]["verifyKeyIndicator"][0]
            == "verificationKey"
        ):
            header_info = signed_data["tbsData"].get("headerInfo", {})
            # §5.2: generationTime SHALL always be present
            if "generationTime" not in header_info:
                return SNVERIFYConfirm(
                    report=ReportVerify.INVALID_TIMESTAMP,
                    certificate_id=authorization_ticket.as_hashedid8(),
                    its_aid=b'',
                    its_aid_length=0,
                    permissions=b'',
                )
            # §5.2: p2pcdLearningRequest and missingCrlIdentifier SHALL always be absent
            if "p2pcdLearningRequest" in header_info or "missingCrlIdentifier" in header_info:
                return SNVERIFYConfirm(
                    report=ReportVerify.INCOMPATIBLE_PROTOCOL,
                    certificate_id=authorization_ticket.as_hashedid8(),
                    its_aid=b'',
                    its_aid_length=0,
                    permissions=b'',
                )
            psid: int = header_info.get("psid", 0)
            # §7.1.2: DENM-specific headerInfo constraints
            if psid == 37:
                # generationLocation SHALL be present
                if "generationLocation" not in header_info:
                    return SNVERIFYConfirm(
                        report=ReportVerify.INCOMPATIBLE_PROTOCOL,
                        certificate_id=authorization_ticket.as_hashedid8(),
                        its_aid=b'',
                        its_aid_length=0,
                        permissions=b'',
                    )
                # All other optional headerInfo fields SHALL be absent
                _denm_forbidden = {
                    "expiryTime", "encryptionKey",
                    "inlineP2pcdRequest", "requestedCertificate",
                }
                for _field in _denm_forbidden:
                    if _field in header_info:
                        return SNVERIFYConfirm(
                            report=ReportVerify.INCOMPATIBLE_PROTOCOL,
                            certificate_id=authorization_ticket.as_hashedid8(),
                            its_aid=b'',
                            its_aid_length=0,
                            permissions=b'',
                        )
            its_aid_bytes = psid.to_bytes((psid.bit_length() + 7) // 8 or 1, "big")
            verification_key = authorization_ticket.certificate["toBeSigned"]["verifyKeyIndicator"][
                1
            ]
            verify = self.backend.verify_with_pk(
                data=data,
                signature=signed_data["signature"],
                pk=verification_key,
            )
            if verify:
                plain_message = signed_data["tbsData"]["payload"]["data"]["content"][1]
                if self.sign_service is not None:
                    if "inlineP2pcdRequest" in header_info:
                        self.sign_service.notify_inline_p2pcd_request(
                            header_info["inlineP2pcdRequest"]
                        )
                    if "requestedCertificate" in header_info:
                        self.sign_service.notify_received_ca_certificate(
                            header_info["requestedCertificate"]
                        )
                return SNVERIFYConfirm(
                    report=ReportVerify.SUCCESS,
                    certificate_id=authorization_ticket.as_hashedid8(),
                    its_aid=its_aid_bytes,
                    its_aid_length=len(its_aid_bytes),
                    permissions=b'',
                    plain_message=plain_message,
                )
            else:
                return SNVERIFYConfirm(
                    report=ReportVerify.FALSE_SIGNATURE,
                    certificate_id=authorization_ticket.as_hashedid8(),
                    its_aid=its_aid_bytes,
                    its_aid_length=len(its_aid_bytes),
                    permissions=b'',
                )
        return SNVERIFYConfirm(
            report=ReportVerify.INVALID_CERTIFICATE,
            certificate_id=b'',
            its_aid=b'',
            its_aid_length=0,
            permissions=b'',
        )
