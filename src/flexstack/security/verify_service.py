from .sn_sap import ReportVerify, SNVERIFYRequest, SNVERIFYConfirm
from .sign_service import ECDSABackend
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
    ):
        """
        Constructor

        """
        self.backend: ECDSABackend = backend
        self.certificate_library: CertificateLibrary = certificate_library

    def verify(self, request: SNVERIFYRequest) -> SNVERIFYConfirm:
        """
        Verify the signature of a message
        """
        sec_header_decoded = SECURITY_CODER.decode_etsi_ts_103097_data_signed(
            request.message
        )
        data = SECURITY_CODER.encode_to_be_signed_data(
            sec_header_decoded["toBeSigned"]
        )
        signer = sec_header_decoded["content"][1]["signer"]
        authorization_ticket = None
        if signer[0] == "certificate":
            authorization_ticket = (
                self.certificate_library.verify_sequence_of_certificates(
                    signer[1], self.backend
                )
            )
            if not authorization_ticket:
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
                return SNVERIFYConfirm(
                    report=ReportVerify.INVALID_CERTIFICATE,
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
            and authorization_ticket.certificate["toBeSigned"]["verifyKeyIndicator"][0]
            == "verificationKey"
        ):
            verification_key = authorization_ticket.certificate["toBeSigned"]["verifyKeyIndicator"][
                1
            ]
            verify = self.backend.verify_with_pk(
                data=data,
                signature=sec_header_decoded["signature"],
                pk=verification_key,
            )
            if verify:
                return SNVERIFYConfirm(
                    report=ReportVerify.SUCCESS,
                    certificate_id=authorization_ticket.as_hashedid8(),
                    its_aid=b'',
                    its_aid_length=0,
                    permissions=b'',
                )
            else:
                return SNVERIFYConfirm(
                    report=ReportVerify.FALSE_SIGNATURE,
                    certificate_id=authorization_ticket.as_hashedid8(),
                    its_aid=b'',
                    its_aid_length=0,
                    permissions=b'',
                )
        return SNVERIFYConfirm(
            report=ReportVerify.INVALID_CERTIFICATE,
            certificate_id=b'',
            its_aid=b'',
            its_aid_length=0,
            permissions=b'',
        )
