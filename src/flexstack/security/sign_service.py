from __future__ import annotations
from .sn_sap import SNSIGNRequest, SNSIGNConfirm
from .certificate import OwnCertificate, SECURITY_CODER
from .certificate_library import CertificateLibrary
from .ecdsa_backend import ECDSABackend
from ..utils.time_service import TimeService


class CooperativeAwarenessMessageSecurityHandler:
    """
    Class that handles the signing of CAMs according the standard ETSI TS 103 097 V2.1.1 (2021-10) 7.1.1

    Attributes
    ----------

    """

    def __init__(self, backend: ECDSABackend) -> None:
        self.backend: ECDSABackend = backend
        self.last_signer_full_certificate_time: float = 0
        self.requested_own_certificate: bool = False

    def sign(self, signed_data: dict, certificate: OwnCertificate) -> None:
        """
        Sign the CAM.
        """
        tobesigned: bytes = SECURITY_CODER.encode_to_be_signed_data(
            signed_data["content"][1]["tbsData"]
        )
        # at_item : OwnCertificate = self.get_present_at_for_signging(request.its_aid)

        signed_data["content"][1]["signer"][1] = certificate.as_hashedid8()
        signed_data["content"][1]["signature"] = certificate.sign_message(
            self.backend, tobesigned)

    def set_up_signer(self, certificate: OwnCertificate) -> tuple:
        """
        Set up the signer. According to the standard rules:
        - As default, the choice digest shall be included.
        - The choice certificate shall be included once, one second after the last inclusion of the choice
        certificate.
        - If the ITS-S receives a CAM signed by a previously unknown AT, it shall include the choice
        certificate immediately in its next CAM, instead of including the choice digest. In this case, the
        timer for the next inclusion of the choice certificate shall be restarted.
        - If an ITS-S receives a CAM that includes a tbsdata.headerInfo component of type
        inlineP2pcdRequest, then the ITS-S shall evaluate the list of certificate digests included in that
        component: If the ITS-S finds a certificate digest of the currently used authorization ticket in that list, it
        shall include the choice certificate immediately in its next CAM, instead of including the choice
        digest.
        """
        signer: tuple = ("digest", certificate.as_hashedid8())
        current_time = TimeService.time()
        if (
            current_time - self.last_signer_full_certificate_time > 1
            or self.requested_own_certificate
        ):
            self.last_signer_full_certificate_time = current_time
            signer = ("certificate", certificate.encode())
        return signer


class SignService:
    """
    Sign service class to sign and verify messages. Follows the specification of ETSI TS 102 723-8 V1.1.1 (2016-04) standard.

    Attributes
    ----------
    ecdsa_backend : ECDSABackend
        ECDSA backend to use.
    certificate_library : CertificateLibrary
        Certificate library holding own certificates, known authorization tickets,
        authorization authorities and root certificates used during signing.
    unknown_ats : list[bytes]
        List of unknown ATs. Each AT is represented by its certificate hashedId3.
    requested_ats : list[bytes]
        List of requested ATs. Each AT is represented by its certificate hashedId3.
    """

    def __init__(self, backend: ECDSABackend, certificate_library: CertificateLibrary) -> None:
        """
        Initialize the Sign Service.

        Parameters
        ----------
        backend : ECDSABackend
            ECDSA backend to use for cryptographic operations.
        certificate_library : CertificateLibrary
            Certificate library holding own certificates and trusted chain certificates.
        """
        self.ecdsa_backend: ECDSABackend = backend
        self.certificate_library: CertificateLibrary = certificate_library
        self.unknown_ats: list = []
        self.requested_ats: list = []

    def sign_request(self, request: SNSIGNRequest) -> SNSIGNConfirm:
        """
        Sign a SNSIGNRequest.
        """
        if request.its_aid == 36:
            raise NotImplementedError("CA signing is not implemented")
        elif request.its_aid == 37:
            raise NotImplementedError("DEN signing is not implemented")
        elif request.its_aid == 137:
            raise NotImplementedError(
                "TLM signing is not implemented (SPATEM)")
        elif request.its_aid == 138:
            raise NotImplementedError("RLT signing is not implemented (MAPEM)")
        elif request.its_aid == 139:
            raise NotImplementedError("IVI signing is not implemented (IVIM)")
        elif request.its_aid == 141:
            raise NotImplementedError(
                "GeoNetworking Management Communications (GN-MGMT)  signing is not implemented (SPATEM)"
            )
        elif request.its_aid == 540 or request.its_aid == 801:
            raise NotImplementedError("SA service signing is not implemented")
        elif request.its_aid == 639:
            raise NotImplementedError("CP signing is not implemented")
        elif request.its_aid == 638:
            raise NotImplementedError("VRU signing is not implemented")
        else:
            raise NotImplementedError(
                "Security profile for the specified message not implemented"
            )

    def sign_cam(self, request: SNSIGNRequest) -> SNSIGNConfirm:
        """
        Sign a CAM according the standard ETSI TS 103 097 V2.1.1 (2021-10) 7.1.1
        """
        sigend_data_dict = {
            "protocolVersion": 3,
            "content": (
                "signedData",
                {
                    "hashId": "sha256",
                    "tbsData": {
                        "payload": {
                            "data": {
                                "protocolVersion": 3,
                                "content": ("unsecuredData", request.tbs_message),
                            }
                        },
                        "headerInfo": {
                            "psid": request.its_aid,
                            # "generationTime": 0,
                            # "expireTime": 0
                        },
                    },
                    "signer": ("digest", b"\x00\x00\x00\x00\x00\x00\x00\x00"),
                    "signature": (
                        "ecdsaNistP256Signature",
                        {
                            "rSig": ("fill", None),
                            "sSig": (0xA495991B7852B855).to_bytes(32, byteorder="big"),
                        },
                    ),
                },
            ),
        }
        if len(self.unknown_ats) > 0:
            sigend_data_dict["content"][1]["tbsData"]["headerInfo"][
                "inlineP2pcdRequest"
            ] = self.unknown_ats
        if len(self.requested_ats) > 0:
            sigend_data_dict["content"][1]["tbsData"]["headerInfo"][
                "requestedCertificate"
            ] = self.get_known_at_for_request(self.requested_ats.pop(0))

        tobesigned: bytes = SECURITY_CODER.encode_to_be_signed_data(
            sigend_data_dict["content"][1]["tbsData"]
        )
        at_item: OwnCertificate | None = self.get_present_at_for_signging(
            request.its_aid)
        if at_item is None:
            raise RuntimeError("No present AT for signing CAM")
        sigend_data_dict["content"][1]["signer"] = (
            "digest", at_item.as_hashedid8())
        sigend_data_dict["content"][1]["signature"] = at_item.sign_message(
            self.ecdsa_backend, tobesigned)

        sec_message = SECURITY_CODER.encode_etsi_ts_103097_data_signed(
            sigend_data_dict)
        confirm = SNSIGNConfirm(
            sec_message=sec_message, sec_message_length=len(sec_message)
        )

        return confirm

    def get_present_at_for_signging(self, its_aid: int) -> OwnCertificate | None:
        """
        Get the present AT for a given ITS-AID.

        Parameters
        ----------
        its_aid : int
            ITS AID to look up.

        Returns
        -------
        OwnCertificate | None
            The OwnCertificate that covers the given ITS-AID, or None if not found.
        """
        for cert in self.certificate_library.own_certificates.values():
            if its_aid in cert.get_list_of_its_aid():
                return cert
        return None

    def add_own_certificate(self, cert: OwnCertificate) -> None:
        """
        Add an own certificate to the certificate library.

        Delegates to :meth:`CertificateLibrary.add_own_certificate` so that the
        certificate is available for signing and can be verified against the
        trusted chain stored in the library.

        Parameters
        ----------
        cert : OwnCertificate
            The own certificate to add.
        """
        self.certificate_library.add_own_certificate(cert)

    def get_known_at_for_request(self, hashedid3: bytes) -> dict:
        """
        Get the known AT for a given hashedId3.
        """
        raise NotImplementedError(
            "Getting a known AT from HashedId3 is not implemented yet!"
        )
