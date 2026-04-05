from __future__ import annotations
from .sn_sap import SNSIGNRequest, SNSIGNConfirm
from .certificate import Certificate, OwnCertificate, SECURITY_CODER
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
            self.requested_own_certificate = False
            signer = ("certificate", [certificate.certificate])
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
        self.cam_handler: CooperativeAwarenessMessageSecurityHandler = CooperativeAwarenessMessageSecurityHandler(backend)

    def sign_request(self, request: SNSIGNRequest) -> SNSIGNConfirm:
        """
        Sign a SNSIGNRequest.

        Routing:
        - its_aid == 36: CAM-related PKI signing — not implemented (CAMs are signed
          directly via sign_cam()).
        - its_aid == 37: DENM — delegates to sign_denm() (§7.1.2).
        - any other its_aid: generic signed message — delegates to sign_other() (§7.1.3).
        """
        if request.its_aid == 36:
            raise NotImplementedError("CA signing is not implemented")
        elif request.its_aid == 37:
            return self.sign_denm(request)
        else:
            return self.sign_other(request)

    def sign_other(self, request: SNSIGNRequest) -> SNSIGNConfirm:
        """
        Sign a message according to ETSI TS 103 097 V2.2.1 §5.2 and §7.1.3.

        §7.1.3 generic profile for signed messages other than CAM and DENM:
        - tbsData.headerInfo SHALL contain psid (set to request.its_aid) and
          generationTime (§5.2).  No other headerInfo fields are added or
          required by this profile.
        - Signer is set to choice 'digest' (hashedId8 of the signing AT).
        """
        signed_data_dict = {
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
                            "generationTime": TimeService.timestamp_its() * 1000,
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
        tobesigned: bytes = SECURITY_CODER.encode_to_be_signed_data(
            signed_data_dict["content"][1]["tbsData"]
        )
        at_item: OwnCertificate | None = self.get_present_at_for_signging(request.its_aid)
        if at_item is None:
            raise RuntimeError("No present AT for signing message")
        signed_data_dict["content"][1]["signer"] = ("digest", at_item.as_hashedid8())
        signed_data_dict["content"][1]["signature"] = at_item.sign_message(
            self.ecdsa_backend, tobesigned
        )
        sec_message = SECURITY_CODER.encode_etsi_ts_103097_data_signed(signed_data_dict)
        return SNSIGNConfirm(
            sec_message=sec_message, sec_message_length=len(sec_message)
        )

    def sign_denm(self, request: SNSIGNRequest) -> SNSIGNConfirm:
        """
        Sign a DENM according to ETSI TS 103 097 V2.2.1 §5.2 and §7.1.2.

        §7.1.2 constraints applied here:
        - signer shall always be choice 'certificate' (never 'digest').
        - tbsData.headerInfo shall contain psid (37), generationTime (§5.2),
          and generationLocation (mandatory).  No other optional fields are
          included (expiryTime, inlineP2pcdRequest, requestedCertificate, etc.
          shall all be absent).
        """
        if request.generation_location is None:
            raise ValueError(
                "sign_denm requires a generation_location (§7.1.2: generationLocation SHALL be present)"
            )
        signed_data_dict = {
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
                            "generationTime": TimeService.timestamp_its() * 1000,
                            "generationLocation": request.generation_location,
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
        tobesigned: bytes = SECURITY_CODER.encode_to_be_signed_data(
            signed_data_dict["content"][1]["tbsData"]
        )
        at_item: OwnCertificate | None = self.get_present_at_for_signging(request.its_aid)
        if at_item is None:
            raise RuntimeError("No present AT for signing DENM")
        # §7.1.2: signer SHALL always be 'certificate'
        signed_data_dict["content"][1]["signer"] = ("certificate", [at_item.certificate])
        signed_data_dict["content"][1]["signature"] = at_item.sign_message(
            self.ecdsa_backend, tobesigned
        )
        sec_message = SECURITY_CODER.encode_etsi_ts_103097_data_signed(signed_data_dict)
        return SNSIGNConfirm(
            sec_message=sec_message, sec_message_length=len(sec_message)
        )

    def sign_cam(self, request: SNSIGNRequest) -> SNSIGNConfirm:
        """
        Sign a CAM according the standard ETSI TS 103 097 V2.2.1 §5.2 and §7.1.1
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
                            "generationTime": TimeService.timestamp_its() * 1000,
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
        sigend_data_dict["content"][1]["signer"] = self.cam_handler.set_up_signer(at_item)
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

    def notify_unknown_at(self, hashedid8: bytes) -> None:
        """
        §7.1.1: An unknown AT cert was seen. Record its HashedId3 for the next
        inlineP2pcdRequest and force own certificate inclusion in the next CAM.
        """
        hashedid3 = hashedid8[-3:]
        if hashedid3 not in self.unknown_ats:
            self.unknown_ats.append(hashedid3)
        self.cam_handler.requested_own_certificate = True

    def notify_inline_p2pcd_request(self, request_list: list) -> None:
        """
        §7.1.1: Process a received inlineP2pcdRequest field.

        - If our own AT's HashedId3 is present, include certificate in next CAM.
        - If a CA cert we hold is requested, schedule it as requestedCertificate.
        """
        for own_cert in self.certificate_library.own_certificates.values():
            own_hashedid3 = own_cert.as_hashedid8()[-3:]
            if own_hashedid3 in request_list:
                self.cam_handler.requested_own_certificate = True
        for hashedid3 in request_list:
            ca_cert = self.certificate_library.get_ca_certificate_by_hashedid3(hashedid3)
            if ca_cert is not None and hashedid3 not in self.requested_ats:
                self.requested_ats.append(hashedid3)

    def notify_received_ca_certificate(self, cert_dict: dict) -> None:
        """
        §7.1.1: A peer sent the CA certificate we requested. Discard the
        pending request and add the certificate to the library.
        """
        cert = Certificate.from_dict(cert_dict)
        hashedid3 = cert.as_hashedid8()[-3:]
        if hashedid3 in self.requested_ats:
            self.requested_ats.remove(hashedid3)
        if hashedid3 in self.unknown_ats:
            self.unknown_ats.remove(hashedid3)
        self.certificate_library.add_authorization_authority(cert)

    def get_known_at_for_request(self, hashedid3: bytes) -> dict:
        """
        §7.1.1: Return the CA certificate dict for the given HashedId3 so it
        can be embedded in the requestedCertificate header field.
        """
        ca_cert = self.certificate_library.get_ca_certificate_by_hashedid3(hashedid3)
        if ca_cert is None:
            raise RuntimeError(
                f"No CA certificate found for HashedId3 {hashedid3.hex()}"
            )
        return ca_cert.certificate
