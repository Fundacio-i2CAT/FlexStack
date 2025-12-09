from __future__ import annotations
from copy import deepcopy, copy
from hashlib import sha256

from .security_coder import SecurityCoder
from .ecdsa_backend import ECDSABackend


class Certificate:
    """
    Class to handle Certificates as specified in ETSI TS 103 097 V2.1.1 (2021-10) standard.

    Attributes
    ----------

    """

    def __init__(self, coder: SecurityCoder, backend: ECDSABackend):
        """
        Initialize the Certificate.

        Parameters
        ----------
        coder : SecurityCoder
            Security Coder.
        backend : ECDSABackend
            ECDSA Backend.
        """
        self.coder: SecurityCoder = coder
        self.backend: ECDSABackend = backend
        self.verifier: CertificateVerifier = CertificateVerifier(
            coder, backend)
        self.certificate: dict | None = None
        self.issuer: Certificate | None = None
        self.verified: bool = False

    def from_dict(self, certificate: dict, issuer: Certificate | None = None) -> None:
        """
        Sets up the certificate from a dictionary.

        Parameters
        ----------
        certificate : dict
            The certificate to be set up.
        issuer : Certificate
            The issuer of the certificate
        """
        self.certificate = deepcopy(certificate)
        self.verified = self.verify(issuer)

    def decode(self, certificate: bytes, issuer: Certificate | None = None) -> None:
        """
        Decode the certificate and set it up in the Certificate object.

        Parameters
        ----------
        certificate : bytes
            The certificate to be decoded.
        issuer : Certificate | None
            The issuer of the certificate. None if self signed.
        """
        self.from_dict(
            self.coder.decode_etsi_ts_103097_certificate(certificate), issuer
        )

    def as_hashedid8(self) -> bytes:
        """
        Return the certificate as a hashedid8.

        Returns
        -------
        bytes
            The certificate as a hashedid8.
        """
        if self.certificate is None:
            raise ValueError("Certificate not initialized")
        m = sha256()
        m.update(self.coder.encode_etsi_ts_103097_certificate(self.certificate))
        return m.digest()[-8:]

    def encode(self) -> bytes:
        """
        Return the certificate as bytes.

        Returns
        -------
        bytes
            The certificate as bytes.
        """
        if self.certificate is None:
            raise ValueError("Certificate not initialized")
        return self.coder.encode_etsi_ts_103097_certificate(self.certificate)

    def get_list_of_its_aid(self) -> list[int]:
        """
        Return the list of ITS AID.

        Returns
        -------
        list[int]
            The list of ITS AID.
        """
        if self.certificate is None:
            raise ValueError("Certificate not initialized")
        to_return = []
        for psid_ssp in self.certificate["toBeSigned"]["appPermissions"]:
            to_return.append(psid_ssp["psid"])
        return to_return

    def as_clear_certificate(self):
        """
        Generate a White Certificate and set it up to the Certificate object.
        """
        self.certificate = {
            "version": 3,
            "type": "explicit",
            "issuer": (
                "sha256AndDigest",
                (0xA495991B7852B855).to_bytes(8, byteorder="big"),
            ),
            "toBeSigned": {
                "id": ("name", "i2cat.net"),
                "cracaId": (0xA49599).to_bytes(3, byteorder="big"),
                "crlSeries": 0,
                "validityPeriod": {"start": 0, "duration": ("seconds", 30)},
                "appPermissions": [
                    {
                        "psid": 0,
                    }
                ],
                "certIssuePermissions": [
                    {
                        "subjectPermissions": ("all", None),
                        "minChainLength": 1,
                        "chainLengthRange": 0,
                        "eeType": (b"\x00", 1),
                    }
                ],
                "verifyKeyIndicator": (
                    "verificationKey",
                    ("ecdsaNistP256", ("fill", None)),
                ),
            },
            "signature": (
                "ecdsaNistP256Signature",
                {
                    "rSig": ("fill", None),
                    "sSig": (0xA495991B7852B855).to_bytes(32, byteorder="big"),
                },
            ),
        }

    def get_issuer_hashedid8(self) -> bytes | None:
        """
        Returns the issuer HashedId8 stored in the dict.

        Returns
        -------
        bytes
            The issuer HashedId8. Is none if it's self signed

        Raises
        ------
        ValueError
            If the issuer type is unknown or the certificate is not initialized.
        """
        if self.certificate is None:
            raise ValueError("Certificate not initialized")
        if self.certificate["issuer"][0] == "sha256AndDigest":
            return self.certificate["issuer"][1]
        if self.certificate["issuer"][0] == "self":
            return None
        raise ValueError("Unknown issuer type")

    def verify(self, issuer: Certificate | None = None) -> bool:
        """
        Verify the certificate.

        Parameters
        ----------
        issuer : Certificate
            The issuer of the certificate.
        """
        return self.verifier.verify(self, issuer)

    def __str__(self):
        """
        Return the certificate as a string.

        Returns
        -------
        str
            The certificate as a string.
        """
        if self.certificate is None:
            raise ValueError("Certificate not initialized")
        return str(self.certificate["toBeSigned"]["id"][1])


class OwnCertificate(Certificate):
    """
    Class that handles certificates that are generated by the user. And thus it has the private key.

    Attributes
    ----------
    key_id : int
        The key id of the pair of keys used to sign the certificate.
    certificate_issuer : CertificateIssuer
        The certificate issuer.
    """

    def __init__(self, coder: SecurityCoder, backend: ECDSABackend):
        """
        Initialize the OwnCertificate.

        Parameters
        ----------
        coder : SecurityCoder
            Security Coder.
        backend : ECDSABackend
            ECDSA Backend.
        """
        super().__init__(coder, backend)
        self.key_id = self.backend.create_key()
        self.certificate_issuer = CertificateIssuer(coder, backend)
        self.as_clear_certificate()

    def initialize_certificate(
        self, to_be_signed_certificate: dict, issuer: OwnCertificate | None = None
    ) -> None:
        """
        Initializes the certificate.

        Parameters
        ----------
        to_be_signed_certificate : dict
            The to be signed certificate to be initialized.
        issuer : OwnCertificate
            The issuer of the certificate. If None, the certificate will be self signed.
        """
        if self.certificate is None:
            raise ValueError("Certificate not initialized")
        if self.verify_to_be_signed_certificate(to_be_signed_certificate):
            self.certificate["toBeSigned"] = deepcopy(to_be_signed_certificate)
            self.certificate["toBeSigned"]["verifyKeyIndicator"] = (
                "verificationKey",
                self.backend.get_public_key(self.key_id),
            )
            if issuer and issuer.verify(issuer.issuer):
                issuer.issue_certificate(self)
            elif issuer is None:
                self.issue_certificate(self)

    def verify_to_be_signed_certificate(self, to_be_signed_certificate: dict) -> bool:
        """
        Verifies if a to be signed certificate is valid.

        Parameters
        ----------
        to_be_signed_certificate : dict
            The to be signed certificate to be verified.

        Returns
        -------
        bool
            True if the to be signed certificate is valid, False otherwise.
        """
        try:
            self.coder.encode_ToBeSignedCertificate(to_be_signed_certificate)
            return True
        except Exception:
            return False

    def issue_certificate(self, certificate: Certificate) -> None:
        """
        Issue a certificate to the given certificate.

        Parameters
        ----------
        certificate : Certificate
            The certificate to be issued.
        """
        self.certificate_issuer.issue_certificate(certificate, self)

    def sign_message(self, message: bytes) -> tuple:
        """
        Sign a message with the private key.

        Parameters
        ----------
        message : bytes

        Returns
        -------
        dict
            The signature of the message.
        """
        return self.backend.sign(message, self.key_id)


class CertificateVerifier:
    """
    Class that verifies certificates.

    Attributes
    ----------
    coder : SecurityCoder
        Security Coder.
    backend : ECDSABackend
        ECDSA Backend.
    """

    def __init__(self, coder: SecurityCoder, backend: ECDSABackend):
        """
        Initialize the Certificate Verifier.

        Parameters
        ----------
        coder : SecurityCoder
            Security Coder.
        backend : ECDSABackend
            ECDSA Backend.
        """
        self.coder: SecurityCoder = coder
        self.backend: ECDSABackend = backend

    def signature_is_nist_p256(self, certificate: Certificate) -> bool:
        """
        Check if the signature is NISTP256.

        Parameters
        ----------
        certificate : Certificate
            The certificate to check.

        Returns
        -------
        bool
            True if the signature is NISTP256, False otherwise.
        """
        if certificate.certificate is None:
            raise ValueError("Certificate not initialized")
        return certificate.certificate["signature"][0] == "ecdsaNistP256Signature"

    def verification_key_is_nist_p256(self, certificate: Certificate) -> bool:
        """
        Check if the verification key is NISTP256.

        Parameters
        ----------
        certificate : Certificate
            The certificate to check.

        Returns
        -------
        bool
            True if the verification key is NISTP256, False otherwise.
        """
        if certificate.certificate is None:
            raise ValueError("Certificate not initialized")
        return (
            certificate.certificate["toBeSigned"]["verifyKeyIndicator"][0]
            == "verificationKey"
            and certificate.certificate["toBeSigned"]["verifyKeyIndicator"][1][0]
            == "ecdsaNistP256"
        )

    def certificate_is_self_signed(self, certificate: Certificate) -> bool:
        """
        Check if the certificate is self signed.

        Parameters
        ----------
        certificate : Certificate
            The certificate to check.

        Returns
        -------
        bool
            True if the certificate is self signed, False otherwise.
        """
        if certificate.certificate is None:
            raise ValueError("Certificate not initialized")
        return (
            certificate.certificate["issuer"][0] == "self"
            and certificate.certificate["issuer"][1] == "sha256"
        )

    def certificate_is_issued(self, certificate: Certificate) -> bool:
        """
        Check if the certificate is issued.

        Parameters
        ----------
        certificate : Certificate
            The certificate to check.

        Returns
        -------
        bool
            True if the certificate is issued, False otherwise.
        """
        if certificate.certificate is None:
            raise ValueError("Certificate not initialized")
        return (
            certificate.certificate["issuer"][0] == "sha256AndDigest"
            and len(certificate.certificate["issuer"][1]) == 8
        )

    def check_corresponding_issuer(
        self, certificate: Certificate, issuer: Certificate
    ) -> bool:
        """
        Check if the issuer corresponds to the certificate stated issuer.

        Parameters
        ----------
        certificate : Certificate
            The certificate to check.

        Returns
        -------
        bool
            True if the issuer corresponds to the certificate stated issuer, False otherwise
        """
        if certificate.certificate is None:
            raise ValueError("Certificate not initialized")
        return certificate.certificate["issuer"][1] == issuer.as_hashedid8()

    def verify_signature(
        self, to_be_signed_certificate: dict, signature: dict, verification_key: dict
    ) -> bool:
        """
        Verify the signature of a certificate.

        Parameters
        ----------
        to_be_signed_certificate : dict
            The to be signed certificate to be verified.
        signature : dict
            The signature to be verified.
        verification_key : dict
            The verification key to be used.

        Returns
        -------
        bool
            True if the signature is valid, False otherwise.
        """
        try:
            return self.backend.verify_with_pk(
                self.coder.encode_ToBeSignedCertificate(
                    to_be_signed_certificate),
                signature,
                verification_key,
            )
        except Exception:
            return False

    def verify_self_signed_certificate(self, certificate: Certificate) -> bool:
        """
        Verifies a self signed Certificate.

        Parameters
        ----------
        certificate : Certificate
            The certificate to be verified.

        Returns
        -------
        bool
            True if the certificate is valid, False otherwise.
        """
        if certificate.certificate is None:
            raise ValueError("Certificate not initialized")
        if self.certificate_is_self_signed(certificate):
            if self.signature_is_nist_p256(
                certificate
            ) and self.verification_key_is_nist_p256(certificate):
                if self.verify_signature(
                    certificate.certificate["toBeSigned"],
                    certificate.certificate["signature"],
                    certificate.certificate["toBeSigned"]["verifyKeyIndicator"][1],
                ):
                    certificate.verified = True
                    return True
        return False

    def verify_correct_issuing_permissions(
        self, certificate: Certificate, issuer: Certificate
    ) -> bool:
        """
        Verifies if a certificate has the correct issuing permissions.

        Parameters
        ----------
        certificate : Certificate
            The certificate to be verified.
        issuer : Certificate
            The issuer of the certificate.

        Returns
        -------
        bool
            True if the certificate has the correct issuing permissions, False otherwise.
        """
        cert_issuer = CertificateIssuer(self.coder, self.backend)
        return cert_issuer.check_issuer_has_subject_permissions(certificate, issuer)

    def verify_issued_certificate(
        self, certificate: Certificate, issuer: Certificate
    ) -> bool:
        """
        Verifies if a certificate is issued and verified by it's issuer.

        Parameters
        ----------
        certificate : Certificate
            The certificate to be verified.
        issuer : Certificate
            The issuer of the certificate.

        Returns
        -------
        bool
            True if the certificate is valid, False otherwise.
        """
        if (
            self.certificate_is_issued(certificate)
            and self.check_corresponding_issuer(certificate, issuer)
            and self.verify_correct_issuing_permissions(certificate, issuer)
        ):
            if self.signature_is_nist_p256(
                certificate
            ) and self.verification_key_is_nist_p256(certificate):
                if certificate.certificate is None or issuer.certificate is None:
                    raise ValueError("Certificate not initialized")
                if self.verify_signature(
                    certificate.certificate["toBeSigned"],
                    certificate.certificate["signature"],
                    issuer.certificate["toBeSigned"]["verifyKeyIndicator"][1],
                ):
                    certificate.verified = True
                    return True
        return False

    def verify(self, certificate: Certificate, issuer: Certificate | None = None) -> bool:
        """
        Verify the certificate.

        Parameters
        ----------
        certificate : Certificate
            The certificate to be verified.
        issuer : Certificate | None
            The issuer of the certificate. None if self signed.

        Returns
        -------
        bool
            True if the certificate is valid, False otherwise.
        """
        if issuer is not None and self.certificate_is_issued(certificate):
            return self.verify_issued_certificate(certificate, issuer)
        if self.certificate_is_self_signed(certificate):
            return self.verify_self_signed_certificate(certificate)
        return False


class CertificateIssuer:
    """
    Class that issues certificates.
    """

    def __init__(self, coder: SecurityCoder, backend: ECDSABackend):
        """
        Initialize the Certificate Issuer.

        Parameters
        ----------
        coder : SecurityCoder
            Security Coder.
        backend : ECDSABackend
            ECDSA Backend.
        """
        self.coder: SecurityCoder = coder
        self.backend: ECDSABackend = backend

    def certificate_is_self_signed(
        self, certificate: Certificate, issuer: OwnCertificate
    ) -> bool:
        """
        Check if the certificate is self signed.

        Parameters
        ----------
        certificate : Certificate
            The certificate to check.
        issuer : OwnCertificate
            The issuer of the certificate.

        Returns
        -------
        bool
            True if the certificate is self signed, False otherwise.
        """
        return certificate == issuer

    def set_issuer_as_self(self, certificate: Certificate) -> None:
        """
        Set the issuer as self.

        Parameters
        ----------
        certificate : Certificate
            The certificate to be set.
        """
        if certificate.certificate is None:
            raise ValueError("Certificate not initialized")
        certificate.certificate["issuer"] = ("self", "sha256")

    def set_issuer(self, certificate: Certificate, issuer: OwnCertificate) -> None:
        """
        Set the issuer of the certificate.

        Parameters
        ----------
        certificate : Certificate
            The certificate to be set.
        issuer : OwnCertificate
            The issuer of the certificate.
        """
        if certificate.certificate is None:
            raise ValueError("Certificate not initialized")
        certificate.certificate["issuer"] = (
            "sha256AndDigest", issuer.as_hashedid8())

    def check_enough_min_chain_length_for_issuer(self, issuer: OwnCertificate) -> bool:
        """
        Checks if the chain of trust is lengthy enough.

        Parameters
        ----------
        issuer : OwnCertificate
            The issuer of the certificate.

        Returns
        -------
        bool
            True if the chain of trust is lengthy enough, False otherwise.
        """
        if issuer.certificate is None:
            raise ValueError("Certificate not initialized")
        issuer_permissions = issuer.certificate["toBeSigned"]["certIssuePermissions"]
        if not any(
            permission["minChainLength"] < 1 for permission in issuer_permissions
        ):
            return True
        return False
        # for permission in issuer_permissions:
        #     if permission['minChainLength'] < 1:
        #         return False
        # return True

    def get_list_of_psid_from_cert_issue_permissions(
        self, certificate: Certificate
    ) -> list[int]:
        """
        Get the list of PSID from the certificate issue permissions.

        Parameters
        ----------
        certificate : Certificate
            The certificate to get the PSID from.

        Returns
        -------
        list[int]
            The list of PSID.
        """
        if certificate.certificate is None:
            raise ValueError("Certificate not initialized")
        to_return = []
        if self.certificate_wants_cert_issue_permissions(certificate):
            cert_issue_permissions = certificate.certificate["toBeSigned"][
                "certIssuePermissions"
            ]
            for permission in cert_issue_permissions:
                if permission["subjectPermissions"][0] == "explicit":
                    for elem in permission["subjectPermissions"][1]:
                        to_return.append(elem["psid"])
        return to_return

    def get_list_of_psid_from_app_permissions(
        self, certificate: Certificate
    ) -> list[int]:
        """
        Get the list of PSID from the application permissions.

        Parameters
        ----------
        certificate : Certificate
            The certificate to get the PSID from.

        Returns
        -------
        list[int]
            The list of PSID.
        """
        if certificate.certificate is None:
            raise ValueError("Certificate not initialized")
        cert_app_permissions = certificate.certificate["toBeSigned"]["appPermissions"]
        to_return = []
        for elem in cert_app_permissions:
            to_return.append(elem["psid"])
        return to_return

    def get_list_of_needed_permissions(self, certificate: Certificate) -> list[int]:
        """
        Gets the list of needed permissions.

        Parameters
        ----------
        certificate : Certificate
            The certificate to get the needed permissions from.

        Returns
        -------
        list[int]
            The list of needed permissions.
        """
        to_return = self.get_list_of_psid_from_cert_issue_permissions(
            certificate)
        to_return.extend(
            self.get_list_of_psid_from_app_permissions(certificate))
        to_return = list(dict.fromkeys(to_return))
        return to_return

    def get_list_of_allowed_persmissions(self, issuer: Certificate) -> list[int]:
        """
        Gets the list of allowed permissions.

        Parameters
        ----------
        issuer : OwnCertificate
            The issuer of the certificate.

        Returns
        -------
        list[int]
            The list of allowed permissions.
        """
        if issuer.certificate is None:
            raise ValueError("Certificate not initialized")
        to_return = []
        issuer_permissions = []
        if self.certificate_wants_cert_issue_permissions(issuer):
            cert_issue_permissions = issuer.certificate["toBeSigned"][
                "certIssuePermissions"
            ]
            for permission in cert_issue_permissions:
                issuer_permissions = permission["subjectPermissions"]
                if issuer_permissions[0] == "explicit":
                    issuer_permissions = issuer_permissions[1]
                    for elem in issuer_permissions:
                        to_return.append(elem["psid"])
        return to_return

    def check_all_requested_permissions_are_allowed(
        self, certificate_permissions: list[int], issuer_permissions: list[int]
    ) -> bool:
        """
        Check if all the requested permissions are allowed.

        Parameters
        ----------
        certificate_permissions : list[int]
            The requested permissions.
        issuer_permissions : list[int]
            The allowed permissions.

        Returns
        -------
        bool
            True if all the requested permissions are allowed, False otherwise.
        """
        return all(item in issuer_permissions for item in certificate_permissions)

    def certificate_has_all_permissions(self, certificate: Certificate) -> bool:
        """
        Check if the certificate has all permissions.

        Parameters
        ----------
        certificate : Certificate
            The certificate to check.

        Returns
        -------
        bool
            True if the certificate has all permissions, False otherwise.
        """
        if certificate.certificate is None:
            raise ValueError("Certificate not initialized")
        if "certIssuePermissions" in certificate.certificate["toBeSigned"]:
            cert_issue_permissions: list = certificate.certificate["toBeSigned"][
                "certIssuePermissions"
            ]
            for permission in cert_issue_permissions:
                if permission["subjectPermissions"][0] == "all":
                    return True
        return False

    def check_issuer_has_subject_permissions(
        self, certificate: Certificate, issuer: Certificate
    ) -> bool:
        """
        Check if the issuer has the subject permissions.

        Parameters
        ----------
        certificate : Certificate
            The certificate to check.
        issuer : Certificate
            The issuer of the certificate.

        Returns
        -------
        bool
            True if the issuer has the subject permissions, False otherwise.
        """
        if self.certificate_has_all_permissions(issuer):
            return True
        return self.check_all_requested_permissions_are_allowed(
            self.get_list_of_needed_permissions(certificate),
            self.get_list_of_allowed_persmissions(issuer),
        )

    def certificate_wants_cert_issue_permissions(
        self, certificate: Certificate
    ) -> bool:
        """
        Check if the certificate wants certificate issue permissions.

        Parameters
        ----------
        certificate : Certificate
            The certificate to check.

        Returns
        -------
        bool
            True if the certificate wants certificate issue permissions, False otherwise.
        """
        if certificate.certificate is None:
            raise ValueError("Certificate not initialized")
        if "certIssuePermissions" in certificate.certificate["toBeSigned"]:
            return True
        return False

    def set_chain_length_issue_permissions(
        self, certificate: Certificate, issuer: OwnCertificate
    ) -> None:
        """
        Set the chain length issue permissions.

        Parameters
        ----------
        certificate : Certificate
            The certificate to set.
        issuer : OwnCertificate
            The issuer of the certificate.
        """
        if certificate.certificate is None or issuer.certificate is None:
            raise ValueError("Certificate not initialized")
        if self.certificate_wants_cert_issue_permissions(certificate):
            needed_issuing_permissions_capability = (
                self.get_list_of_psid_from_cert_issue_permissions(certificate)
            )
            if self.certificate_has_all_permissions(issuer):
                # Get the "all" permissions
                all_permissions = {}
                for permission in issuer.certificate["toBeSigned"][
                    "certIssuePermissions"
                ]:
                    if permission["subjectPermissions"][0] == "all":
                        all_permissions = permission
                for permission in certificate.certificate["toBeSigned"][
                    "certIssuePermissions"
                ]:
                    permission["minChainLength"] = copy(
                        all_permissions["minChainLength"]
                    )
            else:
                certificate.certificate["toBeSigned"]["certIssuePermissions"] = [
                ]
                for permission in issuer.certificate["toBeSigned"][
                    "certIssuePermissions"
                ]:
                    if permission["subjectPermissions"][0] == "explicit":
                        for elem in permission["subjectPermissions"][1]:
                            if elem["psid"] in needed_issuing_permissions_capability:
                                certificate.certificate["toBeSigned"][
                                    "certIssuePermissions"
                                ].append(deepcopy(permission))
            for permission in certificate.certificate["toBeSigned"][
                "certIssuePermissions"
            ]:
                permission["minChainLength"] -= 1
            for permission in list(
                certificate.certificate["toBeSigned"]["certIssuePermissions"]
            ):
                if permission["minChainLength"] < 1:
                    certificate.certificate["toBeSigned"][
                        "certIssuePermissions"
                    ].remove(permission)

    def sign_certificate(
        self, certificate: Certificate, issuer: OwnCertificate
    ) -> None:
        """
        Sign the certificate.

        Parameters
        ----------
        certificate : Certificate
            The certificate to be signed.
        issuer : OwnCertificate
            The issuer of the certificate.
        """
        if certificate.certificate is None:
            raise ValueError("Certificate not initialized")
        certificate.certificate["signature"] = self.backend.sign(
            self.coder.encode_ToBeSignedCertificate(
                certificate.certificate["toBeSigned"]
            ),
            issuer.key_id,
        )
        certificate.issuer = issuer

    def issue_certificate(
        self, certificate: Certificate, issuer: OwnCertificate
    ) -> None:
        """
        Issue a certificate.

        Parameters
        ----------
        certificate : Certificate
            The certificate to be issued.
        issuer : OwnCertificate
            The issuer of the certificate.
        """
        if self.certificate_is_self_signed(certificate, issuer):
            self.set_issuer_as_self(certificate)
            # Certificate and issuer should be the same object
            self.sign_certificate(certificate, issuer)
        elif self.check_issuer_has_subject_permissions(
            certificate, issuer
        ) and self.check_enough_min_chain_length_for_issuer(issuer):
            self.set_chain_length_issue_permissions(certificate, issuer)
            self.set_issuer(certificate, issuer)
            self.sign_certificate(certificate, issuer)
