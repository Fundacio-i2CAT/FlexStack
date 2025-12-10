from __future__ import annotations
from copy import deepcopy, copy
from dataclasses import dataclass, field
from hashlib import sha256

from .security_coder import SecurityCoder
from .ecdsa_backend import ECDSABackend

SECURITY_CODER = SecurityCoder()


@dataclass(frozen=True)
class Certificate:
    certificate: dict = field(default_factory=dict)
    issuer: Certificate | None = None

    @staticmethod
    def from_dict(certificate: dict, issuer: Certificate | None = None) -> Certificate:
        """
        Sets up the certificate from a dictionary.

        Parameters
        ----------
        certificate : dict
            The certificate to be set up.
        issuer : Certificate
            The issuer of the certificate
        """
        return Certificate(certificate=deepcopy(certificate), issuer=issuer if issuer else None)

    def decode(self, certificate: bytes, issuer: Certificate | None = None) -> Certificate:
        """
        Decode the certificate and set it up in the Certificate object.

        Parameters
        ----------
        certificate : bytes
            The certificate to be decoded.
        issuer : Certificate | None
            The issuer of the certificate. None if self signed.
        """
        cert_dict = SECURITY_CODER.decode_etsi_ts_103097_certificate(
            certificate)
        return Certificate.from_dict(cert_dict, issuer)

    def as_hashedid8(self) -> bytes:
        """
        Return the certificate as a hashedid8.

        Returns
        -------
        bytes
            The certificate as a hashedid8.
        """
        m = sha256()
        m.update(SECURITY_CODER.encode_etsi_ts_103097_certificate(self.certificate))
        return m.digest()[-8:]

    def encode(self) -> bytes:
        """
        Return the certificate as bytes.

        Returns
        -------
        bytes
            The certificate as bytes.
        """
        return SECURITY_CODER.encode_etsi_ts_103097_certificate(self.certificate)

    def get_list_of_its_aid(self) -> tuple[int]:
        """
        Return the list of ITS AID.

        Returns
        -------
        tuple[int]
            The list of ITS AID.
        """
        to_return = []
        for psid_ssp in self.certificate["toBeSigned"]["appPermissions"]:
            to_return.append(psid_ssp["psid"])
        return tuple(to_return)

    @staticmethod
    def as_clear_certificate() -> Certificate:
        """
        Generate a White Certificate and set it up to the Certificate object.
        """
        certificate = {
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
        return Certificate.from_dict(certificate)

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
        if self.certificate["issuer"][0] == "sha256AndDigest":
            return self.certificate["issuer"][1]
        if self.certificate["issuer"][0] == "self":
            return None
        raise ValueError("Unknown issuer type")

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

    def signature_is_nist_p256(self) -> bool:
        """
        Check if the signature is NISTP256.

        Returns
        -------
        bool
            True if the signature is NISTP256, False otherwise.
        """
        return self.certificate["signature"][0] == "ecdsaNistP256Signature"

    def verification_key_is_nist_p256(self) -> bool:
        """
        Check if the verification key is NISTP256.

        Returns
        -------
        bool
            True if the verification key is NISTP256, False otherwise.
        """
        return (
            self.certificate["toBeSigned"]["verifyKeyIndicator"][0]
            == "verificationKey"
            and self.certificate["toBeSigned"]["verifyKeyIndicator"][1][0]
            == "ecdsaNistP256"
        )

    def certificate_is_self_signed(self) -> bool:
        """
        Check if the certificate is self signed.

        Returns
        -------
        bool
            True if the certificate is self signed, False otherwise.
        """
        return (
            self.certificate["issuer"][0] == "self"
            and self.certificate["issuer"][1] == "sha256"
        )

    def certificate_is_issued(self) -> bool:
        """
        Check if the certificate is issued.

        Returns
        -------
        bool
            True if the certificate is issued, False otherwise.
        """
        return (
            self.certificate["issuer"][0] == "sha256AndDigest"
            and len(self.certificate["issuer"][1]) == 8
        )

    def check_corresponding_issuer(
        self, issuer: Certificate
    ) -> bool:
        """
        Check if the issuer corresponds to the certificate stated issuer.

        Parameters
        ----------
        issuer : Certificate
            The issuer to check.

        Returns
        -------
        bool
            True if the issuer corresponds to the certificate stated issuer, False otherwise
        """
        return self.certificate["issuer"][1] == issuer.as_hashedid8()

    def certificate_wants_cert_issue_permissions(
        self
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
        if "certIssuePermissions" in self.certificate["toBeSigned"]:
            return True
        return False

    def get_list_of_psid_from_cert_issue_permissions(
        self
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
        to_return = []
        if self.certificate_wants_cert_issue_permissions():
            cert_issue_permissions = self.certificate["toBeSigned"][
                "certIssuePermissions"
            ]
            for permission in cert_issue_permissions:
                if permission["subjectPermissions"][0] == "explicit":
                    for elem in permission["subjectPermissions"][1]:
                        to_return.append(elem["psid"])
        return to_return

    def get_list_of_psid_from_app_permissions(
        self
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
        cert_app_permissions = self.certificate["toBeSigned"]["appPermissions"]
        to_return = []
        for elem in cert_app_permissions:
            to_return.append(elem["psid"])
        return to_return

    def get_list_of_needed_permissions(self) -> list[int]:
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
        )
        to_return.extend(
            self.get_list_of_psid_from_app_permissions())
        to_return = list(dict.fromkeys(to_return))
        return to_return

    def get_list_of_allowed_persmissions(self) -> list[int]:
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
        to_return = []
        issuer_permissions = []
        if self.certificate_wants_cert_issue_permissions():
            cert_issue_permissions = self.certificate["toBeSigned"][
                "certIssuePermissions"
            ]
            for permission in cert_issue_permissions:
                issuer_permissions = permission["subjectPermissions"]
                if issuer_permissions[0] == "explicit":
                    issuer_permissions = issuer_permissions[1]
                    for elem in issuer_permissions:
                        to_return.append(elem["psid"])
        return to_return

    def certificate_has_all_permissions(self) -> bool:
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
        if "certIssuePermissions" in self.certificate["toBeSigned"]:
            cert_issue_permissions: list = self.certificate["toBeSigned"][
                "certIssuePermissions"
            ]
            for permission in cert_issue_permissions:
                if permission["subjectPermissions"][0] == "all":
                    return True
        return False

    @staticmethod
    def check_all_requested_permissions_are_allowed(
        certificate_permissions: list[int], issuer_permissions: list[int]
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

    def check_issuer_has_subject_permissions(
        self, issuer: Certificate
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
        if issuer.certificate_has_all_permissions():
            return True
        return Certificate.check_all_requested_permissions_are_allowed(
            self.get_list_of_needed_permissions(),
            issuer.get_list_of_allowed_persmissions(),
        )

    @staticmethod
    def verify_signature(
        backend: ECDSABackend, to_be_signed_certificate: dict, signature: dict, verification_key: dict
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
            return backend.verify_with_pk(
                SECURITY_CODER.encode_ToBeSignedCertificate(
                    to_be_signed_certificate),
                signature,
                verification_key,
            )
        except Exception:
            return False

    def __verify_issued_certificate(
        self, backend: ECDSABackend
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
            self.issuer is not None
            and self.certificate_is_issued()
            and self.check_corresponding_issuer(self.issuer)
            and self.check_issuer_has_subject_permissions(self.issuer)
        ):
            if self.signature_is_nist_p256() and self.verification_key_is_nist_p256():
                if self.verify_signature(
                    backend,
                    self.certificate["toBeSigned"],
                    self.certificate["signature"],
                    self.issuer.certificate["toBeSigned"]["verifyKeyIndicator"][1],
                ):
                    return True
        return False

    def __verify_self_signed_certificate(self, backend: ECDSABackend) -> bool:
        """
        Verifies a self signed Certificate.

        Parameters
        ----------
        backend : ECDSABackend
            The backend to be used for verification.

        Returns
        -------
        bool
            True if the certificate is valid, False otherwise.
        """
        if self.certificate_is_self_signed():
            if self.signature_is_nist_p256(
            ) and self.verification_key_is_nist_p256():
                if Certificate.verify_signature(
                    backend,
                    self.certificate["toBeSigned"],
                    self.certificate["signature"],
                    self.certificate["toBeSigned"]["verifyKeyIndicator"][1],
                ):
                    return True
        return False

    def verify(self, backend: ECDSABackend) -> bool:
        """
        Verify the certificate.

        Parameters
        ----------
        backend : ECDSABackend
            The backend to be used for verification.
        issuer : Certificate | None
            The issuer of the certificate. None if self signed.

        Returns
        -------
        bool
            True if the certificate is valid, False otherwise.
        """
        if self.issuer is not None and self.certificate_is_issued():
            return self.__verify_issued_certificate(backend)
        if self.certificate_is_self_signed():
            return self.__verify_self_signed_certificate(backend)
        return False

    def set_issuer_as_self(self) -> Certificate:
        """
        Set the issuer as self.

        Parameters
        ----------
        certificate : Certificate
            The certificate to be set.
        """
        cert_dict = deepcopy(self.certificate)
        cert_dict["issuer"] = ("self", "sha256")
        return Certificate(
            cert_dict, None
        )

    def set_issuer(self, issuer: OwnCertificate) -> Certificate:
        """
        Set the issuer of the certificate.

        Parameters
        ----------
        certificate : Certificate
            The certificate to be set.
        issuer : OwnCertificate
            The issuer of the certificate.
        """
        cert_copy = deepcopy(self.certificate)
        cert_copy["issuer"] = (
            "sha256AndDigest", issuer.as_hashedid8())
        return Certificate(
            cert_copy, issuer
        )

    def set_chain_length_issue_permissions(
        self,
        issuer: OwnCertificate
    ) -> Certificate:
        """
        Set the chain length issue permissions.

        Parameters
        ----------
        issuer : OwnCertificate
            The issuer of the certificate.
        """
        cert_dict = deepcopy(self.certificate)
        if self.certificate_wants_cert_issue_permissions():
            needed_issuing_permissions_capability = (
                self.get_list_of_psid_from_cert_issue_permissions()
            )
            if issuer.certificate_has_all_permissions():
                # Get the "all" permissions
                all_permissions = {}
                for permission in issuer.certificate["toBeSigned"][
                    "certIssuePermissions"
                ]:
                    if permission["subjectPermissions"][0] == "all":
                        all_permissions = permission
                for permission in cert_dict["toBeSigned"][
                    "certIssuePermissions"
                ]:
                    permission["minChainLength"] = copy(
                        all_permissions["minChainLength"]
                    )
            else:
                cert_dict["toBeSigned"]["certIssuePermissions"] = [
                ]
                for permission in issuer.certificate["toBeSigned"][
                    "certIssuePermissions"
                ]:
                    if permission["subjectPermissions"][0] == "explicit":
                        for elem in permission["subjectPermissions"][1]:
                            if elem["psid"] in needed_issuing_permissions_capability:
                                cert_dict["toBeSigned"][
                                    "certIssuePermissions"
                                ].append(deepcopy(permission))
            for permission in cert_dict["toBeSigned"][
                "certIssuePermissions"
            ]:
                permission["minChainLength"] -= 1
            for permission in list(
                cert_dict["toBeSigned"]["certIssuePermissions"]
            ):
                if permission["minChainLength"] < 1:
                    cert_dict["toBeSigned"][
                        "certIssuePermissions"
                    ].remove(permission)
        return Certificate(
            cert_dict, issuer)


@dataclass(frozen=True)
class OwnCertificate(Certificate):
    """
    Class that handles certificates that are generated by the user. And thus it has the private key.

    Attributes
    ----------
    key_id : int
        The key id of the pair of keys used to sign the certificate.
    """
    key_id: int = 0

    @staticmethod
    def initialize_certificate(
        backend: ECDSABackend, to_be_signed_certificate: dict, issuer: OwnCertificate | None = None
    ) -> OwnCertificate:
        """
        Initializes the certificate.

        Parameters
        ----------
        to_be_signed_certificate : dict
            The to be signed certificate to be initialized.
        issuer : OwnCertificate
            The issuer of the certificate. If None, the certificate will be self signed.
        """
        key_id = backend.create_key()
        if OwnCertificate.verify_to_be_signed_certificate(to_be_signed_certificate):
            cert_copy = {
                "version": 3,
                "type": "explicit",
                "issuer": (
                    "sha256AndDigest",
                    (0xA495991B7852B855).to_bytes(8, byteorder="big"),
                ),
                "toBeSigned": deepcopy(to_be_signed_certificate),
                "signature": (
                    "ecdsaNistP256Signature",
                    {
                        "rSig": ("fill", None),
                        "sSig": (0xA495991B7852B855).to_bytes(32, byteorder="big"),
                    },
                ),
            }
            cert_copy["toBeSigned"]["verifyKeyIndicator"] = (
                "verificationKey",
                backend.get_public_key(key_id),
            )
            own_cert = Certificate.from_dict(cert_copy, issuer)
            own_cert = OwnCertificate(
                certificate=deepcopy(own_cert.certificate), issuer=issuer, key_id=key_id)
            if issuer and issuer.verify(backend):
                own_cert = own_cert.set_issuer(issuer)
                own_cert = own_cert.set_chain_length_issue_permissions(issuer)
                own_cert = issuer.issue_certificate(backend, own_cert)
                own_cert = OwnCertificate(
                    certificate=own_cert.certificate, issuer=issuer, key_id=key_id)
            elif issuer is None:
                own_cert = own_cert.set_issuer_as_self()
                own_cert = own_cert.issue_certificate(backend, own_cert)

                own_cert = OwnCertificate(
                    certificate=own_cert.certificate, issuer=None, key_id=key_id)
            else:
                raise ValueError("Issuer certificate is not valid")
            if type(own_cert) is not OwnCertificate:
                raise ValueError("Issued certificate is not an OwnCertificate")
            return own_cert
        raise ValueError("To be signed certificate is not valid")

    @staticmethod
    def verify_to_be_signed_certificate(to_be_signed_certificate: dict) -> bool:
        try:
            SECURITY_CODER.encode_ToBeSignedCertificate(
                to_be_signed_certificate)
            return True
        except Exception:
            return False

    def sign_message(self, backend: ECDSABackend, message: bytes) -> tuple:
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
        return backend.sign(message, self.key_id)

    def check_enough_min_chain_length_for_issuer(self) -> bool:
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
        issuer_permissions = self.certificate["toBeSigned"]["certIssuePermissions"]
        if not any(
            permission["minChainLength"] < 1 for permission in issuer_permissions
        ):
            return True
        return False
        # for permission in issuer_permissions:
        #     if permission['minChainLength'] < 1:
        #         return False
        # return True

    def sign_certificate(
        self, backend: ECDSABackend, certificate: Certificate
    ) -> Certificate:
        """
        Sign the certificate.

        Parameters
        ----------
        backend : ECDSABackend
            The ECDSA backend to use.
        certificate : Certificate
            The certificate to be signed.
        """
        certificate_dict = deepcopy(certificate.certificate)
        certificate_dict["signature"] = backend.sign(
            SECURITY_CODER.encode_ToBeSignedCertificate(
                certificate.certificate["toBeSigned"]
            ),
            self.key_id,
        )
        return Certificate.from_dict(certificate_dict, self)

    def issue_certificate(
        self, backend: ECDSABackend, certificate: Certificate
    ) -> Certificate:
        """
        Issue a certificate.

        Parameters
        ----------
        backend : ECDSABackend
            The ECDSA backend to use.
        certificate : Certificate
            The certificate to be issued.
        """
        final_certificate: Certificate = certificate
        if certificate.certificate_is_self_signed():
            final_certificate = certificate.set_issuer_as_self()
            # Certificate and issuer should be the same object
            final_certificate = self.sign_certificate(
                backend, final_certificate)
        elif certificate.check_issuer_has_subject_permissions(
            self
        ) and self.check_enough_min_chain_length_for_issuer():
            final_certificate = certificate.set_chain_length_issue_permissions(
                self)
            final_certificate = final_certificate.set_issuer(self)
            final_certificate = self.sign_certificate(
                backend, final_certificate)
        return final_certificate

    def set_issuer_as_self(self) -> OwnCertificate:
        """
        Set the issuer as self.

        Parameters
        ----------
        certificate : Certificate
            The certificate to be set.
        """
        cert_dict = deepcopy(self.certificate)
        cert_dict["issuer"] = ("self", "sha256")
        return OwnCertificate(
            cert_dict, None, self.key_id
        )

    def set_issuer(self, issuer: OwnCertificate) -> OwnCertificate:
        """
        Set the issuer of the certificate.

        Parameters
        ----------
        certificate : Certificate
            The certificate to be set.
        issuer : OwnCertificate
            The issuer of the certificate.
        """
        cert_copy = deepcopy(self.certificate)
        cert_copy["issuer"] = (
            "sha256AndDigest", issuer.as_hashedid8())
        return OwnCertificate(
            cert_copy, issuer, self.key_id
        )

    def set_chain_length_issue_permissions(
        self,
        issuer: OwnCertificate
    ) -> OwnCertificate:
        """
        Set the chain length issue permissions.

        Parameters
        ----------
        certificate : Certificate
            The certificate to set.
        issuer : OwnCertificate
            The issuer of the certificate.
        """
        super_cert = super().set_chain_length_issue_permissions(issuer)
        return OwnCertificate(
            super_cert.certificate, issuer, self.key_id)
