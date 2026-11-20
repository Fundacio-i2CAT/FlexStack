from __future__ import annotations
from copy import deepcopy, copy
from dataclasses import dataclass, field
from hashlib import sha256, sha384
import secrets

import ecdsa

from .security_coder import SecurityCoder
from .ecdsa_backend import ECDSABackend, hash_for_key, hash_name_for_key, reconstruct_public_key

SECURITY_CODER = SecurityCoder()

_SUPPORTED_SIGNATURES = (
    "ecdsaNistP256Signature", "ecdsaBrainpoolP256r1Signature",
    "ecdsaBrainpoolP384r1Signature", "ecdsaNistP384Signature",
)
_SUPPORTED_KEYS = ("ecdsaNistP256", "ecdsaBrainpoolP256r1", "ecdsaBrainpoolP384r1", "ecdsaNistP384")


def signing_input(data: bytes, signer: bytes, hashfunc=sha256) -> bytes:
    """
    Input to the ECDSA signing and verification operations (IEEE Std
    1609.2-2016, clause 5.3.1, adopted by ETSI TS 103 097 V2.2.1):
    ``Hash(Data input) || Hash(Signer identifier input)``, which ECDSA hashes
    again. ``data`` is the COER encoding of the ToBeSignedData or
    ToBeSignedCertificate; ``signer`` is the canonical COER encoding of the
    signer's certificate, or ``b""`` for self-signed data.
    """
    return hashfunc(data).digest() + hashfunc(signer).digest()


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

    def to_canonical(self) -> Certificate:
        """
        Convert certificate to IEEE 1609.2 / ETSI TS 103 097 canonical form:
        - Every elliptic curve point of toBeSigned compressed
          (compressed-y-0/1): verification key or reconstruction value, on
          every curve, and the encryption key (IEEE 1609.2 clause 6.4.3).
        - Signature rSig as x-only, for every signature algorithm.
        """
        d = deepcopy(self.certificate)
        tbs = d.get("toBeSigned", {})
        vki = tbs.get("verifyKeyIndicator")

        def compressed(point: tuple) -> tuple:
            if point[0] in ("uncompressedP256", "uncompressedP384"):
                y_choice = "compressed-y-0" if point[1]["y"][-1] % 2 == 0 else "compressed-y-1"
                return (y_choice, point[1]["x"])
            return point
        if vki and vki[0] == "verificationKey":
            tbs["verifyKeyIndicator"] = ("verificationKey", (vki[1][0], compressed(vki[1][1])))
        elif vki and vki[0] == "reconstructionValue":
            tbs["verifyKeyIndicator"] = ("reconstructionValue", compressed(vki[1]))
        encryption_key = tbs.get("encryptionKey")
        if encryption_key:
            choice, point = encryption_key["publicKey"]
            tbs["encryptionKey"] = dict(encryption_key, publicKey=(choice, compressed(point)))
        d["toBeSigned"] = tbs
        sig = d.get("signature")
        if sig:
            r_sig = sig[1]["rSig"]
            if r_sig[0] in ("compressed-y-0", "compressed-y-1"):
                d["signature"] = (sig[0], {"rSig": ("x-only", r_sig[1]), "sSig": sig[1]["sSig"]})
            elif r_sig[0] in ("uncompressedP256", "uncompressedP384"):
                d["signature"] = (sig[0], {"rSig": ("x-only", r_sig[1]["x"]), "sSig": sig[1]["sSig"]})
        return Certificate(d, self.issuer)

    def as_hashedid8(self) -> bytes:
        """
        Return the certificate as a canonical hashedid8.

        Returns
        -------
        bytes
            The certificate as a hashedid8.
        """
        canon_cert = self.to_canonical()
        m = sha384() if self.hash_name() == "sha384" else sha256()
        m.update(SECURITY_CODER.encode_etsi_ts_103097_certificate(canon_cert.certificate))
        return m.digest()[-8:]

    def hash_name(self) -> str:
        """
        ``sha256`` or ``sha384``: the hash for the curve of the certificate's
        verification key (:func:`hash_name_for_key`), used for its HashedId8,
        the hashId of data it signs and the issuer choice of certificates it
        issues. SHA-256 for implicit certificates.
        """
        vki = self.certificate.get("toBeSigned", {}).get("verifyKeyIndicator")
        if vki is None or vki[0] != "verificationKey":
            return "sha256"
        return hash_name_for_key(vki[1])

    def issuer_choice(self) -> str:
        """IssuerIdentifier choice of a certificate issued by this one."""
        return "sha384AndDigest" if self.hash_name() == "sha384" else "sha256AndDigest"

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
                "cracaId": b"\x00\x00\x00",
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
        if self.certificate["issuer"][0] in ("sha256AndDigest", "sha384AndDigest"):
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

    def signature_is_supported(self) -> bool:
        """True when the signature algorithm is NIST P-256/P-384 or brainpoolP256r1/P384r1."""
        return self.certificate["signature"][0] in _SUPPORTED_SIGNATURES

    def verification_key_is_supported(self) -> bool:
        """True when the verification key is NIST P-256/P-384 or brainpoolP256r1/P384r1."""
        vki = self.certificate["toBeSigned"]["verifyKeyIndicator"]
        return vki[0] == "verificationKey" and vki[1][0] in _SUPPORTED_KEYS

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
            and self.certificate["issuer"][1] in ("sha256", "sha384")
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
            self.certificate["issuer"][0] in ("sha256AndDigest", "sha384AndDigest")
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
        return (self.certificate["issuer"][0] == issuer.issuer_choice()
                and self.certificate["issuer"][1] == issuer.as_hashedid8())

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
        backend: ECDSABackend, to_be_signed_certificate: dict, signature: tuple, verification_key: tuple
    ) -> bool:
        """
        Verify the signature of a self-signed certificate, computed over
        Hash(Hash(tbs) || Hash("")) (IEEE 1609.2 clause 5.3.1).

        Parameters
        ----------
        to_be_signed_certificate : dict
            The to be signed certificate to be verified.
        signature : tuple
            The signature to be verified.
        verification_key : tuple
            The verification key to be used.

        Returns
        -------
        bool
            True if the signature is valid, False otherwise.
        """
        try:
            return backend.verify_with_pk(
                signing_input(SECURITY_CODER.encode_ToBeSignedCertificate(to_be_signed_certificate),
                              b"", hash_for_key(verification_key)),
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
            if self.signature_is_supported() and self.verification_key_is_supported():
                # IEEE 1609.2 clause 5.3.1: Hash(Hash(tbs) || Hash(issuer certificate))
                issuer_key = self.issuer.verification_key()
                if issuer_key is None:
                    return False
                tbs_bytes = SECURITY_CODER.encode_ToBeSignedCertificate(self.certificate["toBeSigned"])
                payload = signing_input(tbs_bytes, self.issuer.to_canonical().encode(),
                                        hash_for_key(issuer_key))
                if backend.verify_with_pk(payload, self.certificate["signature"], issuer_key):
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
            if self.signature_is_supported() and self.verification_key_is_supported():
                # IEEE 1609.2 clause 5.3.1: self-signed, the signer input is the empty string
                key = self.certificate["toBeSigned"]["verifyKeyIndicator"][1]
                tbs_bytes = SECURITY_CODER.encode_ToBeSignedCertificate(self.certificate["toBeSigned"])
                if backend.verify_with_pk(signing_input(tbs_bytes, b"", hash_for_key(key)),
                                          self.certificate["signature"], key):
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
        # §6: verifyKeyIndicator must match certificate type
        cert_type = self.certificate.get("type")
        vki = self.certificate.get("toBeSigned", {}).get("verifyKeyIndicator")
        if cert_type == "explicit" and (vki is None or vki[0] != "verificationKey"):
            return False
        if cert_type == "implicit":
            # IEEE 1609.2 clause 6.4.2: an implicit certificate carries a
            # reconstruction value and no signature (IEEE 1609.2 clause 5.3.2)
            if vki is None or vki[0] != "reconstructionValue" or "signature" in self.certificate:
                return False
            return self.__verify_implicit_certificate()
        if self.issuer is not None and self.certificate_is_issued():
            return self.__verify_issued_certificate(backend)
        if self.certificate_is_self_signed():
            return self.__verify_self_signed_certificate(backend)
        return False

    def __verify_implicit_certificate(self) -> bool:
        """
        An implicit certificate has no signature: it is accepted when it is
        issued by its (known) issuer with the required permissions and its
        public key can be reconstructed. A wrong certificate yields a wrong key,
        so data it signs does not verify (SEC 4 section 3.5).
        """
        return (
            self.issuer is not None
            and self.certificate_is_issued()
            and self.check_corresponding_issuer(self.issuer)
            and self.check_issuer_has_subject_permissions(self.issuer)
            and self.verification_key() is not None
        )

    def is_implicit(self) -> bool:
        """True for an implicit certificate (reconstruction value, no signature)."""
        return self.certificate.get("type") == "implicit"

    def implicit_hash_integer(self) -> int:
        """
        e = Hn(Hash(ToBeSignedCertificate) || Hash(issuer certificate)): the
        leftmost floor(log2 n) = 255 bits of SHA-256 over the 1609.2 hash input
        (IEEE Std 1609.2-2016 clauses 5.3.2 and 6.4.3; SEC 4 section 2.3).
        """
        assert self.issuer is not None
        tbs = SECURITY_CODER.encode_ToBeSignedCertificate(self.to_canonical().certificate["toBeSigned"])
        digest = sha256(signing_input(tbs, self.issuer.to_canonical().encode())).digest()
        return int.from_bytes(digest, "big") >> 1

    def verification_key(self) -> tuple | None:
        """
        Public verification key of the certificate: the explicit key, or the
        key reconstructed from the reconstruction value and the issuer key
        (ECQV, IEEE Std 1609.2-2016 clause 5.3.2). None when not available.
        """
        vki = self.certificate.get("toBeSigned", {}).get("verifyKeyIndicator")
        if vki is None:
            return None
        if vki[0] == "verificationKey":
            return vki[1]
        if vki[0] == "reconstructionValue" and self.issuer is not None and self.issuer is not self:
            issuer_key = self.issuer.verification_key()
            if issuer_key is not None:
                return reconstruct_public_key(vki[1], issuer_key, self.implicit_hash_integer())
        return None

    def is_authorization_ticket(self) -> bool:
        """
        Check whether this certificate conforms to the §7.2.1 Authorization Ticket profile.

        §7.2.1 constraints:
        - issuer SHALL be sha256AndDigest or sha384AndDigest (never self).
        - toBeSigned.id SHALL be choice none.
        - toBeSigned.certIssuePermissions SHALL be absent.
        - toBeSigned.appPermissions SHALL be present.
        """
        tbs = self.certificate.get("toBeSigned", {})
        if self.certificate.get("issuer", ("",))[0] not in ("sha256AndDigest", "sha384AndDigest"):
            return False
        if tbs.get("id", ("",))[0] != "none":
            return False
        if "certIssuePermissions" in tbs:
            return False
        if "appPermissions" not in tbs:
            return False
        return True

    def is_enrolment_credential(self) -> bool:
        """
        Check whether this certificate conforms to the §7.2.2 Enrolment Credential profile.

        §7.2.2 constraints:
        - type SHALL be explicit.
        - issuer SHALL be sha256AndDigest or sha384AndDigest.
        - toBeSigned.id SHALL be choice name.
        - toBeSigned.certIssuePermissions SHALL be absent.
        - toBeSigned.appPermissions SHALL be present.
        """
        tbs = self.certificate.get("toBeSigned", {})
        if self.certificate.get("type") != "explicit":
            return False
        if self.certificate.get("issuer", ("",))[0] not in ("sha256AndDigest", "sha384AndDigest"):
            return False
        if tbs.get("id", ("",))[0] != "name":
            return False
        if "certIssuePermissions" in tbs:
            return False
        if "appPermissions" not in tbs:
            return False
        return True

    def is_root_ca_certificate(self) -> bool:
        """
        Check whether this certificate conforms to the §7.2.3 Root CA profile.

        §7.2.3 constraints:
        - type SHALL be explicit.
        - issuer SHALL be self.
        - toBeSigned.id SHALL be choice name.
        - toBeSigned.certIssuePermissions SHALL be present.
        - toBeSigned.appPermissions SHALL be present.
        """
        tbs = self.certificate.get("toBeSigned", {})
        if self.certificate.get("type") != "explicit":
            return False
        if self.certificate.get("issuer", ("",))[0] != "self":
            return False
        if tbs.get("id", ("",))[0] != "name":
            return False
        if "certIssuePermissions" not in tbs:
            return False
        if "appPermissions" not in tbs:
            return False
        return True

    def is_subordinate_ca_certificate(self) -> bool:
        """
        Check whether this certificate conforms to the §7.2.4 Subordinate CA profile.

        §7.2.4 constraints:
        - type SHALL be explicit.
        - issuer SHALL be sha256AndDigest or sha384AndDigest.
        - toBeSigned.id SHALL be choice name.
        - toBeSigned.encryptionKey SHALL be present.
        - toBeSigned.certIssuePermissions SHALL be present.
        """
        tbs = self.certificate.get("toBeSigned", {})
        if self.certificate.get("type") != "explicit":
            return False
        if self.certificate.get("issuer", ("",))[0] not in ("sha256AndDigest", "sha384AndDigest"):
            return False
        if tbs.get("id", ("",))[0] != "name":
            return False
        if "encryptionKey" not in tbs:
            return False
        if "certIssuePermissions" not in tbs:
            return False
        return True

    def set_issuer_as_self(self) -> Certificate:
        """
        Set the issuer as self.

        Parameters
        ----------
        certificate : Certificate
            The certificate to be set.
        """
        cert_dict = deepcopy(self.certificate)
        cert_dict["issuer"] = ("self", self.hash_name())
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
        cert_copy["issuer"] = (issuer.issuer_choice(), issuer.as_hashedid8())
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
        backend: ECDSABackend, to_be_signed_certificate: dict, issuer: OwnCertificate | None = None,
        algorithm: str = "nistP256", compressed_key: bool = True,
    ) -> OwnCertificate:
        """
        Initializes the certificate.

        Parameters
        ----------
        to_be_signed_certificate : dict
            The to be signed certificate to be initialized.
        issuer : OwnCertificate
            The issuer of the certificate. If None, the certificate will be self signed.
        algorithm : str
            Curve of the new key pair (an IEEE 1609.2 PublicVerificationKey curve).
        compressed_key : bool
            Verification key as a compressed point (default) or uncompressed.
        """
        key_id = backend.create_key(algorithm)
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
                backend.get_public_key(key_id, compressed_key),
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
        # §6: id must be name or none
        id_entry = to_be_signed_certificate.get("id")
        if id_entry is None or id_entry[0] not in ("name", "none"):
            return False
        # §6: cracaId must be 0x000000
        if to_be_signed_certificate.get("cracaId") != b"\x00\x00\x00":
            return False
        # §6: crlSeries must be 0
        if to_be_signed_certificate.get("crlSeries") != 0:
            return False
        # §6: at least one of appPermissions or certIssuePermissions must be present
        if "appPermissions" not in to_be_signed_certificate and "certIssuePermissions" not in to_be_signed_certificate:
            return False
        # §6: certRequestPermissions must be absent
        if "certRequestPermissions" in to_be_signed_certificate:
            return False
        # §6: canRequestRollover must be absent
        if "canRequestRollover" in to_be_signed_certificate:
            return False
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
        # IEEE 1609.2 clause 5.3.1: the signer identifier input is this certificate
        return backend.sign(signing_input(message, self.to_canonical().encode(), self.hash_function()),
                            self.key_id)

    def hash_function(self):
        """Hash function of :meth:`hash_name` (for the 1609.2 signing input)."""
        return sha384 if self.hash_name() == "sha384" else sha256

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
        tbs_bytes = SECURITY_CODER.encode_ToBeSignedCertificate(
            certificate.certificate["toBeSigned"]
        )
        issuer_type = certificate.certificate.get("issuer", [None])[0]
        # IEEE 1609.2 clause 5.3.1: Hash(Hash(tbs) || Hash(issuer certificate)),
        # with the empty string as signer input for a self-signed certificate.
        signer = self.to_canonical().encode() if issuer_type in ("sha256AndDigest", "sha384AndDigest") else b""
        certificate_dict["signature"] = backend.sign(signing_input(tbs_bytes, signer, self.hash_function()),
                                                     self.key_id)
        return Certificate.from_dict(certificate_dict, self)

    def issue_implicit_certificate(  # pylint: disable=too-many-locals
        self, backend: ECDSABackend, to_be_signed_certificate: dict,
    ) -> OwnCertificate:
        """
        Issue an implicit certificate with ECQV (SEC 4 sections 3.3 to 3.6, as
        profiled by IEEE Std 1609.2-2016 clause 5.3.2) and return it with the
        reconstructed private key of its holder. The requester and the CA role
        are combined here: k_U is the requester key, k the CA ephemeral key,
        P_U = k_U*G + k*G, r = e*k + d_CA and d_U = e*k_U + r.

        Only a NIST P-256 issuer key held by ``backend`` is supported.
        """
        curve = ecdsa.NIST256p
        n = curve.order
        k_u = secrets.randbelow(n - 1) + 1
        k = secrets.randbelow(n - 1) + 1
        p_u = curve.generator * k_u + curve.generator * k
        y_choice = "compressed-y-0" if p_u.y() % 2 == 0 else "compressed-y-1"
        tbs = deepcopy(to_be_signed_certificate)
        tbs["verifyKeyIndicator"] = ("reconstructionValue", (y_choice, p_u.x().to_bytes(32, "big")))
        cert = Certificate.from_dict({
            "version": 3, "type": "implicit", "issuer": ("sha256AndDigest", self.as_hashedid8()),
            "toBeSigned": tbs,
        }, self)
        e = cert.implicit_hash_integer()
        r = (e * k + backend.private_scalar(self.key_id)) % n  # type: ignore[attr-defined]
        d_u = (e * k_u + r) % n
        key_id = backend.import_private_scalar(d_u)  # type: ignore[attr-defined]
        return OwnCertificate(certificate=cert.certificate, issuer=self, key_id=key_id)

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
        cert_dict["issuer"] = ("self", self.hash_name())
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
        cert_copy["issuer"] = (issuer.issuer_choice(), issuer.as_hashedid8())
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
