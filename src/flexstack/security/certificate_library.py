from __future__ import annotations
from flexstack.security.ecdsa_backend import ECDSABackend

from .certificate import Certificate, OwnCertificate


class CertificateLibrary:
    """
    Class for managing certificates.

    Attributes
    ----------
    own_certificates : Dict[bytes, OwnCertificate]
        The list of own certificates. (Messages can be signed with those
        certificates) [Key: Hashedid8, Value: OwnCertificate]
    known_authorization_tickets : Dict[bytes, Certificate]
        The list of known authorization tickets. (Messages can be verified
        with those certificates) [Key: Hashedid8, Value: Certificate]
    known_authorization_authorities : Dict[bytes, Certificate]
        The list of known authorization authorities. (Authorization Tickets
        Certificates can be verified with those certificates)
        [Key: Hashedid8, Value: Certificate]
    known_root_certificates : Dict[bytes, Certificate]
        The list of known root certificates. (Authorization Authorities
        Certificates can be verified with those certificates)
        [Key: Hashedid8, Value: Certificate]
    """

    def __init__(
        self,
        ecdsa_backend: ECDSABackend,
        root_certificates: list[Certificate],
        aa_certificates: list[Certificate],
        at_certificates: list[Certificate],
    ) -> None:
        """
        Initialize the Certificate Library.

        Parameters
        ----------
        root_certificates : list[Certificate]
            The list of root certificates.
        aa_certificates : list[Certificate]
            The list of authorization authorities certificates.
        at_certificates : list[Certificate]
            The list of authorization tickets certificates.
        """
        self.own_certificates = {}
        self.known_authorization_tickets = {}
        self.known_authorization_authorities = {}
        self.known_root_certificates = {}
        #: HashedId8 of revoked CA certificates (CRL, ETSI TS 102 941 clause 6.3.6)
        self.revoked: set[bytes] = set()
        self.ecdsa_backend = ecdsa_backend
        # Root certificates
        for root_certificate in root_certificates:
            self.add_root_certificate(root_certificate)
        # Authorization Authorities certificates
        for aa_certificate in aa_certificates:
            self.add_authorization_authority(aa_certificate)
        # Authorization Tickets certificates
        for at_certificate in at_certificates:
            self.add_authorization_ticket(at_certificate)

    def get_issuer_certificate(self, certificate: Certificate) -> Certificate | None:
        """
        Get the issuer certificate of a certificate.

        Parameters
        ----------
        certificate : Certificate
            The certificate to get the issuer certificate from.

        Returns
        -------
        Certificate
            The issuer certificate. It returns None if the issuer is self.
            Or issuer not found.
        """
        if certificate.certificate["issuer"][0] == "self":
            return None
        if certificate.certificate["issuer"][0] in ("sha256AndDigest", "sha384AndDigest"):
            if certificate.certificate["issuer"][1] in self.revoked:
                return None
            if (
                certificate.certificate["issuer"][1]
                in self.known_root_certificates.keys()
            ):
                return self.known_root_certificates[
                    certificate.certificate["issuer"][1]
                ]
            if (
                certificate.certificate["issuer"][1]
                in self.known_authorization_authorities.keys()
            ):
                return self.known_authorization_authorities[
                    certificate.certificate["issuer"][1]
                ]
            return None
        raise ValueError("Unknown issuer type")

    def add_authorization_ticket(self, certificate: Certificate) -> None:
        """
        Add an authorization ticket to the library.

        Parameters
        ----------
        certificate : Certificate
            The authorization ticket to add.
        """
        if certificate.as_hashedid8() not in self.known_authorization_tickets.keys():
            issuer_certificate = self.get_issuer_certificate(certificate)
            if issuer_certificate is not None:
                if certificate.verify(self.ecdsa_backend):
                    self.known_authorization_tickets[certificate.as_hashedid8()] = (
                        certificate
                    )

    def add_authorization_authority(self, certificate: Certificate) -> None:
        """
        Add an authorization authority to the library.

        Parameters
        ----------
        certificate : Certificate
            The authorization authority to add.
        """
        if (
            certificate.as_hashedid8()
            not in self.known_authorization_authorities.keys()
        ):
            issuer_certificate = self.get_issuer_certificate(certificate)
            if issuer_certificate is not None:
                if certificate.verify(self.ecdsa_backend):
                    self.known_authorization_authorities[certificate.as_hashedid8()] = (
                        certificate
                    )

    def add_root_certificate(self, certificate: Certificate) -> None:
        """
        Add a root certificate to the library.

        Parameters
        ----------
        certificate : Certificate
            The root certificate to add.
        """
        if certificate.as_hashedid8() in self.revoked:
            return
        if certificate.verify(self.ecdsa_backend):
            self.known_root_certificates[certificate.as_hashedid8(
            )] = certificate

    def learn_ca_certificate(self, certificate: dict) -> bool:
        """
        Add a CA certificate received from a peer (P2PCD, IEEE 1609.2 clause
        8.2.4) when its issuer is a known root and its signature verifies;
        returns True when it is (now) known.
        """
        candidate = Certificate.from_dict(certificate)
        if candidate.as_hashedid8() in self.known_authorization_authorities:
            return True
        issuer = self.get_issuer_certificate(candidate)
        if issuer is None or issuer.as_hashedid8() not in self.known_root_certificates:
            return False
        self.add_authorization_authority(Certificate.from_dict(certificate, issuer=issuer))
        return candidate.as_hashedid8() in self.known_authorization_authorities

    def remove_certificate(self, hashedid8: bytes) -> None:
        """
        Forget a root or AA certificate (e.g. deleted from a CTL) and every
        certificate issued under it.
        """
        self.known_root_certificates.pop(hashedid8, None)
        self.known_authorization_authorities.pop(hashedid8, None)
        self._purge()

    def revoke(self, hashedids8: set[bytes]) -> None:
        """
        Apply a CRL: the CA certificates ``hashedids8`` are revoked permanently
        (ETSI TS 102 941 V2.2.1 clause 6.3.3); they and every certificate
        issued under them are no longer trusted, and they cannot be re-added.
        """
        self.revoked |= set(hashedids8)
        for hashedid8 in hashedids8:
            self.known_root_certificates.pop(hashedid8, None)
            self.known_authorization_authorities.pop(hashedid8, None)
        self._purge()

    def _purge(self) -> None:
        """Drop the AAs and ATs whose issuer is no longer known."""
        def issued_by_known(certificate: Certificate, issuers: dict) -> bool:
            issuer = certificate.get_issuer_hashedid8()
            return issuer is not None and issuer not in self.revoked and issuer in issuers
        self.known_authorization_authorities = {
            h: c for h, c in self.known_authorization_authorities.items()
            if issued_by_known(c, self.known_root_certificates)}
        cas = {**self.known_root_certificates, **self.known_authorization_authorities}
        self.known_authorization_tickets = {
            h: c for h, c in self.known_authorization_tickets.items() if issued_by_known(c, cas)}

    def add_own_certificate(self, certificate: OwnCertificate) -> None:
        """
        Add a certificate to the library.

        Parameters
        ----------
        certificate : OwnCertificate
            The certificate to add
        """
        issuer_certificate = self.get_issuer_certificate(certificate)
        if issuer_certificate is not None and certificate.verify(self.ecdsa_backend):
            self.own_certificates[certificate.as_hashedid8()] = certificate

    def get_authorization_ticket_by_hashedid8(self, hashedid8: bytes) -> Certificate | None:
        """
        Get an authorization ticket by its hashedid8.

        Parameters
        ----------
        hashedid8 : bytes | None
            The hashedid8 of the authorization ticket, None if not found.
        """
        if hashedid8 in self.known_authorization_tickets.keys():
            return self.known_authorization_tickets[hashedid8]
        return None

    def verify_sequence_of_certificates(
        self, certificates: list[dict], backend: ECDSABackend
    ) -> Certificate | None:
        """
        Verification of a sequence of certificates as specified in IEEE 1609.2. Signer Identifer.
        The first certificate is the authorization ticket. And then each one is the issuer of the one before.

        Parameters
        ----------
        certificates : list[dict]
            The sequence of certificates to verify.
        coder : SecurityCoder
            The coder to use for encoding and decoding.
        backend : ECDSABackend
            The backend to use for ECDSA operations.

        Returns
        -------
        Certificate
            The Authorization ticket if verified. Returns none otherwise.
        """
        if len(certificates) == 0:
            return None
        if self.revoked and any(Certificate(c).as_hashedid8() in self.revoked for c in certificates[1:]):
            return None
        if len(certificates) == 1:
            temp_certificate = Certificate.from_dict(
                certificate=certificates[0])
            if (
                temp_certificate.as_hashedid8()
                in self.known_authorization_tickets.keys()
            ):
                return self.known_authorization_tickets[temp_certificate.as_hashedid8()]
            issuer_certificate = self.get_issuer_certificate(temp_certificate)
            temp_certificate = Certificate.from_dict(
                certificate=certificates[0], issuer=issuer_certificate)
            if issuer_certificate is not None and temp_certificate.verify(
                backend
            ):
                self.add_authorization_ticket(temp_certificate)
                return temp_certificate
        if len(certificates) == 2:
            authorization_authority = Certificate.from_dict(
                certificate=certificates[1])
            authorization_authority_issuer_hashedid8 = (
                authorization_authority.get_issuer_hashedid8()
            )
            if (
                authorization_authority_issuer_hashedid8
                in self.known_root_certificates.keys()
            ):
                root_certificate = self.known_root_certificates[
                    authorization_authority_issuer_hashedid8
                ]
                authorization_authority = Certificate.from_dict(
                    certificate=certificates[1], issuer=root_certificate
                )
                if authorization_authority.verify(backend=backend):
                    self.add_authorization_authority(authorization_authority)
                    authorization_ticket = Certificate.from_dict(
                        certificate=certificates[0],
                        issuer=authorization_authority,
                    )
                    if authorization_ticket.verify(backend=backend):
                        self.add_authorization_ticket(authorization_ticket)
                        return authorization_ticket
        if len(certificates) == 3:
            root_certificate = Certificate.from_dict(certificates[-1])
            if root_certificate.as_hashedid8() in self.known_root_certificates.keys():
                return self.verify_sequence_of_certificates(
                    certificates[:-1], backend
                )
        return None

    def get_ca_certificate_by_hashedid3(self, hashedid3: bytes) -> Certificate | None:
        """
        Look up an Authorization Authority or Root CA certificate by the last
        3 bytes of its HashedId8 (HashedId3).

        Parameters
        ----------
        hashedid3 : bytes
            The last 3 bytes of the certificate's HashedId8.

        Returns
        -------
        Certificate | None
            The matching certificate, or None if not found.
        """
        for hashedid8, cert in self.known_authorization_authorities.items():
            if hashedid8[-3:] == hashedid3:
                return cert
        for hashedid8, cert in self.known_root_certificates.items():
            if hashedid8[-3:] == hashedid3:
                return cert
        return None
