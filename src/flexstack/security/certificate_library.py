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
        if certificate.certificate["issuer"][0] == "sha256AndDigest":
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
        if certificate.verify(self.ecdsa_backend):
            self.known_root_certificates[certificate.as_hashedid8(
            )] = certificate

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
        elif len(certificates) == 1:
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
        elif len(certificates) == 2:
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
        elif len(certificates) == 3:
            root_certificate = Certificate.from_dict(certificates[-1])
            if root_certificate.as_hashedid8() in self.known_root_certificates.keys():
                return self.verify_sequence_of_certificates(
                    certificates[:-1], backend
                )
        return None
