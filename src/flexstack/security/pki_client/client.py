"""
pki_client/client.py — PkiClient façade: orchestrates enrolment + authorization.

``PkiClient`` wraps the S3 and S2 protocol modules and handles:
  - Generating or loading the canonical (bootstrap) key pair
  - Calling :func:`enrolment.enroll` to obtain an EC
  - Calling :func:`authorization.authorize` to obtain an AT
  - Persisting EC and AT as ``.cert`` / ``.pem`` file pairs (same format as
    ``generate_certificate_chain.py``) so the result is drop-in compatible
    with the existing ``secured_cam_sender_and_receiver.py`` example

Typical usage::

    import asyncio
    from flexstack.security.pki_client import PkiClient
    from flexstack.security.certificate import Certificate

    ea_cert = Certificate.from_coer(open("ea.cert", "rb").read())
    aa_cert = Certificate.from_coer(open("aa.cert", "rb").read())
    rca_cert = Certificate.from_coer(open("rca.cert", "rb").read())

    client = PkiClient(
        ea_url="http://localhost:8080",
        aa_url="http://localhost:8081",
        ea_cert=ea_cert,
        aa_cert=aa_cert,
        rca_cert=rca_cert,
        certs_dir="certs/pki/",
    )
    at_own = asyncio.run(client.provision(app_permissions=[{"psid": 36}, {"psid": 37}]))
    # at_own is ready to use with SignService / CertificateLibrary
"""
from __future__ import annotations

import logging
import pathlib
import time

from flexstack.security.certificate import Certificate, OwnCertificate
from flexstack.security.ecdsa_backend import PythonECDSABackend

from flexstack.security.pki_client.pki_coder import PKI_CODER
from flexstack.security.pki_client.enrolment import enroll
from flexstack.security.pki_client.authorization import authorize

log = logging.getLogger(__name__)

# ITS epoch offset (seconds from Unix epoch to 2004-01-01 00:00:00 UTC)
_ITS_EPOCH: int = 1_072_915_200


class PkiClient:
    """Orchestrates PKI enrolment (S3) and authorization (S2) for an ITS-S.

    Parameters
    ----------
    ea_url:
        Base URL of the Enrolment Authority, e.g. ``"http://localhost:8080"``.
    aa_url:
        Base URL of the Authorization Authority, e.g. ``"http://localhost:8081"``.
    ea_cert:
        Decoded EA ``Certificate``.
    aa_cert:
        Decoded AA ``Certificate``.
    rca_cert:
        Decoded Root CA ``Certificate`` (used to build the trust chain for
        the returned ``CertificateLibrary``).
    canonical_key_pem:
        PEM bytes of an existing canonical ECDSA private key.  If ``None``
        a new key is generated on first call to :meth:`enroll`.
    certs_dir:
        Directory where EC and AT certificates and keys are persisted.
        Created automatically if it does not exist.
    its_id:
        8-byte ITS station identifier.  Defaults to all-zeros (suitable for
        testing; override with a device-specific value in production).
    http_timeout:
        HTTP request timeout in seconds (default 30).
    """

    def __init__(  # pylint: disable=too-many-arguments
        self,
        ea_url: str,
        aa_url: str,
        ea_cert: Certificate,
        aa_cert: Certificate,
        rca_cert: Certificate,
        canonical_key_pem: bytes | None = None,
        certs_dir: str = "certs/pki",
        its_id: bytes = b"\x00" * 8,
        http_timeout: float = 30.0,
    ) -> None:
        self.ea_url = ea_url
        self.aa_url = aa_url
        self.ea_cert = ea_cert
        self.aa_cert = aa_cert
        self.rca_cert = rca_cert
        self.its_id = its_id
        self.http_timeout = http_timeout
        self.certs_dir = pathlib.Path(certs_dir)

        # Shared ECDSA backend — holds canonical + EC + AT private keys
        self.backend = PythonECDSABackend()

        # Load or generate the canonical (bootstrap) key
        # key_id will be determined after canonical cert is first created.
        self._canonical_key_pem: bytes | None = canonical_key_pem
        self._canonical_cert: OwnCertificate | None = None
        self._ec_own: OwnCertificate | None = None
        self._at_own: OwnCertificate | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def enroll(
        self,
        app_permissions: list[dict] | None = None,
        validity_years: int = 1,
    ) -> OwnCertificate:
        """Perform S3 enrolment and return the issued EC.

        On first call a self-signed bootstrap certificate is generated
        from the canonical key.  The issued EC and its private key are
        saved to ``<certs_dir>/ec.cert`` and ``<certs_dir>/ec.pem``.

        Parameters
        ----------
        app_permissions:
            EC application permissions.  Defaults to PSID 623 with SSP 0xC0
            (EnrolmentRequest + AuthorizationRequest).
        validity_years:
            Requested EC validity in years.

        Returns
        -------
        OwnCertificate
            The issued Enrolment Credential.
        """
        signer = self._get_or_create_canonical_cert()

        ec_own = await enroll(
            ea_url=self.ea_url,
            ea_cert=self.ea_cert,
            signer_cert=signer,
            backend=self.backend,
            ecies_backend=None,       # not used by enrolment.py (crypto.py direct)
            its_id=self.its_id,
            requested_app_permissions=app_permissions,
            validity_years=validity_years,
            timeout=self.http_timeout,
        )
        self._ec_own = ec_own
        self._save_cert(ec_own, "ec")
        log.info("EC saved: %s/ec.{cert,pem}", self.certs_dir)
        return ec_own

    async def authorize(
        self,
        ec_own: OwnCertificate | None = None,
        app_permissions: list[dict] | None = None,
        validity_hours: int = 504,
    ) -> OwnCertificate:
        """Perform S2 authorization and return the issued AT.

        The AT and its private key are saved to ``<certs_dir>/at.cert``
        and ``<certs_dir>/at.pem``.

        Parameters
        ----------
        ec_own:
            Enrolment Credential from a previous :meth:`enroll` call.
            Defaults to ``self._ec_own`` if not provided.
        app_permissions:
            AT application permissions.  Defaults to CAM (36) + DENM (37).
        validity_hours:
            Requested AT validity in hours (default 504 = 3 weeks).

        Returns
        -------
        OwnCertificate
            The issued Authorization Ticket.

        Raises
        ------
        RuntimeError
            If *ec_own* is None and :meth:`enroll` has not been called yet.
        """
        if ec_own is None:
            ec_own = self._ec_own
        if ec_own is None:
            raise RuntimeError("No EC available — call enroll() before authorize()")

        at_own = await authorize(
            aa_url=self.aa_url,
            aa_cert=self.aa_cert,
            ea_cert=self.ea_cert,
            ec_own=ec_own,
            backend=self.backend,
            requested_app_permissions=app_permissions,
            validity_hours=validity_hours,
            timeout=self.http_timeout,
        )
        self._at_own = at_own
        self._save_cert(at_own, "at")
        log.info("AT saved: %s/at.{cert,pem}", self.certs_dir)
        return at_own

    async def provision(
        self,
        app_permissions: list[dict] | None = None,
        ec_validity_years: int = 1,
        at_validity_hours: int = 504,
    ) -> OwnCertificate:
        """Run enrolment + authorization in sequence and return the AT.

        This is the single entry-point for most use cases.  After calling
        this method, ``self._ec_own`` and ``self._at_own`` are both set and
        the corresponding files exist in ``certs_dir``.

        Parameters
        ----------
        app_permissions:
            Application permissions for the AT (CAM + DENM by default).
        ec_validity_years:
            EC validity in years.
        at_validity_hours:
            AT validity in hours.

        Returns
        -------
        OwnCertificate
            The issued Authorization Ticket, ready to use with
            :class:`~flexstack.security.certificate_library.CertificateLibrary`.
        """
        log.info("Starting PKI provisioning flow (enrol → authorize)…")
        ec = await self.enroll(validity_years=ec_validity_years)
        at = await self.authorize(ec_own=ec, app_permissions=app_permissions,
                                  validity_hours=at_validity_hours)
        log.info("Provisioning complete — AT HashedId8: %s", at.as_hashedid8().hex())
        return at

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------

    def _save_cert(self, cert: OwnCertificate, name: str) -> None:
        """Save a certificate + private key to disk.

        Creates two files inside ``self.certs_dir``:
          - ``<name>.cert`` — COER-encoded EtsiTs103097Certificate
          - ``<name>.pem``  — PEM-encoded ECDSA private key

        The format is identical to ``generate_certificate_chain.py`` so the
        files are drop-in compatible with the existing example loader.
        """
        self.certs_dir.mkdir(parents=True, exist_ok=True)
        cert_path = self.certs_dir / f"{name}.cert"
        key_path = self.certs_dir / f"{name}.pem"
        cert_path.write_bytes(cert.encode())
        key_path.write_bytes(self.backend.export_signing_key(cert.key_id))
        log.debug("Written %s and %s", cert_path, key_path)

    def load_at_from_disk(self, name: str = "at") -> OwnCertificate | None:
        """Load a previously issued AT from disk (avoids re-provisioning).

        Returns ``None`` if the files do not exist.  If loaded, the private
        key is imported into ``self.backend`` and ``self._at_own`` is set.

        Parameters
        ----------
        name:
            Base name of the files (default ``"at"`` → ``at.cert`` + ``at.pem``).
        """
        cert_path = self.certs_dir / f"{name}.cert"
        key_path = self.certs_dir / f"{name}.pem"
        if not cert_path.exists() or not key_path.exists():
            return None
        try:
            cert_coer = cert_path.read_bytes()
            key_pem = key_path.read_bytes()
            key_id = self.backend.import_signing_key(key_pem)
            cert_dict = PKI_CODER.decode_certificate(cert_coer)
            at_own = OwnCertificate(
                certificate=cert_dict,
                issuer=self.aa_cert,
                key_id=key_id,
            )
            self._at_own = at_own
            log.info("Loaded AT from disk: %s", at_own.as_hashedid8().hex())
            return at_own
        except Exception as exc:  # pylint: disable=broad-exception-caught
            log.warning("Failed to load AT from disk: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Bootstrap canonical certificate (self-signed, for initial enrolment)
    # ------------------------------------------------------------------

    def _get_or_create_canonical_cert(self) -> OwnCertificate:
        """Return (or lazily create) the self-signed canonical certificate.

        The canonical cert is a minimal self-signed certificate built from
        a fresh ECDSA key pair.  It is only used as the ``signer_cert`` for
        the initial enrolment request and is never registered as an EC.
        OwnCertificate is a frozen dataclass, so we call
        ``initialize_certificate`` which creates the key internally.
        """
        if self._canonical_cert is not None:
            return self._canonical_cert

        # If caller supplied a PEM, import it before letting initialize_certificate
        # create a NEW key (we can't pass an existing key_id to it).  For the
        # canonical cert we always generate a fresh key — the canonical identity
        # is determined by the certificate content, not by a long-lived key.
        start = int(time.time()) - _ITS_EPOCH
        tbs: dict = {
            "id": ("name", "its-s-canonical"),
            "cracaId": b"\x00\x00\x00",
            "crlSeries": 0,
            "validityPeriod": {
                "start": start,
                "duration": ("years", 10),
            },
            "appPermissions": [
                {"psid": 623, "ssp": ("opaque", bytes([0x01, 0xC0]))}
            ],
            "certIssuePermissions": [
                {
                    "subjectPermissions": ("all", None),
                    "minChainLength": 2,
                    "chainLengthRange": 0,
                    "eeType": (b"\x00", 1),
                }
            ],
            "verifyKeyIndicator": (
                "verificationKey",
                ("ecdsaNistP256", ("fill", None)),
            ),
        }
        # initialize_certificate creates a new key internally (frozen dataclass).
        # If a PEM was supplied, we import it first and use its key_id.
        if self._canonical_key_pem is not None:
            pre_key_id = self.backend.import_signing_key(self._canonical_key_pem)
            vk = self.backend.get_public_key(pre_key_id)
            tbs["verifyKeyIndicator"] = ("verificationKey", vk)

        canonical_cert = OwnCertificate.initialize_certificate(
            backend=self.backend,
            to_be_signed_certificate=tbs,
            issuer=None,          # self-signed bootstrap
        )
        self._canonical_cert = canonical_cert
        log.debug(
            "Created canonical cert (HashedId8=%s, key_id=%d)",
            canonical_cert.as_hashedid8().hex(),
            canonical_cert.key_id,
        )
        return self._canonical_cert
