"""
pki_client/client.py — ``PkiClient``: the ITS-S side of the ETSI TS 102 941
V2.2.1 security management (enrolment with the EA, authorization with the AA).

States (ETSI TS 103 525-2 V2.1.1 clause 4.2.1):

- ``initialized``: no valid Enrolment Credential (EC); the next enrolment is
  an initial request (canonical identifier and canonical key);
- ``enrolled``: a valid EC; the next enrolment is a re-keying request when the
  EC permits signing enrolment requests (SSP of ITS-AID 623, clause B.4);
- ``authorized``: a valid EC and a valid Authorization Ticket (AT).

A failed request leaves the state as it was. An expired EC or AT no longer
counts. Revocation (CRL, see :mod:`.trust_lists`) of the EA, AA or Root CA of
the own certificates drops them (:meth:`PkiClient.revoke`).

Typical usage::

    client = PkiClient(ea_url="https://ea.example/", aa_url="https://aa.example/",
                       ea_cert=ea, aa_cert=aa, rca_cert=rca,
                       canonical_key_pem=open("canonical.pem", "rb").read(),
                       its_id=b"canonical-id")
    at_own = asyncio.run(client.provision(app_permissions=[{"psid": 36}, {"psid": 37}]))
"""
from __future__ import annotations

import asyncio
import logging
import pathlib
from typing import Awaitable, Callable

from flexstack.security.certificate import Certificate, OwnCertificate
from flexstack.security.ecdsa_backend import PythonECDSABackend
from flexstack.security.validity import valid_at
from flexstack.utils.time_service import TimeService

from flexstack.security.pki_client import messages
from flexstack.security.pki_client.authorization import AuthorizationError, authorize
from flexstack.security.pki_client.enrolment import enroll
from flexstack.security.pki_client.pki_coder import PKI_CODER
from flexstack.security.pki_client.transport import HttpTransport, RetryPolicy

log = logging.getLogger(__name__)

INITIALIZED, ENROLLED, AUTHORIZED = "initialized", "enrolled", "authorized"


class PkiClient:  # pylint: disable=too-many-instance-attributes
    """ITS-S PKI client (see the module documentation).

    Parameters
    ----------
    ea_url, aa_url:
        Access points of the EA and the AA (the requests are POSTed to them).
    ea_cert, aa_cert, rca_cert:
        Certificates of the EA, the AA and their Root CA.
    canonical_key_pem:
        PEM of the canonical private key registered with the EA. Without it a
        key is generated (:meth:`canonical_public_key` gives it for registration).
    certs_dir:
        Directory where EC and AT are saved (``ec``/``at`` ``.cert`` and ``.pem``).
    its_id:
        Canonical identifier of the ITS-S (InnerEcRequest.itsId of an initial request).
    http_timeout:
        Timeout of the default HTTP transport (seconds).
    clock:
        UTC seconds (defaults to :meth:`TimeService.time`).
    transport:
        Object with ``async post(url, content, content_type) -> bytes`` and
        ``async get(url) -> bytes`` (defaults to :class:`HttpTransport`).
    pop:
        Send authorization requests with proof of possession (recommended by
        clause 6.2.3.3.1).
    enrolment_retry:
        Repetition of an enrolment request without response (ETSI TS 103 601
        V2.1.1 clause 5.1, mandatory for every ITS-S); None sends it once.
    authorization_retry:
        Repetition of an authorization request (clause 5.2): for an ITS-S
        without privacy requirements only, hence off (None) by default.
    sleep:
        Coroutine waiting between two transmissions (``asyncio.sleep``).
    """

    def __init__(  # pylint: disable=too-many-arguments,too-many-positional-arguments,too-many-locals
        self, ea_url: str, aa_url: str, ea_cert: Certificate, aa_cert: Certificate,
        rca_cert: Certificate, canonical_key_pem: bytes | None = None, certs_dir: str = "certs/pki",
        its_id: bytes = b"\x00" * 8, http_timeout: float = 30.0, *,
        clock: Callable[[], float] | None = None, transport=None, pop: bool = True,
        enrolment_retry: RetryPolicy | None = RetryPolicy(), authorization_retry: RetryPolicy | None = None,
        sleep: Callable[[float], Awaitable[object]] = asyncio.sleep,
    ) -> None:
        self.ea_url, self.aa_url = ea_url, aa_url
        self.ea_cert, self.aa_cert, self.rca_cert = ea_cert, aa_cert, rca_cert
        self.its_id = its_id
        self.certs_dir = pathlib.Path(certs_dir)
        self.clock = clock or TimeService.time
        self.transport = transport or HttpTransport(http_timeout)
        self.pop = pop
        self.enrolment_retry, self.authorization_retry = enrolment_retry, authorization_retry
        self.sleep = sleep
        self.backend = PythonECDSABackend()
        if canonical_key_pem is not None:
            self.canonical_key = self.backend.import_signing_key(canonical_key_pem)
        else:
            self.canonical_key = self.backend.create_key()
            log.warning("No canonical key given: generated one, which the EA must know")
        self._ec_own: OwnCertificate | None = None
        self._at_own: OwnCertificate | None = None

    # -- state ---------------------------------------------------------------

    def _valid(self, certificate: OwnCertificate | None) -> bool:
        return certificate is not None and valid_at(certificate, messages.time64(self.clock()))

    @property
    def ec(self) -> OwnCertificate | None:
        """The current EC, if valid."""
        return self._ec_own if self._valid(self._ec_own) else None

    @property
    def at(self) -> OwnCertificate | None:
        """The current AT, if valid (and the EC too)."""
        return self._at_own if self.ec is not None and self._valid(self._at_own) else None

    @property
    def state(self) -> str:
        """``initialized``, ``enrolled`` or ``authorized``."""
        if self.ec is None:
            return INITIALIZED
        return AUTHORIZED if self.at is not None else ENROLLED

    def canonical_public_key(self) -> tuple:
        """The canonical verification key (to be registered with the EA)."""
        return self.backend.get_public_key(self.canonical_key)

    def revoke(self, revoked: set[bytes]) -> None:
        """Apply revoked CA certificates (HashedId8): an EC whose EA or Root CA is
        revoked is dropped (state ``initialized``); an AT whose AA (or Root CA)
        is revoked is dropped (state ``enrolled``)."""
        rca = self.rca_cert.as_hashedid8()
        if rca in revoked or self.ea_cert.as_hashedid8() in revoked:
            if self._ec_own is not None:
                log.warning("EC dropped: its EA or Root CA is revoked")
            self._ec_own = self._at_own = None
        if rca in revoked or self.aa_cert.as_hashedid8() in revoked:
            if self._at_own is not None:
                log.warning("AT dropped: its AA or Root CA is revoked")
            self._at_own = None

    # -- requests ------------------------------------------------------------

    def _attributes(self, app_permissions: list[dict], duration: tuple | None) -> dict:
        attributes: dict = {"appPermissions": app_permissions}
        if duration is not None:
            attributes["validityPeriod"] = {"start": messages.time32(self.clock()), "duration": duration}
        return attributes

    async def enroll(self, app_permissions: list[dict] | None = None,
                     validity_years: int | None = None) -> OwnCertificate:
        """Request an EC (clause 6.2.3.2). A re-keying request when the current EC is
        valid and permits enrolment requests, an initial request otherwise. The
        EC is saved to ``<certs_dir>/ec.{cert,pem}``. Raises
        :class:`~flexstack.security.pki_client.enrolment.EnrolmentError`."""
        if app_permissions is None:
            app_permissions = [{"psid": messages.PSID_CERT_REQUEST, "ssp": messages.certificate_ssp()}]
        current = self.ec
        if current is not None and not messages.ssp_permits(current, messages.SSP_ENROLMENT_REQUEST):
            current = None
        ec_own = await enroll(self.transport, self.ea_url, self.ea_cert, self.backend, its_id=self.its_id,
                              canonical_key=self.canonical_key, current_ec=current,
                              attributes=self._attributes(app_permissions, None if validity_years is None
                                                          else ("years", validity_years)), now=self.clock(),
                              retry=self.enrolment_retry, clock=self.clock, sleep=self.sleep)
        self._ec_own = ec_own
        self._save_cert(ec_own, "ec")
        return ec_own

    async def authorize(self, ec_own: OwnCertificate | None = None, app_permissions: list[dict] | None = None,
                        validity_hours: int | None = None) -> OwnCertificate:
        """Request an AT (clause 6.2.3.3) signed (ecSignature) with the EC. The AT
        is saved to ``<certs_dir>/at.{cert,pem}``. Raises
        :class:`~flexstack.security.pki_client.authorization.AuthorizationError`,
        or ``RuntimeError`` without a valid EC."""
        ec_own = ec_own or self.ec
        if ec_own is None:
            raise RuntimeError("No valid EC: enroll() first")
        if not messages.ssp_permits(ec_own, messages.SSP_AUTHORIZATION_REQUEST):
            raise AuthorizationError("deniedpermissions", "the EC does not permit authorization requests")
        if app_permissions is None:
            app_permissions = [{"psid": 36}, {"psid": 37}]
        at_own = await authorize(self.transport, self.aa_url, self.aa_cert, self.ea_cert, ec_own=ec_own,
                                 backend=self.backend,
                                 attributes=self._attributes(app_permissions, None if validity_hours is None
                                                             else ("hours", validity_hours)),
                                 now=self.clock(), pop=self.pop, retry=self.authorization_retry,
                                 clock=self.clock, sleep=self.sleep)
        self._at_own = at_own
        self._save_cert(at_own, "at")
        return at_own

    async def provision(self, app_permissions: list[dict] | None = None, ec_validity_years: int | None = None,
                        at_validity_hours: int | None = None) -> OwnCertificate:
        """Enrol (when not enrolled) and request an AT; returns the AT."""
        if self.ec is None:
            await self.enroll(validity_years=ec_validity_years)
        return await self.authorize(app_permissions=app_permissions, validity_hours=at_validity_hours)

    # -- persistence ---------------------------------------------------------

    def _save_cert(self, cert: OwnCertificate, name: str) -> None:
        """``<name>.cert`` (COER certificate) and ``<name>.pem`` (private key)."""
        self.certs_dir.mkdir(parents=True, exist_ok=True)
        (self.certs_dir / f"{name}.cert").write_bytes(cert.encode())
        (self.certs_dir / f"{name}.pem").write_bytes(self.backend.export_signing_key(cert.key_id))

    def _load(self, name: str, issuer: Certificate) -> OwnCertificate | None:
        cert_path, key_path = self.certs_dir / f"{name}.cert", self.certs_dir / f"{name}.pem"
        if not cert_path.exists() or not key_path.exists():
            return None
        try:
            key_id = self.backend.import_signing_key(key_path.read_bytes())
            certificate = PKI_CODER.decode_certificate(cert_path.read_bytes())
        except Exception as exc:  # pylint: disable=broad-exception-caught
            log.warning("Cannot load %s from %s: %s", name, self.certs_dir, exc)
            return None
        return OwnCertificate(certificate=certificate, issuer=issuer, key_id=key_id)

    def load_ec_from_disk(self, name: str = "ec") -> OwnCertificate | None:
        """Load a previously issued EC (None if absent or unreadable)."""
        ec_own = self._load(name, self.ea_cert)
        if ec_own is not None:
            self._ec_own = ec_own
        return ec_own

    def load_at_from_disk(self, name: str = "at") -> OwnCertificate | None:
        """Load a previously issued AT (None if absent or unreadable)."""
        at_own = self._load(name, self.aa_cert)
        if at_own is not None:
            self._at_own = at_own
        return at_own
