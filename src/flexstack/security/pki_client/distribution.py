"""
Peer-to-peer CRL / CTL distribution of an ITS-S (ETSI TS 103 601 V2.1.1
clauses 5.3 and 5.4): the CRL / CTL Distribution Application (CXLDA).

Responder (clause 5.4)
    A CRL or Delta CTL (ECTL of the TLM, CTL of a Root CA) received from the DC
    is verified, applied and broadcast at frequency ``f1`` during ``d1`` (case 1).
    A neighbour's P2P request for a list the ITS-S holds in a more recent version
    starts its broadcast at ``f2`` during ``d2`` (case 2). The broadcast stops at
    the end of the period, at the nextUpdate of the list, or when the same or a
    newer version of the list is received from another ITS-S (clause 5.4.3). The
    SM-PDU is sent unsecured at the GeoNetworking layer (it is signed by its
    issuer) in a SHB, BTP-B port 2014 (CTL) or 2015 (CRL).

Requester (clause 5.3)
    A pending request is inserted in the ``contributedExtensions`` of the next
    CAM (clause 5.3.4: one request per CAM): ``EtsiTs102941CrlRequest`` with the
    thisUpdate of the last CRL of the issuer, ``EtsiTs102941DeltaCtlRequest`` with
    the ctlSequence of its last CTL (absent when none is known). A request is
    started on demand, when the CRL of an issuer passes its nextUpdate, and when a
    neighbour requests a CTL more recent than the one held (clause 5.3.6); it ends
    when the list is received. A CTL request also ends at the nextUpdate of the
    CTL held.

Not implemented: the Full CTL broadcast and its Segmented CTL Response Message
(clause 5.5, optional PICS items R1.1.2 / R1.2.5); a received
``EtsiTs102941FullCtlRequest`` is ignored.
"""
from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from typing import Callable

from flexstack.btp.service_access_point import BTPDataIndication, BTPDataRequest
from flexstack.geonet.service_access_point import (
    CommonNH, CommunicationProfile, HeaderType, PacketTransportType, TopoBroadcastHST)
from flexstack.security.certificate import Certificate
from flexstack.security.header_extensions import CRL_REQUEST_ID, DELTA_CTL_REQUEST_ID
from flexstack.security.security_profiles import SecurityProfile
from flexstack.utils.time_service import TimeService

from flexstack.security.pki_client.messages import time32
from flexstack.security.pki_client.trust_lists import (
    PSID_CRL, PSID_CTL, ListVersion, TrustListError, TrustStore)

log = logging.getLogger("pki")

# BTP-B destination ports of the CTL and CRL broadcast (ETSI TS 103 601 clause
# 5.4.4 refers to ETSI TS 103 248; values of TS 103 525-2 SECPKI_ITS-S_CTLDIST_03
# and SECPKI_ITS-S_CRLDIST_02).
CTL_PORT = 2014
CRL_PORT = 2015


@dataclass(frozen=True)
class DistributionConfig:
    """Parameters of the service (PIXITs of TS 103 525-2). Defaults: the
    recommended values of TS 103 601 clause 5.4.2 NOTE 1 and NOTE 3."""
    redistribute: bool = True         # broadcast the lists received from the DC (case 1)
    f1: float = 1.0                   # Hz, case 1
    d1: float = 7 * 24 * 3600.0       # s, case 1
    f2: float = 1.0                   # Hz, case 2 (answer to a P2P request)
    d2: float = 10.0                  # s, case 2


@dataclass
class Broadcast:
    """A list being broadcast."""
    message: bytes
    version: ListVersion
    period: float                     # 1 / f, seconds
    until: float                      # end of the broadcast period (UTC seconds)
    next_tx: float                    # next transmission (UTC seconds)


def _newer_or_same(received: ListVersion, sent: ListVersion) -> bool:
    if received.kind == "crl":
        return (received.this_update or 0) >= (sent.this_update or 0)
    return (received.sequence or 0) >= (sent.sequence or 0)


class TrustListDistribution:
    """CRL / CTL distribution of the ITS-S (module documentation).

    Parameters
    ----------
    trust:
        Trust store that verifies and applies the lists.
    btp_router:
        BTP router sending the broadcasts; :meth:`attach` registers the
        reception ports on it (before its callbacks are frozen).
    sign_service, verify_service:
        Services whose CAMs carry the requests of the ITS-S and whose verified
        messages bring the requests of the neighbours (both optional).
    clock:
        UTC seconds; :meth:`TimeService.time` by default.
    """

    def __init__(self, trust: TrustStore, btp_router=None, *,  # pylint: disable=too-many-arguments
                 sign_service=None, verify_service=None,
                 clock: Callable[[], float] | None = None, config: DistributionConfig = DistributionConfig()):
        self.trust = trust
        self.btp_router = btp_router
        self.clock = clock or TimeService.time
        self.config = config
        self.held: dict[tuple[str, bytes], tuple[bytes, ListVersion]] = {}
        self.broadcasts: dict[tuple[str, bytes], Broadcast] = {}
        self.requests: list[tuple[str, bytes]] = []
        self._rotation = 0
        self._lock = threading.RLock()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        if sign_service is not None:
            sign_service.trust_list_request = self.next_request
        if verify_service is not None:
            verify_service.trust_list_listener = self.on_requests

    def attach(self, btp_router) -> None:
        """Register the CTL and CRL ports (open to unsecured packets) on ``btp_router``."""
        self.btp_router = btp_router
        for port in (CTL_PORT, CRL_PORT):
            btp_router.register_indication_callback_btp(port, self.on_btp_indication, accept_unsecured=True)

    # -- reception -----------------------------------------------------------------

    def on_btp_indication(self, indication: BTPDataIndication) -> None:
        """A CRL / CTL broadcast by a neighbour."""
        try:
            self.receive(indication.data, from_dc=False)
        except TrustListError as exc:
            log.debug("Broadcast list discarded: %s", exc)

    def receive(self, message: bytes, *, from_dc: bool) -> ListVersion:
        """A CRL / CTL received from the DC (``from_dc``) or from a neighbour:
        verified, applied when it is new, then redistributed (case 1) or ending a
        broadcast of the same or an older version (clause 5.4.3). Raises
        :class:`TrustListError` for a list that does not verify."""
        version = self.trust.inspect(message)
        key = (version.kind, version.issuer)
        try:
            self.trust.process(message)
            applied = True
        except TrustListError as exc:
            if exc.code not in ("outdated", "outofsequence"):
                raise
            applied = False
        with self._lock:
            current = self.broadcasts.get(key)
            if current is not None and not from_dc and _newer_or_same(version, current.version):
                del self.broadcasts[key]
                log.info("Broadcast of %s %s stopped: sent by another ITS-S", *self._name(key))
            if applied:
                if key in self.requests:
                    self.requests.remove(key)
                if not version.full:
                    self.held[key] = (message, version)
                    if from_dc and self.config.redistribute:
                        self._start(key, self.config.f1, self.config.d1)
        return version

    async def refresh(self, transport) -> list[str]:
        """Download the due lists from the DC / CPOC (:meth:`TrustStore.refresh`) and
        redistribute them."""
        return await self.trust.refresh(transport, process=lambda m: self.receive(m, from_dc=True))

    def on_requests(self, requests: list[tuple[int, dict]], _signer: Certificate | None = None) -> None:
        """P2P requests in a verified message of a neighbour (clauses 5.3.6, 5.4.2)."""
        with self._lock:
            for ext_id, request in requests:
                issuer = request["issuerId"]
                if ext_id == CRL_REQUEST_ID:
                    self._answer_crl(issuer, request.get("lastKnownUpdate"))
                elif ext_id == DELTA_CTL_REQUEST_ID:
                    self._answer_ctl(issuer, request.get("lastKnownCtlSequence"))

    def _answer_crl(self, issuer: bytes, last_known: int | None) -> None:
        held = self.held.get(("crl", issuer))
        if held is not None and (last_known is None or (held[1].this_update or 0) > last_known):
            self._start(("crl", issuer), self.config.f2, self.config.d2)

    def _answer_ctl(self, issuer: bytes, last_known: int | None) -> None:
        for kind in ("ectl", "rca-ctl"):
            held = self.held.get((kind, issuer))
            if held is not None and (last_known is None or (held[1].sequence or 0) > last_known):
                self._start((kind, issuer), self.config.f2, self.config.d2)
            info = self.trust.lists.get((kind, issuer))
            if info is not None and last_known is not None and last_known > (info.sequence or 0):
                self.request_ctl(issuer)              # the neighbour knows a newer CTL

    # -- requests ------------------------------------------------------------------

    def request_crl(self, issuer: bytes) -> None:
        """Request the next CRL of the Root CA ``issuer`` (HashedId8) from the neighbours."""
        with self._lock:
            if ("crl", issuer) not in self.requests:
                self.requests.append(("crl", issuer))

    def request_ctl(self, issuer: bytes) -> None:
        """Request the next Delta CTL of the TLM or Root CA ``issuer`` from the neighbours."""
        kind = "ectl" if issuer in self.trust.tlms else "rca-ctl"
        with self._lock:
            if (kind, issuer) not in self.requests:
                self.requests.append((kind, issuer))

    def next_request(self) -> tuple[int, dict] | None:
        """The request to insert in the next CAM (one per CAM, in turn)."""
        with self._lock:
            if not self.requests:
                return None
            kind, issuer = self.requests[self._rotation % len(self.requests)]
            self._rotation += 1
            info = self.trust.lists.get((kind, issuer))
            if kind == "crl":
                request: dict = {"issuerId": issuer}
                if info is not None and info.this_update is not None:
                    request["lastKnownUpdate"] = info.this_update
                return CRL_REQUEST_ID, request
            request = {"issuerId": issuer}
            if info is not None and info.sequence is not None:
                request["lastKnownCtlSequence"] = info.sequence
            return DELTA_CTL_REQUEST_ID, request

    # -- timers --------------------------------------------------------------------

    def tick(self) -> None:
        """Send the broadcasts due, end the expired ones and start the requests due
        (to be called periodically; :meth:`start` runs it in a thread)."""
        now = self.clock()
        now32 = time32(now)
        with self._lock:
            for key, broadcast in list(self.broadcasts.items()):
                if now >= broadcast.until or now32 >= broadcast.version.next_update:
                    del self.broadcasts[key]
                    log.info("Broadcast of %s %s ended", *self._name(key))
                elif now >= broadcast.next_tx:
                    self._send(key, broadcast.message)
                    broadcast.next_tx = max(broadcast.next_tx + broadcast.period, now)
            for key in list(self.requests):
                info = self.trust.lists.get(key)
                if key[0] != "crl" and info is not None and now32 >= info.next_update:
                    self.requests.remove(key)          # clause 5.3.6: CTL request ends
            for (kind, issuer), info in self.trust.lists.items():
                if kind == "crl" and now32 >= info.next_update:
                    self.request_crl(issuer)           # clause 5.3.6: CRL nextUpdate reached

    def start(self, interval: float = 0.1) -> None:
        """Run :meth:`tick` every ``interval`` seconds in a daemon thread."""
        self._stop.clear()

        def run():
            while not self._stop.wait(interval):
                self.tick()
        self._thread = threading.Thread(target=run, name="cxlda", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop the thread of :meth:`start`."""
        self._stop.set()
        if self._thread is not None:
            self._thread.join()
            self._thread = None

    def _start(self, key: tuple[str, bytes], frequency: float, duration: float) -> None:
        message, version = self.held[key]
        now = self.clock()
        current = self.broadcasts.get(key)
        if current is not None and current.version == version and current.until >= now + duration:
            return                                     # already broadcast for longer
        self.broadcasts[key] = Broadcast(message, version, 1.0 / frequency, now + duration,
                                         now + 1.0 / frequency)
        log.info("Broadcast of %s %s started for %.0f s", *self._name(key), duration)
        self._send(key, message)

    def _send(self, key: tuple[str, bytes], message: bytes) -> None:
        if self.btp_router is None:
            return
        crl = key[0] == "crl"
        self.btp_router.btp_data_request(BTPDataRequest(
            btp_type=CommonNH.BTP_B,
            destination_port=CRL_PORT if crl else CTL_PORT,
            gn_packet_transport_type=PacketTransportType(
                header_type=HeaderType.TSB, header_subtype=TopoBroadcastHST.SINGLE_HOP),
            communication_profile=CommunicationProfile.UNSPECIFIED,
            security_profile=SecurityProfile.UNSECURED,
            its_aid=PSID_CRL if crl else PSID_CTL,
            data=message,
            length=len(message),
        ))

    @staticmethod
    def _name(key: tuple[str, bytes]) -> tuple[str, str]:
        return key[0], key[1].hex().upper()
