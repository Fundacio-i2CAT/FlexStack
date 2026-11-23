"""
Decentralized Environmental Notification (DEN) service.

Implements ETSI TS 103 831 V2.3.1 (2025-11) "Decentralized Environmental
Notification Service; Release 2" (latest version), the successor of ETSI
EN 302 637-3 V1.3.1 (2019-04). DENMs use DENM-PDU-Descriptions v2.3 (Annex A)
over the Common Data Dictionary v4.3 (ETSI TS 102 894-2).

* :class:`DENMTransmissionManagement`: originating ITS-S (clause 8.2):
  AppDENM_trigger / update / termination, DENM repetition.
* :class:`DENMReceptionManagement`: receiving ITS-S (clause 8.4).
* Keep-Alive Forwarding (clause 8.3), optional, enabled with ``kaf_enabled``.

All three share one :class:`~.den_protocol.DENProtocol` (the ITS-S message
tables). A scheduler thread fires the protocol timers (T_O_Validity,
T_Repetition, T_RepetitionDuration, T_R_Validity, T_F_Validity, T_Forwarding)
at their deadlines.
"""

from __future__ import annotations

import logging
import threading
from typing import Callable, List, Optional

from ...utils.time_service import TimeService
from .denm_coder import DENMCoder
from .denm_transmission_management import DENMTransmissionManagement, VehicleData
from ...btp.router import Router as BTPRouter
from .denm_reception_management import DENMReceptionManagement, ReceivedDENM
from ..local_dynamic_map.ldm_facility import LDMFacility
from .den_protocol import ActionId, DENMRequest, DENProtocol, DENResult

_MAX_IDLE_WAIT_S = 1.0


class DecentralizedEnvironmentalNotificationService:
    """
    Decentralized Environmental Notification (DEN) Service.

    Parameters
    ----------
    btp_router : BTPRouter
        BTP Router.
    vehicle_data : VehicleData
        stationId and stationType of this ITS-S.
    ldm : LDMFacility, optional
        Local Dynamic Map fed with accepted DENMs.
    kaf_enabled : bool
        Activate Keep-Alive Forwarding of received DENMs (clause 6.1.4.2).
        KAF only forwards while :meth:`set_ego_position` has placed the
        station inside the DENM destination area.
    start_scheduler : bool
        Start the timer thread (DENM repetition, KAF, table expiry). Tests that
        drive the protocol timers manually pass False.
    clock : callable, optional
        Time source of the service (TimestampIts, ms); the system time when None.

    Attributes
    ----------
    protocol : DENProtocol
        Shared protocol engine.
    denm_transmission_management : DENMTransmissionManagement
        Originating ITS-S operation.
    denm_reception_management : DENMReceptionManagement
        Receiving ITS-S operation.
    """

    def __init__(
        self, btp_router: BTPRouter, vehicle_data: VehicleData, ldm: LDMFacility | None = None,
        kaf_enabled: bool = False, start_scheduler: bool = True,
        *, clock: Optional[Callable[[], int]] = None,
    ) -> None:
        self.logging = logging.getLogger("denm_service")

        self.btp_router = btp_router
        self.denm_coder = DENMCoder()
        self.vehicle_data = vehicle_data
        self.ldm = ldm
        self.clock: Callable[[], int] = clock if clock is not None \
            else (lambda: int(TimeService.timestamp_its()))
        self.lock = threading.RLock()
        self._wakeup = threading.Condition(self.lock)
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self.protocol = DENProtocol(vehicle_data.station_id, vehicle_data.station_type,
                                    kaf_enabled=kaf_enabled, validate=self.denm_coder.validate)
        self.denm_transmission_management = DENMTransmissionManagement(
            btp_router=btp_router,
            denm_coder=self.denm_coder,
            vehicle_data=self.vehicle_data,
            protocol=self.protocol,
            lock=self.lock,
            on_timers_changed=self._notify_scheduler,
            clock=self.clock,
        )
        self.denm_reception_management = DENMReceptionManagement(
            denm_coder=self.denm_coder, btp_router=self.btp_router, ldm=ldm,
            protocol=self.protocol, lock=self.lock, on_timers_changed=self._notify_scheduler,
            clock=self.clock,
        )
        self.expiry_callbacks: List[Callable[[ActionId], None]] = []
        if start_scheduler:
            self.start()
        self.logging.info("DENM Service Started!")

    # ── Application interface (IF.Triggering / IF.DataCollect) ─────────────

    def trigger_denm(self, request: DENMRequest) -> DENResult:
        """AppDENM_trigger."""
        return self.denm_transmission_management.trigger_denm(request)

    def update_denm(self, action_id: ActionId, request: DENMRequest) -> DENResult:
        """AppDENM_update."""
        return self.denm_transmission_management.update_denm(action_id, request)

    def terminate_denm(self, action_id: ActionId, request: DENMRequest) -> DENResult:
        """AppDENM_termination."""
        return self.denm_transmission_management.terminate_denm(action_id, request)

    def add_application_callback(self, callback: Callable[[ReceivedDENM], None]) -> None:
        """Receive accepted DENMs and their state (ACTIVE / CANCELLED / NEGATED)."""
        self.denm_reception_management.add_application_callback(callback)

    def add_expiry_callback(self, callback: Callable[[ActionId], None]) -> None:
        """Be notified when a received event expires (T_R_Validity)."""
        self.expiry_callbacks.append(callback)

    def update_station_id(self, station_id: int) -> None:
        """Pseudonym change: re-label all stored own DENMs (clause 6.1.1.2)."""
        with self.lock:
            self.protocol.update_station_id(station_id)

    def set_ego_position(self, latitude: int, longitude: int) -> None:
        """Own position in 1/10 micro-degree, used by Keep-Alive Forwarding."""
        with self.lock:
            self.protocol.set_ego_position(latitude, longitude)

    # ── Scheduler ──────────────────────────────────────────────────────────

    def start(self) -> None:
        """Start the timer thread."""
        with self.lock:
            if self._running:
                return
            self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True, name="den-scheduler")
        self._thread.start()

    def stop(self) -> None:
        """Stop the timer thread."""
        with self.lock:
            self._running = False
            self._wakeup.notify_all()
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None

    def process_timers(self, now: Optional[int] = None) -> None:
        """Fire the expired protocol timers at ``now`` (TimestampIts ms) and send."""
        with self.lock:
            outgoing, expired = self.protocol.tick(now if now is not None else self.clock())
        for item in outgoing:
            try:
                self.denm_transmission_management.transmit(item)
            except Exception:  # pylint: disable=broad-except
                self.logging.exception("Failed to transmit a DENM")
        for action_id in expired:
            for callback in self.expiry_callbacks:
                callback(action_id)

    def _notify_scheduler(self) -> None:
        with self.lock:
            self._wakeup.notify_all()

    def _run(self) -> None:
        while True:
            with self.lock:
                if not self._running:
                    return
                deadline = self.protocol.next_deadline()
                now = self.clock()
                if deadline is None or deadline > now:
                    wait = _MAX_IDLE_WAIT_S if deadline is None \
                        else min(_MAX_IDLE_WAIT_S, (deadline - now) / 1000)
                    self._wakeup.wait(wait)
                    continue
            self.process_timers()
