"""
DENM reception: receiving ITS-S operation of the DEN service
(ETSI TS 103 831 V2.3.1 (2025-11), clause 8.4), and the reception side of the
optional Keep-Alive Forwarding (clause 8.3).

Received DENMs are decoded and processed against the receiving ITS-S message
table of the shared :class:`~.den_protocol.DENProtocol`. DENMs that are
accepted (new event, update, or termination of a known event) are handed to
the LDM and to the registered application callbacks together with their state;
outdated, repeated, expired and unknown-termination DENMs are discarded.
"""

from __future__ import annotations

import logging
import threading
from typing import Callable, List, Optional

from ...utils.time_service import TimeService
from ...geonet.service_access_point import GeoBroadcastHST, HeaderType
from .denm_coder import DENMCoder
from ...btp.router import Router as BTPRouter
from ...btp.service_access_point import BTPDataIndication
from ..local_dynamic_map.ldm_facility import LDMFacility
from ..local_dynamic_map.ldm_classes import (
    AccessPermission,
    AddDataProviderReq,
    Location,
    RegisterDataProviderReq,
    TimeValidity,
    TimestampIts,
)
from ..local_dynamic_map.ldm_constants import DENM
from .den_protocol import DENProtocol, DenmState, ReceptionOutcome
from .denm_ssp import ssp_consistent
from .denm_transmission_management import DENM_BTP_PORT, DENM_ITS_AID


class ReceivedDENM:
    """
    DENM passed to ITS-S applications (IF.DataCollect, clause 5.3.1.5).

    Attributes
    ----------
    denm : dict
        Decoded DENM.
    state : DenmState
        State of the event after this DENM: ACTIVE, CANCELLED or NEGATED.
    """

    def __init__(self, denm: dict, state: DenmState) -> None:
        self.denm = denm
        self.state = state


class DENMReceptionManagement:
    """
    Receiving ITS-S operation of the DEN service.

    Parameters
    ----------
    denm_coder : DENMCoder
        UPER coder.
    btp_router : BTPRouter
        BTP router; the reception callback is registered on port 2002.
    ldm : LDMFacility or None
        LDM fed with accepted DENMs.
    protocol : DENProtocol, optional
        Shared protocol engine (receiving and forwarding tables).
    lock : threading.RLock, optional
        Lock protecting the engine.
    on_timers_changed : callable, optional
        Called after each reception (KAF timers may have changed).
    """

    def __init__(
        self, denm_coder: DENMCoder, btp_router: BTPRouter, ldm: LDMFacility | None,
        protocol: Optional[DENProtocol] = None, lock: Optional[threading.RLock] = None,
        on_timers_changed: Optional[Callable[[], None]] = None,
        *, clock: Optional[Callable[[], int]] = None,
    ) -> None:
        self.logging = logging.getLogger("denm_service")
        self.denm_coder = denm_coder
        self.btp_router = btp_router
        self.protocol = protocol if protocol is not None else DENProtocol(0, 0)
        self.lock = lock if lock is not None else threading.RLock()
        self._on_timers_changed = on_timers_changed
        self._clock: Callable[[], int] = clock if clock is not None \
            else (lambda: int(TimeService.timestamp_its()))
        self.application_callbacks: List[Callable[[ReceivedDENM], None]] = []
        self.btp_router.register_indication_callback_btp(
            port=DENM_BTP_PORT, callback=self.reception_callback
        )
        self.ldm_facility = ldm
        if self.ldm_facility is not None:
            self.ldm_facility.if_ldm_3.register_data_provider(
                RegisterDataProviderReq(
                    application_id=DENM,
                    access_permissions=(
                        AccessPermission.DENM,
                    ),
                    time_validity=TimeValidity(1000),
                )
            )

    def add_application_callback(self, callback: Callable[[ReceivedDENM], None]) -> None:
        """Register an ITS-S application callback for accepted DENMs."""
        self.application_callbacks.append(callback)

    def feed_ldm(self, denm: dict) -> None:
        """
        Send DENM to LDM Facility.

        Parameters
        ----------
        denm : dict
            DENM message.
        """
        if self.ldm_facility is not None:
            data = AddDataProviderReq(
                application_id=DENM,
                timestamp=TimestampIts.initialize_with_utc_timestamp_seconds(),
                location=Location.location_builder_circle(
                    latitude=denm["denm"]["management"]["eventPosition"]["latitude"],
                    longitude=denm["denm"]["management"]["eventPosition"]["longitude"],
                    altitude=denm["denm"]["management"]["eventPosition"]["altitude"][
                        "altitudeValue"
                    ],
                    radius=0,
                ),
                data_object=denm,
                time_validity=TimeValidity(3),
            )
            self.ldm_facility.if_ldm_3.add_provider_data(data)
            self.logging.debug("Added DENM with timestamp: %s, station_id: %s to the LDM.",
                               denm["denm"]["management"]["referenceTime"],
                               denm["header"]["stationId"])

    def reception_callback(self, btp_indication: BTPDataIndication) -> None:
        """
        Process a DENM received on BTP port 2002 (clause 8.4.2).

        Parameters
        ----------
        btp_indication : BTPDataIndication
            BTP indication carrying the DENM.
        """
        # ETSI TS 103 097 V2.2.1 clause 7.1.2: a
        # secured DENM shall carry the DENM ITS-AID.
        if btp_indication.gn_its_aid is not None and btp_indication.gn_its_aid != DENM_ITS_AID:
            self.logging.debug("Discarded secured DENM with ITS-AID %s", btp_indication.gn_its_aid)
            return
        try:
            denm = self.denm_coder.decode(btp_indication.data)
        except Exception:  # pylint: disable=broad-except
            # DENM decoding exception (clause 8.4.3.2): discard.
            self.logging.debug("Discarded undecodable DENM")
            return
        area = btp_indication.gn_destination_area
        area_type = None
        transport = btp_indication.gn_packet_transport_type
        if area is not None and transport.header_type == HeaderType.GEOBROADCAST \
                and isinstance(transport.header_subtype, GeoBroadcastHST):
            area_type = transport.header_subtype
        with self.lock:
            outcome: ReceptionOutcome = self.protocol.receive(
                denm, self._clock(), area=area, area_type=area_type,
                ssp_consistent=ssp_consistent(btp_indication.gn_permissions, denm))
        if self._on_timers_changed is not None:
            self._on_timers_changed()
        if not outcome.accepted:
            self.logging.debug("Discarded DENM %s: %s", outcome.action_id, outcome.reason)
            return
        self.feed_ldm(denm)
        received = ReceivedDENM(denm, outcome.state)  # type: ignore[arg-type]
        for callback in self.application_callbacks:
            try:
                callback(received)
            except Exception:  # pylint: disable=broad-except
                self.logging.exception("DENM application callback failed")
