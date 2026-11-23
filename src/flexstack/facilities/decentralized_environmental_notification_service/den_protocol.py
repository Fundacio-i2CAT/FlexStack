"""
DEN service protocol engine (ETSI TS 103 831 V2.3.1 (2025-11), clause 8).

Pure protocol logic, independent of threads, sockets and codecs:

* originating ITS-S operation (clause 8.2): AppDENM_trigger, AppDENM_update,
  AppDENM_termination, the originating ITS-S message table, timers
  T_O_Validity, T_RepetitionDuration and T_Repetition;
* forwarding ITS-S operation (clause 8.3): the optional Keep-Alive Forwarding
  (KAF), the forwarding ITS-S message table, timers T_F_Validity and
  T_Forwarding, DENM regeneration;
* receiving ITS-S operation (clause 8.4): the receiving ITS-S message table and
  timer T_R_Validity.

Time is always passed in explicitly as ``now`` (TimestampIts, milliseconds
since 2004-01-01T00:00:00Z), so every rule can be unit-tested. The engine never
transmits: every operation returns the DENMs to hand to the networking &
transport layer as :class:`OutgoingDENM` objects. :meth:`DENProtocol.tick`
fires the expired timers and :meth:`DENProtocol.next_deadline` tells a
scheduler when to call it next.

DENMs are handled as the ``dict`` representation produced by ``DENMCoder``
(DENM-PDU-Descriptions v2.3, ETSI TS 103 831 V2.3.1 Annex A).

Mirrors ``rustflexstack::facilities::decentralized_environmental_notification_service::den_protocol``.
"""

from __future__ import annotations

import copy
import math
import random
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Optional, Tuple

from ...geonet.service_access_point import Area, GeoBroadcastHST, TrafficClass

DEFAULT_VALIDITY_DURATION_S = 600
"""Default validityDuration (``defaultValidity``, Annex A) in seconds."""
KAF_MAX_RANDOM_DELAY_MS = 150
"""Upper bound of the random part of the T_Forwarding timeout (clause 8.3.2.5)."""
SEQUENCE_NUMBER_MODULO = 65536
"""SequenceNumber ::= INTEGER (0..65535) (ETSI TS 102 894-2)."""
DEFAULT_DESTINATION_RADIUS_M = 1000
"""Radius of the default circular destination area around the event position."""
EARTH_RADIUS_M = 6371000.0


class DenmState(Enum):
    """State of a DENM entry in an ITS-S message table (clauses 8.2.1.6, 8.4.1.6)."""

    ACTIVE = "active"
    CANCELLED = "cancelled"
    NEGATED = "negated"


class DenFailure(Enum):
    """Reason of a failure notification to the ITS-S application (clause 8.2.3)."""

    VALIDITY_EXPIRED = "T_O_Validity expiration time lies in the past"
    UNKNOWN_ACTION_ID = "actionId not found in the ITS-S message tables"
    GENERATION_FAILED = "DENM could not be generated"


class DiscardReason(Enum):
    """Why the receiving ITS-S discarded a DENM (clause 8.4.2)."""

    EXPIRED = "T_R_Validity expiration time lies in the past"
    UNKNOWN_TERMINATION = "termination DENM for an unknown actionId"
    OUTDATED = "referenceTime or detectionTime older than the stored entry"
    REPEATED = "repetition of the stored DENM"
    SSP_INCONSISTENT = "SSP of the signer is not consistent with the cause code"


@dataclass(frozen=True)
class ActionId:
    """actionId: originating stationId and sequenceNumber (clause 6.1.1.1)."""

    station_id: int
    sequence_number: int

    def to_dict(self) -> dict:
        """actionId in the DENMCoder dict format."""
        return {"originatingStationId": self.station_id, "sequenceNumber": self.sequence_number}

    @staticmethod
    def from_dict(value: dict) -> "ActionId":
        """actionId from the DENMCoder dict format."""
        return ActionId(value["originatingStationId"], value["sequenceNumber"])


@dataclass
class DENMRequest:
    """
    Data passed with AppDENM_trigger / AppDENM_update / AppDENM_termination
    (clause 5.3.1, Tables 2 to 4). Container contents use the ``DENMCoder``
    dict representation.

    Attributes
    ----------
    event_position : dict
        ReferencePosition of the event (management.eventPosition).
    detection_time : int or None
        TimestampIts (ms) of the detection; the current time when ``None``.
    situation, location, alacarte : dict or None
        Situation, Location and A La Carte containers. Situation and Location
        are mandatory for new and update DENMs (clause 7.1.1); for an update,
        containers not provided keep their previous content.
    awareness_distance, traffic_direction : str or None
        StandardLength3b / TrafficDirection identifiers (clause 6.1.3.1).
    validity_duration : int or None
        validityDuration in seconds; 600 s when not provided (clause 8.2.1.5).
    repetition_interval, repetition_duration : int or None
        DENM repetition in ms (clause 6.1.2.3); repetition is executed only
        when both are provided and greater than 0.
    transmission_interval : int or None
        transmissionInterval in ms; required for KAF by forwarding ITS-Ss
        (clause 7.1.3).
    station_type : int or None
        stationType; the station's own type when ``None``.
    action_id : ActionId or None
        AppDENM_trigger: actionId assigned by a central entity (Table 2,
        note 10); otherwise the DEN service assigns one.
    destination_area, destination_area_type : Area, GeoBroadcastHST
        GeoBroadcast destination area (clause 6.1.3.4). Defaults to a circle of
        DEFAULT_DESTINATION_RADIUS_M around the event position.
    traffic_class : TrafficClass or None
        Traffic class requested by the application.
    """

    event_position: dict
    detection_time: Optional[int] = None
    situation: Optional[dict] = None
    location: Optional[dict] = None
    alacarte: Optional[dict] = None
    awareness_distance: Optional[str] = None
    traffic_direction: Optional[str] = None
    validity_duration: Optional[int] = None
    repetition_interval: Optional[int] = None
    repetition_duration: Optional[int] = None
    transmission_interval: Optional[int] = None
    station_type: Optional[int] = None
    action_id: Optional[ActionId] = None
    destination_area: Optional[Area] = None
    destination_area_type: GeoBroadcastHST = GeoBroadcastHST.GEOBROADCAST_CIRCLE
    traffic_class: Optional[TrafficClass] = None


@dataclass(frozen=True)
class DENResult:
    """Answer to an application request: the actionId, or a failure notification."""

    action_id: Optional[ActionId] = None
    failure: Optional[DenFailure] = None

    @property
    def ok(self) -> bool:
        """True when the request succeeded (no failure notification)."""
        return self.failure is None


@dataclass(frozen=True)
class OutgoingDENM:
    """A DENM to pass to the networking & transport layer (GeoBroadcast)."""

    denm: dict
    area: Area
    area_type: GeoBroadcastHST
    traffic_class: TrafficClass


@dataclass(frozen=True)
class ReceptionOutcome:
    """Result of the receiving ITS-S operation for one received DENM."""

    accepted: bool
    action_id: ActionId
    state: Optional[DenmState] = None
    reason: Optional[DiscardReason] = None


@dataclass
class _OriginatingEntry:
    denm: dict
    state: DenmState
    validity_expiry: int
    area: Area
    area_type: GeoBroadcastHST
    traffic_class: TrafficClass
    repetition_interval: Optional[int] = None
    repetition_duration: Optional[int] = None
    repetition_end: Optional[int] = None
    next_repetition: Optional[int] = None


@dataclass
class _ReceivingEntry:
    reference_time: int
    detection_time: int
    state: DenmState
    validity_expiry: int
    denm: dict


@dataclass
class _ForwardingEntry:
    denm: dict
    reference_time: int
    validity_expiry: int
    forwarding_timeout: int
    next_forwarding: Optional[int]
    area: Area
    area_type: GeoBroadcastHST
    traffic_class: TrafficClass = field(default_factory=TrafficClass)


def validity_duration_s(management: dict) -> int:
    """validityDuration in seconds; DEFAULT 600 s when absent (Annex A)."""
    value = management.get("validityDuration", DEFAULT_VALIDITY_DURATION_S)
    return value if isinstance(value, int) else DEFAULT_VALIDITY_DURATION_S


def state_of(management: dict) -> DenmState:
    """State conveyed by a DENM: termination absent, isCancellation or isNegation."""
    termination = management.get("termination")
    if termination is None:
        return DenmState.ACTIVE
    return DenmState.CANCELLED if termination == "isCancellation" else DenmState.NEGATED


def inside_area(area: Area, area_type: GeoBroadcastHST, latitude: int, longitude: int) -> bool:
    """
    True when the point (1/10 micro-degree) lies inside or on the border of the
    GeoBroadcast area, using the geometric function F of ETSI EN 302 931
    (F >= 0), with the area rotated by its azimuth angle (degrees from north).
    """
    lat0 = math.radians(area.latitude / 1e7)
    d_north = math.radians((latitude - area.latitude) / 1e7) * EARTH_RADIUS_M
    d_east = math.radians((longitude - area.longitude) / 1e7) * EARTH_RADIUS_M * math.cos(lat0)
    theta = math.radians(area.angle)
    x = d_north * math.cos(theta) + d_east * math.sin(theta)   # along the long axis
    y = -d_north * math.sin(theta) + d_east * math.cos(theta)
    a = max(area.a, 1e-9)
    if area_type == GeoBroadcastHST.GEOBROADCAST_CIRCLE:
        f = 1 - (x / a) ** 2 - (y / a) ** 2
    else:
        b = max(area.b, 1e-9)
        if area_type == GeoBroadcastHST.GEOBROADCAST_ELIP:
            f = 1 - (x / a) ** 2 - (y / b) ** 2
        else:
            f = min(1 - (x / a) ** 2, 1 - (y / b) ** 2)
    return f >= 0


def default_area(event_position: dict) -> Area:
    """Circle of DEFAULT_DESTINATION_RADIUS_M centred on the event position."""
    return Area(latitude=event_position["latitude"], longitude=event_position["longitude"],
                a=DEFAULT_DESTINATION_RADIUS_M, b=0, angle=0)


class DENProtocol:
    """
    DEN service protocol engine for one ITS-S.

    Parameters
    ----------
    station_id : int
        stationId used in the ITS PDU header and in new actionIds.
    station_type : int
        Default stationType of the management container.
    kaf_enabled : bool
        Activate the optional Keep-Alive Forwarding for all received DENMs
        (clause 6.1.4.2). Off by default.
    validate : callable, optional
        Called with every DENM generated for an application request; raising
        an exception turns it into a DENM generation exception (clause 8.2.3.2).
        The DEN service passes the UPER encoder here.
    rng : random.Random, optional
        Source of the KAF random delay (clause 8.3.2.5).
    """

    def __init__(self, station_id: int, station_type: int, kaf_enabled: bool = False,
                 validate: Optional[Callable[[dict], object]] = None,
                 rng: Optional[random.Random] = None) -> None:
        self.station_id = station_id
        self.station_type = station_type
        self.kaf_enabled = kaf_enabled
        self._validate = validate
        self._rng = rng if rng is not None else random.Random()
        self._next_sequence_number = 0
        self.originating: Dict[ActionId, _OriginatingEntry] = {}
        self.receiving: Dict[ActionId, _ReceivingEntry] = {}
        self.forwarding: Dict[ActionId, _ForwardingEntry] = {}
        self.ego_position: Optional[Tuple[int, int]] = None

    def set_seed(self, seed: int) -> None:
        """Re-seed the KAF random delay generator (tests)."""
        self._rng = random.Random(seed)

    def set_next_sequence_number(self, value: int) -> None:
        """Next sequence number to try (tests and diagnostics)."""
        self._next_sequence_number = value % SEQUENCE_NUMBER_MODULO

    # ── Originating ITS-S (clause 8.2) ─────────────────────────────────────

    def trigger(self, request: DENMRequest, now: int) -> Tuple[DENResult, List[OutgoingDENM]]:
        """AppDENM_trigger: generate a new DENM (clause 8.2.2)."""
        detection_time = request.detection_time if request.detection_time is not None else now
        validity = request.validity_duration if request.validity_duration is not None \
            else DEFAULT_VALIDITY_DURATION_S
        expiry = detection_time + validity * 1000
        if expiry < now:
            return DENResult(failure=DenFailure.VALIDITY_EXPIRED), []
        if request.situation is None or request.location is None:
            return DENResult(failure=DenFailure.GENERATION_FAILED), []
        action_id = request.action_id if request.action_id is not None else self._new_action_id()
        management = self._management(action_id, detection_time, now, None, request, validity)
        denm = self._denm(management, request.situation, request.location, request.alacarte)
        return self._store_and_send(action_id, denm, DenmState.ACTIVE, expiry, request,
                                    request.repetition_interval, request.repetition_duration, now)

    def update(self, action_id: ActionId, request: DENMRequest,
               now: int) -> Tuple[DENResult, List[OutgoingDENM]]:
        """AppDENM_update: generate an update DENM for an own event (clause 8.2.2)."""
        entry = self.originating.get(action_id)
        if entry is None:
            return DENResult(failure=DenFailure.UNKNOWN_ACTION_ID), []
        previous = entry.denm["denm"]["management"]
        detection_time = request.detection_time if request.detection_time is not None else now
        validity = request.validity_duration if request.validity_duration is not None \
            else validity_duration_s(previous)
        expiry = detection_time + validity * 1000
        if expiry < now:
            return DENResult(failure=DenFailure.VALIDITY_EXPIRED), []
        reference_time = max(now, previous["referenceTime"] + 1)
        merged = self._merge(previous, request)
        management = self._management(action_id, detection_time, reference_time, None, merged,
                                      validity)
        body = entry.denm["denm"]
        denm = self._denm(management,
                          request.situation if request.situation is not None else body.get("situation"),
                          request.location if request.location is not None else body.get("location"),
                          request.alacarte if request.alacarte is not None else body.get("alacarte"))
        if denm["denm"].get("situation") is None or denm["denm"].get("location") is None:
            return DENResult(failure=DenFailure.GENERATION_FAILED), []
        interval = request.repetition_interval if request.repetition_interval is not None \
            else entry.repetition_interval
        duration = request.repetition_duration if request.repetition_duration is not None \
            else entry.repetition_duration
        if request.destination_area is None:
            request = copy.copy(request)
            request.destination_area = entry.area
            request.destination_area_type = entry.area_type
        if request.traffic_class is None:
            request.traffic_class = entry.traffic_class
        return self._store_and_send(action_id, denm, DenmState.ACTIVE, expiry, request,
                                    interval, duration, reference_time)

    def terminate(self, action_id: ActionId, request: DENMRequest,
                  now: int) -> Tuple[DENResult, List[OutgoingDENM]]:
        """
        AppDENM_termination: cancellation DENM for an own active event, negation
        DENM for an active event received from another ITS-S (clause 8.2.2).
        """
        detection_time = request.detection_time if request.detection_time is not None else now
        validity = request.validity_duration if request.validity_duration is not None \
            else DEFAULT_VALIDITY_DURATION_S
        expiry = detection_time + validity * 1000
        if expiry < now:
            return DENResult(failure=DenFailure.VALIDITY_EXPIRED), []
        own = self.originating.get(action_id)
        received = self.receiving.get(action_id)
        if own is not None and own.state == DenmState.ACTIVE:
            termination, state = "isCancellation", DenmState.CANCELLED
            reference_time = max(now, own.denm["denm"]["management"]["referenceTime"] + 1)
        elif received is not None and received.state == DenmState.ACTIVE:
            termination, state = "isNegation", DenmState.NEGATED
            reference_time = received.reference_time
        else:
            return DENResult(failure=DenFailure.UNKNOWN_ACTION_ID), []
        management = self._management(action_id, detection_time, reference_time, termination,
                                      request, validity)
        denm = self._denm(management, None, None, None)
        return self._store_and_send(action_id, denm, state, expiry, request,
                                    request.repetition_interval, request.repetition_duration,
                                    reference_time)

    def update_station_id(self, station_id: int) -> None:
        """
        Pseudonym change (clause 6.1.1.2): update the actionIds and ITS PDU
        headers of all DENMs generated and stored by this ITS-S.
        """
        old = self.station_id
        self.station_id = station_id
        rekeyed: Dict[ActionId, _OriginatingEntry] = {}
        for action_id, entry in self.originating.items():
            entry.denm["header"]["stationId"] = station_id
            if action_id.station_id == old:
                action_id = ActionId(station_id, action_id.sequence_number)
                entry.denm["denm"]["management"]["actionId"] = action_id.to_dict()
            rekeyed[action_id] = entry
        self.originating = rekeyed
        for entry in self.forwarding.values():
            entry.denm["header"]["stationId"] = station_id

    # ── Receiving ITS-S (clause 8.4) and KAF (clause 8.3) ──────────────────

    def receive(self, denm: dict, now: int, area: Optional[Area] = None,
                area_type: Optional[GeoBroadcastHST] = None,
                ssp_consistent: bool = True) -> ReceptionOutcome:
        """
        Receiving ITS-S operation for one decoded DENM (clause 8.4.2), followed by
        the KAF operation (clause 8.3.3) when KAF is enabled.

        ``area`` / ``area_type`` are the GeoBroadcast destination area of the
        packet, used by KAF. ``ssp_consistent`` is the result of the SSP check
        of the signer (clause 6.2.2.2); True when security is not used.
        """
        management = denm["denm"]["management"]
        action_id = ActionId.from_dict(management["actionId"])
        reference_time = management["referenceTime"]
        detection_time = management["detectionTime"]
        state = state_of(management)
        expiry = detection_time + validity_duration_s(management) * 1000
        if expiry < now:
            return ReceptionOutcome(False, action_id, reason=DiscardReason.EXPIRED)

        entry = self.receiving.get(action_id)
        if entry is None:
            if state != DenmState.ACTIVE:
                return ReceptionOutcome(False, action_id, reason=DiscardReason.UNKNOWN_TERMINATION)
            if not ssp_consistent:
                return ReceptionOutcome(False, action_id, reason=DiscardReason.SSP_INCONSISTENT)
            self.receiving[action_id] = _ReceivingEntry(reference_time, detection_time, state,
                                                        expiry, denm)
            outcome = ReceptionOutcome(True, action_id, state=state)
        elif reference_time < entry.reference_time or detection_time < entry.detection_time:
            return ReceptionOutcome(False, action_id, reason=DiscardReason.OUTDATED)
        elif (reference_time == entry.reference_time and detection_time == entry.detection_time
              and state == entry.state):
            outcome = ReceptionOutcome(False, action_id, reason=DiscardReason.REPEATED)
        elif not ssp_consistent:
            return ReceptionOutcome(False, action_id, reason=DiscardReason.SSP_INCONSISTENT)
        else:
            entry.reference_time = reference_time
            entry.detection_time = detection_time
            entry.state = state
            entry.validity_expiry = expiry
            entry.denm = denm
            outcome = ReceptionOutcome(True, action_id, state=state)

        if self.kaf_enabled:
            self._kaf_receive(action_id, denm, now, area, area_type)
        return outcome

    def _kaf_receive(self, action_id: ActionId, denm: dict, now: int,
                     area: Optional[Area], area_type: Optional[GeoBroadcastHST]) -> None:
        """
        KAF operation upon reception (clause 8.3.3).

        Step 1 of clause 8.3.3 reads "check if the termination exists in the
        received DENM; if yes, continue, otherwise omit further steps". Taken
        literally, only terminated DENMs would be forwarded, which contradicts
        clause 6.1.4.2 and the test purposes TP/DEN/KAFW/BV-01 (forwarding of a
        DENM without termination) and TP/DEN/KAFW/BV-07 (forwarding of a negation
        DENM with termination unchanged), both in ETSI TS 102 869-2 V1.6.1. The
        same wording is in ETSI EN 302 637-3 V1.3.1. Both kinds are therefore
        forwarded here.
        """
        management = denm["denm"]["management"]
        reference_time = management["referenceTime"]
        entry = self.forwarding.get(action_id)
        if entry is not None:
            same_state = state_of(entry.denm["denm"]["management"]) == state_of(management)
            if reference_time == entry.reference_time and same_state:
                # Same DENM seen again (originator or another forwarder): restart.
                if entry.next_forwarding is not None:
                    entry.next_forwarding = now + entry.forwarding_timeout
                return
            if reference_time < entry.reference_time:
                return
            # Equal referenceTime with a state change (e.g. a negation, which
            # keeps the latest referenceTime) updates the entry, as the
            # receiving ITS-S rules do (clauses 8.3.2.6 and 8.4.1.6).
        validity_ms = validity_duration_s(management) * 1000
        f_validity = management["detectionTime"] + validity_ms
        transmission_interval = management.get("transmissionInterval")
        if transmission_interval is None:
            # No KAF requested by the originator (clause 7.1.3): stop forwarding.
            self.forwarding.pop(action_id, None)
            return
        timeout = 2 * transmission_interval + self._rng.randint(0, KAF_MAX_RANDOM_DELAY_MS)
        timeout = min(timeout, validity_ms)
        regenerated = copy.deepcopy(denm)
        regenerated["header"] = {"protocolVersion": 2, "messageId": 1, "stationId": self.station_id}
        if area is None:
            area, area_type = default_area(management["eventPosition"]), \
                GeoBroadcastHST.GEOBROADCAST_CIRCLE
        self.forwarding[action_id] = _ForwardingEntry(
            denm=regenerated, reference_time=reference_time, validity_expiry=f_validity,
            forwarding_timeout=timeout, next_forwarding=now + timeout, area=area,
            area_type=area_type or GeoBroadcastHST.GEOBROADCAST_CIRCLE)

    def set_ego_position(self, latitude: int, longitude: int) -> None:
        """Own position (1/10 micro-degree), used by KAF to check the area."""
        self.ego_position = (latitude, longitude)

    # ── Timers ─────────────────────────────────────────────────────────────

    def tick(self, now: int) -> Tuple[List[OutgoingDENM], List[ActionId]]:
        """
        Fire every timer expired at ``now``. Returns the DENMs to send
        (repetitions and KAF forwards) and the actionIds removed from the
        receiving ITS-S message table (T_R_Validity expiry), which the
        application may be notified about (clause 8.4.2).
        """
        outgoing: List[OutgoingDENM] = []
        for action_id, entry in list(self.originating.items()):
            if entry.validity_expiry <= now:             # T_O_Validity
                del self.originating[action_id]
                continue
            if entry.next_repetition is not None and entry.next_repetition <= now:   # T_Repetition
                outgoing.append(OutgoingDENM(entry.denm, entry.area, entry.area_type,
                                             entry.traffic_class))
                nxt = entry.next_repetition + entry.repetition_interval  # type: ignore[operator]
                while nxt <= now:
                    nxt += entry.repetition_interval  # type: ignore[operator]
                entry.next_repetition = nxt
            if entry.next_repetition is not None and entry.repetition_end is not None \
                    and entry.next_repetition > entry.repetition_end:  # T_RepetitionDuration
                entry.next_repetition = None
        expired = [a for a, e in self.receiving.items() if e.validity_expiry <= now]
        for action_id in expired:                          # T_R_Validity
            del self.receiving[action_id]
        for action_id, fwd in list(self.forwarding.items()):
            if fwd.validity_expiry <= now:                 # T_F_Validity
                del self.forwarding[action_id]
                continue
            if fwd.next_forwarding is not None and fwd.next_forwarding <= now:   # T_Forwarding
                if self.ego_position is None or not inside_area(
                        fwd.area, fwd.area_type, *self.ego_position):
                    fwd.next_forwarding = None             # outside: stop forwarding
                    continue
                outgoing.append(OutgoingDENM(fwd.denm, fwd.area, fwd.area_type, fwd.traffic_class))
                fwd.next_forwarding = now + fwd.forwarding_timeout
        return outgoing, expired

    def next_deadline(self) -> Optional[int]:
        """Earliest pending timer expiry, or None when no timer is running."""
        times: List[int] = []
        for entry in self.originating.values():
            times.append(entry.validity_expiry)
            if entry.next_repetition is not None:
                times.append(entry.next_repetition)
        times.extend(e.validity_expiry for e in self.receiving.values())
        for fwd in self.forwarding.values():
            times.append(fwd.validity_expiry)
            if fwd.next_forwarding is not None:
                times.append(fwd.next_forwarding)
        return min(times) if times else None

    # ── Helpers ────────────────────────────────────────────────────────────

    def _new_action_id(self) -> ActionId:
        """Unused actionId (clause 6.1.1.1): next sequence number not in use."""
        for _ in range(SEQUENCE_NUMBER_MODULO):
            sequence_number = self._next_sequence_number
            self._next_sequence_number = (sequence_number + 1) % SEQUENCE_NUMBER_MODULO
            candidate = ActionId(self.station_id, sequence_number)
            if candidate not in self.originating:
                return candidate
        raise RuntimeError("all 65536 sequence numbers are in use")

    def _management(self, action_id: ActionId, detection_time: int, reference_time: int,
                    termination: Optional[str], request: DENMRequest, validity: int) -> dict:
        management = {
            "actionId": action_id.to_dict(),
            "detectionTime": detection_time,
            "referenceTime": reference_time,
            "eventPosition": request.event_position,
            "validityDuration": validity,
            "stationType": request.station_type if request.station_type is not None
            else self.station_type,
        }
        if termination is not None:
            management["termination"] = termination
        if request.awareness_distance is not None:
            management["awarenessDistance"] = request.awareness_distance
        if request.traffic_direction is not None:
            management["trafficDirection"] = request.traffic_direction
        if request.transmission_interval is not None:
            management["transmissionInterval"] = request.transmission_interval
        return management

    @staticmethod
    def _merge(previous: dict, request: DENMRequest) -> DENMRequest:
        """Update request in which fields not provided keep their previous value."""
        merged = copy.copy(request)
        if merged.awareness_distance is None:
            merged.awareness_distance = previous.get("awarenessDistance")
        if merged.traffic_direction is None:
            merged.traffic_direction = previous.get("trafficDirection")
        if merged.transmission_interval is None:
            merged.transmission_interval = previous.get("transmissionInterval")
        if merged.station_type is None:
            merged.station_type = previous.get("stationType")
        return merged

    def _denm(self, management: dict, situation: Optional[dict], location: Optional[dict],
              alacarte: Optional[dict]) -> dict:
        payload: dict = {"management": management}
        if situation is not None:
            payload["situation"] = situation
        if location is not None:
            payload["location"] = location
        if alacarte is not None:
            payload["alacarte"] = alacarte
        return {"header": {"protocolVersion": 2, "messageId": 1, "stationId": self.station_id},
                "denm": payload}

    def _store_and_send(self, action_id: ActionId, denm: dict, state: DenmState, expiry: int,
                        request: DENMRequest, interval: Optional[int], duration: Optional[int],
                        reference_time: int) -> Tuple[DENResult, List[OutgoingDENM]]:
        if self._validate is not None:
            try:
                self._validate(denm)
            except Exception:  # pylint: disable=broad-except
                return DENResult(failure=DenFailure.GENERATION_FAILED), []
        area = request.destination_area if request.destination_area is not None \
            else default_area(request.event_position)
        traffic_class = request.traffic_class if request.traffic_class is not None \
            else TrafficClass()
        entry = _OriginatingEntry(denm=denm, state=state, validity_expiry=expiry, area=area,
                                  area_type=request.destination_area_type,
                                  traffic_class=traffic_class,
                                  repetition_interval=interval, repetition_duration=duration)
        if interval and duration and interval > 0 and duration > 0:
            # T_Repetition and T_RepetitionDuration not greater than validityDuration
            validity_ms = expiry - denm["denm"]["management"]["detectionTime"]
            interval = min(interval, validity_ms)
            duration = min(duration, validity_ms)
            entry.repetition_interval = interval
            entry.repetition_end = reference_time + duration
            entry.next_repetition = reference_time + interval
            if entry.next_repetition > entry.repetition_end:
                entry.next_repetition = None
        self.originating[action_id] = entry
        outgoing = [OutgoingDENM(denm, area, request.destination_area_type, traffic_class)]
        return DENResult(action_id=action_id), outgoing
