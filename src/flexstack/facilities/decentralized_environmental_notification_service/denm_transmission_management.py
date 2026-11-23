"""
DENM transmission: originating ITS-S operation of the DEN service
(ETSI TS 103 831 V2.3.1 (2025-11), clauses 5.3.1 and 8.2).

The protocol rules live in :mod:`.den_protocol`; this module turns application
requests into protocol operations and hands the resulting DENMs to BTP
(port 2002, GeoBroadcast, clause 6.1.3.4 / ETSI TS 103 836-5-1).

Two request styles are supported:

* the standard requests :meth:`DENMTransmissionManagement.trigger_denm`,
  :meth:`~DENMTransmissionManagement.update_denm` and
  :meth:`~DENMTransmissionManagement.terminate_denm` (AppDENM_trigger,
  AppDENM_update, AppDENM_termination) taking a :class:`DENMRequest`;
* the road-hazard-signalling ``DENRequest`` used by the applications in
  ``flexstack.applications.road_hazard_signalling_service``, converted to an
  AppDENM_trigger with repetition (:meth:`request_denm_sending`).
"""

from __future__ import annotations

import logging
import math
import threading
from typing import Callable, Optional

from ...utils.time_service import TimeService
from ..ca_basic_service.cam_transmission_management import VehicleData
from ...geonet.service_access_point import (
    GeoBroadcastHST, HeaderType, PacketTransportType, TrafficClass,
)
from .denm_coder import DENMCoder
from ...btp.router import Router as BTPRouter
from ...btp.service_access_point import BTPDataRequest, CommonNH, CommunicationProfile
from ...security.security_profiles import SecurityProfile
from .denm_ssp import permissions_bitmap
from ...applications.road_hazard_signalling_service.service_access_point import (
    DENRequest,
)
from .den_protocol import (
    ActionId,
    DENMRequest,
    DENProtocol,
    DENResult,
    OutgoingDENM,
    default_area,
)

DENM_BTP_PORT = 2002
"""Well-known BTP port of the DEN service (ETSI TS 103 248)."""
DENM_ITS_AID = 37
"""ITS-AID of the DEN service (ETSI TS 102 965)."""

# Release 1 relevance names used by DENRequest -> Release 2 management fields.
_TRAFFIC_DIRECTION = {
    "allTrafficDirections": "allTrafficDirections",
    "upstreamTraffic": "sameAsReferenceDirection-upstreamOfReferencePosition",
    "downstreamTraffic": "sameAsReferenceDirection-downstreamOfReferencePosition",
    "oppositeTraffic": "oppositeToReferenceDirection",
}


def _transmission_interval(interval_ms: int) -> int:
    """DeltaTimeMilliSecondPositive range 1..10000 ms (CDD)."""
    return max(1, min(10000, int(interval_ms)))


class DecentralizedEnvironmentalNotificationMessage:
    """
    Builder of the containers of a road-hazard DENM from a ``DENRequest``.

    Attributes
    ----------
    denm : dict
        DENM in the dict format of the DENMCoder (DENM-PDU-Descriptions v2.3).
    """

    def __init__(self) -> None:
        self.denm = self.generate_white_denm()

    def generate_white_denm(self) -> dict:
        """
        A new (non-terminated) DENM with default values: no termination
        component (clause 8.2.1.4) and the default validityDuration of 600 s.
        """
        return {
            "header": {"protocolVersion": 2, "messageId": 1, "stationId": 0},
            "denm": {
                "management": {
                    "actionId": {"originatingStationId": 0, "sequenceNumber": 0},
                    "detectionTime": 0,
                    "referenceTime": 0,
                    "eventPosition": {
                        "latitude": 900000001,
                        "longitude": 1800000001,
                        "positionConfidenceEllipse": {
                            "semiMajorConfidence": 4095,
                            "semiMinorConfidence": 4095,
                            "semiMajorOrientation": 3601,
                        },
                        "altitude": {
                            "altitudeValue": 800001,
                            "altitudeConfidence": "unavailable",
                        },
                    },
                    "validityDuration": 600,
                    "stationType": 0,
                }
            },
        }

    def fullfill_with_denrequest(self, request: DENRequest) -> None:
        """
        Fill the DENM with the DENRequest data of the Road Hazard Signalling
        application (Emergency Vehicle Approaching).
        """
        management = self.denm["denm"]["management"]
        management["detectionTime"] = request.detection_time
        management["referenceTime"] = int(TimeService.timestamp_its())
        management["transmissionInterval"] = _transmission_interval(request.denm_interval)
        if request.time_period:
            management["validityDuration"] = max(1, math.ceil(request.time_period / 1000))
        if request.relevance_distance is not None:
            management["awarenessDistance"] = request.relevance_distance
        if request.relevance_traffic_direction is not None:
            management["trafficDirection"] = _TRAFFIC_DIRECTION.get(
                request.relevance_traffic_direction, request.relevance_traffic_direction)
        management["eventPosition"] = request.event_position
        management["stationType"] = request.rhs_vehicle_type

        self.denm["denm"]["situation"] = {
            "informationQuality": request.quality,
            "eventType": {
                "ccAndScc": (request.rhs_cause_code, request.rhs_subcause_code)
            },
        }
        self.denm["denm"]["location"] = {
            "eventSpeed": {
                "speedValue": request.rhs_event_speed,
                "speedConfidence": int(request.confidence / 2),
            },
            "eventPositionHeading": {
                "value": request.heading,
                "confidence": request.confidence,
            },
            "detectionZonesToEventPosition": [
                [
                    {
                        "pathPosition": {
                            "deltaLatitude": 131072,
                            "deltaLongitude": 131072,
                            "deltaAltitude": 12800,
                        }
                    }
                ]
            ],
        }

    def fullfill_with_collision_risk_warning(self, request: DENRequest) -> None:
        """
        Fill the DENM with the DENRequest data of the Longitudinal Collision
        Risk Warning application.
        """
        management = self.denm["denm"]["management"]
        management["detectionTime"] = request.detection_time
        management["referenceTime"] = int(TimeService.timestamp_its())
        management["transmissionInterval"] = _transmission_interval(request.denm_interval)
        management["eventPosition"] = request.event_position

        self.denm["denm"]["situation"] = {
            "informationQuality": request.quality,
            "eventType": {
                "ccAndScc": (request.lcrw_cause_code, request.lcrw_subcause_code)
            },
        }
        self.denm["denm"]["location"] = {
            "detectionZonesToEventPosition": [
                [
                    {
                        "pathPosition": {
                            "deltaLatitude": 131072,
                            "deltaLongitude": 131072,
                            "deltaAltitude": 12800,
                        }
                    }
                ]
            ],
        }

    def fullfill_with_vehicle_data(self, vehicle_data: VehicleData) -> None:
        """Fill the ITS PDU header, actionId station and stationType from the vehicle data."""
        self.denm["header"]["stationId"] = vehicle_data.station_id
        self.denm["denm"]["management"]["stationType"] = vehicle_data.station_type
        self.denm["denm"]["management"]["actionId"]["originatingStationId"] = \
            vehicle_data.station_id

    def to_denm_request(self, repetition_interval: Optional[int] = None,
                        repetition_duration: Optional[int] = None) -> DENMRequest:
        """AppDENM_trigger request carrying this message's content."""
        management = self.denm["denm"]["management"]
        return DENMRequest(
            event_position=management["eventPosition"],
            detection_time=management["detectionTime"],
            situation=self.denm["denm"].get("situation"),
            location=self.denm["denm"].get("location"),
            alacarte=self.denm["denm"].get("alacarte"),
            awareness_distance=management.get("awarenessDistance"),
            traffic_direction=management.get("trafficDirection"),
            validity_duration=management.get("validityDuration"),
            repetition_interval=repetition_interval,
            repetition_duration=repetition_duration,
            transmission_interval=management.get("transmissionInterval"),
            station_type=management.get("stationType"),
        )


class DENMTransmissionManagement:
    """
    Originating ITS-S operation of the DEN service (clause 8.2).

    Parameters
    ----------
    btp_router : BTPRouter
        BTP router used to send the DENMs.
    denm_coder : DENMCoder
        UPER coder.
    vehicle_data : VehicleData
        stationId and stationType of this ITS-S.
    protocol : DENProtocol, optional
        Shared protocol engine. When omitted a private engine is created; the
        DEN service passes the engine it also uses for reception and timers.
    lock : threading.RLock, optional
        Lock protecting the engine, shared with reception and the scheduler.
    on_timers_changed : callable, optional
        Called after every request so that the scheduler re-evaluates its next
        deadline (repetition timers).
    """

    def __init__(
        self, btp_router: BTPRouter, denm_coder: DENMCoder, vehicle_data: VehicleData,
        protocol: Optional[DENProtocol] = None, lock: Optional[threading.RLock] = None,
        on_timers_changed: Optional[Callable[[], None]] = None,
        *, clock: Optional[Callable[[], int]] = None,
    ) -> None:
        self.logging = logging.getLogger("denm_service")
        self.btp_router: BTPRouter = btp_router
        self.vehicle_data = vehicle_data
        self.denm_coder = denm_coder
        self.protocol = protocol if protocol is not None else DENProtocol(
            vehicle_data.station_id, vehicle_data.station_type, validate=denm_coder.validate)
        self.lock = lock if lock is not None else threading.RLock()
        self._on_timers_changed = on_timers_changed
        self._clock: Callable[[], int] = clock if clock is not None \
            else (lambda: int(TimeService.timestamp_its()))

    # ── Standard application requests (clause 5.3.1) ──────────────────────

    def trigger_denm(self, request: DENMRequest) -> DENResult:
        """AppDENM_trigger: returns the new actionId or a failure notification."""
        with self.lock:
            result, outgoing = self.protocol.trigger(request, self._clock())
        return self._dispatch(result, outgoing)

    def update_denm(self, action_id: ActionId, request: DENMRequest) -> DENResult:
        """AppDENM_update for an event triggered by this ITS-S."""
        with self.lock:
            result, outgoing = self.protocol.update(action_id, request,
                                                    self._clock())
        return self._dispatch(result, outgoing)

    def terminate_denm(self, action_id: ActionId, request: DENMRequest) -> DENResult:
        """AppDENM_termination: cancellation (own event) or negation (received event)."""
        with self.lock:
            result, outgoing = self.protocol.terminate(action_id, request,
                                                       self._clock())
        return self._dispatch(result, outgoing)

    # ── Road hazard signalling requests (DENRequest) ───────────────────────

    def request_denm_sending(self, denm_request: DENRequest) -> DENResult:
        """
        Emergency Vehicle Approaching: AppDENM_trigger repeated every
        ``denm_interval`` ms for ``time_period`` ms (DENM repetition, clause
        6.1.2.3), with transmissionInterval set so receivers may keep it alive.
        """
        message = DecentralizedEnvironmentalNotificationMessage()
        message.fullfill_with_vehicle_data(self.vehicle_data)
        message.fullfill_with_denrequest(denm_request)
        return self.trigger_denm(message.to_denm_request(
            repetition_interval=denm_request.denm_interval,
            repetition_duration=denm_request.time_period))

    def trigger_denm_messages(self, denm_request: DENRequest) -> DENResult:
        """Alias of :meth:`request_denm_sending` (kept for compatibility)."""
        return self.request_denm_sending(denm_request)

    def send_collision_risk_warning_denm(self, denm_request: DENRequest) -> DENResult:
        """Longitudinal Collision Risk Warning: a single new DENM, no repetition."""
        message = DecentralizedEnvironmentalNotificationMessage()
        message.fullfill_with_vehicle_data(self.vehicle_data)
        message.fullfill_with_collision_risk_warning(denm_request)
        return self.trigger_denm(message.to_denm_request())

    # ── Transmission ───────────────────────────────────────────────────────

    def _dispatch(self, result: DENResult, outgoing: list) -> DENResult:
        for item in outgoing:
            self.transmit(item)
        if not result.ok:
            self.logging.warning("DEN service request failed: %s", result.failure)
        if self._on_timers_changed is not None:
            self._on_timers_changed()
        return result

    def transmit(self, outgoing: OutgoingDENM) -> None:
        """Encode a DENM and pass it to BTP-B port 2002 over GeoBroadcast."""
        data = self.denm_coder.encode(outgoing.denm)
        request = BTPDataRequest(
            btp_type=CommonNH.BTP_B,
            destination_port=DENM_BTP_PORT,
            gn_packet_transport_type=PacketTransportType(
                header_type=HeaderType.GEOBROADCAST,
                header_subtype=outgoing.area_type,
            ),
            gn_area=outgoing.area,
            communication_profile=CommunicationProfile.UNSPECIFIED,
            traffic_class=outgoing.traffic_class,
            security_profile=SecurityProfile.DECENTRALIZED_ENVIRONMENTAL_NOTIFICATION_MESSAGE,
            its_aid=DENM_ITS_AID,
            # Sender-side SSP check (clause 6.2.2.2): sign only with an AT
            # granting the cause code of this DENM.
            security_permissions=permissions_bitmap(outgoing.denm),
            data=data,
            length=len(data),
        )
        self.btp_router.btp_data_request(request)
        management = outgoing.denm["denm"]["management"]
        self.logging.info(
            "Sent DENM actionId=%s referenceTime=%s termination=%s",
            management["actionId"], management["referenceTime"], management.get("termination"))

    def transmit_denm(self, denm_to_send: DecentralizedEnvironmentalNotificationMessage) -> None:
        """Send a pre-built DENM once, bypassing the protocol tables (kept for compatibility)."""
        position = denm_to_send.denm["denm"]["management"]["eventPosition"]
        area = default_area(position)
        self.transmit(OutgoingDENM(denm_to_send.denm, area,
                                   GeoBroadcastHST.GEOBROADCAST_CIRCLE, TrafficClass()))
