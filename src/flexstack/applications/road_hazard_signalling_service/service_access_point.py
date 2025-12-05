from __future__ import annotations
from typing import TYPE_CHECKING
from dataclasses import dataclass, field
from enum import Enum
from ...facilities.local_dynamic_map.ldm_classes import ReferencePosition, TimestampIts
if TYPE_CHECKING:
    from .emergency_vehicle_approaching_service import (
        EmergencyVehicleApproachingService,
    )


@dataclass(frozen=True)
class RelevanceArea:
    """
    Class to define the relevance area of the DENM.

    Parameters
    ----------
    relevance_distance : int
        Relevance distance from the vehicle to a traffic hazard
        or to its future position.
    relevance_direction : int
        Relevance direction from the vehicle to a traffic hazard
        or to its future position.
    """
    relevance_distance: int
    relevance_direction: int


class PriorityLevel(Enum):
    """
    Class to define the priority levels of the DENMs.

    Parameters
    ----------
    AWARENESS : int
    WARNING : int
    PRECRASH : int
    """

    AWARENESS = 2
    WARNING = 1
    PRECRASH = 0


@dataclass(frozen=True)
class DENRequest:
    """
    Class for storing the data of the DENM.

    Parameters
    ----------
    denm_interval : int
        Interval between two consecutive DENM messages in ms.
    priority_level : int
        Priority level of the DENM message.
    relevance_distance : str
        Relevance distance where the DENMs need to be received. [0] less than 50m
                                                                [1] -> 100m // [2] -> 200m // [3] -> 500m
    relevance_traffic_direction : str
        Relevance direction where the DENMs need to be received. [0] -> all traffic directions
                                                                 [1] -> upstream traffic    [2] -> downstream traffic
                                                                 [3] -> opposite direction traffic
    DENMTermination : str
        Type of termination message: isCancellation(0) or isNegation (1)
    detection_time : int
        Time of the detection of the hazard.
    time_period : int
        Max duration of the hazard.
    quality : int
        Quality level of the provided information. Values from 0 to 7. 7 = highest quality.
    event_position : Dict
        Position of the hazard. Contains Latitude, Longitude, Elevation and confidence values.
    heading : int
        Heading of the vehicle. Values from 0 to 3601. 0 = North.
    confidence : int
        Confidence level on provided data. % values from 0 to 100. 101 = not available.
    traceID : int
        [Optional] Provides the Trace ID enabling the providion of several traces.
    waypoints : Dict
        [Optional] Indication of the path followed by the vehicles before detecting the hazard
    rhs_cause_code : int
        rhs cause code defining the emergency vehicle approaching.
    rhs_subcause_code : int
        [OPTIONAL] RHS subcause code of the emergency vehicle approaching.
    rhs_event_speed : int
        Speed of the emergency vehicle.
    rhs_vehicle_type : int
        Type of emergency vehicle approaching. From ISO 3833, "Road vehicle Type - Terms and definitions".
        passengerCar = 0  //  minibus = 12
    rhs_trace : int
        [OPTIONAL] Set of planned waypoints for the vehicle.
    rhs_relevance_area : RelevanceArea
        Relevance area for the emergency vehicle approaching use case.
        Defines the farthest future position of the emergency vehicle.
    """
    denm_interval: int = 100
    priority_level: PriorityLevel = PriorityLevel.WARNING
    # Data elements values
    detection_time: int = 0
    time_period: int = 0
    quality: int = 7
    event_position: dict = field(default_factory=dict)
    heading: int = 0  # or N/A
    confidence: int = 2  # or N/A
    # traceID = N/A
    # waypoints = N/A
    # Emergency Vehicle Approaching specific data elements
    relevance_distance: str | None = None
    relevance_traffic_direction: str | None = None
    rhs_cause_code: str | None = None
    rhs_subcause_code: int | None = None
    rhs_event_speed: int | None = None
    rhs_vehicle_type: int | None = None
    # Longitudinal Collision Risk Warning specific data elements
    lcrw_cause_code: str | None = None
    lcrw_subcause_code: int | None = None

    @staticmethod
    def with_emergency_vehicle_approaching(
        service: "EmergencyVehicleApproachingService"
    ) -> DENRequest:
        """
        Fulfills the DENM Request for Emergency Vehicle Approaching Service

        Parameters
        ----------
        service : EmergencyVehicleApproachingService
            Emergency Vehicle Approaching Service object
        """
        return DENRequest(
            denm_interval=service.denm_interval,
            priority_level=service.priority_level,
            # Relevance area parameters
            relevance_distance="lessThan200m",
            relevance_traffic_direction="upstreamTraffic",
            # DENMTermination = "isCancellation"
            # Data elements values
            detection_time=service.detection_time,
            time_period=service.denm_duration,
            event_position=service.event_position,
            # Specific use cases data elemenets
            rhs_cause_code="emergencyVehicleApproaching95",
            rhs_subcause_code=1,  # [OPTIONAL]
            rhs_event_speed=30,  # 108 km/h
            rhs_vehicle_type=0,
            # rhs_relevance_area=RelevanceArea(4, 0),
        )

    @staticmethod
    def with_collision_risk_warning(
        detection_time: TimestampIts, event_position: ReferencePosition
    ) -> DENRequest:
        """
        Fulfills the DENM Request for Longitudinal Collision Risk Warnings

        Parameters
        ----------
        detection_time : TimestampIts
            Timestamp of the detection of the hazard.
        event_position : ReferencePosition
            Position of the hazard.
        """
        return DENRequest(
            priority_level=PriorityLevel.WARNING,
            detection_time=detection_time.timestamp_its,
            event_position=event_position.to_dict(),
            lcrw_cause_code="collisionRisk97",  # Collision risk
            lcrw_subcause_code=4  # Collision risk involving VRU
        )
