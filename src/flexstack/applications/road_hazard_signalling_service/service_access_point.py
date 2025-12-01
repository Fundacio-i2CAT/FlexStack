from __future__ import annotations
from enum import Enum
from typing import TYPE_CHECKING
from ...facilities.local_dynamic_map.ldm_classes import ReferencePosition, TimestampIts

if TYPE_CHECKING:
    from .emergency_vehicle_approaching_service import (
        EmergencyVehicleApproachingService,
    )


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

    def __init__(self, r_distance: int, r_direction: int) -> None:
        """
        Initialize the relevance area of the DENM.

        Parameters
        ----------
        r_distance : int
            Relevance distance from the vehicle to a traffic hazard
            or to its future position.
        r_direction : int
            Relevance direction from the vehicle to a traffic hazard
            or to its future position.
        """
        self.relevance_distance = r_distance
        self.relevance_direction = r_direction


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

    def __init__(self) -> None:
        """
        Initialize the specific data of the DENM.
        """

        self.denm_interval = 100
        self.priority_level = 1
        # Data elements values
        self.detection_time = 0
        self.time_period = 0
        self.quality = 7
        self.event_position = {}
        self.heading = 0  # or N/A
        self.confidence = 2  # or N/A
        # self.traceID = N/A
        # self.waypoints = N/A
        # Emergency Vehicle Approaching specific data elements
        self.relevance_distance: str = None
        self.relevance_traffic_direction: str = None
        self.rhs_cause_code: str = None
        self.rhs_subcause_code: int = None
        self.rhs_event_speed: int = None
        self.rhs_vehicle_type: int = None
        # Longitudinal Collision Risk Warning specific data elements
        self.lcrw_cause_code: str = None
        self.lcrw_subcause_code: int = None

    def with_emergency_vehicle_approaching(
        self, service: "EmergencyVehicleApproachingService"
    ) -> None:
        """
        Fulfills the DENM Request for Emergency Vehicle Approaching Service

        Parameters
        ----------
        service : EmergencyVehicleApproachingService
            Emergency Vehicle Approaching Service object
        """
        self.denm_interval = service.denm_interval
        self.priority_level = service.priority_level

        # Relevance area parameters
        self.relevance_distance = "lessThan200m"
        self.relevance_traffic_direction = "upstreamTraffic"
        # self.DENMTermination = "isCancellation"

        # Data elements values
        self.detection_time = service.detection_time
        self.time_period = service.denm_duration
        self.event_position = service.event_position

        # Specific use cases data elemenets
        self.rhs_cause_code = "emergencyVehicleApproaching95"
        self.rhs_subcause_code = 1  # [OPTIONAL]
        self.rhs_event_speed = 30  # 108 km/h
        self.rhs_vehicle_type = 0
        # self.rhs_relevance_area = RelevanceArea(4, 0)

    def with_collision_risk_warning(
        self, detection_time: TimestampIts, event_position: ReferencePosition
    ) -> None:
        """
        Fulfills the DENM Request for Longitudinal Collision Risk Warnings

        Parameters
        ----------
        detection_time : TimestampIts
            Timestamp of the detection of the hazard.
        event_position : ReferencePosition
            Position of the hazard.
        """
        self.priority_level = 1
        self.detection_time = detection_time.timestamp_its
        self.event_position = event_position.to_dict()
        self.lcrw_cause_code = "collisionRisk97"  # Collision risk
        self.lcrw_subcause_code = 4  # Collision risk involving VRU
