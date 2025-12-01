from __future__ import annotations
from .service_access_point import DENRequest, PriorityLevel
from ...facilities.local_dynamic_map.ldm_facility import LDMFacility
from ...facilities.decentralized_environmental_notification_service.den_service import (
    DecentralizedEnvironmentalNotificationService,
)
from ...btp.router import Router as BTPRouter
from ...utils.time_service import TimeService


class EmergencyVehicleApproachingService:
    """
    The Emergency Vehicle Approaching Service is the class that triggers a
    DENM transmission notifying about the approach of an emergency vehicle.
    It's an example of a partial implementation of the Road Hazard Signalling (RHS)
    Application.
    It expects to receive the position of the approaching vehicle and its characterstics
    to trigger the periodic and temporary transmission of DENM messages.

    Attributes
    ----------
    den_service : DecentralizedEnvironmentalNotificationService
        Reference to the DEN Basic Service for handling DENM transmissions.
    denm_interval : int
        Time interval (in milliseconds) between two consecutive DENM messages.
    denm_duration : int
        Total duration (in milliseconds) for which DENM messages will be transmitted.
    priority_level : int
        Priority level of the DENM messages being sent.
    detection_time : int
        Timestamp of the hazard detection event in milliseconds since 2004-01-01T00:00:00Z.
    event_position : dict
        Dictionary containing the geographic position of the hazard, including latitude, longitude,
        altitude, and confidence values.
    """

    def __init__(
        self, den_service: DecentralizedEnvironmentalNotificationService, duration: int = 10000
    ) -> None:
        """
        Initialize the Emergency Vehicle Approaching Service.

        Parameters
        ----------
        den_service : DecentralizedEnvironmentalNotificationService
            Decentralized Environmental Notification Service
        duration : int, optional
            Duration in milliseconds for which DENM messages will be transmitted
            (default is 10 seconds).
        """
        self.den_service = den_service
        self.denm_duration = duration  # [ms] 10 seconds
        self.denm_interval = 1000
        self.priority_level = PriorityLevel.WARNING
        # Get DENM data to simulate the hazard detection
        self.detection_time = TimeService.timestamp_its()
        self.event_position = {
            "latitude": 900000001,
            "longitude": 1800000001,
            "positionConfidenceEllipse": {
                "semiMajorConfidence": 4095,
                "semiMinorConfidence": 4095,
                "semiMajorOrientation": 3601,
            },
            "altitude": {"altitudeValue": 800001, "altitudeConfidence": "unavailable"},
        }

    def trigger_denm_sending(self, tpv: dict) -> None:
        """
        Trigger the DENM sending process using the facilities layer.

        Parameters
        ----------
        tpv : dict
            Dictionary containing the current position and altitude information.
            Expected keys include:
                - "lat" : Latitude in decimal degrees.
                - "lon" : Longitude in decimal degrees.
                - "altHAE" : Altitude in meters above the WGS-84 ellipsoid.
        """
        request = DENRequest()
        if "lat" in tpv.keys():
            self.event_position["latitude"] = int(tpv["lat"] * 10000000)
        if "lon" in tpv.keys():
            self.event_position["longitude"] = int(tpv["lon"] * 10000000)
        if "altHAE" in tpv.keys():
            alt = int(tpv["altHAE"] * 100)
            if alt < -800000:
                self.event_position["altitude"]["altitudeValue"] = -100000
            elif alt > 613000:
                self.event_position["altitude"]["altitudeValue"] = 800000
            else:
                self.event_position["altitude"]["altitudeValue"] = int(
                    tpv["altHAE"] * 100
                )

        request.with_emergency_vehicle_approaching(self)
        self.den_service.denm_transmission_management.request_denm_sending(
            request)
