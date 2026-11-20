"""
CAM Transmission Management

This file implements the CAM Transmission Management required by the CAM Basic Service,
strictly following ETSI TS 103 900 V2.3.1 (2026-05), the latest version.

Key behavioural changes versus the pre-standard implementation:
  - Timer-based (T_CheckCamGen) instead of GPS-callback-reactive (§6.1.2, Annex B).
  - T_GenCam is initialised to T_GenCamMax (not T_GenCamMin) as mandated by §6.1.2.
  - Condition 1 (dynamics: heading/position/speed) and Condition 2 (time) are both
    evaluated on every T_CheckCamGen tick.
  - A condition-1 CAM sets T_GenCam to the elapsed time; N_GenCam consecutive
    condition-2 CAMs reset it to T_GenCamMax; the first CAM keeps T_GenCamMax.
  - Low-Frequency, Special-Vehicle, Very-Low-Frequency and Two-Wheeler extension
    containers are included according to §6.1.2.
  - CAM construction failures are handled per Annex B.2.5 (skip, continue timer).
  - GN max packet lifetime 950 ms, below 1 s (TS 102 868-2 TP/CAM/MSD/PAR/BV-03;
    single-hop BTP-B/SHB per §6.1.1 and §5.3.4; V2.2.1 §5.3.4.1 allows at most
    1000 ms, V2.3.1 leaves it to the NTL protocol stack).
  - CA service start/stop correspond to ITS-S activation/deactivation per §5.3.1 (CA_Activation).
"""

from __future__ import annotations

import logging
import random
import threading
from math import atan2, cos, radians, sin, sqrt, trunc
from typing import Optional
from dateutil import parser
from dataclasses import dataclass, field, replace as dataclass_replace
from .cam_coder import CAMCoder
from .cam_ssp import ROLE_SPECIAL_CONTAINER, permissions_bitmap
from ...btp.router import Router as BTPRouter
from ...btp.service_access_point import (
    BTPDataRequest,
    CommonNH,
    PacketTransportType,
    CommunicationProfile,
    TrafficClass,
)
from ...security.security_profiles import SecurityProfile
from ...utils.time_service import ITS_EPOCH_MS, ELAPSED_MILLISECONDS, TimeService
from .cam_ldm_adaptation import CABasicServiceLDM

# ---------------------------------------------------------------------------
# Timing constants (ETSI TS 103 900 V2.3.1 §6.1.2)
# ---------------------------------------------------------------------------
T_GEN_CAM_MIN = 100       # T_GenCamMin [ms]
T_GEN_CAM_MAX = 1000      # T_GenCamMax [ms]
T_CHECK_CAM_GEN = T_GEN_CAM_MIN   # T_CheckCamGen ≤ T_GenCamMin [ms]
T_GEN_CAM_DCC = T_GEN_CAM_MIN    # Default T_GenCam_DCC ∈ [T_GenCamMin, T_GenCamMax] [ms]
#                                  until a DCC entity provides a value (see set_t_gen_cam_dcc)

# ---------------------------------------------------------------------------
# Optional-container intervals (§6.1.2)
# ---------------------------------------------------------------------------
N_GEN_CAM_DEFAULT = 3         # N_GenCam: max consecutive high-dynamic CAMs
T_GEN_CAM_LF_MS = 500         # Low-frequency container minimum interval [ms]
T_GEN_CAM_SPECIAL_MS = 500    # Special-vehicle container minimum interval [ms]
T_GEN_CAM_VLF_MS = 10_000     # Very-low-frequency container minimum interval [ms]
CAM_PACKET_LIFETIME_S = 0.95  # GN packet lifetime of CAMs [s] (< 1 s, TP/CAM/MSD/PAR/BV-03)
# Tolerance of the elapsed-time comparisons [ms]: the evaluations are at least
# T_CheckCamGen apart, but millisecond truncation of the timestamps can make the
# measured interval 1 ms shorter.
TIMESTAMP_TOLERANCE_MS = 1

# ---------------------------------------------------------------------------
# Station types that must include the Two-Wheeler extension container (§6.1.2)
# cyclist(2), moped(3), motorcycle(4)
# ---------------------------------------------------------------------------
TWO_WHEELER_STATION_TYPES: frozenset = frozenset({2, 3, 4})

# ---------------------------------------------------------------------------
# VehicleRole enumeration names (index = integer value, §6.1.2 / CDD)
# ---------------------------------------------------------------------------
_VEHICLE_ROLE_NAMES = [
    "default", "publicTransport", "specialTransport", "dangerousGoods",
    "roadWork", "rescue", "emergency", "safetyCar",
    "agricultural", "commercial", "military", "roadOperator",
    "taxi", "reserved1", "reserved2", "reserved3",
]


def _haversine_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Return the great-circle distance in metres between two WGS-84 points."""
    R = 6_371_000.0
    dlat = radians(lat2 - lat1)
    dlon = radians(lon2 - lon1)
    a = (sin(dlat / 2) ** 2
         + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon / 2) ** 2)
    return R * 2 * atan2(sqrt(a), sqrt(max(0.0, 1.0 - a)))


@dataclass(frozen=True)
class VehicleData:
    """
    Class that stores the vehicle data.

    Attributes
    ----------
    station_id : int
        Station Id as specified in ETSI TS 102 894-2 V2.3.1 (2024-08).
    station_type : int
        Station Type as specified in ETSI TS 102 894-2 V2.3.1 (2024-08).
    drive_direction : str
        Drive Direction as specified in ETSI TS 102 894-2 V2.3.1 (2024-08).
    vehicle_length : dict
        Vehicle Length as specified in ETSI TS 102 894-2 V2.3.1 (2024-08).
    vehicle_width : int
        Vehicle Width as specified in ETSI TS 102 894-2 V2.3.1 (2024-08).
    vehicle_role : int
        VehicleRole (0=default). Used in the Low-Frequency container and to
        decide whether a Special-Vehicle container is required (§6.1.2).
    exterior_lights : bytes
        ExteriorLights BIT STRING (SIZE(8)). One byte; bits ordered MSB→LSB
        correspond to lowBeam(0)…parkingLights(7). Default = all off.
    special_vehicle_data : dict or None
        Special vehicle container data (CHOICE value dict), e.g.
        ``("emergencyContainer", {...})``.  None if not applicable.
    """

    station_id: int = 0
    station_type: int = 0
    drive_direction: str = "unavailable"
    vehicle_length: dict = field(
        default_factory=lambda: {
            "vehicleLengthValue": 1023,
            "vehicleLengthConfidenceIndication": "unavailable",
        }
    )
    vehicle_width: int = 62
    vehicle_role: int = 0
    exterior_lights: bytes = field(default=b"\x00")
    special_vehicle_data: Optional[dict] = None

    def __check_valid_station_id(self) -> None:
        if self.station_id < 0 or self.station_id > 4294967295:
            raise ValueError("Station ID must be between 0 and 4294967295")

    def __check_valid_station_type(self) -> None:
        if self.station_type < 0 or self.station_type > 15:
            raise ValueError("Station Type must be between 0 and 15")

    def __check_valid_drive_direction(self) -> None:
        if self.drive_direction not in ["forward", "backward", "unavailable"]:
            raise ValueError("Drive Direction must be forward, backward or unavailable")

    def __check_valid_vehicle_length(self) -> None:
        if (
            self.vehicle_length["vehicleLengthValue"] < 0
            or self.vehicle_length["vehicleLengthValue"] > 1023
        ):
            raise ValueError("Vehicle length must be between 0 and 1023")

    def __check_valid_vehicle_width(self) -> None:
        if self.vehicle_width < 0 or self.vehicle_width > 62:
            raise ValueError("Vehicle width must be between 0 and 62")

    def __check_valid_vehicle_role(self) -> None:
        if self.vehicle_role < 0 or self.vehicle_role > 15:
            raise ValueError("vehicle_role must be between 0 and 15")

    def __check_valid_special_vehicle_data(self) -> None:
        """
        The special vehicle container must be the one of the vehicle role
        (TS 103 900 V2.3.1 clauses 7.6 and Annex A), e.g. emergencyContainer for
        vehicleRole emergency(6).
        """
        if self.special_vehicle_data is None:
            return
        expected = ROLE_SPECIAL_CONTAINER.get(self.vehicle_role)
        if expected is None:
            raise ValueError(
                f"vehicle_role {self.vehicle_role} has no special vehicle container")
        if self.special_vehicle_data[0] != expected:
            raise ValueError(
                f"vehicle_role {self.vehicle_role} requires {expected}, "
                f"got {self.special_vehicle_data[0]}")

    def __check_valid_exterior_lights(self) -> None:
        if len(self.exterior_lights) < 1:
            raise ValueError("exterior_lights must be at least 1 byte")

    def __post_init__(self) -> None:
        self.__check_valid_station_id()
        self.__check_valid_station_type()
        self.__check_valid_drive_direction()
        self.__check_valid_vehicle_length()
        self.__check_valid_vehicle_width()
        self.__check_valid_vehicle_role()
        self.__check_valid_exterior_lights()
        self.__check_valid_special_vehicle_data()


# AccelerationControl BIT STRING (SIZE(7)), ETSI TS 102 894-2 V2.3.1 (CDD)
ACCELERATION_CONTROL_BITS = (
    "brakePedalEngaged", "gasPedalEngaged", "emergencyBrakeEngaged",
    "collisionWarningEngaged", "accEngaged", "cruiseControlEngaged", "speedLimiterEngaged",
)
# ExteriorLights BIT STRING (SIZE(8)), ETSI TS 102 894-2 V2.3.1 (CDD)
EXTERIOR_LIGHTS_BITS = (
    "lowBeamHeadlightsOn", "highBeamHeadlightsOn", "leftTurnSignalOn", "rightTurnSignalOn",
    "daytimeRunningLightsOn", "reverseLightOn", "fogLightOn", "parkingLightsOn",
)
_CURVATURE_CONFIDENCES = ("onePerMeter-0-00002", "onePerMeter-0-0001", "onePerMeter-0-0005",
                          "onePerMeter-0-002", "onePerMeter-0-01", "onePerMeter-0-1",
                          "outOfRange", "unavailable")
_CURVATURE_MODES = ("yawRateUsed", "yawRateNotUsed", "unavailable")
_YAW_RATE_CONFIDENCES = ("degSec-000-01", "degSec-000-05", "degSec-000-10", "degSec-001-00",
                         "degSec-005-00", "degSec-010-00", "degSec-100-00", "outOfRange",
                         "unavailable")


def bits_to_bytes(names: tuple, flags: dict) -> bytes:
    """
    Encode named BIT STRING flags (bit 0 = most significant bit of the first
    octet) into bytes; unknown names raise ValueError.
    """
    unknown = set(flags) - set(names)
    if unknown:
        raise ValueError(f"Unknown bit names: {sorted(unknown)}")
    value = 0
    for position, name in enumerate(names):
        if flags.get(name):
            value |= 0x80 >> position if position < 8 else 0
    return bytes([value])


@dataclass(frozen=True)
class InVehicleData:
    """
    Latest in-vehicle data provided to the CA basic service (ETSI TS 103 900
    V2.3.1 clauses 5.2 and 7.1): the next generated CAM carries these values.
    ``None`` keeps the static value of :class:`VehicleData` (drive direction,
    exterior lights) or omits the optional field (accelerationControl).

    Attributes
    ----------
    curvature_value : int
        CurvatureValue (-1023..1023, 1023 = unavailable).
    curvature_confidence : str
        CurvatureConfidence.
    curvature_calculation_mode : str
        CurvatureCalculationMode.
    yaw_rate_value : int
        YawRateValue in 0,01 degree/s (-32766..32767, 32767 = unavailable).
    yaw_rate_confidence : str
        YawRateConfidence.
    drive_direction : str or None
        DriveDirection ("forward", "backward", "unavailable").
    acceleration_control : dict or None
        AccelerationControl flags by name (see ``ACCELERATION_CONTROL_BITS``).
    exterior_lights : dict or None
        ExteriorLights flags by name (see ``EXTERIOR_LIGHTS_BITS``).
    """

    curvature_value: int = 1023
    curvature_confidence: str = "unavailable"
    curvature_calculation_mode: str = "unavailable"
    yaw_rate_value: int = 32767
    yaw_rate_confidence: str = "unavailable"
    drive_direction: Optional[str] = None
    acceleration_control: Optional[dict] = None
    exterior_lights: Optional[dict] = None

    def __post_init__(self) -> None:
        if not -1023 <= self.curvature_value <= 1023:
            raise ValueError("curvature_value out of range (-1023..1023)")
        if self.curvature_confidence not in _CURVATURE_CONFIDENCES:
            raise ValueError(f"Invalid curvature_confidence {self.curvature_confidence}")
        if self.curvature_calculation_mode not in _CURVATURE_MODES:
            raise ValueError(f"Invalid curvature_calculation_mode {self.curvature_calculation_mode}")
        if not -32766 <= self.yaw_rate_value <= 32767:
            raise ValueError("yaw_rate_value out of range (-32766..32767)")
        if self.yaw_rate_confidence not in _YAW_RATE_CONFIDENCES:
            raise ValueError(f"Invalid yaw_rate_confidence {self.yaw_rate_confidence}")
        if self.drive_direction not in (None, "forward", "backward", "unavailable"):
            raise ValueError(f"Invalid drive_direction {self.drive_direction}")
        if self.acceleration_control is not None:
            bits_to_bytes(ACCELERATION_CONTROL_BITS, self.acceleration_control)
        if self.exterior_lights is not None:
            bits_to_bytes(EXTERIOR_LIGHTS_BITS, self.exterior_lights)


@dataclass(frozen=True)
class GenerationDeltaTime:
    """
    Generation Delta Time class. As specified in ETSI TS 102 894-2 V2.3.1 (2024-08).

    The reason this type is implemented as a class is to be able to quickly perform operations.

    Express the following way:
    generationDeltaTime = TimestampIts mod 65536
    TimestampIts represents an integer value in milliseconds since
    2004-01-01T00:00:00:000Z as defined in ETSI TS 102 894-2

    Attributes
    ----------
    msec : int
        Time in milliseconds.
    """

    msec: int = 0

    @classmethod
    def from_timestamp(cls, utc_timestamp_in_seconds: float) -> "GenerationDeltaTime":
        """
        Set the Generation Delta Time in normal UTC timestamp. [Seconds]

        Parameters
        ----------
        utc_timestamp_in_seconds : float
            Timestamp in seconds.
        """
        msec = (
            utc_timestamp_in_seconds * 1000 - ITS_EPOCH_MS + ELAPSED_MILLISECONDS
        ) % 65536
        return cls(msec=int(msec))

    def as_timestamp_in_certain_point(self, utc_timestamp_in_millis: int) -> float:
        """
        Returns the generation delta time as timestamp as it would be if received at
        certain point in time.

        Parameters
        ----------
        utc_timestamp_in_millis : int
            Timestamp in milliseconds

        Returns
        -------
        float
            Timestamp of the generation delta time in milliseconds
        """
        number_of_cycles = trunc(
            (utc_timestamp_in_millis - ITS_EPOCH_MS + ELAPSED_MILLISECONDS) / 65536
        )
        transformed_timestamp = (
            self.msec + 65536 * number_of_cycles + ITS_EPOCH_MS - ELAPSED_MILLISECONDS
        )
        if transformed_timestamp <= utc_timestamp_in_millis:
            return transformed_timestamp
        return (
            self.msec
            + 65536 * (number_of_cycles - 1)
            + ITS_EPOCH_MS
            - ELAPSED_MILLISECONDS
        )

    def __gt__(self, other: object) -> bool:
        """
        Greater than operator.
        """
        if isinstance(other, GenerationDeltaTime):
            return self.msec > other.msec
        return False

    def __lt__(self, other: object) -> bool:
        """
        Less than operator.
        """
        if isinstance(other, GenerationDeltaTime):
            return self.msec < other.msec
        return False

    def __ge__(self, other: object) -> bool:
        """
        Greater than or equal operator.
        """
        if isinstance(other, GenerationDeltaTime):
            return self.msec >= other.msec
        return False

    def __le__(self, other: object) -> bool:
        """
        Less than or equal operator.
        """
        if isinstance(other, GenerationDeltaTime):
            return self.msec <= other.msec
        return False

    def __add__(self, other: object) -> int:
        """
        Addition operator.
        """
        if isinstance(other, GenerationDeltaTime):
            return int((self.msec + other.msec) % 65536)
        return NotImplemented

    def __sub__(self, other: object) -> int:
        """
        Subtraction operator.
        """
        if isinstance(other, GenerationDeltaTime):
            subs = self.msec - other.msec
            if subs < 0:
                subs = subs + 65536
            return int(subs)
        return NotImplemented


@dataclass(frozen=True)
class CooperativeAwarenessMessage:
    """
    Cooperative Awareness Message class.

    Attributes
    ----------
    cam : dict
        All the CAM message in dict format as decoded by the CAMCoder.

    """

    cam: dict = field(
        default_factory=lambda: CooperativeAwarenessMessage.generate_white_cam_static()
    )

    @staticmethod
    def generate_white_cam_static() -> dict:
        """
        Generate a white CAM.
        """
        return {
            "header": {"protocolVersion": 2, "messageId": 2, "stationId": 0},
            "cam": {
                "generationDeltaTime": 0,
                "camParameters": {
                    "basicContainer": {
                        "stationType": 0,
                        "referencePosition": {
                            "latitude": 900000001,
                            "longitude": 1800000001,
                            "positionConfidenceEllipse": {
                                "semiMajorAxisLength": 4095,
                                "semiMinorAxisLength": 4095,
                                "semiMajorAxisOrientation": 3601,
                            },
                            "altitude": {
                                "altitudeValue": 800001,
                                "altitudeConfidence": "unavailable",
                            },
                        },
                    },
                    "highFrequencyContainer": (
                        "basicVehicleContainerHighFrequency",
                        {
                            "heading": {"headingValue": 3601, "headingConfidence": 127},
                            "speed": {"speedValue": 16383, "speedConfidence": 127},
                            "driveDirection": "unavailable",
                            "vehicleLength": {
                                "vehicleLengthValue": 1023,
                                "vehicleLengthConfidenceIndication": "unavailable",
                            },
                            "vehicleWidth": 62,
                            "longitudinalAcceleration": {
                                "value": 161,
                                "confidence": 102,
                            },
                            "curvature": {
                                "curvatureValue": 1023,
                                "curvatureConfidence": "unavailable",
                            },
                            "curvatureCalculationMode": "unavailable",
                            "yawRate": {
                                "yawRateValue": 32767,
                                "yawRateConfidence": "unavailable",
                            },
                        },
                    ),
                },
            },
        }

    def generate_white_cam(self) -> dict:
        """
        Generate a white CAM.
        """
        return self.generate_white_cam_static()

    def fullfill_with_vehicle_data(self, vehicle_data: VehicleData) -> None:
        """
        Fullfill the CAM with vehicle data.

        Parameters
        ----------
        vehicle_data : VehicleData
            Vehicle data.
        """
        self.cam["header"]["stationId"] = vehicle_data.station_id
        self.cam["cam"]["camParameters"]["basicContainer"][
            "stationType"
        ] = vehicle_data.station_type
        self.cam["cam"]["camParameters"]["highFrequencyContainer"][1][
            "driveDirection"
        ] = vehicle_data.drive_direction
        self.cam["cam"]["camParameters"]["highFrequencyContainer"][1][
            "vehicleLength"
        ] = vehicle_data.vehicle_length
        self.cam["cam"]["camParameters"]["highFrequencyContainer"][1][
            "vehicleWidth"
        ] = vehicle_data.vehicle_width

    def fullfill_gen_delta_time_with_tpv_data(self, tpv: dict) -> None:
        """
        Fullfills the generation delta time with the GPSD TPV data.

        Parameters
        ----------
        tpv : dict
            GPSD TPV data.
        """
        if "time" in tpv:
            gen_delta_time = GenerationDeltaTime.from_timestamp(
                parser.parse(tpv["time"]).timestamp()
            )
            self.cam["cam"]["generationDeltaTime"] = int(gen_delta_time.msec)

    def fullfill_basic_container_with_tpv_data(self, tpv: dict) -> None:
        """
        Fullfills the basic container with the GPSD TPV data.

        Parameters
        ----------
        tpv : dict
            GPSD TPV data.
        """
        if "lat" in tpv.keys():
            self.cam["cam"]["camParameters"]["basicContainer"]["referencePosition"][
                "latitude"
            ] = int(tpv["lat"] * 10000000)
        if "lon" in tpv.keys():
            self.cam["cam"]["camParameters"]["basicContainer"]["referencePosition"][
                "longitude"
            ] = int(tpv["lon"] * 10000000)
        if "epx" in tpv.keys() and "epy" in tpv.keys():
            self.cam["cam"]["camParameters"]["basicContainer"]["referencePosition"][
                "positionConfidenceEllipse"
            ] = self.create_position_confidence(tpv["epx"], tpv["epy"])
        if "altHAE" in tpv.keys():
            alt = int(tpv["altHAE"] * 100)
            if alt < -800000:
                self.cam["cam"]["camParameters"]["basicContainer"]["referencePosition"][
                    "altitude"
                ]["altitudeValue"] = -100000
            elif alt > 613000:
                self.cam["cam"]["camParameters"]["basicContainer"]["referencePosition"][
                    "altitude"
                ]["altitudeValue"] = 800000
            else:
                self.cam["cam"]["camParameters"]["basicContainer"]["referencePosition"][
                    "altitude"
                ]["altitudeValue"] = int(tpv["altHAE"] * 100)
        if "epv" in tpv.keys():
            self.cam["cam"]["camParameters"]["basicContainer"]["referencePosition"][
                "altitude"
            ]["altitudeConfidence"] = self.create_altitude_confidence(tpv["epv"])

    def fullfill_high_frequency_container_with_tpv_data(self, tpv: dict) -> None:
        """
        Fullfills the high frequency container with the GPSD TPV data.

        Parameters
        ----------
        tpv : dict
            GPSD TPV data.
        """
        if "track" in tpv.keys():
            self.cam["cam"]["camParameters"]["highFrequencyContainer"][1]["heading"][
                "headingValue"
            ] = int(tpv["track"] * 10)
        if "epd" in tpv.keys():
            self.cam["cam"]["camParameters"]["highFrequencyContainer"][1]["heading"][
                "headingConfidence"
            ] = self.create_heading_confidence(tpv["epd"])
        if "speed" in tpv.keys():
            if int(tpv["speed"] * 100) > 16381:
                self.cam["cam"]["camParameters"]["highFrequencyContainer"][1]["speed"][
                    "speedValue"
                ] = 16382
            else:
                self.cam["cam"]["camParameters"]["highFrequencyContainer"][1]["speed"][
                    "speedValue"
                ] = int(tpv["speed"] * 100)

    def fullfill_with_tpv_data(self, tpv: dict) -> None:
        """
        Convert a TPV data to a CAM.

        Parameters
        ----------
        tpv : dict
            GPSD TPV data.
        """
        self.fullfill_gen_delta_time_with_tpv_data(tpv)
        self.fullfill_basic_container_with_tpv_data(tpv)
        self.fullfill_high_frequency_container_with_tpv_data(tpv)

    def create_position_confidence(self, epx: int, epy: int) -> dict:
        """
        Translates the epx and epy TPV values to the position confidence ellipse value.

        Parameters
        ----------
        epx : int
            TPV epx value.
        epy : int
            TPV epy value.

        Returns
        -------
        dict
            Position confidence ellipse value.
        """
        position_confidence_ellipse = {
            "semiMajorAxisLength": int(epx * 100),
            "semiMinorAxisLength": int(epy * 100),
            "semiMajorAxisOrientation": 0,
        }
        if epy >= epx:
            position_confidence_ellipse = {
                "semiMajorAxisLength": int(epy * 100),
                "semiMinorAxisLength": int(epx * 100),
                "semiMajorAxisOrientation": 0,
            }
        return position_confidence_ellipse

    # def create_altitude_confidence(self, epv: float) -> str:
    #     """
    #     Translates the epv TPV value to the altitude confidence value.

    #     Parameters
    #     ----------
    #     epv : float
    #         TPV epv value.

    #     Returns
    #     -------
    #     str
    #         Altitude confidence value.
    #     """
    #     altitude_confidence = "unavailable"
    #     if epv < 0.01:
    #         altitude_confidence = "alt-000-01"
    #     elif epv < 0.02:
    #         altitude_confidence = "alt-000-02"
    #     elif epv < 0.05:
    #         altitude_confidence = "alt-000-05"
    #     elif epv < 0.1:
    #         altitude_confidence = "alt-000-10"
    #     elif epv < 0.2:
    #         altitude_confidence = "alt-000-20"
    #     elif epv < 0.5:
    #         altitude_confidence = "alt-000-50"
    #     elif epv < 1:
    #         altitude_confidence = "alt-001-00"
    #     elif epv < 2:
    #         altitude_confidence = "alt-002-00"
    #     elif epv < 5:
    #         altitude_confidence = "alt-005-00"
    #     elif epv < 10:
    #         altitude_confidence = "alt-010-00"
    #     elif epv < 20:
    #         altitude_confidence = "alt-020-00"
    #     elif epv < 50:
    #         altitude_confidence = "alt-050-00"
    #     elif epv < 100:
    #         altitude_confidence = "alt-100-00"
    #     elif epv <= 200:
    #         altitude_confidence = "alt-200-00"
    #     elif epv > 200:
    #         altitude_confidence = "outOfRange"
    #     return altitude_confidence

    def create_altitude_confidence(self, epv: float) -> str:
        """Translates the epv TPV value to the altitude confidence value.

        Parameters
        ----------
        epv : float
            TPV epv value.

        Returns
        -------
        str
            Altitude confidence value.
        """
        altitude_confidence_map = {
            0.01: "alt-000-01",
            0.02: "alt-000-02",
            0.05: "alt-000-05",
            0.1: "alt-000-10",
            0.2: "alt-000-20",
            0.5: "alt-000-50",
            1: "alt-001-00",
            2: "alt-002-00",
            5: "alt-005-00",
            10: "alt-010-00",
            20: "alt-020-00",
            50: "alt-050-00",
            100: "alt-100-00",
            200: "alt-200-00",
            float("inf"): "outOfRange",
        }

        for key in sorted(altitude_confidence_map.keys()):
            if epv < key:
                return altitude_confidence_map[key]

        return "unavailable"

    def create_heading_confidence(self, epd: float) -> int:
        """
        Translates the epd TPV value to the heading confidence value.

        Parameters
        ----------
        epd : float
            TPV epd value.

        Returns
        -------
        int
            Heading confidence value.
        """
        heading_confidence = 126
        if epd <= 12.5:
            heading_confidence = int(epd * 10)
        return heading_confidence

    def __str__(self) -> str:
        return str(self.cam)


class CAMTransmissionManagement:
    """
    CAM Transmission Management — ETSI TS 103 900 V2.3.1 §6.1.

    Protocol operation is timer-based (T_CheckCamGen) rather than
    GPS-callback-reactive.  Call :meth:`start` to activate the service and
    :meth:`stop` to deactivate it (§5.3.1 (CA_Activation)).

    The :meth:`location_service_callback` only updates the current position
    cache; the T_CheckCamGen timer evaluates CAM generation conditions on
    every tick (§6.1.2, Annex B.2.4).

    Attributes
    ----------
    btp_router : BTPRouter
        BTP Router.
    vehicle_data : VehicleData
        Vehicle Data (static parameters).
    cam_coder : CAMCoder
        CAM encoder/decoder.
    ca_basic_service_ldm : CABasicServiceLDM or None
        Local Dynamic Map adapter; may be None.
    t_gen_cam : int
        Current T_GenCam upper bound [ms].  Starts at T_GenCamMax per §6.1.2.
    t_gen_cam_dcc : int
        T_GenCam_DCC [ms] provided by the management layer (DCC), see
        :meth:`set_t_gen_cam_dcc`.  Defaults to ``T_GEN_CAM_DCC``.
    last_cam_generation_delta_time : GenerationDeltaTime or None
        GenerationDeltaTime of the most recently sent CAM (legacy attribute).
    """

    def __init__(
        self,
        btp_router: BTPRouter,
        cam_coder: CAMCoder,
        vehicle_data: VehicleData,
        ca_basic_service_ldm: Optional[CABasicServiceLDM] = None,
    ) -> None:
        self.logging = logging.getLogger("ca_basic_service")
        self.btp_router: BTPRouter = btp_router
        self.vehicle_data = vehicle_data
        self.cam_coder = cam_coder
        self.ca_basic_service_ldm = ca_basic_service_ldm

        # §6.1.2 — T_GenCam starts at T_GenCamMax (not T_GenCamMin!)
        self.t_gen_cam: int = T_GEN_CAM_MAX
        # §6.1.2 — T_GenCam_DCC, provided by the management layer (DCC)
        self.t_gen_cam_dcc: int = T_GEN_CAM_DCC
        self._n_gen_cam_counter: int = 0         # consecutive condition-2 CAMs

        # Dynamics state of the last transmitted CAM
        self._last_cam_time_ms: Optional[int] = None
        self._last_cam_heading: Optional[float] = None   # degrees
        self._last_cam_lat: Optional[float] = None
        self._last_cam_lon: Optional[float] = None
        self._last_cam_speed: Optional[float] = None     # m/s

        # Container timing state
        self._cam_count: int = 0                         # CAMs sent since start()
        self._last_lf_time_ms: Optional[int] = None
        self._last_vlf_time_ms: Optional[int] = None
        self._last_special_time_ms: Optional[int] = None

        # Path history for Low-Frequency container (§6.1.2).
        # Stored as list of (lat, lon, time_ms) oldest→newest; max 40 entries.
        self._path_history: list = []

        # Current GPS/position data from the location service
        self._current_tpv: Optional[dict] = None
        self._tpv_lock = threading.Lock()
        # Latest in-vehicle data (§5.2, §7.1), guarded by _tpv_lock
        self._in_vehicle_data = InVehicleData()

        # T_CheckCamGen timer
        self._active: bool = False
        self._timer: Optional[threading.Timer] = None

        # Legacy compatibility attribute
        self.last_cam_generation_delta_time: Optional[GenerationDeltaTime] = None

    # ------------------------------------------------------------------
    # Service lifecycle (§5.3.1 (CA_Activation))
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Activate the CA service.  Starts the T_CheckCamGen timer (§5.3.1 (CA_Activation))."""
        if self._active:
            return
        self._active = True
        # Reset per-activation state
        self._cam_count = 0
        self._last_cam_time_ms = None
        self._last_cam_heading = None
        self._last_cam_lat = None
        self._last_cam_lon = None
        self._last_cam_speed = None
        self._last_lf_time_ms = None
        self._last_vlf_time_ms = None
        self._last_special_time_ms = None
        self._path_history.clear()
        self.t_gen_cam = T_GEN_CAM_MAX
        self._n_gen_cam_counter = 0
        # Annex B.2.4 step 1 — non-clock-synchronised start (random initial delay)
        initial_delay_s = random.uniform(0.0, T_CHECK_CAM_GEN / 1000.0)
        self._schedule_next_check(initial_delay_s)

    def stop(self) -> None:
        """Deactivate the CA service.  Cancels the T_CheckCamGen timer (§5.3.1 (CA_Activation))."""
        self._active = False
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None

    def set_t_gen_cam_dcc(self, t_gen_cam_dcc_ms: int) -> None:
        """
        Set T_GenCam_DCC (§6.1.2), clamped to [T_GenCamMin, T_GenCamMax].

        Intended as a :class:`~flexstack.management.dcc_entity.DccEntity`
        listener; may be called from the DCC thread while the CA service runs.

        Parameters
        ----------
        t_gen_cam_dcc_ms : int
            Minimum CAM generation interval imposed by DCC [ms].
        """
        self.t_gen_cam_dcc = max(T_GEN_CAM_MIN, min(T_GEN_CAM_MAX, int(t_gen_cam_dcc_ms)))

    # ------------------------------------------------------------------
    # Location service integration
    # ------------------------------------------------------------------

    def location_service_callback(self, tpv: dict) -> None:
        """
        Cache the latest position data (§6.1.2).

        This method no longer triggers CAM generation directly.  The
        T_CheckCamGen timer evaluates generation conditions at each tick.

        Parameters
        ----------
        tpv : dict
            GPSD TPV message or compatible position dict.
        """
        with self._tpv_lock:
            self._current_tpv = tpv

    def update_in_vehicle_data(self, **changes) -> InVehicleData:
        """
        Update the latest in-vehicle data (§5.2, §7.1): the next CAM carries
        the new values. Keyword arguments are :class:`InVehicleData` fields;
        invalid values raise ``ValueError`` and leave the data unchanged.

        Returns
        -------
        InVehicleData
            The in-vehicle data now in use.
        """
        with self._tpv_lock:
            self._in_vehicle_data = dataclass_replace(self._in_vehicle_data, **changes)
            return self._in_vehicle_data

    @property
    def in_vehicle_data(self) -> InVehicleData:
        """The latest in-vehicle data."""
        with self._tpv_lock:
            return self._in_vehicle_data

    def _exterior_lights(self) -> bytes:
        lights = self.in_vehicle_data.exterior_lights
        if lights is None:
            return self.vehicle_data.exterior_lights
        return bits_to_bytes(EXTERIOR_LIGHTS_BITS, lights)

    def _apply_in_vehicle_data(self, cam: "CooperativeAwarenessMessage") -> None:
        """Fill the HF container with the latest in-vehicle data (§7.1)."""
        data = self.in_vehicle_data
        hf = cam.cam["cam"]["camParameters"]["highFrequencyContainer"][1]
        hf["curvature"] = {"curvatureValue": data.curvature_value,
                           "curvatureConfidence": data.curvature_confidence}
        hf["curvatureCalculationMode"] = data.curvature_calculation_mode
        hf["yawRate"] = {"yawRateValue": data.yaw_rate_value,
                         "yawRateConfidence": data.yaw_rate_confidence}
        if data.drive_direction is not None:
            hf["driveDirection"] = data.drive_direction
        if data.acceleration_control is not None:
            hf["accelerationControl"] = (
                bits_to_bytes(ACCELERATION_CONTROL_BITS, data.acceleration_control), 7)

    # ------------------------------------------------------------------
    # Timer callbacks (Annex B.2.4)
    # ------------------------------------------------------------------

    def _schedule_next_check(self, delay_s: Optional[float] = None) -> None:
        """Schedule the next T_CheckCamGen evaluation."""
        if not self._active:
            return
        if delay_s is None:
            delay_s = T_CHECK_CAM_GEN / 1000.0
        self._timer = threading.Timer(delay_s, self._check_cam_conditions)
        self._timer.daemon = True
        self._timer.start()

    def _check_cam_conditions(self) -> None:
        """
        T_CheckCamGen expiry callback (Annex B.2.4 steps 2–7).

        Evaluates conditions 1 and 2, generates and sends a CAM if either is
        satisfied, then reschedules the timer.
        """
        if not self._active:
            return
        try:
            self._evaluate_and_maybe_send()
        finally:
            # Annex B.2.4 step 8 — always restart T_CheckCamGen
            self._schedule_next_check()

    def _evaluate_and_maybe_send(self) -> None:
        """Evaluate CAM generation conditions and send if required."""
        with self._tpv_lock:
            tpv = self._current_tpv
        if tpv is None:
            return

        now_ms = int(TimeService.time() * 1000)

        # First CAM after activation — send immediately (no elapsed constraint);
        # T_GenCam keeps its default T_GenCamMax (condition 0: neither 1 nor 2).
        if self._last_cam_time_ms is None:
            self._generate_and_send_cam(tpv, now_ms, condition=0)
            return

        elapsed_ms = now_ms - self._last_cam_time_ms + TIMESTAMP_TOLERANCE_MS
        t_gen_cam_dcc = self.t_gen_cam_dcc

        # Condition 1 (§6.1.2): elapsed ≥ T_GenCam_DCC  AND  dynamics changed
        if elapsed_ms >= t_gen_cam_dcc and self._check_dynamics(tpv):
            self._generate_and_send_cam(tpv, now_ms, condition=1)
            return

        # Condition 2 (§6.1.2): elapsed ≥ T_GenCam  AND  elapsed ≥ T_GenCam_DCC
        if elapsed_ms >= self.t_gen_cam and elapsed_ms >= t_gen_cam_dcc:
            self._generate_and_send_cam(tpv, now_ms, condition=2)

    # ------------------------------------------------------------------
    # Dynamics check — §6.1.2 Condition 1
    # ------------------------------------------------------------------

    def _check_dynamics(self, tpv: dict) -> bool:
        """
        Return True if at least one dynamics threshold is exceeded.

        Thresholds (§6.1.2):
          * |Δheading| > 4°
          * |Δposition| > 4 m  (haversine)
          * |Δspeed| > 0,5 m/s
        """
        if self._last_cam_heading is None:
            return True  # No reference — treat as changed

        # Heading
        if "track" in tpv:
            diff = abs(tpv["track"] - self._last_cam_heading)
            if diff > 180.0:
                diff = 360.0 - diff
            if diff > 4.0:
                return True

        # Position
        if ("lat" in tpv and "lon" in tpv
                and self._last_cam_lat is not None
                and self._last_cam_lon is not None):
            if _haversine_m(self._last_cam_lat, self._last_cam_lon,
                            tpv["lat"], tpv["lon"]) > 4.0:
                return True

        # Speed
        if "speed" in tpv and self._last_cam_speed is not None:
            if abs(tpv["speed"] - self._last_cam_speed) > 0.5:
                return True

        return False

    # ------------------------------------------------------------------
    # Optional container inclusion rules (§6.1.2)
    # ------------------------------------------------------------------

    def _should_include_lf(self, now_ms: int) -> bool:
        """Low-Frequency container: first CAM, then every ≥ 500 ms."""
        if self._cam_count == 0:
            return True
        if self._last_lf_time_ms is None:
            return True
        return (now_ms - self._last_lf_time_ms) >= T_GEN_CAM_LF_MS

    def _should_include_special_vehicle(self, now_ms: int) -> bool:
        """Special-Vehicle container: first CAM (if role ≠ default), then ≥ 500 ms."""
        if self.vehicle_data.vehicle_role == 0:
            return False
        if self._cam_count == 0:
            return True
        if self._last_special_time_ms is None:
            return True
        return (now_ms - self._last_special_time_ms) >= T_GEN_CAM_SPECIAL_MS

    def _should_include_vlf(
        self, now_ms: int, include_lf: bool, include_special: bool
    ) -> bool:
        """
        Very-Low-Frequency extension container (§6.1.2):
          - Second CAM after activation (cam_count == 1).
          - After that: ≥ 10 s elapsed AND LF/special containers NOT included.
        """
        if self._cam_count == 1:
            return True
        if self._last_vlf_time_ms is None:
            return False
        return (
            (now_ms - self._last_vlf_time_ms) >= T_GEN_CAM_VLF_MS
            and not include_lf
            and not include_special
        )

    def _should_include_two_wheeler(self) -> bool:
        """Two-Wheeler extension container in ALL CAMs for cyclist/moped/motorcycle."""
        return self.vehicle_data.station_type in TWO_WHEELER_STATION_TYPES

    # ------------------------------------------------------------------
    # Low-Frequency container helpers
    # ------------------------------------------------------------------

    def _build_lf_container(self, tpv: dict) -> dict:
        """Build the BasicVehicleContainerLowFrequency dict."""
        role_idx = self.vehicle_data.vehicle_role
        role_name = (
            _VEHICLE_ROLE_NAMES[role_idx]
            if 0 <= role_idx < len(_VEHICLE_ROLE_NAMES)
            else "default"
        )
        return {
            "vehicleRole": role_name,
            "exteriorLights": (self._exterior_lights(), 8),
            "pathHistory": self._get_path_history(tpv),
        }

    def _get_path_history(self, current_tpv: dict) -> list:
        """
        Convert the stored path history to a list of PathPoint dicts relative
        to the current position.  Entries outside the DeltaLatitude/DeltaLongitude
        valid range (-131071..131072) are dropped.
        """
        current_lat = current_tpv.get("lat")
        current_lon = current_tpv.get("lon")
        if current_lat is None or current_lon is None or not self._path_history:
            return []

        now_ms = int(TimeService.time() * 1000)
        result = []
        for h_lat, h_lon, h_time_ms in reversed(self._path_history):
            delta_lat = round((h_lat - current_lat) * 10_000_000)
            delta_lon = round((h_lon - current_lon) * 10_000_000)
            if not (-131071 <= delta_lat <= 131072):
                break
            if not (-131071 <= delta_lon <= 131072):
                break
            delta_time_10ms = max(1, min(65534, round((now_ms - h_time_ms) / 10)))
            result.append({
                "pathPosition": {
                    "deltaLatitude": delta_lat,
                    "deltaLongitude": delta_lon,
                    "deltaAltitude": 12800,  # unavailable
                },
                "pathDeltaTime": delta_time_10ms,
            })
            if len(result) >= 23:  # ASN.1 WITH COMPONENTS limit in LF container
                break
        return result

    # ------------------------------------------------------------------
    # CAM generation and transmission (Annex B.2.4/B.2.5)
    # ------------------------------------------------------------------

    def _generate_and_send_cam(
        self, tpv: dict, now_ms: int, condition: int
    ) -> None:
        """
        Build the CAM, encode it and transmit it via BTP (Annex B.2.4 steps 3–6).

        If CAM construction or encoding fails (Annex B.2.5) the transmission is
        skipped and the timer continues.
        """
        elapsed_ms = (
            (now_ms - self._last_cam_time_ms)
            if self._last_cam_time_ms is not None
            else 0
        )

        include_lf = self._should_include_lf(now_ms)
        include_special = self._should_include_special_vehicle(now_ms)
        include_vlf = self._should_include_vlf(now_ms, include_lf, include_special)
        include_two_wheeler = self._should_include_two_wheeler()

        # Build the CAM PDU
        cam = CooperativeAwarenessMessage()
        cam.fullfill_with_vehicle_data(self.vehicle_data)
        cam.fullfill_with_tpv_data(tpv)
        self._apply_in_vehicle_data(cam)

        if include_lf:
            cam.cam["cam"]["camParameters"]["lowFrequencyContainer"] = (
                "basicVehicleContainerLowFrequency",
                self._build_lf_container(tpv),
            )

        if include_special and self.vehicle_data.special_vehicle_data is not None:
            cam.cam["cam"]["camParameters"]["specialVehicleContainer"] = (
                self.vehicle_data.special_vehicle_data
            )

        extension_containers = []
        if include_two_wheeler:
            tw_bytes = self.cam_coder.encode_extension_container(1, {})
            extension_containers.append({"containerId": 1, "containerData": tw_bytes})
        if include_vlf:
            vlf_bytes = self.cam_coder.encode_extension_container(3, {})
            extension_containers.append({"containerId": 3, "containerData": vlf_bytes})
        if extension_containers:
            cam.cam["cam"]["camParameters"]["extensionContainers"] = extension_containers

        # Annex B.2.5 — construction exception: skip this transmission
        try:
            self._send_cam(cam)
        except Exception:
            self.logging.exception(
                "CAM construction or encoding failed (Annex B.2.5) — skipping"
            )
            return

        # Update state after successful transmission (Annex B.2.4 step 5)
        self._update_send_state(tpv, now_ms, elapsed_ms, condition,
                                include_lf, include_special, include_vlf)

    def _send_cam(self, cam: CooperativeAwarenessMessage) -> None:
        """Encode and transmit a CAM PDU via BTP-B/SHB (§6.1.1, §5.3.4; V2.2.1 §5.3.4.1)."""
        data = self.cam_coder.encode(cam.cam)
        request = BTPDataRequest(
            btp_type=CommonNH.BTP_B,
            destination_port=2001,
            gn_packet_transport_type=PacketTransportType(),
            communication_profile=CommunicationProfile.UNSPECIFIED,
            traffic_class=TrafficClass(),
            # Lifetime below 1 s (TS 102 868-2 TP/CAM/MSD/PAR/BV-03; TS 103 900
            # V2.2.1 §5.3.4.1: at most 1000 ms): 950 ms = 19 x 50 ms.
            gn_max_packet_lifetime=CAM_PACKET_LIFETIME_S,
            security_profile=SecurityProfile.COOPERATIVE_AWARENESS_MESSAGE,
            its_aid=36,
            # Sender-side SSP check (clause 6.2.2.2): sign only with an AT
            # granting the protected content of this CAM.
            security_permissions=permissions_bitmap(
                cam.cam, lambda data: self.cam_coder.decode_extension_container(1, data)),
            data=data,
            length=len(data),
        )
        self.btp_router.btp_data_request(request)
        if self.ca_basic_service_ldm is not None:
            self.ca_basic_service_ldm.add_provider_data_to_ldm(cam.cam)
        self.logging.info(
            "Sent CAM: generationDeltaTime=%d, stationId=%d",
            cam.cam["cam"]["generationDeltaTime"],
            cam.cam["header"]["stationId"],
        )

    # ------------------------------------------------------------------
    # Post-transmission state update (§6.1.2 T_GenCam management)
    # ------------------------------------------------------------------

    def _update_send_state(
        self,
        tpv: dict,
        now_ms: int,
        elapsed_ms: int,
        condition: int,
        include_lf: bool,
        include_special: bool,
        include_vlf: bool,
    ) -> None:
        """Update all state variables after a successful CAM transmission."""
        # T_GenCam management (§6.1.2): a condition-1 CAM sets T_GenCam to the
        # time elapsed since the last CAM; after N_GenCam consecutive CAMs due
        # to condition 2, T_GenCam is set to T_GenCamMax. The first CAM after
        # activation (condition 0) leaves the default T_GenCamMax.
        if condition == 1:
            self.t_gen_cam = max(T_GEN_CAM_MIN, min(T_GEN_CAM_MAX, elapsed_ms))
            self._n_gen_cam_counter = 0
        elif condition == 2:
            self._n_gen_cam_counter += 1
            if self._n_gen_cam_counter >= N_GEN_CAM_DEFAULT:
                self.t_gen_cam = T_GEN_CAM_MAX
                self._n_gen_cam_counter = 0

        # Update last-CAM dynamics reference
        self._last_cam_time_ms = now_ms
        if "track" in tpv:
            self._last_cam_heading = tpv["track"]
        if "lat" in tpv and "lon" in tpv:
            self._last_cam_lat = tpv["lat"]
            self._last_cam_lon = tpv["lon"]
        if "speed" in tpv:
            self._last_cam_speed = tpv["speed"]

        # Update path history (add current position)
        if "lat" in tpv and "lon" in tpv:
            self._path_history.append((tpv["lat"], tpv["lon"], now_ms))
            if len(self._path_history) > 40:
                self._path_history.pop(0)

        # Update container timing
        if include_lf:
            self._last_lf_time_ms = now_ms
        if include_special:
            self._last_special_time_ms = now_ms
        if include_vlf:
            self._last_vlf_time_ms = now_ms

        self._cam_count += 1

        # Legacy compatibility
        self.last_cam_generation_delta_time = GenerationDeltaTime(
            msec=int(
                (TimeService.time() * 1000 - ITS_EPOCH_MS + ELAPSED_MILLISECONDS)
                % 65536
            )
        )
