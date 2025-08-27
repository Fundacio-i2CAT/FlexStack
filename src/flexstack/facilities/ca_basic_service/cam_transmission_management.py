"""
CAM Transmission Management

This file implements the CAM Transmission Management required by the CAM Basic Service.
"""

from math import trunc
import logging
from dateutil import parser
from .cam_coder import CAMCoder
from ...btp.router import Router as BTPRouter
from ...btp.service_access_point import (
    BTPDataRequest,
    CommonNH,
    PacketTransportType,
    CommunicationProfile,
    TrafficClass,
)
from ...utils.time_service import ITS_EPOCH_MS, ELAPSED_MILLISECONDS
from .cam_ldm_adaptation import CABasicServiceLDM

T_GEN_CAM_MIN = 100  # T_GenCamMin [in ms]
T_GEN_CAM_MAX = 1000  # ms
T_CHECK_CAM_GEN = (
    # T_CheckCamGen [in ms] Shall be equal to or less than T_GenCamMin
    T_GEN_CAM_MIN
)
T_GEN_CAM_DCC = (
    # T_GenCam_DCC [in ms] T_GenCamMin ≤ T_GenCam_DCC ≤ T_GenCamMax
    T_GEN_CAM_MIN
)


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
    """

    def __init__(self) -> None:
        self.station_id = 0
        self.station_type = 0
        self.drive_direction = "unavailable"
        self.vehicle_length = {
            "vehicleLengthValue": 1023,
            "vehicleLengthConfidenceIndication": "unavailable",
        }
        self.vehicle_width = 62

    def set_station_type(self, station_type: int) -> None:
        """
        Set the station type.

        Parameters
        ----------
        station_type : int
            Station type.
        """
        if station_type < 0 or station_type > 15:
            raise ValueError("Station type must be between 0 and 15.")
        self.station_type = station_type

    def set_drive_direction(self, drive_direction: str) -> None:
        """
        Set the drive direction.

        Parameters
        ----------
        drive_direction : str
            Drive direction.
        """
        if drive_direction not in [
            "forward",
            "reverse",
            "unavailable",
        ]:
            raise ValueError(
                "Drive direction must be 'forward', 'reverse' or 'unavailable'."
            )
        self.drive_direction = drive_direction


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

    def __init__(self) -> None:
        self.msec = 0

    def set_in_normal_timestamp(self, utc_timestamp_in_seconds: float) -> None:
        """
        Set the Generation Delta Time in normal UTC timestamp. [Seconds]

        Parameters
        ----------
        timestamp : int
            Timestamp in milliseconds.
        """
        self.msec = (
            utc_timestamp_in_seconds * 1000 - ITS_EPOCH_MS + ELAPSED_MILLISECONDS
        ) % 65536

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
            (utc_timestamp_in_millis - ITS_EPOCH_MS + ELAPSED_MILLISECONDS) / 65536)
        transformed_timestamp = self.msec + 65536 * \
            number_of_cycles + ITS_EPOCH_MS - ELAPSED_MILLISECONDS
        if transformed_timestamp <= utc_timestamp_in_millis:
            return transformed_timestamp
        return self.msec + 65536 * (number_of_cycles - 1) + ITS_EPOCH_MS - ELAPSED_MILLISECONDS

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

    def __add__(self, other: object) -> object:
        """
        Addition operator.
        """
        if isinstance(other, GenerationDeltaTime):
            return (self.msec + other.msec) % 65536
        return NotImplemented

    def __sub__(self, other: object) -> object:
        """
        Subtraction operator.
        """
        if isinstance(other, GenerationDeltaTime):
            subs = self.msec - other.msec
            if subs < 0:
                subs = subs + 65536
            return subs
        return NotImplemented


class CooperativeAwarenessMessage:
    """
    Cooperative Awareness Message class.

    Attributes
    ----------
    cam : dict
        All the CAM message in dict format as decoded by the CAMCoder.

    """

    def __init__(self) -> None:
        self.cam = self.generate_white_cam()

    def generate_white_cam(self) -> dict:
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
            gen_delta_time = GenerationDeltaTime()
            gen_delta_time.set_in_normal_timestamp(
                parser.parse(tpv["time"]).timestamp())
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
            ] = int(tpv["track"]*10)
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
    CAM Transmission Management class.
    This sub-function ahould implement the protocol operation of the originating ITS-S, as specified
    in ETSI TS 102 894-2 V2.3.1 (2024-08) clause C.2, including in particular:
    - Activation and termination of CAM transmission operation.
    - Determination of the CAM generation frequency.
    - Trigger the generation of CAM.

    By now, it implements the same algorithms but being reactive to when a new position is received.

    Attributes
    ----------
    btp_router : BTPRouter
        BTP Router.
    vehicle_data : VehicleData
        Vehicle Data.
    cam_coder : CAMCoder
        CAM Coder.
    ca_basic_service_ldm : CABasicServiceLDM
        CA Basic Service LDM.
    t_gen_cam : int
        Time between CAM generations.
    last_cam_sent : CooperativeAwarenessMessage
        Last CAM sent.
    current_cam_to_send : CooperativeAwarenessMessage
        Current CAM to send.

    """

    def __init__(
        self,
        btp_router: BTPRouter,
        cam_coder: CAMCoder,
        vehicle_data: VehicleData,
        ca_basic_service_ldm: CABasicServiceLDM = None,
    ) -> None:
        """
        Initialize the CAM Transmission Management.
        """
        self.logging = logging.getLogger("ca_basic_service")
        self.btp_router: BTPRouter = btp_router
        self.vehicle_data = vehicle_data
        self.cam_coder = cam_coder
        self.ca_basic_service_ldm = ca_basic_service_ldm
        # self.T_GenCam_DCC = T_GenCamMin We don't have a DCC yet.
        self.t_gen_cam = T_GEN_CAM_MIN
        self.last_cam_sent = None
        self.current_cam_to_send = CooperativeAwarenessMessage()
        self.current_cam_to_send.fullfill_with_vehicle_data(self.vehicle_data)

    def location_service_callback(self, tpv: dict) -> None:
        """
        Callback function for location service.

        The Cooperative Awareness Service gets triggered everytime the location service gets a
        new position.

        TODO: Once the DCC is implemented, all conditions should be checked before sending a CAM.
        1) The time elapsed since the last CAM generation is equal to or greater than T_GenCam_Dcc,
        as applicable, and one of the following ITS-S dynamics related conditions is given:
            - the absolute difference between the current heading of the originating ITS-S and the
            heading included in the CAM previously transmitted by the originating ITS-S exceeds 4°;
            - the distance between the current position of the originating ITS-S and the position
            included in the CAM previously transmitted by the originating ITS-S exceeds 4 m;
            - the absolute difference between the current speed of the originating ITS-S and the
            speed included in the CAM previously transmitted by the originating ITS-S exceeds
            0,5 m/s.
        2) The time elapsed since the last CAM generation is equal to or greater than T_GenCam and,
        in the case of ITS-G5, is also equal to or greater than T_GenCam_Dcc.
        If one of the above two conditions is satisfied, a CAM shall be generated immediately.

        Parameters
        ----------
        tpv : dict
            GPSD TP
        """
        self.current_cam_to_send.fullfill_with_tpv_data(tpv)

        if self.last_cam_sent is None:
            self.send_next_cam()
            return
        received_generation_delta_time = GenerationDeltaTime()
        last_sent_generation_delta_time = GenerationDeltaTime()
        received_generation_delta_time.set_in_normal_timestamp(
            parser.parse(tpv["time"]).timestamp()
        )
        last_sent_generation_delta_time.msec = self.last_cam_sent.cam["cam"][
            "generationDeltaTime"
        ]
        if (
            received_generation_delta_time - last_sent_generation_delta_time
            >= self.t_gen_cam
        ):
            self.send_next_cam()
        else:
            pass

    def send_next_cam(self) -> None:
        """
        Send the next CAM.
        """
        if self.ca_basic_service_ldm is not None:
            self.ca_basic_service_ldm.add_provider_data_to_ldm(
                self.current_cam_to_send.cam
            )
        request = BTPDataRequest()
        request.btp_type = CommonNH.BTP_B
        request.destination_port = 2001
        request.gn_packet_transport_type = PacketTransportType()
        request.communication_profile = CommunicationProfile.UNSPECIFIED
        request.traffic_class = TrafficClass()
        request.data = self.cam_coder.encode(self.current_cam_to_send.cam)
        request.length = len(request.data)

        self.btp_router.btp_data_request(request)
        self.logging.debug(
            "Sent CAM message with timestamp: %d, station_id: %d",
            self.current_cam_to_send.cam["cam"]["generationDeltaTime"],
            self.current_cam_to_send.cam["header"]["stationId"],
        )

        self.last_cam_sent = self.current_cam_to_send
        self.current_cam_to_send = CooperativeAwarenessMessage()
        self.current_cam_to_send.fullfill_with_vehicle_data(self.vehicle_data)
