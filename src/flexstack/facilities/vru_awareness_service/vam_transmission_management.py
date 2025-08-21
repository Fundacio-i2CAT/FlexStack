from __future__ import annotations

import logging

from dateutil import parser

from ...facilities.local_dynamic_map.ldm_classes import Utils

from .vam_ldm_adaptation import VRUBasicServiceLDM

from .vam_coder import VAMCoder
from ...btp.router import Router as BTPRouter
from ...btp.service_access_point import (
    BTPDataRequest,
    CommonNH,
    PacketTransportType,
    CommunicationProfile,
    TrafficClass,
)
from ..ca_basic_service.cam_transmission_management import (
    GenerationDeltaTime,
    CooperativeAwarenessMessage,
)
from . import vam_constants

# from ..local_dynamic_map import LocalDynamicMap


class DeviceDataProvider:
    """
    Class that stores the vehicle data.

    Attributes
    ----------
    station_id : int
        Station ID as specified in ETSI TS 103 300-3 V2.2.1 (2023-02).
    station_type : int
        Station Type as specified in ETSI TS 103 300-3 V2.2.1 (2023-02).
    heading : dict
       Heading as specified in ETSI TS 103 300-3 V2.2.1 (2023-02).
    speed : dict
        Speed as specified in ETSI TS 103 300-3 V2.2.1 (2023-02).
    longitudinalAcceleration : dict
        Longitudinal Acceleration as specified in ETSI TS 103 300-3 V2.2.1 (2023-02).
    """

    def __init__(self) -> None:
        self.station_id = 0
        self.station_type = 0
        self.heading = {"value": 3601, "confidence": 127}
        self.speed = {"speedValue": 16383, "speedConfidence": 127}
        self.longitudinal_acceleration = {
            "longitudinalAccelerationValue": 161,
            "longitudinalAccelerationConfidence": 102,
        }


class PathPoint:
    """
    Class that stores the path point data.

    Attributes
    ----------
    pathPosition : tuple
        The pathPosition DF shall comprise the latitude, longitude and altitude of the VRU.
        All values as specified by ETSI TS 103 300-3 V2.2.1 (2023-02).
    pathDeltaTime : int
        The pathDeltaTime DF shall comprise the time difference between the current time and
        the time when the VRU was at the pathPosition.
        All values as specified by ETSI TS 103 300-3 V2.2.1 (2023-02).
    """

    def __init__(self, latitude, longitude, altitude, time=None):
        self.path_position = (latitude, longitude, altitude)
        self.path_delta_time = time


class PathHistory:
    """
    Class that stores the path history data.

    Attributes
    ----------
    pathPoints : list
        The pathPoints DF shall comprise the VRU's recent movement over the last 40 pathPoints.
        All values as specified by ETSI TS 103 300-3 V2.2.1 (2023-02).
    """

    def __init__(self, path_points: list[PathPoint] = None):
        self.path_points = path_points

    def append(self, path_point):
        """
        Appends each point to the pathPoints list. With a maximum value of 40
        (as specified by ETSI TS 103 300-3 V2.2.1 (2023-02))

        Attributes
        ----------
        path_point : PathPoint

        """
        try:
            if len(self.path_points) >= 40:
                self.path_points.pop(0)
            self.path_points.append(path_point)
        except TypeError:
            self.path_points = [path_point]

    def generate_path_history_dict(self):
        """
        Generates the path history JSON data.

        Attributes
        ----------
        path_points : list
            The pathPoints DF shall comprise the VRU's recent movement over the last 40 pathPoints.
            All values as specified by ETSI TS 103 300-3 V2.2.1 (2023-02).
        """
        path_points = []
        for path_point in self.path_points:
            path_points.append(
                {
                    "pathPosition": {
                        "latitude": path_point.path_position[0],
                        "longitude": path_point.path_position[1],
                        "altitude": path_point.path_position[2],
                    },
                    "pathDeltaTime": path_point.path_delta_time,
                }
            )
        return path_points


class PathPointPredicted:
    """
    Class that stores the path point predicted data.

    Attributes
    ----------
    deltaLatitude : int
        The deltaLatitude DF shall comprise an offset latitude with regards to a
        pre-defined reference position.
        All values as specified by ETSI TS 103 300-3 V2.2.1 (2023-02).
    deltaLongitude : int
        The deltaLongitude DF shall comprise an offset longitude with regards to a
        pre-defined reference position.
        All values as specified by ETSI TS 103 300-3 V2.2.1 (2023-02).
    pathDeltaTime : int
        The pathDeltaTime DF shall comprise the  travel time separated from the
        waypoint to the predefined reference position.
        All values as specified by ETSI TS 103 300-3 V2.2.1 (2023-02).

    Attributes: horizontalPositionConfidence (OPTIONAL), deltaAltitude (UNAVAILABLE),
                altitudeConfidence (UNAVAILABLE) are not currently implemented.
    """

    def __init__(self, delta_latitude, delta_longitude, path_delta_time):
        self.delta_latitude = delta_latitude
        self.delta_longitude = delta_longitude
        self.path_delta_time = path_delta_time

    def __dict__(self) -> dict:
        return {
            "deltaLatitude": self.delta_latitude,
            "deltaLongitude": self.delta_longitude,
            "pathDeltaTime": self.path_delta_time,
        }


class PathPrediction:
    """
    Class that stores the path prediction data.

    Attributes
    ----------
    pathPointPredicted : list
        The pathPoints DF shall comprise the VRU's recent movement over the last 40 pathPoints.
        All values as specified by ETSI TS 103 300-3 V2.2.1 (2023-02).
    """

    def __init__(self, path_point_predicted: list[PathPointPredicted] = None):
        self.path_point_predicted = path_point_predicted

    def append(self, path_point: PathPointPredicted):
        """
        Function to append data into the PathPrediction class. It will append data until the
        maximum length of 15 is achieved. Then it will act as a FIFO memory.

        Parameters
        -----------
        path_point: PathPointPredicted
            The path point predicted

        Returns
        --------
        None
        """
        try:
            if len(self.path_point_predicted) >= 15:
                self.path_point_predicted.pop(0)
            self.path_point_predicted.append(path_point)
        except TypeError:
            self.path_point_predicted = [path_point]

    def generate_path_prediction_dict(self):
        """
        Generates a json object from the PathPrediction class.

        Returns
        -------
        dict
            A dictionary containing the PathPrediction class attributes.
        """
        return {
            "pathPointPredicted": [
                path_point.__dict__() for path_point in self.path_point_predicted
            ]
        }


class MotionPredictionContainer:
    """
    TODO: Implement the Motion Prediction Container using the Local Dynamic Map (LDM).

    As specified by ETSI TS 103 300-3 V2.2.1 (2023-02);

    The VRU Motion Prediction Container carries the past and future motion state information of
    the VRU. The VRU Motion Prediction Container of type VruMotionPredictionContainer shall contain
    information about the past locations of the VRU of type PathHistory, predicted future locations
    of the VRU, safe distance indication between VRU and other road users/objects of type
    SequenceOfSafeDistanceIndication, VRU's possible trajectory interception with another
    VRU/object shall be of type SequenceOfTrajectoryInterceptionIndication , the change in the
    acceleration of the VRU shall be of type AccelerationChangeIndication, the heading changes of
    the VRU shall be of HeadingChangeIndication, and changes in the stability of the VRU shall be
    of type StabilityChangeIndication:

    - The pathHistory is of PathHistory type. The PathHistory DF shall comprise the VRU's recent
        movement over past time and/or distance. It consists of up to 40 past path points
        (see ETSI TS 102 894-2 [7]). When a VRU leaves a cluster and wants to transmit its past
        locations in the VAM, the VRU may use the PathHistory DF.
    - The Path Prediction DF is of PathPredicted type and shall define up to 15 future path points,
        confidence values and corresponding time instances of the VRU ITS-S. It contains future
        path information for up to 10 seconds or up to 15 path points, whichever is smaller.
    - The Safe Distance Indication is of type SequenceOfSafeDistanceIndication and provides an
        indication of whether the VRU is at a recommended safe distance laterally,
        longitudinally and vertically from up to 8 other stations in its vicinity. The simultaneous
        comparisons between Lateral Distance (LaD), Longitudinal Distance (LoD) and
        Vertical Distance (VD) and their respective thresholds, Minimum Safe Lateral Distance
        (MSLaD), Minimum Safe Longitudinal Distance (MSLoD), and Minimum Safe Vertical Distance
        (MSVD) as defined inclause 6.5.10.5 of ETSI TS 103 300-2 [1], shall be used for setting the
        safeDistanceIndicator DF. Other ITS-s involved are indicated as subjectStation DE within
        the SafeDistanceIndication DE. The timeToCollision (TTC) DE within the container shall
        reflect the estimated time taken for collision based on the latest onboard sensor
        measurements and VAMs.
    - The trajectoryInterceptionIndication shall contain ego-VRU's possible trajectory interception
        with up to 8 other stations in the vicinity of the ego-VRU. The trajectory interception of
        a VRU is indicated by trajectoryInterceptionIndication DF. The other ITS-S involved are
        designated by StationID DE. The trajectory interception probability and its confidence
        level metrics are indicated by TrajectoryInterceptionProbability and
        TrajectoryInterceptionConfidence DEs.
    - The accelerationChangeIndication shall contain ego-VRU's change of acceleration in the
        future (acceleration or deceleration) for a time period. The DE accelOrDecel shall give the
        choice between acceleration and deceleration. The DE actionDeltaTime shall indicate the
        time duration.
    - The headingChangeIndication shall contain ego-VRU's change of heading in the future
        (left or right) for a time period. The DE directionshall give the choice between heading
        change in left and right directions. The DE actionDeltaTime shall indicate the time
        duration.
    - The stabilityChangeIndication shall contain ego-VRU's change in stability for a time period.
        The lossProbability shall give the probability indication of the stability loss of the
        ego-VRU. It is expressed in the estimated probability of a complete VRU stability loss
        which may lead to a VRU ejection of its VRU vehicle. The loss of stability is projected
        for a time period actionDeltaTime.
    """

    def __init__(
        self,
        path_history: PathHistory,
        path_prediction: PathPrediction,
        safe_distance=None,
        trajectory_interception_indication=None,
        acceleration_change_indication=None,
        heading_change_indication=None,
        stability_change_indication=None,
    ) -> None:
        self.path_history = path_history
        self.path_prediction = path_prediction
        self.safe_distance = safe_distance
        self.trajectory_interception_indication = trajectory_interception_indication
        self.acceleration_change_indication = acceleration_change_indication
        self.heading_change_indication = heading_change_indication
        self.stability_change_indication = stability_change_indication

    def generate_motion_container_message(self) -> dict:
        """
        Function to Generate Motion Containers (as specified in ETSI TS 103 300-3 V2.2.1 (2023-02)).

        Parameters
        ----------
        None
        """
        motion_prediction_container_json = {
            "pathHistory": self.path_history.generate_path_history_dict(),
            "pathPrediction": self.path_prediction.generate_path_prediction_dict(),
            "safeDistance": self.safe_distance,
            "trajectoryInterceptionIndication": self.trajectory_interception_indication,
            "accelerationChangeIndication": self.acceleration_change_indication,
            "headingChangeIndication": self.heading_change_indication,
            "stabilityChangeIndication": self.stability_change_indication,
        }
        return motion_prediction_container_json


class VAMMessage(CooperativeAwarenessMessage):
    """
    VAM Message class.

    Attributes
    ----------
    vam : dict
        All the vam message in dict format as decoded by the vamCoder.

    """

    def __init__(self) -> None:
        super().__init__()
        self.vam = self.generate_white_vam()

    def generate_white_vam(self) -> dict:
        """
        Generate a white vam.
        """
        white_vam = {
            "header": {"protocolVersion": 3, "messageId": 16, "stationId": 0},
            "vam": {
                "generationDeltaTime": 0,
                "vamParameters": {
                    "basicContainer": {
                        # roadSideUnit(15), cyclist(2)
                        "stationType": 15,
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
                    "vruHighFrequencyContainer": {
                        "heading": {"value": 3601, "confidence": 127},
                        "speed": {"speedValue": 16383, "speedConfidence": 127},
                        "longitudinalAcceleration": {
                            "longitudinalAccelerationValue": 161,
                            "longitudinalAccelerationConfidence": 102,
                        },
                    },
                },
            },
        }

        return white_vam

    def fullfill_with_device_data(
        self, device_data_provider: DeviceDataProvider
    ) -> None:
        """
        Fullfill the vam with vehicle data.
        """
        self.vam["header"]["stationId"] = device_data_provider.station_id
        self.vam["vam"]["vamParameters"]["basicContainer"][
            "stationType"
        ] = device_data_provider.station_type
        self.vam["vam"]["vamParameters"]["vruHighFrequencyContainer"][
            "heading"
        ] = device_data_provider.heading
        self.vam["vam"]["vamParameters"]["vruHighFrequencyContainer"][
            "speed"
        ] = device_data_provider.speed
        self.vam["vam"]["vamParameters"]["vruHighFrequencyContainer"][
            "longitudinalAcceleration"
        ] = device_data_provider.longitudinal_acceleration

    def fullfill_gen_delta_time_with_tpv_data(self, tpv: dict) -> None:
        """
        Fullfills the generation delta time with the GPSD TPV data.

        Attributes
        ----------
        tpv : dict
            GPSD TPV data.
        """
        if "time" in tpv:
            gen_delta_time = GenerationDeltaTime()
            gen_delta_time.set_in_normal_timestamp(parser.parse(tpv["time"]).timestamp())
            self.vam["vam"]["generationDeltaTime"] = int(gen_delta_time.msec)

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

        return position_confidence_ellipse

    def fullfill_basic_container_with_tpv_data(self, tpv: dict) -> None:
        """
        Fullfills the basic container with the GPSD TPV data.

        Attributes
        ----------
        tpv : dict
            GPSD TPV data.
        """
        if "lat" in tpv.keys():
            self.vam["vam"]["vamParameters"]["basicContainer"]["referencePosition"][
                "latitude"
            ] = int(tpv["lat"] * 10000000)
        if "lon" in tpv.keys():
            self.vam["vam"]["vamParameters"]["basicContainer"]["referencePosition"][
                "longitude"
            ] = int(tpv["lon"] * 10000000)
        if "epx" in tpv.keys() and "epy" in tpv.keys():
            self.vam["vam"]["vamParameters"]["basicContainer"]["referencePosition"][
                "positionConfidenceEllipse"
            ] = self.create_position_confidence(tpv["epx"], tpv["epy"])
        if "altHAE" in tpv.keys():
            alt = int(tpv["altHAE"] * 100)
            if alt < -800000:
                self.vam["vam"]["vamParameters"]["basicContainer"]["referencePosition"][
                    "altitude"
                ]["altitudeValue"] = -100000
            elif alt > 613000:
                self.vam["vam"]["vamParameters"]["basicContainer"]["referencePosition"][
                    "altitude"
                ]["altitudeValue"] = 800000
            else:
                self.vam["vam"]["vamParameters"]["basicContainer"]["referencePosition"][
                    "altitude"
                ]["altitudeValue"] = int(tpv["altHAE"] * 100)
        if "epv" in tpv.keys():
            self.vam["vam"]["vamParameters"]["basicContainer"]["referencePosition"][
                "altitude"
            ]["altitudeConfidence"] = self.create_altitude_confidence(tpv["epv"])

    def fullfill_high_frequency_container_with_tpv_data(self, tpv: dict) -> None:
        """
        Fullfills the high frequency container with the GPSD TPV data.
        Attributes
        ----------
        tpv : dict
            GPSD TPV data.
        """
        if "track" in tpv.keys():
            self.vam["vam"]["vamParameters"]["vruHighFrequencyContainer"]["heading"][
                "headingValue"
            ] = int(tpv["track"]*10)
        if "epd" in tpv.keys():
            self.vam["vam"]["vamParameters"]["vruHighFrequencyContainer"]["heading"][
                "headingConfidence"
            ] = self.create_heading_confidence(tpv["epd"])
        if "speed" in tpv.keys():
            if int(tpv["speed"] * 100) > 16381:
                self.vam["vam"]["vamParameters"]["vruHighFrequencyContainer"]["speed"][
                    "speedValue"
                ] = 16382
            else:
                self.vam["vam"]["vamParameters"]["vruHighFrequencyContainer"]["speed"][
                    "speedValue"
                ] = int(tpv["speed"] * 100)


class VAMTransmissionManagement:
    """
    vam Transmission Management class.
    This sub-function implements the protocol operation of the originating ITS-S, as specified in
    ETSI TS 103 300-3 V2.2.1 clause 6, including in particular:
    - Activation and termination of vam transmission operation.
    - Determination of the vam generation frequency.
    - Trigger the generation of vam.

    Attributes
    ----------
    vam_coder : vamCoder
        vam Coder object.
    T_Genvam_DCC : int
        Time to wait between vams according to the DCC.
    T_Genvam : int
        Time to wait between vams.
    N_Genvam : int
        Consecutive vams to be generated.
    last_vam_sent : dict
        Last vam sent.
    current_vam_to_send : dict
        Current vam to send.
    """

    def __init__(
        self,
        btp_router: BTPRouter,
        vam_coder: VAMCoder,
        device_data_provider: DeviceDataProvider,
        vru_basic_service_ldm: VRUBasicServiceLDM = None,
    ) -> None:
        """
        Initialize the vam Transmission Management.
        """
        self.logging = logging.getLogger("vru_basic_service")
        self.btp_router: BTPRouter = btp_router
        self.device_data_provider = device_data_provider
        self.vru_basic_service_ldm = vru_basic_service_ldm
        self.vam_coder = vam_coder
        # self.T_Genvam_DCC = T_GenvamMin We don't have a DCC yet.
        self.t_genvam = vam_constants.T_GENVAMMIN
        self.n_genvam = 1
        self.last_vam_sent = None
        self.current_vam_to_send = VAMMessage()
        self.current_vam_to_send.fullfill_with_device_data(self.device_data_provider)

    def location_service_callback(self, tpv: dict) -> None:
        """
        Callback function for location service.

        The VAM gets triggered everytime the location service gets a new position.

        TODO: Conditions 5-7 are not currently implemented. Conditions 5 and 7 will be implemented
            once the Local Dynamic Map (LDM)
        TODO: is available. Condition 6 will be implemented once cluster functionality is
            implemented.

        ETSI TS 103 300-3 V2.2.1 (2023-02) Clause 6.4.1 Individual VAM transmission management
        by VBS at VRU ITS-S.
        The first time individual VAM shall be generated immediately after VBS activation.
        The VAM shall also be generated at the earliest time instant for transmission if any
        of the following conditions are satisfied and the individual VAM transmission does not
        subject to redundancy mitigation techniques:

        1) A VRU is in VRU-IDLE VBS state and has entered VRU-ACTIVE-STANDALONE.
        2) A VRU is in VRU-PASSIVE VBS state; it decides to leave the cluster and enters in
            VRU-ACTIVE-STANDALONE VBS state.
        3) A VRU is in VRU-PASSIVE VBS state; it has determined that VRU cluster leader is lost
            and has decided to enter VRU-ACTIVE-STANDALONE VBS state.
        4) A VRU is in VRU-ACTIVE-CLUSTER-LEADER VBS state; it has determined breaking up the
            cluster and has transmitted VRU cluster VAM with disband indication; it has decided
            to enter VRU-ACTIVE-STANDALONE VBS state.

        Consecutive VAM transmissions are contingent upon the conditions described here.
        Consecutive individual VAM generation events shall occur at an interval equal to or
        larger than T_GenVam. An individual VAM shall be generated for transmission as part of
        a generation event if the originating VRU ITS-S is still in VBS
        VRU-ACTIVE-STANDALONE VBS state, any of the following conditions is satisfied and
        individual VAM transmission is not subject to redundancy mitigation techniques:

        1) The time elapsed since the last time the individual VAM was transmitted exceeds
            T_GENVAMAX.
        2) The Euclidian absolute distance between the current estimated position of the
            reference point of the VRU and the estimated position of the reference point
            lastly included in an individual VAM exceeds a pre-defined threshold
            minReferencePointPositionChangeThreshold.
        3) The difference between the current estimated ground speed of the reference point of
            the VRU and the estimated absolute speed of the reference point of the VRU lastly
            included in an individual VAM exceeds a pre-defined threshold
            minGroundSpeedChangeThreshold.
        4) The difference between the orientation of the vector of the current estimated ground
            velocity of the reference point of the VRU and the estimated orientation of the
            vector of the ground velocity of the reference point of the VRU lastly included in
            an individual VAM exceeds a pre-defined threshold
            minGroundVelocityOrientationChangeThreshold.
        5) The VRU has determined that there is a difference between the current estimated
            trajectory interception probability with vehicle(s) or other VRU(s) and the
            trajectory interception probability with vehicle(s) or other VRU(s) lastly reported
            in an individual VAM exceeds a predefined threshold
            minTrajectoryInterceptionProbChangeThreshold.
        6) The originating ITS-S is a VRU in VRU-ACTIVE-STANDALONE VBS state and has decided
            to join a cluster after its previous individual VAM transmission.
        7) VRU has determined that one or more new vehicles or other VRUs have satisfied the
            following conditions simultaneously after the lastly transmitted VAM:
                - coming closer than Minimum Safe Lateral Distance (MSLaD) laterally;
                - coming closer than Minimum Safe Longitudinal Distance (MSLoD) longitudinally;
                - coming closer than Minimum Safe Vertical Distance (MSVD) vertically.
        """
        self.current_vam_to_send.fullfill_with_tpv_data(tpv)
        self.logging.debug("Fullfilled VAM with TPV data %s", tpv)

        if self.last_vam_sent is None:
            self.send_next_vam()
            return
        received_generation_delta_time = GenerationDeltaTime()
        last_sent_generation_delta_time = GenerationDeltaTime()
        received_generation_delta_time.set_in_normal_timestamp(
            parser.parse(tpv["time"]).timestamp()
        )
        last_sent_generation_delta_time.msec = self.last_vam_sent.vam["vam"][
            "generationDeltaTime"
        ]

        received_position = [int(tpv["lat"]), int(tpv["lon"])]
        last_sent_position = [
            self.last_vam_sent.vam["vam"]["vamParameters"]["basicContainer"][
                "referencePosition"
            ]["latitude"],
            self.last_vam_sent.vam["vam"]["vamParameters"]["basicContainer"][
                "referencePosition"
            ]["longitude"],
        ]

        if (
            received_generation_delta_time - last_sent_generation_delta_time
            >= self.t_genvam
        ):
            self.send_next_vam()
            return
        if (
            Utils.euclidian_distance(received_position, last_sent_position)
            > vam_constants.MINREFERENCEPOINTPOSITIONCHANGETHRESHOLD
        ):
            self.send_next_vam()
            return
        if (
            abs(
                tpv["speed"]
                - self.last_vam_sent.vam["vam"]["vamParameters"][
                    "vruHighFrequencyContainer"
                ]["speed"]["speedValue"]
            )
            > vam_constants.MINGROUNDSPEEDCHANGETHRESHOLD
        ):
            self.send_next_vam()
            return

    def send_next_vam(self) -> None:
        """
        Send the next vam.

        BTP Port Number: 2018
        """
        if self.vru_basic_service_ldm is not None:
            self.vru_basic_service_ldm.add_provider_data_to_ldm(
                self.current_vam_to_send.vam
            )
        request = BTPDataRequest()
        request.btp_type = CommonNH.BTP_B
        request.destination_port = 2018
        request.gn_packet_transport_type = PacketTransportType()
        request.communication_profile = CommunicationProfile.UNSPECIFIED
        request.traffic_class = TrafficClass()
        request.data = self.vam_coder.encode(self.current_vam_to_send.vam)
        request.length = len(request.data)
        self.btp_router.btp_data_request(request)
        self.logging.info(
            "Sent VAM message with timestamp: %s, station_id: %s",
            self.current_vam_to_send.vam['vam']['generationDeltaTime'],
            self.current_vam_to_send.vam['header']['stationId']
        )
        self.last_vam_sent = self.current_vam_to_send
        self.current_vam_to_send = VAMMessage()
        self.current_vam_to_send.fullfill_with_device_data(self.device_data_provider)
