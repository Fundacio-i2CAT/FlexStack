from __future__ import annotations
from types import MappingProxyType
from typing import Mapping
import logging
from dataclasses import dataclass, field
import threading
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
from ...utils.time_service import TimeService
from ..ca_basic_service.cam_transmission_management import CooperativeAwarenessMessage, GenerationDeltaTime
from ...security.security_profiles import SecurityProfile
from . import vam_constants
from .vru_clustering import VBSClusteringManager


@dataclass(frozen=True)
class DeviceDataProvider:
    """
    Immutable DeviceDataProvider for thread-safe access.

    Attributes
    ----------
    station_id : int
        Station ID as specified in ETSI TS 103 300-3 V2.2.1 (2023-02).
    station_type : int
        Station Type as specified in ETSI TS 103 300-3 V2.2.1 (2023-02).
    heading : Mapping[str, int]
        Heading as specified in ETSI TS 103 300-3 V2.2.1 (2023-02).
    speed : Mapping[str, int]
        Speed as specified in ETSI TS 103 300-3 V2.2.1 (2023-02).
    longitudinal_acceleration : Mapping[str, int]
        Longitudinal Acceleration as specified in ETSI TS 103 300-3 V2.2.1 (2023-02).
    """

    station_id: int = 0
    station_type: int = 0
    heading: Mapping[str, int] = field(
        default_factory=lambda: MappingProxyType(
            {"value": 3601, "confidence": 127})
    )
    speed: Mapping[str, int] = field(
        default_factory=lambda: MappingProxyType(
            {"speedValue": 16383, "speedConfidence": 127})
    )
    longitudinal_acceleration: Mapping[str, int] = field(
        default_factory=lambda: MappingProxyType(
            {
                "longitudinalAccelerationValue": 161,
                "longitudinalAccelerationConfidence": 102,
            }
        )
    )


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

    def __init__(self, path_points: list[PathPoint] | None = None):
        if path_points is None:
            path_points = []
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

    def to_dict(self) -> dict:
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

    def __init__(self, path_point_predicted: list[PathPointPredicted] | None = None):
        if path_point_predicted is None:
            path_point_predicted = []
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
                path_point.to_dict() for path_point in self.path_point_predicted
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


@dataclass(frozen=True)
class VAMMessage(CooperativeAwarenessMessage):
    """
    VAM Message class.

    Attributes
    ----------
    vam : dict
        All the vam message in dict format as decoded by the vamCoder.

    """
    vam: dict = field(
        default_factory=lambda: VAMMessage.generate_white_vam_static())

    @staticmethod
    def generate_white_vam_static() -> dict:
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

    def generate_white_vam(self) -> dict:
        """
        Generate a white vam.
        """
        return self.generate_white_vam_static()

    def fullfill_with_device_data(
        self, device_data_provider: DeviceDataProvider
    ) -> None:
        """
        Fullfill the vam with vehicle data.
        """
        self.vam["header"]["stationId"] = int(device_data_provider.station_id)
        self.vam["vam"]["vamParameters"]["basicContainer"]["stationType"] = int(
            device_data_provider.station_type
        )
        self.vam["vam"]["vamParameters"]["vruHighFrequencyContainer"]["heading"] = dict(
            device_data_provider.heading
        )
        self.vam["vam"]["vamParameters"]["vruHighFrequencyContainer"]["speed"] = dict(
            device_data_provider.speed
        )
        self.vam["vam"]["vamParameters"]["vruHighFrequencyContainer"][
            "longitudinalAcceleration"
        ] = dict(device_data_provider.longitudinal_acceleration)

    def fullfill_gen_delta_time_with_tpv_data(self, tpv: dict) -> None:
        """
        Fullfills the generation delta time with the GPSD TPV data.

        Attributes
        ----------
        tpv : dict
            GPSD TPV data.
        """
        if "time" in tpv:
            gen_delta_time = GenerationDeltaTime.from_timestamp(
                parser.parse(tpv["time"]).timestamp())
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
                "value"
            ] = int(tpv["track"]*10)
        if "epd" in tpv.keys():
            self.vam["vam"]["vamParameters"]["vruHighFrequencyContainer"]["heading"][
                "confidence"
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
    VAM Transmission Management.

    Implements the originating-ITS-S protocol operation specified in
    ETSI TS 103 300-3 V2.3.1 (2025-12), clause 6, including:

    * Activation and termination of VAM transmission.
    * VAM generation frequency determination (Table 16).
    * Triggering VAM generation according to conditions 1–4 of clause 6.4.1.
    * Periodic inclusion of the VRU Low-Frequency Container (clause 6.2).
    * Integration with the VBS clustering state machine (clause 5.4).

    Attributes
    ----------
    btp_router:
        BTP router used to send the encoded VAM.
    device_data_provider:
        Static device parameters (station ID, station type, etc.).
    vru_basic_service_ldm:
        Optional LDM adapter for storing own VAMs.
    vam_coder:
        ASN.1 encode/decode wrapper.
    clustering_manager:
        Optional VBS clustering state machine.  When provided, VAM
        transmission is suppressed in VRU_PASSIVE state and cluster
        containers are appended to outgoing VAMs.
    """

    def __init__(
        self,
        btp_router: BTPRouter,
        vam_coder: VAMCoder,
        device_data_provider: DeviceDataProvider,
        vru_basic_service_ldm: VRUBasicServiceLDM | None = None,
        clustering_manager: VBSClusteringManager | None = None,
    ) -> None:
        """
        Initialise VAM Transmission Management.

        Parameters
        ----------
        btp_router:
            BTP router instance.
        vam_coder:
            VAM ASN.1 coder.
        device_data_provider:
            Immutable device parameters.
        vru_basic_service_ldm:
            Optional LDM adapter.
        clustering_manager:
            Optional VBS clustering manager.  Pass ``None`` to disable
            cluster-aware transmission.
        """
        self.logging = logging.getLogger("vru_basic_service")
        self.btp_router: BTPRouter = btp_router
        self.device_data_provider = device_data_provider
        self.vru_basic_service_ldm = vru_basic_service_ldm
        self.vam_coder = vam_coder
        self.clustering_manager: VBSClusteringManager | None = clustering_manager
        # self.T_Genvam_DCC = T_GenvamMin We don't have a DCC yet.
        self.t_genvam = vam_constants.T_GENVAMMIN
        self.n_genvam = 1
        self.last_vam_generation_delta_time: GenerationDeltaTime | None = None
        self.last_sent_position: tuple[float, float] = (0.0, 0.0)
        self.last_vam_info_lock = threading.Lock()
        self.last_vam_speed: float = 0.0
        self.last_vam_heading: float = 0.0
        #: Time (seconds since epoch) when the LF container was last included.
        self.last_lf_vam_time: float | None = None
        #: True until the first VAM has been sent; used to force LF inclusion.
        self.is_first_vam: bool = True

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
        vam_to_send = VAMMessage()
        vam_to_send.fullfill_with_device_data(self.device_data_provider)
        vam_to_send.fullfill_with_tpv_data(tpv)
        self.logging.debug("Fullfilled VAM with TPV data %s", tpv)

        # Suppress individual VAMs when passive (clustering state machine).
        if (
            self.clustering_manager is not None
            and not self.clustering_manager.should_transmit_vam()
        ):
            return

        if self.last_vam_generation_delta_time is None:
            self.send_next_vam(vam=vam_to_send)
            return
        received_generation_delta_time = GenerationDeltaTime.from_timestamp(
            parser.parse(tpv["time"]).timestamp()
        )

        diff_time: int = received_generation_delta_time - \
            self.last_vam_generation_delta_time
        if (
            diff_time
            >= self.t_genvam
        ):
            self.send_next_vam(vam=vam_to_send)
            return
        received_position = (tpv["lat"], tpv["lon"])
        if (
            Utils.euclidian_distance(
                received_position, self.last_sent_position)
            > vam_constants.MINREFERENCEPOINTPOSITIONCHANGETHRESHOLD
        ):
            self.send_next_vam(vam=vam_to_send)
            return
        if (
            abs(
                tpv["speed"]
                - self.last_vam_speed
            )
            > vam_constants.MINGROUNDSPEEDCHANGETHRESHOLD
        ):
            self.send_next_vam(vam=vam_to_send)
            return
        # Condition 4 (clause 6.4.1): heading change exceeds threshold.
        if "track" in tpv:
            heading_diff = abs(tpv["track"] - self.last_vam_heading) % 360.0
            if heading_diff > 180.0:
                heading_diff = 360.0 - heading_diff
            if heading_diff > vam_constants.MINGROUNDVELOCITYORIENTATIONCHANGETHRESHOLD:
                self.send_next_vam(vam=vam_to_send)
                return

    def _attach_lf_container_if_due(self, vam: VAMMessage) -> None:
        """Attach ``vruLowFrequencyContainer`` to *vam* when required.

        The Low-Frequency Container shall be included (clause 6.2):

        * On the first transmitted VAM.
        * When the time elapsed since the last LF container exceeds
          ``T_GenVamLFMin`` (2 000 ms).
        * Whenever a ``VruClusterOperationContainer`` is also present, so
          that receivers can correlate cluster operations with a full VRU
          profile update.

        Parameters
        ----------
        vam:
            The :class:`VAMMessage` that is about to be transmitted.
        """
        import time as _time_module
        now = _time_module.time()
        has_cluster_op = (
            "vruClusterOperationContainer"
            in vam.vam["vam"]["vamParameters"]
        )
        lf_due = (
            self.is_first_vam
            or self.last_lf_vam_time is None
            or (now - self.last_lf_vam_time) * 1000
            >= vam_constants.T_GENVAM_LFMIN
            or has_cluster_op
        )
        if lf_due:
            # The LF container carries VRU profile and device usage.
            # Profile is derived from the station type in the basic container.
            vam.vam["vam"]["vamParameters"]["vruLowFrequencyContainer"] = {
                "profileAndSubprofile": ("pedestrian", "unavailable")
            }
            self.last_lf_vam_time = now

    def send_next_vam(self, vam: VAMMessage) -> None:
        """Encode and send *vam* via the BTP router.

        Before encoding, this method:

        * Attaches cluster containers from the clustering state machine
          (when a :class:`~.vru_clustering.VBSClusteringManager` is
          configured).
        * Attaches the ``VruLowFrequencyContainer`` when inclusion criteria
          are met (clause 6.2).

        BTP destination port: 2018 (as specified in Table B.2 of
        ETSI TS 103 300-3 V2.3.1).
        """
        params = vam.vam["vam"]["vamParameters"]

        # Attach cluster containers when clustering is active.
        if self.clustering_manager is not None:
            cluster_info = self.clustering_manager.get_cluster_information_container()
            if cluster_info is not None:
                params["vruClusterInformationContainer"] = cluster_info
            cluster_op = self.clustering_manager.get_cluster_operation_container()
            if cluster_op is not None:
                params["vruClusterOperationContainer"] = cluster_op

        # Attach LF container when due (must be done *after* cluster-op is
        # present so has_cluster_op detection inside the helper works).
        self._attach_lf_container_if_due(vam)

        if self.vru_basic_service_ldm is not None:
            vam_ldm = vam.vam.copy()
            vam_ldm["utc_timestamp"] = int(TimeService.time()*1000)
            self.vru_basic_service_ldm.add_provider_data_to_ldm(
                vam.vam
            )
        data = self.vam_coder.encode(vam.vam)
        request = BTPDataRequest(
            btp_type=CommonNH.BTP_B,
            destination_port=2018,
            gn_packet_transport_type=PacketTransportType(),
            communication_profile=CommunicationProfile.UNSPECIFIED,
            traffic_class=TrafficClass(),
            security_profile=SecurityProfile.VRU_AWARENESS_MESSAGE,
            its_aid=638,
            data=data,
            length=len(data),
        )
        self.btp_router.btp_data_request(request)
        self.logging.info(
            "Sent VAM message with timestamp: %s, station_id: %s",
            vam.vam['vam']['generationDeltaTime'],
            vam.vam['header']['stationId']
        )
        with self.last_vam_info_lock:
            self.last_vam_generation_delta_time = GenerationDeltaTime(
                msec=vam.vam['vam']['generationDeltaTime'])
            self.last_sent_position = (
                vam.vam["vam"]["vamParameters"]["basicContainer"][
                    "referencePosition"
                ]["latitude"]/10**7,
                vam.vam["vam"]["vamParameters"]["basicContainer"][
                    "referencePosition"
                ]["longitude"]/10**7,
            )
            self.last_vam_speed = vam.vam["vam"]["vamParameters"][
                "vruHighFrequencyContainer"
            ]["speed"]["speedValue"] / 100
            self.last_vam_heading = (
                vam.vam["vam"]["vamParameters"][
                    "vruHighFrequencyContainer"
                ]["heading"]["value"] / 10.0
            )
            self.is_first_vam = False
