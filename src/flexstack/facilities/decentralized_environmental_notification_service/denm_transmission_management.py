import time
import threading
import logging
from ...utils.time_service import TimeService
from ...geonet.service_access_point import Area, GeoBroadcastHST, HeaderType
from .denm_coder import DENMCoder
from ...btp.router import Router as BTPRouter
from ...btp.service_access_point import BTPDataRequest, CommonNH, CommunicationProfile
from ...applications.road_hazard_signalling_service.service_access_point import (
    DENRequest,
)


class VehicleData:
    """
    Class that stores the vehicle data.

    Attributes
    ----------
    station_id : int
        Station ID as specified in ETSI TS 103 831 V2.1.1 (2022-11).
    station_type : int
        Station Type as specified in ETSI TS 103 831 V2.1.1 (2022-11).
    """

    def __init__(self) -> None:
        self.station_id = 0
        self.station_type = 0


class DecentralizedEnvironmentalNotificationMessage:
    """
    Decentralized Environmental Notification Message class.

    Attributes
    ----------
    denm : dict
        All the DENM message in dict format as decoded by the DENMCoder.
    sequence_number : int
        Sequence number to serialize the DENMs.
    """

    def __init__(self) -> None:
        self.denm = self.generate_white_denm()
        self.sequence_number = 0

    def generate_white_denm(self) -> dict:
        """
        Generate a white DENM.
        """
        white_denm = {
            "header": {"protocolVersion": 2, "messageId": 1, "stationId": 0},
            "denm": {
                "management": {
                    "actionId": {
                        "originatingStationId": 0,  # 4294967295
                        "sequenceNumber": 0,  # 65535
                    },
                    "detectionTime": 0,
                    "referenceTime": 0,
                    "termination": "isCancellation",
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
                    "relevanceDistance": "lessThan50m",
                    "relevanceTrafficDirection": "allTrafficDirections",
                    "validityDuration": 0,
                    "TransmissionInterval": 100,
                    "stationType": 0,
                }
            },
        }
        return white_denm

    def fullfill_with_denrequest(self, request: DENRequest) -> None:
        """
        Fullfill the DENM with the DENRequest data for the Road Hazard Signalling aplication.
        """
        # Add Management Container
        self.denm["denm"]["management"]["detectionTime"] = request.detection_time
        self.denm["denm"]["management"]["referenceTime"] = int(
            TimeService.timestamp_its()
        )
        self.denm["denm"]["management"]["TransmissionInterval"] = request.denm_interval

        self.denm["denm"]["management"][
            "relevanceDistance"
        ] = request.relevance_distance
        self.denm["denm"]["management"][
            "relevanceTrafficDirection"
        ] = request.relevance_traffic_direction
        # self.denm['denm']['management']['termination'] = request.DENMTermination
        # --> TODO: [OPTIONAL] to be implemented

        self.denm["denm"]["management"][
            "eventPosition"
        ] = request.event_position  # to be defined
        self.denm["denm"]["management"]["stationType"] = request.rhs_vehicle_type

        # Add Situation Container
        situation_container = {
            "informationQuality": request.quality,
            "eventType": {
                "ccAndScc": (request.rhs_cause_code, request.rhs_subcause_code)
            },
        }
        self.denm["denm"]["situation"] = situation_container

        # Add Location Container
        location_container = {
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
        self.denm["denm"]["location"] = location_container

    def fullfill_with_collision_risk_warning(self, request: DENRequest) -> None:
        """
        Fullfill the DENM with the DENRequest data for the Collision Risk Warning aplication.
        """
        # Add Management Container
        self.denm["denm"]["management"]["detectionTime"] = request.detection_time
        self.denm["denm"]["management"]["referenceTime"] = int(
            TimeService.timestamp_its()
        )
        self.denm["denm"]["management"]["TransmissionInterval"] = request.denm_interval

        self.denm["denm"]["management"]["eventPosition"] = request.event_position

        # Add Situation Container
        situation_container = {
            "informationQuality": request.quality,
            "eventType": {
                "ccAndScc": (request.lcrw_cause_code, request.lcrw_subcause_code)
            },
        }
        self.denm["denm"]["situation"] = situation_container

    def fullfill_with_vehicle_data(self, vehicle_data: VehicleData) -> None:
        """
        Fullfill the DENM with vehicle data.
        """
        self.denm["header"]["stationId"] = vehicle_data.station_id
        self.denm["denm"]["management"]["stationType"] = vehicle_data.station_type
        self.denm["denm"]["management"]["actionId"][
            "originatingStationId"
        ] = vehicle_data.station_id
        self.denm["denm"]["management"]["actionId"][
            "sequenceNumber"
        ] = self.sequence_number
        self.sequence_number = (self.sequence_number + 1) % 65535


class DENMTransmissionManagement:
    """
    DENM Transmission Management class.
    This sub-function implements the protocol operation of the originating ITS-S, as specified in
    ETSI TS 103 831 V2.1.1 (2022-11) Section 8, including in particular:
    - Trigger a thread to start the generation of consecutive DENM messages.
    - The general parameters of the DENM are defined in the application layer.
    - Transmission of the DENMs.

    Attributes
    ----------
    btp_router : BTPRouter
        BTP Router object.
    vehicle_data : VehicleData
        Vehicle data object.
    denm_coder : DENMCoder
        DENM Coder object.
    crw_denm : DecentralizedEnvironmentalNotificationMessage
        DENM message with the Collision Risk Warning data.
    new_denm : DecentralizedEnvironmentalNotificationMessage
        New DENM message to be sent, as Emergency Vehicle Warning message.
    """

    def __init__(
        self, btp_router: BTPRouter, denm_coder: DENMCoder, vehicle_data: VehicleData
    ) -> None:
        """
        Initialize the DENM Transmission Management.
        """
        self.logging = logging.getLogger("denm_service")
        self.btp_router: BTPRouter = btp_router
        self.vehicle_data = vehicle_data
        self.denm_coder = denm_coder
        self.crw_denm = DecentralizedEnvironmentalNotificationMessage()
        self.new_denm = DecentralizedEnvironmentalNotificationMessage()

    def request_denm_sending(self, denm_request: DENRequest) -> None:
        """
        Request to send a DENM and starts a thread.
        """
        t = threading.Thread(
            target=self.trigger_denm_messages, args=[denm_request])
        t.start()

    def send_collision_risk_warning_denm(self, denm_request: DENRequest) -> None:
        """
        Request to send a single DENM message with the Collision Risk Warning data.
        """
        self.crw_denm = DecentralizedEnvironmentalNotificationMessage()
        self.crw_denm.fullfill_with_vehicle_data(self.vehicle_data)
        self.crw_denm.fullfill_with_collision_risk_warning(denm_request)
        self.transmit_denm(self.crw_denm)

    def trigger_denm_messages(self, denm_request: DENRequest) -> None:
        """
        Function to transmits consecutive DENM message.

        Parameters
        ----------
        denm_request : DENRequest
            DENM Request object.
        """
        transmission_time = 0

        while transmission_time < denm_request.time_period:
            self.new_denm = DecentralizedEnvironmentalNotificationMessage()
            self.new_denm.fullfill_with_vehicle_data(self.vehicle_data)
            self.new_denm.fullfill_with_denrequest(denm_request)

            self.transmit_denm(self.new_denm)
            time.sleep(denm_request.denm_interval / 1000)
            transmission_time += denm_request.denm_interval

    def transmit_denm(
        self, denm_to_send: DecentralizedEnvironmentalNotificationMessage
    ) -> None:
        """
        Function to fullfill and send a single DENM message.

        Parameters
        ----------
        denm_to_send : DecentralizedEnvironmentalNotificationMessage
            New DENM message to be sent.
        """
        request = BTPDataRequest()
        request.btp_type = CommonNH.BTP_B
        request.destination_port = 2002
        request.gn_packet_transport_type.header_type = HeaderType.GEOBROADCAST
        request.gn_packet_transport_type.header_subtype = (
            GeoBroadcastHST.GEOBROADCAST_CIRCLE
        )
        request.gn_area = Area()
        request.gn_area.a = 100
        request.gn_area.b = 0
        request.gn_area.angle = 0
        request.gn_area.latitude = denm_to_send.denm["denm"]["management"][
            "eventPosition"
        ]["latitude"]
        request.gn_area.longitude = denm_to_send.denm["denm"]["management"][
            "eventPosition"
        ]["longitude"]
        request.communication_profile = CommunicationProfile.UNSPECIFIED
        request.data = self.denm_coder.encode(denm_to_send.denm)
        request.length = len(request.data)
        self.btp_router.btp_data_request(request)
        self.logging.debug(
            "Recieved DENM with timestamp: %s, station_id: %s",
            denm_to_send.denm["denm"]["management"]["referenceTime"],
            denm_to_send.denm["header"]["stationId"],
        )
