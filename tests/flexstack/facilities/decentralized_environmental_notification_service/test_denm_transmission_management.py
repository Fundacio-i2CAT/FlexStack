import unittest
from unittest.mock import MagicMock, patch
from flexstack.applications.road_hazard_signalling_service.service_access_point import DENRequest
from flexstack.facilities.decentralized_environmental_notification_service.denm_coder import DENMCoder
from flexstack.facilities.decentralized_environmental_notification_service.\
    denm_transmission_management import (
        DENMTransmissionManagement, DecentralizedEnvironmentalNotificationMessage
    )
from flexstack.facilities.ca_basic_service.cam_transmission_management import VehicleData


class TestDecentralizedEnvironmentalNotificationMessage(unittest.TestCase):
    """Test class for the DecentralizedEnvironmentalNotificationMessage."""

    def test__init__(self):
        """Test DecentralizedEnvironmentalNotificationMessage initialization"""
        decentralized_environmental_notification_message = \
            DecentralizedEnvironmentalNotificationMessage()
        coder = DENMCoder()
        encoded_white = coder.encode(
            decentralized_environmental_notification_message.denm)
        expected_denm = b'\x02\x01\x00\x00\x00\x00\t\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
            + b'\x00\x03ZN\x90\x0e\xb4\x9d \x0f\xff\xff\xff\x08\xed\xdd\x0f\x80\x00\x00\x00'
        # print(encoded_white)
        self.assertEqual(encoded_white, expected_denm)

    @patch('flexstack.utils.time_service.TimeService.time')
    def test_fullfill_with_denrequest(self, time_mock):
        """Test DENMCoder decoding"""
        # Given
        den_request = DENRequest(
            detection_time=20000,
            denm_interval=100,
            relevance_distance="lessThan200m",
            relevance_traffic_direction="upstreamTraffic",
            event_position={
                "latitude": 900000001,
                "longitude": 1800000001,
                "positionConfidenceEllipse": {
                    "semiMajorConfidence": 4095,
                    "semiMinorConfidence": 4095,
                    "semiMajorOrientation": 3601
                },
                "altitude": {
                    "altitudeValue": 800001,
                    "altitudeConfidence": "unavailable"
                }
            },
            heading=0,
            confidence=2,
            quality=7,
            rhs_cause_code="emergencyVehicleApproaching95",
            rhs_subcause_code=1,
            rhs_event_speed=30,
            rhs_vehicle_type=0,
        )

        # When
        decentralized_environmental_notification_message = \
            DecentralizedEnvironmentalNotificationMessage()
        decentralized_environmental_notification_message.fullfill_with_denrequest(
            den_request)

        # Then
        self.assertEqual(decentralized_environmental_notification_message.denm['denm']
                         ['management']['detectionTime'], den_request.detection_time)
        self.assertEqual(decentralized_environmental_notification_message.denm['denm']
                         ['management']['TransmissionInterval'], den_request.denm_interval)
        self.assertEqual(decentralized_environmental_notification_message.denm['denm']
                         ['management']['relevanceDistance'], den_request.relevance_distance)
        self.assertEqual(decentralized_environmental_notification_message.denm['denm']
                         ['management']['relevanceTrafficDirection'],
                         den_request.relevance_traffic_direction)
        self.assertEqual(decentralized_environmental_notification_message.denm['denm']
                         ['situation']['informationQuality'], den_request.quality)
        self.assertEqual(decentralized_environmental_notification_message.denm['denm']
                         ['management']['eventPosition'], den_request.event_position)
        self.assertEqual(decentralized_environmental_notification_message.denm['denm']
                         ['location']['eventPositionHeading']['value'], den_request.heading)
        self.assertEqual(decentralized_environmental_notification_message.denm['denm']
                         ['location']['eventPositionHeading']['confidence'],
                         den_request.confidence)
        self.assertEqual(decentralized_environmental_notification_message.denm['denm']
                         ['situation']['eventType']['ccAndScc'][0], den_request.rhs_cause_code)
        self.assertEqual(decentralized_environmental_notification_message.denm['denm']
                         ['situation']['eventType']['ccAndScc'][1], den_request.rhs_subcause_code)
        self.assertEqual(decentralized_environmental_notification_message.denm['denm']
                         ['location']['eventSpeed']['speedValue'], den_request.rhs_event_speed)
        self.assertEqual(decentralized_environmental_notification_message.denm['denm']
                         ['location']['eventSpeed']['speedConfidence'], int(den_request.confidence/2))
        self.assertEqual(decentralized_environmental_notification_message.denm['denm']
                         ['management']['stationType'], den_request.rhs_vehicle_type)
        time_mock.assert_called_once()

    @patch('flexstack.utils.time_service.TimeService.time')
    def test_fullfill_with_collision_risk_warning(self, time_mock):
        """Test fullfill_with_collision_risk_warning function"""
        # Given
        den_request = DENRequest(
            detection_time=20000,
            denm_interval=100,
            event_position={
                "latitude": 900000001,
                "longitude": 1800000001,
                "positionConfidenceEllipse": {
                    "semiMajorConfidence": 4095,
                    "semiMinorConfidence": 4095,
                    "semiMajorOrientation": 3601
                },
                "altitude": {
                    "altitudeValue": 800001,
                    "altitudeConfidence": "unavailable"
                }
            },
            quality=7,
            lcrw_cause_code="collisionRisk97",
            lcrw_subcause_code=4
        )

        # When
        decentralized_environmental_notification_message = \
            DecentralizedEnvironmentalNotificationMessage()
        decentralized_environmental_notification_message.fullfill_with_collision_risk_warning(
            den_request)

        # Then
        self.assertEqual(decentralized_environmental_notification_message.denm['denm']
                         ['management']['detectionTime'], den_request.detection_time)
        self.assertEqual(decentralized_environmental_notification_message.denm['denm']
                         ['management']['TransmissionInterval'], den_request.denm_interval)
        self.assertEqual(decentralized_environmental_notification_message.denm['denm']
                         ['management']['eventPosition'], den_request.event_position)
        self.assertEqual(decentralized_environmental_notification_message.denm['denm']
                         ['situation']['informationQuality'], den_request.quality)
        self.assertEqual(decentralized_environmental_notification_message.denm['denm']
                         ['situation']['eventType']['ccAndScc'][0], den_request.lcrw_cause_code)
        self.assertEqual(decentralized_environmental_notification_message.denm['denm']
                         ['situation']['eventType']['ccAndScc'][1], den_request.lcrw_subcause_code)
        time_mock.assert_called_once()

    def test_fullfill_with_vehicle_data(self):
        """Test fullfill_with_vehicle_data function"""
        vehicle_data = VehicleData(
            station_id=30,
            station_type=5,
        )
        sequence_number = 0

        decentralized_environmental_notification_message = \
            DecentralizedEnvironmentalNotificationMessage()
        decentralized_environmental_notification_message.fullfill_with_vehicle_data(
            vehicle_data)
        self.assertEqual(decentralized_environmental_notification_message.denm['header']
                         ['stationId'], vehicle_data.station_id)
        self.assertEqual(decentralized_environmental_notification_message.denm['denm']
                         ['management']['stationType'], vehicle_data.station_type)
        self.assertEqual(decentralized_environmental_notification_message.denm['denm']
                         ['management']['actionId']['originatingStationId'],
                         vehicle_data.station_id)
        self.assertEqual(decentralized_environmental_notification_message.denm['denm']
                         ['management']['actionId']['sequenceNumber'], sequence_number)


class TestDENMTransmissionManagement(unittest.TestCase):
    """Test class for the DENM Transmission Management."""

    def setUp(self):
        btp_router = MagicMock()
        btp_router.BTPDataRequest = MagicMock()
        denm_coder = MagicMock()
        vehicle_data = MagicMock()
        self.denm_transmission_management = DENMTransmissionManagement(
            btp_router, denm_coder, vehicle_data)

    @patch('threading.Thread')
    def test_request_denm_sending(self, thread_mock):
        """Test request_denm_sending function"""
        # Given
        den_request = DENRequest()
        created_thread_mock = MagicMock()
        thread_mock.return_value = created_thread_mock
        mock_start = MagicMock()
        created_thread_mock.start = mock_start

        # When
        self.denm_transmission_management.request_denm_sending(den_request)

        # Then
        thread_mock.assert_called_once_with(
            target=self.denm_transmission_management.trigger_denm_messages,
            args=[den_request])
        mock_start.assert_called_once()

    @patch.object(DecentralizedEnvironmentalNotificationMessage,
                  'fullfill_with_collision_risk_warning')
    @patch.object(DecentralizedEnvironmentalNotificationMessage,
                  'fullfill_with_vehicle_data')
    def test_send_collision_risk_warning_denm(self, mock_fullfill_with_vehicle_data,
                                              mock_fullfill_with_collision_risk_warning):
        """Test send_collision_risk_warning_denm function"""
        # Given
        den_request = DENRequest()
        self.denm_transmission_management.transmit_denm = MagicMock()

        # When
        self.denm_transmission_management.send_collision_risk_warning_denm(
            den_request)

        # Then
        mock_fullfill_with_vehicle_data.assert_called_once_with(
            self.denm_transmission_management.vehicle_data)
        mock_fullfill_with_collision_risk_warning.assert_called_once_with(
            den_request)
        self.denm_transmission_management.transmit_denm.assert_called_once()

    @patch.object(DecentralizedEnvironmentalNotificationMessage,
                  'fullfill_with_vehicle_data')
    @patch.object(DecentralizedEnvironmentalNotificationMessage,
                  'fullfill_with_denrequest')
    @patch('time.sleep')
    def test_trigger_denm_messages(self, sleep_mock, mock_fullfill_with_denrequest,
                                   mock_fullfill_with_vehicle_data):
        """Test trigger_denm_messages function"""
        # Given
        den_request = DENRequest(
            time_period=10000,
            denm_interval=100
        )
        self.denm_transmission_management.transmit_denm = MagicMock()
        self.denm_transmission_management.denm_coder.encode = MagicMock(
            return_value=b'\x02\x01\x00\x00\x00\x00\xcf\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x00\x00\x03ZN\x90\x0e\xb4\x9d \x0f\xff\xff\xff\x08\xed\xdd\x0f\x80'
            b'\x00\x00\x008\x00\x01\xbf\xff\xfd\xc2?\x80/\xff\xff\xff\xff\xc78')

        # When
        self.denm_transmission_management.trigger_denm_messages(den_request)

        # Then
        self.assertEqual(self.denm_transmission_management.transmit_denm.call_count,
                         den_request.time_period / den_request.denm_interval)
        self.assertEqual(mock_fullfill_with_vehicle_data.call_count,
                         den_request.time_period / den_request.denm_interval)
        self.assertEqual(mock_fullfill_with_denrequest.call_count,
                         den_request.time_period / den_request.denm_interval)
        self.assertEqual(sleep_mock.call_count,
                         den_request.time_period / den_request.denm_interval)

    def test_transmit_denm(self):
        """Test transmit_denm function"""
        # Given
        self.denm_transmission_management.btp_router = MagicMock()
        self.denm_transmission_management.btp_router.btp_data_request = MagicMock()
        self.denm_transmission_management.denm_coder.encode = MagicMock()
        new_denm = MagicMock()

        # When
        self.denm_transmission_management.transmit_denm(new_denm)

        # Then
        self.denm_transmission_management.btp_router.btp_data_request.assert_called_once()
        self.denm_transmission_management.denm_coder.encode.assert_called_once_with(
            new_denm.denm)
