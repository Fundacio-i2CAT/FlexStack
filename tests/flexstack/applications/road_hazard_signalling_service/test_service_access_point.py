import unittest
from unittest.mock import MagicMock
from flexstack.applications.road_hazard_signalling_service.service_access_point import (
    RelevanceArea, PriorityLevel, DENRequest
)
from flexstack.facilities.local_dynamic_map.ldm_classes import TimestampIts


class TestRelevanceArea(unittest.TestCase):
    """Test class for the RelevanceArea class."""

    def test_relevance_area_initialization(self):
        """Test the initialization of the RelevanceArea class."""
        relevance_area = RelevanceArea(100, 45)
        self.assertEqual(relevance_area.relevance_distance, 100)
        self.assertEqual(relevance_area.relevance_direction, 45)


class TestPriorityLevel(unittest.TestCase):
    """Test class for the PriorityLevel class."""

    def test_priority_level_values(self):
        """Test the values of the PriorityLevel class."""
        self.assertEqual(PriorityLevel.AWARENESS.value, 2)
        self.assertEqual(PriorityLevel.WARNING.value, 1)
        self.assertEqual(PriorityLevel.PRECRASH.value, 0)


class TestDENRequest(unittest.TestCase):
    """Test class for the DENRequest class."""

    def test_den_request_initialization(self):
        """Test the initialization of the DENRequest."""
        # When
        den_request = DENRequest()

        # Then
        self.assertEqual(den_request.denm_interval, 100)
        self.assertEqual(den_request.priority_level, PriorityLevel.WARNING)
        self.assertEqual(den_request.detection_time, 0)
        self.assertEqual(den_request.time_period, 0)
        self.assertEqual(den_request.quality, 7)
        self.assertDictEqual(den_request.event_position, {})
        self.assertEqual(den_request.heading, 0)
        self.assertEqual(den_request.confidence, 2)

    def test_den_request_with_emergency_vehicle_approaching(self):
        """Test the with_emergency_vehicle_approaching method."""
        # Given
        service = MagicMock()
        service.denm_interval = 100
        service.priority_level = PriorityLevel.WARNING
        service.detection_time = 20000
        service.denm_duration = 10000
        service.event_position = {
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
        }

        # When
        den_request = DENRequest.with_emergency_vehicle_approaching(service)

        # Then
        self.assertEqual(den_request.denm_interval, 100)
        self.assertEqual(den_request.priority_level, PriorityLevel.WARNING)
        self.assertEqual(den_request.relevance_distance, "lessThan200m")
        self.assertEqual(
            den_request.relevance_traffic_direction, "upstreamTraffic")
        self.assertEqual(den_request.detection_time, 20000)
        self.assertEqual(den_request.time_period, 10000)
        self.assertDictEqual(den_request.event_position,
                             service.event_position)
        self.assertEqual(den_request.rhs_cause_code,
                         "emergencyVehicleApproaching95")
        self.assertEqual(den_request.rhs_subcause_code, 1)
        self.assertEqual(den_request.rhs_event_speed, 30)
        self.assertEqual(den_request.rhs_vehicle_type, 0)

    def test_den_request_with_collision_risk_warning(self):
        """Test the with_collision_risk_warning method."""
        # Given
        detection_time = TimestampIts(5000)
        event_position = MagicMock()
        event_position.to_dict.return_value = {
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
        }

        # When
        den_request = DENRequest.with_collision_risk_warning(
            detection_time, event_position)

        # Then
        self.assertEqual(den_request.priority_level, PriorityLevel.WARNING)
        self.assertEqual(den_request.detection_time, 5000)
        self.assertDictEqual(den_request.event_position,
                             event_position.to_dict())
        self.assertEqual(den_request.lcrw_cause_code, "collisionRisk97")
        self.assertEqual(den_request.lcrw_subcause_code, 4)
