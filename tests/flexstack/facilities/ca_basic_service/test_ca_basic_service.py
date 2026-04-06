import unittest
from unittest.mock import MagicMock, patch
from flexstack.facilities.ca_basic_service.ca_basic_service import (
    CooperativeAwarenessBasicService,
)
from flexstack.facilities.ca_basic_service.cam_transmission_management import VehicleData


def _make_vehicle_data():
    return VehicleData(
        station_id=1,
        station_type=5,
        drive_direction="forward",
        vehicle_length={
            "vehicleLengthValue": 50,
            "vehicleLengthConfidenceIndication": "unavailable",
        },
        vehicle_width=30,
    )


class TestCooperativeAwarenessBasicService(unittest.TestCase):

    def test__init__(self):
        btp_router = MagicMock()
        vehicle_data = _make_vehicle_data()
        service = CooperativeAwarenessBasicService(btp_router, vehicle_data)
        self.assertIsNotNone(service.cam_transmission_management)
        self.assertIsNotNone(service.cam_reception_management)
        self.assertIsNotNone(service.cam_coder)

    def test_start_delegates_to_transmission_management(self):
        btp_router = MagicMock()
        service = CooperativeAwarenessBasicService(btp_router, _make_vehicle_data())
        service.cam_transmission_management = MagicMock()
        service.start()
        service.cam_transmission_management.start.assert_called_once()

    def test_stop_delegates_to_transmission_management(self):
        btp_router = MagicMock()
        service = CooperativeAwarenessBasicService(btp_router, _make_vehicle_data())
        service.cam_transmission_management = MagicMock()
        service.stop()
        service.cam_transmission_management.stop.assert_called_once()

    def test_location_service_callback_available(self):
        btp_router = MagicMock()
        service = CooperativeAwarenessBasicService(btp_router, _make_vehicle_data())
        # The callback must exist and accept a TPV dict without raising
        tpv = {"lat": 41.0, "lon": 2.0, "track": 0.0, "speed": 1.0}
        service.cam_transmission_management.location_service_callback(tpv)
        self.assertEqual(service.cam_transmission_management._current_tpv, tpv)


if __name__ == "__main__":
    unittest.main()

