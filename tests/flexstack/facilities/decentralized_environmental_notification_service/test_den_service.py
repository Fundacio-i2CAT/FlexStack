import time
import unittest
from unittest.mock import MagicMock

from flexstack.btp.service_access_point import BTPDataIndication
from flexstack.facilities.ca_basic_service.cam_transmission_management import VehicleData
from flexstack.facilities.decentralized_environmental_notification_service.den_protocol import (
    ActionId,
    DENMRequest,
    DenmState,
)
from flexstack.facilities.decentralized_environmental_notification_service.den_service import (
    DecentralizedEnvironmentalNotificationService,
)
from flexstack.utils.time_service import TimeService

POSITION = {
    "latitude": 415520000,
    "longitude": 21340000,
    "positionConfidenceEllipse": {"semiMajorConfidence": 4095, "semiMinorConfidence": 4095,
                                  "semiMajorOrientation": 3601},
    "altitude": {"altitudeValue": 800001, "altitudeConfidence": "unavailable"},
}
SITUATION = {"informationQuality": 3, "eventType": {"ccAndScc": ("accident2", 0)}}
LOCATION = {"detectionZonesToEventPosition": [[{"pathPosition": {
    "deltaLatitude": 131072, "deltaLongitude": 131072, "deltaAltitude": 12800}}]]}


def request(**kwargs):
    return DENMRequest(POSITION, situation=SITUATION, location=LOCATION, **kwargs)


class TestDecentralizedEnvironmentalNotificationService(unittest.TestCase):

    def make(self, **kwargs):
        btp_router = MagicMock()
        service = DecentralizedEnvironmentalNotificationService(
            btp_router, VehicleData(station_id=7, station_type=5), **kwargs)
        self.addCleanup(service.stop)
        return service, btp_router

    def test_components_share_one_protocol_engine(self):
        service, _ = self.make(start_scheduler=False)
        self.assertIs(service.denm_transmission_management.protocol, service.protocol)
        self.assertIs(service.denm_reception_management.protocol, service.protocol)

    def test_scheduler_sends_repetitions(self):
        """DENM repetition driven by the timer thread (clause 6.1.2.3)."""
        service, btp_router = self.make()
        result = service.trigger_denm(request(repetition_interval=50, repetition_duration=1000))
        self.assertTrue(result.ok)
        deadline = time.monotonic() + 2
        while btp_router.btp_data_request.call_count < 3 and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertGreaterEqual(btp_router.btp_data_request.call_count, 3)
        references = {service.denm_coder.decode(c[0][0].data)["denm"]["management"]["referenceTime"]
                      for c in btp_router.btp_data_request.call_args_list}
        self.assertEqual(len(references), 1)        # referenceTime kept in repetitions

    def test_process_timers_manually(self):
        service, btp_router = self.make(start_scheduler=False)
        now = int(TimeService.timestamp_its())
        service.trigger_denm(request(repetition_interval=100, repetition_duration=1000,
                                     detection_time=now))
        reference = service.protocol.originating[ActionId(7, 0)].denm["denm"]["management"][
            "referenceTime"]
        service.process_timers(reference + 100)
        self.assertEqual(btp_router.btp_data_request.call_count, 2)

    def test_update_and_terminate(self):
        service, btp_router = self.make(start_scheduler=False)
        result = service.trigger_denm(request())
        self.assertTrue(service.update_denm(result.action_id, DENMRequest(POSITION)).ok)
        self.assertTrue(service.terminate_denm(result.action_id, DENMRequest(POSITION)).ok)
        self.assertEqual(btp_router.btp_data_request.call_count, 3)

    def test_received_denm_reaches_application_and_expires(self):
        sender, sender_btp = self.make(start_scheduler=False)
        receiver, _ = self.make(start_scheduler=False)
        received, expired = [], []
        receiver.add_application_callback(received.append)
        receiver.add_expiry_callback(expired.append)
        result = sender.trigger_denm(request(validity_duration=1))
        data = sender_btp.btp_data_request.call_args[0][0].data
        receiver.denm_reception_management.reception_callback(BTPDataIndication(data=data))
        self.assertEqual(received[0].state, DenmState.ACTIVE)
        detection = received[0].denm["denm"]["management"]["detectionTime"]
        receiver.process_timers(detection + 1000)
        self.assertEqual(expired, [result.action_id])

    def test_update_station_id(self):
        service, btp_router = self.make(start_scheduler=False)
        result = service.trigger_denm(request(repetition_interval=100, repetition_duration=1000))
        service.update_station_id(8)
        self.assertIn(ActionId(8, result.action_id.sequence_number), service.protocol.originating)

    def test_set_ego_position(self):
        service, _ = self.make(start_scheduler=False, kaf_enabled=True)
        service.set_ego_position(1, 2)
        self.assertEqual(service.protocol.ego_position, (1, 2))
        self.assertTrue(service.protocol.kaf_enabled)

    def test_start_is_idempotent_and_stop_joins(self):
        service, _ = self.make()
        service.start()
        service.stop()
        self.assertIsNone(service._thread)  # pylint: disable=protected-access


if __name__ == '__main__':
    unittest.main()
