import unittest
from unittest.mock import MagicMock

from flexstack.applications.road_hazard_signalling_service.service_access_point import DENRequest
from flexstack.btp.service_access_point import BTPDataRequest, CommonNH
from flexstack.facilities.ca_basic_service.cam_transmission_management import VehicleData
from flexstack.facilities.decentralized_environmental_notification_service.den_protocol import (
    DENMRequest,
    DenFailure,
    OutgoingDENM,
)
from flexstack.facilities.decentralized_environmental_notification_service.denm_coder import DENMCoder
from flexstack.facilities.decentralized_environmental_notification_service.\
    denm_transmission_management import (
        DENMTransmissionManagement, DecentralizedEnvironmentalNotificationMessage
    )
from flexstack.geonet.service_access_point import (
    Area,
    GeoBroadcastHST,
    HeaderType,
    TrafficClass,
)
from flexstack.security.security_profiles import SecurityProfile
from flexstack.utils.time_service import TimeService

POSITION = {
    "latitude": 415520000,
    "longitude": 21340000,
    "positionConfidenceEllipse": {"semiMajorConfidence": 4095, "semiMinorConfidence": 4095,
                                  "semiMajorOrientation": 3601},
    "altitude": {"altitudeValue": 800001, "altitudeConfidence": "unavailable"},
}


def eva_request(**kwargs) -> DENRequest:
    fields = dict(
        denm_interval=1000, detection_time=int(TimeService.timestamp_its()), time_period=10000,
        event_position=POSITION, relevance_distance="lessThan200m",
        relevance_traffic_direction="upstreamTraffic",
        rhs_cause_code="emergencyVehicleApproaching95", rhs_subcause_code=1,
        rhs_event_speed=30, rhs_vehicle_type=0,
    )
    fields.update(kwargs)
    return DENRequest(**fields)


class TestDecentralizedEnvironmentalNotificationMessage(unittest.TestCase):
    """Builder of road-hazard DENMs from DENRequest."""

    def test_white_denm_is_not_a_termination(self):
        """A new DENM has no termination component (TS 103 831 clause 8.2.1.4)."""
        denm = DecentralizedEnvironmentalNotificationMessage().denm
        self.assertNotIn("termination", denm["denm"]["management"])
        self.assertEqual(denm["denm"]["management"]["validityDuration"], 600)

    def test_fullfill_with_denrequest_on_the_wire(self):
        """Release 2 management fields survive encoding (they were dropped before)."""
        message = DecentralizedEnvironmentalNotificationMessage()
        message.fullfill_with_denrequest(eva_request())
        coder = DENMCoder()
        management = coder.decode(coder.validate(message.denm))["denm"]["management"]
        self.assertNotIn("termination", management)
        self.assertEqual(management["awarenessDistance"], "lessThan200m")
        self.assertEqual(management["trafficDirection"],
                         "sameAsReferenceDirection-upstreamOfReferencePosition")
        self.assertEqual(management["transmissionInterval"], 1000)
        self.assertEqual(management["validityDuration"], 10)

    def test_fullfill_with_denrequest_containers(self):
        message = DecentralizedEnvironmentalNotificationMessage()
        message.fullfill_with_denrequest(eva_request())
        self.assertEqual(message.denm["denm"]["situation"]["eventType"]["ccAndScc"],
                         ("emergencyVehicleApproaching95", 1))
        self.assertIn("detectionZonesToEventPosition", message.denm["denm"]["location"])

    def test_fullfill_with_collision_risk_warning(self):
        message = DecentralizedEnvironmentalNotificationMessage()
        message.fullfill_with_collision_risk_warning(eva_request(
            lcrw_cause_code="collisionRisk97", lcrw_subcause_code=2))
        self.assertEqual(message.denm["denm"]["situation"]["eventType"]["ccAndScc"],
                         ("collisionRisk97", 2))
        DENMCoder().validate(message.denm)

    def test_fullfill_with_vehicle_data(self):
        """New event (TS 103 831 clauses 6.1.1, 8.2.2): actionId carries the stationId of the originating ITS-S."""
        message = DecentralizedEnvironmentalNotificationMessage()
        message.fullfill_with_vehicle_data(VehicleData(station_id=7, station_type=5))
        self.assertEqual(message.denm["header"]["stationId"], 7)
        self.assertEqual(message.denm["denm"]["management"]["actionId"]["originatingStationId"], 7)
        self.assertEqual(message.denm["denm"]["management"]["stationType"], 5)

    def test_to_denm_request(self):
        message = DecentralizedEnvironmentalNotificationMessage()
        message.fullfill_with_denrequest(eva_request())
        request = message.to_denm_request(repetition_interval=1000, repetition_duration=10000)
        self.assertEqual(request.repetition_interval, 1000)
        self.assertEqual(request.transmission_interval, 1000)
        self.assertEqual(request.awareness_distance, "lessThan200m")


class TestDENMTransmissionManagement(unittest.TestCase):

    def setUp(self):
        self.btp_router = MagicMock()
        self.vehicle_data = VehicleData(station_id=7, station_type=5)
        self.tm = DENMTransmissionManagement(self.btp_router, DENMCoder(), self.vehicle_data)

    def sent(self):
        return [call[0][0] for call in self.btp_router.btp_data_request.call_args_list]

    def decoded(self, request: BTPDataRequest):
        return self.tm.denm_coder.decode(request.data)

    def test_request_denm_sending_triggers_repeated_denm(self):
        """Emergency Vehicle Approaching: one new DENM now, repetition scheduled."""
        result = self.tm.request_denm_sending(eva_request())
        self.assertTrue(result.ok)
        self.assertEqual(len(self.sent()), 1)
        entry = self.tm.protocol.originating[result.action_id]
        self.assertEqual(entry.repetition_interval, 1000)
        self.assertIsNotNone(entry.next_repetition)

    def test_trigger_denm_messages_is_alias(self):
        self.assertTrue(self.tm.trigger_denm_messages(eva_request()).ok)
        self.assertEqual(len(self.sent()), 1)

    def test_consecutive_requests_get_distinct_action_ids(self):
        """New event (TS 103 831 clause 6.1.1.1): unused actionIds through the application interface."""
        first = self.tm.request_denm_sending(eva_request())
        second = self.tm.request_denm_sending(eva_request())
        self.assertNotEqual(first.action_id, second.action_id)
        ids = {self.decoded(r)["denm"]["management"]["actionId"]["sequenceNumber"]
               for r in self.sent()}
        self.assertEqual(len(ids), 2)

    def test_send_collision_risk_warning_denm_without_repetition(self):
        result = self.tm.send_collision_risk_warning_denm(eva_request(
            lcrw_cause_code="collisionRisk97", lcrw_subcause_code=2))
        self.assertTrue(result.ok)
        self.assertIsNone(self.tm.protocol.originating[result.action_id].next_repetition)
        self.assertEqual(len(self.sent()), 1)

    def test_failed_request_sends_nothing(self):
        """Clause 8.2.3.4: expired validity -> failure notification, no DENM."""
        result = self.tm.request_denm_sending(eva_request(detection_time=1000))
        self.assertEqual(result.failure, DenFailure.VALIDITY_EXPIRED)
        self.assertEqual(self.sent(), [])

    def test_trigger_update_terminate(self):
        """AppDENM_trigger / update / termination through the transmission management."""
        situation = {"informationQuality": 3, "eventType": {"ccAndScc": ("accident2", 0)}}
        location = {"detectionZonesToEventPosition": [[{"pathPosition": {
            "deltaLatitude": 131072, "deltaLongitude": 131072, "deltaAltitude": 12800}}]]}
        result = self.tm.trigger_denm(DENMRequest(POSITION, situation=situation,
                                                  location=location))
        self.assertTrue(self.tm.update_denm(result.action_id, DENMRequest(POSITION)).ok)
        self.assertTrue(self.tm.terminate_denm(result.action_id, DENMRequest(POSITION)).ok)
        terminations = [self.decoded(r)["denm"]["management"].get("termination")
                        for r in self.sent()]
        self.assertEqual(terminations, [None, None, "isCancellation"])

    def test_timers_changed_callback(self):
        callback = MagicMock()
        tm = DENMTransmissionManagement(self.btp_router, DENMCoder(), self.vehicle_data,
                                        on_timers_changed=callback)
        tm.request_denm_sending(eva_request())
        callback.assert_called_once()

    def test_transmit_denm_btp_b_port_2002_over_gbc(self):
        """DENM encapsulation (TS 103 831 clause 5.4.2.2): BTP-B to port 2002 in a GeoNetworking GBC packet."""
        self.tm.request_denm_sending(eva_request())
        request = self.sent()[0]
        self.assertEqual(request.btp_type, CommonNH.BTP_B)
        self.assertEqual(request.destination_port, 2002)
        self.assertEqual(request.gn_packet_transport_type.header_type, HeaderType.GEOBROADCAST)
        self.assertEqual(request.gn_packet_transport_type.header_subtype,
                         GeoBroadcastHST.GEOBROADCAST_CIRCLE)
        self.assertEqual(request.gn_area.latitude, POSITION["latitude"])

    def test_transmit_denm_uses_denm_security_profile(self):
        """TS 103 097 §7.1.2: DENM security profile with ITS-AID 37."""
        self.tm.request_denm_sending(eva_request())
        request = self.sent()[0]
        self.assertEqual(request.security_profile,
                         SecurityProfile.DECENTRALIZED_ENVIRONMENTAL_NOTIFICATION_MESSAGE)
        self.assertEqual(request.its_aid, 37)

    def test_transmit_uses_requested_area_and_traffic_class(self):
        area = Area(latitude=1, longitude=2, a=300, b=100, angle=45)
        message = DecentralizedEnvironmentalNotificationMessage()
        message.fullfill_with_denrequest(eva_request())
        self.tm.transmit(OutgoingDENM(message.denm, area, GeoBroadcastHST.GEOBROADCAST_ELIP,
                                      TrafficClass(tc_id=3)))
        request = self.sent()[0]
        self.assertEqual(request.gn_area, area)
        self.assertEqual(request.gn_packet_transport_type.header_subtype,
                         GeoBroadcastHST.GEOBROADCAST_ELIP)
        self.assertEqual(request.traffic_class.tc_id, 3)

    def test_transmit_denm_compatibility(self):
        message = DecentralizedEnvironmentalNotificationMessage()
        message.fullfill_with_denrequest(eva_request())
        self.tm.transmit_denm(message)
        self.assertEqual(len(self.sent()), 1)


if __name__ == '__main__':
    unittest.main()
