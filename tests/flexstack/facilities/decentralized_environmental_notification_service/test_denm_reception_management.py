import unittest

from flexstack.facilities.decentralized_environmental_notification_service.denm_ssp import permissions_bitmap
from unittest.mock import MagicMock

from flexstack.btp.service_access_point import BTPDataIndication
from flexstack.facilities.decentralized_environmental_notification_service.den_protocol import (
    DENMRequest,
    DENProtocol,
    DenmState,
)
from flexstack.facilities.decentralized_environmental_notification_service.denm_coder import DENMCoder
from flexstack.facilities.decentralized_environmental_notification_service.denm_reception_management import (
    DENMReceptionManagement,
)
from flexstack.facilities.local_dynamic_map.ldm_classes import AddDataProviderReq
from flexstack.facilities.local_dynamic_map.ldm_facility import LDMFacility
from flexstack.geonet.service_access_point import (
    Area,
    GeoBroadcastHST,
    HeaderType,
    PacketTransportType,
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
AREA = Area(latitude=415520000, longitude=21340000, a=1000, b=0, angle=0)


class TestDENMReceptionManagement(unittest.TestCase):

    def setUp(self):
        self.coder = DENMCoder()
        self.btp_router = MagicMock()
        self.ldm = MagicMock(spec=LDMFacility)
        self.ldm.if_ldm_3 = MagicMock()
        self.protocol = DENProtocol(9, 5, kaf_enabled=True)
        self.reception = DENMReceptionManagement(self.coder, self.btp_router, self.ldm,
                                                 protocol=self.protocol)
        self.callback = MagicMock()
        self.reception.add_application_callback(self.callback)
        self.originator = DENProtocol(7, 5, validate=self.coder.validate)

    def indication(self, denm: dict, permissions=None, its_aid=None) -> BTPDataIndication:
        return BTPDataIndication(
            gn_its_aid=its_aid,
            destination_port=2002,
            gn_packet_transport_type=PacketTransportType(
                header_type=HeaderType.GEOBROADCAST,
                header_subtype=GeoBroadcastHST.GEOBROADCAST_CIRCLE),
            gn_destination_area=AREA,
            gn_permissions=permissions,
            data=self.coder.encode(denm),
        )

    def new_denm(self):
        result, out = self.originator.trigger(
            DENMRequest(POSITION, situation=SITUATION, location=LOCATION,
                        transmission_interval=100),
            int(TimeService.timestamp_its()))
        return result.action_id, out[0].denm

    def test_registers_on_port_2002(self):
        self.btp_router.register_indication_callback_btp.assert_called_once_with(
            port=2002, callback=self.reception.reception_callback)

    def test_feed_ldm(self):
        """The received DENM is handed to the LDM as provider data."""
        denm = MagicMock()
        self.reception.feed_ldm(denm)
        add = self.ldm.if_ldm_3.add_provider_data
        add.assert_called_once()
        request = add.call_args[0][0]
        self.assertIsInstance(request, AddDataProviderReq)
        self.assertIs(request.data_object, denm)

    def test_reception_callback_accepts_new_event(self):
        """Receiving ITS-S (TS 103 831 clause 8.4.2): DENM passed to the LDM and the application."""
        action_id, denm = self.new_denm()
        self.reception.reception_callback(self.indication(denm))
        self.ldm.if_ldm_3.add_provider_data.assert_called_once()
        received = self.callback.call_args[0][0]
        self.assertEqual(received.state, DenmState.ACTIVE)
        self.assertIn(action_id, self.protocol.receiving)

    def test_repeated_denm_not_passed_again(self):
        _, denm = self.new_denm()
        self.reception.reception_callback(self.indication(denm))
        self.reception.reception_callback(self.indication(denm))
        self.assertEqual(self.callback.call_count, 1)

    def test_kaf_entry_uses_destination_area_of_packet(self):
        """Clause 8.3: the GBC destination area is kept for forwarding."""
        action_id, denm = self.new_denm()
        self.reception.reception_callback(self.indication(denm))
        self.assertEqual(self.protocol.forwarding[action_id].area, AREA)

    def test_ssp_of_signer_is_checked(self):
        """Receiving ITS-S (TS 103 831 clause 8.4.2): SSP not permitting accident(2) -> discarded."""
        _, denm = self.new_denm()
        self.reception.reception_callback(
            self.indication(denm, permissions=bytes([2, 0x80, 0, 0, 0])))
        self.callback.assert_not_called()
        self.reception.reception_callback(
            self.indication(denm, permissions=bytes([2, 0x40, 0, 0, 0])))
        self.callback.assert_called_once()

    def test_secured_denm_with_another_its_aid_is_discarded(self):
        """ETSI TS 103 097 clause 7.1.2: a secured DENM shall carry the DENM ITS-AID."""
        _, denm = self.new_denm()
        self.reception.reception_callback(self.indication(denm, its_aid=36))
        self.callback.assert_not_called()
        self.reception.reception_callback(self.indication(denm, its_aid=37))
        self.callback.assert_called_once()

    def test_permissions_bitmap_requests_the_cause_code_bit(self):
        """Sender-side SSP: accident(2) needs octet 1 bit 0x40 (Table 10)."""
        _, denm = self.new_denm()
        self.assertEqual(permissions_bitmap(denm), bytes([0, 0x40]))
        denm["denm"].pop("situation")
        self.assertEqual(permissions_bitmap(denm), b"\x00")

    def test_undecodable_denm_is_discarded(self):
        """Clause 8.4.3.2: decoding exception."""
        self.reception.reception_callback(BTPDataIndication(data=b"\xff\x00"))
        self.callback.assert_not_called()
        self.ldm.if_ldm_3.add_provider_data.assert_not_called()

    def test_faulty_application_callback_does_not_propagate(self):
        _, denm = self.new_denm()
        self.reception.add_application_callback(MagicMock(side_effect=RuntimeError("oops")))
        self.reception.reception_callback(self.indication(denm))
        self.callback.assert_called_once()


if __name__ == '__main__':
    unittest.main()
