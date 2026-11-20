import unittest
from unittest.mock import MagicMock

from flexstack.btp.router import Router
from flexstack.btp.service_access_point import BTPDataRequest, PacketTransportType, CommunicationProfile, TrafficClass, CommonNH
from flexstack.geonet.mib import GnSecurity
from flexstack.geonet.service_access_point import GNDataIndication


class TestRouter(unittest.TestCase):

    def test__init__(self):
        gn_router = MagicMock()
        router = Router(gn_router)
        self.assertEqual(router.indication_callbacks, None)
        self.assertEqual(router.gn_router, gn_router)

    def test_register_indication_callback(self):
        gn_router = MagicMock()
        router = Router(gn_router)
        callback = MagicMock()
        router.register_indication_callback_btp(1, callback)
        router.freeze_callbacks()
        self.assertEqual(router.indication_callbacks.get(1),  # type: ignore
                         callback)

    def test_BTPDataRequest(self):
        """
        Test to be improved!
        """
        gn_router = MagicMock()
        gn_router.gn_data_request = MagicMock()
        router = Router(gn_router)
        request = BTPDataRequest(
            btp_type=CommonNH.BTP_B,
            destination_port=2001,
            gn_packet_transport_type=PacketTransportType(),
            communication_profile=CommunicationProfile.UNSPECIFIED,
            traffic_class=TrafficClass(),
            data=b'Hello World',
            length=11,
        )
        router.btp_data_request(request)
        gn_router.gn_data_request.assert_called_once()


class TestRouterConformance(unittest.TestCase):
    """BTP request encoding and upper-layer dispatch (EN 302 636-5-1 clauses 7, 8), with a mocked GN
    router; the TPs of TS 102 870-2 are in test_btp_conformance.py."""

    @staticmethod
    def _request(btp_type, destination_port, **kwargs):
        return BTPDataRequest(
            btp_type=btp_type,
            destination_port=destination_port,
            gn_packet_transport_type=PacketTransportType(),
            communication_profile=CommunicationProfile.UNSPECIFIED,
            traffic_class=TrafficClass(),
            data=b"\xca\xfe",
            length=2,
            **kwargs,
        )

    def _sent_data(self, request):
        gn_router = MagicMock()
        Router(gn_router).btp_data_request(request)
        gn_request = gn_router.gn_data_request.call_args[0][0]
        return gn_request

    def test_btp_a_request_is_well_formatted(self):
        """EN 302 636-5-1 clause 7.2.1 (BTP-A header): destination port, source port, then payload."""
        gn_request = self._sent_data(self._request(CommonNH.BTP_A, 2001, source_port=5000))
        self.assertEqual(gn_request.upper_protocol_entity, CommonNH.BTP_A)
        self.assertEqual(gn_request.data, b"\x07\xd1\x13\x88\xca\xfe")
        self.assertEqual(gn_request.length, 6)

    def test_btp_b_request_with_destination_port_info(self):
        """EN 302 636-5-1 clause 7.3.1 (BTP-B header): destination port, destination port info, payload."""
        gn_request = self._sent_data(
            self._request(CommonNH.BTP_B, 2001, destination_port_info=0x1234))
        self.assertEqual(gn_request.upper_protocol_entity, CommonNH.BTP_B)
        self.assertEqual(gn_request.data, b"\x07\xd1\x12\x34\xca\xfe")

    def test_btp_b_request_without_destination_port_info(self):
        """EN 302 636-5-1 clause 7.3.1: destination port info is 0 when not provided."""
        gn_request = self._sent_data(self._request(CommonNH.BTP_B, 2001))
        self.assertEqual(gn_request.data, b"\x07\xd1\x00\x00\xca\xfe")

    @staticmethod
    def _dispatch(btp_type, packet):
        router = Router(MagicMock())
        callback = MagicMock()
        router.register_indication_callback_btp(2001, callback)
        router.freeze_callbacks()
        router.btp_data_indication(
            GNDataIndication(upper_protocol_entity=btp_type, data=packet, length=len(packet)))
        return callback

    def test_btp_a_indication_passed_to_upper_entity(self):
        """EN 302 636-5-1 clause 8.3: valid BTP-A packet reaches the registered port."""
        callback = self._dispatch(CommonNH.BTP_A, b"\x07\xd1\x13\x88\xcc\xdd")
        callback.assert_called_once()
        indication = callback.call_args[0][0]
        self.assertEqual(indication.destination_port, 2001)
        self.assertEqual(indication.source_port, 5000)
        self.assertEqual(indication.data, b"\xcc\xdd")

    def test_btp_b_indication_passed_to_upper_entity(self):
        """EN 302 636-5-1 clause 8.3: valid BTP-B packet reaches the registered port."""
        callback = self._dispatch(CommonNH.BTP_B, b"\x07\xd1\x00\x07\xcc\xdd")
        callback.assert_called_once()
        indication = callback.call_args[0][0]
        self.assertEqual(indication.destination_port, 2001)
        self.assertEqual(indication.destination_port_info, 7)
        self.assertEqual(indication.data, b"\xcc\xdd")

    def test_security_results_reach_the_upper_entity(self):
        """GN Table 38 security parameters are passed in the BTP indication."""
        router = Router(MagicMock())
        callback = MagicMock()
        router.register_indication_callback_btp(2001, callback)
        router.freeze_callbacks()
        packet = b"\x07\xd1\x00\x00\xcc\xdd"
        router.btp_data_indication(GNDataIndication(
            upper_protocol_entity=CommonNH.BTP_B, data=packet, length=len(packet),
            security_report=0, certificate_id=b"\x01" * 8, its_aid=36,
            security_permissions=b"\x02\x02\x00"))
        indication = callback.call_args[0][0]
        self.assertEqual(indication.gn_security_report, b"\x00")
        self.assertEqual(indication.gn_certificate_id, b"\x01" * 8)
        self.assertEqual(indication.gn_its_aid, 36)
        self.assertEqual(indication.gn_permissions, b"\x02\x02\x00")

    def test_indication_for_unregistered_port_is_not_dispatched(self):
        callback = self._dispatch(CommonNH.BTP_B, b"\x07\xd2\x00\x00\xcc\xdd")
        callback.assert_not_called()

    def test_unsecured_packet_only_to_ports_open_to_it(self):
        """With itsGnSecurity ENABLED an unsecured packet (no security report) reaches
        only a port registered with accept_unsecured (the CRL / CTL broadcast, ETSI
        TS 103 601 V2.1.1 clause 5.4.2); a secured one reaches every port."""
        gn_router = MagicMock()
        gn_router.mib.itsGnSecurity = GnSecurity.ENABLED
        router = Router(gn_router)
        closed, opened = MagicMock(), MagicMock()
        router.register_indication_callback_btp(2001, closed)
        router.register_indication_callback_btp(2015, opened, accept_unsecured=True)
        router.freeze_callbacks()
        for port, report in ((2001, None), (2015, None), (2001, 0)):
            packet = port.to_bytes(2, "big") + b"\x00\x00\xcc"
            router.btp_data_indication(GNDataIndication(
                upper_protocol_entity=CommonNH.BTP_B, data=packet, length=len(packet), security_report=report))
        self.assertEqual(closed.call_count, 1)                      # only the secured one
        self.assertIsNotNone(closed.call_args[0][0].gn_security_report)
        opened.assert_called_once()
        gn_router.mib.itsGnSecurity = GnSecurity.DISABLED
        packet = b"\x07\xd1\x00\x00\xcc"
        router.btp_data_indication(GNDataIndication(upper_protocol_entity=CommonNH.BTP_B, data=packet, length=5))
        self.assertEqual(closed.call_count, 2)                      # security disabled: delivered


if __name__ == '__main__':
    unittest.main()
