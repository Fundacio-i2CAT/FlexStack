"""
ETSI TS 102 870-2 V1.2.1 (2022-03) test purposes of the Basic Transport
Protocol, one test per TP, on complete stations: the BTP router on a
GeoNetworking router whose link layer is captured, frames decoded from the
wire. The receiving IUT gets the frame sent by a second station (the test
system). Mirrors ``rustflexstack::btp::conformance``.

Frame of an unsecured SHB: Basic Header (4) | Common Header (8) | SHB Extended
Header (24 + 4) | BTP header (4) | payload. The Common Header NH is 1 for BTP-A
and 2 for BTP-B (ETSI TS 103 836-4-1 V2.2.1 table 9).
"""
import unittest
from unittest.mock import Mock

from flexstack.btp.btp_header import BTPAHeader, BTPBHeader
from flexstack.btp.router import Router as BTPRouter
from flexstack.btp.service_access_point import BTPDataRequest
from flexstack.geonet.basic_header import BasicHeader, BasicNH
from flexstack.geonet.common_header import CommonHeader
from flexstack.geonet.gn_address import MID, GNAddress
from flexstack.geonet.mib import MIB
from flexstack.geonet.position_vector import TST, LongPositionVector
from flexstack.geonet.router import Router as GNRouter
from flexstack.geonet.gbc_extended_header import GBCExtendedHeader
from flexstack.geonet.service_access_point import (
    Area, CommonNH, GeoBroadcastHST, HeaderType, PacketTransportType, TopoBroadcastHST, TrafficClass)
from flexstack.linklayer.link_layer import LinkLayer
from flexstack.utils.time_service import TimeService

SOURCE_PORT, DESTINATION_PORT, DESTINATION_PORT_INFO = 5000, 2001, 0x1234
PAYLOAD = b"upper layer payload"
SHB = PacketTransportType(header_type=HeaderType.TSB, header_subtype=TopoBroadcastHST.SINGLE_HOP)
HEADERS = 4 + 8 + 28                      # Basic, Common, SHB Extended Header


class _Station:
    """BTP on a GeoNetworking router (security disabled); frames sent are captured
    in ``sent``, indications of the registered ports in ``received``."""

    def __init__(self, n):
        self.addr = GNAddress(mid=MID(bytes([0x02, 0, 0, 0, 0, n])))
        self.gn = GNRouter(MIB(itsGnLocalGnAddr=self.addr, itsGnBeaconServiceRetransmitTimer=0))
        self.gn.ego_position_vector = LongPositionVector(
            gn_addr=self.addr, tst=TST.set_in_normal_timestamp_seconds(TimeService.time()),
            latitude=415520000, longitude=21340000, pai=True)
        self.sent = []
        self.gn.link_layer = Mock(spec=LinkLayer)
        self.gn.link_layer.send.side_effect = lambda raw, *_a, **_k: self.sent.append(raw)
        self.btp = BTPRouter(self.gn)
        self.gn.register_indication_callback(self.btp.btp_data_indication)
        self.received = []
        self.btp.register_indication_callback_btp(DESTINATION_PORT, self.received.append)
        self.btp.freeze_callbacks()

    def send(self, btp_type, **fields):
        """A BTP-data request (SHB unless given); the frame sent."""
        fields.setdefault("gn_packet_transport_type", SHB)
        self.btp.btp_data_request(BTPDataRequest(
            btp_type=btp_type, destination_port=DESTINATION_PORT, data=PAYLOAD, length=len(PAYLOAD), **fields))
        return self.sent[-1]


def _decode(frame):
    """(Common Header, BTP header bytes, payload) of an unsecured SHB frame."""
    assert BasicHeader.decode_from_bytes(frame[:4]).nh == BasicNH.COMMON_HEADER
    common = CommonHeader.decode_from_bytes(frame[4:12])
    return common, frame[HEADERS:HEADERS + 4], frame[HEADERS + 4:]


class TestBtpPacketGeneration(unittest.TestCase):
    """TP/BTP/PGA and TP/BTP/PGB: packet generation."""

    def test_tp_btp_pga_bv_01(self):
        """TP/BTP/PGA/BV/01: a BTP-data request of type BTP-A with SOURCE_PORT and
        DESTINATION_PORT gives a BTP-A packet with these ports and the payload."""
        common, header, payload = _decode(_Station(1).send(CommonNH.BTP_A, source_port=SOURCE_PORT))
        self.assertEqual(common.nh, CommonNH.BTP_A)
        btp = BTPAHeader.decode(header)
        self.assertEqual((btp.destination_port, btp.source_port), (DESTINATION_PORT, SOURCE_PORT))
        self.assertEqual(payload, PAYLOAD)
        self.assertEqual(common.pl, 4 + len(PAYLOAD))

    def test_tp_btp_pgb_bv_01(self):
        """TP/BTP/PGB/BV/01: a BTP-data request of type BTP-B with DESTINATION_PORT and
        DESTINATION_PORT_INFO gives a BTP-B packet with both and the payload."""
        common, header, payload = _decode(
            _Station(1).send(CommonNH.BTP_B, destination_port_info=DESTINATION_PORT_INFO))
        self.assertEqual(common.nh, CommonNH.BTP_B)
        btp = BTPBHeader.decode(header)
        self.assertEqual((btp.destination_port, btp.destination_port_info),
                         (DESTINATION_PORT, DESTINATION_PORT_INFO))
        self.assertEqual(payload, PAYLOAD)
        self.assertEqual(common.pl, 4 + len(PAYLOAD))

    def test_tp_btp_pgb_bv_02(self):
        """TP/BTP/PGB/BV/02: a BTP-B request without Destination Port Info gives a BTP-B
        packet whose destination port info is 0."""
        common, header, payload = _decode(_Station(1).send(CommonNH.BTP_B))
        self.assertEqual(common.nh, CommonNH.BTP_B)
        self.assertEqual(header, DESTINATION_PORT.to_bytes(2, "big") + b"\x00\x00")
        self.assertEqual(payload, PAYLOAD)


class TestBtpPacketProcessing(unittest.TestCase):
    """TP/BTP/PP: packet processing."""

    def test_tp_btp_pp_bv_01(self):
        """TP/BTP/PP/BV/01: a valid BTP-A packet (SOURCE_PORT, DESTINATION_PORT, payload)
        received by the IUT is passed to the upper layer of DESTINATION_PORT."""
        tester, iut = _Station(9), _Station(1)
        iut.gn.gn_data_indicate(tester.send(CommonNH.BTP_A, source_port=SOURCE_PORT))
        self.assertEqual(len(iut.received), 1)
        indication = iut.received[0]
        self.assertEqual((indication.source_port, indication.destination_port), (SOURCE_PORT, DESTINATION_PORT))
        self.assertEqual(indication.data, PAYLOAD)
        self.assertEqual(indication.gn_source_position_vector.gn_addr, tester.addr)

    def test_tp_btp_pp_bv_02(self):
        """TP/BTP/PP/BV/02: a valid BTP-B packet (DESTINATION_PORT, DESTINATION_PORT_INFO,
        payload) received by the IUT is passed to the upper protocol of DESTINATION_PORT."""
        tester, iut = _Station(9), _Station(1)
        iut.gn.gn_data_indicate(tester.send(CommonNH.BTP_B, destination_port_info=DESTINATION_PORT_INFO))
        self.assertEqual(len(iut.received), 1)
        indication = iut.received[0]
        self.assertEqual((indication.destination_port, indication.destination_port_info),
                         (DESTINATION_PORT, DESTINATION_PORT_INFO))
        self.assertEqual(indication.data, PAYLOAD)
        self.assertEqual(indication.gn_source_position_vector.gn_addr, tester.addr)


class TestBtpServicePrimitives(unittest.TestCase):
    """EN 302 636-5-1 V2.2.1 clauses 8.2 and 8.3: the GN parameters of the
    BTP-Data.request reach the GN-Data.request (table 6) and those of the
    GN-Data.indication the BTP-Data.indication (table 7). Not covered by a TP."""

    def test_source_operations_pass_the_gn_parameters(self):
        """Table 6: packet transport type, destination area, traffic class, maximum
        packet lifetime and maximum hop limit; Length = ITS-FSDU + 4."""
        frame = _Station(1).send(
            CommonNH.BTP_B,
            gn_packet_transport_type=PacketTransportType(header_type=HeaderType.GEOBROADCAST,
                                                         header_subtype=GeoBroadcastHST.GEOBROADCAST_CIRCLE),
            gn_area=Area(latitude=415520000, longitude=21340000, a=500),
            traffic_class=TrafficClass(channel_offload=True, tc_id=3), gn_max_packet_lifetime=5.0, gn_max_hop_limit=4)
        basic = BasicHeader.decode_from_bytes(frame[:4])
        common = CommonHeader.decode_from_bytes(frame[4:12])
        gbc = GBCExtendedHeader.decode(frame[12:56])
        self.assertEqual((common.ht, common.nh), (HeaderType.GEOBROADCAST, CommonNH.BTP_B))
        self.assertEqual((common.tc.channel_offload, common.tc.tc_id), (True, 3))
        self.assertEqual(common.mhl, 4)
        self.assertEqual(basic.lt.get_value_in_seconds(), 5)
        self.assertEqual((gbc.latitude, gbc.longitude, gbc.a), (415520000, 21340000, 500))
        self.assertEqual(common.pl, len(PAYLOAD) + 4)
        self.assertEqual(frame[56:60], DESTINATION_PORT.to_bytes(2, "big") + b"\x00\x00")

    def test_geounicast_destination_address(self):
        """Table 6: GN Destination address of a GeoUnicast; table 7: the indication
        carries the destination the packet was generated with."""
        tester, iut = _Station(9), _Station(1)
        tester.gn.gn_data_indicate(iut.send(CommonNH.BTP_B))          # the tester learns the IUT
        iut.received.clear()
        frame = tester.send(CommonNH.BTP_A, source_port=SOURCE_PORT, gn_destination_address=iut.addr,
                            gn_packet_transport_type=PacketTransportType(header_type=HeaderType.GEOUNICAST))
        self.assertEqual(CommonHeader.decode_from_bytes(frame[4:12]).ht, HeaderType.GEOUNICAST)
        iut.gn.gn_data_indicate(frame)
        self.assertEqual(len(iut.received), 1)
        indication = iut.received[0]
        self.assertEqual(indication.gn_packet_transport_type.header_type, HeaderType.GEOUNICAST)
        self.assertEqual(indication.gn_destination_address.mid, iut.addr.mid)
        self.assertEqual((indication.source_port, indication.data), (SOURCE_PORT, PAYLOAD))

    def test_destination_operations_pass_the_gn_parameters(self):
        """Table 7: packet transport type, source position vector, traffic class,
        remaining packet lifetime, no security report; Length = GN-PDU payload - 4."""
        tester, iut = _Station(9), _Station(1)
        iut.gn.gn_data_indicate(tester.send(CommonNH.BTP_B, traffic_class=TrafficClass(tc_id=2),
                                            gn_max_packet_lifetime=10.0))
        indication = iut.received[0]
        self.assertEqual(indication.gn_packet_transport_type.header_type, HeaderType.TSB)
        self.assertEqual(indication.gn_source_position_vector.gn_addr, tester.addr)
        self.assertEqual(indication.gn_traffic_class.tc_id, 2)
        self.assertEqual(indication.gn_remaining_packet_lifetime, 10.0)
        self.assertIsNone(indication.gn_security_report)
        self.assertEqual((indication.length, indication.data), (len(PAYLOAD), PAYLOAD))


if __name__ == "__main__":
    unittest.main()
