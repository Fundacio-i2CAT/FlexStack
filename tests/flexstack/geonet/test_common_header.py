import unittest

from flexstack.geonet.common_header import CommonHeader, CommonNH, HeaderType, HeaderSubType, TrafficClass
from flexstack.geonet.service_access_point import GNDataRequest, PacketTransportType, GeoBroadcastHST


class TestCommonHeader(unittest.TestCase):

    def test_initialize_with_request(self):
        request = GNDataRequest(
            upper_protocol_entity=CommonNH.BTP_B,
            packet_transport_type=PacketTransportType(
                header_type=HeaderType.GEOBROADCAST,
                header_subtype=GeoBroadcastHST.GEOBROADCAST_CIRCLE,
            ),
            traffic_class=TrafficClass(),
            length=500,
        )
        ch = CommonHeader.initialize_with_request(request)
        self.assertEqual(ch.nh, CommonNH.BTP_B)
        self.assertEqual(ch.ht, HeaderType.GEOBROADCAST)
        self.assertEqual(ch.hst, GeoBroadcastHST.GEOBROADCAST_CIRCLE)
        self.assertEqual(ch.tc.encode_to_int(), 0)
        self.assertEqual(ch.flags, 0)
        self.assertEqual(ch.pl, 500)
        self.assertEqual(ch.mhl, 1)

    def test_encode_to_bytes(self):
        ch = CommonHeader()
        self.assertEqual(ch.encode_to_bytes(),
                         b'\x00\x00\x00\x00\x00\x00\x00\x00')
        ch = CommonHeader(
            nh=CommonNH.BTP_A,
            ht=HeaderType.BEACON,
            hst=HeaderSubType.UNSPECIFIED,
            tc=TrafficClass(
                tc_id=0x1,
                scf=True,
                channel_offload=True,
            ),
            pl=300,
            mhl=1,
        )
        self.assertEqual(ch.encode_to_bytes(),
                         b'\x10\x10\xc1\x00\x01,\x01\x00')

    def test_decode_from_bytes(self):
        ch = CommonHeader(
            nh=CommonNH.BTP_A,
            ht=HeaderType.BEACON,
            hst=HeaderSubType.UNSPECIFIED,
            tc=TrafficClass(
                tc_id=0x1,
                scf=True,
                channel_offload=True,
            ),
            pl=300,
            mhl=1,
        )
        ch2 = CommonHeader.decode_from_bytes(ch.encode_to_bytes())
        self.assertEqual(ch.nh, ch2.nh)
        self.assertEqual(ch.ht, ch2.ht)
        self.assertEqual(ch.hst, ch2.hst)
        self.assertEqual(ch.tc, ch2.tc)
        self.assertEqual(ch.flags, ch2.flags)
        self.assertEqual(ch.pl, ch2.pl)
        self.assertEqual(ch.mhl, ch2.mhl)


if __name__ == '__main__':
    unittest.main()
