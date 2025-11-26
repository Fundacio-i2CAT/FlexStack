import unittest
import json

from flexstack.geonet.service_access_point import (
    CommonNH,
    GeoAnycastHST,
    GeoBroadcastHST,
    HeaderType,
    LocationServiceHST,
    TopoBroadcastHST,
    TrafficClass,
    PacketTransportType,
    Area,
    GNDataRequest,
    CommunicationProfile,
    GNDataIndication,
)


class TestTrafficClass(unittest.TestCase):
    def test_set_tc_id_raise_value_error(self):
        tc = TrafficClass()
        with self.assertRaises(ValueError):
            tc.set_tc_id(0x100)

    def test_encode_to_bytes(self):
        tc = TrafficClass(
            tc_id=0x1,
            scf=True,
            channel_offload=True,
        )
        self.assertEqual(tc.encode_to_bytes(), b"\xc1")

    def test_decode_from_bytes(self):
        tcp = TrafficClass(
            tc_id=1,
            scf=True,
            channel_offload=True,
        )
        tc = TrafficClass.decode_from_bytes(tcp.encode_to_bytes())
        self.assertEqual(tc.tc_id, 0x1)
        self.assertTrue(tc.scf)
        self.assertTrue(tc.channel_offload)


class TestPacketTransportType(unittest.TestCase):
    def test__init__(self):
        ptt = PacketTransportType()
        self.assertEqual(ptt.header_type, HeaderType.TSB)
        self.assertEqual(ptt.header_subtype, TopoBroadcastHST.SINGLE_HOP)

    def test_to_dict(self):
        ptt = PacketTransportType()
        self.assertEqual(ptt.to_dict(), {"header_type": 5, "header_subtype": 0})

    def test_from_dict(self):
        # Geoanycast
        ptt = PacketTransportType(
            header_type=HeaderType.GEOANYCAST,
            header_subtype=GeoAnycastHST.GEOANYCAST_CIRCLE,
        )
        nppt = PacketTransportType.from_dict(ptt.to_dict())
        self.assertEqual(nppt.header_type, HeaderType.GEOANYCAST)
        self.assertEqual(nppt.header_subtype, GeoAnycastHST.GEOANYCAST_CIRCLE)
        # Geobroadcast
        ptt = PacketTransportType(
            header_type=HeaderType.GEOBROADCAST,
            header_subtype=GeoBroadcastHST.GEOBROADCAST_CIRCLE,
        )
        nppt = PacketTransportType.from_dict(ptt.to_dict())
        self.assertEqual(nppt.header_type, HeaderType.GEOBROADCAST)
        self.assertEqual(nppt.header_subtype, GeoBroadcastHST.GEOBROADCAST_CIRCLE)
        # TSB
        ptt = PacketTransportType(
            header_type=HeaderType.TSB,
            header_subtype=TopoBroadcastHST.SINGLE_HOP,
        )
        nppt = PacketTransportType.from_dict(ptt.to_dict())
        self.assertEqual(nppt.header_type, HeaderType.TSB)
        self.assertEqual(nppt.header_subtype, TopoBroadcastHST.SINGLE_HOP)
        # LS
        ptt = PacketTransportType(
            header_type=HeaderType.LS,
            header_subtype=LocationServiceHST.LS_REPLY,
        )
        nppt = PacketTransportType.from_dict(ptt.to_dict())
        self.assertEqual(nppt.header_type, HeaderType.LS)
        self.assertEqual(nppt.header_subtype, LocationServiceHST.LS_REPLY)


class TestArea(unittest.TestCase):
    def test__init__(self):
        area = Area()
        self.assertEqual(area.latitude, 0)
        self.assertEqual(area.longitude, 0)
        self.assertEqual(area.a, 0)
        self.assertEqual(area.b, 0)
        self.assertEqual(area.angle, 0)

    def test_to_dict(self):
        area = Area()
        self.assertEqual(
            area.to_dict(), {"latitude": 0, "longitude": 0, "a": 0, "b": 0, "angle": 0}
        )

    def test_from_dict(self):
        area = Area(
            latitude=1,
            longitude=2,
            a=3,
            b=4,
            angle=5,
        )
        narea = Area.from_dict(area.to_dict())
        self.assertEqual(narea.latitude, 1)
        self.assertEqual(narea.longitude, 2)
        self.assertEqual(narea.a, 3)
        self.assertEqual(narea.b, 4)
        self.assertEqual(narea.angle, 5)


class TestGNDataRequest(unittest.TestCase):
    def test__init__(self):
        gndr = GNDataRequest()
        self.assertEqual(gndr.upper_protocol_entity, CommonNH.ANY)
        self.assertEqual(gndr.communication_profile, CommunicationProfile.UNSPECIFIED)
        self.assertEqual(gndr.length, 0)
        self.assertEqual(gndr.data, b"")

    def test_to_dict(self):
        gndr = GNDataRequest()
        self.assertEqual(
            gndr.to_dict(),
            {
                "upper_protocol_entity": 0,
                "packet_transport_type": {"header_type": 5, "header_subtype": 0},
                "communication_profile": 0,
                "traffic_class": "AA==",
                "length": 0,
                "data": "",
                "area": {"latitude": 0, "longitude": 0, "a": 0, "b": 0, "angle": 0},
            },
        )

    def test_from_dict(self):
        gndr = GNDataRequest(
            upper_protocol_entity=CommonNH.ANY,
            packet_transport_type=PacketTransportType(),
            communication_profile=CommunicationProfile.UNSPECIFIED,
            traffic_class=TrafficClass(),
            length=0,
            data=b"",
            area=Area(),
        )
        ngndr = GNDataRequest.from_dict(gndr.to_dict())
        self.assertEqual(ngndr.upper_protocol_entity, CommonNH.ANY)
        self.assertEqual(ngndr.packet_transport_type.header_type, HeaderType.TSB)
        self.assertEqual(
            ngndr.packet_transport_type.header_subtype, TopoBroadcastHST.SINGLE_HOP
        )
        self.assertEqual(ngndr.communication_profile, CommunicationProfile.UNSPECIFIED)
        self.assertEqual(ngndr.traffic_class.tc_id, 0)
        self.assertEqual(ngndr.length, 0)
        self.assertEqual(ngndr.data, b"")
        self.assertEqual(ngndr.area.latitude, 0)
        self.assertEqual(ngndr.area.longitude, 0)
        self.assertEqual(ngndr.area.a, 0)
        self.assertEqual(ngndr.area.b, 0)
        self.assertEqual(ngndr.area.angle, 0)

    def test_json_dict_encoding_decoding(self):
        gndr = GNDataRequest()
        json.loads(json.dumps(gndr.to_dict()))


class TestGNDataIndication(unittest.TestCase):
    def test__init__(self):
        gn_data_indication = GNDataIndication()
        self.assertEqual(gn_data_indication.upper_protocol_entity, CommonNH.ANY)
        self.assertEqual(gn_data_indication.length, 0)
        self.assertEqual(gn_data_indication.data, b"")

    def test_to_dict(self):
        gn_data_indication = GNDataIndication()
        self.assertEqual(
            gn_data_indication.to_dict(),
            {
                "upper_protocol_entity": 0,
                "packet_transport_type": {"header_type": 5, "header_subtype": 0},
                "source_position_vector": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "traffic_class": "AA==",
                "length": 0,
                "data": "",
            },
        )

    def test_from_dict(self):
        gn_data_indication = GNDataIndication(
            upper_protocol_entity=CommonNH.ANY,
            packet_transport_type=PacketTransportType(),
            length=0,
            data=b""
        )
        ngndi = GNDataIndication()
        ngndi.from_dict(gn_data_indication.to_dict())
        self.assertEqual(ngndi.upper_protocol_entity, CommonNH.ANY)
        self.assertEqual(ngndi.packet_transport_type.header_type, HeaderType.TSB)
        self.assertEqual(
            ngndi.packet_transport_type.header_subtype, TopoBroadcastHST.SINGLE_HOP
        )
        self.assertEqual(ngndi.length, 0)
        self.assertEqual(ngndi.data, b"")

    def test_json_dict_encoding_decoding(self):
        gndr = GNDataIndication()
        json.loads(json.dumps(gndr.to_dict()))


if __name__ == "__main__":
    unittest.main()
