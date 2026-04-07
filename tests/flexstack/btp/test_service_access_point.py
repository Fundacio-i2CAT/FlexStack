import json
from unittest import TestCase
from flexstack.geonet.gn_address import GNAddress
from flexstack.btp.service_access_point import BTPDataIndication, BTPDataRequest
from flexstack.geonet.service_access_point import TrafficClass
from flexstack.security.security_profiles import SecurityProfile


class TestBTPDataRequest(TestCase):
    def test__init__(self):
        btp_data_request = BTPDataRequest()
        self.assertEqual(btp_data_request.btp_type.value, 2)
        self.assertEqual(btp_data_request.source_port, 0)
        self.assertEqual(btp_data_request.destination_port, 0)
        self.assertEqual(btp_data_request.destination_port_info, 0)
        self.assertEqual(
            btp_data_request.gn_destination_address.encode(), GNAddress().encode()
        )
        self.assertEqual(btp_data_request.communication_profile.value, 0)
        self.assertEqual(
            btp_data_request.traffic_class.encode_to_bytes(),
            TrafficClass().encode_to_bytes(),
        )
        self.assertEqual(btp_data_request.length, 0)
        self.assertEqual(btp_data_request.data, b"")
        self.assertEqual(btp_data_request.security_profile, SecurityProfile.NO_SECURITY)
        self.assertEqual(btp_data_request.its_aid, 0)
        self.assertEqual(btp_data_request.security_permissions, b"\x00")

    def test_security_profile_can_be_set(self):
        btp_data_request = BTPDataRequest(
            security_profile=SecurityProfile.COOPERATIVE_AWARENESS_MESSAGE,
            its_aid=36,
            security_permissions=b"\x01",
        )
        self.assertEqual(
            btp_data_request.security_profile,
            SecurityProfile.COOPERATIVE_AWARENESS_MESSAGE,
        )
        self.assertEqual(btp_data_request.its_aid, 36)
        self.assertEqual(btp_data_request.security_permissions, b"\x01")

    def test_to_dict(self):
        btp_data_request = BTPDataRequest()
        self.assertEqual(
            btp_data_request.to_dict(),
            {
                "btp_type": 2,
                "source_port": 0,
                "destination_port": 0,
                "destination_port_info": 0,
                "gn_packet_transport_type": {"header_type": 5, "header_subtype": 0},
                "gn_destination_address": "AAAAAAAAAAA=",
                "gn_area": {"latitude": 0, "longitude": 0, "a": 0, "b": 0, "angle": 0},
                "gn_max_packet_lifetime": None,
                "gn_repetition_interval": None,
                "gn_max_repetition_time": None,
                "communication_profile": 0,
                "traffic_class": "AA==",
                "length": 0,
                "data": "",
            },
        )

    def test_from_dict(self):
        btp_data_request = BTPDataRequest.from_dict(
            {
                "btp_type": 1,
                "source_port": 12,
                "destination_port": 0,
                "destinaion_port_info": 0,
                "gn_packet_transport_type": {"header_type": 5, "header_subtype": 0},
                "gn_destination_address": "AAAAAAAAAAA=",
                "gn_area": {"latitude": 0, "longitude": 0, "a": 0, "b": 0, "angle": 0},
                "communication_profile": 0,
                "traffic_class": "AA==",
                "length": 0,
                "data": "",
            }
        )
        self.assertEqual(btp_data_request.btp_type.value, 1)
        self.assertEqual(btp_data_request.source_port, 12)
        self.assertEqual(btp_data_request.destination_port, 0)
        self.assertEqual(btp_data_request.destination_port_info, 0)
        self.assertEqual(
            btp_data_request.gn_destination_address.encode(), GNAddress().encode()
        )
        self.assertEqual(btp_data_request.communication_profile.value, 0)
        self.assertEqual(
            btp_data_request.traffic_class.encode_to_bytes(),
            TrafficClass().encode_to_bytes(),
        )
        self.assertEqual(btp_data_request.length, 0)
        self.assertEqual(btp_data_request.data, b"")

    def test_json_dict_encoding_decoding(self):
        btp_data_request = BTPDataRequest()
        json.loads(json.dumps(btp_data_request.to_dict()))


class TestBTPDataIndication(TestCase):
    def test__init__(self):
        btp_data_indication = BTPDataIndication()
        self.assertEqual(btp_data_indication.source_port, 0)
        self.assertEqual(btp_data_indication.destination_port, 0)
        self.assertEqual(btp_data_indication.destination_port_info, 0)
        self.assertEqual(
            btp_data_indication.gn_destination_address.encode(), GNAddress().encode()
        )
        self.assertEqual(btp_data_indication.length, 0)
        self.assertEqual(btp_data_indication.data, b"")

    def test_to_dict(self):
        btp_data_indication = BTPDataIndication()
        self.assertEqual(
            btp_data_indication.to_dict(),
            {
                "source_port": 0,
                "destination_port": 0,
                "destination_port_info": 0,
                "gn_packet_transport_type": {"header_type": 5, "header_subtype": 0},
                "gn_destination_address": "AAAAAAAAAAA=",
                "gn_source_position_vector": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "gn_security_report": None,
                "gn_certificate_id": None,
                "gn_permissions": None,
                "gn_traffic_class": "AA==",
                "gn_remaining_packet_lifetime": None,
                "length": 0,
                "data": "",
            },
        )

    def test_from_dict(self):
        btp_data_indication = BTPDataIndication.from_dict(
            {
                "source_port": 12,
                "destination_port": 0,
                "destinaion_port_info": 0,
                "gn_packet_transport_type": {"header_type": 5, "header_subtype": 0},
                "gn_destination_address": "AAAAAAAAAAA=",
                "gn_source_position_vector": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "gn_traffic_class": "AA==",
                "length": 0,
                "data": "",
            }
        )
        self.assertEqual(btp_data_indication.source_port, 12)
        self.assertEqual(btp_data_indication.destination_port, 0)
        self.assertEqual(btp_data_indication.destination_port_info, 0)
        self.assertEqual(
            btp_data_indication.gn_destination_address.encode(), GNAddress().encode()
        )
        self.assertEqual(
            btp_data_indication.gn_traffic_class.encode_to_bytes(),
            TrafficClass().encode_to_bytes(),
        )
        self.assertEqual(btp_data_indication.length, 0)
        self.assertEqual(btp_data_indication.data, b"")

    def test_json_dict_encoding_decoding(self):
        btp_data_request = BTPDataIndication()
        json.loads(json.dumps(btp_data_request.to_dict()))
