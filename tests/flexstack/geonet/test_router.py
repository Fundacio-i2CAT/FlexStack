import unittest
from unittest.mock import Mock

from flexstack.geonet.router import DADException, GNForwardingAlgorithmResponse, Router
from flexstack.geonet.mib import MIB
from flexstack.geonet.position_vector import LongPositionVector
from flexstack.geonet.service_access_point import Area, CommonNH, GNDataIndication, GNDataRequest, GNDataConfirm, GeoBroadcastHST, HeaderType, ResultCode, TopoBroadcastHST, PacketTransportType
from flexstack.geonet.gn_address import ST, GNAddress
from flexstack.geonet.basic_header import BasicHeader
from flexstack.geonet.common_header import CommonHeader
from flexstack.geonet.gbc_extended_header import GBCExtendedHeader


class TestRouter(unittest.TestCase):
    def test__init__(self):
        # Given
        mib = MIB()
        position_vector = LongPositionVector().set_gn_addr(mib.itsGnLocalGnAddr)
        # When
        router = Router(mib)
        # Then
        self.assertEqual(router.mib, mib)
        self.assertEqual(router.ego_position_vector, position_vector)
        self.assertIsNone(router.link_layer)
        self.assertIsNone(router.indication_callback)
        # self.assertEqual(router.location_table, location_table)
        # __eq__ is not implemented for LocationTable

    def test_get_sequence_number(self):
        # Given
        mib = MIB()
        router = Router(mib)
        # When
        sequence_number = router.get_sequence_number()
        # Then
        self.assertEqual(sequence_number, 1)
        # When
        sequence_number = router.get_sequence_number()
        # Then
        self.assertEqual(sequence_number, 2)

    def test_register_indication_callback(self):
        # Given
        def indication_callback(indication: GNDataIndication) -> None:
            pass
        # when
        router = Router(MIB())
        router.register_indication_callback(indication_callback)
        # Then
        self.assertEqual(router.indication_callback, indication_callback)

    def test_setup_gn_address(self):
        # Given
        mib = MIB(
            itsGnLocalGnAddr=GNAddress(st=ST.TRAILER)
        )
        router = Router(mib)
        # When
        router.setup_gn_address()
        # Then
        self.assertEqual(router.ego_position_vector.gn_addr,
                         mib.itsGnLocalGnAddr)

    def test_GNDataRequestSHB(self):
        # Given
        mib = MIB()
        router = Router(mib)
        link_layer = Mock()
        link_layer.send = Mock()
        router.link_layer = link_layer

        # Create a mock GNDataRequest object to pass as an argument to the function
        request: GNDataRequest = GNDataRequest(
            data=b'request_data'
        )

        # When
        result = router.gn_data_request_shb(request)

        # Assert that the result is an instance of GNDataConfirm
        self.assertIsInstance(result, GNDataConfirm)
        link_layer.send.assert_called_once_with(
            b'\x11\x00\x1a\x01\x00P\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00request_data')
        self.assertEqual(result.result_code, ResultCode.ACCEPTED)

    def test_calculate_distance(self):
        # Given
        coord1 = (41.386303, 2.170094)
        coord2 = (41.385884, 2.164387)
        # When
        result = Router.calculate_distance(coord1, coord2)
        # Then
        self.assertAlmostEqual(round(result[0], 2), 46.59)
        self.assertAlmostEqual(round(result[1], 2), -476.11)

    def test_transform_distance_angle(self):
        # Given
        distance = (1, 0)
        # When
        result = Router.transform_distance_angle(distance, 45)
        # Then
        self.assertAlmostEqual(round(result[0], 2), 0.71)
        self.assertAlmostEqual(round(result[1], 2), 0)

    def test_GNGeometricFunctionF(self):
        # Given
        mib = MIB()
        router = Router(mib)
        # When
        area_type = GeoBroadcastHST.GEOBROADCAST_CIRCLE
        area = Area(
            a=100,
            b=100,
            angle=0,
            latitude=421255850,
            longitude=27601710
        )
        latitude = 421254550
        longitude = 27603740
        result = router.gn_geometric_function_f(
            area_type, area, latitude, longitude)
        # Then
        self.assertGreater(result, 0)
        latitude = 421236840
        longitude = 27632710
        result = router.gn_geometric_function_f(
            area_type, area, latitude, longitude)
        self.assertLess(result, 0)

    def test_GNForwardingAlgorithmSelection(self):
        # Given
        mib = MIB()
        router = Router(mib)
        router.ego_position_vector = LongPositionVector(
            latitude=421255850,
            longitude=27601710
        )
        request = GNDataRequest(
            data=b'request_data',
            area=Area(
                a=100,
                b=100,
                angle=0,
                latitude=421255850,
                longitude=27601710
            ),
            packet_transport_type=PacketTransportType(
                header_type=HeaderType.GEOBROADCAST,
                header_subtype=GeoBroadcastHST.GEOBROADCAST_CIRCLE,
            )
        )
        # When
        result = router.gn_forwarding_algorithm_selection(request)
        # Then
        self.assertEqual(result, GNForwardingAlgorithmResponse.AREA_FORWARDING)

    def test_GNDataforwardGBC(self):
        # Given
        mib = MIB()
        router = Router(mib)
        router.link_layer = Mock()
        router.link_layer.send = Mock()
        router.gn_forwarding_algorithm_selection = Mock(
            return_value=GNForwardingAlgorithmResponse.AREA_FORWARDING)

        basic_header = BasicHeader(rhl=10)

        common_header = CommonHeader(
            ht=HeaderType.GEOBROADCAST,
            hst=GeoBroadcastHST.GEOBROADCAST_CIRCLE  # type: ignore
        )
        gbc_extended_header = GBCExtendedHeader(
            latitude=421255850,
            longitude=27601710,
            a=100,
            b=100,
            angle=0
        )

        # When
        router.gn_data_forward_gbc(
            basic_header, common_header, gbc_extended_header, b'payload')

        basic_header = basic_header.set_rhl(basic_header.rhl - 1)
        # Then
        router.link_layer.send.assert_called_once_with(basic_header.encode_to_bytes(
        ) + common_header.encode_to_bytes() + gbc_extended_header.encode() + b'payload')
        router.gn_forwarding_algorithm_selection.assert_called_once()

    def test_GNDataRequestGBC(self):
        # Given
        mib = MIB()
        router = Router(mib)
        router.link_layer = Mock()
        router.link_layer.send = Mock()
        request = GNDataRequest(
            upper_protocol_entity=CommonNH.BTP_B,
            packet_transport_type=PacketTransportType(
                header_type=HeaderType.GEOBROADCAST,
                header_subtype=GeoBroadcastHST.GEOBROADCAST_CIRCLE,
            ),
            area=Area(
                a=100,
                b=100,
                angle=0,
                latitude=421255850,
                longitude=27601710
            ),
        )
        router.gn_forwarding_algorithm_selection = Mock(
            return_value=GNForwardingAlgorithmResponse.AREA_FORWARDING)

        # When
        router.gn_data_request_gbc(request=request)

        # Then
        router.link_layer.send.assert_called_once()
        router.gn_forwarding_algorithm_selection.assert_called_once()

    def test_GNDataRequest(self):
        # Given
        mib = MIB()
        router = Router(mib)
        confirm = GNDataConfirm(
            result_code=ResultCode.ACCEPTED
        )
        router.gn_data_request_gbc = Mock(return_value=confirm)
        router.gn_data_request_shb = Mock(return_value=confirm)
        request = GNDataRequest(
            upper_protocol_entity=CommonNH.BTP_B,
            packet_transport_type=PacketTransportType(
                header_type=HeaderType.GEOBROADCAST,
                header_subtype=GeoBroadcastHST.GEOBROADCAST_CIRCLE,
            ),
        )
        # When
        router.gn_data_request(request=request)

        # Then
        router.gn_data_request_gbc.assert_called_once_with(request)
        router.gn_data_request_shb.assert_not_called()

        # Given
        router.gn_data_request_gbc = Mock(return_value=confirm)
        router.gn_data_request_shb = Mock(return_value=confirm)
        request = GNDataRequest(
            upper_protocol_entity=CommonNH.BTP_B,
            packet_transport_type=PacketTransportType(
                header_type=HeaderType.TSB,
                header_subtype=TopoBroadcastHST.SINGLE_HOP,
            ),
        )
        # When
        router.gn_data_request(request=request)

        # Then
        router.gn_data_request_gbc.assert_not_called()
        router.gn_data_request_shb.assert_called_once_with(request)

    def test_GNDataIndicateSHB(self):
        # Given
        mib = MIB()
        router = Router(mib)
        router.location_table.new_shb_packet = Mock()
        common_header = CommonHeader(
            hst=TopoBroadcastHST.SINGLE_HOP,  # type: ignore
            ht=HeaderType.TSB
        )
        position_vector = LongPositionVector(
            latitude=421255850,
            longitude=27601710,
            s=12,
            h=30
        )
        packet = position_vector.encode() + bytes(4) + b'payload'

        # When
        result = router.gn_data_indicate_shb(packet, common_header)

        # Then
        router.location_table.new_shb_packet.assert_called_once()
        self.assertEqual(result.data, b'payload')

    def test_GNDataIndicateGBC(self):
        # Given
        mib = MIB()
        router = Router(mib)
        router.location_table.new_gbc_packet = Mock()
        router.gn_geometric_function_f = Mock(return_value=0.5)
        gbc_extended_header = GBCExtendedHeader(
            latitude=421255850,
            longitude=27601710,
            a=100,
            b=100,
            angle=0
        )
        router.duplicate_address_detection = Mock()
        common_header = CommonHeader()
        packet = gbc_extended_header.encode() + b'payload'

        # When
        result = router.gn_data_indicate_gbc(packet, common_header)

        # Then
        self.assertEqual(result.data, b'payload')
        router.location_table.new_gbc_packet.assert_called_once()
        router.gn_geometric_function_f.assert_called_once()
        router.duplicate_address_detection.assert_called_once()

    def test_GNDataIndicate(self):
        # Given
        mib = MIB()
        router = Router(mib)
        router.gn_data_indicate_gbc = Mock()
        router.gn_data_indicate_shb = Mock()
        common_header = CommonHeader(
            hst=GeoBroadcastHST.GEOBROADCAST_CIRCLE,  # type: ignore
            ht=HeaderType.GEOBROADCAST
        )
        basic_header = BasicHeader(
            version=1
        )
        packet = basic_header.encode_to_bytes() + common_header.encode_to_bytes() + \
            b'packetthebestpacket'

        # When
        router.gn_data_indicate(packet)

        # Then
        router.gn_data_indicate_gbc.assert_called_once()
        router.gn_data_indicate_shb.assert_not_called()

        # Given
        router.gn_data_indicate_gbc = Mock()
        router.gn_data_indicate_shb = Mock()
        common_header = CommonHeader(
            hst=TopoBroadcastHST.SINGLE_HOP,  # type: ignore
            ht=HeaderType.TSB
        )
        packet = basic_header.encode_to_bytes() + common_header.encode_to_bytes() + \
            b'packetthebestpacket'

        # When
        router.gn_data_indicate(packet)

        # Then
        router.gn_data_indicate_gbc.assert_not_called()
        router.gn_data_indicate_shb.assert_called_once()

    def test_duplicate_address_detection(self):
        # Given
        mib = MIB()
        router = Router(mib)

        # When & Then
        self.assertRaises(
            DADException, router.duplicate_address_detection, mib.itsGnLocalGnAddr)

    def test_refresh_ego_position_vector(self):
        # Given
        mib = MIB()
        router = Router(mib)
        tpv_data = {"class": "TPV", "device": "/dev/pts/1",
                    "time": "2005-06-08T10:34:48.283Z", "ept": 0.005,
                    "lat": 46.498293369, "lon": 7.567411672, "alt": 1343.127,
                    "eph": 36.000, "epv": 32.321,
                    "track": 10.3788, "speed": 0.091, "climb": -0.085, "mode": 3}

        # When
        router.refresh_ego_position_vector(tpv_data)

        # Then
        self.assertEqual(router.ego_position_vector.latitude, 464982933)
        self.assertEqual(router.ego_position_vector.longitude, 75674116)
        self.assertEqual(router.ego_position_vector.s, 9)
        self.assertEqual(router.ego_position_vector.h, 103)
