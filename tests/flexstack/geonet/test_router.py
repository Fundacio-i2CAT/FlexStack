import unittest
from unittest.mock import Mock, MagicMock

from flexstack.geonet.router import DADException, GNForwardingAlgorithmResponse, Router
from flexstack.geonet.mib import MIB, AreaForwardingAlgorithm
from flexstack.geonet.position_vector import LongPositionVector, ShortPositionVector
from flexstack.geonet.service_access_point import Area, CommonNH, GNDataIndication, GNDataRequest, GNDataConfirm, GeoBroadcastHST, GeoAnycastHST, HeaderType, LocationServiceHST, ResultCode, TopoBroadcastHST, PacketTransportType, TrafficClass
from flexstack.geonet.gn_address import ST, GNAddress, M, MID
from flexstack.geonet.basic_header import BasicHeader, BasicNH
from flexstack.geonet.common_header import CommonHeader
from flexstack.geonet.gbc_extended_header import GBCExtendedHeader
from flexstack.geonet.guc_extended_header import GUCExtendedHeader
from flexstack.geonet.ls_extended_header import LSRequestExtendedHeader, LSReplyExtendedHeader
from flexstack.security.verify_service import VerifyService
from flexstack.security.sn_sap import SNVERIFYConfirm, ReportVerify


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
            b'\x11\x00\x1a\x01\x00P\x00\x80\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00request_data')
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
        # Given – use SIMPLE forwarding so AREA_FORWARDING sends immediately (§F.2)
        mib = MIB(itsGnAreaForwardingAlgorithm=AreaForwardingAlgorithm.SIMPLE)
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
        router.duplicate_address_detection = Mock()
        common_header = CommonHeader(
            hst=TopoBroadcastHST.SINGLE_HOP,  # type: ignore
            ht=HeaderType.TSB
        )
        basic_header = BasicHeader(rhl=1)
        position_vector = LongPositionVector(
            latitude=421255850,
            longitude=27601710,
            s=12,
            h=30
        )
        packet = position_vector.encode() + bytes(4) + b'payload'

        # When
        result = router.gn_data_indicate_shb(
            packet, common_header, basic_header)

        # Then
        router.location_table.new_shb_packet.assert_called_once()
        router.duplicate_address_detection.assert_called_once()
        self.assertEqual(result.data, b'payload')

    def test_GNDataIndicateGBC(self):
        # Given
        mib = MIB()
        router = Router(mib)
        router.location_table.new_gbc_packet = Mock()
        router.gn_geometric_function_f = Mock(return_value=0.5)
        router.gn_data_forward_gbc = Mock()
        gbc_extended_header = GBCExtendedHeader(
            latitude=421255850,
            longitude=27601710,
            a=100,
            b=100,
            angle=0
        )
        router.duplicate_address_detection = Mock()
        common_header = CommonHeader()
        basic_header = BasicHeader(rhl=5)
        packet = gbc_extended_header.encode() + b'payload'

        # When
        result = router.gn_data_indicate_gbc(
            packet, common_header, basic_header)

        # Then
        self.assertEqual(result.data, b'payload')
        # destination_area must be populated from the GBC extended header (Table 38)
        self.assertIsNotNone(result.destination_area)
        self.assertEqual(result.destination_area.latitude, 421255850)
        # remaining_packet_lifetime and remaining_hop_limit must be set (Table 38)
        self.assertIsNotNone(result.remaining_packet_lifetime)
        self.assertEqual(result.remaining_hop_limit, 5)
        router.location_table.new_gbc_packet.assert_called_once()
        router.gn_geometric_function_f.assert_called_once()
        router.duplicate_address_detection.assert_called_once()
        # forwarding must be triggered (steps 9-14, rhl=5>0)
        router.gn_data_forward_gbc.assert_called_once()

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

    def test_gn_security_enabled_drops_unsecured_packets(self):
        """When itsGnSecurity=ENABLED, unsecured packets (NH=COMMON_HEADER) must be silently dropped."""
        from flexstack.geonet.mib import GnSecurity
        mib = MIB(itsGnSecurity=GnSecurity.ENABLED)
        router = Router(mib)
        callback = Mock()
        router.register_indication_callback(callback)
        router.gn_data_indicate_shb = Mock()

        # Build an unsecured SHB packet (NH=COMMON_HEADER)
        basic_header = BasicHeader(version=1)
        common_header = CommonHeader(
            ht=HeaderType.TSB, hst=TopoBroadcastHST.SINGLE_HOP)  # type: ignore
        packet = basic_header.encode_to_bytes() + common_header.encode_to_bytes() + bytes(28)

        router.gn_data_indicate(packet)

        router.gn_data_indicate_shb.assert_not_called()
        callback.assert_not_called()

    def test_gn_security_disabled_accepts_unsecured_packets(self):
        """When itsGnSecurity=DISABLED (default), unsecured packets must be processed normally."""
        mib = MIB()  # itsGnSecurity defaults to DISABLED
        router = Router(mib)
        router.gn_data_indicate_shb = Mock(return_value=GNDataIndication())
        callback = Mock()
        router.register_indication_callback(callback)

        basic_header = BasicHeader(version=1)
        common_header = CommonHeader(
            ht=HeaderType.TSB, hst=TopoBroadcastHST.SINGLE_HOP)  # type: ignore
        packet = basic_header.encode_to_bytes() + common_header.encode_to_bytes() + bytes(28)

        router.gn_data_indicate(packet)

        router.gn_data_indicate_shb.assert_called_once()

    def test_GNDataRequestBeacon(self):
        # Given
        mib = MIB()
        router = Router(mib)
        link_layer = Mock()
        link_layer.send = Mock()
        router.link_layer = link_layer

        # When
        router.gn_data_request_beacon()

        # Then - packet = BasicHeader(4) + CommonHeader(8) + LPV(24) = 36 bytes
        # BasicHeader: version=1, NH=COMMON_HEADER, LT=60s(0x1a), RHL=1
        # CommonHeader: NH=ANY(0x00), HT=BEACON(0x1)(+HST=0 => 0x10), TC=0,
        #               flags=itsGnIsMobile=MOBILE=0x80, PL=0, MHL=1, reserved=0
        link_layer.send.assert_called_once_with(
            b'\x11\x00\x1a\x01\x00\x10\x00\x01\x00\x00\x01\x00' + bytes(24)
        )

    def test_GNDataIndicateBeacon(self):
        # Given
        mib = MIB()
        router = Router(mib)
        router.location_table.new_shb_packet = Mock()
        router.duplicate_address_detection = Mock()
        callback = Mock()
        router.register_indication_callback(callback)
        position_vector = LongPositionVector(
            latitude=421255850,
            longitude=27601710,
        )
        # Beacon packet (after Basic and Common headers are stripped): only a LPV, no payload
        packet = position_vector.encode()

        # When
        router.gn_data_indicate_beacon(packet)

        # Then: DAD is executed (§10.3.6.3 -> §10.3.10.3 step 3)
        router.duplicate_address_detection.assert_called_once()
        # And location table is updated
        router.location_table.new_shb_packet.assert_called_once()
        # Beacons do NOT pass payload to upper entity (§10.3.6.3 exception for step 8)
        callback.assert_not_called()

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


class TestRouterSecuredPacket(unittest.TestCase):
    """Tests for SECURED_PACKET reception in the GeoNetworking router."""

    def _build_secured_packet(self, inner_bytes: bytes) -> bytes:
        """Return a GN PDU with BasicNH.SECURED_PACKET + arbitrary inner payload."""
        basic_header = BasicHeader(version=1).set_nh(BasicNH.SECURED_PACKET)
        return basic_header.encode_to_bytes() + inner_bytes

    def test_gn_data_indicate_secured_no_verify_service(self):
        """Secured packets must be silently discarded when no VerifyService is configured."""
        mib = MIB()
        router = Router(mib)  # verify_service defaults to None
        callback = MagicMock()
        router.register_indication_callback(callback)

        packet = self._build_secured_packet(b"some_signed_data")
        router.gn_data_indicate(packet)

        callback.assert_not_called()

    def test_gn_data_indicate_secured_verification_failed(self):
        """Secured packets must be discarded when verification returns a failure report."""
        mib = MIB()
        verify_service = MagicMock(spec=VerifyService)
        verify_service.verify.return_value = SNVERIFYConfirm(
            report=ReportVerify.FALSE_SIGNATURE,
            certificate_id=b"",
            its_aid=b"",
            its_aid_length=0,
            permissions=b"",
            plain_message=b"",
        )
        router = Router(mib, verify_service=verify_service)
        callback = MagicMock()
        router.register_indication_callback(callback)

        packet = self._build_secured_packet(b"bad_signed_data")
        router.gn_data_indicate(packet)

        verify_service.verify.assert_called_once()
        callback.assert_not_called()

    def test_gn_data_indicate_secured_verification_success(self):
        """On successful verification the inner GN packet must be indicated via the callback."""
        mib = MIB()
        # Build a valid inner SHB GN packet (common_header + LPV + media_dep + payload)
        common_header = CommonHeader(
            ht=HeaderType.TSB,
            hst=TopoBroadcastHST.SINGLE_HOP,  # type: ignore
        )
        long_position_vector = LongPositionVector()
        media_dep = b"\x00\x00\x00\x00"
        upper_payload = b"secured_cam_data"
        plain_message = (
            common_header.encode_to_bytes() + long_position_vector.encode() + media_dep + upper_payload
        )

        verify_service = MagicMock(spec=VerifyService)
        verify_service.verify.return_value = SNVERIFYConfirm(
            report=ReportVerify.SUCCESS,
            certificate_id=b"\x01\x02\x03\x04\x05\x06\x07\x08",
            its_aid=b"",
            its_aid_length=0,
            permissions=b"",
            plain_message=plain_message,
        )

        router = Router(mib, verify_service=verify_service)
        router.location_table.new_shb_packet = MagicMock()
        router.duplicate_address_detection = MagicMock()
        callback = MagicMock()
        router.register_indication_callback(callback)

        packet = self._build_secured_packet(b"valid_signed_data")
        router.gn_data_indicate(packet)

        verify_service.verify.assert_called_once()
        callback.assert_called_once()
        indication: GNDataIndication = callback.call_args[0][0]
        self.assertEqual(indication.data, upper_payload)


class TestProcessBasicHeader(unittest.TestCase):
    """Unit tests for Router.process_basic_header."""

    def _make_packet(self, nh: BasicNH, payload: bytes = b"payload") -> bytes:
        bh = BasicHeader(version=1).set_nh(nh)
        return bh.encode_to_bytes() + payload

    def test_common_header_dispatches_to_process_common_header(self):
        """NH=COMMON_HEADER (security DISABLED) must forward to process_common_header."""
        mib = MIB()
        router = Router(mib)
        router.process_common_header = Mock()

        payload = b"\x00" * 8 + b"rest"
        packet = self._make_packet(BasicNH.COMMON_HEADER, payload)
        router.process_basic_header(packet)

        router.process_common_header.assert_called_once()
        args = router.process_common_header.call_args[0]
        # remaining bytes after basic header
        self.assertEqual(args[0], payload)

    def test_secured_packet_dispatches_to_process_security_header(self):
        """NH=SECURED_PACKET must forward to process_security_header."""
        mib = MIB()
        router = Router(mib)
        router.process_security_header = Mock()

        payload = b"signed_bytes"
        packet = self._make_packet(BasicNH.SECURED_PACKET, payload)
        router.process_basic_header(packet)

        router.process_security_header.assert_called_once()
        args = router.process_security_header.call_args[0]
        self.assertEqual(args[0], payload)

    def test_security_enabled_drops_common_header(self):
        """NH=COMMON_HEADER must be silently dropped when itsGnSecurity=ENABLED."""
        from flexstack.geonet.mib import GnSecurity
        mib = MIB(itsGnSecurity=GnSecurity.ENABLED)
        router = Router(mib)
        router.process_common_header = Mock()

        packet = self._make_packet(BasicNH.COMMON_HEADER)
        router.process_basic_header(packet)

        router.process_common_header.assert_not_called()

    def test_security_enabled_accepts_secured_packet(self):
        """NH=SECURED_PACKET must still be forwarded when itsGnSecurity=ENABLED."""
        from flexstack.geonet.mib import GnSecurity
        mib = MIB(itsGnSecurity=GnSecurity.ENABLED)
        router = Router(mib)
        router.process_security_header = Mock()

        packet = self._make_packet(BasicNH.SECURED_PACKET, b"signed_bytes")
        router.process_basic_header(packet)

        router.process_security_header.assert_called_once()

    def test_wrong_version_raises(self):
        """A basic header with a version != itsGnProtocolVersion must raise."""
        mib = MIB()
        router = Router(mib)
        bh = BasicHeader(version=0)  # version 0 != default 1
        packet = bh.encode_to_bytes() + b"payload"
        with self.assertRaises(NotImplementedError):
            router.process_basic_header(packet)


class TestProcessCommonHeader(unittest.TestCase):
    """Unit tests for Router.process_common_header."""

    def _make_common_header_packet(
        self,
        ht: HeaderType,
        hst,
        rhl: int = 1,
        mhl: int = 1,
        payload: bytes = b"",
    ) -> tuple[CommonHeader, BasicHeader, bytes]:
        bh = BasicHeader(version=1, rhl=rhl)
        ch = CommonHeader(ht=ht, hst=hst, mhl=mhl)  # type: ignore
        return ch, bh, ch.encode_to_bytes() + payload

    def test_shb_dispatches_and_calls_callback(self):
        """TSB/SINGLE_HOP must call gn_data_indicate_shb and invoke the callback."""
        mib = MIB()
        router = Router(mib)
        router.gn_data_indicate_shb = Mock(return_value=GNDataIndication())
        callback = Mock()
        router.register_indication_callback(callback)

        ch, bh, packet = self._make_common_header_packet(
            HeaderType.TSB, TopoBroadcastHST.SINGLE_HOP, payload=bytes(28)
        )
        router.process_common_header(packet, bh)

        router.gn_data_indicate_shb.assert_called_once()
        callback.assert_called_once()

    def test_gbc_dispatches_and_calls_callback(self):
        """GEOBROADCAST must call gn_data_indicate_gbc and invoke the callback."""
        mib = MIB()
        router = Router(mib)
        router.gn_data_indicate_gbc = Mock(return_value=GNDataIndication())
        callback = Mock()
        router.register_indication_callback(callback)

        ch, bh, packet = self._make_common_header_packet(
            HeaderType.GEOBROADCAST, GeoBroadcastHST.GEOBROADCAST_CIRCLE, payload=bytes(
                44)
        )
        router.process_common_header(packet, bh)

        router.gn_data_indicate_gbc.assert_called_once()
        callback.assert_called_once()

    def test_beacon_dispatches_and_does_not_call_callback(self):
        """BEACON must call gn_data_indicate_beacon and must NOT invoke the callback."""
        mib = MIB()
        router = Router(mib)
        router.gn_data_indicate_beacon = Mock()
        callback = Mock()
        router.register_indication_callback(callback)

        ch, bh, packet = self._make_common_header_packet(
            HeaderType.BEACON, TopoBroadcastHST.SINGLE_HOP, payload=bytes(24)
        )
        router.process_common_header(packet, bh)

        router.gn_data_indicate_beacon.assert_called_once()
        callback.assert_not_called()

    def test_hop_limit_exceeded_raises(self):
        """RHL > MHL must raise DecapError."""
        from flexstack.geonet.exceptions import DecapError
        mib = MIB()
        router = Router(mib)

        ch, bh, packet = self._make_common_header_packet(
            HeaderType.TSB, TopoBroadcastHST.SINGLE_HOP, rhl=5, mhl=3
        )
        with self.assertRaises(DecapError):
            router.process_common_header(packet, bh)


class TestProcessSecurityHeader(unittest.TestCase):
    """Unit tests for Router.process_security_header."""

    def _make_basic_header(self) -> BasicHeader:
        return BasicHeader(version=1).set_nh(BasicNH.SECURED_PACKET)

    def test_no_verify_service_discards(self):
        """Without a VerifyService configured, the packet must be silently discarded."""
        mib = MIB()
        router = Router(mib)  # verify_service=None
        router.process_common_header = Mock()

        router.process_security_header(
            b"signed_data", self._make_basic_header())

        router.process_common_header.assert_not_called()

    def test_verification_failure_discards(self):
        """A failed verification result must not dispatch further."""
        mib = MIB()
        verify_service = MagicMock(spec=VerifyService)
        verify_service.verify.return_value = SNVERIFYConfirm(
            report=ReportVerify.FALSE_SIGNATURE,
            certificate_id=b"",
            its_aid=b"",
            its_aid_length=0,
            permissions=b"",
            plain_message=b"",
        )
        router = Router(mib, verify_service=verify_service)
        router.process_common_header = Mock()

        router.process_security_header(b"bad_data", self._make_basic_header())

        verify_service.verify.assert_called_once()
        router.process_common_header.assert_not_called()

    def test_verification_success_dispatches_to_process_common_header(self):
        """Successful verification must hand the plain_message to process_common_header."""
        mib = MIB()
        plain_message = bytes(8) + b"inner_payload"
        verify_service = MagicMock(spec=VerifyService)
        verify_service.verify.return_value = SNVERIFYConfirm(
            report=ReportVerify.SUCCESS,
            certificate_id=b"\x01\x02\x03\x04\x05\x06\x07\x08",
            its_aid=b"",
            its_aid_length=0,
            permissions=b"",
            plain_message=plain_message,
        )
        router = Router(mib, verify_service=verify_service)
        router.process_common_header = Mock()

        bh = self._make_basic_header()
        router.process_security_header(b"valid_data", bh)

        verify_service.verify.assert_called_once()
        router.process_common_header.assert_called_once_with(
            plain_message, bh.set_nh(BasicNH.COMMON_HEADER))


class TestGNDataIndicateTSB(unittest.TestCase):
    """Unit tests for Router.gn_data_indicate_tsb (\u00a710.3.9.3)."""

    def _build_tsb_payload(self, rhl: int = 3) -> tuple:
        """Return (basic_header, common_header, tsb_ext_header, upper_payload, raw_packet_after_common_header)."""
        from flexstack.geonet.tsb_extended_header import TSBExtendedHeader
        bh = BasicHeader(version=1, rhl=rhl)
        ch = CommonHeader(ht=HeaderType.TSB,
                          hst=TopoBroadcastHST.MULTI_HOP)  # type: ignore
        tsb = TSBExtendedHeader(sn=1, so_pv=LongPositionVector())
        payload = b"tsb_upper_payload"
        packet_after_common = tsb.encode() + payload
        return bh, ch, tsb, payload, packet_after_common

    def test_delivery_to_upper_entity(self):
        """Step 7: payload and correct indication fields must reach the callback."""
        mib = MIB()
        router = Router(mib)
        router.location_table.new_tsb_packet = Mock()
        router.duplicate_address_detection = Mock()
        callback = Mock()
        router.register_indication_callback(callback)

        bh, ch, tsb, payload, raw = self._build_tsb_payload()
        indication = router.gn_data_indicate_tsb(raw, ch, bh)

        self.assertEqual(indication.data, payload)
        self.assertEqual(indication.packet_transport_type.header_subtype,
                         TopoBroadcastHST.MULTI_HOP)
        router.duplicate_address_detection.assert_called_once()
        router.location_table.new_tsb_packet.assert_called_once()

    def test_forwarded_when_rhl_gt_1(self):
        """Steps 9+12: packet must be forwarded via LL when RHL > 1."""
        mib = MIB()
        router = Router(mib)
        router.location_table.new_tsb_packet = Mock()
        router.duplicate_address_detection = Mock()
        link_layer = Mock()
        router.link_layer = link_layer

        bh, ch, tsb, payload, raw = self._build_tsb_payload(rhl=3)
        router.gn_data_indicate_tsb(raw, ch, bh)

        link_layer.send.assert_called_once()
        # RHL in forwarded packet must be decremented to 2
        forwarded = link_layer.send.call_args[0][0]
        forwarded_bh = BasicHeader.decode_from_bytes(forwarded[0:4])
        self.assertEqual(forwarded_bh.rhl, 2)

    def test_not_forwarded_when_rhl_equals_1(self):
        """Step 9a: packet must NOT be forwarded when RHL decrements to 0."""
        mib = MIB()
        router = Router(mib)
        router.location_table.new_tsb_packet = Mock()
        router.duplicate_address_detection = Mock()
        link_layer = Mock()
        router.link_layer = link_layer

        bh, ch, tsb, payload, raw = self._build_tsb_payload(rhl=1)
        router.gn_data_indicate_tsb(raw, ch, bh)

        link_layer.send.assert_not_called()

    def test_indication_via_gn_data_indicate(self):
        """gn_data_indicate must dispatch MULTI_HOP TSB and invoke the callback."""
        mib = MIB()
        router = Router(mib)
        router.gn_data_indicate_tsb = Mock(return_value=GNDataIndication())
        callback = Mock()
        router.register_indication_callback(callback)

        from flexstack.geonet.tsb_extended_header import TSBExtendedHeader
        bh = BasicHeader(version=1)
        ch = CommonHeader(ht=HeaderType.TSB,
                          hst=TopoBroadcastHST.MULTI_HOP)  # type: ignore
        tsb = TSBExtendedHeader(sn=1)
        packet = bh.encode_to_bytes() + ch.encode_to_bytes() + tsb.encode() + b"data"

        router.gn_data_indicate(packet)

        router.gn_data_indicate_tsb.assert_called_once()
        callback.assert_called_once()

    def test_remaining_hop_limit_in_indication(self):
        """Table 32: remaining_hop_limit must equal the original RHL value."""
        mib = MIB()
        router = Router(mib)
        router.location_table.new_tsb_packet = Mock()
        router.duplicate_address_detection = Mock()

        bh, ch, tsb, payload, raw = self._build_tsb_payload(rhl=5)
        indication = router.gn_data_indicate_tsb(raw, ch, bh)

        self.assertEqual(indication.remaining_hop_limit, 5)


def _make_gn_addr() -> GNAddress:
    return GNAddress(m=M.GN_MULTICAST, st=ST.CYCLIST, mid=MID(b"\xaa\xbb\xcc\xdd\x22\x33"))


def _make_guc_packet(so_pv: LongPositionVector, de_addr: GNAddress,
                     rhl: int = 0, payload: bytes = b"guc_payload"):
    """Build a complete GUC wire packet (BH + CH + ext + payload). rhl=0 passes the mhl check."""
    de_pv = ShortPositionVector(gn_addr=de_addr)
    bh = BasicHeader(version=1, rhl=rhl)
    ch = CommonHeader(ht=HeaderType.GEOUNICAST)  # type: ignore
    guc = GUCExtendedHeader(sn=1, so_pv=so_pv, de_pv=de_pv)
    return bh.encode_to_bytes() + ch.encode_to_bytes() + guc.encode() + payload


class TestGNDataRequestGUC(unittest.TestCase):
    """Unit tests for Router.gn_data_request_guc (§10.3.8.2)."""

    def test_no_locte_returns_accepted(self):
        """When there is no LocTE for the destination the stub must return ACCEPTED."""
        mib = MIB()
        router = Router(mib)
        dest_addr = _make_gn_addr()
        request = GNDataRequest(
            packet_transport_type=PacketTransportType(
                header_type=HeaderType.GEOUNICAST),
            destination=dest_addr,
            data=b"hello",
        )
        confirm = router.gn_data_request(request)
        self.assertEqual(confirm.result_code, ResultCode.ACCEPTED)

    def test_sends_packet_when_locte_exists(self):
        """When a LocTE exists for the destination a GUC packet must be sent to the LL."""
        mib = MIB()
        router = Router(mib)
        dest_addr = _make_gn_addr()
        # Inject a fake LocTE for the destination
        de_lpv = LongPositionVector(
            gn_addr=dest_addr, latitude=100, longitude=200)
        fake_entry = Mock()
        fake_entry.position_vector = de_lpv
        router.location_table.get_entry = Mock(return_value=fake_entry)
        router.location_table.get_neighbours = Mock(return_value=[fake_entry])

        link_layer = Mock()
        router.link_layer = link_layer

        request = GNDataRequest(
            packet_transport_type=PacketTransportType(
                header_type=HeaderType.GEOUNICAST),
            destination=dest_addr,
            data=b"hello",
        )
        confirm = router.gn_data_request(request)

        self.assertEqual(confirm.result_code, ResultCode.ACCEPTED)
        link_layer.send.assert_called_once()

    def test_dispatched_via_gn_data_request(self):
        """gn_data_request must dispatch GEOUNICAST to gn_data_request_guc."""
        mib = MIB()
        router = Router(mib)
        router.gn_data_request_guc = Mock(
            return_value=GNDataConfirm(result_code=ResultCode.ACCEPTED))
        dest_addr = _make_gn_addr()
        request = GNDataRequest(
            packet_transport_type=PacketTransportType(
                header_type=HeaderType.GEOUNICAST),
            destination=dest_addr,
            data=b"hello",
        )
        router.gn_data_request(request)
        router.gn_data_request_guc.assert_called_once_with(request)


class TestGNDataIndicateGUC(unittest.TestCase):
    """Unit tests for Router.gn_data_indicate_guc (§10.3.8.3 / §10.3.8.4)."""

    def _build_guc_raw(self, so_pv: LongPositionVector, de_addr: GNAddress,
                       rhl: int = 3, payload: bytes = b"guc_payload"):
        """Return (bh, ch, guc_ext, payload, raw_after_common)."""
        de_pv = ShortPositionVector(gn_addr=de_addr)
        bh = BasicHeader(version=1, rhl=rhl)
        ch = CommonHeader(ht=HeaderType.GEOUNICAST)  # type: ignore
        guc = GUCExtendedHeader(sn=1, so_pv=so_pv, de_pv=de_pv)
        raw = guc.encode() + payload
        return bh, ch, guc, payload, raw

    def test_destination_delivery(self):
        """§10.3.8.4: when DE == self, payload must be delivered via GN-DATA.indication."""
        mib = MIB()
        router = Router(mib)
        router.duplicate_address_detection = Mock()
        router.location_table.new_guc_packet = Mock()

        so_pv = LongPositionVector(gn_addr=_make_gn_addr())
        de_addr = mib.itsGnLocalGnAddr  # self is the destination
        bh, ch, guc, payload, raw = self._build_guc_raw(so_pv, de_addr)

        indication = router.gn_data_indicate_guc(raw, ch, bh)

        self.assertEqual(indication.data, payload)
        self.assertEqual(
            indication.packet_transport_type.header_type, HeaderType.GEOUNICAST)
        router.duplicate_address_detection.assert_called_once()
        router.location_table.new_guc_packet.assert_called_once()

    def test_destination_not_forwarded(self):
        """§10.3.8.4: destination node must NOT forward the packet."""
        mib = MIB()
        router = Router(mib)
        router.duplicate_address_detection = Mock()
        router.location_table.new_guc_packet = Mock()
        link_layer = Mock()
        router.link_layer = link_layer

        so_pv = LongPositionVector(gn_addr=_make_gn_addr())
        de_addr = mib.itsGnLocalGnAddr
        bh, ch, guc, payload, raw = self._build_guc_raw(so_pv, de_addr)
        router.gn_data_indicate_guc(raw, ch, bh)

        link_layer.send.assert_not_called()

    def test_forwarder_forwards_with_decremented_rhl(self):
        """§10.3.8.3: forwarder must forward packet with RHL decremented by 1."""
        mib = MIB()
        router = Router(mib)
        router.duplicate_address_detection = Mock()
        router.location_table.new_guc_packet = Mock()
        link_layer = Mock()
        router.link_layer = link_layer

        so_pv = LongPositionVector(gn_addr=_make_gn_addr())
        de_addr = _make_gn_addr()  # different from self
        bh, ch, guc, payload, raw = self._build_guc_raw(so_pv, de_addr, rhl=3)
        router.gn_data_indicate_guc(raw, ch, bh)

        link_layer.send.assert_called_once()
        forwarded = link_layer.send.call_args[0][0]
        fwd_bh = BasicHeader.decode_from_bytes(forwarded[0:4])
        self.assertEqual(fwd_bh.rhl, 2)

    def test_forwarder_not_forwarded_when_rhl_1(self):
        """Step 9: packet must NOT be forwarded when RHL decrements to 0."""
        mib = MIB()
        router = Router(mib)
        router.duplicate_address_detection = Mock()
        router.location_table.new_guc_packet = Mock()
        link_layer = Mock()
        router.link_layer = link_layer

        so_pv = LongPositionVector(gn_addr=_make_gn_addr())
        de_addr = _make_gn_addr()
        bh, ch, guc, payload, raw = self._build_guc_raw(so_pv, de_addr, rhl=1)
        router.gn_data_indicate_guc(raw, ch, bh)

        link_layer.send.assert_not_called()

    def test_dispatched_via_gn_data_indicate(self):
        """gn_data_indicate must dispatch GEOUNICAST to gn_data_indicate_guc and invoke callback."""
        mib = MIB()
        router = Router(mib)
        router.gn_data_indicate_guc = Mock(return_value=GNDataIndication())
        callback = Mock()
        router.register_indication_callback(callback)

        so_pv = LongPositionVector(gn_addr=_make_gn_addr())
        de_addr = mib.itsGnLocalGnAddr
        packet = _make_guc_packet(so_pv, de_addr)
        router.gn_data_indicate(packet)

        router.gn_data_indicate_guc.assert_called_once()
        callback.assert_called_once()


# ---------------------------------------------------------------------------
# GAC helpers
# ---------------------------------------------------------------------------

def _make_gac_area(inside: bool) -> Area:
    """
    Return an Area whose centre is at lat=0, lon=0, radius a=100 m (circle).
    The ego position vector in Router defaults to lat=0, lon=0, so:
      inside=True  → ego is at the centre  → F ≥ 0
      inside=False → ego is at lat=10000000 (≈1°) → F < 0
    """
    return Area(latitude=0, longitude=0, a=100, b=100, angle=0)


def _make_gac_packet(so_pv: LongPositionVector, area: Area,
                     hst: GeoAnycastHST = GeoAnycastHST.GEOANYCAST_CIRCLE,
                     rhl: int = 0, payload: bytes = b"gac_payload") -> bytes:
    """Build a complete GAC wire packet (BH + CH + ext + payload). rhl=0 passes the mhl check."""
    bh = BasicHeader(version=1, rhl=rhl)
    ch = CommonHeader(ht=HeaderType.GEOANYCAST, hst=hst)  # type: ignore
    gbc = GBCExtendedHeader(
        sn=1, so_pv=so_pv,
        latitude=area.latitude, longitude=area.longitude,
        a=area.a, b=area.b, angle=area.angle,
    )
    return bh.encode_to_bytes() + ch.encode_to_bytes() + gbc.encode() + payload


class TestGNDataRequestGAC(unittest.TestCase):
    """Unit tests for Router.gn_data_request_gac (§10.3.12.2)."""

    def _make_request(self, inside: bool = True) -> GNDataRequest:
        area = _make_gac_area(inside)
        return GNDataRequest(
            packet_transport_type=PacketTransportType(
                header_type=HeaderType.GEOANYCAST,
                header_subtype=GeoAnycastHST.GEOANYCAST_CIRCLE,
            ),
            area=area,
            data=b"hello",
        )

    def test_dispatched_via_gn_data_request(self):
        """gn_data_request must dispatch GEOANYCAST to gn_data_request_gac."""
        mib = MIB()
        router = Router(mib)
        router.gn_data_request_gac = Mock(
            return_value=GNDataConfirm(result_code=ResultCode.ACCEPTED))
        request = self._make_request(inside=True)
        router.gn_data_request(request)
        router.gn_data_request_gac.assert_called_once_with(request)

    def test_sends_packet_when_inside_area(self):
        """Inside area: source must send the GAC packet to the LL."""
        mib = MIB()
        router = Router(mib)
        # Ego is at (0,0), area centred at (0,0) radius 100 m → inside
        router.ego_position_vector = LongPositionVector(
            latitude=0, longitude=0)
        link_layer = Mock()
        router.link_layer = link_layer

        confirm = router.gn_data_request_gac(self._make_request(inside=True))

        self.assertEqual(confirm.result_code, ResultCode.ACCEPTED)
        link_layer.send.assert_called_once()

    def test_sends_packet_when_outside_area(self):
        """Outside area: GF executes; no neighbours + SCF=False → BCAST fallback → LL send."""
        mib = MIB()
        router = Router(mib)
        # Move ego far outside the area
        router.ego_position_vector = LongPositionVector(
            latitude=100000000, longitude=100000000)
        link_layer = Mock()
        router.link_layer = link_layer

        confirm = router.gn_data_request_gac(self._make_request(inside=False))

        # §E.2: local optimum with SCF=False → BCAST fallback → packet is sent
        self.assertEqual(confirm.result_code, ResultCode.ACCEPTED)
        link_layer.send.assert_called_once()


class TestGNDataIndicateGAC(unittest.TestCase):
    """Unit tests for Router.gn_data_indicate_gac (§10.3.12.3)."""

    def _setup_router_inside(self):
        """Router ego placed inside the GAC area (lat=0, lon=0, area centred at 0,0 r=100m)."""
        mib = MIB()
        router = Router(mib)
        router.ego_position_vector = LongPositionVector(
            latitude=0, longitude=0)
        router.duplicate_address_detection = Mock()
        router.location_table.new_gac_packet = Mock()
        return router

    def _setup_router_outside(self):
        """Router ego placed outside the GAC area."""
        mib = MIB()
        router = Router(mib)
        router.ego_position_vector = LongPositionVector(
            latitude=100000000, longitude=100000000)
        router.duplicate_address_detection = Mock()
        router.location_table.new_gac_packet = Mock()
        return router

    def _base_gac_raw(self, so_pv, area, rhl=3, payload=b"gac_payload"):
        """Return (bh, ch, gbc_ext, payload, raw_after_common)."""
        bh = BasicHeader(version=1, rhl=rhl)
        ch = CommonHeader(ht=HeaderType.GEOANYCAST,
                          hst=GeoAnycastHST.GEOANYCAST_CIRCLE)  # type: ignore
        gbc = GBCExtendedHeader(
            sn=1, so_pv=so_pv,
            latitude=area.latitude, longitude=area.longitude,
            a=area.a, b=area.b, angle=area.angle,
        )
        raw = gbc.encode() + payload
        return bh, ch, gbc, payload, raw

    def test_inside_area_delivers_to_upper_entity(self):
        """§10.3.12.3 step 9a: inside area → payload delivered via GN-DATA.indication."""
        router = self._setup_router_inside()
        area = _make_gac_area(inside=True)
        so_pv = LongPositionVector(gn_addr=_make_gn_addr())
        bh, ch, gbc, payload, raw = self._base_gac_raw(so_pv, area)

        indication = router.gn_data_indicate_gac(raw, ch, bh)

        self.assertEqual(indication.data, payload)
        self.assertEqual(
            indication.packet_transport_type.header_type, HeaderType.GEOANYCAST)
        router.duplicate_address_detection.assert_called_once()
        router.location_table.new_gac_packet.assert_called_once()

    def test_inside_area_does_not_forward(self):
        """§10.3.12.3 step 9b: inside area → packet MUST NOT be forwarded (omit further steps)."""
        router = self._setup_router_inside()
        area = _make_gac_area(inside=True)
        so_pv = LongPositionVector(gn_addr=_make_gn_addr())
        link_layer = Mock()
        router.link_layer = link_layer
        bh, ch, gbc, payload, raw = self._base_gac_raw(so_pv, area, rhl=5)

        router.gn_data_indicate_gac(raw, ch, bh)

        link_layer.send.assert_not_called()

    def test_outside_area_forwards_with_decremented_rhl(self):
        """§10.3.12.3 step 10: outside area → packet forwarded with RHL decremented by 1."""
        router = self._setup_router_outside()
        # area at (0,0); ego is far away → outside
        area = _make_gac_area(inside=True)
        so_pv = LongPositionVector(gn_addr=_make_gn_addr())
        link_layer = Mock()
        router.link_layer = link_layer
        bh, ch, gbc, payload, raw = self._base_gac_raw(so_pv, area, rhl=3)

        router.gn_data_indicate_gac(raw, ch, bh)

        link_layer.send.assert_called_once()
        forwarded = link_layer.send.call_args[0][0]
        fwd_bh = BasicHeader.decode_from_bytes(forwarded[0:4])
        self.assertEqual(fwd_bh.rhl, 2)

    def test_outside_area_does_not_deliver_to_upper_entity(self):
        """§10.3.12.3 NOTE 2: outside area → payload must NOT reach upper layer."""
        router = self._setup_router_outside()
        area = _make_gac_area(inside=True)
        so_pv = LongPositionVector(gn_addr=_make_gn_addr())
        bh, ch, gbc, payload, raw = self._base_gac_raw(so_pv, area, rhl=3)

        indication = router.gn_data_indicate_gac(raw, ch, bh)

        # Outside → returns None (no upper-layer delivery)
        self.assertIsNone(indication)

    def test_outside_area_rhl_1_discards(self):
        """§10.3.12.3 step 10a(i): outside area with RHL=1 → discard (RHL decrements to 0)."""
        router = self._setup_router_outside()
        area = _make_gac_area(inside=True)
        so_pv = LongPositionVector(gn_addr=_make_gn_addr())
        link_layer = Mock()
        router.link_layer = link_layer
        bh, ch, gbc, payload, raw = self._base_gac_raw(so_pv, area, rhl=1)

        router.gn_data_indicate_gac(raw, ch, bh)

        link_layer.send.assert_not_called()

    def test_dispatched_via_gn_data_indicate(self):
        """gn_data_indicate must dispatch GEOANYCAST to gn_data_indicate_gac and invoke callback."""
        mib = MIB()
        router = Router(mib)
        router.gn_data_indicate_gac = Mock(return_value=GNDataIndication())
        callback = Mock()
        router.register_indication_callback(callback)

        area = _make_gac_area(inside=True)
        so_pv = LongPositionVector(gn_addr=_make_gn_addr())
        packet = _make_gac_packet(so_pv, area)
        router.gn_data_indicate(packet)

        router.gn_data_indicate_gac.assert_called_once()
        callback.assert_called_once()


# ---------------------------------------------------------------------------
# Helpers for LS tests
# ---------------------------------------------------------------------------

def _make_ls_request_packet(
    so_pv: LongPositionVector,
    request_gn_addr: GNAddress,
    rhl: int = 3,
    payload: bytes = b"",
) -> bytes:
    """Build a complete LS Request wire packet (BH + CH + ext)."""
    bh = BasicHeader(version=1, rhl=rhl)
    ch = CommonHeader(ht=HeaderType.LS,
                      hst=LocationServiceHST.LS_REQUEST)  # type: ignore
    ls_req = LSRequestExtendedHeader(
        sn=1, so_pv=so_pv, request_gn_addr=request_gn_addr)
    return bh.encode_to_bytes() + ch.encode_to_bytes() + ls_req.encode() + payload


def _make_ls_reply_packet(
    so_pv: LongPositionVector,
    de_pv: ShortPositionVector,
    rhl: int = 3,
    payload: bytes = b"",
) -> bytes:
    """Build a complete LS Reply wire packet (BH + CH + ext)."""
    bh = BasicHeader(version=1, rhl=rhl)
    ch = CommonHeader(ht=HeaderType.LS,
                      hst=LocationServiceHST.LS_REPLY)  # type: ignore
    ls_reply = LSReplyExtendedHeader(sn=2, so_pv=so_pv, de_pv=de_pv)
    return bh.encode_to_bytes() + ch.encode_to_bytes() + ls_reply.encode() + payload


class TestGNLSRequest(unittest.TestCase):
    """Unit tests for Router.gn_ls_request and Router._ls_retransmit (§10.3.7.1.2/3)."""

    def test_sends_ls_request_packet(self):
        """gn_ls_request must broadcast an LS Request packet via the link layer."""
        mib = MIB()
        router = Router(mib)
        link_layer = Mock()
        router.link_layer = link_layer
        sought = _make_gn_addr()

        router.gn_ls_request(sought)

        link_layer.send.assert_called_once()
        raw = link_layer.send.call_args[0][0]
        # Verify it is an LS Request packet
        ch = CommonHeader.decode_from_bytes(raw[4:12])
        self.assertEqual(ch.ht, HeaderType.LS)
        self.assertEqual(ch.hst, LocationServiceHST.LS_REQUEST)

    def test_sets_ls_pending(self):
        """gn_ls_request must set ls_pending=TRUE on the destination LocTE."""
        mib = MIB()
        router = Router(mib)
        sought = _make_gn_addr()

        router.gn_ls_request(sought)

        entry = router.location_table.get_entry(sought)
        self.assertIsNotNone(entry)
        self.assertTrue(entry.ls_pending)

    def test_buffers_request_when_ls_pending(self):
        """If ls_pending is already TRUE, gn_ls_request must buffer the new request and NOT resend."""
        mib = MIB()
        router = Router(mib)
        link_layer = Mock()
        router.link_layer = link_layer
        sought = _make_gn_addr()

        # First call starts LS
        router.gn_ls_request(sought)
        send_count = link_layer.send.call_count

        # Build a dummy buffered request
        extra_req = GNDataRequest(
            packet_transport_type=PacketTransportType(
                header_type=HeaderType.GEOUNICAST),
            destination=sought,
            data=b"extra",
        )
        # Second call while LS is pending: must NOT send another LS Request
        router.gn_ls_request(sought, extra_req)
        self.assertEqual(link_layer.send.call_count, send_count)
        # Buffer must contain the extra request
        self.assertIn(extra_req, router._ls_packet_buffers.get(sought, []))

    def test_retransmit_resends_and_increments_counter(self):
        """_ls_retransmit must resend the LS Request and increment the counter."""
        mib = MIB()
        router = Router(mib)
        link_layer = Mock()
        router.link_layer = link_layer
        sought = _make_gn_addr()

        router.gn_ls_request(sought)
        initial_count = link_layer.send.call_count

        # Fire retransmit directly (avoids actual timer sleep)
        router._ls_retransmit(sought)

        self.assertEqual(link_layer.send.call_count, initial_count + 1)
        self.assertEqual(router._ls_retransmit_counters.get(sought), 1)

    def test_retransmit_gives_up_at_max_retrans(self):
        """_ls_retransmit must stop and set ls_pending=FALSE when counter reaches maximum."""
        mib = MIB(itsGnLocationServiceMaxRetrans=2)
        router = Router(mib)
        link_layer = Mock()
        router.link_layer = link_layer
        sought = _make_gn_addr()

        router.gn_ls_request(sought)
        # Fire retransmit at the limit
        router._ls_retransmit_counters[sought] = mib.itsGnLocationServiceMaxRetrans
        count_before = link_layer.send.call_count
        router._ls_retransmit(sought)

        # No extra send should have happened
        self.assertEqual(link_layer.send.call_count, count_before)
        entry = router.location_table.get_entry(sought)
        self.assertIsNotNone(entry)
        self.assertFalse(entry.ls_pending)

    def test_no_locte_triggers_ls_via_gn_data_request_guc(self):
        """gn_data_request_guc must trigger gn_ls_request when no LocTE for destination exists."""
        mib = MIB()
        router = Router(mib)
        link_layer = Mock()
        router.link_layer = link_layer
        dest = _make_gn_addr()
        request = GNDataRequest(
            packet_transport_type=PacketTransportType(
                header_type=HeaderType.GEOUNICAST),
            destination=dest,
            data=b"hello",
        )
        confirm = router.gn_data_request(request)

        # Must return ACCEPTED and have sent an LS Request
        self.assertEqual(confirm.result_code, ResultCode.ACCEPTED)
        link_layer.send.assert_called_once()
        raw = link_layer.send.call_args[0][0]
        ch = CommonHeader.decode_from_bytes(raw[4:12])
        self.assertEqual(ch.ht, HeaderType.LS)


class TestGNDataIndicateLSRequest(unittest.TestCase):
    """Unit tests for Router.gn_data_indicate_ls_request (§10.3.7.2 / §10.3.7.3)."""

    def _build_packet_body(self, so_pv, request_gn_addr, payload=b""):
        """Return the bytes AFTER the common header (ext header + payload)."""
        ls_req = LSRequestExtendedHeader(
            sn=1, so_pv=so_pv, request_gn_addr=request_gn_addr)
        return ls_req.encode() + payload

    def test_forwarder_forwards_with_decremented_rhl(self):
        """§10.3.7.2: forwarder must re-broadcast LS Request with RHL decremented by 1."""
        mib = MIB()
        router = Router(mib)
        router.duplicate_address_detection = Mock()
        router.location_table.new_ls_request_packet = Mock()
        link_layer = Mock()
        router.link_layer = link_layer

        so_pv = LongPositionVector(gn_addr=_make_gn_addr())
        # request_gn_addr is NOT self → forwarder role
        request_gn_addr = _make_gn_addr()
        bh = BasicHeader(version=1, rhl=3)
        ch = CommonHeader(ht=HeaderType.LS,
                          hst=LocationServiceHST.LS_REQUEST)  # type: ignore
        body = self._build_packet_body(so_pv, request_gn_addr)

        router.gn_data_indicate_ls_request(body, ch, bh)

        link_layer.send.assert_called_once()
        forwarded = link_layer.send.call_args[0][0]
        fwd_bh = BasicHeader.decode_from_bytes(forwarded[0:4])
        self.assertEqual(fwd_bh.rhl, 2)

    def test_forwarder_rhl_1_discards(self):
        """§10.3.7.2: forwarder must discard packet when RHL decrements to 0."""
        mib = MIB()
        router = Router(mib)
        router.duplicate_address_detection = Mock()
        router.location_table.new_ls_request_packet = Mock()
        link_layer = Mock()
        router.link_layer = link_layer

        so_pv = LongPositionVector(gn_addr=_make_gn_addr())
        request_gn_addr = _make_gn_addr()
        bh = BasicHeader(version=1, rhl=1)
        ch = CommonHeader(ht=HeaderType.LS,
                          hst=LocationServiceHST.LS_REQUEST)  # type: ignore
        body = self._build_packet_body(so_pv, request_gn_addr)

        router.gn_data_indicate_ls_request(body, ch, bh)

        link_layer.send.assert_not_called()

    def test_destination_sends_ls_reply(self):
        """§10.3.7.3: destination (Request_GN_ADDR == own) must send an LS Reply."""
        mib = MIB()
        router = Router(mib)
        router.duplicate_address_detection = Mock()
        router.location_table.new_ls_request_packet = Mock()
        link_layer = Mock()
        router.link_layer = link_layer

        so_pv = LongPositionVector(gn_addr=_make_gn_addr())
        # Inject SO LocTE so the reply can find DE PV
        fake_so_entry = Mock()
        fake_so_entry.position_vector = so_pv
        router.location_table.get_entry = Mock(return_value=fake_so_entry)

        # request_gn_addr IS self
        request_gn_addr = mib.itsGnLocalGnAddr
        bh = BasicHeader(version=1, rhl=3)
        ch = CommonHeader(ht=HeaderType.LS,
                          hst=LocationServiceHST.LS_REQUEST)  # type: ignore
        body = self._build_packet_body(so_pv, request_gn_addr)

        router.gn_data_indicate_ls_request(body, ch, bh)

        link_layer.send.assert_called_once()
        reply_raw = link_layer.send.call_args[0][0]
        reply_ch = CommonHeader.decode_from_bytes(reply_raw[4:12])
        self.assertEqual(reply_ch.ht, HeaderType.LS)
        self.assertEqual(reply_ch.hst, LocationServiceHST.LS_REPLY)

    def test_destination_does_not_forward(self):
        """§10.3.7.3: after sending reply the destination must NOT re-broadcast the request."""
        mib = MIB()
        router = Router(mib)
        router.duplicate_address_detection = Mock()
        router.location_table.new_ls_request_packet = Mock()
        link_layer = Mock()
        router.link_layer = link_layer

        so_pv = LongPositionVector(gn_addr=_make_gn_addr())
        fake_so_entry = Mock()
        fake_so_entry.position_vector = so_pv
        router.location_table.get_entry = Mock(return_value=fake_so_entry)

        request_gn_addr = mib.itsGnLocalGnAddr
        bh = BasicHeader(version=1, rhl=3)
        ch = CommonHeader(ht=HeaderType.LS,
                          hst=LocationServiceHST.LS_REQUEST)  # type: ignore
        body = self._build_packet_body(so_pv, request_gn_addr)

        router.gn_data_indicate_ls_request(body, ch, bh)

        # Exactly ONE send (the LS Reply) – not forwarded
        link_layer.send.assert_called_once()

    def test_dispatched_via_gn_data_indicate(self):
        """process_common_header must dispatch HT=LS to gn_data_indicate_ls."""
        mib = MIB()
        router = Router(mib)
        router.gn_data_indicate_ls = Mock()

        so_pv = LongPositionVector(gn_addr=_make_gn_addr())
        raw = _make_ls_request_packet(so_pv, _make_gn_addr(), rhl=0)
        router.gn_data_indicate(raw)

        router.gn_data_indicate_ls.assert_called_once()


class TestGNDataIndicateLSReply(unittest.TestCase):
    """Unit tests for Router.gn_data_indicate_ls_reply (§10.3.7.1.4 / §10.3.7.2)."""

    def _build_packet_body(self, so_pv, de_pv, payload=b""):
        """Return the bytes AFTER the common header (ext header + payload)."""
        ls_reply = LSReplyExtendedHeader(sn=2, so_pv=so_pv, de_pv=de_pv)
        return ls_reply.encode() + payload

    def test_source_sets_ls_pending_false(self):
        """§10.3.7.1.4: source receiving reply must set ls_pending=FALSE."""
        mib = MIB()
        router = Router(mib)
        router.duplicate_address_detection = Mock()
        router.location_table.new_ls_reply_packet = Mock()

        so_addr = _make_gn_addr()
        so_pv = LongPositionVector(gn_addr=so_addr)
        de_pv = ShortPositionVector(gn_addr=mib.itsGnLocalGnAddr)

        # Simulate an ongoing LS for so_addr
        entry = router.location_table.ensure_entry(so_addr)
        entry.ls_pending = True
        router._ls_packet_buffers[so_addr] = []
        router._ls_retransmit_counters[so_addr] = 1

        bh = BasicHeader(version=1, rhl=3)
        ch = CommonHeader(ht=HeaderType.LS,
                          hst=LocationServiceHST.LS_REPLY)  # type: ignore
        body = self._build_packet_body(so_pv, de_pv)

        router.gn_data_indicate_ls_reply(body, ch, bh)

        self.assertFalse(entry.ls_pending)

    def test_source_flushes_buffered_requests(self):
        """§10.3.7.1.4 step 7: source must re-process buffered GNDataRequests after LS completes."""
        mib = MIB()
        router = Router(mib)
        router.duplicate_address_detection = Mock()
        router.location_table.new_ls_reply_packet = Mock()
        link_layer = Mock()
        router.link_layer = link_layer

        so_addr = _make_gn_addr()
        so_pv = LongPositionVector(gn_addr=so_addr)
        de_pv = ShortPositionVector(gn_addr=mib.itsGnLocalGnAddr)

        # Prepare a buffered request for so_addr
        buffered_req = GNDataRequest(
            packet_transport_type=PacketTransportType(
                header_type=HeaderType.GEOUNICAST),
            destination=so_addr,
            data=b"buffered",
        )
        entry = router.location_table.ensure_entry(so_addr)
        entry.ls_pending = True
        router._ls_packet_buffers[so_addr] = [buffered_req]
        router._ls_retransmit_counters[so_addr] = 0

        # Inject a LocTE with a real position vector so gn_data_request_guc can build GUC packet
        so_pv_full = LongPositionVector(
            gn_addr=so_addr, latitude=100, longitude=200)
        fake_entry = Mock()
        fake_entry.position_vector = so_pv_full
        router.location_table.get_entry = Mock(return_value=fake_entry)
        router.location_table.get_neighbours = Mock(return_value=[fake_entry])

        bh = BasicHeader(version=1, rhl=3)
        ch = CommonHeader(ht=HeaderType.LS,
                          hst=LocationServiceHST.LS_REPLY)  # type: ignore
        body = self._build_packet_body(so_pv, de_pv)

        router.gn_data_indicate_ls_reply(body, ch, bh)

        # link_layer.send is called once for the flushed GUC packet
        link_layer.send.assert_called_once()
        flushed_raw = link_layer.send.call_args[0][0]
        flushed_ch = CommonHeader.decode_from_bytes(flushed_raw[4:12])
        self.assertEqual(flushed_ch.ht, HeaderType.GEOUNICAST)

    def test_forwarder_forwards_with_decremented_rhl(self):
        """§10.3.7.2 forwarder: LS Reply must be forwarded with RHL decremented by 1."""
        mib = MIB()
        router = Router(mib)
        router.duplicate_address_detection = Mock()
        router.location_table.new_ls_reply_packet = Mock()
        link_layer = Mock()
        router.link_layer = link_layer

        so_addr = _make_gn_addr()
        so_pv = LongPositionVector(gn_addr=so_addr)
        # DE is NOT self → forwarder role
        de_addr = _make_gn_addr()
        de_pv = ShortPositionVector(gn_addr=de_addr)

        router.location_table.get_entry = Mock(
            return_value=None)  # DE not a neighbour

        bh = BasicHeader(version=1, rhl=3)
        ch = CommonHeader(ht=HeaderType.LS,
                          hst=LocationServiceHST.LS_REPLY)  # type: ignore
        body = self._build_packet_body(so_pv, de_pv)

        router.gn_data_indicate_ls_reply(body, ch, bh)

        link_layer.send.assert_called_once()
        forwarded = link_layer.send.call_args[0][0]
        fwd_bh = BasicHeader.decode_from_bytes(forwarded[0:4])
        self.assertEqual(fwd_bh.rhl, 2)

    def test_forwarder_rhl_1_discards(self):
        """§10.3.7.2 forwarder: LS Reply must be discarded when RHL decrements to 0."""
        mib = MIB()
        router = Router(mib)
        router.duplicate_address_detection = Mock()
        router.location_table.new_ls_reply_packet = Mock()
        link_layer = Mock()
        router.link_layer = link_layer

        so_addr = _make_gn_addr()
        so_pv = LongPositionVector(gn_addr=so_addr)
        de_addr = _make_gn_addr()
        de_pv = ShortPositionVector(gn_addr=de_addr)
        router.location_table.get_entry = Mock(return_value=None)

        bh = BasicHeader(version=1, rhl=1)
        ch = CommonHeader(ht=HeaderType.LS,
                          hst=LocationServiceHST.LS_REPLY)  # type: ignore
        body = self._build_packet_body(so_pv, de_pv)

        router.gn_data_indicate_ls_reply(body, ch, bh)

        link_layer.send.assert_not_called()

    def test_dispatched_via_gn_data_indicate(self):
        """process_common_header must dispatch HT=LS/HST=LS_REPLY to gn_data_indicate_ls."""
        mib = MIB()
        router = Router(mib)
        router.gn_data_indicate_ls = Mock()

        so_pv = LongPositionVector(gn_addr=_make_gn_addr())
        de_pv = ShortPositionVector(gn_addr=_make_gn_addr())
        raw = _make_ls_reply_packet(so_pv, de_pv, rhl=0)
        router.gn_data_indicate(raw)

        router.gn_data_indicate_ls.assert_called_once()


# ---------------------------------------------------------------------------
# Annex B – Packet data rate and geographical area size control
# ---------------------------------------------------------------------------

class TestAnnexB(unittest.TestCase):
    """Unit tests verifying compliance with ETSI EN 302 636-4-1 V1.4.1 Annex B."""

    # ── §B.3 _compute_area_size_m2 ──────────────────────────────────────────

    def test_compute_area_size_circle(self):
        """§B.3: Circle area = π × a²."""
        import math
        area = Area(a=1000, b=0, latitude=0, longitude=0, angle=0)
        result = Router._compute_area_size_m2(
            GeoBroadcastHST.GEOBROADCAST_CIRCLE, area)
        self.assertAlmostEqual(result, math.pi * 1000 ** 2, places=0)

    def test_compute_area_size_ellipse(self):
        """§B.3: Ellipse area = π × a × b."""
        import math
        area = Area(a=2000, b=500, latitude=0, longitude=0, angle=0)
        result = Router._compute_area_size_m2(
            GeoBroadcastHST.GEOBROADCAST_ELIP, area)
        self.assertAlmostEqual(result, math.pi * 2000 * 500, places=0)

    def test_compute_area_size_rect(self):
        """§B.3: Rectangle area = 4 × a × b (a, b are half-lengths from centre)."""
        area = Area(a=1000, b=500, latitude=0, longitude=0, angle=0)
        result = Router._compute_area_size_m2(
            GeoBroadcastHST.GEOBROADCAST_RECT, area)
        self.assertAlmostEqual(result, 4 * 1000 * 500, places=0)

    def test_compute_area_size_gac_circle(self):
        """§B.3: GAC circle variant also handled correctly."""
        import math
        area = Area(a=1000, b=0, latitude=0, longitude=0, angle=0)
        result = Router._compute_area_size_m2(
            GeoAnycastHST.GEOANYCAST_CIRCLE, area)
        self.assertAlmostEqual(result, math.pi * 1000 ** 2, places=0)

    # ── §B.3 GBC source ────────────────────────────────────────────────────

    def test_gbc_source_large_area_returns_geo_scope_too_large(self):
        """§B.3: gn_data_request_gbc must return GEOGRAPHICAL_SCOPE_TOO_LARGE for area > itsGnMaxGeoAreaSize."""
        mib = MIB()  # itsGnMaxGeoAreaSize = 10 km²
        router = Router(mib)
        # Circle with a=2000m → area ≈ 12.57 km² > 10 km²
        request = GNDataRequest(
            packet_transport_type=PacketTransportType(
                header_type=HeaderType.GEOBROADCAST,
                header_subtype=GeoBroadcastHST.GEOBROADCAST_CIRCLE,
            ),
            area=Area(a=2000, b=0, latitude=0, longitude=0, angle=0),
            data=b"hello",
        )
        confirm = router.gn_data_request_gbc(request)
        self.assertEqual(confirm.result_code,
                         ResultCode.GEOGRAPHICAL_SCOPE_TOO_LARGE)

    def test_gbc_source_small_area_not_rejected(self):
        """§B.3: gn_data_request_gbc must NOT reject when area ≤ itsGnMaxGeoAreaSize."""
        mib = MIB()
        router = Router(mib)
        router.link_layer = Mock()
        router.gn_forwarding_algorithm_selection = Mock(
            return_value=GNForwardingAlgorithmResponse.AREA_FORWARDING)
        # Circle with a=100m → area ≈ 31,416 m² < 10 km²
        request = GNDataRequest(
            packet_transport_type=PacketTransportType(
                header_type=HeaderType.GEOBROADCAST,
                header_subtype=GeoBroadcastHST.GEOBROADCAST_CIRCLE,
            ),
            area=Area(a=100, b=100, latitude=0, longitude=0, angle=0),
            data=b"hello",
        )
        confirm = router.gn_data_request_gbc(request)
        self.assertEqual(confirm.result_code, ResultCode.ACCEPTED)

    def test_gac_source_large_area_returns_geo_scope_too_large(self):
        """§B.3: gn_data_request_gac must also reject oversized areas (delegates to gn_data_request_gbc)."""
        mib = MIB()
        router = Router(mib)
        request = GNDataRequest(
            packet_transport_type=PacketTransportType(
                header_type=HeaderType.GEOANYCAST,
                header_subtype=GeoAnycastHST.GEOANYCAST_CIRCLE,
            ),
            area=Area(a=2000, b=0, latitude=0, longitude=0, angle=0),
            data=b"hello",
        )
        confirm = router.gn_data_request_gac(request)
        self.assertEqual(confirm.result_code,
                         ResultCode.GEOGRAPHICAL_SCOPE_TOO_LARGE)

    # ── §B.3 GBC forwarder ─────────────────────────────────────────────────

    def test_gbc_forwarder_large_area_not_forwarded_but_delivered_inside(self):
        """§B.3: Forwarder must NOT forward a GBC with oversized area, but MUST deliver if inside."""
        mib = MIB()
        router = Router(mib)
        router.ego_position_vector = LongPositionVector(
            latitude=0, longitude=0)
        router.duplicate_address_detection = Mock()
        router.location_table.new_gbc_packet = Mock()
        router.location_table.get_entry = Mock(return_value=None)
        link_layer = Mock()
        router.link_layer = link_layer

        so_pv = LongPositionVector(gn_addr=_make_gn_addr())
        # Circle a=2000m → area > 10 km²; centred at (0,0), ego at (0,0) → inside
        gbc = GBCExtendedHeader(
            sn=1, so_pv=so_pv, latitude=0, longitude=0, a=2000, b=0)
        bh = BasicHeader(version=1, rhl=3)
        ch = CommonHeader(ht=HeaderType.GEOBROADCAST,
                          hst=GeoBroadcastHST.GEOBROADCAST_CIRCLE)  # type: ignore
        raw = gbc.encode() + b"payload"

        indication = router.gn_data_indicate_gbc(raw, ch, bh)

        link_layer.send.assert_not_called()
        self.assertEqual(indication.data, b"payload")

    def test_gbc_forwarder_large_area_not_forwarded_outside(self):
        """§B.3: Forwarder must NOT forward a GBC with oversized area even when outside."""
        mib = MIB()
        router = Router(mib)
        router.ego_position_vector = LongPositionVector(
            latitude=100000000, longitude=100000000)
        router.duplicate_address_detection = Mock()
        router.location_table.new_gbc_packet = Mock()
        router.location_table.get_entry = Mock(return_value=None)
        link_layer = Mock()
        router.link_layer = link_layer

        so_pv = LongPositionVector(gn_addr=_make_gn_addr())
        gbc = GBCExtendedHeader(
            sn=1, so_pv=so_pv, latitude=0, longitude=0, a=2000, b=0)
        bh = BasicHeader(version=1, rhl=3)
        ch = CommonHeader(ht=HeaderType.GEOBROADCAST,
                          hst=GeoBroadcastHST.GEOBROADCAST_CIRCLE)  # type: ignore
        raw = gbc.encode() + b"payload"

        indication = router.gn_data_indicate_gbc(raw, ch, bh)

        link_layer.send.assert_not_called()
        # Outside area → no upper-layer delivery
        self.assertIsNone(indication)

    # ── §B.3 GAC forwarder ─────────────────────────────────────────────────

    def test_gac_forwarder_large_area_not_forwarded(self):
        """§B.3: Forwarder must NOT forward a GAC with oversized area when outside."""
        mib = MIB()
        router = Router(mib)
        router.ego_position_vector = LongPositionVector(
            latitude=100000000, longitude=100000000)
        router.duplicate_address_detection = Mock()
        router.location_table.new_gac_packet = Mock()
        router.location_table.get_entry = Mock(return_value=None)
        link_layer = Mock()
        router.link_layer = link_layer

        so_pv = LongPositionVector(gn_addr=_make_gn_addr())
        gbc = GBCExtendedHeader(
            sn=1, so_pv=so_pv, latitude=0, longitude=0, a=2000, b=0)
        bh = BasicHeader(version=1, rhl=3)
        ch = CommonHeader(ht=HeaderType.GEOANYCAST,
                          hst=GeoAnycastHST.GEOANYCAST_CIRCLE)  # type: ignore
        raw = gbc.encode() + b"payload"

        router.gn_data_indicate_gac(raw, ch, bh)

        link_layer.send.assert_not_called()

    # ── §B.2 PDR enforcement – GBC ─────────────────────────────────────────

    def _make_high_pdr_entry(self, mib: MIB):
        """Return a Mock LocTE with PDR above itsGnMaxPacketDataRate (100 kB/s = 100,000 bytes/s)."""
        entry = Mock()
        entry.pdr = mib.itsGnMaxPacketDataRate * 1000 + 1  # just above threshold
        return entry

    def test_gbc_pdr_exceeded_not_forwarded_but_delivered_inside(self):
        """§B.2: GBC inside area must still be delivered to upper entity even when SO PDR exceeded."""
        mib = MIB()
        router = Router(mib)
        router.ego_position_vector = LongPositionVector(
            latitude=0, longitude=0)
        router.duplicate_address_detection = Mock()
        router.location_table.new_gbc_packet = Mock()
        router.location_table.get_entry = Mock(
            return_value=self._make_high_pdr_entry(mib))
        link_layer = Mock()
        router.link_layer = link_layer

        so_pv = LongPositionVector(gn_addr=_make_gn_addr())
        gbc = GBCExtendedHeader(
            sn=1, so_pv=so_pv, latitude=0, longitude=0, a=100, b=100)
        bh = BasicHeader(version=1, rhl=3)
        ch = CommonHeader(ht=HeaderType.GEOBROADCAST,
                          hst=GeoBroadcastHST.GEOBROADCAST_CIRCLE)  # type: ignore
        raw = gbc.encode() + b"payload"

        indication = router.gn_data_indicate_gbc(raw, ch, bh)

        link_layer.send.assert_not_called()
        self.assertEqual(indication.data, b"payload")

    def test_gbc_pdr_ok_forwarded(self):
        """§B.2: GBC must be forwarded when SO PDR is within limit."""
        mib = MIB()
        router = Router(mib)
        router.ego_position_vector = LongPositionVector(
            latitude=0, longitude=0)
        router.duplicate_address_detection = Mock()
        router.location_table.new_gbc_packet = Mock()
        entry = Mock()
        entry.pdr = 0  # well below threshold
        router.location_table.get_entry = Mock(return_value=entry)
        router.gn_data_forward_gbc = Mock()

        so_pv = LongPositionVector(gn_addr=_make_gn_addr())
        gbc = GBCExtendedHeader(
            sn=1, so_pv=so_pv, latitude=0, longitude=0, a=100, b=100)
        bh = BasicHeader(version=1, rhl=3)
        ch = CommonHeader(ht=HeaderType.GEOBROADCAST,
                          hst=GeoBroadcastHST.GEOBROADCAST_CIRCLE)  # type: ignore
        raw = gbc.encode() + b"payload"

        router.gn_data_indicate_gbc(raw, ch, bh)

        router.gn_data_forward_gbc.assert_called_once()

    # ── §B.2 PDR enforcement – GAC ─────────────────────────────────────────

    def test_gac_pdr_exceeded_not_forwarded(self):
        """§B.2: GAC outside area must NOT be forwarded when SO PDR exceeded."""
        mib = MIB()
        router = Router(mib)
        router.ego_position_vector = LongPositionVector(
            latitude=100000000, longitude=100000000)
        router.duplicate_address_detection = Mock()
        router.location_table.new_gac_packet = Mock()
        router.location_table.get_entry = Mock(
            return_value=self._make_high_pdr_entry(mib))
        link_layer = Mock()
        router.link_layer = link_layer

        so_pv = LongPositionVector(gn_addr=_make_gn_addr())
        gbc = GBCExtendedHeader(
            sn=1, so_pv=so_pv, latitude=0, longitude=0, a=100, b=100)
        bh = BasicHeader(version=1, rhl=3)
        ch = CommonHeader(ht=HeaderType.GEOANYCAST,
                          hst=GeoAnycastHST.GEOANYCAST_CIRCLE)  # type: ignore
        raw = gbc.encode() + b"payload"

        router.gn_data_indicate_gac(raw, ch, bh)

        link_layer.send.assert_not_called()

    # ── §B.2 PDR enforcement – GUC ─────────────────────────────────────────

    def test_guc_pdr_exceeded_not_forwarded(self):
        """§B.2: GUC forwarder must NOT forward when SO PDR exceeded."""
        mib = MIB()
        router = Router(mib)
        router.duplicate_address_detection = Mock()
        router.location_table.new_guc_packet = Mock()
        router.location_table.get_entry = Mock(
            return_value=self._make_high_pdr_entry(mib))
        link_layer = Mock()
        router.link_layer = link_layer

        so_addr = _make_gn_addr()
        so_pv = LongPositionVector(gn_addr=so_addr)
        de_addr = _make_gn_addr()  # not self → forwarder role
        raw = _make_guc_packet(so_pv, de_addr)
        bh = BasicHeader.decode_from_bytes(raw[0:4])
        ch = CommonHeader.decode_from_bytes(raw[4:12])
        body = raw[12:]

        router.gn_data_indicate_guc(body, ch, bh)

        link_layer.send.assert_not_called()

    # ── §B.2 PDR enforcement – TSB ─────────────────────────────────────────

    def test_tsb_pdr_exceeded_not_forwarded(self):
        """§B.2: TSB must NOT be forwarded when SO PDR exceeded."""
        from flexstack.geonet.tsb_extended_header import TSBExtendedHeader
        mib = MIB()
        router = Router(mib)
        router.duplicate_address_detection = Mock()
        router.location_table.new_tsb_packet = Mock()
        router.location_table.get_entry = Mock(
            return_value=self._make_high_pdr_entry(mib))
        link_layer = Mock()
        router.link_layer = link_layer

        so_pv = LongPositionVector(gn_addr=_make_gn_addr())
        tsb = TSBExtendedHeader(sn=1, so_pv=so_pv)
        bh = BasicHeader(version=1, rhl=3)
        ch = CommonHeader(ht=HeaderType.TSB,
                          hst=TopoBroadcastHST.MULTI_HOP)  # type: ignore
        raw = tsb.encode() + b"payload"

        router.gn_data_indicate_tsb(raw, ch, bh)

        link_layer.send.assert_not_called()

    def test_tsb_pdr_exceeded_still_delivered(self):
        """§B.2: TSB payload must still be delivered to upper entity even when PDR exceeded."""
        from flexstack.geonet.tsb_extended_header import TSBExtendedHeader
        mib = MIB()
        router = Router(mib)
        router.duplicate_address_detection = Mock()
        router.location_table.new_tsb_packet = Mock()
        router.location_table.get_entry = Mock(
            return_value=self._make_high_pdr_entry(mib))

        so_pv = LongPositionVector(gn_addr=_make_gn_addr())
        tsb = TSBExtendedHeader(sn=1, so_pv=so_pv)
        bh = BasicHeader(version=1, rhl=3)
        ch = CommonHeader(ht=HeaderType.TSB,
                          hst=TopoBroadcastHST.MULTI_HOP)  # type: ignore
        raw = tsb.encode() + b"payload"

        indication = router.gn_data_indicate_tsb(raw, ch, bh)

        self.assertEqual(indication.data, b"payload")


# ---------------------------------------------------------------------------
# Annex C – Position vector update in forwarded packets
# ---------------------------------------------------------------------------

class TestAnnexC(unittest.TestCase):
    """Unit tests verifying compliance with ETSI EN 302 636-4-1 V1.4.1 Annex C.3."""

    _TIMESTAMP = 1675071608.0

    def _make_de_entry(self, mib: MIB, tst_seconds: float) -> Mock:
        """Return a Mock LocTE entry that is a neighbour, with a given LPV timestamp."""
        de_addr = GNAddress(m=M.GN_MULTICAST, st=ST.CYCLIST,
                            mid=MID(b"\xbb\xcc\xdd\xee\x11\x22"))
        de_lpv = LongPositionVector(
            gn_addr=de_addr, latitude=111111, longitude=222222
        ).set_tst_in_normal_timestamp_seconds(tst_seconds)
        entry = Mock()
        entry.is_neighbour = True
        entry.position_vector = de_lpv
        entry.pdr = 0.0
        return entry, de_addr

    def _build_guc_raw_with_tst(self, so_pv, de_addr, de_tst_seconds, rhl=3):
        """Build a GUC raw packet where the DE PV has a specific TST."""
        de_spv = ShortPositionVector(
            gn_addr=de_addr
        ).set_tst_in_normal_timestamp_seconds(de_tst_seconds)
        bh = BasicHeader(version=1, rhl=rhl)
        ch = CommonHeader(ht=HeaderType.GEOUNICAST)  # type: ignore
        guc = GUCExtendedHeader(sn=1, so_pv=so_pv, de_pv=de_spv)
        raw = guc.encode() + b"guc_payload"
        return bh, ch, guc, raw

    def _build_ls_reply_raw_with_tst(self, so_pv, de_addr, de_tst_seconds, rhl=3):
        """Build an LS Reply packet where the DE PV has a specific TST."""
        de_spv = ShortPositionVector(
            gn_addr=de_addr
        ).set_tst_in_normal_timestamp_seconds(de_tst_seconds)
        bh = BasicHeader(version=1, rhl=rhl)
        ch = CommonHeader(ht=HeaderType.LS,
                          hst=LocationServiceHST.LS_REPLY)  # type: ignore
        ls_reply = LSReplyExtendedHeader(sn=2, so_pv=so_pv, de_pv=de_spv)
        raw = ls_reply.encode() + b"ls_payload"
        return bh, ch, ls_reply, raw

    # ── §C.3 GUC forwarder ──────────────────────────────────────────────────

    def test_guc_forwarder_de_pv_updated_when_loct_is_newer(self):
        """§C.3: GUC forwarder must update DE PV when LocT TST is strictly newer."""
        mib = MIB()
        router = Router(mib)
        router.duplicate_address_detection = Mock()
        router.location_table.new_guc_packet = Mock()
        link_layer = Mock()
        router.link_layer = link_layer

        so_pv = LongPositionVector(gn_addr=_make_gn_addr()).set_tst_in_normal_timestamp_seconds(
            self._TIMESTAMP)

        # DE is a neighbour with LocT TST = TIMESTAMP + 1 (newer than packet's DE PV)
        de_entry, de_addr = self._make_de_entry(mib, self._TIMESTAMP + 1.0)
        # LocT entry for SO (get_entry called for SO in PDR check, then for DE in C.3)

        def mock_get_entry(addr):
            if addr == de_addr:
                return de_entry
            return None
        router.location_table.get_entry = Mock(side_effect=mock_get_entry)

        # Packet DE PV has older TST = TIMESTAMP
        bh, ch, guc, raw = self._build_guc_raw_with_tst(
            so_pv, de_addr, self._TIMESTAMP)
        router.gn_data_indicate_guc(raw, ch, bh)

        link_layer.send.assert_called_once()
        forwarded = link_layer.send.call_args[0][0]
        # Decode the forwarded GUC header to check DE PV was refreshed
        from flexstack.geonet.guc_extended_header import GUCExtendedHeader as GUCHdr
        fwd_guc = GUCHdr.decode(forwarded[12:])
        # DE PV TST must now match LocT TST (TIMESTAMP + 1)
        from flexstack.geonet.position_vector import TST
        expected_tst = TST().set_in_normal_timestamp_seconds(self._TIMESTAMP + 1.0)
        self.assertEqual(fwd_guc.de_pv.tst, expected_tst)

    def test_guc_forwarder_de_pv_not_updated_when_loct_is_older(self):
        """§C.3 ELSE: GUC forwarder must NOT update DE PV when LocT TST is not newer."""
        mib = MIB()
        router = Router(mib)
        router.duplicate_address_detection = Mock()
        router.location_table.new_guc_packet = Mock()
        link_layer = Mock()
        router.link_layer = link_layer

        so_pv = LongPositionVector(gn_addr=_make_gn_addr()).set_tst_in_normal_timestamp_seconds(
            self._TIMESTAMP)

        # DE is a neighbour with LocT TST = TIMESTAMP (same, not newer than packet's DE PV)
        de_entry, de_addr = self._make_de_entry(mib, self._TIMESTAMP)

        def mock_get_entry(addr):
            if addr == de_addr:
                return de_entry
            return None
        router.location_table.get_entry = Mock(side_effect=mock_get_entry)

        # Packet DE PV has the same TST = TIMESTAMP (LocT is not strictly newer)
        bh, ch, guc, raw = self._build_guc_raw_with_tst(
            so_pv, de_addr, self._TIMESTAMP)
        router.gn_data_indicate_guc(raw, ch, bh)

        link_layer.send.assert_called_once()
        forwarded = link_layer.send.call_args[0][0]
        from flexstack.geonet.guc_extended_header import GUCExtendedHeader as GUCHdr
        fwd_guc = GUCHdr.decode(forwarded[12:])
        # DE PV TST must remain as in the original packet
        from flexstack.geonet.position_vector import TST
        expected_tst = TST().set_in_normal_timestamp_seconds(self._TIMESTAMP)
        self.assertEqual(fwd_guc.de_pv.tst, expected_tst)
        # Coordinates must also be unchanged (original packet has lat=0, lon=0)
        self.assertEqual(fwd_guc.de_pv.latitude, 0)
        self.assertEqual(fwd_guc.de_pv.longitude, 0)

    # ── §C.3 LS Reply forwarder ─────────────────────────────────────────────

    def test_ls_reply_forwarder_de_pv_updated_when_loct_is_newer(self):
        """§C.3: LS Reply forwarder must update DE PV when LocT TST is strictly newer."""
        mib = MIB()
        router = Router(mib)
        router.duplicate_address_detection = Mock()
        router.location_table.new_ls_reply_packet = Mock()
        link_layer = Mock()
        router.link_layer = link_layer

        so_pv = LongPositionVector(gn_addr=_make_gn_addr()).set_tst_in_normal_timestamp_seconds(
            self._TIMESTAMP)

        # DE is a neighbour with LocT TST = TIMESTAMP + 1 (newer)
        de_entry, de_addr = self._make_de_entry(mib, self._TIMESTAMP + 1.0)

        def mock_get_entry(addr):
            if addr == de_addr:
                return de_entry
            return None
        router.location_table.get_entry = Mock(side_effect=mock_get_entry)

        bh, ch, ls_reply, raw = self._build_ls_reply_raw_with_tst(
            so_pv, de_addr, self._TIMESTAMP)
        router.gn_data_indicate_ls_reply(raw, ch, bh)

        link_layer.send.assert_called_once()
        forwarded = link_layer.send.call_args[0][0]
        fwd_ls = LSReplyExtendedHeader.decode(forwarded[12:])
        from flexstack.geonet.position_vector import TST
        expected_tst = TST().set_in_normal_timestamp_seconds(self._TIMESTAMP + 1.0)
        self.assertEqual(fwd_ls.de_pv.tst, expected_tst)

    def test_ls_reply_forwarder_de_pv_not_updated_when_loct_is_older(self):
        """§C.3 ELSE: LS Reply forwarder must NOT update DE PV when LocT TST is not newer."""
        mib = MIB()
        router = Router(mib)
        router.duplicate_address_detection = Mock()
        router.location_table.new_ls_reply_packet = Mock()
        link_layer = Mock()
        router.link_layer = link_layer

        so_pv = LongPositionVector(gn_addr=_make_gn_addr()).set_tst_in_normal_timestamp_seconds(
            self._TIMESTAMP)

        # DE is a neighbour with LocT TST = TIMESTAMP (not newer than packet)
        de_entry, de_addr = self._make_de_entry(mib, self._TIMESTAMP)

        def mock_get_entry(addr):
            if addr == de_addr:
                return de_entry
            return None
        router.location_table.get_entry = Mock(side_effect=mock_get_entry)

        bh, ch, ls_reply, raw = self._build_ls_reply_raw_with_tst(
            so_pv, de_addr, self._TIMESTAMP)
        router.gn_data_indicate_ls_reply(raw, ch, bh)

        link_layer.send.assert_called_once()
        forwarded = link_layer.send.call_args[0][0]
        fwd_ls = LSReplyExtendedHeader.decode(forwarded[12:])
        from flexstack.geonet.position_vector import TST
        expected_tst = TST().set_in_normal_timestamp_seconds(self._TIMESTAMP)
        self.assertEqual(fwd_ls.de_pv.tst, expected_tst)
        self.assertEqual(fwd_ls.de_pv.latitude, 0)
        self.assertEqual(fwd_ls.de_pv.longitude, 0)


# ---------------------------------------------------------------------------
# Annex D – GeoNetworking forwarding algorithm selection procedure
# ---------------------------------------------------------------------------

class TestAnnexD(unittest.TestCase):
    """Unit tests verifying compliance with ETSI EN 302 636-4-1 V1.4.1 Annex D."""

    # Area centred at (421255850, 27601710) with a = b = 100 m
    _AREA = Area(latitude=421255850, longitude=27601710, a=100, b=100, angle=0)
    # Ego positions (1/10 micro-degree)
    _LAT_INSIDE = 421255850   # at area centre → F = 1
    _LON_INSIDE = 27601710
    _LAT_OUTSIDE = 421236840  # far outside → F << 0
    _LON_OUTSIDE = 27632710

    def _make_request(self) -> GNDataRequest:
        return GNDataRequest(
            packet_transport_type=PacketTransportType(
                header_type=HeaderType.GEOBROADCAST,
                header_subtype=GeoBroadcastHST.GEOBROADCAST_CIRCLE,
            ),
            area=self._AREA,
        )

    def _make_router_outside(self) -> Router:
        mib = MIB()
        router = Router(mib)
        router.ego_position_vector = LongPositionVector(
            latitude=self._LAT_OUTSIDE, longitude=self._LON_OUTSIDE)
        return router

    # ── §D.1 F(x,y) for rectangle ───────────────────────────────────────────

    def test_rect_f_at_centre_is_one(self):
        """§D / EN 302 931: F(0, 0) for rectangle must equal 1 (at centre)."""
        mib = MIB()
        router = Router(mib)
        result = router.gn_geometric_function_f(
            GeoBroadcastHST.GEOBROADCAST_RECT, self._AREA,
            self._LAT_INSIDE, self._LON_INSIDE,
        )
        self.assertAlmostEqual(result, 1.0)

    def test_rect_f_outside_on_y_axis_is_negative(self):
        """§D / EN 302 931: F(x≈0, y>>b) for rectangle must be negative (outside)."""
        mib = MIB()
        router = Router(mib)
        # Same latitude as centre (x≈0) but longitude far away (|y| >> b=100m)
        result = router.gn_geometric_function_f(
            GeoBroadcastHST.GEOBROADCAST_RECT, self._AREA,
            self._LAT_INSIDE, self._LON_OUTSIDE,
        )
        self.assertLess(result, 0)

    # ── §D.2 gn_forwarding_algorithm_selection ──────────────────────────────

    def test_ego_inside_returns_area_forwarding(self):
        """§D step 9: ego inside/at border → AREA_FORWARDING."""
        mib = MIB()
        router = Router(mib)
        router.ego_position_vector = LongPositionVector(
            latitude=self._LAT_INSIDE, longitude=self._LON_INSIDE)
        result = router.gn_forwarding_algorithm_selection(self._make_request())
        self.assertEqual(result, GNForwardingAlgorithmResponse.AREA_FORWARDING)

    def test_ego_outside_no_sender_returns_non_area_forwarding(self):
        """§D ELSE, no sender (source op): SE_POS_VALID = False → NON_AREA_FORWARDING."""
        router = self._make_router_outside()
        result = router.gn_forwarding_algorithm_selection(self._make_request())
        self.assertEqual(
            result, GNForwardingAlgorithmResponse.NON_AREA_FORWARDING)

    def test_ego_outside_sender_outside_pai_true_returns_non_area_forwarding(self):
        """§D ELSE: sender outside area, PAI=True → F_SE < 0 → NON_AREA_FORWARDING."""
        router = self._make_router_outside()
        sender_addr = _make_gn_addr()
        se_entry = router.location_table.ensure_entry(sender_addr)
        se_pv = LongPositionVector(
            gn_addr=sender_addr, pai=True,
            latitude=self._LAT_OUTSIDE, longitude=self._LON_OUTSIDE,
        )
        se_entry.update_position_vector(se_pv)

        result = router.gn_forwarding_algorithm_selection(
            self._make_request(), sender_gn_addr=sender_addr)
        self.assertEqual(
            result, GNForwardingAlgorithmResponse.NON_AREA_FORWARDING)

    def test_ego_outside_sender_inside_pai_true_returns_discarted(self):
        """§D ELSE: sender inside area, PAI=True → SE_POS_VALID AND F_SE ≥ 0 → DISCARTED."""
        router = self._make_router_outside()
        sender_addr = _make_gn_addr()
        se_entry = router.location_table.ensure_entry(sender_addr)
        se_pv = LongPositionVector(
            gn_addr=sender_addr, pai=True,
            latitude=self._LAT_INSIDE, longitude=self._LON_INSIDE,
        )
        se_entry.update_position_vector(se_pv)

        result = router.gn_forwarding_algorithm_selection(
            self._make_request(), sender_gn_addr=sender_addr)
        self.assertEqual(result, GNForwardingAlgorithmResponse.DISCARTED)

    def test_ego_outside_sender_inside_pai_false_returns_non_area_forwarding(self):
        """§D ELSE: sender inside area but PAI=False → SE_POS_VALID=False → NON_AREA_FORWARDING."""
        router = self._make_router_outside()
        sender_addr = _make_gn_addr()
        se_entry = router.location_table.ensure_entry(sender_addr)
        se_pv = LongPositionVector(
            gn_addr=sender_addr, pai=False,
            latitude=self._LAT_INSIDE, longitude=self._LON_INSIDE,
        )
        se_entry.update_position_vector(se_pv)

        result = router.gn_forwarding_algorithm_selection(
            self._make_request(), sender_gn_addr=sender_addr)
        self.assertEqual(
            result, GNForwardingAlgorithmResponse.NON_AREA_FORWARDING)

    def test_ego_outside_sender_not_in_loct_returns_non_area_forwarding(self):
        """§D ELSE: sender not in LocT → PV_SE not found → SE_POS_VALID=False → NON_AREA_FORWARDING."""
        router = self._make_router_outside()
        unknown_addr = GNAddress(m=M.GN_MULTICAST, st=ST.CYCLIST,
                                 mid=MID(b"\xff\xff\xff\xff\xff\xff"))
        result = router.gn_forwarding_algorithm_selection(
            self._make_request(), sender_gn_addr=unknown_addr)
        self.assertEqual(
            result, GNForwardingAlgorithmResponse.NON_AREA_FORWARDING)

    # ── §D.4 GAC indicate – Annex D sender check ────────────────────────────

    def _build_gac_raw_with_pv(self, so_pv: LongPositionVector, rhl: int = 3) -> bytes:
        """Build a complete GAC wire packet with the given SO PV."""
        area = _make_gac_area(inside=True)  # centred at (0,0), r=100m
        bh = BasicHeader(version=1, rhl=rhl)
        ch = CommonHeader(ht=HeaderType.GEOANYCAST,
                          hst=GeoAnycastHST.GEOANYCAST_CIRCLE)  # type: ignore
        gbc = GBCExtendedHeader(
            sn=1, so_pv=so_pv,
            latitude=area.latitude, longitude=area.longitude,
            a=area.a, b=area.b, angle=area.angle,
        )
        return bh.encode_to_bytes() + ch.encode_to_bytes() + gbc.encode() + b"payload"

    def _setup_gac_outside_router(self):
        """Return a router whose ego is outside the GAC test area at (0,0) r=100m."""
        mib = MIB()
        router = Router(mib)
        router.ego_position_vector = LongPositionVector(
            latitude=100000000, longitude=100000000)
        router.duplicate_address_detection = Mock()
        router.location_table.new_gac_packet = Mock()  # prevent LocT-update side-effects
        link_layer = Mock()
        router.link_layer = link_layer
        return router, link_layer

    def test_gac_indicate_ego_outside_sender_inside_pai_true_discards(self):
        """§D: ego outside, sender at area centre with PAI=True → must be discarded."""
        router, link_layer = self._setup_gac_outside_router()
        so_addr = _make_gn_addr()
        # Pre-populate LocT: sender at area centre (0,0), PAI=True → F_SE = 1 ≥ 0
        se_entry = router.location_table.ensure_entry(so_addr)
        se_pv = LongPositionVector(
            gn_addr=so_addr, pai=True, latitude=0, longitude=0)
        se_entry.update_position_vector(se_pv)

        so_pv = LongPositionVector(
            gn_addr=so_addr, pai=True, latitude=0, longitude=0)
        raw = self._build_gac_raw_with_pv(so_pv, rhl=3)
        ch = CommonHeader.decode_from_bytes(raw[4:12])
        bh = BasicHeader.decode_from_bytes(raw[0:4])

        router.gn_data_indicate_gac(raw[12:], ch, bh)

        link_layer.send.assert_not_called()

    def test_gac_indicate_ego_outside_sender_inside_pai_false_forwards(self):
        """§D ELSE: ego outside, sender inside but PAI=False → SE_POS_VALID=False → forward."""
        router, link_layer = self._setup_gac_outside_router()
        so_addr = _make_gn_addr()
        # Pre-populate LocT: sender at area centre (0,0) but PAI=False → SE_POS_VALID = False
        se_entry = router.location_table.ensure_entry(so_addr)
        se_pv = LongPositionVector(
            gn_addr=so_addr, pai=False, latitude=0, longitude=0)
        se_entry.update_position_vector(se_pv)

        so_pv = LongPositionVector(
            gn_addr=so_addr, pai=False, latitude=0, longitude=0)
        raw = self._build_gac_raw_with_pv(so_pv, rhl=3)
        ch = CommonHeader.decode_from_bytes(raw[4:12])
        bh = BasicHeader.decode_from_bytes(raw[0:4])

        router.gn_data_indicate_gac(raw[12:], ch, bh)

        link_layer.send.assert_called_once()

    def test_gac_indicate_ego_outside_sender_outside_pai_true_forwards(self):
        """§D ELSE: ego outside, sender also outside area with PAI=True → F_SE < 0 → forward."""
        router, link_layer = self._setup_gac_outside_router()
        so_addr = _make_gn_addr()
        # Pre-populate LocT: sender far outside area, PAI=True → F_SE < 0
        se_entry = router.location_table.ensure_entry(so_addr)
        se_pv = LongPositionVector(
            gn_addr=so_addr, pai=True, latitude=100000000, longitude=100000000)
        se_entry.update_position_vector(se_pv)

        so_pv = LongPositionVector(
            gn_addr=so_addr, pai=True, latitude=100000000, longitude=100000000)
        raw = self._build_gac_raw_with_pv(so_pv, rhl=3)
        ch = CommonHeader.decode_from_bytes(raw[4:12])
        bh = BasicHeader.decode_from_bytes(raw[0:4])

        router.gn_data_indicate_gac(raw[12:], ch, bh)

        link_layer.send.assert_called_once()


# ---------------------------------------------------------------------------
# Annex E – Non-area forwarding algorithms (Greedy Forwarding)
# ---------------------------------------------------------------------------

class TestAnnexE(unittest.TestCase):
    """Unit tests verifying compliance with ETSI EN 302 636-4-1 V1.4.1 Annex E."""

    # Coordinates in 1/10 µdeg
    _EGO_LAT = 421255850    # ~42.1 N
    _EGO_LON = 27601710     # ~2.76 E
    # Destination ~200 m east of ego
    _DEST_LAT = 421255850
    _DEST_LON = 27628710
    # Area centre for GBC/GAC tests (same as Annex D)
    _AREA = Area(latitude=421255850, longitude=27601710, a=100, b=100, angle=0)

    def _make_router(self) -> Router:
        mib = MIB()
        router = Router(mib)
        router.ego_position_vector = LongPositionVector(
            latitude=self._EGO_LAT, longitude=self._EGO_LON)
        return router

    def _neighbour_entry(self, router: Router, lat: int, lon: int):
        """Insert a LocTE marked as neighbour at (lat, lon)."""
        addr = GNAddress(m=M.GN_MULTICAST, st=ST.UNKNOWN,
                         mid=MID(b"\x01\x02\x03\x04\x05\x06"))
        entry = router.location_table.ensure_entry(addr)
        pv = LongPositionVector(gn_addr=addr, latitude=lat, longitude=lon)
        entry.update_position_vector(pv)
        entry.is_neighbour = True
        return entry

    # ── _distance_m ─────────────────────────────────────────────────────────

    def test_distance_m_zero_same_point(self):
        """Distance from a point to itself is 0."""
        d = Router._distance_m(self._EGO_LAT, self._EGO_LON,
                               self._EGO_LAT, self._EGO_LON)
        self.assertAlmostEqual(d, 0.0)

    def test_distance_m_positive_different_points(self):
        """Distance between two distinct points is positive."""
        d = Router._distance_m(self._EGO_LAT, self._EGO_LON,
                               self._DEST_LAT, self._DEST_LON)
        self.assertGreater(d, 0.0)

    # ── gn_greedy_forwarding ────────────────────────────────────────────────

    def test_greedy_neighbour_closer_to_dest_returns_true(self):
        """§E.2: neighbour closer to destination than ego → GF returns True (send to NH)."""
        router = self._make_router()
        tc = TrafficClass()
        # Place neighbour halfway between ego and destination
        mid_lon = (self._EGO_LON + self._DEST_LON) // 2
        self._neighbour_entry(router, self._DEST_LAT, mid_lon)

        result = router.gn_greedy_forwarding(
            self._DEST_LAT, self._DEST_LON, tc)

        self.assertTrue(result)

    def test_greedy_no_neighbours_scf_false_bcast_fallback(self):
        """§E.2: local optimum, SCF=False → BCAST fallback → returns True."""
        router = self._make_router()
        tc = TrafficClass(scf=False)

        result = router.gn_greedy_forwarding(
            self._DEST_LAT, self._DEST_LON, tc)

        self.assertTrue(result)

    def test_greedy_no_neighbours_scf_true_buffer(self):
        """§E.2: local optimum, SCF=True → buffer → returns False."""
        router = self._make_router()
        tc = TrafficClass(scf=True)

        result = router.gn_greedy_forwarding(
            self._DEST_LAT, self._DEST_LON, tc)

        self.assertFalse(result)

    def test_greedy_neighbour_farther_than_ego_local_optimum_scf_false(self):
        """§E.2: neighbour farther from dest than ego → local optimum + SCF=False → True."""
        router = self._make_router()
        tc = TrafficClass(scf=False)
        # Place neighbour on the opposite side of ego relative to the destination
        far_lon = self._EGO_LON - (self._DEST_LON - self._EGO_LON)
        self._neighbour_entry(router, self._EGO_LAT, far_lon)

        result = router.gn_greedy_forwarding(
            self._DEST_LAT, self._DEST_LON, tc)

        self.assertTrue(result)

    # ── GUC source: GF blocks send when local optimum + SCF ─────────────────

    def test_guc_source_scf_true_local_optimum_not_sent(self):
        """§10.3.8.2 step 4 / §E.2: dest == ego (MFR=0) + SCF=True → local optimum → not sent."""
        router = self._make_router()
        link_layer = Mock()
        router.link_layer = link_layer
        # Add one neighbour far from dest so Step 3 (no-neighbours gate) is bypassed
        far_neigh_lon = self._EGO_LON - (self._DEST_LON - self._EGO_LON) * 2
        self._neighbour_entry(router, self._EGO_LAT, far_neigh_lon)
        # Destination positioned at ego → MFR=0; no neighbour is closer → local optimum
        dest_addr = GNAddress(m=M.GN_MULTICAST, st=ST.UNKNOWN,
                              mid=MID(b"\xAA\xBB\xCC\xDD\xEE\xFF"))
        dest_entry = router.location_table.ensure_entry(dest_addr)
        dest_lpv = LongPositionVector(
            gn_addr=dest_addr, latitude=self._EGO_LAT, longitude=self._EGO_LON)
        dest_entry.update_position_vector(dest_lpv)
        tc_scf = TrafficClass(scf=True)
        request = GNDataRequest(
            packet_transport_type=PacketTransportType(
                header_type=HeaderType.GEOUNICAST,
            ),
            destination=dest_addr,
            traffic_class=tc_scf,
            data=b"test",
        )

        confirm = router.gn_data_request_guc(request)

        self.assertEqual(confirm.result_code, ResultCode.ACCEPTED)
        link_layer.send.assert_not_called()

    # ── GBC NON_AREA: GF executes, sends toward area centre ─────────────────

    def test_gbc_non_area_forwarding_sends_with_scf_false(self):
        """§E.2 via gn_data_request_gbc: ego outside area + no neighbours + SCF=False → sent."""
        mib = MIB()
        router = Router(mib)
        router.ego_position_vector = LongPositionVector(
            latitude=100000000, longitude=100000000)
        link_layer = Mock()
        router.link_layer = link_layer

        request = GNDataRequest(
            packet_transport_type=PacketTransportType(
                header_type=HeaderType.GEOBROADCAST,
                header_subtype=GeoBroadcastHST.GEOBROADCAST_CIRCLE,
            ),
            area=self._AREA,
            traffic_class=TrafficClass(scf=False),
            data=b"gbc-data",
        )
        confirm = router.gn_data_request_gbc(request)

        self.assertEqual(confirm.result_code, ResultCode.ACCEPTED)
        link_layer.send.assert_called_once()

    def test_gbc_non_area_forwarding_not_sent_with_scf_true(self):
        """§E.2 via gn_data_request_gbc: ego outside + farther neighbour + SCF=True → buffered."""
        mib = MIB()
        router = Router(mib)
        # Ego 300 m north of area centre – outside area (radius=100 m)
        ego_lat = self._AREA.latitude + 30_000  # +300 m in 1/10 µdeg
        router.ego_position_vector = LongPositionVector(
            latitude=ego_lat, longitude=self._AREA.longitude)
        link_layer = Mock()
        router.link_layer = link_layer
        # Add a neighbour 600 m from area centre (farther than ego) so the
        # "no-neighbours + SCF" pre-check is bypassed and GF is actually exercised
        neigh_addr = GNAddress(
            m=M.GN_MULTICAST, st=ST.UNKNOWN, mid=MID(b"\x11\x22\x33\x44\x55\x66"))
        neigh_entry = router.location_table.ensure_entry(neigh_addr)
        neigh_pv = LongPositionVector(
            gn_addr=neigh_addr,
            latitude=self._AREA.latitude + 60_000,
            longitude=self._AREA.longitude,
        )
        neigh_entry.update_position_vector(neigh_pv)
        neigh_entry.is_neighbour = True

        request = GNDataRequest(
            packet_transport_type=PacketTransportType(
                header_type=HeaderType.GEOBROADCAST,
                header_subtype=GeoBroadcastHST.GEOBROADCAST_CIRCLE,
            ),
            area=self._AREA,
            traffic_class=TrafficClass(scf=True),
            data=b"gbc-data",
        )
        confirm = router.gn_data_request_gbc(request)

        self.assertEqual(confirm.result_code, ResultCode.ACCEPTED)
        link_layer.send.assert_not_called()


class TestAnnexF(unittest.TestCase):
    """Unit tests verifying compliance with ETSI EN 302 636-4-1 V1.4.1 Annex F."""

    # Area centred inside ego position (same geometry as Annex D/E tests)
    _AREA = Area(latitude=421255850, longitude=27601710, a=100, b=100, angle=0)
    _LAT_INSIDE = 421255850
    _LON_INSIDE = 27601710

    def _make_router_inside(self, algo: AreaForwardingAlgorithm = AreaForwardingAlgorithm.CBF) -> Router:
        mib = MIB(itsGnAreaForwardingAlgorithm=algo)
        router = Router(mib)
        router.ego_position_vector = LongPositionVector(
            latitude=self._LAT_INSIDE, longitude=self._LON_INSIDE)
        router.duplicate_address_detection = Mock()
        router.location_table.new_gbc_packet = Mock()
        return router

    def _make_gbc_headers(self, so_pv: LongPositionVector, rhl: int = 3):
        bh = BasicHeader(version=1, rhl=rhl)
        ch = CommonHeader(
            ht=HeaderType.GEOBROADCAST,
            hst=GeoBroadcastHST.GEOBROADCAST_CIRCLE,  # type: ignore
        )
        gbc = GBCExtendedHeader(
            sn=42, so_pv=so_pv,
            latitude=self._AREA.latitude, longitude=self._AREA.longitude,
            a=self._AREA.a, b=self._AREA.b, angle=self._AREA.angle,
        )
        return bh, ch, gbc

    # ── §F.3 _cbf_compute_timeout_ms ────────────────────────────────────────

    def test_cbf_timeout_at_zero_dist_is_max(self):
        """§F.3 eq. F.1: DIST=0 → TO = TO_CBF_MAX."""
        mib = MIB()
        router = Router(mib)
        to = router._cbf_compute_timeout_ms(0.0)
        self.assertAlmostEqual(to, mib.itsGnCbfMaxTime)

    def test_cbf_timeout_at_dist_max_is_min(self):
        """§F.3 eq. F.1: DIST=DIST_MAX → TO = TO_CBF_MIN."""
        mib = MIB()
        router = Router(mib)
        to = router._cbf_compute_timeout_ms(
            float(mib.itsGnDefaultMaxCommunicationRange))
        self.assertAlmostEqual(to, mib.itsGnCbfMinTime)

    def test_cbf_timeout_linear_midpoint(self):
        """§F.3 eq. F.1: DIST=DIST_MAX/2 → TO = midpoint between MIN and MAX."""
        mib = MIB()
        router = Router(mib)
        mid_dist = mib.itsGnDefaultMaxCommunicationRange / 2.0
        to = router._cbf_compute_timeout_ms(mid_dist)
        expected = (mib.itsGnCbfMinTime + mib.itsGnCbfMaxTime) / 2.0
        self.assertAlmostEqual(to, expected)

    # ── §F.3 gn_area_cbf_forwarding ─────────────────────────────────────────

    def test_cbf_new_packet_buffered_not_sent_immediately(self):
        """§F.3: new packet → buffered in CBF buffer → link_layer.send NOT called immediately."""
        router = self._make_router_inside()
        link_layer = Mock()
        router.link_layer = link_layer
        so_pv = LongPositionVector(gn_addr=_make_gn_addr())
        bh, ch, gbc = self._make_gbc_headers(so_pv)

        result = router.gn_area_cbf_forwarding(bh, ch, gbc, b"payload")

        self.assertTrue(result)  # buffered (§F.3 return 0)
        link_layer.send.assert_not_called()
        # Clean up timer
        key = (gbc.so_pv.gn_addr, gbc.sn)
        with router._cbf_lock:
            if key in router._cbf_buffer:
                router._cbf_buffer.pop(key).cancel()

    def test_cbf_duplicate_cancels_timer_and_discards(self):
        """§F.3: duplicate arrival → timer cancelled, returns False (discard, -1)."""
        router = self._make_router_inside()
        link_layer = Mock()
        router.link_layer = link_layer
        so_pv = LongPositionVector(gn_addr=_make_gn_addr())
        bh, ch, gbc = self._make_gbc_headers(so_pv)

        first = router.gn_area_cbf_forwarding(bh, ch, gbc, b"payload")
        second = router.gn_area_cbf_forwarding(bh, ch, gbc, b"payload")

        self.assertTrue(first)    # first: buffered
        self.assertFalse(second)  # duplicate: discarded
        link_layer.send.assert_not_called()
        # Buffer must be empty after duplicate suppression
        key = (gbc.so_pv.gn_addr, gbc.sn)
        with router._cbf_lock:
            self.assertNotIn(key, router._cbf_buffer)

    def test_cbf_timer_expiry_sends_packet(self):
        """§F.3: when timer fires → link_layer.send is called once."""
        import threading
        import unittest.mock

        router = self._make_router_inside()
        link_layer = Mock()
        router.link_layer = link_layer
        so_pv = LongPositionVector(gn_addr=_make_gn_addr())
        bh, ch, gbc = self._make_gbc_headers(so_pv)

        fired_event = threading.Event()

        def send_and_signal(pkt):
            fired_event.set()

        link_layer.send.side_effect = send_and_signal

        # Patch Timer to fire after a very short delay (10 ms)
        real_timer_args = []

        def fast_timer(interval, func, args=()):
            t = threading.Timer(0.01, func, args)
            real_timer_args.append(t)
            return t

        with unittest.mock.patch("flexstack.geonet.router.Timer", side_effect=fast_timer):
            router.gn_area_cbf_forwarding(bh, ch, gbc, b"payload")

        fired_event.wait(timeout=2.0)
        link_layer.send.assert_called_once()

    # ── §F.2 Simple forwarding via gn_data_forward_gbc ──────────────────────

    def test_simple_forwarding_sends_immediately(self):
        """§F.2: SIMPLE algorithm → AREA_FORWARDING sends immediately via BCAST."""
        router = self._make_router_inside(algo=AreaForwardingAlgorithm.SIMPLE)
        link_layer = Mock()
        router.link_layer = link_layer
        so_pv = LongPositionVector(gn_addr=_make_gn_addr())
        bh, ch, gbc = self._make_gbc_headers(so_pv, rhl=3)
        router.gn_forwarding_algorithm_selection = Mock(
            return_value=GNForwardingAlgorithmResponse.AREA_FORWARDING)

        router.gn_data_forward_gbc(bh, ch, gbc, b"payload")

        link_layer.send.assert_called_once()

    def test_cbf_forwarding_does_not_send_immediately_via_data_forward(self):
        """§F.3: CBF algorithm → gn_data_forward_gbc does NOT call link_layer.send immediately."""
        router = self._make_router_inside(algo=AreaForwardingAlgorithm.CBF)
        link_layer = Mock()
        router.link_layer = link_layer
        so_pv = LongPositionVector(gn_addr=_make_gn_addr())
        bh, ch, gbc = self._make_gbc_headers(so_pv, rhl=3)
        router.gn_forwarding_algorithm_selection = Mock(
            return_value=GNForwardingAlgorithmResponse.AREA_FORWARDING)

        router.gn_data_forward_gbc(bh, ch, gbc, b"payload")

        link_layer.send.assert_not_called()
        # Clean up timer
        key = (gbc.so_pv.gn_addr, gbc.sn)
        with router._cbf_lock:
            if key in router._cbf_buffer:
                router._cbf_buffer.pop(key).cancel()

    def test_source_always_sends_immediately_regardless_of_cbf(self):
        """§F.3 lines 1-3: source (gn_data_request_gbc) with ego inside area → immediate BCAST."""
        mib = MIB(itsGnAreaForwardingAlgorithm=AreaForwardingAlgorithm.CBF)
        router = Router(mib)
        router.ego_position_vector = LongPositionVector(
            latitude=self._LAT_INSIDE, longitude=self._LON_INSIDE)
        link_layer = Mock()
        router.link_layer = link_layer

        request = GNDataRequest(
            packet_transport_type=PacketTransportType(
                header_type=HeaderType.GEOBROADCAST,
                header_subtype=GeoBroadcastHST.GEOBROADCAST_CIRCLE,
            ),
            area=self._AREA,
            data=b"source-data",
        )
        confirm = router.gn_data_request_gbc(request)

        self.assertEqual(confirm.result_code, ResultCode.ACCEPTED)
        link_layer.send.assert_called_once()  # §F.3: source always sends immediately
