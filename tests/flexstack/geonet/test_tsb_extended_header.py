import unittest

from flexstack.geonet.tsb_extended_header import TSBExtendedHeader
from flexstack.geonet.position_vector import LongPositionVector
from flexstack.geonet.service_access_point import GNDataRequest
from flexstack.geonet.exceptions import DecodeError


class TestTSBExtendedHeader(unittest.TestCase):

    def test_encode_decode_roundtrip(self):
        """Encoding then decoding must return an equal header."""
        lpv = LongPositionVector(latitude=421255850, longitude=27601710)
        original = TSBExtendedHeader(sn=42, reserved=0, so_pv=lpv)
        encoded = original.encode()
        self.assertEqual(len(encoded), 28)
        decoded = TSBExtendedHeader.decode(encoded)
        self.assertEqual(decoded.sn, 42)
        self.assertEqual(decoded.reserved, 0)
        self.assertEqual(decoded.so_pv.latitude, lpv.latitude)
        self.assertEqual(decoded.so_pv.longitude, lpv.longitude)

    def test_encode_length(self):
        """Encoded header must be exactly 28 bytes."""
        header = TSBExtendedHeader(sn=1)
        self.assertEqual(len(header.encode()), 28)

    def test_decode_too_short_raises(self):
        """Decoding fewer than 28 bytes must raise DecodeError."""
        with self.assertRaises(DecodeError):
            TSBExtendedHeader.decode(bytes(27))

    def test_initialize_with_request_sequence_number_ego_pv(self):
        """Factory method must set sn and so_pv from the given arguments."""
        lpv = LongPositionVector(latitude=100, longitude=200)
        request = GNDataRequest()
        header = TSBExtendedHeader.initialize_with_request_sequence_number_ego_pv(
            request, sequence_number=7, ego_pv=lpv
        )
        self.assertEqual(header.sn, 7)
        self.assertEqual(header.so_pv.latitude, 100)
        self.assertEqual(header.so_pv.longitude, 200)

    def test_sn_byte_order(self):
        """SN must be stored in big-endian at bytes 0-1 of the encoded header."""
        header = TSBExtendedHeader(sn=0x0102)
        encoded = header.encode()
        self.assertEqual(encoded[0], 0x01)
        self.assertEqual(encoded[1], 0x02)

    def test_reserved_zero_by_default(self):
        """Reserved field must default to 0."""
        header = TSBExtendedHeader()
        self.assertEqual(header.reserved, 0)
        encoded = header.encode()
        self.assertEqual(encoded[2], 0x00)
        self.assertEqual(encoded[3], 0x00)
