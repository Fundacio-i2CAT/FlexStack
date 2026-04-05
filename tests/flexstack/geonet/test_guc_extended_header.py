import unittest

from flexstack.geonet.exceptions import DecodeError
from flexstack.geonet.guc_extended_header import GUCExtendedHeader
from flexstack.geonet.gn_address import GNAddress, M, ST, MID
from flexstack.geonet.position_vector import LongPositionVector, ShortPositionVector


def _make_gn_addr() -> GNAddress:
    return GNAddress(m=M.GN_MULTICAST, st=ST.CYCLIST, mid=MID(b"\xaa\xbb\xcc\xdd\x22\x33"))


class TestGUCExtendedHeader(unittest.TestCase):
    """Unit tests for GUCExtendedHeader (§9.8.2 Table 11)."""

    def _make_header(self) -> GUCExtendedHeader:
        lpv = LongPositionVector(gn_addr=_make_gn_addr(), latitude=413872756, longitude=21122668)
        de_pv = ShortPositionVector(gn_addr=_make_gn_addr(), latitude=100000000, longitude=20000000)
        return GUCExtendedHeader(sn=42, so_pv=lpv, de_pv=de_pv)

    def test_encode_length(self):
        """Encoded GUC Extended Header must be exactly 48 bytes."""
        self.assertEqual(len(self._make_header().encode()), 48)

    def test_encode_decode_roundtrip(self):
        """Encoding then decoding must return an equal header."""
        original = self._make_header()
        decoded = GUCExtendedHeader.decode(original.encode())
        self.assertEqual(decoded, original)

    def test_decode_too_short_raises(self):
        """Decoding fewer than 48 bytes must raise DecodeError."""
        with self.assertRaises(DecodeError):
            GUCExtendedHeader.decode(b"\x00" * 47)

    def test_sn_byte_order(self):
        """SN must be stored in big-endian at bytes 0-1 of the encoded header."""
        header = GUCExtendedHeader(sn=0x1234)
        encoded = header.encode()
        self.assertEqual(encoded[0], 0x12)
        self.assertEqual(encoded[1], 0x34)

    def test_reserved_zero_by_default(self):
        """Reserved field must default to 0 and be encoded at bytes 2-3."""
        header = GUCExtendedHeader()
        encoded = header.encode()
        self.assertEqual(encoded[2], 0x00)
        self.assertEqual(encoded[3], 0x00)

    def test_initialize_factory(self):
        """Factory method must set sn, so_pv, and de_pv from given arguments."""
        lpv = LongPositionVector(gn_addr=_make_gn_addr())
        de_pv = ShortPositionVector(gn_addr=_make_gn_addr())
        header = GUCExtendedHeader.initialize_with_request_sequence_number_ego_pv_de_pv(
            sequence_number=7, ego_pv=lpv, de_pv=de_pv
        )
        self.assertEqual(header.sn, 7)
        self.assertEqual(header.so_pv, lpv)
        self.assertEqual(header.de_pv, de_pv)

    def test_with_de_pv(self):
        """with_de_pv must return a new header with only DE PV changed."""
        original = self._make_header()
        new_de_pv = ShortPositionVector(gn_addr=GNAddress(), latitude=99, longitude=88)
        updated = original.with_de_pv(new_de_pv)
        self.assertEqual(updated.de_pv, new_de_pv)
        self.assertEqual(updated.sn, original.sn)
        self.assertEqual(updated.so_pv, original.so_pv)
        # Must be a different object
        self.assertIsNot(updated, original)


if __name__ == "__main__":
    unittest.main()
