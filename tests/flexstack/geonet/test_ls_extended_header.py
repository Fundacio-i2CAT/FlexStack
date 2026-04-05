import unittest

from flexstack.geonet.exceptions import DecodeError
from flexstack.geonet.ls_extended_header import LSRequestExtendedHeader, LSReplyExtendedHeader
from flexstack.geonet.gn_address import GNAddress, M, ST, MID
from flexstack.geonet.position_vector import LongPositionVector, ShortPositionVector


def _make_gn_addr() -> GNAddress:
    return GNAddress(m=M.GN_MULTICAST, st=ST.CYCLIST, mid=MID(b"\xaa\xbb\xcc\xdd\x22\x33"))


def _make_request_addr() -> GNAddress:
    return GNAddress(m=M.GN_MULTICAST, st=ST.PEDESTRIAN, mid=MID(b"\x11\x22\x33\x44\x55\x66"))


class TestLSRequestExtendedHeader(unittest.TestCase):
    """Unit tests for LSRequestExtendedHeader (§9.8.7 Table 16)."""

    def _make_header(self) -> LSRequestExtendedHeader:
        so_pv = LongPositionVector(gn_addr=_make_gn_addr(), latitude=413872756, longitude=21122668)
        return LSRequestExtendedHeader(sn=7, so_pv=so_pv, request_gn_addr=_make_request_addr())

    def test_encode_length(self):
        """Encoded LS Request Extended Header must be exactly 36 bytes."""
        self.assertEqual(len(self._make_header().encode()), 36)

    def test_encode_decode_roundtrip(self):
        """Encoding then decoding must return an equal header."""
        original = self._make_header()
        decoded = LSRequestExtendedHeader.decode(original.encode())
        self.assertEqual(decoded, original)

    def test_decode_too_short_raises(self):
        """Decoding fewer than 36 bytes must raise DecodeError."""
        with self.assertRaises(DecodeError):
            LSRequestExtendedHeader.decode(b"\x00" * 35)

    def test_sn_byte_order(self):
        """SN must be stored big-endian at bytes 0-1 of the encoded header."""
        header = LSRequestExtendedHeader(sn=0x1234)
        encoded = header.encode()
        self.assertEqual(encoded[0], 0x12)
        self.assertEqual(encoded[1], 0x34)

    def test_reserved_zero_by_default(self):
        """Reserved field must default to 0 and be encoded at bytes 2-3."""
        header = LSRequestExtendedHeader()
        encoded = header.encode()
        self.assertEqual(encoded[2], 0x00)
        self.assertEqual(encoded[3], 0x00)

    def test_so_pv_occupies_bytes_4_to_27(self):
        """SO PV must occupy bytes 4-27 (24 bytes)."""
        encoded = self._make_header().encode()
        self.assertEqual(len(encoded[4:28]), 24)

    def test_request_gn_addr_occupies_bytes_28_to_35(self):
        """Request GN_ADDR must occupy bytes 28-35 (8 bytes)."""
        encoded = self._make_header().encode()
        self.assertEqual(len(encoded[28:36]), 8)

    def test_initialize_factory(self):
        """initialize() must produce the same header as the direct constructor."""
        so_pv = LongPositionVector(gn_addr=_make_gn_addr())
        req_addr = _make_request_addr()
        via_init = LSRequestExtendedHeader.initialize(42, so_pv, req_addr)
        direct = LSRequestExtendedHeader(sn=42, so_pv=so_pv, request_gn_addr=req_addr)
        self.assertEqual(via_init, direct)


class TestLSReplyExtendedHeader(unittest.TestCase):
    """Unit tests for LSReplyExtendedHeader (§9.8.8 Table 17)."""

    def _make_header(self) -> LSReplyExtendedHeader:
        so_pv = LongPositionVector(gn_addr=_make_gn_addr(), latitude=413872756, longitude=21122668)
        de_pv = ShortPositionVector(gn_addr=_make_request_addr(), latitude=100000000, longitude=20000000)
        return LSReplyExtendedHeader(sn=3, so_pv=so_pv, de_pv=de_pv)

    def test_encode_length(self):
        """Encoded LS Reply Extended Header must be exactly 48 bytes."""
        self.assertEqual(len(self._make_header().encode()), 48)

    def test_encode_decode_roundtrip(self):
        """Encoding then decoding must return an equal header."""
        original = self._make_header()
        decoded = LSReplyExtendedHeader.decode(original.encode())
        self.assertEqual(decoded, original)

    def test_decode_too_short_raises(self):
        """Decoding fewer than 48 bytes must raise DecodeError."""
        with self.assertRaises(DecodeError):
            LSReplyExtendedHeader.decode(b"\x00" * 47)

    def test_sn_byte_order(self):
        """SN must be stored big-endian at bytes 0-1."""
        header = LSReplyExtendedHeader(sn=0xABCD)
        encoded = header.encode()
        self.assertEqual(encoded[0], 0xAB)
        self.assertEqual(encoded[1], 0xCD)

    def test_reserved_zero_by_default(self):
        """Reserved field must default to 0 and be encoded at bytes 2-3."""
        header = LSReplyExtendedHeader()
        encoded = header.encode()
        self.assertEqual(encoded[2], 0x00)
        self.assertEqual(encoded[3], 0x00)

    def test_so_pv_occupies_bytes_4_to_27(self):
        """SO PV must occupy bytes 4-27 (24 bytes)."""
        encoded = self._make_header().encode()
        self.assertEqual(len(encoded[4:28]), 24)

    def test_de_pv_occupies_bytes_28_to_47(self):
        """DE PV must occupy bytes 28-47 (20 bytes)."""
        encoded = self._make_header().encode()
        self.assertEqual(len(encoded[28:48]), 20)

    def test_initialize_factory(self):
        """initialize() must produce the same header as the direct constructor."""
        so_pv = LongPositionVector(gn_addr=_make_gn_addr())
        de_pv = ShortPositionVector(gn_addr=_make_request_addr())
        via_init = LSReplyExtendedHeader.initialize(99, so_pv, de_pv)
        direct = LSReplyExtendedHeader(sn=99, so_pv=so_pv, de_pv=de_pv)
        self.assertEqual(via_init, direct)


if __name__ == "__main__":
    unittest.main()
