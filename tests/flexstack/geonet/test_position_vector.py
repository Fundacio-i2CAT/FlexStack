import unittest

from flexstack.geonet.position_vector import TST, LongPositionVector, ShortPositionVector
from flexstack.geonet.gn_address import GNAddress, M, ST, MID


class TestTST(unittest.TestCase):
    def test_set_in_normal_timestamp_seconds(self):
        tst = TST()
        tst.set_in_normal_timestamp_seconds(1674637884)
        self.assertEqual(tst.msec, 427267560)

    def test_set_in_normal_timestamp_milliseconds(self):
        tst = TST()
        tst.set_in_normal_timestamp_milliseconds(1674637884000)
        self.assertEqual(tst.msec, 427267560)

    def test_encode(self):
        tst = TST()
        tst.set_in_normal_timestamp_seconds(1674637884)
        self.assertEqual(tst.encode(), 427267560)

    def test_decode(self):
        tst = TST()
        tst.decode(430862560)
        self.assertEqual(tst.msec, 430862560)


class TestLongPositionVector(unittest.TestCase):

    def test_encode(self):
        lpv = LongPositionVector()
        gn_address = GNAddress()
        gn_address.set_m(M(1))
        gn_address.set_st(ST(1))
        gn_address.set_mid(MID(b'\xaa\xbb\xcc\x11\x22\x33'))
        lpv.set_gn_addr(gn_address)
        lpv.set_tst_in_normal_timestamp_seconds(1674638854)
        lpv.set_latitude(52.520008)
        lpv.set_longitude(13.404954)
        lpv.set_pai(True)
        lpv.set_heading(0)
        lpv.set_speed(0)
        self.assertEqual(lpv.encode(
        ), bytes.fromhex('8800aabbcc112233198662f81f4dead007fd6f0480000000'))

    def test_decode(self):
        lpv = LongPositionVector()
        lpv.decode(
            b'\x88\x00\xaa\xbb\xcc\x11"3\x19\xbd=\xf0\x1fM\xea\xd0\x07\xfdo\x04\x80\x00\x00\x00')
        self.assertEqual(lpv.gn_addr.encode(), b'\x88\x00\xaa\xbb\xcc\x11"3')
        self.assertEqual(lpv.tst.msec, 431832560)
        self.assertEqual(lpv.latitude, 525200080)
        self.assertEqual(lpv.longitude, 134049540)
        self.assertEqual(lpv.pai, True)
        self.assertEqual(lpv.h, 0)
        self.assertEqual(lpv.s, 0)


class TestShortPositionVector(unittest.TestCase):
    def test_encode(self):
        spv = ShortPositionVector()
        gn_address = GNAddress()
        gn_address.set_m(M(1))
        gn_address.set_st(ST(1))
        gn_address.set_mid(MID(b'\xaa\xbb\xcc\x11\x22\x33'))
        spv.set_gn_addr(gn_address)
        spv.set_tst_in_normal_timestamp_seconds(1674638854)
        spv.set_latitude(52.520008)
        spv.set_longitude(13.404954)
        self.assertEqual(spv.encode(
        ), b'\x88\x00\xaa\xbb\xcc\x11"3\x19\x86b\xf8\x1fM\xea\xd0\x07\xfdo\x04')

    def test_decode(self):
        spv = ShortPositionVector()
        spv.decode(
            b'\x88\x00\xaa\xbb\xcc\x11"3\x19\xbd=\xf0\x1fM\xea\xd0\x07\xfdo\x04')
        self.assertEqual(spv.gn_addr.encode(), b'\x88\x00\xaa\xbb\xcc\x11"3')
        self.assertEqual(spv.tst.msec, 431832560)
        self.assertEqual(spv.latitude, 525200080)
        self.assertEqual(spv.longitude, 134049540)


if __name__ == '__main__':
    unittest.main()
