import unittest

from flexstack.geonet.position_vector import TST, LongPositionVector, ShortPositionVector
from flexstack.geonet.gn_address import GNAddress, M, ST, MID


class TestTST(unittest.TestCase):
    def test_set_in_normal_timestamp_seconds(self):
        tst = TST.set_in_normal_timestamp_seconds(1674637884)
        self.assertEqual(tst.msec, 427267560)

    def test_set_in_normal_timestamp_milliseconds(self):
        tst = TST.set_in_normal_timestamp_milliseconds(1674637884000)
        self.assertEqual(tst.msec, 427267560)

    def test_encode(self):
        tst = TST.set_in_normal_timestamp_seconds(1674637884)
        self.assertEqual(tst.encode(), 427267560)

    def test_decode(self):
        tst = TST.decode(430862560)
        self.assertEqual(tst.msec, 430862560)


class TestLongPositionVector(unittest.TestCase):

    def test_encode(self):
        gn_address = GNAddress(
            m=M(1),
            st=ST(1),
            mid=MID(b'\xaa\xbb\xcc\x11\x22\x33')
        )
        lpv = LongPositionVector(
            gn_addr=gn_address,
            latitude=525200080,
            longitude=134049540,
            pai=True,
            h=0,
            s=0

        )
        lpv = lpv.set_tst_in_normal_timestamp_seconds(1674638854)
        self.assertEqual(lpv.encode(
        ), bytes.fromhex('8400aabbcc112233198662f81f4dead007fd6f0480000000'))

    def test_decode(self):
        lpv = LongPositionVector.decode(
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
        gn_address = GNAddress(
            m=M(1),
            st=ST(1),
            mid=MID(b'\xaa\xbb\xcc\x11\x22\x33')
        )
        spv = ShortPositionVector(
            gn_addr=gn_address,
            latitude=525200080,
            longitude=134049540,
        )
        spv = spv.set_tst_in_normal_timestamp_seconds(1674638854)
        self.assertEqual(spv.encode(
        ), b'\x84\x00\xaa\xbb\xcc\x11"3\x19\x86b\xf8\x1fM\xea\xd0\x07\xfdo\x04')

    def test_decode(self):
        spv = ShortPositionVector.decode(
            b'\x88\x00\xaa\xbb\xcc\x11"3\x19\xbd=\xf0\x1fM\xea\xd0\x07\xfdo\x04')
        self.assertEqual(spv.gn_addr.encode(), b'\x88\x00\xaa\xbb\xcc\x11"3')
        self.assertEqual(spv.tst.msec, 431832560)
        self.assertEqual(spv.latitude, 525200080)
        self.assertEqual(spv.longitude, 134049540)


if __name__ == '__main__':
    unittest.main()
