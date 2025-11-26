import unittest
from unittest.mock import MagicMock
from flexstack.geonet.basic_header import BasicHeader, BasicNH, LT, LTbase


class TestLT(unittest.TestCase):

    def test_set_value_in_milis(self):
        lt = LT()
        lt = lt.set_value_in_millis(50)
        self.assertEqual(lt.multiplier, 1)
        self.assertEqual(lt.base, LTbase.FIFTY_MILLISECONDS)
        lt = lt.set_value_in_millis(100)
        self.assertEqual(lt.multiplier, 2)
        self.assertEqual(lt.base, LTbase.FIFTY_MILLISECONDS)
        lt = lt.set_value_in_millis(1000)
        self.assertEqual(lt.multiplier, 1)
        self.assertEqual(lt.base, LTbase.ONE_SECOND)
        lt = lt.set_value_in_millis(10000)
        self.assertEqual(lt.multiplier, 1)
        self.assertEqual(lt.base, LTbase.TEN_SECONDS)
        lt = lt.set_value_in_millis(100000)
        self.assertEqual(lt.multiplier, 1)
        self.assertEqual(lt.base, LTbase.ONE_HUNDRED_SECONDS)
        lt = lt.set_value_in_millis(1000000)
        self.assertEqual(lt.multiplier, 0)
        self.assertEqual(lt.base, LTbase.ONE_HUNDRED_SECONDS)
        lt = lt.set_value_in_millis(10000000)
        self.assertEqual(lt.multiplier, 0)
        self.assertEqual(lt.base, LTbase.ONE_HUNDRED_SECONDS)

    def test_set_value_in_seconds(self):
        lt = LT()
        lt = lt.set_value_in_seconds(0)
        self.assertEqual(lt.multiplier, 0)
        self.assertEqual(lt.base, LTbase.FIFTY_MILLISECONDS)
        lt = lt.set_value_in_seconds(1)
        self.assertEqual(lt.multiplier, 1)
        self.assertEqual(lt.base, LTbase.ONE_SECOND)
        lt = lt.set_value_in_seconds(10)
        self.assertEqual(lt.multiplier, 1)
        self.assertEqual(lt.base, LTbase.TEN_SECONDS)
        lt = lt.set_value_in_seconds(100)
        self.assertEqual(lt.multiplier, 1)
        self.assertEqual(lt.base, LTbase.ONE_HUNDRED_SECONDS)
        lt = lt.set_value_in_seconds(1000)
        self.assertEqual(lt.multiplier, 0)
        self.assertEqual(lt.base, LTbase.ONE_HUNDRED_SECONDS)
        lt = lt.set_value_in_seconds(10000)
        self.assertEqual(lt.multiplier, 0)
        self.assertEqual(lt.base, LTbase.ONE_HUNDRED_SECONDS)

    def test_get_value_in_millis(self):
        lt = LT()
        lt = lt.set_value_in_millis(50)
        self.assertEqual(lt.get_value_in_millis(), 50)
        lt = lt.set_value_in_millis(100)
        self.assertEqual(lt.get_value_in_millis(), 100)
        lt = lt.set_value_in_millis(1000)
        self.assertEqual(lt.get_value_in_millis(), 1000)
        lt = lt.set_value_in_millis(10000)
        self.assertEqual(lt.get_value_in_millis(), 10000)
        lt = lt.set_value_in_millis(100000)
        self.assertEqual(lt.get_value_in_millis(), 100000)

    def test_get_value_in_seconds(self):
        lt = LT()
        lt = lt.set_value_in_millis(50)
        self.assertEqual(lt.get_value_in_seconds(), 0)
        lt = lt.set_value_in_millis(100)
        self.assertEqual(lt.get_value_in_seconds(), 0)
        lt = lt.set_value_in_millis(1000)
        self.assertEqual(lt.get_value_in_seconds(), 1)
        lt = lt.set_value_in_millis(10000)
        self.assertEqual(lt.get_value_in_seconds(), 10)
        lt = lt.set_value_in_millis(100000)
        self.assertEqual(lt.get_value_in_seconds(), 100)

    def test_encode_to_bytes(self):
        lt = LT()
        lt = lt.set_value_in_millis(50)
        self.assertEqual(lt.encode_to_bytes(), b'\x04')
        lt = lt.set_value_in_millis(100)
        self.assertEqual(lt.encode_to_bytes(), b'\x08')
        lt = lt.set_value_in_millis(1000)
        self.assertEqual(lt.encode_to_bytes(), b'\x05')
        lt = lt.set_value_in_millis(10000)
        self.assertEqual(lt.encode_to_bytes(), b'\x06')
        lt = lt.set_value_in_millis(100000)
        self.assertEqual(lt.encode_to_bytes(), b'\x07')

    def test_encode_to_int(self):
        lt = LT()
        lt = lt.set_value_in_millis(50)
        self.assertEqual(lt.encode_to_int(), 4)
        lt = lt.set_value_in_millis(100)
        self.assertEqual(lt.encode_to_int(), 8)
        lt = lt.set_value_in_millis(1000)
        self.assertEqual(lt.encode_to_int(), 5)
        lt = lt.set_value_in_millis(10000)
        self.assertEqual(lt.encode_to_int(), 6)
        lt = lt.set_value_in_millis(100000)
        self.assertEqual(lt.encode_to_int(), 7)


class TestBasicHeader(unittest.TestCase):

    def test_initialize_with_mib_and_rhl(self):
        mib = MagicMock()
        mib.itsGnDefaultPacketLifetime = 60
        rhl = 1
        bh = BasicHeader.initialize_with_mib_and_rhl(mib, rhl)
        self.assertEqual(bh.encode_to_bytes(), b'\x11\x00\x1a\x01')

    def test_set_version(self):
        bh = BasicHeader()
        bh = bh.set_version(10)
        self.assertEqual(bh.version, 10)

    def test_set_nh(self):
        bh = BasicHeader()
        bh = bh.set_nh(BasicNH.ANY)
        self.assertEqual(bh.nh, BasicNH.ANY)

    def test_set_lt(self):
        bh = BasicHeader()
        lt = LT(base=LTbase.FIFTY_MILLISECONDS, multiplier=1)
        bh = bh.set_lt(lt)
        self.assertEqual(bh.lt.base, LTbase.FIFTY_MILLISECONDS)
        self.assertEqual(bh.lt.multiplier, 1)

    def test_set_rhl(self):
        bh = BasicHeader()
        bh = bh.set_rhl(5)
        self.assertEqual(bh.rhl, 5)

    def test_encode_to_int(self):
        bh = BasicHeader(
            lt=LT(base=LTbase.FIFTY_MILLISECONDS, multiplier=1),
            version=1,
            nh=BasicNH.ANY,
            rhl=1
        )
        self.assertEqual(bh.encode_to_int(), 0x10000401)
        bh = BasicHeader()
        self.assertEqual(bh.encode_to_int(), 0x11000000)

    def test_encode_to_bytes(self):
        bh = BasicHeader(
            lt=LT(base=LTbase.FIFTY_MILLISECONDS, multiplier=1),
            version=1,
            nh=BasicNH.ANY,
            rhl=1
        )
        self.assertEqual(bh.encode_to_bytes(), b'\x10\x00\x04\x01')
        bh = BasicHeader()
        self.assertEqual(bh.encode_to_bytes(), b'\x11\x00\x00\x00')

    def test_decode_from_bytes(self):
        bh = BasicHeader(
            lt=LT(base=LTbase.FIFTY_MILLISECONDS, multiplier=1),
            version=1,
            nh=BasicNH.ANY,
            rhl=1
        )
        encoded = bh.encode_to_bytes()
        bh = BasicHeader(
            lt=LT(base=LTbase.FIFTY_MILLISECONDS, multiplier=1),
            version=1,
            nh=BasicNH.ANY,
            rhl=1
        )
        bh.decode_from_bytes(encoded)
        self.assertEqual(bh.lt.base, LTbase.FIFTY_MILLISECONDS)
        self.assertEqual(bh.lt.multiplier, 1)
        self.assertEqual(bh.lt.get_value_in_millis(), 50)
        self.assertEqual(bh.version, 1)
        self.assertEqual(bh.nh, BasicNH.ANY)
        self.assertEqual(bh.rhl, 1)


if __name__ == '__main__':
    unittest.main()
