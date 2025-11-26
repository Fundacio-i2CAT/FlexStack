import unittest

from flexstack.geonet.gn_address import M, ST, MID, InvalidMIDLength, GNAddress


class TestM(unittest.TestCase):
    def test_encode_to_address(self):
        self.assertEqual(M(0).encode_to_address(), 0)
        self.assertEqual(M(1).encode_to_address(), 0x8000000000000000)


class TestST(unittest.TestCase):
    def test_encode_to_address(self):
        self.assertEqual(ST(0).encode_to_address(), 0)
        self.assertEqual(ST(1).encode_to_address(), 0x0800000000000000)


class TestMID(unittest.TestCase):

    def test_init_raises_on_invalid_length(self):
        with self.assertRaises(InvalidMIDLength):
            MID(b'\x00\x00\x00\x00\x00\x00\x00')

    def test_encode_to_address(self):
        self.assertEqual(
            MID(b'\xaa\xbb\xcc\x11\x22\x33').encode_to_address(), 0x0000aabbcc112233)


class TestGNAddress(unittest.TestCase):
    def test_encode_to_address(self):
        self.assertEqual(GNAddress().encode(),
                         b'\x00\x00\x00\x00\x00\x00\x00\x00')
        gn_address = GNAddress(
            m=M(1),
            st=ST(1),
            mid=MID(b'\xaa\xbb\xcc\x11\x22\x33')
        )
        self.assertEqual(gn_address.encode(),
                         b'\x88\x00\xaa\xbb\xcc\x11\x22\x33')

    def test_decode(self):
        gn_address = GNAddress(
            m=M(1),
            st=ST(1),
            mid=MID(b'\xaa\xbb\xcc\x11\x22\x33')
        )
        gn_address_decoded = GNAddress.decode(gn_address.encode())
        self.assertEqual(gn_address.m.value, gn_address_decoded.m.value)
        self.assertEqual(gn_address.st.value, gn_address_decoded.st.value)
        self.assertEqual(gn_address.mid.mid, gn_address_decoded.mid.mid)


if __name__ == '__main__':
    unittest.main()
