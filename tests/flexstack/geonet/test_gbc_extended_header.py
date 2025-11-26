import unittest

from flexstack.geonet.gbc_extended_header import GBCExtendedHeader
from flexstack.geonet.service_access_point import GNDataRequest, Area, LongPositionVector


class TestGBCExtendedHeader(unittest.TestCase):
    """
    Test the GBC extended header.
    """

    def test_initialize_with_request(self):
        # Given
        request = GNDataRequest(
            area=Area(
                latitude=425234589,
                longitude=29878965,
                a=30,
                b=40,
                angle=45
            )
        )
        # when
        gbc_extended_header = GBCExtendedHeader.initialize_with_request(request)
        # then
        self.assertEqual(gbc_extended_header.latitude, 425234589)
        self.assertEqual(gbc_extended_header.longitude, 29878965)
        self.assertEqual(gbc_extended_header.a, 30)
        self.assertEqual(gbc_extended_header.b, 40)
        self.assertEqual(gbc_extended_header.angle, 45)

    def test_encode(self):
        # Given
        gbc_extended_header = GBCExtendedHeader(
            sn=1,
            reserved=0,
            so_pv=LongPositionVector(
                latitude=425234589,
                longitude=29878965
            ),
            latitude=425238621,
            longitude=29877856,
            a=30,
            b=40,
            angle=45,
            reserved2=0
        )
        # when
        encoded_bytes = gbc_extended_header.encode()
        # then
        self.assertEqual(
            encoded_bytes, b'\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x19X\x90\x9d\x01\xc7\xea\xb5\x00\x00\x00\x00\x19X\xa0]\x01\xc7\xe6`\x00\x1e\x00(\x00-\x00\x00')

    def test_decode(self):
        # Given
        encoded_gbc = b'\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x19X\x90\x9d\x01\xc7\xea\xb5\x00\x00\x00\x00\x19X\xa0]\x01\xc7\xe6`\x00\x1e\x00(\x00-\x00\x00'
        # When
        gbc_extended_header = GBCExtendedHeader.decode(encoded_gbc)
        # then
        self.assertEqual(gbc_extended_header.sn, 1)
        self.assertEqual(gbc_extended_header.reserved, 0)
        self.assertEqual(gbc_extended_header.so_pv.latitude, 425234589)
        self.assertEqual(gbc_extended_header.so_pv.longitude, 29878965)
        self.assertEqual(gbc_extended_header.latitude, 425238621)
        self.assertEqual(gbc_extended_header.longitude, 29877856)
        self.assertEqual(gbc_extended_header.a, 30)
        self.assertEqual(gbc_extended_header.b, 40)
        self.assertEqual(gbc_extended_header.angle, 45)
        self.assertEqual(gbc_extended_header.reserved2, 0)
