import unittest
from unittest.mock import patch

from flexstack.geonet.gn_address import MID, M, ST, GNAddress
from flexstack.geonet.exceptions import (
    DuplicatedPacketException,
    IncongruentTimestampException,
)
from flexstack.geonet.location_table import (
    LocationTableEntry,
    LongPositionVector,
)
from flexstack.geonet.mib import MIB


class TestLocationTableEntry(unittest.TestCase):

    def create_filled_position_vector(self):
        naddress = GNAddress(
            m=M.GN_MULTICAST,
            st=ST.CYCLIST,
            mid=MID(b"\xaa\xbb\xcc\xdd\x22\x33"),
        )
        position_vector = LongPositionVector(
            gn_addr=naddress,
            pai=True,
            s=3,
            h=4,
            latitude=413872756,
            longitude=21122668
        )
        return position_vector

    @patch("time.time")
    def test_update_position_vector(self, mock_time):
        timestamp = 1675071608.1964376
        mock_time.return_value = timestamp - 100
        mib = MIB()
        entry = LocationTableEntry(mib)
        mock_time.assert_not_called()
        position_vector = self.create_filled_position_vector()
        entry.update_position_vector(position_vector)
        self.assertEqual(entry.position_vector, position_vector)
        position_vector2 = self.create_filled_position_vector()
        position_vector2 = position_vector2.set_tst_in_normal_timestamp_seconds(
            timestamp + 0.1)
        entry.update_position_vector(position_vector2)
        self.assertRaises(
            IncongruentTimestampException, entry.update_position_vector, position_vector
        )

    @patch("time.time")
    def test_update_pdr(self, mock_time):
        timestamp = 1675071608.1964376
        mock_time.return_value = timestamp - 200
        mib = MIB()
        entry = LocationTableEntry(mib)
        mock_time.assert_not_called()

        # First position_vector
        position_vector = self.create_filled_position_vector()
        position_vector = position_vector.set_tst_in_normal_timestamp_seconds(timestamp)
        entry.update_position_vector(position_vector)
        entry.update_pdr(position_vector=position_vector, packet_size=100)
        self.assertAlmostEqual(entry.pdr, 1.1566219266650857e-05)
        # Second position_vector
        position_vector2 = self.create_filled_position_vector()
        position_vector2 = position_vector2.set_tst_in_normal_timestamp_seconds(
            timestamp + 0.1)
        entry.update_position_vector(position_vector2)
        entry.update_pdr(position_vector=position_vector2, packet_size=100)
        self.assertAlmostEqual(entry.pdr, 100.00001045306173)
        # Third position_vector
        position_vector3 = self.create_filled_position_vector()
        position_vector3 = position_vector3.set_tst_in_normal_timestamp_seconds(timestamp + 0.2)
        entry.update_position_vector(position_vector3)
        entry.update_pdr(position_vector=position_vector3, packet_size=100)
        self.assertAlmostEqual(entry.pdr, 190.00000940775553)

    def test_duplicate_packet(self):
        mib = MIB()
        entry = LocationTableEntry(mib)
        packet1 = b"\x07\xd1\x00\x00\x02\x02\x00\x00\x07\xa9\xb5\xc8\x40\x59\xca\x03\xa2\x4d\x91\x82\x8b\xe1\x90\x19\x03\x84\x38\x6c\xf0\x00\xe1\x0f\xc0\x00\x2c\x82\xf0\x8a\x80\x03\xff\x05\xff\xf8\x00\x00\x0e\x00\x70\x80\x54\xd8\x5d\x9f\x2b\xc0"
        entry.check_duplicate_packet(packet1)
        self.assertRaises(
            DuplicatedPacketException, entry.check_duplicate_packet, packet1
        )


if __name__ == "__main__":
    unittest.main()
