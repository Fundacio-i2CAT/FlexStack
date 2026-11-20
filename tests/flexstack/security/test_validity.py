"""
Certificate validity restrictions (IEEE Std 1609.2-2016 clauses 5.2.3.2.2,
6.4.17). Mirrors ``rustflexstack::security::validity`` tests.
"""

import unittest

from flexstack.security.sign_service import ssp_covers
from flexstack.security.validity import (
    app_permission, recognized_identified_regions, region_contains, register_identified_region,
    unregister_identified_region, validity_window_us)


def _point(lat, lon):
    return {"latitude": lat, "longitude": lon}


class TestRegions(unittest.TestCase):

    def test_circular_region(self):
        region = ("circularRegion", {"center": _point(415520000, 21340000), "radius": 5000})
        self.assertTrue(region_contains(region, 415520000, 21340000))
        self.assertFalse(region_contains(region, 425520000, 21340000))
        self.assertTrue(region_contains(None, 0, 0))

    def test_rectangular_region(self):
        """IEEE 1609.2 clause 6.4.17: any of the rectangles contains the position."""
        rects = [{"northWest": _point(400000000, 0), "southEast": _point(390000000, 10000000)},
                 {"northWest": _point(420000000, 20000000), "southEast": _point(410000000, 30000000)}]
        self.assertTrue(region_contains(("rectangularRegion", rects), 415000000, 25000000))
        self.assertFalse(region_contains(("rectangularRegion", rects), 400000000, 25000000))

    def test_polygonal_region_with_8_points(self):
        """IEEE 1609.2 clause 6.4.17: polygon of at least 8 points."""
        points = [(420000000, 24000000), (420000000, 26000000), (418000000, 28000000),
                  (412000000, 28000000), (410000000, 26000000), (410000000, 24000000),
                  (412000000, 22000000), (418000000, 22000000)]
        region = ("polygonalRegion", [_point(a, b) for a, b in points])
        self.assertTrue(region_contains(region, 415000000, 25000000))
        self.assertFalse(region_contains(region, 419500000, 22100000))

    def test_identified_region_cannot_be_evaluated(self):
        self.assertIsNone(region_contains(("identifiedRegion", [("countryOnly", 9000)]), 0, 0))


def _box(south, west, north, east):
    return [(south, west), (north, west), (north, east), (south, east)]


def _country(code):
    return ("countryOnly", code)


class TestIdentifiedRegions(unittest.TestCase):
    """
    IEEE 1609.2 clauses 6.4.22 to 6.4.26 with synthetic geometry and
    identifiers (same values as the Rust tests).
    """

    def register(self, country, polygons, region=None, subregion=None):
        register_identified_region(country, polygons, region, subregion)
        self.addCleanup(unregister_identified_region, country, region, subregion)

    def test_identified_region_country(self):
        self.register(9001, [_box(410000000, 15000000, 420000000, 28000000)])
        self.assertIn((9001,), recognized_identified_regions())
        region = ("identifiedRegion", [_country(9001)])
        self.assertIs(region_contains(region, 415520000, 21340000), True)
        self.assertIs(region_contains(region, 425520000, 21340000), False)
        unregister_identified_region(9001)
        self.assertIsNone(region_contains(region, 415520000, 21340000))

    def test_identified_region_with_8_entries(self):
        """IEEE 1609.2 clause 6.4.17: 8 entries, one containing the position."""
        for i in range(8):
            lat = 340000000 + i * 15000000
            self.register(9100 + i, [_box(lat, 0, lat + 10000000, 30000000)])
        region = ("identifiedRegion", [_country(9100 + i) for i in range(8)])
        # Boxes 34.0-35.0 N, 35.5-36.5 N, ...: 41.55 N lies in the 6th (41.5-42.5 N)
        self.assertIs(region_contains(region, 415520000, 21340000), True)
        self.assertIs(region_contains(region, 412000000, 21340000), False)

    def test_identified_regions_and_subregions(self):
        self.register(9200, [_box(400000000, 0, 430000000, 40000000)])
        self.register(9200, [_box(410000000, 15000000, 420000000, 28000000)], region=3)
        regions = ("identifiedRegion", [("countryAndRegions", {"countryOnly": 9200, "regions": [3]})])
        self.assertIs(region_contains(regions, 415520000, 21340000), True)
        self.assertIs(region_contains(regions, 425520000, 21340000), False)
        subregions = ("identifiedRegion", [("countryAndSubregions", {
            "countryOnly": 9200, "regionAndSubregions": [{"region": 3, "subregions": [7]}]})])
        # Subregion 7 has no geometry: inside region 3 it cannot be decided,
        # outside region 3 (or the country) it is outside.
        self.assertIsNone(region_contains(subregions, 415520000, 21340000))
        self.assertIs(region_contains(subregions, 425520000, 21340000), False)
        self.assertIs(region_contains(subregions, 500000000, 21340000), False)
        self.register(9200, [_box(415000000, 21000000, 416000000, 22000000)], region=3, subregion=7)
        self.assertIs(region_contains(subregions, 415520000, 21340000), True)
        self.assertIs(region_contains(subregions, 418000000, 21340000), False)

    def test_identified_region_with_unrecognised_entries(self):
        """IEEE 1609.2 clause 6.4.24: recognised values may establish validity alone."""
        self.register(9301, [_box(410000000, 15000000, 420000000, 28000000)])
        region = ("identifiedRegion", [_country(9300), _country(9301)])
        self.assertIs(region_contains(region, 415520000, 21340000), True)
        self.assertIsNone(region_contains(region, 425520000, 21340000))

    def test_subregion_needs_region(self):
        with self.assertRaises(ValueError):
            register_identified_region(9500, [], subregion=1)


class TestPermissionsAndTime(unittest.TestCase):

    def test_ssp_coverage(self):
        at = bytes([2, 0x02, 0x00])
        self.assertTrue(ssp_covers(at, bytes([0, 0x02])))
        self.assertFalse(ssp_covers(at, bytes([0, 0x01])))
        self.assertFalse(ssp_covers(at, bytes([0, 0, 0, 0x80])))
        self.assertTrue(ssp_covers(at, b"\x00"))
        self.assertTrue(ssp_covers(None, b""))
        self.assertFalse(ssp_covers(None, bytes([0, 0x01])))

    def test_app_permission(self):
        tbs = {"appPermissions": [{"psid": 36, "ssp": ("bitmapSsp", b"\x02\x02\x00")}, {"psid": 37}]}
        self.assertEqual(app_permission(tbs, 36), (True, b"\x02\x02\x00"))
        self.assertEqual(app_permission(tbs, 37), (True, None))
        self.assertEqual(app_permission(tbs, 38), (False, None))

    def test_validity_window(self):
        tbs = {"validityPeriod": {"start": 100, "duration": ("hours", 2)}}
        self.assertEqual(validity_window_us(tbs), (100_000_000, 100_000_000 + 7_200_000_000))
        tbs = {"validityPeriod": {"start": 0, "duration": ("years", 1)}}
        self.assertEqual(validity_window_us(tbs)[1], 31_556_952_000_000)


if __name__ == "__main__":
    unittest.main()
