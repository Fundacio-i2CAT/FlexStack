"""
Certificate validity restrictions (IEEE Std 1609.2-2016, clauses 5.2.3.2.2,
6.4.8 and 6.4.17, as profiled by ETSI TS 103 097 V2.2.1 (2026-03)).

- time: the validityPeriod of a certificate (start + duration);
- region: the circular, rectangular or polygonal region of a certificate;
  a certificate without region inherits the region of its issuer;
- permissions: the appPermissions entry (PSID and SSP) of a certificate.

Identified regions (clauses 6.4.22 to 6.4.26) name countries (UN M.49 codes;
65535 is the EU-27 in ETSI TS 103 097 clause 6), regions and subregions. The
stack ships no border data: the application registers the geometry of the
identifiers it recognises (``register_identified_region``), and the PICS
conformance claim is the list of registered identifiers (TS 103 097 clause 5).
An identifier without geometry cannot be evaluated (None).

Mirrors ``rustflexstack::security::validity``.
"""

from __future__ import annotations

import math
from typing import Dict, List, Optional, Sequence, Tuple

# Seconds per unit of the IEEE 1609.2 Duration choice (clause 6.4.15).
_DURATION_SECONDS = {
    "microseconds": 1e-6,
    "milliseconds": 1e-3,
    "seconds": 1,
    "minutes": 60,
    "hours": 3600,
    "sixtyHours": 216000,
    "years": 31556952,
}
_EARTH_RADIUS_M = 6371000.0
_TENTH_MICRODEGREE = 1e-7
# ETSI TS 103 097 clause 6: UnCountryId 65535 is the European Union
# "27 countries as of 31 January 2020".
EU27_COUNTRY_ID = 65535

# Key: (country,), (country, region) or (country, region, subregion).
RegionKey = Tuple[int, ...]
# Geometry: polygons of (latitude, longitude) vertices in 1/10 µdeg.
_IDENTIFIED_REGIONS: Dict[RegionKey, List[List[Tuple[float, float]]]] = {}


def register_identified_region(country: int, polygons: Sequence[Sequence[Tuple[int, int]]],
                               region: Optional[int] = None,
                               subregion: Optional[int] = None) -> None:
    """
    Register the borders of an identified region so that certificates
    restricted to it can be evaluated. ``polygons`` is a list of polygons
    (several for territories with islands), each a list of (latitude,
    longitude) vertices in 1/10 µdeg. ``region`` is the CountryAndRegions
    value, ``subregion`` the RegionAndSubregions.subregions value.
    """
    if subregion is not None and region is None:
        raise ValueError("a subregion needs its region")
    key = tuple(k for k in (country, region, subregion) if k is not None)
    _IDENTIFIED_REGIONS[key] = [
        [(lat * _TENTH_MICRODEGREE, lon * _TENTH_MICRODEGREE) for lat, lon in polygon]
        for polygon in polygons]


def unregister_identified_region(country: int, region: Optional[int] = None,
                                 subregion: Optional[int] = None) -> None:
    """Forget the geometry of an identified region (no-op if unknown)."""
    _IDENTIFIED_REGIONS.pop(tuple(k for k in (country, region, subregion) if k is not None), None)


def recognized_identified_regions() -> List[RegionKey]:
    """Identifiers the stack can evaluate (the PICS list of recognised values)."""
    return sorted(_IDENTIFIED_REGIONS)


def validity_window_us(to_be_signed: dict) -> Tuple[int, int]:
    """(start, end) of the validityPeriod in TAI microseconds since 2004."""
    period = to_be_signed["validityPeriod"]
    unit, value = period["duration"]
    start_us = period["start"] * 1_000_000
    return start_us, start_us + int(value * _DURATION_SECONDS[unit] * 1_000_000)


def valid_at(certificate, time_us: int) -> bool:
    """
    True when ``time_us`` (Time64, TAI µs since 2004) lies in the validity
    period of the certificate and of every issuer in its chain.
    """
    while certificate is not None and certificate.certificate:
        start, end = validity_window_us(certificate.certificate["toBeSigned"])
        if not start <= time_us <= end:
            return False
        issuer = certificate.issuer
        certificate = issuer if issuer is not certificate else None
    return True


def effective_region(certificate) -> Optional[tuple]:
    """Region of the certificate, or of the closest issuer that has one."""
    while certificate is not None and certificate.certificate:
        region = certificate.certificate["toBeSigned"].get("region")
        if region is not None:
            return region
        issuer = certificate.issuer
        certificate = issuer if issuer is not certificate else None
    return None


def _distance_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance (haversine) in metres between two points in degrees."""
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * _EARTH_RADIUS_M * math.asin(min(1.0, math.sqrt(a)))


def _deg(point: dict) -> Tuple[float, float]:
    return point["latitude"] * _TENTH_MICRODEGREE, point["longitude"] * _TENTH_MICRODEGREE


def _in_rectangle(rect: dict, lat: float, lon: float) -> bool:
    north, west = _deg(rect["northWest"])
    south, east = _deg(rect["southEast"])
    return south <= lat <= north and west <= lon <= east


def _in_polygon(vertices: Sequence[Tuple[float, float]], lat: float, lon: float) -> bool:
    """
    Ray casting in the (longitude, latitude) plane over (lat, lon) vertices in
    degrees; the border counts as inside.
    """
    inside = False
    for i, (lat_i, lon_i) in enumerate(vertices):
        lat_j, lon_j = vertices[i - 1]
        if (lat_i > lat) != (lat_j > lat):
            cross = lon_i + (lat - lat_i) * (lon_j - lon_i) / (lat_j - lat_i)
            if lon == cross:
                return True
            if lon < cross:
                inside = not inside
        elif lat_i == lat_j == lat and min(lon_i, lon_j) <= lon <= max(lon_i, lon_j):
            return True
    return inside


def _key_contains(key: RegionKey, lat: float, lon: float) -> Optional[bool]:
    """
    Whether the position lies in a registered identifier. When the identifier
    itself is not registered, a registered enclosing one (the region of a
    subregion, the country of a region) can still show that the position is
    outside; otherwise None.
    """
    polygons = _IDENTIFIED_REGIONS.get(key)
    if polygons is not None:
        return any(_in_polygon(polygon, lat, lon) for polygon in polygons)
    for length in range(len(key) - 1, 0, -1):
        parent = _IDENTIFIED_REGIONS.get(key[:length])
        if parent is not None and not any(_in_polygon(p, lat, lon) for p in parent):
            return False
    return None


def _identified_keys(entry: tuple) -> List[RegionKey]:
    """Identifiers named by one IdentifiedRegion (clauses 6.4.22 to 6.4.26)."""
    kind, value = entry
    if kind == "countryOnly":
        return [(value,)]
    keys: List[RegionKey] = []
    if kind == "countryAndRegions":
        keys = [(value["countryOnly"], r) for r in value["regions"]]
    elif kind == "countryAndSubregions":
        keys = [(value["countryOnly"], item["region"], sub)
                for item in value["regionAndSubregions"] for sub in item["subregions"]]
    return keys or [()]    # () : unknown alternative or empty list, not evaluable


def identified_region_contains(entries: list, lat: float, lon: float) -> Optional[bool]:
    """
    SequenceOfIdentifiedRegion: inside when any recognised identifier contains
    the position (IEEE 1609.2 allows unrecognised values when the recognised
    ones establish validity); outside when every identifier is recognised and
    none contains it; otherwise None.
    """
    unknown = False
    for entry in entries:
        for key in _identified_keys(entry):
            result = _key_contains(key, lat, lon) if key else None
            if result:
                return True
            unknown = unknown or result is None
    return None if unknown else False


def region_contains(region: Optional[tuple], latitude: int, longitude: int) -> Optional[bool]:
    """
    Whether a position (1/10 µdeg) lies inside a GeographicRegion. True for no
    region (no restriction); None when the region cannot be evaluated
    (identifiedRegion without registered geometry).
    """
    if region is None:
        return True
    lat, lon = latitude * _TENTH_MICRODEGREE, longitude * _TENTH_MICRODEGREE
    kind, value = region
    if kind == "circularRegion":
        c_lat, c_lon = _deg(value["center"])
        return _distance_m(c_lat, c_lon, lat, lon) <= value["radius"]
    if kind == "rectangularRegion":
        return any(_in_rectangle(rect, lat, lon) for rect in value)
    if kind == "polygonalRegion":
        return _in_polygon([_deg(p) for p in value], lat, lon)
    if kind == "identifiedRegion":
        return identified_region_contains(value, lat, lon)
    return None


def location_permitted(certificate, latitude: int, longitude: int) -> bool:
    """
    Region consistency (IEEE 1609.2 clause 5.2.3.2.2): the position lies in the
    effective region of the certificate chain. A region that cannot be
    evaluated is not treated as a violation.
    """
    return region_contains(effective_region(certificate), latitude, longitude) is not False


def app_permission(to_be_signed: dict, psid: int) -> Tuple[bool, Optional[bytes]]:
    """
    (permitted, SSP) for ``psid`` in the appPermissions of a certificate. The
    SSP is the BitmapSsp or opaque octets, or None when the entry has no SSP.
    """
    for entry in to_be_signed.get("appPermissions", []) or []:
        if entry.get("psid") == psid:
            ssp = entry.get("ssp")
            if ssp is None:
                return True, None
            value = ssp[1]
            return True, value if isinstance(value, bytes) else None
    return False, None
