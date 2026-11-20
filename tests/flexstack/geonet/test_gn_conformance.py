"""
GeoNetworking conformance tests: one test per Test Purpose of
ETSI TS 102 871-2 V2.1.1, against ETSI TS 103 836-4-1 V2.2.1 (2026-04) and
TS 103 836-4-2 / -4-3 V2.1.1.

Each test is named after its TP and quotes the TP identifier, so that a search
for the identifier finds it. The IUT is a GeoNetworking router on an injected
clock; the test system sends frames from the ETSI test nodes (clause 4 of
TS 102 871-2) and checks the frames the IUT passes to its link layer, with
their destination link-layer address, and the indications it passes up.

Geometry (north axis, metres from the IUT), after the configurations CF01-CF04:
ItsNodeA 1500 m (out of range), ItsNodeB 400 m and ItsNodeD 200 m (both in the
direction of A, B closer to A), ItsNodeC 400 m south (not in the direction of
A). AREA1: circle of 600 m around the IUT; AREA2: circle of 300 m around B
(contains B and D, not the IUT).

The TPs of the Advanced forwarding algorithm (GBC/AREA/ADV) are not applicable
(removed in Release 2) and TP/GEONW/FDV/SHB/BV-03 (LTE-V2X time
synchronisation) is not implemented.

Mirrors ``rustflexstack::geonet::conformance``.
"""

import math
import unittest
from dataclasses import replace as dataclass_replace
from unittest.mock import Mock

from flexstack.geonet.basic_header import LT, BasicHeader
from flexstack.geonet.common_header import CommonHeader
from flexstack.geonet.dcc_net import DccNet, LocTexG5
from flexstack.geonet.gbc_extended_header import GBCExtendedHeader
from flexstack.geonet.gn_address import MID, ST, GNAddress
from flexstack.geonet.guc_extended_header import GUCExtendedHeader
from flexstack.geonet.ls_extended_header import LSReplyExtendedHeader, LSRequestExtendedHeader
from flexstack.geonet.mib import (
    MIB,
    AreaForwardingAlgorithm,
    GnIfType,
    LocalGnAddrConfMethod,
    NonAreaForwardingAlgorithm,
)
from flexstack.geonet.position_vector import TST, LongPositionVector, ShortPositionVector
from flexstack.geonet.router import Router
from flexstack.geonet.service_access_point import (
    Area,
    CommonNH,
    GeoAnycastHST,
    GeoBroadcastHST,
    GNDataRequest,
    HeaderSubType,
    HeaderType,
    LocationServiceHST,
    PacketTransportType,
    TopoBroadcastHST,
    TrafficClass,
)
from flexstack.geonet.tsb_extended_header import TSBExtendedHeader
from flexstack.linklayer.link_layer import LinkLayer
from flexstack.utils.time_service import TimeService

EGO_LAT, EGO_LON = 421255850, 27601710
METRES_PER_DEGREE = 6371000 * math.pi / 180
IUT, A, B, C, D, FAR = 0x01, 0x0A, 0x0B, 0x0C, 0x0D, 0x0F


def north(metres: float) -> int:
    return EGO_LAT + round(metres / METRES_PER_DEGREE * 1e7)


POS = {A: north(1500), B: north(400), C: north(-400), D: north(200), FAR: north(-1100), IUT: EGO_LAT}
AREA1 = Area(latitude=EGO_LAT, longitude=EGO_LON, a=600, b=600, angle=0)
AREA2 = Area(latitude=POS[B], longitude=EGO_LON, a=300, b=300, angle=0)
AREA_A = Area(latitude=POS[A], longitude=EGO_LON, a=200, b=200, angle=0)     # "addressed to ItsNodeA"
BIG_AREA = Area(latitude=POS[B], longitude=EGO_LON, a=2000, b=2000, angle=0)  # 12.6 km2 > itsGnMaxGeoAreaSize
DEFAULT_LT_MS = 60_000


def addr(n: int) -> GNAddress:
    return GNAddress(st=ST.PASSENGER_CAR, mid=MID(bytes([0x02, 0, 0, 0, 0, n])))


def mac(n: int) -> bytes:
    return addr(n).mid.mid


def lpv(n: int, lat: int | None = None, pai: bool = True, tst_offset_ms: int = 0) -> LongPositionVector:
    return LongPositionVector(
        gn_addr=addr(n), tst=TST.set_in_normal_timestamp_seconds(TimeService.time() + tst_offset_ms / 1000),
        latitude=POS[n] if lat is None else lat, longitude=EGO_LON, pai=pai)


def spv(n: int) -> ShortPositionVector:
    return ShortPositionVector(gn_addr=addr(n), tst=TST.set_in_normal_timestamp_seconds(TimeService.time()),
                               latitude=POS[n], longitude=EGO_LON)


def lt_ms(ms: int) -> int:
    """Lifetime ``ms`` as the LT field encodes it."""
    return LT().set_value_in_millis(ms).get_value_in_millis()


def cbf_timeout_ms(distance_m: float, mib: MIB) -> float:
    """
    TO_CBF_WO_ACC of TS 103 836-4-1 V2.2.1 clauses E.3.2.2-E.3.2.3 (and F.3.2.2-F.3.2.3):
    progress or distance D in segment SEGN = max(1, ceil(D / DIST_MAX)),
    TO = TO_CBF_MAX x SEGN + (TO_CBF_MIN - TO_CBF_MAX) / DIST_MAX x (D - DIST_MAX x (SEGN - 1)).
    """
    dist_max = mib.itsGnDefaultMaxCommunicationRange
    segn = max(1, math.ceil(distance_m / dist_max))
    slope = (mib.itsGnCbfMinTime - mib.itsGnCbfMaxTime) / dist_max
    return mib.itsGnCbfMaxTime * segn + slope * (distance_m - dist_max * (segn - 1))


# -- Test system: frames from the test nodes ------------------------------------------

def _packet(ht, hst, ext: bytes, payload: bytes = b"payload", rhl: int = 5, mhl: int = 10,
            scf: bool = False, nh=CommonNH.BTP_B, version: int = 1, lifetime_ms: int | None = None) -> bytes:
    basic = BasicHeader.initialize_with_mib(MIB()).set_rhl(rhl).set_version(version)
    if lifetime_ms is not None:
        basic = basic.set_lt(LT().set_value_in_millis(lifetime_ms))
    common = CommonHeader(nh=nh, ht=ht, hst=hst, tc=TrafficClass(scf=scf), mhl=mhl, pl=len(payload))
    return basic.encode_to_bytes() + common.encode_to_bytes() + ext + payload


def beacon(n: int, pai: bool = True, lat: int | None = None) -> bytes:
    basic = BasicHeader.initialize_with_mib(MIB()).set_rhl(1)
    common = CommonHeader(ht=HeaderType.BEACON, mhl=1)
    return basic.encode_to_bytes() + common.encode_to_bytes() + lpv(n, lat, pai).encode()


def shb(so: LongPositionVector, payload: bytes = b"payload", mco: bytes = bytes(4), version: int = 1) -> bytes:
    return _packet(HeaderType.TSB, TopoBroadcastHST.SINGLE_HOP, so.encode() + mco, payload,
                   rhl=1, mhl=1, version=version)


def tsb(so: LongPositionVector, sn: int, rhl: int = 5, mhl: int = 10, payload: bytes = b"tsb", **kw) -> bytes:
    return _packet(HeaderType.TSB, TopoBroadcastHST.MULTI_HOP, TSBExtendedHeader(sn=sn, so_pv=so).encode(),
                   payload, rhl=rhl, mhl=mhl, **kw)


def guc(so: LongPositionVector, sn: int, de: ShortPositionVector, rhl: int = 5, mhl: int = 10,
        payload: bytes = b"guc", **kw) -> bytes:
    return _packet(HeaderType.GEOUNICAST, HeaderSubType.UNSPECIFIED,
                   GUCExtendedHeader(sn=sn, so_pv=so, de_pv=de).encode(), payload, rhl=rhl, mhl=mhl, **kw)


def gbc(so: LongPositionVector, sn: int, area: Area, rhl: int = 5, mhl: int = 10, anycast: bool = False,
        payload: bytes = b"gbc", **kw) -> bytes:
    ext = GBCExtendedHeader(sn=sn, so_pv=so, latitude=area.latitude, longitude=area.longitude,
                            a=area.a, b=area.b, angle=area.angle)
    ht, hst = ((HeaderType.GEOANYCAST, GeoAnycastHST.GEOANYCAST_CIRCLE) if anycast
               else (HeaderType.GEOBROADCAST, GeoBroadcastHST.GEOBROADCAST_CIRCLE))
    return _packet(ht, hst, ext.encode(), payload, rhl=rhl, mhl=mhl, **kw)


def ls_request(so: LongPositionVector, sn: int, sought: GNAddress, rhl: int = 5) -> bytes:
    ext = LSRequestExtendedHeader(sn=sn, so_pv=so, request_gn_addr=sought)
    return _packet(HeaderType.LS, LocationServiceHST.LS_REQUEST, ext.encode(), b"", rhl=rhl, nh=CommonNH.ANY)


def ls_reply(so: LongPositionVector, sn: int, de: ShortPositionVector, rhl: int = 5) -> bytes:
    ext = LSReplyExtendedHeader(sn=sn, so_pv=so, de_pv=de)
    return _packet(HeaderType.LS, LocationServiceHST.LS_REPLY, ext.encode(), b"", rhl=rhl, nh=CommonNH.ANY)


class _Frame:
    """A frame the IUT passed to its link layer, decoded."""

    def __init__(self, raw: bytes, destination: bytes | None, at: float):
        self.raw, self.destination, self.at = raw, destination, at
        self.basic = BasicHeader.decode_from_bytes(raw[0:4])
        self.common = CommonHeader.decode_from_bytes(raw[4:12])
        body, ht = raw[12:], self.common.ht
        self.ext = None
        self.mco = None
        if ht == HeaderType.BEACON:
            self.so_pv, size = LongPositionVector.decode(body[0:24]), 24
        elif ht == HeaderType.TSB and self.common.hst == TopoBroadcastHST.SINGLE_HOP:
            self.so_pv, self.mco, size = LongPositionVector.decode(body[0:24]), body[24:28], 28
        elif ht == HeaderType.TSB:
            self.ext, size = TSBExtendedHeader.decode(body[0:28]), 28
        elif ht == HeaderType.GEOUNICAST:
            self.ext, size = GUCExtendedHeader.decode(body[0:48]), 48
        elif ht in (HeaderType.GEOBROADCAST, HeaderType.GEOANYCAST):
            self.ext, size = GBCExtendedHeader.decode(body[0:44]), 44
        elif self.common.hst == LocationServiceHST.LS_REQUEST:
            self.ext, size = LSRequestExtendedHeader.decode(body[0:36]), 36
        else:
            self.ext, size = LSReplyExtendedHeader.decode(body[0:48]), 48
        if self.ext is not None:
            self.so_pv = self.ext.so_pv
        self.payload = body[size:]

    @property
    def is_ls_request(self) -> bool:
        return self.common.ht == HeaderType.LS and self.common.hst == LocationServiceHST.LS_REQUEST


class _Iut:
    """The IUT: a GN router on an injected clock, its link layer and upper layer captured."""

    def __init__(self, beacons: bool = False, dcc_net: DccNet | None = None, **mib):
        mib.setdefault("itsGnLocalGnAddr", addr(IUT))
        if not beacons:
            mib.setdefault("itsGnBeaconServiceRetransmitTimer", 0)
        self.now: float = 0
        self.mib = MIB(**mib)
        self.router = Router(self.mib, clock=lambda: self.now, dcc_net=dcc_net)
        self.router.ego_position_vector = LongPositionVector(
            gn_addr=self.mib.itsGnLocalGnAddr, tst=TST.set_in_normal_timestamp_seconds(TimeService.time()),
            latitude=EGO_LAT, longitude=EGO_LON, pai=True)
        self.frames: list = []
        self.router.link_layer = Mock(spec=LinkLayer)
        self.router.link_layer.send.side_effect = \
            lambda raw, destination=None: self.frames.append(_Frame(raw, destination, self.now))
        self.router.link_layer.media_dependent_mid.return_value = self.mib.itsGnLocalGnAddr.mid
        self.indications: list = []
        self.router.register_indication_callback(self.indications.append)

    # lower tester
    def receive(self, packet: bytes, sender: int) -> None:
        self.router.gn_data_indicate(packet, sender_ll_address=mac(sender))

    def beacons_from(self, *nodes: int, pai: bool = True) -> None:
        for n in nodes:
            self.receive(beacon(n, pai), n)

    # time
    def at(self, ms: float) -> None:
        """Advance the clock to ``ms``, firing every timer due on the way."""
        while True:
            deadline = self.router.next_deadline()
            if deadline is None or deadline > ms:
                break
            self.now = max(self.now, deadline)
            self.router.tick()
        self.now = ms

    # upper tester
    def request(self, ht, hst, payload: bytes = b"req", scf: bool = False, **kw):
        return self.router.gn_data_request(GNDataRequest(
            upper_protocol_entity=CommonNH.BTP_B, packet_transport_type=PacketTransportType(
                header_type=ht, header_subtype=hst),
            traffic_class=TrafficClass(scf=scf), data=payload, length=len(payload), **kw))

    def request_shb(self, payload: bytes = b"shb"):
        return self.request(HeaderType.TSB, TopoBroadcastHST.SINGLE_HOP, payload)

    def request_tsb(self, scf: bool = False):
        return self.request(HeaderType.TSB, TopoBroadcastHST.MULTI_HOP, b"tsb", scf)

    def request_gbc(self, area: Area = AREA1, scf: bool = False, anycast: bool = False):
        ht, hst = ((HeaderType.GEOANYCAST, GeoAnycastHST.GEOANYCAST_CIRCLE) if anycast
                   else (HeaderType.GEOBROADCAST, GeoBroadcastHST.GEOBROADCAST_CIRCLE))
        return self.request(ht, hst, b"gbc", scf, area=area)

    def request_guc(self, de: int, scf: bool = False, payload: bytes = b"guc", lifetime_s: float | None = None):
        return self.request(HeaderType.GEOUNICAST, HeaderSubType.UNSPECIFIED, payload, scf, destination=addr(de),
                            max_packet_lifetime=lifetime_s)

    # observations
    def sent(self, ht=None) -> list:
        return [f for f in self.frames if ht is None or f.common.ht == ht]

    def ls_requests(self) -> list:
        return [f for f in self.frames if f.is_ls_request]


class TestGnFormatting(unittest.TestCase):
    """TP/GEONW/FDV: header formatting and data validity (clauses 9, 10.3.2-10.3.4)."""

    def test_tp_geonw_fdv_bah_bv_01(self):
        """TP/GEONW/FDV/BAH/BV-01: a GBC carries version = itsGnProtocolVersion and
        RHL = itsGnDefaultHopLimit in its Basic Header."""
        iut = _Iut()
        iut.beacons_from(B)
        iut.request_gbc(AREA1)
        frame = iut.sent(HeaderType.GEOBROADCAST)[0]
        self.assertEqual(frame.basic.version, iut.mib.itsGnProtocolVersion)
        self.assertEqual(frame.basic.rhl, iut.mib.itsGnDefaultHopLimit)

    def test_tp_geonw_fdv_bah_bi_02(self):
        """TP/GEONW/FDV/BAH/BI-02: an SHB with a version other than itsGnProtocolVersion is
        discarded (the same SHB with the right version is passed up)."""
        iut = _Iut()
        iut.receive(shb(lpv(B), b"v1"), B)
        self.assertEqual(len(iut.indications), 1)
        iut.receive(shb(lpv(B), b"v2", version=2), B)
        self.assertEqual(len(iut.indications), 1)

    def test_tp_geonw_fdv_coh_bv_01(self):
        """TP/GEONW/FDV/COH/BV-01: a Beacon has HT = 1 (BEACON), HST = 0 and PL = 0."""
        iut = _Iut(beacons=True)
        iut.at(iut.router.next_deadline())
        frame = iut.sent(HeaderType.BEACON)[0]
        self.assertEqual(frame.common.hst.value, 0)
        self.assertEqual(frame.common.pl, 0)

    def test_tp_geonw_fdv_coh_bv_02(self):
        """TP/GEONW/FDV/COH/BV-02: an SHB has HT = 5 (TSB), HST = 0 (SINGLE_HOP), MHL = 1
        and PL = length of the payload it carries."""
        iut = _Iut()
        iut.request_shb(b"x" * 37)
        frame = iut.sent(HeaderType.TSB)[0]
        self.assertEqual(frame.common.hst, TopoBroadcastHST.SINGLE_HOP)
        self.assertEqual(frame.common.mhl, 1)
        self.assertEqual(frame.common.pl, 37)
        self.assertEqual(frame.payload, b"x" * 37)

    def test_tp_geonw_fdv_coh_bv_03(self):
        """TP/GEONW/FDV/COH/BV-03: a GBC has Flags = itsGnIsMobile and MHL = itsGnDefaultHopLimit."""
        iut = _Iut()
        iut.beacons_from(B)
        iut.request_gbc(AREA1)
        frame = iut.sent(HeaderType.GEOBROADCAST)[0]
        self.assertEqual(frame.common.flags >> 7, iut.mib.itsGnIsMobile.value)
        self.assertEqual(frame.common.mhl, iut.mib.itsGnDefaultHopLimit)

    def test_tp_geonw_fdv_coh_bo_04(self):
        """TP/GEONW/FDV/COH/BO-04: a TSB with RHL > MHL is discarded (not forwarded nor passed up)."""
        iut = _Iut()
        iut.beacons_from(D, B)
        iut.receive(tsb(lpv(C), 1, rhl=5, mhl=3), C)
        self.assertEqual(iut.sent(HeaderType.TSB), [])
        self.assertEqual(iut.indications, [])

    def test_tp_geonw_fdv_bea_bv_01(self):
        """TP/GEONW/FDV/BEA/BV-01: a Beacon has HT = BEACON, HST = 0, NH = 0 and the IUT LPV as SO PV."""
        iut = _Iut(beacons=True)
        iut.at(iut.router.next_deadline())
        frame = iut.sent(HeaderType.BEACON)[0]
        self.assertEqual(frame.common.hst.value, 0)
        self.assertEqual(frame.common.nh, CommonNH.ANY)
        ego = iut.router.ego_position_vector
        self.assertEqual((frame.so_pv.gn_addr, frame.so_pv.latitude, frame.so_pv.longitude),
                         (ego.gn_addr, ego.latitude, ego.longitude))

    def test_tp_geonw_fdv_bea_bv_02(self):
        """TP/GEONW/FDV/BEA/BV-02: the Beacon SO PV GN_ADDR is itsGnLocalGnAddr, with the ITS-S type in ST."""
        iut = _Iut(beacons=True)
        iut.at(iut.router.next_deadline())
        so = iut.sent(HeaderType.BEACON)[0].so_pv.gn_addr
        self.assertEqual(so, iut.mib.itsGnLocalGnAddr)
        self.assertEqual(so.st, ST.PASSENGER_CAR)

    def _beacon_after_fix(self, time: str):
        iut = _Iut(beacons=True)
        iut.router.refresh_ego_position_vector(
            {"lat": 41.3, "lon": 2.1, "speed": 0.0, "track": 0.0, "time": time})
        iut.at(iut.router.next_deadline())
        return iut.sent(HeaderType.BEACON)[0].so_pv

    def test_tp_geonw_fdv_bea_bv_03(self):
        """TP/GEONW/FDV/BEA/BV-03: the Beacon SO PV is the latest position of the IUT."""
        so = self._beacon_after_fix("2026-11-17T10:00:00.250Z")
        self.assertEqual((so.latitude, so.longitude), (413000000, 21000000))

    def test_tp_geonw_fdv_bea_bv_04(self):
        """TP/GEONW/FDV/BEA/BV-04: the Beacon SO PV TST is the acquisition time of the position
        (milliseconds included)."""
        so = self._beacon_after_fix("2026-11-17T10:00:00.250Z")
        from datetime import datetime, timezone
        acquisition = datetime(2026, 11, 17, 10, 0, 0, 250000, tzinfo=timezone.utc).timestamp()
        self.assertEqual(so.tst.msec, TST.set_in_normal_timestamp_seconds(acquisition).msec)

    def test_tp_geonw_fdv_bea_bv_05(self):
        """TP/GEONW/FDV/BEA/BV-05: over ITS-G5 the Beacon SO PV MID is the 48-bit MAC address of
        the interface (TS 103 836-4-2 clause 6.1); a GN address with another MID is reported."""
        interface_mac = bytes([0x02, 0x11, 0x22, 0x33, 0x44, 0x55])
        local = GNAddress(st=ST.PASSENGER_CAR, mid=MID.from_its_g5_mac(interface_mac))
        iut = _Iut(beacons=True, itsGnIfType=GnIfType.ITS_G5, itsGnLocalGnAddr=local)
        iut.router.link_layer.media_dependent_mid.return_value = MID(interface_mac)
        self.assertTrue(iut.router.media_dependent_address_ok())
        iut.at(iut.router.next_deadline())
        self.assertEqual(iut.sent(HeaderType.BEACON)[0].so_pv.gn_addr.mid.mid, interface_mac)
        iut.router.link_layer.media_dependent_mid.return_value = MID(bytes(6))
        self.assertFalse(iut.router.media_dependent_address_ok())

    def test_tp_geonw_fdv_bea_bv_06(self):
        """TP/GEONW/FDV/BEA/BV-06: over LTE-V2X the Beacon SO PV MID carries the Layer 2 ID in
        octets 2-4 and 0 in octets 5-7 (TS 103 836-4-3 clause 5.2)."""
        local = GNAddress(st=ST.PASSENGER_CAR, mid=MID.from_lte_v2x_l2_id(0xABCDEF))
        iut = _Iut(beacons=True, itsGnIfType=GnIfType.LTE_V2X, itsGnLocalGnAddr=local)
        iut.router.link_layer.media_dependent_mid.return_value = None
        self.assertTrue(iut.router.media_dependent_address_ok())
        iut.at(iut.router.next_deadline())
        mid = iut.sent(HeaderType.BEACON)[0].so_pv.gn_addr.mid.mid
        self.assertEqual(mid, bytes([0xAB, 0xCD, 0xEF, 0, 0, 0]))

    def test_tp_geonw_fdv_guc_bv_01(self):
        """TP/GEONW/FDV/GUC/BV-01: a GUC to B has HT = 2, HST = 0, DE PV = position of B and
        SO PV = position of the IUT."""
        iut = _Iut()
        iut.beacons_from(B)
        iut.request_guc(B)
        frame = iut.sent(HeaderType.GEOUNICAST)[0]
        self.assertEqual(frame.common.hst.value, 0)
        self.assertEqual((frame.ext.de_pv.gn_addr, frame.ext.de_pv.latitude), (addr(B), POS[B]))
        self.assertEqual((frame.so_pv.gn_addr, frame.so_pv.latitude), (addr(IUT), EGO_LAT))

    def test_tp_geonw_fdv_gbc_bv_01(self):
        """TP/GEONW/FDV/GBC/BV-01: a GBC has HT = 4 and SO PV = position of the IUT."""
        iut = _Iut()
        iut.beacons_from(B)
        iut.request_gbc(AREA1)
        frame = iut.sent(HeaderType.GEOBROADCAST)[0]
        self.assertEqual((frame.so_pv.gn_addr, frame.so_pv.latitude), (addr(IUT), EGO_LAT))

    def test_tp_geonw_fdv_gac_bv_01(self):
        """TP/GEONW/FDV/GAC/BV-01: a GAC has HT = 3 and SO PV = position of the IUT."""
        iut = _Iut()
        iut.beacons_from(B)
        iut.request_gbc(AREA1, anycast=True)
        frame = iut.sent(HeaderType.GEOANYCAST)[0]
        self.assertEqual((frame.so_pv.gn_addr, frame.so_pv.latitude), (addr(IUT), EGO_LAT))

    def test_tp_geonw_fdv_shb_bv_01(self):
        """TP/GEONW/FDV/SHB/BV-01: an SHB has HT = TSB, HST = SINGLE_HOP, MHL = 1 and the IUT LPV."""
        iut = _Iut()
        iut.beacons_from(B)
        iut.request_shb()
        frame = iut.sent(HeaderType.TSB)[0]
        self.assertEqual((frame.common.hst, frame.common.mhl), (TopoBroadcastHST.SINGLE_HOP, 1))
        self.assertEqual((frame.so_pv.gn_addr, frame.so_pv.latitude), (addr(IUT), EGO_LAT))

    def test_tp_geonw_fdv_shb_bv_02(self):
        """TP/GEONW/FDV/SHB/BV-02: with DCC_NET over ITS-G5 the SHB carries the DCC-MCO field:
        CBR_L_0_Hop, CBR_L_1_Hop and the transmit power (TS 103 836-4-2 clauses 6.3.3, 7.2.1)."""
        dcc = DccNet(tx_power_dbm=20, rng=lambda: 0.0)
        iut = _Iut(dcc_net=dcc, itsGnIfType=GnIfType.ITS_G5)
        iut.beacons_from(B)
        iut.receive(shb(lpv(B), mco=bytes([127, 64, 10, 0])), B)     # CBR_R_0_Hop of B = 127/255
        iut.at(0)                                                      # T_Trig: CBR_L_1_Hop from B
        dcc.report_local_cbr(0.3)
        iut.request_shb()
        self.assertEqual(iut.sent(HeaderType.TSB)[-1].mco, bytes([76, 127, 20, 0]))

    def test_tp_geonw_fdv_tsb_bv_01(self):
        """TP/GEONW/FDV/TSB/BV-01: a TSB has HT = 5, HST = 1 (MULTI_HOP) and SO PV = position of the IUT."""
        iut = _Iut()
        iut.beacons_from(B)
        iut.request_tsb()
        frame = iut.sent(HeaderType.TSB)[0]
        self.assertEqual(frame.common.hst, TopoBroadcastHST.MULTI_HOP)
        self.assertEqual((frame.so_pv.gn_addr, frame.so_pv.latitude), (addr(IUT), EGO_LAT))


# LOT/BV-03-X: (variant, node, packet originated by the node, sender)
def _lot_messages(node_pv):
    return {
        "01": (B, lambda: beacon(B), B),
        "02": (A, lambda: guc(node_pv(A), 1, spv(IUT)), B),
        "03": (A, lambda: gbc(node_pv(A), 1, AREA1, anycast=True), B),
        "04": (A, lambda: gbc(node_pv(A), 1, AREA1), B),
        "05": (A, lambda: tsb(node_pv(A), 1), B),
        "06": (B, lambda: shb(node_pv(B)), B),
        "07": (A, lambda: ls_request(node_pv(A), 1, addr(IUT)), B),
        "08": (A, lambda: ls_reply(node_pv(A), 1, spv(IUT)), B),
    }


class TestGnLocationTable(unittest.TestCase):
    """TP/GEONW/PON/LOT, LPV, SQN, GNA: location table, local position vector, sequence
    number, GN address (clauses 8.2-8.4, 10.2.1, 10.3)."""

    def _guc_to(self, iut, n):
        iut.request_guc(n)
        self.assertEqual(iut.ls_requests(), [])
        return iut.sent(HeaderType.GEOUNICAST)[-1]

    def test_tp_geonw_pon_lot_bv_01(self):
        """TP/GEONW/PON/LOT/BV-01: a Beacon creates the LocTE of B: a GUC to B needs no LS and
        carries the Beacon SO PV as DE PV."""
        iut = _Iut()
        iut.beacons_from(B)
        frame = self._guc_to(iut, B)
        self.assertEqual((frame.ext.de_pv.gn_addr, frame.ext.de_pv.latitude), (addr(B), POS[B]))

    def test_tp_geonw_pon_lot_bv_02(self):
        """TP/GEONW/PON/LOT/BV-02: an LS Reply creates the LocTE of A: after the first GUC, a
        second GUC to A needs no LS and carries the LS Reply SO PV as DE PV."""
        iut = _Iut()
        iut.beacons_from(B)
        iut.request_guc(A)
        self.assertEqual(len(iut.ls_requests()), 1)
        iut.at(100)
        iut.receive(ls_reply(lpv(A), 1, spv(IUT)), B)
        self.assertEqual(len(iut.sent(HeaderType.GEOUNICAST)), 1)
        iut.request_guc(A)
        self.assertEqual(len(iut.ls_requests()), 1)
        frame = iut.sent(HeaderType.GEOUNICAST)[-1]
        self.assertEqual(len(iut.sent(HeaderType.GEOUNICAST)), 2)
        self.assertEqual((frame.ext.de_pv.gn_addr, frame.ext.de_pv.latitude), (addr(A), POS[A]))

    def test_tp_geonw_pon_lot_bv_03_x(self):
        """TP/GEONW/PON/LOT/BV-03-X (variants 01-08): a Beacon, GUC, GAC, GBC, TSB, SHB, LS
        Request or LS Reply originated by NODE creates its LocTE: a GUC to NODE needs no LS and
        carries the SO PV of the message as DE PV."""
        for variant, (node, message, sender) in _lot_messages(lambda n: lpv(n)).items():
            with self.subTest(variant=variant):
                iut = _Iut()
                if node == A:
                    iut.beacons_from(B)
                iut.receive(message(), sender)
                iut.request_guc(node)
                self.assertEqual(iut.ls_requests(), [])
                frame = iut.sent(HeaderType.GEOUNICAST)[-1]
                self.assertEqual((frame.ext.de_pv.gn_addr, frame.ext.de_pv.latitude), (addr(node), POS[node]))

    def test_tp_geonw_pon_lot_bv_04(self):
        """TP/GEONW/PON/LOT/BV-04: without Beacons from B for itsGnLifetimeLocTE the LocTE expires:
        a GUC to B starts an LS Request for B (MID of B, other bits 0)."""
        iut = _Iut()
        iut.beacons_from(B)
        iut.at(iut.mib.itsGnLifetimeLocTE * 1000 + 1)
        iut.request_guc(B)
        requests = iut.ls_requests()
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0].ext.request_gn_addr, GNAddress(mid=addr(B).mid))

    def test_tp_geonw_pon_lot_bv_05_x(self):
        """TP/GEONW/PON/LOT/BV-05-X (variants 01-07): a GUC, GAC, GBC, TSB, SHB, LS Request or LS
        Reply from B with an older TST and another position does not update the LocTE: the GUC
        to B carries the Beacon position."""
        older = north(450)
        messages = {
            "01": lambda pv: guc(pv, 1, spv(IUT)),
            "02": lambda pv: gbc(pv, 1, AREA1, anycast=True),
            "03": lambda pv: gbc(pv, 1, AREA1),
            "04": lambda pv: tsb(pv, 1),
            "05": lambda pv: shb(pv),
            "06": lambda pv: ls_request(pv, 1, addr(IUT)),
            "07": lambda pv: ls_reply(pv, 1, spv(IUT)),
        }
        for variant, message in messages.items():
            with self.subTest(variant=variant):
                iut = _Iut()
                iut.beacons_from(B)
                iut.receive(message(lpv(B, lat=older, tst_offset_ms=-1000)), B)
                frame = self._guc_to(iut, B)
                self.assertEqual(frame.ext.de_pv.latitude, POS[B])

    def test_tp_geonw_pon_lot_bv_06(self):
        """TP/GEONW/PON/LOT/BV-06: with DCC_NET, an SHB from B (older TST, other position) updates
        the LocTEX-G5 of B with its DCC-MCO, while the LocTE keeps the Beacon position; no LS is
        needed for B. The TP's expected SHB (SO PV and DCC-MCO equal to B's) cannot hold for an
        IUT's own SHB; the IUT's SHB carries its own DCC-MCO (TS 103 836-4-2 clauses 6.2, 7.2)."""
        dcc = DccNet(tx_power_dbm=20, rng=lambda: 0.0)
        iut = _Iut(dcc_net=dcc, itsGnIfType=GnIfType.ITS_G5)
        iut.beacons_from(B)
        iut.receive(shb(lpv(B, lat=north(450), tst_offset_ms=-1000), mco=bytes([102, 51, 15, 0])), B)
        loctex: LocTexG5 = dcc.loctex[addr(B)]
        self.assertEqual((round(loctex.cbr_r_0_hop * 255), round(loctex.cbr_r_1_hop * 255),
                          loctex.tx_power_dbm), (102, 51, 15))
        self.assertEqual(iut.router.location_table.get_entry(addr(B)).position_vector.latitude, POS[B])
        iut.request_shb()
        self.assertEqual(iut.ls_requests(), [])
        self.assertEqual(iut.sent(HeaderType.TSB)[-1].mco, dcc.dcc_mco())

    def test_tp_geonw_pon_lot_bv_07(self):
        """TP/GEONW/PON/LOT/BV-07: without DCC_NET, after an SHB with a DCC-MCO from B the IUT's
        SHB carries a DCC-MCO with CBR_L_0_Hop, CBR_L_1_Hop and transmit power 0."""
        iut = _Iut(itsGnIfType=GnIfType.ITS_G5)
        iut.beacons_from(B)
        iut.receive(shb(lpv(B, lat=north(450), tst_offset_ms=-1000), mco=bytes([102, 51, 15, 0])), B)
        iut.request_shb()
        self.assertEqual(iut.ls_requests(), [])
        self.assertEqual(iut.sent(HeaderType.TSB)[-1].mco, bytes(4))

    def test_tp_geonw_pon_lpv_bv_01(self):
        """TP/GEONW/PON/LPV/BV-01: after a position change the next Beacon carries the new position."""
        iut = _Iut(beacons=True)
        iut.at(iut.router.next_deadline())
        iut.router.refresh_ego_position_vector(
            {"lat": 41.4, "lon": 2.2, "speed": 0.0, "track": 0.0, "time": "2026-11-17T10:00:00Z"})
        iut.at(iut.router.next_deadline())
        so = iut.sent(HeaderType.BEACON)[-1].so_pv
        self.assertEqual((so.latitude, so.longitude), (414000000, 22000000))

    def test_tp_geonw_pon_sqn_bv_01(self):
        """TP/GEONW/PON/SQN/BV-01: the first GBC has SN 0."""
        iut = _Iut()
        iut.beacons_from(B)
        iut.request_gbc(AREA1)
        self.assertEqual(iut.sent(HeaderType.GEOBROADCAST)[0].ext.sn, 0)

    def test_tp_geonw_pon_sqn_bv_02(self):
        """TP/GEONW/PON/SQN/BV-02: the next GBC has SN1 + 1."""
        iut = _Iut()
        iut.beacons_from(B)
        iut.request_gbc(AREA1)
        iut.request_gbc(AREA1)
        first, second = iut.sent(HeaderType.GEOBROADCAST)[:2]
        self.assertEqual(second.ext.sn, first.ext.sn + 1)

    def test_tp_geonw_pon_gna_bv_01(self):
        """TP/GEONW/PON/GNA/BV-01: with auto address configuration the Beacon SO PV GN_ADDR is
        itsGnLocalGnAddr."""
        iut = _Iut(beacons=True, itsGnLocalGnAddrConfMethod=LocalGnAddrConfMethod.AUTO)
        iut.at(iut.router.next_deadline())
        self.assertEqual(iut.sent(HeaderType.BEACON)[0].so_pv.gn_addr, iut.mib.itsGnLocalGnAddr)

    def test_tp_geonw_pon_gna_bv_02(self):
        """TP/GEONW/PON/GNA/BV-02: duplicate address detection: after an SHB from B with the IUT's
        GN_ADDR, the next SHB of the IUT uses another GN_ADDR (clause 10.2.1.5)."""
        iut = _Iut(itsGnLocalGnAddrConfMethod=LocalGnAddrConfMethod.AUTO)
        changes = []
        iut.router.address_change_callback = changes.append
        iut.request_shb()
        first = iut.sent(HeaderType.TSB)[-1].so_pv.gn_addr
        iut.receive(shb(dataclass_replace(lpv(B), gn_addr=first)), B)
        iut.request_shb()
        second = iut.sent(HeaderType.TSB)[-1].so_pv.gn_addr
        self.assertNotEqual(second, first)
        self.assertEqual(changes, [second])
        self.assertEqual(iut.router.mib.itsGnLocalGnAddr, second)
        self.assertEqual(second.mid.mid[0] & 0x03, 0x02)          # unicast, locally administered


class TestGnLocationService(unittest.TestCase):
    """TP/GEONW/PON/LOS and TP/GEONW/CAP/LOS: Location Service (clauses 8.5.3, 10.3.7)."""

    def test_tp_geonw_pon_los_bv_01(self):
        """TP/GEONW/PON/LOS/BV-01: a GUC to an unknown A starts an LS Request (HT = LS, HST =
        LS_REQUEST, NH = 0) for the MID of A with the other bits 0."""
        iut = _Iut()
        iut.request_guc(A)
        request = iut.ls_requests()[0]
        self.assertEqual(request.common.nh, CommonNH.ANY)
        self.assertEqual(request.ext.request_gn_addr, GNAddress(mid=addr(A).mid))
        self.assertEqual(request.ext.request_gn_addr.encode()[0:2], b"\x00\x00")

    def test_tp_geonw_pon_los_bv_02(self):
        """TP/GEONW/PON/LOS/BV-02: a second GUC to A while the LS is active sends no second LS Request."""
        iut = _Iut()
        iut.request_guc(A)
        iut.at(500)
        iut.request_guc(A)
        self.assertEqual(len(iut.ls_requests()), 1)

    def test_tp_geonw_pon_los_bv_03(self):
        """TP/GEONW/PON/LOS/BV-03: on the LS Reply the buffered GUC is sent with LT = default LT -
        waiting time."""
        iut = _Iut()
        iut.beacons_from(B)
        iut.request_guc(A, scf=True)
        iut.at(500)
        iut.receive(ls_reply(lpv(A), 1, spv(IUT)), B)
        frame = iut.sent(HeaderType.GEOUNICAST)[0]
        self.assertEqual(frame.basic.lt.get_value_in_millis(), lt_ms(DEFAULT_LT_MS - 500))

    def test_tp_geonw_pon_los_bv_04(self):
        """TP/GEONW/PON/LOS/BV-04: the LS buffer is FIFO: PL1 then PL2 after the LS Reply."""
        iut = _Iut()
        iut.beacons_from(B)
        iut.request_guc(A, scf=True, payload=b"PL1")
        iut.request_guc(A, scf=True, payload=b"PL2")
        iut.at(200)
        iut.receive(ls_reply(lpv(A), 1, spv(IUT)), B)
        self.assertEqual([f.payload for f in iut.sent(HeaderType.GEOUNICAST)], [b"PL1", b"PL2"])

    def test_tp_geonw_pon_los_bv_05(self):
        """TP/GEONW/PON/LOS/BV-05: GUCs whose LT expired in the LS buffer are discarded."""
        iut = _Iut()
        for payload in (b"PL1", b"PL2"):
            iut.request_guc(A, scf=True, payload=payload, lifetime_s=0.5)
        iut.at(800)
        iut.receive(ls_reply(lpv(A), 1, spv(IUT)), B)
        self.assertEqual(iut.sent(HeaderType.GEOUNICAST), [])

    def test_tp_geonw_pon_los_ti_06(self):
        """TP/GEONW/PON/LOS/TI-06: without LS Reply the LS Request is retransmitted when
        itsGnLocationServiceRetransmitTimer expires."""
        iut = _Iut()
        iut.request_guc(A, scf=True)
        timer = iut.mib.itsGnLocationServiceRetransmitTimer
        iut.at(timer - 1)
        self.assertEqual(len(iut.ls_requests()), 1)
        iut.at(timer)
        self.assertEqual([f.at for f in iut.ls_requests()], [0, timer])

    def test_tp_geonw_pon_los_bv_07(self):
        """TP/GEONW/PON/LOS/BV-07: without LS Reply the LS Request is retransmitted
        itsGnLocationServiceMaxRetrans times."""
        iut = _Iut()
        iut.request_guc(A, scf=True)
        iut.at(iut.mib.itsGnLocationServiceRetransmitTimer * (iut.mib.itsGnLocationServiceMaxRetrans + 5))
        self.assertEqual(len(iut.ls_requests()), 1 + iut.mib.itsGnLocationServiceMaxRetrans)

    def test_tp_geonw_pon_los_bv_08(self):
        """TP/GEONW/PON/LOS/BV-08: an LS Request for the IUT is answered with an LS Reply (NH = 0)
        whose DE PV is the SO PV of the request."""
        iut = _Iut()
        iut.receive(ls_request(lpv(B), 7, GNAddress(mid=addr(IUT).mid)), B)
        replies = [f for f in iut.sent(HeaderType.LS) if f.common.hst == LocationServiceHST.LS_REPLY]
        self.assertEqual(len(replies), 1)
        self.assertEqual(replies[0].common.nh, CommonNH.ANY)
        self.assertEqual((replies[0].ext.de_pv.gn_addr, replies[0].ext.de_pv.latitude), (addr(B), POS[B]))

    def test_tp_geonw_pon_los_bo_09(self):
        """TP/GEONW/PON/LOS/BO-09: the same LS Request received again (from D) is not answered again."""
        iut = _Iut()
        request = ls_request(lpv(B), 7, addr(IUT))
        iut.receive(request, B)
        iut.receive(request, D)
        self.assertEqual(len(iut.sent(HeaderType.LS)), 1)

    def test_tp_geonw_pon_los_bv_10(self):
        """TP/GEONW/PON/LOS/BV-10: an LS Request for another router (RHL > 1) is re-broadcast with RHL - 1."""
        iut = _Iut()
        iut.beacons_from(B, C)
        iut.receive(ls_request(lpv(C), 3, addr(A), rhl=5), C)
        forwarded = iut.ls_requests()
        self.assertEqual(len(forwarded), 1)
        self.assertEqual(forwarded[0].basic.rhl, 4)
        self.assertEqual((forwarded[0].ext.sn, forwarded[0].so_pv.gn_addr), (3, addr(C)))
        self.assertIsNone(forwarded[0].destination)

    def test_tp_geonw_pon_los_bv_11(self):
        """TP/GEONW/PON/LOS/BV-11: an LS Reply for B (RHL > 1) is forwarded to B with RHL - 1."""
        iut = _Iut()
        iut.beacons_from(B, C)
        iut.receive(ls_reply(lpv(C), 3, spv(B), rhl=5), C)
        forwarded = iut.sent(HeaderType.LS)
        self.assertEqual(len(forwarded), 1)
        self.assertEqual(forwarded[0].basic.rhl, 4)
        self.assertEqual(forwarded[0].destination, mac(B))

    def _pending(self, **kw):
        iut = _Iut()
        iut.beacons_from(B)
        iut.request_guc(A, scf=True, **kw)
        return iut

    def test_tp_geonw_pon_los_bv_12(self):
        """TP/GEONW/PON/LOS/BV-12: a GUC from A addressed to the IUT flushes the LS buffer of A."""
        iut = self._pending()
        iut.at(300)
        iut.receive(guc(lpv(A), 1, spv(IUT)), B)
        frames = iut.sent(HeaderType.GEOUNICAST)
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].ext.de_pv.gn_addr, addr(A))

    def test_tp_geonw_pon_los_bv_13(self):
        """TP/GEONW/PON/LOS/BV-13: LS buffer FIFO with lifetime: after LT2 (< LT1) expired, only PL1 is sent."""
        iut = _Iut()
        iut.beacons_from(B)
        iut.request_guc(A, scf=True, payload=b"PL1", lifetime_s=5)
        iut.request_guc(A, scf=True, payload=b"PL2", lifetime_s=0.5)
        iut.at(800)
        iut.receive(ls_reply(lpv(A), 1, spv(IUT)), B)
        self.assertEqual([f.payload for f in iut.sent(HeaderType.GEOUNICAST)], [b"PL1"])

    def test_tp_geonw_pon_los_bv_14(self):
        """TP/GEONW/PON/LOS/BV-14: after itsGnLocationServiceMaxRetrans retransmissions the LS fails
        and its buffer is discarded: a later GUC from A sends nothing to A."""
        iut = _Iut()
        iut.request_guc(A, scf=True)
        iut.at(iut.mib.itsGnLocationServiceRetransmitTimer * (iut.mib.itsGnLocationServiceMaxRetrans + 2))
        self.assertEqual(len(iut.ls_requests()), 1 + iut.mib.itsGnLocationServiceMaxRetrans)
        iut.receive(guc(lpv(A), 1, spv(IUT)), B)
        self.assertEqual(iut.sent(HeaderType.GEOUNICAST), [])

    def test_tp_geonw_pon_los_bv_15(self):
        """TP/GEONW/PON/LOS/BV-15: a GUC from A addressed to B (forwarded by the IUT) also flushes
        the LS buffer of A."""
        iut = self._pending()
        iut.at(300)
        iut.receive(guc(lpv(A), 1, spv(B)), C)
        to_a = [f for f in iut.sent(HeaderType.GEOUNICAST) if f.ext.de_pv.gn_addr == addr(A)]
        self.assertEqual(len(to_a), 1)

    def _retransmission_stops(self, de: int):
        iut = self._pending()
        timer = iut.mib.itsGnLocationServiceRetransmitTimer
        iut.at(timer)
        self.assertEqual(len(iut.ls_requests()), 2)
        iut.at(timer + 300)
        iut.receive(guc(lpv(A), 1, spv(de)), C)
        iut.at(timer * 6)
        self.assertEqual(len(iut.ls_requests()), 2)
        self.assertEqual(len([f for f in iut.sent(HeaderType.GEOUNICAST) if f.ext.de_pv.gn_addr == addr(A)]), 1)

    def test_tp_geonw_pon_los_bv_16(self):
        """TP/GEONW/PON/LOS/BV-16: a GUC from A addressed to the IUT stops the LS Request
        retransmissions; the buffered GUC is sent instead."""
        self._retransmission_stops(IUT)

    def test_tp_geonw_pon_los_bv_17(self):
        """TP/GEONW/PON/LOS/BV-17: a GUC from A addressed to B stops the LS Request
        retransmissions; the buffered GUC is sent instead."""
        self._retransmission_stops(B)

    def test_tp_geonw_cap_los_bv_01(self):
        """TP/GEONW/CAP/LOS/BV-01: when itsGnLocationServicePacketBufferSize is exceeded the oldest
        packets are removed and the new one is queued at the end."""
        iut = _Iut()
        iut.beacons_from(B)
        payloads = [bytes([i]) * 400 for i in (1, 2, 3)]     # 1200 octets > 1024
        for payload in payloads:
            iut.request_guc(A, scf=True, payload=payload)
        iut.receive(ls_reply(lpv(A), 1, spv(IUT)), B)
        self.assertEqual([f.payload for f in iut.sent(HeaderType.GEOUNICAST)], payloads[1:])


class TestGnPacketBuffers(unittest.TestCase):
    """TP/GEONW/PON/FPB and TP/GEONW/CAP/FPB: forwarding packet buffers (clauses 8.6, 10.3.5, Annex D)."""

    @staticmethod
    def _knows_a(iut):
        """LocTE of A, not a neighbour: a TSB originated by A relayed by C (RHL 1: not re-broadcast)."""
        iut.receive(tsb(lpv(A), 50, rhl=1, mhl=10), C)

    def test_tp_geonw_pon_fpb_bv_01(self):
        """TP/GEONW/PON/FPB/BV-01: a source GUC without next hop (SCF) is buffered and sent to B
        when B's Beacon arrives."""
        iut = _Iut()
        self._knows_a(iut)
        iut.request_guc(A, scf=True)
        self.assertEqual(iut.sent(HeaderType.GEOUNICAST), [])
        iut.at(200)
        iut.beacons_from(B)
        frames = iut.sent(HeaderType.GEOUNICAST)
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].destination, mac(B))

    def _forwarder_buffer(self, *sns, lifetime_ms=None):
        iut = _Iut()
        for sn in sns:
            iut.receive(guc(lpv(C), sn, spv(A), rhl=10, mhl=10, scf=True, lifetime_ms=lifetime_ms), C)
        self.assertEqual(iut.sent(HeaderType.GEOUNICAST), [])
        return iut

    def test_tp_geonw_pon_fpb_bv_02(self):
        """TP/GEONW/PON/FPB/BV-02: a received GUC without next hop (SCF) is buffered and forwarded
        to B with RHL - 1 and the same SN when B's Beacon arrives."""
        iut = self._forwarder_buffer(7)
        iut.beacons_from(B)
        frame = iut.sent(HeaderType.GEOUNICAST)[0]
        self.assertEqual((frame.basic.rhl, frame.ext.sn, frame.destination), (9, 7, mac(B)))

    def test_tp_geonw_pon_fpb_bv_03(self):
        """TP/GEONW/PON/FPB/BV-03: the UC forwarding buffer is FIFO: SN1 then SN2."""
        iut = self._forwarder_buffer(7, 8)
        iut.beacons_from(B)
        self.assertEqual([f.ext.sn for f in iut.sent(HeaderType.GEOUNICAST)], [7, 8])

    def test_tp_geonw_pon_fpb_bv_04(self):
        """TP/GEONW/PON/FPB/BV-04: a buffered GUC whose LT expired is not forwarded."""
        iut = self._forwarder_buffer(7, lifetime_ms=1000)
        iut.at(2000)
        iut.beacons_from(B)
        self.assertEqual(iut.sent(HeaderType.GEOUNICAST), [])

    def test_tp_geonw_pon_fpb_bv_06(self):
        """TP/GEONW/PON/FPB/BV-06: a source GBC without neighbours (SCF) is buffered and broadcast
        when a Beacon arrives."""
        iut = _Iut()
        iut.request_gbc(AREA1, scf=True)
        self.assertEqual(iut.sent(HeaderType.GEOBROADCAST), [])
        iut.beacons_from(D)
        frames = iut.sent(HeaderType.GEOBROADCAST)
        self.assertEqual(len(frames), 1)
        self.assertIsNone(frames[0].destination)

    def test_tp_geonw_pon_fpb_bv_07(self):
        """TP/GEONW/PON/FPB/BV-07: the BC forwarding buffer is FIFO: GBC1 (SN1) then GBC2 (SN2)."""
        iut = _Iut()
        iut.request_gbc(AREA1, scf=True)
        iut.request_gbc(AREA1, scf=True)
        iut.beacons_from(B)
        self.assertEqual([f.ext.sn for f in iut.sent(HeaderType.GEOBROADCAST)], [0, 1])

    def test_tp_geonw_pon_fpb_bv_08(self):
        """TP/GEONW/PON/FPB/BV-08: buffered GBCs whose LT expired are not broadcast."""
        iut = _Iut()
        for _ in range(2):
            iut.router.gn_data_request(GNDataRequest(
                upper_protocol_entity=CommonNH.BTP_B, packet_transport_type=PacketTransportType(
                    header_type=HeaderType.GEOBROADCAST, header_subtype=GeoBroadcastHST.GEOBROADCAST_CIRCLE),
                traffic_class=TrafficClass(scf=True), data=b"gbc", length=3, area=AREA1,
                max_packet_lifetime=1.0))
        iut.at(2000)
        iut.beacons_from(B)
        self.assertEqual(iut.sent(HeaderType.GEOBROADCAST), [])

    def test_tp_geonw_pon_fpb_bv_09(self):
        """TP/GEONW/PON/FPB/BV-09: the buffered source GUC is sent with LT = default LT - waiting time."""
        iut = _Iut()
        self._knows_a(iut)
        iut.request_guc(A, scf=True)
        iut.at(1500)
        iut.beacons_from(B)
        frame = iut.sent(HeaderType.GEOUNICAST)[0]
        self.assertEqual(frame.basic.lt.get_value_in_millis(), lt_ms(DEFAULT_LT_MS - 1500))

    def test_tp_geonw_pon_fpb_bv_10(self):
        """TP/GEONW/PON/FPB/BV-10: the buffered source GBC is broadcast with LT = default LT - waiting time."""
        iut = _Iut()
        iut.request_gbc(AREA1, scf=True)
        iut.at(1500)
        iut.beacons_from(B)
        frame = iut.sent(HeaderType.GEOBROADCAST)[0]
        self.assertEqual(frame.basic.lt.get_value_in_millis(), lt_ms(DEFAULT_LT_MS - 1500))

    def test_tp_geonw_pon_fpb_bv_11_x(self):
        """TP/GEONW/PON/FPB/BV-11-X (variants 01-05): without next hop and with SCF = 0 a source
        GUC, GAC (AREA2), GBC (AREA2), TSB or SHB is broadcast immediately."""
        variants = {
            "01": (HeaderType.GEOUNICAST, lambda iut: iut.request_guc(A)),
            "02": (HeaderType.GEOANYCAST, lambda iut: iut.request_gbc(AREA2, anycast=True)),
            "03": (HeaderType.GEOBROADCAST, lambda iut: iut.request_gbc(AREA2)),
            "04": (HeaderType.TSB, lambda iut: iut.request_tsb()),
            "05": (HeaderType.TSB, lambda iut: iut.request_shb()),
        }
        for variant, (ht, send) in variants.items():
            with self.subTest(variant=variant):
                iut = _Iut()
                self._knows_a(iut)
                before = len(iut.sent(ht))
                send(iut)
                frames = iut.sent(ht)[before:]
                self.assertEqual(len(frames), 1)
                self.assertIsNone(frames[0].destination)
                self.assertEqual(frames[0].at, 0)

    def test_tp_geonw_pon_fpb_bv_12_x(self):
        """TP/GEONW/PON/FPB/BV-12-X (variants 01-04): without next hop and with SCF = 0 a received
        GUC (to A), GAC (AREA2), GBC (AREA2) or TSB is forwarded by broadcast immediately."""
        variants = {
            "01": (HeaderType.GEOUNICAST, guc(lpv(C), 1, spv(A), rhl=10, mhl=10)),
            "02": (HeaderType.GEOANYCAST, gbc(lpv(C), 1, AREA2, rhl=10, mhl=10, anycast=True)),
            "03": (HeaderType.GEOBROADCAST, gbc(lpv(C), 1, AREA2, rhl=10, mhl=10)),
            "04": (HeaderType.TSB, tsb(lpv(C), 1, rhl=10, mhl=10)),
        }
        for variant, (ht, packet) in variants.items():
            with self.subTest(variant=variant):
                iut = _Iut()
                iut.receive(packet, C)
                frames = iut.sent(ht)
                self.assertEqual(len(frames), 1)
                self.assertIsNone(frames[0].destination)
                self.assertEqual(frames[0].basic.rhl, 9)

    def test_tp_geonw_cap_fpb_bv_01(self):
        """TP/GEONW/CAP/FPB/BV-01: when itsGnUcForwardingPacketBufferSize is exceeded the oldest
        packets are removed and the new GUC is queued at the end."""
        iut = _Iut(itsGnUcForwardingPacketBufferSize=1)          # 1 kB
        for sn in (1, 2, 3):
            iut.receive(guc(lpv(C), sn, spv(A), rhl=10, mhl=10, scf=True, payload=bytes(400)), C)
        iut.beacons_from(B)
        self.assertEqual([f.ext.sn for f in iut.sent(HeaderType.GEOUNICAST)], [2, 3])

    def test_tp_geonw_cap_fpb_bv_02(self):
        """TP/GEONW/CAP/FPB/BV-02: when itsGnBcForwardingPacketBufferSize is exceeded the oldest
        packets are removed and the new GBC is queued at the end."""
        iut = _Iut(itsGnBcForwardingPacketBufferSize=1)          # 1 kB
        for sn in (1, 2, 3):
            iut.receive(gbc(lpv(C), sn, AREA2, rhl=10, mhl=10, scf=True, payload=bytes(400)), C)
        iut.beacons_from(B)
        self.assertEqual([f.ext.sn for f in iut.sent(HeaderType.GEOBROADCAST)], [2, 3])


class TestGnBeacon(unittest.TestCase):
    """TP/GEONW/PON/BEA: Beacon service (clauses 10.3.6, 10.3.10.2 step 7)."""

    def test_tp_geonw_pon_bea_ti_01(self):
        """TP/GEONW/PON/BEA/TI-01: Beacons are sent every itsGnBeaconServiceRetransmitTimer +
        RAND[0, itsGnBeaconServiceMaxJitter]."""
        iut = _Iut(beacons=True)
        while len(iut.sent(HeaderType.BEACON)) < 6:
            iut.at(iut.router.next_deadline())
        times = [f.at for f in iut.sent(HeaderType.BEACON)]
        timer, jitter = iut.mib.itsGnBeaconServiceRetransmitTimer, iut.mib.itsGnBeaconServiceMaxJitter
        for previous, current in zip(times, times[1:]):
            self.assertTrue(timer <= current - previous <= timer + jitter, (previous, current))

    def test_tp_geonw_pon_bea_bv_02(self):
        """TP/GEONW/PON/BEA/BV-02: an SHB restarts the Beacon timer: the next Beacon comes
        itsGnBeaconServiceRetransmitTimer (+ jitter) after the SHB."""
        iut = _Iut(beacons=True)
        iut.at(iut.router.next_deadline())
        iut.beacons_from(B)
        iut.at(2000)
        iut.request_shb()
        iut.at(2000 + iut.mib.itsGnBeaconServiceRetransmitTimer - 1)
        self.assertEqual(len(iut.sent(HeaderType.BEACON)), 1)
        iut.at(2000 + iut.mib.itsGnBeaconServiceRetransmitTimer + iut.mib.itsGnBeaconServiceMaxJitter)
        beacons = iut.sent(HeaderType.BEACON)
        self.assertEqual(len(beacons), 2)
        self.assertGreaterEqual(beacons[1].at, 2000 + iut.mib.itsGnBeaconServiceRetransmitTimer)


class TestGnGeoUnicast(unittest.TestCase):
    """TP/GEONW/PON/GUC: GeoUnicast (clauses 10.3.8, Annex E)."""

    def test_tp_geonw_pon_guc_all_bv_03(self):
        """TP/GEONW/PON/GUC/ALL/BV-03: a forwarded GUC has RHL - 1 and the same MHL. DE PV,
        after TS 103 836-4-1 V2.2.1 clause 10.3.8.3: for A, not a neighbour, step 7 applies (the
        LocTE of A is updated from a newer DE PV, never from an older one) and the DE PV is
        forwarded unchanged; the DE PV is replaced by a newer LocTE only when DE is a neighbour
        (step 8), checked with D. The TP (Release 1) expects the replacement for A."""
        iut = _Iut()
        iut.beacons_from(B, C, D)
        iut.receive(guc(lpv(A), 1, spv(IUT)), B)                            # GEOUNI1 from A

        def stale(n):
            return dataclass_replace(spv(n), latitude=north(1400),
                                     tst=TST.set_in_normal_timestamp_seconds(TimeService.time() - 5))
        iut.receive(guc(lpv(C), 2, stale(A), rhl=7, mhl=9, scf=True), C)      # GEOUNI2
        frame = iut.sent(HeaderType.GEOUNICAST)[0]
        self.assertEqual((frame.basic.rhl, frame.common.mhl), (6, 9))
        self.assertEqual(frame.ext.de_pv.latitude, north(1400))
        self.assertEqual(iut.router.location_table.get_entry(addr(A)).position_vector.latitude, POS[A])
        iut.receive(guc(lpv(C), 3, stale(D), rhl=7, mhl=9, scf=True), C)      # to neighbour D
        self.assertEqual(iut.sent(HeaderType.GEOUNICAST)[-1].ext.de_pv.latitude, POS[D])
        newer = dataclass_replace(spv(A), latitude=north(1600),
                                  tst=TST.set_in_normal_timestamp_seconds(TimeService.time() + 1))
        iut.receive(guc(lpv(C), 4, newer, rhl=7, mhl=9, scf=True), C)         # step 7: LocTE updated
        self.assertEqual(iut.router.location_table.get_entry(addr(A)).position_vector.latitude, north(1600))

    def test_tp_geonw_pon_guc_all_bo_04(self):
        """TP/GEONW/PON/GUC/ALL/BO-04: a GUC to A with RHL 1 is not forwarded."""
        iut = _Iut()
        iut.beacons_from(B, C)
        iut.receive(guc(lpv(C), 2, spv(A), rhl=1, scf=True), C)
        self.assertEqual(iut.sent(HeaderType.GEOUNICAST), [])

    def test_tp_geonw_pon_guc_all_bv_05(self):
        """TP/GEONW/PON/GUC/ALL/BV-05: a GUC addressed to the IUT is passed to the right upper protocol."""
        iut = _Iut()
        iut.receive(guc(lpv(B), 2, spv(IUT), payload=b"data"), B)
        self.assertEqual(len(iut.indications), 1)
        self.assertEqual(iut.indications[0].upper_protocol_entity, CommonNH.BTP_B)
        self.assertEqual(iut.indications[0].data, b"data")

    def test_tp_geonw_pon_guc_all_bv_06(self):
        """TP/GEONW/PON/GUC/ALL/BV-06: a GUC addressed to B is not passed up."""
        iut = _Iut()
        iut.beacons_from(B, C)
        iut.receive(guc(lpv(C), 2, spv(B)), C)
        self.assertEqual(iut.indications, [])

    def test_tp_geonw_pon_guc_all_bo_08(self):
        """TP/GEONW/PON/GUC/ALL/BO-08: a GUC to the IUT received twice is passed up once."""
        iut = _Iut()
        iut.beacons_from(C, B)
        packet = guc(lpv(C), 2, spv(IUT), rhl=5, scf=True)
        iut.receive(packet, C)
        iut.receive(packet[:3] + bytes([4]) + packet[4:], B)
        self.assertEqual(len(iut.indications), 1)

    def test_tp_geonw_pon_guc_grd_bv_01(self):
        """TP/GEONW/PON/GUC/GRD/BV-01: a GUC to B (greedy) carries B's Beacon position as DE PV
        and goes to B's link-layer address."""
        iut = _Iut()
        iut.beacons_from(B)
        iut.request_guc(B)
        frame = iut.sent(HeaderType.GEOUNICAST)[0]
        self.assertEqual(frame.ext.de_pv.latitude, POS[B])
        self.assertEqual(frame.destination, mac(B))

    def test_tp_geonw_pon_guc_grd_bv_02(self):
        """TP/GEONW/PON/GUC/GRD/BV-02: a GUC to A is forwarded to the greedy next hop B (not D, not C)."""
        iut = _Iut()
        iut.beacons_from(B, D, C)
        iut.receive(guc(lpv(C), 2, spv(A), scf=True), C)
        frame = iut.sent(HeaderType.GEOUNICAST)[0]
        self.assertEqual(frame.destination, mac(B))

    def test_tp_geonw_pon_guc_grd_bo_07(self):
        """TP/GEONW/PON/GUC/GRD/BO-07: the same GUC received again (from B) is not forwarded again."""
        iut = _Iut()
        iut.beacons_from(C, B)
        packet = guc(lpv(C), 2, spv(A), rhl=5, scf=True)
        iut.receive(packet, C)
        iut.receive(packet[:3] + bytes([4]) + packet[4:], B)
        self.assertEqual(len(iut.sent(HeaderType.GEOUNICAST)), 1)

    @staticmethod
    def _cbf(**mib):
        return _Iut(itsGnNonAreaForwardingAlgorithm=NonAreaForwardingAlgorithm.CBF, **mib)

    def test_tp_geonw_pon_guc_cbf_bv_01(self):
        """TP/GEONW/PON/GUC/CBF/BV-01: with CBF a GUC to B is broadcast with B's position as DE PV."""
        iut = self._cbf()
        iut.beacons_from(B)
        iut.request_guc(B)
        frame = iut.sent(HeaderType.GEOUNICAST)[0]
        self.assertEqual(frame.ext.de_pv.latitude, POS[B])
        self.assertIsNone(frame.destination)

    def _cbf_forwarding_time(self, iut, sender, so=C):
        iut.receive(guc(lpv(so), 2, spv(A), scf=True), sender)
        self.assertEqual(iut.sent(HeaderType.GEOUNICAST), [])
        iut.at(500)
        frames = iut.sent(HeaderType.GEOUNICAST)
        self.assertEqual(len(frames), 1)
        self.assertIsNone(frames[0].destination)
        return frames[0].at

    def test_tp_geonw_pon_guc_cbf_bv_02(self):
        """TP/GEONW/PON/GUC/CBF/BV-02: a GUC from C is re-broadcast when the CBF timer of its
        progress (400 m) expires."""
        iut = self._cbf()
        iut.beacons_from(B, C)
        self.assertAlmostEqual(self._cbf_forwarding_time(iut, C), cbf_timeout_ms(400, iut.mib), delta=1)

    def test_tp_geonw_pon_guc_cbf_bv_07(self):
        """TP/GEONW/PON/GUC/CBF/BV-07: the same GUC heard from B (a better forwarder) before the CBF
        timer expires cancels the re-broadcast."""
        iut = self._cbf()
        iut.beacons_from(B, C)
        packet = guc(lpv(C), 2, spv(A), scf=True)
        iut.receive(packet, C)
        iut.at(20)
        iut.receive(packet[:3] + bytes([4]) + packet[4:], B)
        iut.at(500)
        self.assertEqual(iut.sent(HeaderType.GEOUNICAST), [])

    def test_tp_geonw_pon_guc_cbf_bv_20(self):
        """TP/GEONW/PON/GUC/CBF/BV-20: with a progress beyond itsGnDefaultMaxCommunicationRange
        (1100 m) the GUC is re-broadcast when the CBF timer of the second segment expires. The TP
        (Release 1) expects itsGnCbfMinTime; TS 103 836-4-1 V2.2.1 clauses E.3.2.2-E.3.2.3 assign
        progress beyond DIST_MAX to segment SEGN = 2 (190.1 ms here)."""
        iut = self._cbf()
        iut.beacons_from(B, FAR)
        at = self._cbf_forwarding_time(iut, FAR, so=FAR)
        self.assertAlmostEqual(at, cbf_timeout_ms(1100, iut.mib), delta=1)

    def test_tp_geonw_pon_guc_cbf_bv_21(self):
        """TP/GEONW/PON/GUC/CBF/BV-21: a GUC from an unknown sender D is re-broadcast after CBF_MAX."""
        iut = self._cbf()
        iut.beacons_from(B, C)
        self.assertAlmostEqual(self._cbf_forwarding_time(iut, D), iut.mib.itsGnCbfMaxTime, delta=1)

    def test_tp_geonw_pon_guc_cbf_bv_22(self):
        """TP/GEONW/PON/GUC/CBF/BV-22: a GUC from a sender D with PAI = 0 is re-broadcast after CBF_MAX."""
        iut = self._cbf()
        iut.beacons_from(B)
        iut.beacons_from(D, pai=False)
        self.assertAlmostEqual(self._cbf_forwarding_time(iut, D), iut.mib.itsGnCbfMaxTime, delta=1)


def _area_kind(anycast: bool):
    return HeaderType.GEOANYCAST if anycast else HeaderType.GEOBROADCAST


class _AreaForwarding:
    """GBC and GAC share their forwarding TPs; ``anycast`` selects the packet type."""

    anycast = False

    def assertEqual(self, first, second, msg=None):  # pragma: no cover - provided by TestCase
        raise NotImplementedError

    def kind(self):
        return _area_kind(self.anycast)

    def packet(self, so, sn, area, **kw):
        return gbc(so, sn, area, anycast=self.anycast, **kw)

    def frames(self, iut):
        return iut.sent(self.kind())

    # non-area
    def nonarea_retransmission(self):
        iut = _Iut()
        iut.beacons_from(B, C)
        iut.receive(self.packet(lpv(C), 2, AREA2, rhl=7, mhl=9, scf=True), C)
        frame = self.frames(iut)[0]
        self.assertEqual((frame.basic.rhl, frame.common.mhl), (6, 9))
        self.assertEqual((frame.ext.latitude, frame.ext.a), (AREA2.latitude, AREA2.a))

    def nonarea_rhl_one(self):
        iut = _Iut()
        iut.beacons_from(B, C)
        iut.receive(self.packet(lpv(C), 2, AREA2, rhl=1, scf=True), C)
        iut.at(500)
        self.assertEqual(self.frames(iut), [])

    def nonarea_not_passed_up(self):
        iut = _Iut()
        iut.beacons_from(B)
        iut.receive(self.packet(lpv(B), 2, AREA2, scf=True), B)
        self.assertEqual(iut.indications, [])

    def nonarea_too_big(self):
        iut = _Iut()
        iut.beacons_from(B, D)
        iut.receive(self.packet(lpv(C), 2, BIG_AREA, scf=True), C)
        iut.at(500)
        self.assertEqual(self.frames(iut), [])

    def nonarea_sender_inside(self):
        iut = _Iut()
        iut.beacons_from(B, C, D)
        iut.receive(self.packet(lpv(D), 2, AREA2, scf=True), D)
        iut.at(500)
        self.assertEqual(self.frames(iut), [])
        self.assertEqual(iut.indications, [])

    def nonarea_greedy_source(self):
        iut = _Iut()
        iut.beacons_from(D, B)
        iut.request_gbc(AREA2, scf=True, anycast=self.anycast)
        frame = self.frames(iut)[0]
        self.assertEqual(frame.destination, mac(B))
        self.assertEqual((frame.ext.latitude, frame.ext.a), (AREA2.latitude, AREA2.a))

    def nonarea_greedy_forwarder(self):
        iut = _Iut()
        iut.beacons_from(B, D, C)
        iut.receive(self.packet(lpv(C), 2, AREA2, scf=True), C)
        self.assertEqual(self.frames(iut)[0].destination, mac(B))

    def nonarea_greedy_duplicate(self):
        iut = _Iut()
        iut.beacons_from(B, D)
        packet = self.packet(lpv(C), 2, AREA2, rhl=5, scf=True)
        iut.receive(packet, C)
        iut.receive(packet[:3] + bytes([4]) + packet[4:], D)
        self.assertEqual(len(self.frames(iut)), 1)

    @staticmethod
    def _cbf_iut():
        return _Iut(itsGnNonAreaForwardingAlgorithm=NonAreaForwardingAlgorithm.CBF)

    def nonarea_cbf_source(self):
        iut = self._cbf_iut()
        iut.beacons_from(D, B)
        iut.request_gbc(AREA2, scf=True, anycast=self.anycast)
        frames = self.frames(iut)
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].at, 0)
        self.assertIsNone(frames[0].destination)

    def _nonarea_cbf_time(self, iut, so, sender, area=AREA_A):
        iut.receive(self.packet(lpv(so), 2, area, scf=True), sender)
        self.assertEqual(self.frames(iut), [])
        iut.at(500)
        frames = self.frames(iut)
        self.assertEqual(len(frames), 1)
        self.assertIsNone(frames[0].destination)
        return frames[0].at

    def nonarea_cbf_timer(self):
        iut = self._cbf_iut()
        iut.beacons_from(B, C)
        at = self._nonarea_cbf_time(iut, C, C)
        self.assertAlmostEqual(at, cbf_timeout_ms(400, iut.mib), delta=1)

    def nonarea_cbf_better_forwarder(self):
        iut = self._cbf_iut()
        iut.beacons_from(B, C)
        packet = self.packet(lpv(C), 2, AREA_A, rhl=5, scf=True)
        iut.receive(packet, C)
        iut.at(20)
        iut.receive(packet[:3] + bytes([4]) + packet[4:], B)
        iut.at(500)
        self.assertEqual(self.frames(iut), [])

    def nonarea_cbf_min(self):
        iut = self._cbf_iut()
        iut.beacons_from(B, FAR)
        at = self._nonarea_cbf_time(iut, FAR, FAR)
        self.assertAlmostEqual(at, cbf_timeout_ms(1100, iut.mib), delta=1)

    def nonarea_cbf_unknown_sender(self):
        iut = self._cbf_iut()
        iut.beacons_from(B)
        at = self._nonarea_cbf_time(iut, C, D, AREA2)
        self.assertEqual(at, iut.mib.itsGnCbfMaxTime)

    def nonarea_cbf_sender_pai_0(self):
        iut = self._cbf_iut()
        iut.beacons_from(B)
        iut.beacons_from(D, pai=False)
        at = self._nonarea_cbf_time(iut, C, D, AREA2)
        self.assertEqual(at, iut.mib.itsGnCbfMaxTime)

    # area
    def area_source(self):
        iut = _Iut()
        iut.beacons_from(D, B)
        iut.request_gbc(AREA1, scf=True, anycast=self.anycast)
        frame = self.frames(iut)[0]
        self.assertEqual(frame.at, 0)
        self.assertIsNone(frame.destination)
        self.assertEqual((frame.ext.latitude, frame.ext.a), (AREA1.latitude, AREA1.a))

    def area_passed_up(self):
        iut = _Iut()
        iut.beacons_from(B)
        iut.receive(self.packet(lpv(B), 2, AREA1, scf=True, payload=b"area"), B)
        self.assertEqual(len(iut.indications), 1)
        self.assertEqual(iut.indications[0].upper_protocol_entity, CommonNH.BTP_B)
        self.assertEqual(iut.indications[0].data, b"area")

    def area_duplicate_not_passed_up(self):
        iut = _Iut()
        iut.beacons_from(D, B)
        packet = self.packet(lpv(B), 2, AREA1, rhl=5, scf=True)
        iut.receive(packet, B)
        iut.receive(packet[:3] + bytes([4]) + packet[4:], D)
        self.assertEqual(len(iut.indications), 1)


class TestGnGeoBroadcast(unittest.TestCase, _AreaForwarding):
    """TP/GEONW/PON/GBC: GeoBroadcast (clauses 10.3.11, Annexes D, E, F)."""

    anycast = False

    def test_tp_geonw_pon_gbc_nonarea_all_bv_03(self):
        """TP/GEONW/PON/GBC/NONAREA/ALL/BV-03: a forwarded GBC (AREA2) has RHL - 1, the same MHL
        and the same destination area."""
        self.nonarea_retransmission()

    def test_tp_geonw_pon_gbc_nonarea_all_bv_04(self):
        """TP/GEONW/PON/GBC/NONAREA/ALL/BV-04: a GBC with RHL 1 is not retransmitted."""
        self.nonarea_rhl_one()

    def test_tp_geonw_pon_gbc_nonarea_all_bv_06(self):
        """TP/GEONW/PON/GBC/NONAREA/ALL/BV-06: a GBC received outside its area (AREA2) is not passed up."""
        self.nonarea_not_passed_up()

    def test_tp_geonw_pon_gbc_nonarea_all_bo_09(self):
        """TP/GEONW/PON/GBC/NONAREA/ALL/BO-09: a GBC with an area larger than itsGnMaxGeoAreaSize
        is not retransmitted (clause B.3)."""
        self.nonarea_too_big()

    def test_tp_geonw_pon_gbc_nonarea_all_bo_10(self):
        """TP/GEONW/PON/GBC/NONAREA/ALL/BO-10: a GBC from a known sender D inside AREA2, received
        by the IUT outside AREA2, is discarded (Annex D)."""
        self.nonarea_sender_inside()

    def test_tp_geonw_pon_gbc_nonarea_grd_bv_01(self):
        """TP/GEONW/PON/GBC/NONAREA/GRD/BV-01: a source GBC to AREA2 (IUT outside) is line
        forwarded to the greedy next hop B."""
        self.nonarea_greedy_source()

    def test_tp_geonw_pon_gbc_nonarea_grd_bv_02(self):
        """TP/GEONW/PON/GBC/NONAREA/GRD/BV-02: a GBC from C to AREA2 is line forwarded to B."""
        self.nonarea_greedy_forwarder()

    def test_tp_geonw_pon_gbc_nonarea_grd_bo_07(self):
        """TP/GEONW/PON/GBC/NONAREA/GRD/BO-07: the same GBC received again (from D) is not forwarded again."""
        self.nonarea_greedy_duplicate()

    def test_tp_geonw_pon_gbc_nonarea_cbf_bv_01(self):
        """TP/GEONW/PON/GBC/NONAREA/CBF/BV-01: with CBF a source GBC to AREA2 is broadcast immediately."""
        self.nonarea_cbf_source()

    def test_tp_geonw_pon_gbc_nonarea_cbf_bv_02(self):
        """TP/GEONW/PON/GBC/NONAREA/CBF/BV-02: a GBC from C towards A is re-broadcast when the CBF
        timer of its progress (400 m) expires."""
        self.nonarea_cbf_timer()

    def test_tp_geonw_pon_gbc_nonarea_cbf_bv_07(self):
        """TP/GEONW/PON/GBC/NONAREA/CBF/BV-07: the same GBC heard from B (a better forwarder)
        before the CBF timer expires cancels the re-broadcast."""
        self.nonarea_cbf_better_forwarder()

    def test_tp_geonw_pon_gbc_nonarea_cbf_bv_20(self):
        """TP/GEONW/PON/GBC/NONAREA/CBF/BV-20: with a progress beyond
        itsGnDefaultMaxCommunicationRange (1100 m) the GBC is re-broadcast when the CBF timer of the
        second segment expires (TS 103 836-4-1 V2.2.1 clause E.3.2.2; the Release 1 TP expects
        itsGnCbfMinTime)."""
        self.nonarea_cbf_min()

    def test_tp_geonw_pon_gbc_nonarea_cbf_bv_21(self):
        """TP/GEONW/PON/GBC/NONAREA/CBF/BV-21: a GBC from an unknown sender D (IUT outside AREA2)
        is re-broadcast after CBF_MAX."""
        self.nonarea_cbf_unknown_sender()

    def test_tp_geonw_pon_gbc_nonarea_cbf_bv_22(self):
        """TP/GEONW/PON/GBC/NONAREA/CBF/BV-22: a GBC from a sender D with PAI = 0 (IUT outside
        AREA2) is re-broadcast after CBF_MAX."""
        self.nonarea_cbf_sender_pai_0()

    def test_tp_geonw_pon_gbc_area_all_bv_01(self):
        """TP/GEONW/PON/GBC/AREA/ALL/BV-01: a source GBC to AREA1 (IUT inside) is broadcast immediately."""
        self.area_source()

    def test_tp_geonw_pon_gbc_area_all_bv_03(self):
        """TP/GEONW/PON/GBC/AREA/ALL/BV-03: a GBC to AREA1 is retransmitted with RHL - 1 and the same MHL."""
        iut = _Iut()
        iut.beacons_from(D, B)
        iut.receive(gbc(lpv(B), 2, AREA1, rhl=7, mhl=9, scf=True), B)
        iut.at(500)
        frame = iut.sent(HeaderType.GEOBROADCAST)[0]
        self.assertEqual((frame.basic.rhl, frame.common.mhl), (6, 9))

    def test_tp_geonw_pon_gbc_area_all_bv_04(self):
        """TP/GEONW/PON/GBC/AREA/ALL/BV-04: a GBC to AREA1 with RHL 1 is not retransmitted."""
        iut = _Iut()
        iut.beacons_from(D, B)
        iut.receive(gbc(lpv(B), 2, AREA1, rhl=1, scf=True), B)
        iut.at(500)
        self.assertEqual(iut.sent(HeaderType.GEOBROADCAST), [])

    def test_tp_geonw_pon_gbc_area_all_bv_05(self):
        """TP/GEONW/PON/GBC/AREA/ALL/BV-05: a GBC received inside its area is passed to the right
        upper protocol."""
        self.area_passed_up()

    def test_tp_geonw_pon_gbc_area_all_bo_08(self):
        """TP/GEONW/PON/GBC/AREA/ALL/BO-08: the same GBC received again (from D) is not passed up again."""
        self.area_duplicate_not_passed_up()

    def _simple(self):
        iut = _Iut(itsGnAreaForwardingAlgorithm=AreaForwardingAlgorithm.SIMPLE)
        iut.beacons_from(D, B)
        return iut

    def test_tp_geonw_pon_gbc_area_smp_bv_02(self):
        """TP/GEONW/PON/GBC/AREA/SMP/BV-02: with Simple forwarding a GBC received inside its area
        is re-broadcast immediately."""
        iut = self._simple()
        iut.receive(gbc(lpv(B), 2, AREA1, scf=True), B)
        frames = iut.sent(HeaderType.GEOBROADCAST)
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].at, 0)
        self.assertIsNone(frames[0].destination)

    def test_tp_geonw_pon_gbc_area_smp_bo_07(self):
        """TP/GEONW/PON/GBC/AREA/SMP/BO-07: the same GBC received again (from D) is not re-broadcast again."""
        iut = self._simple()
        packet = gbc(lpv(B), 2, AREA1, rhl=5, scf=True)
        iut.receive(packet, B)
        iut.receive(packet[:3] + bytes([4]) + packet[4:], D)
        self.assertEqual(len(iut.sent(HeaderType.GEOBROADCAST)), 1)

    def _area_cbf_time(self, iut, sender):
        iut.receive(gbc(lpv(C), 2, AREA1, scf=True), sender)
        self.assertEqual(iut.sent(HeaderType.GEOBROADCAST), [])
        iut.at(500)
        frames = iut.sent(HeaderType.GEOBROADCAST)
        self.assertEqual(len(frames), 1)
        return frames[0].at

    def test_tp_geonw_pon_gbc_area_cbf_bv_02(self):
        """TP/GEONW/PON/GBC/AREA/CBF/BV-02: a GBC from a known sender C inside the area is buffered
        and re-broadcast when the contention timer (distance 400 m) expires."""
        iut = _Iut()
        iut.beacons_from(B, D, C)
        at = self._area_cbf_time(iut, C)
        self.assertAlmostEqual(at, cbf_timeout_ms(400, iut.mib), delta=1)

    def test_tp_geonw_pon_gbc_area_cbf_bv_07(self):
        """TP/GEONW/PON/GBC/AREA/CBF/BV-07: the same GBC received from D while buffered is removed
        from the CBF buffer and not re-broadcast."""
        iut = _Iut()
        iut.beacons_from(B, D)
        packet = gbc(lpv(C), 2, AREA1, rhl=5, scf=True)
        iut.receive(packet, C)
        iut.at(20)
        iut.receive(packet[:3] + bytes([4]) + packet[4:], D)
        iut.at(500)
        self.assertEqual(iut.sent(HeaderType.GEOBROADCAST), [])

    def test_tp_geonw_pon_gbc_area_cbf_bv_21(self):
        """TP/GEONW/PON/GBC/AREA/CBF/BV-21: a GBC from an unknown sender D inside the area is
        re-broadcast after CBF_MAX."""
        iut = _Iut()
        iut.beacons_from(B)
        self.assertEqual(self._area_cbf_time(iut, D), iut.mib.itsGnCbfMaxTime)

    def test_tp_geonw_pon_gbc_area_cbf_bv_22(self):
        """TP/GEONW/PON/GBC/AREA/CBF/BV-22: a GBC from a sender D with PAI = 0 inside the area is
        re-broadcast after CBF_MAX."""
        iut = _Iut()
        iut.beacons_from(B)
        iut.beacons_from(D, pai=False)
        self.assertEqual(self._area_cbf_time(iut, D), iut.mib.itsGnCbfMaxTime)


class TestGnGeoAnycast(unittest.TestCase, _AreaForwarding):
    """TP/GEONW/PON/GAC: GeoAnycast (clauses 10.3.12, Annexes D, E)."""

    anycast = True

    def test_tp_geonw_pon_gac_nonarea_all_bv_03(self):
        """TP/GEONW/PON/GAC/NONAREA/ALL/BV-03: a forwarded GAC (AREA2) has RHL - 1, the same MHL
        and the same destination area."""
        self.nonarea_retransmission()

    def test_tp_geonw_pon_gac_nonarea_all_bo_04(self):
        """TP/GEONW/PON/GAC/NONAREA/ALL/BO-04: a GAC with RHL 1 is not retransmitted."""
        self.nonarea_rhl_one()

    def test_tp_geonw_pon_gac_nonarea_all_bv_06(self):
        """TP/GEONW/PON/GAC/NONAREA/ALL/BV-06: a GAC received outside its area (AREA2) is not passed up."""
        self.nonarea_not_passed_up()

    def test_tp_geonw_pon_gac_nonarea_all_bo_09(self):
        """TP/GEONW/PON/GAC/NONAREA/ALL/BO-09: a GAC with an area larger than itsGnMaxGeoAreaSize
        is not retransmitted (clause B.3)."""
        self.nonarea_too_big()

    def test_tp_geonw_pon_gac_nonarea_all_bv_10(self):
        """TP/GEONW/PON/GAC/NONAREA/ALL/BV-10: a GAC from a known sender D inside AREA2, received
        by the IUT outside AREA2, is discarded (Annex D)."""
        self.nonarea_sender_inside()

    def test_tp_geonw_pon_gac_nonarea_grd_bv_01(self):
        """TP/GEONW/PON/GAC/NONAREA/GRD/BV-01: a source GAC to AREA2 (IUT outside) is line
        forwarded to the greedy next hop B."""
        self.nonarea_greedy_source()

    def test_tp_geonw_pon_gac_nonarea_grd_bv_02(self):
        """TP/GEONW/PON/GAC/NONAREA/GRD/BV-02: a GAC from C to AREA2 is line forwarded to B."""
        self.nonarea_greedy_forwarder()

    def test_tp_geonw_pon_gac_nonarea_grd_bo_07(self):
        """TP/GEONW/PON/GAC/NONAREA/GRD/BO-07: the same GAC received again is not forwarded again."""
        self.nonarea_greedy_duplicate()

    def test_tp_geonw_pon_gac_nonarea_cbf_bv_01(self):
        """TP/GEONW/PON/GAC/NONAREA/CBF/BV-01: with CBF a source GAC to AREA2 is broadcast immediately."""
        self.nonarea_cbf_source()

    def test_tp_geonw_pon_gac_nonarea_cbf_bv_02(self):
        """TP/GEONW/PON/GAC/NONAREA/CBF/BV-02: a GAC from C towards A is re-broadcast when the CBF
        timer of its progress (400 m) expires."""
        self.nonarea_cbf_timer()

    def test_tp_geonw_pon_gac_nonarea_cbf_bv_07(self):
        """TP/GEONW/PON/GAC/NONAREA/CBF/BV-07: the same GAC heard from B (a better forwarder)
        before the CBF timer expires cancels the re-broadcast."""
        self.nonarea_cbf_better_forwarder()

    def test_tp_geonw_pon_gac_nonarea_cbf_bv_20(self):
        """TP/GEONW/PON/GAC/NONAREA/CBF/BV-20: with a progress beyond
        itsGnDefaultMaxCommunicationRange (1100 m) the GAC is re-broadcast when the CBF timer of the
        second segment expires (TS 103 836-4-1 V2.2.1 clause E.3.2.2; the Release 1 TP expects
        itsGnCbfMinTime)."""
        self.nonarea_cbf_min()

    def test_tp_geonw_pon_gac_nonarea_cbf_bv_21(self):
        """TP/GEONW/PON/GAC/NONAREA/CBF/BV-21: a GAC from an unknown sender D (IUT outside AREA2)
        is re-broadcast after CBF_MAX."""
        self.nonarea_cbf_unknown_sender()

    def test_tp_geonw_pon_gac_nonarea_cbf_bv_22(self):
        """TP/GEONW/PON/GAC/NONAREA/CBF/BV-22: a GAC from a sender D with PAI = 0 (IUT outside
        AREA2) is re-broadcast after CBF_MAX."""
        self.nonarea_cbf_sender_pai_0()

    def test_tp_geonw_pon_gac_area_all_bv_01(self):
        """TP/GEONW/PON/GAC/AREA/ALL/BV-01: a source GAC to AREA1 (IUT inside) is broadcast immediately."""
        self.area_source()

    def test_tp_geonw_pon_gac_area_all_bv_02(self):
        """TP/GEONW/PON/GAC/AREA/ALL/BV-02: a GAC received inside its area is neither forwarded
        nor re-broadcast."""
        iut = _Iut()
        iut.beacons_from(D, B)
        iut.receive(gbc(lpv(B), 2, AREA1, scf=True, anycast=True), B)
        iut.at(500)
        self.assertEqual(iut.sent(HeaderType.GEOANYCAST), [])

    def test_tp_geonw_pon_gac_area_all_bv_05(self):
        """TP/GEONW/PON/GAC/AREA/ALL/BV-05: a GAC received inside its area is passed to the right
        upper protocol."""
        self.area_passed_up()

    def test_tp_geonw_pon_gac_area_all_bo_08(self):
        """TP/GEONW/PON/GAC/AREA/ALL/BO-08: the same GAC received again is not passed up again."""
        self.area_duplicate_not_passed_up()


class TestGnTopologicallyScopedBroadcast(unittest.TestCase):
    """TP/GEONW/PON/TSB: Topologically-Scoped Broadcast (clause 10.3.9)."""

    def test_tp_geonw_pon_tsb_bv_01(self):
        """TP/GEONW/PON/TSB/BV-01: a TSB request is broadcast as a TSB packet."""
        iut = _Iut()
        iut.beacons_from(B, D)
        iut.request_tsb()
        frames = iut.sent(HeaderType.TSB)
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].common.hst, TopoBroadcastHST.MULTI_HOP)
        self.assertIsNone(frames[0].destination)

    def test_tp_geonw_pon_tsb_bv_02(self):
        """TP/GEONW/PON/TSB/BV-02: a TSB with RHL > 1 received for the first time is re-broadcast."""
        iut = _Iut()
        iut.beacons_from(D, B)
        iut.receive(tsb(lpv(C), 4, rhl=5), C)
        frames = iut.sent(HeaderType.TSB)
        self.assertEqual(len(frames), 1)
        self.assertIsNone(frames[0].destination)

    def test_tp_geonw_pon_tsb_bv_03(self):
        """TP/GEONW/PON/TSB/BV-03: the re-broadcast TSB has RHL - 1 and the same MHL."""
        iut = _Iut()
        iut.beacons_from(D, B)
        iut.receive(tsb(lpv(C), 4, rhl=7, mhl=9), C)
        frame = iut.sent(HeaderType.TSB)[0]
        self.assertEqual((frame.basic.rhl, frame.common.mhl), (6, 9))

    def test_tp_geonw_pon_tsb_bo_04(self):
        """TP/GEONW/PON/TSB/BO-04: a TSB with RHL 1 is not re-broadcast."""
        iut = _Iut()
        iut.receive(tsb(lpv(C), 4, rhl=1), C)
        self.assertEqual(iut.sent(HeaderType.TSB), [])

    def test_tp_geonw_pon_tsb_bv_05(self):
        """TP/GEONW/PON/TSB/BV-05: a TSB received for the first time is passed to the right upper protocol."""
        iut = _Iut()
        iut.receive(tsb(lpv(C), 4, payload=b"tsb!"), C)
        self.assertEqual(len(iut.indications), 1)
        self.assertEqual((iut.indications[0].upper_protocol_entity, iut.indications[0].data),
                         (CommonNH.BTP_B, b"tsb!"))

    def test_tp_geonw_pon_tsb_bo_07(self):
        """TP/GEONW/PON/TSB/BO-07: the same TSB received again (from D, RHL - 1) is not re-broadcast again."""
        iut = _Iut()
        iut.beacons_from(D, B)
        packet = tsb(lpv(B), 4, rhl=5)
        iut.receive(packet, B)
        iut.receive(packet[:3] + bytes([4]) + packet[4:], D)
        self.assertEqual(len(iut.sent(HeaderType.TSB)), 1)

    def test_tp_geonw_pon_tsb_bo_08(self):
        """TP/GEONW/PON/TSB/BO-08: the same TSB received again (from D) is not passed up again."""
        iut = _Iut()
        packet = tsb(lpv(B), 4, rhl=5)
        iut.receive(packet, B)
        iut.receive(packet[:3] + bytes([4]) + packet[4:], D)
        self.assertEqual(len(iut.indications), 1)


class TestGnSingleHopBroadcast(unittest.TestCase):
    """TP/GEONW/PON/SHB: Single-Hop Broadcast (clause 10.3.10)."""

    def test_tp_geonw_pon_shb_bv_01(self):
        """TP/GEONW/PON/SHB/BV-01: an SHB request is broadcast as an SHB packet."""
        iut = _Iut()
        iut.beacons_from(D, B)
        iut.request_shb()
        frames = iut.sent(HeaderType.TSB)
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].common.hst, TopoBroadcastHST.SINGLE_HOP)
        self.assertIsNone(frames[0].destination)

    def test_tp_geonw_pon_shb_bv_05(self):
        """TP/GEONW/PON/SHB/BV-05: a received SHB is passed to the upper layer."""
        iut = _Iut()
        iut.receive(shb(lpv(B), b"hello"), B)
        self.assertEqual(len(iut.indications), 1)
        self.assertEqual((iut.indications[0].upper_protocol_entity, iut.indications[0].data),
                         (CommonNH.BTP_B, b"hello"))


if __name__ == "__main__":
    unittest.main()
