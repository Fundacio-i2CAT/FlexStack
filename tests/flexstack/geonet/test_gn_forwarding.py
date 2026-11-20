"""
GeoNetworking forwarding with packet buffers, Location Service buffering and
contention-based forwarding (ETSI TS 103 836-4-1 V2.2.1 (2026-04), clauses
8.5, 8.6, 10.3.5, 10.3.7, 10.3.9, Annexes E and F).

The router runs on an injected clock; timers are driven with ``tick``.

Mirrors the forwarding tests of ``rustflexstack::geonet::router``.
"""

import math
import unittest
from datetime import datetime, timezone
from dataclasses import replace as dataclass_replace
from unittest.mock import MagicMock, Mock, patch

from flexstack.geonet.basic_header import BasicHeader, BasicNH
from flexstack.geonet.common_header import CommonHeader
from flexstack.geonet.gbc_extended_header import GBCExtendedHeader
from flexstack.geonet.gn_address import MID, ST, GNAddress
from flexstack.geonet.guc_extended_header import GUCExtendedHeader
from flexstack.geonet.ls_extended_header import LSReplyExtendedHeader, LSRequestExtendedHeader
from flexstack.geonet.mib import MIB, AreaForwardingAlgorithm, GnIfType, NonAreaForwardingAlgorithm
from flexstack.geonet.position_vector import TST, LongPositionVector, ShortPositionVector
from flexstack.utils.time_service import TimeService
from flexstack.geonet.router import Router
from flexstack.linklayer.raw_link_layer import RawLinkLayer
from flexstack.geonet.service_access_point import (
    Area,
    CommonNH,
    GeoAnycastHST,
    GeoBroadcastHST,
    GNDataRequest,
    HeaderType,
    LocationServiceHST,
    PacketTransportType,
    ResultCode,
    TopoBroadcastHST,
    TrafficClass,
)
from flexstack.geonet.tsb_extended_header import TSBExtendedHeader
from flexstack.security.sn_sap import ReportVerify, SNVERIFYConfirm
from flexstack.security.verify_service import VerifyService

EGO_LAT, EGO_LON = 421255850, 27601710
METRES_PER_DEGREE = 6371000 * math.pi / 180


def north(metres: float) -> int:
    """Latitude of a point ``metres`` north of the ego position."""
    return EGO_LAT + round(metres / METRES_PER_DEGREE * 1e7)


def east(metres: float) -> int:
    """Longitude of a point ``metres`` east of the ego position."""
    return EGO_LON + round(metres / (METRES_PER_DEGREE * math.cos(math.radians(EGO_LAT / 1e7))) * 1e7)


def lpv(n: int, lat: int, lon: int = EGO_LON) -> LongPositionVector:
    """Position vector of ``addr(n)`` stamped now (so that its LocTE does not expire)."""
    return LongPositionVector(gn_addr=addr(n), tst=TST.set_in_normal_timestamp_seconds(TimeService.time()),
                              latitude=lat, longitude=lon, pai=True)


def addr(n: int) -> GNAddress:
    return GNAddress(mid=MID(bytes([0x02, 0, 0, 0, 0, n])))


def make_router(**mib_kwargs):
    # No beacon thread: it would send on its own schedule (beacons tested separately)
    mib_kwargs.setdefault("itsGnBeaconServiceRetransmitTimer", 0)
    now = [0]
    mib = MIB(**mib_kwargs)
    router = Router(mib, clock=lambda: now[0])
    router.ego_position_vector = LongPositionVector(
        gn_addr=mib.itsGnLocalGnAddr, latitude=EGO_LAT, longitude=EGO_LON, pai=True)
    router.link_layer = Mock()
    return router, now


def add_neighbour(router: Router, n: int, lat: int, lon: int = EGO_LON) -> None:
    router.location_table.new_shb_packet(
        lpv(n, lat, lon), b"")


def sent(router: Router) -> list:
    return [c[0][0] for c in router.link_layer.send.call_args_list]


def beacon_from(router: Router, n: int, lat: int) -> bytes:
    basic = BasicHeader.initialize_with_mib(router.mib).set_rhl(1)
    common = CommonHeader(ht=HeaderType.BEACON, mhl=1)
    pv = lpv(n, lat)
    return basic.encode_to_bytes() + common.encode_to_bytes() + pv.encode()


def gbc_packet(router: Router, so: LongPositionVector, sn: int, area: Area, rhl: int = 5) -> bytes:
    basic = BasicHeader.initialize_with_mib(router.mib).set_rhl(rhl)
    common = CommonHeader(nh=CommonNH.BTP_B, ht=HeaderType.GEOBROADCAST,
                          hst=GeoBroadcastHST.GEOBROADCAST_CIRCLE, mhl=10)  # type: ignore
    ext = GBCExtendedHeader(sn=sn, so_pv=so, latitude=area.latitude, longitude=area.longitude,
                            a=area.a, b=area.b, angle=area.angle)
    return basic.encode_to_bytes() + common.encode_to_bytes() + ext.encode() + b"payload"


def guc_packet(router: Router, so: LongPositionVector, sn: int, de: ShortPositionVector) -> bytes:
    basic = BasicHeader.initialize_with_mib(router.mib).set_rhl(5)
    common = CommonHeader(nh=CommonNH.BTP_A, ht=HeaderType.GEOUNICAST, mhl=10)
    ext = GUCExtendedHeader(sn=sn, so_pv=so, de_pv=de)
    return basic.encode_to_bytes() + common.encode_to_bytes() + ext.encode() + b"payload"


def shb_request(scf: bool = False, lifetime=None) -> GNDataRequest:
    return GNDataRequest(
        packet_transport_type=PacketTransportType(
            header_type=HeaderType.TSB, header_subtype=TopoBroadcastHST.SINGLE_HOP),
        traffic_class=TrafficClass(scf=scf), max_packet_lifetime=lifetime, data=b"shb")


def guc_request(destination: GNAddress) -> GNDataRequest:
    return GNDataRequest(
        packet_transport_type=PacketTransportType(header_type=HeaderType.GEOUNICAST),
        destination=destination, data=b"guc")


class TestStoreCarryForward(unittest.TestCase):
    """Clauses 8.6 and 10.3.5 step 2."""

    def test_shb_buffered_without_neighbour_and_flushed_on_reception(self):
        router, now = make_router()
        confirm = router.gn_data_request(shb_request(scf=True))
        self.assertEqual(confirm.result_code, ResultCode.ACCEPTED)
        router.link_layer.send.assert_not_called()
        now[0] = 2000
        router.gn_data_indicate(beacon_from(router, 2, north(100)))
        packets = sent(router)
        self.assertEqual(len(packets), 1)
        self.assertEqual(CommonHeader.decode_from_bytes(packets[0][4:12]).ht, HeaderType.TSB)
        # LT reduced by the queuing time (60 s default lifetime, 2 s queued)
        self.assertLess(BasicHeader.decode_from_bytes(packets[0][0:4]).lt.get_value_in_millis(), 60_000)

    def test_buffered_packet_discarded_after_its_lifetime(self):
        router, now = make_router()
        router.gn_data_request(shb_request(scf=True, lifetime=1))
        now[0] = 1500
        router.gn_data_indicate(beacon_from(router, 2, north(100)))
        router.link_layer.send.assert_not_called()

    def test_without_scf_the_packet_is_sent(self):
        router, _ = make_router()
        router.gn_data_request(shb_request(scf=False))
        self.assertEqual(len(sent(router)), 1)

    def test_greedy_local_optimum_buffers_guc_in_uc_buffer(self):
        """E.2: forwarder at a local optimum with SCF keeps the packet per destination."""
        router, _ = make_router()
        add_neighbour(router, 3, north(-200))                # behind ego
        dest = ShortPositionVector(gn_addr=addr(9), latitude=north(1000), longitude=EGO_LON)
        so = lpv(2, north(-100))
        basic = BasicHeader.initialize_with_mib(router.mib).set_rhl(5)
        common = CommonHeader(nh=CommonNH.BTP_A, ht=HeaderType.GEOUNICAST, tc=TrafficClass(scf=True), mhl=10)
        packet = basic.encode_to_bytes() + common.encode_to_bytes()
        packet += GUCExtendedHeader(sn=1, so_pv=so, de_pv=dest).encode() + b"x"
        router.gn_data_indicate(packet)
        router.link_layer.send.assert_not_called()
        self.assertEqual(len(router._uc_buffers[addr(9)]), 1)
        # A packet from the destination flushes its UC forwarding packet buffer
        router.gn_data_indicate(beacon_from(router, 9, north(150)))
        packets = sent(router)
        self.assertEqual(len(packets), 1)
        self.assertEqual(CommonHeader.decode_from_bytes(packets[0][4:12]).ht, HeaderType.GEOUNICAST)


class TestTsbSource(unittest.TestCase):
    """Clause 10.3.9.2."""

    def test_tsb_request_sends_multi_hop_packet(self):
        router, _ = make_router()
        confirm = router.gn_data_request(GNDataRequest(
            packet_transport_type=PacketTransportType(
                header_type=HeaderType.TSB, header_subtype=TopoBroadcastHST.MULTI_HOP),
            data=b"tsb"))
        self.assertEqual(confirm.result_code, ResultCode.ACCEPTED)
        packet = sent(router)[0]
        common = CommonHeader.decode_from_bytes(packet[4:12])
        self.assertEqual((common.ht, common.hst), (HeaderType.TSB, TopoBroadcastHST.MULTI_HOP))
        self.assertEqual(BasicHeader.decode_from_bytes(packet[0:4]).rhl, router.mib.itsGnDefaultHopLimit)
        ext = TSBExtendedHeader.decode(packet[12:40])
        self.assertEqual(ext.so_pv.gn_addr, router.mib.itsGnLocalGnAddr)
        self.assertEqual(packet[40:], b"tsb")


class TestLocationServiceBuffer(unittest.TestCase):
    """Clauses 8.5 and 10.3.7.1."""

    def ls_reply(self, router: Router, n: int) -> bytes:
        basic = BasicHeader.initialize_with_mib(router.mib).set_rhl(5)
        common = CommonHeader(ht=HeaderType.LS, hst=LocationServiceHST.LS_REPLY, mhl=10)  # type: ignore
        ext = LSReplyExtendedHeader(
            sn=1, so_pv=LongPositionVector(gn_addr=addr(n), latitude=north(300), longitude=EGO_LON, pai=True),
            de_pv=ShortPositionVector(gn_addr=router.mib.itsGnLocalGnAddr))
        return basic.encode_to_bytes() + common.encode_to_bytes() + ext.encode()

    def test_guc_buffered_until_ls_reply(self):
        router, now = make_router()
        router.gn_data_request(guc_request(addr(7)))
        router.gn_data_request(guc_request(addr(7)))          # LS pending: buffered too
        packets = sent(router)
        self.assertEqual(len(packets), 1)
        self.assertEqual(CommonHeader.decode_from_bytes(packets[0][4:12]).ht, HeaderType.LS)
        now[0] = 500
        router.gn_data_indicate(self.ls_reply(router, 7))
        packets = sent(router)
        self.assertEqual(len(packets), 3)
        for packet in packets[1:]:
            self.assertEqual(CommonHeader.decode_from_bytes(packet[4:12]).ht, HeaderType.GEOUNICAST)
            de = GUCExtendedHeader.decode(packet[12:60]).de_pv
            self.assertEqual(de.latitude, north(300))
        self.assertIsNone(router.next_deadline())

    def test_ls_retransmission_then_abandon(self):
        router, now = make_router(itsGnLocationServiceMaxRetrans=2)
        router.gn_data_request(guc_request(addr(7)))
        self.assertEqual(router.next_deadline(), 1000)
        for t in (1000, 2000):
            now[0] = t
            router.tick()
        self.assertEqual(len(sent(router)), 3)
        now[0] = 3000
        router.tick()
        self.assertEqual(len(sent(router)), 3)
        self.assertIsNone(router.location_table.get_entry(addr(7)))
        self.assertNotIn(addr(7), router._ls_packet_buffers)
        self.assertIsNone(router.next_deadline())


class TestAreaCbf(unittest.TestCase):
    """Annex F.3 (segment-based area CBF) (CBF)."""

    AREA = Area(latitude=EGO_LAT, longitude=EGO_LON, a=1500, b=1500, angle=0)

    def gbc_request(self) -> GNDataRequest:
        return GNDataRequest(
            packet_transport_type=PacketTransportType(
                header_type=HeaderType.GEOBROADCAST, header_subtype=GeoBroadcastHST.GEOBROADCAST_CIRCLE),
            area=Area(latitude=EGO_LAT, longitude=EGO_LON, a=100, b=100, angle=0), data=b"gbc")

    def test_source_rebroadcasts_after_to_cbf_max(self):
        router, now = make_router()
        router.gn_data_request(self.gbc_request())
        self.assertEqual(len(sent(router)), 1)
        self.assertEqual(router.next_deadline(), router.mib.itsGnCbfMaxTime)
        now[0] = router.mib.itsGnCbfMaxTime
        router.tick()
        self.assertEqual(len(sent(router)), 2)

    def test_source_stops_when_a_forwarded_copy_is_heard(self):
        router, now = make_router()
        router.gn_data_request(self.gbc_request())
        original = sent(router)[0]
        forwarded = BasicHeader.decode_from_bytes(original[0:4]).set_rhl(9).encode_to_bytes() + original[4:]
        router.gn_data_indicate(forwarded, sender_ll_address=addr(2).mid.mid)
        now[0] = 1000
        router.tick()
        self.assertEqual(len(sent(router)), 1)

    def receive_from_source(self, router: Router):
        """GBC from SO = addr(2), 500 m north, received directly from it."""
        add_neighbour(router, 2, north(500))
        so = lpv(2, north(500))
        packet = gbc_packet(router, so, 7, self.AREA)
        router.gn_data_indicate(packet, sender_ll_address=addr(2).mid.mid)
        return packet

    def test_forwarder_timeout_from_forwarding_distance(self):
        router, _ = make_router()
        callback = MagicMock()
        router.register_indication_callback(callback)
        self.receive_from_source(router)
        callback.assert_called_once()
        router.link_layer.send.assert_not_called()
        expected = math.ceil(router._cbf_timeout(500))           # F_DIST = 500 m
        self.assertAlmostEqual(router.next_deadline(), expected, delta=1)

    def test_duplicate_from_better_forwarder_cancels(self):
        router, now = make_router()
        packet = self.receive_from_source(router)
        add_neighbour(router, 3, north(-600))      # D1=500 < D2=1100, D2 > D3=600
        router.gn_data_indicate(packet, sender_ll_address=addr(3).mid.mid)
        self.assertEqual(len(router._cbf_buffer), 0)
        now[0] = 1000
        router.tick()
        router.link_layer.send.assert_not_called()

    def test_duplicate_from_worse_forwarder_keeps_the_packet(self):
        router, now = make_router()
        packet = self.receive_from_source(router)
        deadline = router.next_deadline()
        add_neighbour(router, 4, north(100))       # between ego and SO: D2=400 < D1
        now[0] = 10
        router.gn_data_indicate(packet, sender_ll_address=addr(4).mid.mid)
        self.assertEqual(len(router._cbf_buffer), 1)
        self.assertLessEqual(router.next_deadline(), deadline)
        now[0] = 1000
        router.tick()
        self.assertEqual(len(sent(router)), 1)


class TestNonAreaCbf(unittest.TestCase):
    """Annex E.3 (non-area CBF) for GUC forwarders."""

    def make(self):
        router, now = make_router(itsGnNonAreaForwardingAlgorithm=NonAreaForwardingAlgorithm.CBF,
                                  itsGnAreaForwardingAlgorithm=AreaForwardingAlgorithm.SIMPLE)
        self.dest = ShortPositionVector(gn_addr=addr(9), latitude=north(2000), longitude=EGO_LON)
        return router, now

    def test_forwarder_with_progress_buffers_with_segment_timeout(self):
        router, _ = self.make()
        add_neighbour(router, 2, north(-300))
        so = lpv(2, north(-300))
        router.gn_data_indicate(guc_packet(router, so, 1, self.dest), sender_ll_address=addr(2).mid.mid)
        router.link_layer.send.assert_not_called()
        self.assertAlmostEqual(router.next_deadline(), math.ceil(router._cbf_timeout(300)), delta=1)

    def test_forwarder_without_progress_discards(self):
        router, _ = self.make()
        add_neighbour(router, 5, north(300))
        so = lpv(5, north(300))
        router.gn_data_indicate(guc_packet(router, so, 1, self.dest), sender_ll_address=addr(5).mid.mid)
        self.assertEqual(len(router._cbf_buffer), 0)
        router.link_layer.send.assert_not_called()


def guc_source_request(destination: GNAddress, scf: bool, data: bytes = b"guc") -> GNDataRequest:
    return GNDataRequest(
        packet_transport_type=PacketTransportType(header_type=HeaderType.GEOUNICAST),
        destination=destination, traffic_class=TrafficClass(scf=scf), data=data)


def sequence_number(packet: bytes) -> int:
    return int.from_bytes(packet[12:14], "big")


def lifetime_ms(packet: bytes) -> int:
    return BasicHeader.decode_from_bytes(packet[0:4]).lt.get_value_in_millis()


class TestForwardingPacketBuffers(unittest.TestCase):
    """(clause 8.6)."""

    def known_destination(self, router: Router, n: int = 9) -> None:
        """LocTE of a non-neighbour destination, learnt from a GUC it originated."""
        router.location_table.new_guc_packet(
            GUCExtendedHeader(sn=99, so_pv=lpv(n, north(800)), de_pv=ShortPositionVector()), b"")

    def test_guc_source_buffered_and_sent_when_a_neighbour_appears(self):
        """UC buffer, FIFO, LT reduced by the queuing time."""
        router, now = make_router()
        self.known_destination(router)
        router.gn_data_request(guc_source_request(addr(9), scf=True, data=b"first"))
        router.gn_data_request(guc_source_request(addr(9), scf=True, data=b"second"))
        router.link_layer.send.assert_not_called()
        now[0] = 3000
        router.gn_data_indicate(beacon_from(router, 2, north(400)))
        packets = sent(router)
        self.assertTrue(packets[0].endswith(b"first") and packets[1].endswith(b"second"))
        self.assertLess(sequence_number(packets[0]), sequence_number(packets[1]))
        self.assertLess(lifetime_ms(packets[0]), 60_000)

    def test_gbc_source_buffered_without_recipients(self):
        """BC buffer for GBC, FIFO, LT reduced."""
        router, now = make_router(itsGnAreaForwardingAlgorithm=AreaForwardingAlgorithm.SIMPLE)
        for data in (b"g1", b"g2"):
            router.gn_data_request(GNDataRequest(
                packet_transport_type=PacketTransportType(
                    header_type=HeaderType.GEOBROADCAST, header_subtype=GeoBroadcastHST.GEOBROADCAST_CIRCLE),
                area=Area(latitude=EGO_LAT, longitude=EGO_LON, a=100, b=100, angle=0),
                traffic_class=TrafficClass(scf=True), data=data))
        router.link_layer.send.assert_not_called()
        now[0] = 2000
        router.gn_data_indicate(beacon_from(router, 2, north(50)))
        packets = sent(router)
        self.assertEqual([p[-2:] for p in packets], [b"g1", b"g2"])
        self.assertLess(lifetime_ms(packets[0]), 60_000)

    def test_bc_buffer_capacity_head_drop(self):
        """itsGnBcForwardingPacketBufferSize, head drop."""
        router, _ = make_router(itsGnBcForwardingPacketBufferSize=1)     # 1 Ko
        for i in range(3):        # 440-octet SHB packets: only two fit in 1024 octets
            router.gn_data_request(GNDataRequest(
                packet_transport_type=PacketTransportType(
                    header_type=HeaderType.TSB, header_subtype=TopoBroadcastHST.SINGLE_HOP),
                traffic_class=TrafficClass(scf=True), data=bytes([i]) * 400))
        self.assertLessEqual(router._bc_buffer.size, 1024)
        router.gn_data_indicate(beacon_from(router, 2, north(50)))
        payloads = [p[-1] for p in sent(router) if len(p) > 400]
        self.assertEqual(payloads, [1, 2])                  # the oldest was dropped


class TestLocationServicePacketBuffer(unittest.TestCase):
    """(clause 8.5)."""

    def test_flushed_by_any_packet_from_the_destination(self):
        router, now = make_router()
        router.gn_data_request(guc_source_request(addr(7), scf=False, data=b"a"))
        router.gn_data_request(guc_source_request(addr(7), scf=False, data=b"b"))
        now[0] = 400
        router.gn_data_indicate(beacon_from(router, 7, north(100)))
        packets = sent(router)[1:]
        self.assertEqual([p[-1:] for p in packets], [b"a", b"b"])              # FIFO
        self.assertLess(sequence_number(packets[0]), sequence_number(packets[1]))
        self.assertLess(lifetime_ms(packets[0]), 60_000)                    # LT reduced
        self.assertFalse(router.location_table.get_entry(addr(7)).ls_pending)
        self.assertIsNone(router.next_deadline())

    def test_expired_packets_are_not_sent(self):
        router, now = make_router()
        short = dataclass_replace(guc_source_request(addr(7), scf=False, data=b"s"), max_packet_lifetime=1)
        router.gn_data_request(short)
        router.gn_data_request(guc_source_request(addr(7), scf=False, data=b"l"))
        now[0] = 1500
        router.gn_data_indicate(beacon_from(router, 7, north(100)))
        self.assertEqual([p[-1:] for p in sent(router)[1:]], [b"l"])

    def test_capacity_head_drop(self):
        router, _ = make_router()                       # itsGnLocationServicePacketBufferSize = 1024
        for i in range(3):
            router.gn_data_request(guc_source_request(addr(7), scf=False, data=bytes([i]) * 400))
        router.gn_data_indicate(beacon_from(router, 7, north(100)))
        self.assertEqual([p[-1] for p in sent(router)[1:]], [1, 2])


class TestCbfTimers(unittest.TestCase):
    """timing and duplicates."""

    def non_area(self):
        return make_router(itsGnNonAreaForwardingAlgorithm=NonAreaForwardingAlgorithm.CBF,
                           itsGnAreaForwardingAlgorithm=AreaForwardingAlgorithm.SIMPLE)

    def dest(self):
        return ShortPositionVector(gn_addr=addr(9), latitude=north(2000), longitude=EGO_LON)

    def test_guc_source_sends_immediately(self):
        router, _ = self.non_area()
        TestForwardingPacketBuffers().known_destination(router)
        router.gn_data_request(guc_source_request(addr(9), scf=False))
        self.assertEqual(len(sent(router)), 1)
        self.assertEqual(router.next_deadline(), router.mib.itsGnCbfMaxTime)

    def test_guc_forwarded_at_contention_timeout(self):
        router, now = self.non_area()
        add_neighbour(router, 2, north(-300))
        router.gn_data_indicate(guc_packet(router, lpv(2, north(-300)), 1, self.dest()),
                                sender_ll_address=addr(2).mid.mid)
        deadline = router.next_deadline()
        now[0] = deadline - 1
        router.tick()
        router.link_layer.send.assert_not_called()
        now[0] = deadline
        router.tick()
        self.assertEqual(len(sent(router)), 1)

    def test_guc_duplicate_from_better_forwarder_cancels(self):
        router, now = self.non_area()
        add_neighbour(router, 2, north(-300))
        packet = guc_packet(router, lpv(2, north(-300)), 1, self.dest())
        router.gn_data_indicate(packet, sender_ll_address=addr(2).mid.mid)
        add_neighbour(router, 3, north(400))            # closer to the destination
        router.gn_data_indicate(packet, sender_ll_address=addr(3).mid.mid)
        now[0] = 1000
        router.tick()
        router.link_layer.send.assert_not_called()

    def test_guc_minimum_delay_at_dist_max(self):
        """PROG = DIST_MAX gives TO_CBF_MIN."""
        router, _ = self.non_area()
        dist_max = router.mib.itsGnDefaultMaxCommunicationRange
        add_neighbour(router, 2, north(-dist_max))
        router.gn_data_indicate(guc_packet(router, lpv(2, north(-dist_max)), 1, self.dest()),
                                sender_ll_address=addr(2).mid.mid)
        self.assertLessEqual(router.next_deadline(), router.mib.itsGnCbfMinTime + 1)

    def test_unknown_or_uncertain_sender_uses_to_cbf_max(self):
        for area_mode in (False, True):
            for pai in (None, False):          # None: sender unknown
                with self.subTest(area=area_mode, pai=pai):
                    router, _ = self.non_area() if not area_mode else make_router()
                    so = lpv(2, north(-300))
                    if pai is not None:
                        router.location_table.new_shb_packet(
                            dataclass_replace(lpv(4, north(-300)), pai=False), b"")
                    sender = addr(4).mid.mid
                    if area_mode:
                        packet = gbc_packet(router, so, 1, TestAreaCbf.AREA)
                    else:
                        packet = guc_packet(router, so, 1, self.dest())
                    router.gn_data_indicate(packet, sender_ll_address=sender)
                    self.assertEqual(router.next_deadline(), router.mib.itsGnCbfMaxTime)

    def test_gbc_received_again_after_forwarding_is_discarded(self):
        router, now = make_router()
        add_neighbour(router, 2, north(500))
        packet = gbc_packet(router, lpv(2, north(500)), 7, TestAreaCbf.AREA)
        router.gn_data_indicate(packet, sender_ll_address=addr(2).mid.mid)
        now[0] = 1000
        router.tick()
        self.assertEqual(len(sent(router)), 1)
        router.gn_data_indicate(packet, sender_ll_address=addr(2).mid.mid)
        now[0] = 2000
        router.tick()
        self.assertEqual(len(sent(router)), 1)
        self.assertEqual(len(router._cbf_buffer), 0)


class TestAreaPacketHandling(unittest.TestCase):
    """Ports of the Rust router tests for GBC/GAC handling (TS 102 871-2 test purposes)."""

    REMOTE = Area(latitude=north(3000), longitude=EGO_LON, a=100, b=100, angle=0)

    def test_non_area_forwarding_outside_the_area(self):
        router, _ = make_router()
        callback = MagicMock()
        router.register_indication_callback(callback)
        so = lpv(2, north(-100))
        router.gn_data_indicate(gbc_packet(router, so, 1, self.REMOTE, rhl=5))
        packets = sent(router)
        self.assertEqual(len(packets), 1)
        self.assertEqual(BasicHeader.decode_from_bytes(packets[0][0:4]).rhl, 4)
        router.gn_data_indicate(gbc_packet(router, so, 2, self.REMOTE, rhl=1))
        self.assertEqual(len(sent(router)), 1)
        callback.assert_not_called()

    def test_simple_area_forwarding_rhl_restriction(self):
        router, _ = make_router(itsGnAreaForwardingAlgorithm=AreaForwardingAlgorithm.SIMPLE)
        callback = MagicMock()
        router.register_indication_callback(callback)
        so = lpv(2, north(100))
        router.gn_data_indicate(gbc_packet(router, so, 1, TestAreaCbf.AREA, rhl=5))
        router.gn_data_indicate(gbc_packet(router, so, 2, TestAreaCbf.AREA, rhl=1))
        packets = sent(router)
        self.assertEqual(len(packets), 1)
        self.assertEqual(BasicHeader.decode_from_bytes(packets[0][0:4]).rhl, 4)
        self.assertEqual(callback.call_count, 2)


class TestBeaconReset(unittest.TestCase):
    """(clause 10.3.10.2 step 7): an SHB restarts the beacon timer."""

    def test_shb_resets_the_beacon_timer(self):
        router, now = make_router(itsGnBeaconServiceRetransmitTimer=3000, itsGnBeaconServiceMaxJitter=750)
        first = router.next_deadline()
        self.assertEqual(first, 1500)                 # first Beacon after half a period
        now[0] = 1000
        router.gn_data_request(shb_request())
        self.assertTrue(4000 <= router.next_deadline() <= 4750)


class TestSecuredForwarding(unittest.TestCase):
    """Clauses 8.6.3 NOTE 1 / 10.3.8.3 step 8: forwarded secured packets are relayed unmodified."""

    def test_forwarded_tsb_keeps_the_secured_packet(self):
        router, _ = make_router()
        so = lpv(2, north(100))
        common = CommonHeader(nh=CommonNH.BTP_B, ht=HeaderType.TSB,
                              hst=TopoBroadcastHST.MULTI_HOP, mhl=10)  # type: ignore
        plain = common.encode_to_bytes() + TSBExtendedHeader(sn=3, so_pv=so).encode() + b"payload"
        verify = MagicMock(spec=VerifyService)
        verify.verify.return_value = SNVERIFYConfirm(
            report=ReportVerify.SUCCESS, certificate_id=b"", its_aid=b"", its_aid_length=0,
            permissions=b"", plain_message=plain)
        router.verify_service = verify
        secured = b"\x03\x81\x00SIGNED-DATA"
        basic = BasicHeader.initialize_with_mib(router.mib).set_rhl(5).set_nh(BasicNH.SECURED_PACKET)
        router.gn_data_indicate(basic.encode_to_bytes() + secured)
        packet = sent(router)[0]
        self.assertEqual(packet[4:], secured)
        forwarded_basic = BasicHeader.decode_from_bytes(packet[0:4])
        self.assertEqual((forwarded_basic.nh, forwarded_basic.rhl), (BasicNH.SECURED_PACKET, 4))


class TestAreaAngle(unittest.TestCase):
    """Geometric function F with a rotated area (azimuth of side a)."""

    def test_rectangle_rotation(self):
        router, _ = make_router()
        hst = GeoBroadcastHST.GEOBROADCAST_RECT
        for angle, inside, outside in ((0, (north(50), EGO_LON), (EGO_LAT, east(50))),
                                       (90, (EGO_LAT, east(50)), (north(50), EGO_LON))):
            area = Area(latitude=EGO_LAT, longitude=EGO_LON, a=100, b=10, angle=angle)
            with self.subTest(angle=angle):
                self.assertGreater(router.gn_geometric_function_f(hst, area, *inside), 0)
                self.assertLess(router.gn_geometric_function_f(hst, area, *outside), 0)


if __name__ == "__main__":
    unittest.main()


class TestSecurityIntegration(unittest.TestCase):
    """GN with the security entity: no valid AT, no packet; Table 38 results in the indication."""

    def test_no_valid_at_means_no_packet(self):
        """IEEE 1609.2 clause 5.2.3.2.2: the message is not sent when signing is refused."""
        from flexstack.geonet.mib import GnSecurity
        from flexstack.security.sign_service import SigningError
        router, _ = make_router(itsGnSecurity=GnSecurity.ENABLED)
        router.sign_service = MagicMock()
        router.sign_service.sign_request.side_effect = SigningError("no AT")
        confirm = router.gn_data_request(shb_request())
        self.assertEqual(confirm.result_code, ResultCode.UNSPECIFIED)
        router.link_layer.send.assert_not_called()

    def test_security_results_in_indication(self):
        router, _ = make_router()
        so = lpv(2, north(100))
        common = CommonHeader(nh=CommonNH.BTP_B, ht=HeaderType.TSB, hst=TopoBroadcastHST.SINGLE_HOP,
                              mhl=1)  # type: ignore
        plain = common.encode_to_bytes() + so.encode() + b"\x00" * 4 + b"payload"
        verify = MagicMock(spec=VerifyService)
        verify.verify.return_value = SNVERIFYConfirm(
            report=ReportVerify.SUCCESS, certificate_id=b"\x01" * 8, its_aid=b"\x24",
            its_aid_length=1, permissions=b"\x02\x02\x00", plain_message=plain)
        router.verify_service = verify
        callback = MagicMock()
        router.register_indication_callback(callback)
        basic = BasicHeader.initialize_with_mib(router.mib).set_rhl(1).set_nh(BasicNH.SECURED_PACKET)
        router.gn_data_indicate(basic.encode_to_bytes() + b"SECURED")
        indication = callback.call_args[0][0]
        self.assertEqual((indication.security_report, indication.its_aid), (0, 36))
        self.assertEqual(indication.certificate_id, b"\x01" * 8)
        self.assertEqual(indication.security_permissions, b"\x02\x02\x00")


def _secured_psid(frame: bytes):
    """PSID of a secured frame; None when the frame is not secured."""
    from flexstack.security.certificate import SECURITY_CODER
    if BasicHeader.decode_from_bytes(frame[0:4]).nh != BasicNH.SECURED_PACKET:
        return None
    signed = SECURITY_CODER.decode_etsi_ts_103097_data_signed(frame[4:])["content"][1]
    return signed["tbsData"]["headerInfo"]["psid"]


def _gbc_request(its_aid=0, profile=None, header_type=HeaderType.GEOBROADCAST,
                 subtype=GeoBroadcastHST.GEOBROADCAST_CIRCLE) -> GNDataRequest:
    from flexstack.security.security_profiles import SecurityProfile
    return GNDataRequest(
        packet_transport_type=PacketTransportType(header_type=header_type, header_subtype=subtype),
        area=Area(latitude=EGO_LAT, longitude=EGO_LON, a=100, b=100, angle=0),
        security_profile=profile or SecurityProfile.NO_SECURITY, its_aid=its_aid, data=b"req")


def _denm_gbc_request() -> GNDataRequest:
    from flexstack.security.security_profiles import SecurityProfile
    return _gbc_request(37, SecurityProfile.DECENTRALIZED_ENVIRONMENTAL_NOTIFICATION_MESSAGE)


def _generic_guc_request(destination: GNAddress) -> GNDataRequest:
    return dataclass_replace(guc_request(destination), its_aid=3)


class TestSourceSecurity(unittest.TestCase):
    """
    Security encapsulation of GBC, GAC and GUC packets at the source (clause 9.4):
    signed when itsGnSecurity is enabled, whatever the message; unsecured when it
    is disabled. Mirrors the Rust forwarding tests of the same names.
    """

    def _secured_router(self, sign=True):
        from flexstack.geonet.mib import GnSecurity
        from flexstack.security.sign_service import SignService
        from tests.flexstack.facilities.ca_basic_service.test_cam_conformance import _Pki
        router, _ = make_router(itsGnSecurity=GnSecurity.ENABLED)
        if sign:
            pki = _Pki()
            at = pki.at([{"psid": 37}, {"psid": 3}])
            router.sign_service = SignService(backend=pki.backend, certificate_library=pki.library(at))
        add_neighbour(router, 9, north(50))
        return router

    def test_gbc_denm_unsecured_when_security_disabled(self):
        router, _ = make_router()
        add_neighbour(router, 9, north(50))
        confirm = router.gn_data_request(_denm_gbc_request())
        self.assertEqual(confirm.result_code, ResultCode.ACCEPTED)
        frames = sent(router)
        self.assertEqual(len(frames), 1)
        self.assertIsNone(_secured_psid(frames[0]))
        self.assertEqual(CommonHeader.decode_from_bytes(frames[0][4:12]).ht, HeaderType.GEOBROADCAST)

    def test_gbc_gac_guc_not_sent_when_security_enabled_without_sign_service(self):
        router = self._secured_router(sign=False)
        gac = _gbc_request(header_type=HeaderType.GEOANYCAST, subtype=GeoAnycastHST.GEOANYCAST_CIRCLE)
        for request in (_denm_gbc_request(), gac, _generic_guc_request(addr(9))):
            with self.subTest(header_type=request.packet_transport_type.header_type):
                with self.assertRaises(ValueError):
                    router.gn_data_request(request)
        router.link_layer.send.assert_not_called()

    def test_gbc_and_guc_signed_when_security_enabled(self):
        router = self._secured_router()
        router.gn_data_request(_denm_gbc_request())
        router.gn_data_request(_gbc_request(its_aid=3))
        router.gn_data_request(_generic_guc_request(addr(9)))
        self.assertEqual([_secured_psid(f) for f in sent(router)], [37, 3, 3])

    def test_gbc_not_sent_when_no_at_may_sign(self):
        router = self._secured_router()
        confirm = router.gn_data_request(_gbc_request(its_aid=140))   # not in the AT appPermissions
        self.assertEqual(confirm.result_code, ResultCode.UNSPECIFIED)
        router.link_layer.send.assert_not_called()


class TestRouterPorts(unittest.TestCase):
    """Ports of Rust router tests (TS 102 871-2 test purposes)."""

    def test_gac_source_header(self):
        """GAC header built by the source."""
        router, _ = make_router()
        router.gn_data_request(GNDataRequest(
            packet_transport_type=PacketTransportType(
                header_type=HeaderType.GEOANYCAST, header_subtype=GeoAnycastHST.GEOANYCAST_CIRCLE),
            area=Area(latitude=EGO_LAT, longitude=EGO_LON, a=100, b=100, angle=0), data=b"gac"))
        packets = sent(router)
        self.assertEqual(len(packets), 1)
        self.assertEqual(CommonHeader.decode_from_bytes(packets[0][4:12]).ht, HeaderType.GEOANYCAST)
        ext = GBCExtendedHeader.decode(packets[0][12:56])
        self.assertEqual(ext.so_pv.gn_addr, router.mib.itsGnLocalGnAddr)
        self.assertEqual(ext.so_pv.latitude, EGO_LAT)
        self.assertEqual((ext.latitude, ext.longitude, ext.a, ext.b), (EGO_LAT, EGO_LON, 100, 100))

    def test_ls_request_for_ego_is_answered_once(self):
        """one LS Reply, none for the duplicate."""
        router, _ = make_router()
        basic = BasicHeader.initialize_with_mib(router.mib).set_rhl(5)
        common = CommonHeader(ht=HeaderType.LS, hst=LocationServiceHST.LS_REQUEST, mhl=10)  # type: ignore
        ext = LSRequestExtendedHeader(sn=5, so_pv=lpv(2, north(-100)),
                                      request_gn_addr=router.mib.itsGnLocalGnAddr)
        request = basic.encode_to_bytes() + common.encode_to_bytes() + ext.encode()
        router.gn_data_indicate(request)
        router.gn_data_indicate(request)
        packets = sent(router)
        self.assertEqual(len(packets), 1)
        common = CommonHeader.decode_from_bytes(packets[0][4:12])
        self.assertEqual((common.ht, common.hst), (HeaderType.LS, LocationServiceHST.LS_REPLY))
        self.assertEqual(LSReplyExtendedHeader.decode(packets[0][12:60]).de_pv.gn_addr, addr(2))

    def test_guc_forwarder_without_scf_broadcasts_at_local_optimum(self):
        """no better next hop and no SCF:
        broadcast at once with RHL - 1; not passed up (destination is not the IUT)."""
        router, _ = make_router()
        callback = MagicMock()
        router.register_indication_callback(callback)
        add_neighbour(router, 3, north(-200))                 # behind the ego
        destination = ShortPositionVector(gn_addr=addr(9), latitude=north(1000), longitude=EGO_LON)
        router.gn_data_indicate(guc_packet(router, lpv(2, north(-100)), 1, destination))
        packets = sent(router)
        self.assertEqual(len(packets), 1)
        self.assertEqual(BasicHeader.decode_from_bytes(packets[0][0:4]).rhl, 4)
        callback.assert_not_called()

    def test_guc_to_ego_delivered_once(self):
        """a duplicate GUC for the IUT is not passed up again."""
        router, _ = make_router()
        callback = MagicMock()
        router.register_indication_callback(callback)
        to_ego = ShortPositionVector(gn_addr=router.mib.itsGnLocalGnAddr, latitude=EGO_LAT,
                                     longitude=EGO_LON)
        packet = guc_packet(router, lpv(2, north(-100)), 2, to_ego)
        router.gn_data_indicate(packet)
        router.gn_data_indicate(packet)
        callback.assert_called_once()
        self.assertEqual(callback.call_args[0][0].data, b"payload")
        self.assertEqual(sent(router), [])

    def test_tsb_forwarding_rhl(self):
        """TSB re-broadcast with RHL - 1; not with RHL 1."""
        router, _ = make_router()
        callback = MagicMock()
        router.register_indication_callback(callback)
        for sn, rhl in ((1, 5), (2, 1)):
            basic = BasicHeader.initialize_with_mib(router.mib).set_rhl(rhl)
            common = CommonHeader(nh=CommonNH.BTP_B, ht=HeaderType.TSB,
                                  hst=TopoBroadcastHST.MULTI_HOP, mhl=10)  # type: ignore
            ext = TSBExtendedHeader(sn=sn, so_pv=lpv(2, north(100)))
            headers = basic.encode_to_bytes() + common.encode_to_bytes()
            router.gn_data_indicate(headers + ext.encode() + b"payload")
        packets = sent(router)
        self.assertEqual(len(packets), 1)
        self.assertEqual(BasicHeader.decode_from_bytes(packets[0][0:4]).rhl, 4)
        self.assertEqual(callback.call_count, 2)

    def test_beacon_periodicity(self):
        """(clause 10.3.6.2): a beacon every
        itsGnBeaconServiceRetransmitTimer + RAND[0, itsGnBeaconServiceMaxJitter]
        ms; an SHB during the wait restarts it without a beacon."""
        router, now = make_router(itsGnBeaconServiceRetransmitTimer=3000, itsGnBeaconServiceMaxJitter=750)
        times = []
        while len(times) < 4:
            now[0] = router.next_deadline()
            router.tick()
            times.append(now[0])
        packets = sent(router)
        self.assertEqual(len(packets), 4)
        for packet in packets:
            self.assertEqual(CommonHeader.decode_from_bytes(packet[4:12]).ht, HeaderType.BEACON)
        for previous, current in zip(times, times[1:]):
            self.assertTrue(3000 <= current - previous <= 3750)
        # An SHB restarts TBeacon: no Beacon at the old deadline.
        old = router.next_deadline()
        now[0] = times[-1] + 1000
        router.gn_data_request(shb_request())
        restarted = router.next_deadline()
        self.assertTrue(now[0] + 3000 <= restarted <= now[0] + 3750)
        if old < restarted:
            now[0] = old
            router.tick()
            self.assertEqual(len(sent(router)), 5)          # only the SHB
        now[0] = restarted
        router.tick()
        self.assertEqual(CommonHeader.decode_from_bytes(sent(router)[-1][4:12]).ht, HeaderType.BEACON)


class TestRouterDuplicatesAndStartup(unittest.TestCase):
    """Mirrors the Rust router tests for LocT insertion, start-up address and duplicates."""

    def test_beacon_inserts_location_table_entry(self):
        """(clauses 10.3.10.3, 10.3.6.2)."""
        router, _ = make_router()
        callback = MagicMock()
        router.register_indication_callback(callback)
        self.assertIsNone(router.location_table.get_entry(addr(2)))
        router.gn_data_indicate(beacon_from(router, 2, north(100)))
        entry = router.location_table.get_entry(addr(2))
        assert entry is not None
        self.assertTrue(entry.is_neighbour)
        self.assertEqual((entry.position_vector.latitude, entry.position_vector.longitude),
                         (north(100), EGO_LON))
        callback.assert_not_called()
        self.assertEqual(sent(router), [])

    def test_initial_gn_address_with_auto_configuration(self):
        """(clauses 10.2.1.2, 10.3.6.2)."""
        router, _ = make_router(itsGnLocalGnAddr=addr(42))
        self.assertEqual(router.ego_position_vector.gn_addr, addr(42))
        router.gn_data_request_beacon()
        packet = sent(router)[0]
        self.assertEqual(CommonHeader.decode_from_bytes(packet[4:12]).ht, HeaderType.BEACON)
        self.assertEqual(LongPositionVector.decode(packet[12:36]).gn_addr, addr(42))

    def test_guc_duplicate_not_forwarded_again(self):
        """(clause 10.3.9.2, E.2)."""
        router, _ = make_router()
        add_neighbour(router, 3, north(500))                  # closer to the destination
        destination = ShortPositionVector(gn_addr=addr(9), latitude=north(1000), longitude=EGO_LON)
        packet = guc_packet(router, lpv(2, north(-100)), 1, destination)
        router.gn_data_indicate(packet)
        router.gn_data_indicate(packet)
        self.assertEqual(len(sent(router)), 1)

    def test_tsb_duplicate_neither_forwarded_nor_delivered(self):
        """(clause 10.3.9.3)."""
        router, _ = make_router()
        callback = MagicMock()
        router.register_indication_callback(callback)
        basic = BasicHeader.initialize_with_mib(router.mib).set_rhl(5)
        common = CommonHeader(nh=CommonNH.BTP_B, ht=HeaderType.TSB,
                              hst=TopoBroadcastHST.MULTI_HOP, mhl=10)  # type: ignore
        headers = basic.encode_to_bytes() + common.encode_to_bytes()
        packet = headers + TSBExtendedHeader(sn=1, so_pv=lpv(2, north(100))).encode() + b"payload"
        router.gn_data_indicate(packet)
        router.gn_data_indicate(packet)
        self.assertEqual(len(sent(router)), 1)
        callback.assert_called_once()

    def test_gac_duplicate_outside_area_not_forwarded_again(self):
        """(clause 10.3.12.3, E.2)."""
        router, _ = make_router()
        callback = MagicMock()
        router.register_indication_callback(callback)
        area = TestAreaPacketHandling.REMOTE
        basic = BasicHeader.initialize_with_mib(router.mib).set_rhl(5)
        common = CommonHeader(nh=CommonNH.BTP_B, ht=HeaderType.GEOANYCAST,
                              hst=GeoAnycastHST.GEOANYCAST_CIRCLE, mhl=10)  # type: ignore
        ext = GBCExtendedHeader(sn=1, so_pv=lpv(2, north(-100)), latitude=area.latitude,
                                longitude=area.longitude, a=area.a, b=area.b, angle=area.angle)
        packet = basic.encode_to_bytes() + common.encode_to_bytes() + ext.encode() + b"payload"
        router.gn_data_indicate(packet)
        router.gn_data_indicate(packet)
        self.assertEqual(len(sent(router)), 1)
        callback.assert_not_called()


class TestNonAreaCbfAreaPackets(unittest.TestCase):
    """
    and GAC/NONAREA/CBF (clause E.3): GBC and GAC
    packets outside their destination area with non-area CBF. Mirrors the
    Rust ``cbf_gbc_gac_*`` tests.
    """

    KINDS = ((HeaderType.GEOBROADCAST, GeoBroadcastHST.GEOBROADCAST_CIRCLE),
             (HeaderType.GEOANYCAST, GeoAnycastHST.GEOANYCAST_CIRCLE))

    @staticmethod
    def router():
        return make_router(itsGnNonAreaForwardingAlgorithm=NonAreaForwardingAlgorithm.CBF,
                           itsGnAreaForwardingAlgorithm=AreaForwardingAlgorithm.SIMPLE)

    @staticmethod
    def area_packet(router, ht, hst, so_lat, rhl=5):
        area = TestAreaPacketHandling.REMOTE
        basic = BasicHeader.initialize_with_mib(router.mib).set_rhl(rhl)
        common = CommonHeader(nh=CommonNH.BTP_B, ht=ht, hst=hst, mhl=10)  # type: ignore
        ext = GBCExtendedHeader(sn=1, so_pv=lpv(2, so_lat), latitude=area.latitude,
                                longitude=area.longitude, a=area.a, b=area.b, angle=area.angle)
        return basic.encode_to_bytes() + common.encode_to_bytes() + ext.encode() + b"payload"

    def test_source_outside_area_broadcasts(self):
        for ht, hst in self.KINDS:
            with self.subTest(ht=ht):
                router, _ = self.router()
                router.gn_data_request(GNDataRequest(
                    packet_transport_type=PacketTransportType(header_type=ht, header_subtype=hst),
                    area=TestAreaPacketHandling.REMOTE, data=b"area"))
                packets = sent(router)
                self.assertEqual(len(packets), 1)
                self.assertEqual(CommonHeader.decode_from_bytes(packets[0][4:12]).ht, ht)

    def test_forwarded_at_contention_timeout(self):
        for ht, hst in self.KINDS:
            with self.subTest(ht=ht):
                router, now = self.router()
                callback = MagicMock()
                router.register_indication_callback(callback)
                add_neighbour(router, 2, north(-300))
                router.gn_data_indicate(self.area_packet(router, ht, hst, north(-300)),
                                        sender_ll_address=addr(2).mid.mid)
                deadline = router.next_deadline()
                self.assertLess(deadline, router.mib.itsGnCbfMaxTime)
                now[0] = deadline - 1
                router.tick()
                self.assertEqual(sent(router), [])
                now[0] = deadline
                router.tick()
                packets = sent(router)
                self.assertEqual(len(packets), 1)
                self.assertEqual(CommonHeader.decode_from_bytes(packets[0][4:12]).ht, ht)
                self.assertEqual(BasicHeader.decode_from_bytes(packets[0][0:4]).rhl, 4)
                callback.assert_not_called()

    def test_duplicate_from_better_forwarder_cancels(self):
        for ht, hst in self.KINDS:
            with self.subTest(ht=ht):
                router, now = self.router()
                add_neighbour(router, 2, north(-300))
                packet = self.area_packet(router, ht, hst, north(-300))
                router.gn_data_indicate(packet, sender_ll_address=addr(2).mid.mid)
                add_neighbour(router, 3, north(400))           # closer to the area
                router.gn_data_indicate(packet, sender_ll_address=addr(3).mid.mid)
                now[0] = 1000
                router.tick()
                self.assertEqual(sent(router), [])

    def test_minimum_delay_at_dist_max(self):
        for ht, hst in self.KINDS:
            with self.subTest(ht=ht):
                router, _ = self.router()
                dist_max = router.mib.itsGnDefaultMaxCommunicationRange
                add_neighbour(router, 2, north(-dist_max))
                router.gn_data_indicate(self.area_packet(router, ht, hst, north(-dist_max)),
                                        sender_ll_address=addr(2).mid.mid)
                self.assertLessEqual(router.next_deadline(), router.mib.itsGnCbfMinTime + 1)

    def test_unknown_or_uncertain_sender_uses_to_cbf_max(self):
        for ht, hst in self.KINDS:
            for known_without_pai in (False, True):
                with self.subTest(ht=ht, known_without_pai=known_without_pai):
                    router, _ = self.router()
                    if known_without_pai:
                        router.location_table.new_shb_packet(
                            dataclass_replace(lpv(4, north(-300)), pai=False), b"")
                    router.gn_data_indicate(self.area_packet(router, ht, hst, north(-300)),
                                            sender_ll_address=addr(4).mid.mid)
                    self.assertEqual(router.next_deadline(), router.mib.itsGnCbfMaxTime)


class TestPacketFieldValidity(unittest.TestCase):
    """
    Fields of the packets sent by the IUT (TS 102 871-2 clause 6.2.1, FDV) and
    the initial sequence number. Mirrors the Rust
    ``sent_*_fields`` tests.
    """

    def test_gbc_fields(self):
        router, _ = make_router()
        router.gn_data_indicate(beacon_from(router, 2, north(100)))
        router.gn_data_request(TestAreaCbf().gbc_request())
        packet = sent(router)[0]
        basic = BasicHeader.decode_from_bytes(packet[0:4])
        self.assertEqual(basic.version, router.mib.itsGnProtocolVersion)
        self.assertEqual(basic.rhl, router.mib.itsGnDefaultHopLimit)
        common = CommonHeader.decode_from_bytes(packet[4:12])
        self.assertEqual(common.flags >> 7, router.mib.itsGnIsMobile.value)
        self.assertEqual(common.mhl, router.mib.itsGnDefaultHopLimit)
        self.assertEqual(common.ht, HeaderType.GEOBROADCAST)
        ext = GBCExtendedHeader.decode(packet[12:56])
        self.assertEqual(ext.so_pv, router.ego_position_vector)
        self.assertEqual(ext.sn, 0)

    def test_beacon_fields(self):
        router, _ = make_router(itsGnLocalGnAddr=GNAddress(st=ST.PASSENGER_CAR, mid=MID(b"\x02\x00\x00\x00\x00\x2a")))
        router.ego_position_vector = dataclass_replace(router.ego_position_vector,
                                                       gn_addr=router.mib.itsGnLocalGnAddr)
        router.gn_data_request_beacon()
        packet = sent(router)[0]
        common = CommonHeader.decode_from_bytes(packet[4:12])
        self.assertEqual((common.nh, common.ht, common.hst.value, common.pl),
                         (CommonNH.ANY, HeaderType.BEACON, 0, 0))
        self.assertEqual(common.flags >> 7, router.mib.itsGnIsMobile.value)
        so = LongPositionVector.decode(packet[12:36])
        self.assertEqual(so, router.ego_position_vector)
        self.assertEqual(so.gn_addr.st, ST.PASSENGER_CAR)
        self.assertEqual(so.gn_addr, router.mib.itsGnLocalGnAddr)

    def test_shb_fields(self):
        router, _ = make_router()
        router.gn_data_indicate(beacon_from(router, 2, north(100)))
        router.gn_data_request(shb_request())
        packet = sent(router)[0]
        common = CommonHeader.decode_from_bytes(packet[4:12])
        self.assertEqual((common.ht, common.hst, common.mhl), (HeaderType.TSB, TopoBroadcastHST.SINGLE_HOP, 1))
        self.assertEqual(common.pl, len(b"shb"))
        self.assertEqual(LongPositionVector.decode(packet[12:36]), router.ego_position_vector)
        self.assertEqual(packet[40:], b"shb")

    def test_guc_fields(self):
        """DE PV from the LocTE of the destination."""
        router, _ = make_router()
        router.gn_data_indicate(beacon_from(router, 2, north(100)))
        router.gn_data_request(guc_request(addr(2)))
        packet = sent(router)[0]
        common = CommonHeader.decode_from_bytes(packet[4:12])
        self.assertEqual((common.ht, common.hst.value), (HeaderType.GEOUNICAST, 0))
        ext = GUCExtendedHeader.decode(packet[12:60])
        self.assertEqual((ext.de_pv.gn_addr, ext.de_pv.latitude, ext.de_pv.longitude),
                         (addr(2), north(100), EGO_LON))
        self.assertEqual(ext.so_pv, router.ego_position_vector)

    def test_lpv_from_sensor_data(self):
        """latest position and the sensor
        acquisition time (ms) in the SO PV."""
        router, _ = make_router()
        router.refresh_ego_position_vector({"lat": 41.552, "lon": 2.134, "speed": 3.5, "track": 90.0,
                                            "time": "2026-11-16T10:34:48.283Z"})
        router.gn_data_request_beacon()
        so = LongPositionVector.decode(sent(router)[0][12:36])
        self.assertEqual((so.latitude, so.longitude), (415520000, 21340000))
        acquired = datetime(2026, 11, 16, 10, 34, 48, 283000, tzinfo=timezone.utc).timestamp()
        self.assertEqual(so.tst.msec, TST.set_in_normal_timestamp_seconds(acquired).msec)
        self.assertNotEqual(so.tst.msec, TST.set_in_normal_timestamp_seconds(int(acquired)).msec)


class TestForwardingBufferThroughRouter(unittest.TestCase):
    """UC forwarding packet buffer of a forwarder (clause 8.5.2)."""

    @staticmethod
    def buffer_guc(router, sn, rhl=5, lifetime=None, data=b"x"):
        dest = ShortPositionVector(gn_addr=addr(9), latitude=north(1000), longitude=EGO_LON)
        basic = BasicHeader.initialize_with_mib_request_and_rhl(router.mib, lifetime, rhl)
        common = CommonHeader(nh=CommonNH.BTP_A, ht=HeaderType.GEOUNICAST, tc=TrafficClass(scf=True),
                              mhl=10, pl=len(data))
        ext = GUCExtendedHeader(sn=sn, so_pv=lpv(2, north(-100)), de_pv=dest)
        headers = basic.encode_to_bytes() + common.encode_to_bytes() + ext.encode()
        router.gn_data_indicate(headers + data)

    def test_expired_packet_not_forwarded(self):
        """no next hop, SCF: buffered; a Beacon from a
        next hop after expiry of LT1 does not release it."""
        router, now = make_router()
        add_neighbour(router, 3, north(-200))                # behind ego: local optimum
        self.buffer_guc(router, 1, lifetime=1.0)
        router.link_layer.send.assert_not_called()
        self.assertEqual(len(router._uc_buffers[addr(9)]), 1)   # pylint: disable=protected-access
        now[0] = 1500
        router.gn_data_indicate(beacon_from(router, 4, north(500)))
        self.assertEqual(sent(router), [])

    def test_capacity_head_drop(self):
        """over itsGnUcForwardingPacketBufferSize the oldest
        packets are dropped; the newest are sent when a next hop appears."""
        router, _ = make_router(itsGnUcForwardingPacketBufferSize=1)       # 1 KiB
        add_neighbour(router, 3, north(-200))                # behind ego: local optimum
        for sn in range(1, 5):
            self.buffer_guc(router, sn, data=bytes(400))
        router.gn_data_indicate(beacon_from(router, 4, north(500)))
        numbers = [sequence_number(p) for p in sent(router)]
        self.assertEqual(numbers, [3, 4])


class TestDuplicatesInsideArea(unittest.TestCase):
    """Duplicate GBC / GAC received inside the destination area."""

    def area_packet(self, router, ht, hst, rhl):
        area = TestAreaCbf.AREA
        basic = BasicHeader.initialize_with_mib(router.mib).set_rhl(rhl)
        common = CommonHeader(nh=CommonNH.BTP_B, ht=ht, hst=hst, mhl=10, tc=TrafficClass(scf=True))  # type: ignore
        ext = GBCExtendedHeader(sn=1, so_pv=lpv(2, north(300)), latitude=area.latitude,
                                longitude=area.longitude, a=area.a, b=area.b, angle=area.angle)
        return basic.encode_to_bytes() + common.encode_to_bytes() + ext.encode() + b"payload"

    def test_duplicate_not_passed_up(self):
        for ht, hst in TestNonAreaCbfAreaPackets.KINDS:
            with self.subTest(ht=ht):
                router, _ = make_router()
                callback = MagicMock()
                router.register_indication_callback(callback)
                add_neighbour(router, 2, north(300))
                add_neighbour(router, 4, north(200))
                router.gn_data_indicate(self.area_packet(router, ht, hst, 5),
                                        sender_ll_address=addr(2).mid.mid)
                router.gn_data_indicate(self.area_packet(router, ht, hst, 4),
                                        sender_ll_address=addr(4).mid.mid)
                callback.assert_called_once()

    def test_simple_forwarding_duplicate_not_rebroadcast(self):
        router, _ = make_router(itsGnAreaForwardingAlgorithm=AreaForwardingAlgorithm.SIMPLE)
        add_neighbour(router, 2, north(300))
        add_neighbour(router, 4, north(200))
        packet = self.area_packet(router, HeaderType.GEOBROADCAST, GeoBroadcastHST.GEOBROADCAST_CIRCLE, 5)
        router.gn_data_indicate(packet, sender_ll_address=addr(2).mid.mid)
        self.assertEqual(len(sent(router)), 1)
        duplicate = self.area_packet(router, HeaderType.GEOBROADCAST, GeoBroadcastHST.GEOBROADCAST_CIRCLE, 4)
        router.gn_data_indicate(duplicate, sender_ll_address=addr(4).mid.mid)
        self.assertEqual(len(sent(router)), 1)


class TestMediaDependentAddress(unittest.TestCase):
    """
    MID of the GN address per access layer: (ITS-G5,
    ETSI TS 103 836-4-2 clause 6.1) and (LTE-V2X, TS 103 836-4-3
    clause 5.2). Mirrors the Rust ``media_dependent_*`` tests.
    """

    MAC = b"\x02\x1a\x2b\x3c\x4d\x5e"

    @staticmethod
    def raw_link_layer(mac):
        with patch("socket.socket"), patch("threading.Thread"):
            return RawLinkLayer(iface="lo", mac_address=mac, receive_callback=MagicMock())

    def beacon_mid(self, router):
        router.ego_position_vector = dataclass_replace(router.ego_position_vector,
                                                       gn_addr=router.mib.itsGnLocalGnAddr)
        router.gn_data_request_beacon()
        return LongPositionVector.decode(sent(router)[0][12:36]).gn_addr.mid

    def test_its_g5_mid_is_the_mac_address(self):
        router, _ = make_router(itsGnIfType=GnIfType.ITS_G5,
                                itsGnLocalGnAddr=GNAddress(mid=MID.from_its_g5_mac(self.MAC)))
        link_layer = self.raw_link_layer(self.MAC)
        self.assertEqual(link_layer.media_dependent_mid(), MID(self.MAC))
        self.assertTrue(router.media_dependent_address_ok(link_layer.media_dependent_mid()))
        self.assertEqual(self.beacon_mid(router).mid, self.MAC)
        other = self.raw_link_layer(b"\x02\x00\x00\x00\x00\x01")
        self.assertFalse(router.media_dependent_address_ok(other.media_dependent_mid()))
        router.link_layer = other                    # default: the attached link layer
        self.assertFalse(router.media_dependent_address_ok())

    def test_lte_v2x_mid_is_the_layer_2_id(self):
        """Layer 2 ID in octets 2-4, zero in octets 5-7."""
        mid = MID.from_lte_v2x_l2_id(0xA1B2C3)
        self.assertEqual(mid.mid, b"\xa1\xb2\xc3\x00\x00\x00")
        router, _ = make_router(itsGnIfType=GnIfType.LTE_V2X, itsGnLocalGnAddr=GNAddress(mid=mid))
        self.assertTrue(router.media_dependent_address_ok(mid))
        self.assertTrue(router.media_dependent_address_ok())          # L2 ID unknown: zeros checked
        self.assertEqual(self.beacon_mid(router).mid, b"\xa1\xb2\xc3\x00\x00\x00")
        self.assertFalse(router.media_dependent_address_ok(MID.from_lte_v2x_l2_id(0x000001)))
        bad, _ = make_router(itsGnIfType=GnIfType.LTE_V2X,
                             itsGnLocalGnAddr=GNAddress(mid=MID(b"\xa1\xb2\xc3\x00\x00\x01")))
        self.assertFalse(bad.media_dependent_address_ok())
        with self.assertRaises(ValueError):
            MID.from_lte_v2x_l2_id(2**24)

    def test_unspecified_interface_is_not_checked(self):
        router, _ = make_router()
        self.assertTrue(router.media_dependent_address_ok(MID(b"\x02\x00\x00\x00\x00\x01")))
