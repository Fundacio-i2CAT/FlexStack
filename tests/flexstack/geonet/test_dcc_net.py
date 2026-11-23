"""
DCC_NET for GN over ITS-G5 (ETSI TS 103 836-4-2 V2.1.1, clauses 5 to 7).
Mirrors ``rustflexstack::geonet::dcc_net`` tests and the DCC_NET router tests.
"""

import unittest
from unittest.mock import Mock

from flexstack.geonet.basic_header import BasicHeader
from flexstack.geonet.common_header import CommonHeader
from flexstack.geonet.dcc_net import DccNet, decode_dcc_mco, encode_dcc_mco
from flexstack.geonet.gn_address import MID, GNAddress
from flexstack.geonet.mib import MIB, GnIfType
from flexstack.geonet.position_vector import TST, LongPositionVector
from flexstack.geonet.router import Router
from flexstack.geonet.service_access_point import (
    CommonNH, GNDataRequest, HeaderType, PacketTransportType, TopoBroadcastHST)
from flexstack.management.cbr import SharedCbr, parse_tx_power_dbm
from flexstack.management.dcc_entity import DccEntity, DccMode
from flexstack.utils.time_service import TimeService

EGO_LAT, EGO_LON = 421255850, 27601710


def addr(n):
    return GNAddress(mid=MID(bytes([0x02, 0, 0, 0, 0, n])))


def station(n, dcc_net=None):
    now = [0]
    mib = MIB(itsGnBeaconServiceRetransmitTimer=0, itsGnIfType=GnIfType.ITS_G5,
              itsGnLocalGnAddr=addr(n))
    router = Router(mib, clock=lambda: now[0], dcc_net=dcc_net)
    router.ego_position_vector = LongPositionVector(
        gn_addr=addr(n), tst=TST.set_in_normal_timestamp_seconds(TimeService.time()),
        latitude=EGO_LAT, longitude=EGO_LON, pai=True)
    router.link_layer = Mock()
    return router, now


def shb_request():
    return GNDataRequest(packet_transport_type=PacketTransportType(
        header_type=HeaderType.TSB, header_subtype=TopoBroadcastHST.SINGLE_HOP), data=b"shb")


def shb_from(router, n, mco, tst=None):
    basic = BasicHeader.initialize_with_mib(router.mib).set_rhl(1)
    common = CommonHeader(nh=CommonNH.BTP_B, ht=HeaderType.TSB, hst=TopoBroadcastHST.SINGLE_HOP,
                          mhl=1, pl=7)  # type: ignore
    so = LongPositionVector(gn_addr=addr(n), latitude=EGO_LAT + 1000, longitude=EGO_LON, pai=True,
                            tst=tst or TST.set_in_normal_timestamp_seconds(TimeService.time()))
    return basic.encode_to_bytes() + common.encode_to_bytes() + so.encode() + mco + b"payload"


def sent_mco(router):
    router.gn_data_request(shb_request())
    return router.link_layer.send.call_args_list[-1][0][0][36:40]


class TestDccMcoField(unittest.TestCase):
    """Clause 6.3.3, table 3."""

    def test_encoding(self):
        self.assertEqual(encode_dcc_mco(0.5, 0.8, 20), bytes([127, 204, 20, 0]))
        self.assertEqual(encode_dcc_mco(1.0, 0.0, 40), bytes([255, 0, 31, 0]))     # > 31 dBm -> 31
        self.assertEqual(encode_dcc_mco(0.0, 0.0, -3), bytes([0, 0, 0, 0]))

    def test_decoding(self):
        self.assertEqual(decode_dcc_mco(bytes([204, 51, 23, 0])), (204 / 255, 51 / 255, 23))
        self.assertIsNone(decode_dcc_mco(b"\x00\x00\x00\x00"))          # sender without DCC_NET


class TestGlobalCbr(unittest.TestCase):
    """Clause 5.3: CBR_L_1_Hop, CBR_L_2_Hop and CBR_G every T_Trig."""

    def loctex(self, dcc, n, r0, r1, now):
        dcc.update_loctex(addr(n), 0, encode_dcc_mco(r0, r1, 20), now)

    def test_first_trigger_has_random_offset(self):
        dcc = DccNet(rng=lambda: 0.5)
        self.assertEqual(dcc.next_trigger(1000), 1050)
        dcc.trigger(1050)
        self.assertEqual(dcc.next_trigger(1050), 1150)

    def test_maximum_above_target_second_largest_below(self):
        dcc = DccNet(rng=lambda: 0.0)
        for n, r0 in ((1, 0.9), (2, 0.8), (3, 0.7)):        # average 0.8 > 0.62: maximum
            self.loctex(dcc, n, r0, 0.1 * n, 0)
        dcc.trigger(0)
        self.assertAlmostEqual(dcc.cbr_l_1_hop, 0.9, places=2)
        self.assertAlmostEqual(dcc.cbr_l_2_hop, 0.2, places=2)         # average 0.2: second largest
        dcc = DccNet(rng=lambda: 0.0)
        for n, r0 in ((1, 0.5), (2, 0.3), (3, 0.1)):        # average 0.3: second largest
            self.loctex(dcc, n, r0, 0.0, 0)
        dcc.trigger(0)
        self.assertAlmostEqual(dcc.cbr_l_1_hop, 0.3, places=2)

    def test_cbr_g_uses_previous_local_cbr(self):
        """Step 5: CBR_G(n) = max(CBR_L_0_Hop(n-1), CBR_L_1_Hop(n), CBR_L_2_Hop(n))."""
        local = SharedCbr()
        dcc = DccNet(local_cbr=local, rng=lambda: 0.0)
        local.report(0.7)
        self.assertEqual(dcc.trigger(0), 0.0)                # CBR_L_0_Hop(0) = 0
        self.assertEqual(dcc.cbr_l_0_hop, 0.7)
        self.assertEqual(dcc.trigger(100), 0.7)
        self.assertEqual(dcc.global_cbr.measure_cbr(), 0.7)

    def test_outdated_values_are_ignored(self):
        """Entries older than T_Cbr (itsGNCBRLifetime) do not count; LocTEX-G5 expires."""
        dcc = DccNet(rng=lambda: 0.0)
        self.loctex(dcc, 1, 0.9, 0.9, 0)
        dcc.trigger(500)
        self.assertGreater(dcc.cbr_l_1_hop, 0.8)
        dcc.trigger(1100)
        self.assertEqual((dcc.cbr_l_1_hop, dcc.cbr_l_2_hop), (0.0, 0.0))
        self.assertEqual(dcc.loctex, {})

    def test_global_cbr_drives_the_dcc_entity(self):
        """DCC_CROSS: CBR_G is the input of the DCC algorithm (clause 5.3)."""
        dcc = DccNet(rng=lambda: 0.0)
        for n in (1, 2):
            self.loctex(dcc, n, 0.9, 0.0, 0)
        dcc.trigger(0)
        entity = DccEntity(DccMode.reactive(), dcc.global_cbr)
        self.assertGreater(entity.evaluate().t_gen_cam_dcc_ms, 100)


class TestDccNetRouter(unittest.TestCase):
    """SHB packet handling with DCC_NET (clause 7.2)."""

    def test_shb_carries_dcc_mco(self):
        """CBR_L_0_Hop, CBR_L_1_Hop and Transmit Power."""
        local = SharedCbr()
        router, now = station(1, DccNet(local_cbr=local, tx_power_dbm=20, rng=lambda: 0.0))
        local.report(0.5)
        router.gn_data_indicate(shb_from(router, 2, encode_dcc_mco(0.8, 0.1, 23)))
        router.tick(0)                                       # CBR_L_0_Hop = 0.5, CBR_L_1_Hop = 0.8
        now[0] = 50
        self.assertEqual(sent_mco(router), bytes([127, 204, 20, 0]))

    def test_loctex_updated_from_received_shb(self):
        """the LocTEX-G5 holds the received DCC-MCO and the
        next SHB disseminates it as CBR_L_1_Hop."""
        router, now = station(1, DccNet(tx_power_dbm=20, rng=lambda: 0.0))
        tst = TST.set_in_normal_timestamp_seconds(TimeService.time())
        mco = encode_dcc_mco(0.8, 0.3, 23)
        router.gn_data_indicate(shb_from(router, 2, mco, tst))
        entry = router.dcc_net.loctex[addr(2)]
        self.assertEqual((entry.tx_power_dbm, entry.tst_so_pv, entry.tst_g5_ms), (23, tst.msec, 0))
        self.assertEqual((round(entry.cbr_r_0_hop * 255), round(entry.cbr_r_1_hop * 255)), (204, 76))
        self.assertIsNotNone(router.location_table.get_entry(addr(2)))
        router.tick(0)
        self.assertEqual(sent_mco(router)[1], mco[0])
        router.link_layer.send.reset_mock()
        router.gn_data_indicate(shb_from(router, 3, b"\x00\x00\x00\x00"))   # no DCC-MCO
        self.assertNotIn(addr(3), router.dcc_net.loctex)

    def test_without_dcc_net_the_field_is_zero(self):
        """DCC-MCO received, but no DCC_NET: zeros sent."""
        router, _ = station(1)
        router.gn_data_indicate(shb_from(router, 2, encode_dcc_mco(0.8, 0.3, 23)))
        self.assertIsNotNone(router.location_table.get_entry(addr(2)))
        self.assertEqual(sent_mco(router), b"\x00\x00\x00\x00")

    def test_next_deadline_includes_the_cbr_g_trigger(self):
        router, _ = station(1, DccNet(rng=lambda: 0.3))
        self.assertEqual(router.next_deadline(), 30)


class TestNl80211TxPower(unittest.TestCase):

    def test_parse_iw_info(self):
        text = "Interface wlan0\n\tifindex 4\n\ttype IBSS\n\tchannel 180 (5900 MHz), width: 10 MHz\n\ttxpower 23.00 dBm\n"
        self.assertEqual(parse_tx_power_dbm(text), 23.0)
        self.assertIsNone(parse_tx_power_dbm("Interface wlan0\n"))


if __name__ == "__main__":
    unittest.main()
