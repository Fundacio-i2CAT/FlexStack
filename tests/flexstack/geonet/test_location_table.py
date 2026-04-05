import unittest
from unittest.mock import patch

from flexstack.geonet.gn_address import MID, M, ST, GNAddress
from flexstack.geonet.exceptions import (
    DuplicatedPacketException,
)
from flexstack.geonet.location_table import (
    LocationTableEntry,
    LocationTable,
)
from flexstack.geonet.tsb_extended_header import TSBExtendedHeader
from flexstack.geonet.guc_extended_header import GUCExtendedHeader
from flexstack.geonet.gbc_extended_header import GBCExtendedHeader
from flexstack.geonet.ls_extended_header import LSRequestExtendedHeader, LSReplyExtendedHeader
from flexstack.geonet.position_vector import LongPositionVector, ShortPositionVector
from flexstack.geonet.mib import MIB
from flexstack.geonet.service_access_point import Area


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
        # §C.2 ELSE: older PV must be silently ignored – no exception, PV stays at position_vector2
        entry.update_position_vector(position_vector)
        self.assertEqual(entry.position_vector, position_vector2)

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
        """Annex A.2: SN already in DPL must raise DuplicatedPacketException."""
        mib = MIB()
        entry = LocationTableEntry(mib)
        entry.check_duplicate_sn(42)
        self.assertRaises(
            DuplicatedPacketException, entry.check_duplicate_sn, 42
        )

    def test_dpd_ring_buffer_evicts_oldest(self):
        """A.2: when DPL is full the oldest SN must be evicted, allowing re-use."""
        mib = MIB(itsGnDPLLength=3)
        entry = LocationTableEntry(mib)
        # Fill the ring buffer: SNs 0, 1, 2
        entry.check_duplicate_sn(0)
        entry.check_duplicate_sn(1)
        entry.check_duplicate_sn(2)
        # Adding SN 3 evicts SN 0
        entry.check_duplicate_sn(3)
        # SN 0 should no longer be in the DPL → not a duplicate
        entry.check_duplicate_sn(0)  # must NOT raise

    def test_dpd_not_applied_to_shb(self):
        """A.1: SHB packets must NOT trigger DPD (no SN field)."""
        mib = MIB()
        entry = LocationTableEntry(mib)
        position_vector = LongPositionVector(
            gn_addr=GNAddress()).set_tst_in_normal_timestamp_seconds(1675071608.0)
        payload = b"shb_payload"
        # Call twice with the same payload – must NOT raise DuplicatedPacketException
        entry.update_with_shb_packet(position_vector, payload)
        entry.update_with_shb_packet(position_vector, payload)  # second call must not raise


class TestLocationTableTSB(unittest.TestCase):
    """Tests for TSB-specific location table behaviour (\u00a710.3.9.3 steps 5-6)."""

    _TIMESTAMP = 1675071608.0

    def _make_tsb_header(self, gn_addr, timestamp_offset: float = 0.0, sn: int = 1):
        lpv = LongPositionVector(gn_addr=gn_addr).set_tst_in_normal_timestamp_seconds(
            self._TIMESTAMP + timestamp_offset)
        return TSBExtendedHeader(sn=sn, so_pv=lpv)

    def _make_gn_addr(self):
        return GNAddress(
            m=M.GN_MULTICAST,
            st=ST.CYCLIST,
            mid=MID(b"\xaa\xbb\xcc\xdd\x22\x33"),
        )

    @patch("flexstack.geonet.location_table.TimeService.time")
    def test_new_entry_is_neighbour_set_to_false(self, mock_time):
        """Step 5b: IS_NEIGHBOUR must be FALSE for a newly created TSB LocTE."""
        mock_time.return_value = self._TIMESTAMP
        mib = MIB()
        table = LocationTable(mib)
        addr = self._make_gn_addr()
        header = self._make_tsb_header(addr)

        table.new_tsb_packet(header, b"payload")

        entry = table.get_entry(addr)
        self.assertIsNotNone(entry)
        self.assertFalse(entry.is_neighbour)

    @patch("flexstack.geonet.location_table.TimeService.time")
    def test_existing_entry_is_neighbour_unchanged(self, mock_time):
        """NOTE 1: IS_NEIGHBOUR flag remains unchanged for an existing TSB LocTE."""
        mock_time.return_value = self._TIMESTAMP
        mib = MIB()
        table = LocationTable(mib)
        addr = self._make_gn_addr()

        # First packet: creates entry with IS_NEIGHBOUR = False
        table.new_tsb_packet(self._make_tsb_header(addr, 0.0, sn=1), b"payload1")
        # Manually set IS_NEIGHBOUR to True (e.g. SHB was received before)
        table.get_entry(addr).is_neighbour = True

        # Second TSB packet (different SN so DPD does not trigger): IS_NEIGHBOUR must remain True.
        # Use same timestamp so the PV satisfies tst >= prev_tst and refresh_table keeps the entry.
        table.new_tsb_packet(self._make_tsb_header(addr, 0.0, sn=2), b"payload2")

        self.assertTrue(table.get_entry(addr).is_neighbour)

    @patch("flexstack.geonet.location_table.TimeService.time")
    def test_duplicate_tsb_packet_raises(self, mock_time):
        """DPD (annex A.2): same SN received twice must raise DuplicatedPacketException."""
        mock_time.return_value = self._TIMESTAMP
        mib = MIB()
        table = LocationTable(mib)
        addr = self._make_gn_addr()
        header = self._make_tsb_header(addr)
        payload = b"same_payload"

        table.new_tsb_packet(header, payload)
        with self.assertRaises(DuplicatedPacketException):
            table.new_tsb_packet(header, payload)


class TestLocationTableGUC(unittest.TestCase):
    """Tests for GUC-specific location table behaviour (§10.3.8.3/.8.4 steps 5-6)."""

    _TIMESTAMP = 1675071608.0

    def _make_gn_addr(self):
        return GNAddress(m=M.GN_MULTICAST, st=ST.CYCLIST, mid=MID(b"\xaa\xbb\xcc\xdd\x22\x33"))

    def _make_guc_header(self, so_gn_addr, de_gn_addr, timestamp_offset: float = 0.0, sn: int = 1):
        so_lpv = LongPositionVector(gn_addr=so_gn_addr).set_tst_in_normal_timestamp_seconds(
            self._TIMESTAMP + timestamp_offset)
        de_spv = ShortPositionVector(gn_addr=de_gn_addr)
        return GUCExtendedHeader(sn=sn, so_pv=so_lpv, de_pv=de_spv)

    @patch("flexstack.geonet.location_table.TimeService.time")
    def test_new_entry_is_neighbour_set_to_false(self, mock_time):
        """IS_NEIGHBOUR must be FALSE for a newly created GUC LocTE."""
        mock_time.return_value = self._TIMESTAMP
        mib = MIB()
        table = LocationTable(mib)
        so_addr = self._make_gn_addr()
        de_addr = GNAddress()
        header = self._make_guc_header(so_addr, de_addr)

        table.new_guc_packet(header, b"payload")

        entry = table.get_entry(so_addr)
        self.assertIsNotNone(entry)
        self.assertFalse(entry.is_neighbour)

    @patch("flexstack.geonet.location_table.TimeService.time")
    def test_existing_entry_is_neighbour_unchanged(self, mock_time):
        """NOTE 2: IS_NEIGHBOUR flag remains unchanged for an existing GUC LocTE."""
        mock_time.return_value = self._TIMESTAMP
        mib = MIB()
        table = LocationTable(mib)
        so_addr = self._make_gn_addr()
        de_addr = GNAddress()

        # First packet creates the entry
        table.new_guc_packet(self._make_guc_header(so_addr, de_addr, 0.0, sn=1), b"payload1")
        # Manually set IS_NEIGHBOUR to True
        table.get_entry(so_addr).is_neighbour = True

        # Second packet (different SN so DPD does not trigger) must not reset IS_NEIGHBOUR
        table.new_guc_packet(self._make_guc_header(so_addr, de_addr, 0.0, sn=2), b"payload2")

        self.assertTrue(table.get_entry(so_addr).is_neighbour)

    @patch("flexstack.geonet.location_table.TimeService.time")
    def test_duplicate_guc_packet_raises(self, mock_time):
        """DPD (annex A.2): same SN received twice must raise DuplicatedPacketException."""
        mock_time.return_value = self._TIMESTAMP
        mib = MIB()
        table = LocationTable(mib)
        so_addr = self._make_gn_addr()
        de_addr = GNAddress()
        header = self._make_guc_header(so_addr, de_addr)
        payload = b"dup_payload"

        table.new_guc_packet(header, payload)
        with self.assertRaises(DuplicatedPacketException):
            table.new_guc_packet(header, payload)


class TestLocationTableGAC(unittest.TestCase):
    """Tests for GAC-specific location table behaviour (§10.3.12.3 steps 5-6)."""

    _TIMESTAMP = 1675071608.0

    def _make_gn_addr(self):
        return GNAddress(m=M.GN_MULTICAST, st=ST.CYCLIST, mid=MID(b"\xaa\xbb\xcc\xdd\x22\x33"))

    def _make_gac_header(self, gn_addr, timestamp_offset: float = 0.0, sn: int = 1):
        so_lpv = LongPositionVector(gn_addr=gn_addr).set_tst_in_normal_timestamp_seconds(
            self._TIMESTAMP + timestamp_offset)
        return GBCExtendedHeader(
            sn=sn, so_pv=so_lpv,
            latitude=413872756, longitude=21122668, a=100, b=100, angle=0
        )

    @patch("flexstack.geonet.location_table.TimeService.time")
    def test_new_entry_is_neighbour_set_to_false(self, mock_time):
        """Step 5b: IS_NEIGHBOUR must be FALSE for a newly created GAC LocTE."""
        mock_time.return_value = self._TIMESTAMP
        mib = MIB()
        table = LocationTable(mib)
        addr = self._make_gn_addr()
        header = self._make_gac_header(addr)

        table.new_gac_packet(header, b"payload")

        entry = table.get_entry(addr)
        self.assertIsNotNone(entry)
        self.assertFalse(entry.is_neighbour)

    @patch("flexstack.geonet.location_table.TimeService.time")
    def test_existing_entry_is_neighbour_unchanged(self, mock_time):
        """NOTE 1: IS_NEIGHBOUR flag must remain unchanged for an existing GAC LocTE."""
        mock_time.return_value = self._TIMESTAMP
        mib = MIB()
        table = LocationTable(mib)
        addr = self._make_gn_addr()

        # First packet creates entry (IS_NEIGHBOUR = False)
        table.new_gac_packet(self._make_gac_header(addr, 0.0, sn=1), b"payload1")
        # Manually mark as neighbour (e.g. a SHB was received from this node)
        table.get_entry(addr).is_neighbour = True

        # Second GAC packet (different SN so DPD does not trigger): IS_NEIGHBOUR must NOT be reset to False
        table.new_gac_packet(self._make_gac_header(addr, 0.0, sn=2), b"payload2")

        self.assertTrue(table.get_entry(addr).is_neighbour)

    @patch("flexstack.geonet.location_table.TimeService.time")
    def test_duplicate_gac_packet_raises(self, mock_time):
        """DPD (annex A.2): same SN received twice must raise DuplicatedPacketException."""
        mock_time.return_value = self._TIMESTAMP
        mib = MIB()
        table = LocationTable(mib)
        addr = self._make_gn_addr()
        header = self._make_gac_header(addr)
        payload = b"dup_gac_payload"

        table.new_gac_packet(header, payload)
        with self.assertRaises(DuplicatedPacketException):
            table.new_gac_packet(header, payload)


class TestLocationTableLS(unittest.TestCase):
    """Tests for Location Service location table methods (§10.3.7)."""

    _TIMESTAMP = 1675071608.0

    def _make_gn_addr(self):
        return GNAddress(m=M.GN_MULTICAST, st=ST.CYCLIST, mid=MID(b"\xaa\xbb\xcc\xdd\x22\x33"))

    def _make_req_addr(self):
        return GNAddress(m=M.GN_MULTICAST, st=ST.PEDESTRIAN, mid=MID(b"\x11\x22\x33\x44\x55\x66"))

    def _make_ls_request_header(self, so_addr, timestamp_offset: float = 0.0):
        so_lpv = LongPositionVector(gn_addr=so_addr).set_tst_in_normal_timestamp_seconds(
            self._TIMESTAMP + timestamp_offset)
        return LSRequestExtendedHeader(sn=1, so_pv=so_lpv, request_gn_addr=self._make_req_addr())

    def _make_ls_reply_header(self, so_addr, de_addr, timestamp_offset: float = 0.0):
        so_lpv = LongPositionVector(gn_addr=so_addr).set_tst_in_normal_timestamp_seconds(
            self._TIMESTAMP + timestamp_offset)
        de_pv = ShortPositionVector(gn_addr=de_addr)
        return LSReplyExtendedHeader(sn=2, so_pv=so_lpv, de_pv=de_pv)

    @patch("flexstack.geonet.location_table.TimeService.time")
    def test_ensure_entry_creates_new(self, mock_time):
        """ensure_entry must create a new LocTE if none exists for the address."""
        mock_time.return_value = self._TIMESTAMP
        mib = MIB()
        table = LocationTable(mib)
        addr = self._make_gn_addr()

        self.assertIsNone(table.get_entry(addr))
        entry = table.ensure_entry(addr)
        self.assertIsNotNone(entry)
        self.assertIs(table.get_entry(addr), entry)

    @patch("flexstack.geonet.location_table.TimeService.time")
    def test_ensure_entry_returns_existing(self, mock_time):
        """ensure_entry must return the existing LocTE if one already exists."""
        mock_time.return_value = self._TIMESTAMP
        mib = MIB()
        table = LocationTable(mib)
        addr = self._make_gn_addr()
        first = table.ensure_entry(addr)
        second = table.ensure_entry(addr)
        self.assertIs(first, second)

    @patch("flexstack.geonet.location_table.TimeService.time")
    def test_ls_request_new_entry_is_neighbour_false(self, mock_time):
        """Step 5b: IS_NEIGHBOUR must be FALSE for a newly created LS Request LocTE."""
        mock_time.return_value = self._TIMESTAMP
        mib = MIB()
        table = LocationTable(mib)
        addr = self._make_gn_addr()
        header = self._make_ls_request_header(addr)

        table.new_ls_request_packet(header, b"payload")

        entry = table.get_entry(addr)
        self.assertIsNotNone(entry)
        self.assertFalse(entry.is_neighbour)

    @patch("flexstack.geonet.location_table.TimeService.time")
    def test_ls_request_existing_entry_is_neighbour_unchanged(self, mock_time):
        """NOTE: IS_NEIGHBOUR flag must remain unchanged for an existing LS Request LocTE."""
        mock_time.return_value = self._TIMESTAMP
        mib = MIB()
        table = LocationTable(mib)
        addr = self._make_gn_addr()
        # First packet creates entry (IS_NEIGHBOUR = False)
        table.new_ls_request_packet(self._make_ls_request_header(addr, 0.0), b"payload1")
        table.get_entry(addr).is_neighbour = True  # manually mark as neighbour
        # Second packet (different SN so DPD does not trigger) must not reset IS_NEIGHBOUR
        header2 = LSRequestExtendedHeader(
            sn=2,
            so_pv=LongPositionVector(gn_addr=addr).set_tst_in_normal_timestamp_seconds(self._TIMESTAMP),
            request_gn_addr=self._make_req_addr(),
        )
        table.new_ls_request_packet(header2, b"payload2")
        self.assertTrue(table.get_entry(addr).is_neighbour)

    @patch("flexstack.geonet.location_table.TimeService.time")
    def test_ls_reply_new_entry_is_neighbour_false(self, mock_time):
        """IS_NEIGHBOUR must be FALSE for a newly created LS Reply LocTE."""
        mock_time.return_value = self._TIMESTAMP
        mib = MIB()
        table = LocationTable(mib)
        so_addr = self._make_gn_addr()
        de_addr = self._make_req_addr()
        header = self._make_ls_reply_header(so_addr, de_addr)

        table.new_ls_reply_packet(header, b"payload")

        entry = table.get_entry(so_addr)
        self.assertIsNotNone(entry)
        self.assertFalse(entry.is_neighbour)

    @patch("flexstack.geonet.location_table.TimeService.time")
    def test_duplicate_ls_request_raises(self, mock_time):
        """DPD (annex A.2): same SN received twice must raise DuplicatedPacketException."""
        mock_time.return_value = self._TIMESTAMP
        mib = MIB()
        table = LocationTable(mib)
        addr = self._make_gn_addr()
        header = self._make_ls_request_header(addr)
        payload = b"dup_ls_request_payload"

        table.new_ls_request_packet(header, payload)
        with self.assertRaises(DuplicatedPacketException):
            table.new_ls_request_packet(header, payload)


# ---------------------------------------------------------------------------
# Annex C – Position vector update
# ---------------------------------------------------------------------------

class TestAnnexC(unittest.TestCase):
    """Unit tests verifying compliance with ETSI EN 302 636-4-1 V1.4.1 Annex C."""

    _TIMESTAMP = 1675071608.0

    def _make_lpv(self, timestamp_seconds: float) -> LongPositionVector:
        gn_addr = GNAddress(m=M.GN_MULTICAST, st=ST.CYCLIST, mid=MID(b"\xaa\xbb\xcc\xdd\x22\x33"))
        return LongPositionVector(
            gn_addr=gn_addr, pai=True, latitude=413872756, longitude=21122668
        ).set_tst_in_normal_timestamp_seconds(timestamp_seconds)

    # ── §C.2 update_position_vector ─────────────────────────────────────────

    def test_pv_not_updated_when_tst_equal(self):
        """§C.2 ELSE: when received TST equals stored TST, PV must remain unchanged."""
        mib = MIB()
        entry = LocationTableEntry(mib)
        pv1 = self._make_lpv(self._TIMESTAMP)
        entry.update_position_vector(pv1)

        # Build a PV with identical TST but different lat/lon
        pv2 = LongPositionVector(
            gn_addr=pv1.gn_addr, pai=True, latitude=0, longitude=0
        ).set_tst_in_normal_timestamp_seconds(self._TIMESTAMP)

        entry.update_position_vector(pv2)  # same TST -> must do nothing, no exception
        self.assertEqual(entry.position_vector, pv1)

    def test_pv_not_updated_when_tst_older(self):
        """§C.2 ELSE: when received TST is older than stored TST, PV must remain unchanged."""
        mib = MIB()
        entry = LocationTableEntry(mib)
        pv_newer = self._make_lpv(self._TIMESTAMP + 1.0)
        entry.update_position_vector(pv_newer)

        pv_older = self._make_lpv(self._TIMESTAMP)
        entry.update_position_vector(pv_older)  # older -> must do nothing, no exception
        self.assertEqual(entry.position_vector, pv_newer)

    def test_pv_updated_when_tst_newer(self):
        """§C.2 IF: received PV with strictly newer TST must replace stored PV."""
        mib = MIB()
        entry = LocationTableEntry(mib)
        pv_old = self._make_lpv(self._TIMESTAMP)
        entry.update_position_vector(pv_old)

        pv_new = self._make_lpv(self._TIMESTAMP + 1.0)
        entry.update_position_vector(pv_new)
        self.assertEqual(entry.position_vector, pv_new)

    # ── §C.2 refresh_table lifetime ─────────────────────────────────────────

    @patch("flexstack.geonet.location_table.TimeService.time")
    def test_locte_not_expired_within_lifetime(self, mock_time):
        """§C.2: LocTE must survive until itsGnLifetimeLocTE seconds have elapsed."""
        mock_time.return_value = self._TIMESTAMP
        mib = MIB()
        table = LocationTable(mib)
        gn_addr = GNAddress()
        pv = LongPositionVector(gn_addr=gn_addr).set_tst_in_normal_timestamp_seconds(
            self._TIMESTAMP)
        tsb = TSBExtendedHeader(sn=1, so_pv=pv)
        table.new_tsb_packet(tsb, b"payload")

        # Advance time just inside the lifetime window (19 s < 20 s)
        mock_time.return_value = self._TIMESTAMP + 19
        table.refresh_table()
        self.assertIsNotNone(table.get_entry(gn_addr))

    @patch("flexstack.geonet.location_table.TimeService.time")
    def test_locte_expired_after_lifetime(self, mock_time):
        """§C.2: LocTE must be removed after itsGnLifetimeLocTE (20 s) have elapsed."""
        mock_time.return_value = self._TIMESTAMP
        mib = MIB()
        table = LocationTable(mib)
        gn_addr = GNAddress()
        pv = LongPositionVector(gn_addr=gn_addr).set_tst_in_normal_timestamp_seconds(
            self._TIMESTAMP)
        tsb = TSBExtendedHeader(sn=1, so_pv=pv)
        table.new_tsb_packet(tsb, b"payload")

        # Advance time past the lifetime window (21 s > 20 s)
        mock_time.return_value = self._TIMESTAMP + 21
        table.refresh_table()
        self.assertIsNone(table.get_entry(gn_addr))


if __name__ == "__main__":
    unittest.main()
