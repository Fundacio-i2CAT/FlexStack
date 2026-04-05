from __future__ import annotations
from collections import deque
from threading import Lock, RLock
from ..utils.time_service import TimeService
from .gbc_extended_header import GBCExtendedHeader
from .tsb_extended_header import TSBExtendedHeader
from .guc_extended_header import GUCExtendedHeader
from .ls_extended_header import LSRequestExtendedHeader, LSReplyExtendedHeader
from .gn_address import GNAddress
from .mib import MIB
from .position_vector import LongPositionVector, TST
from .exceptions import DuplicatedPacketException


class LocationTableEntry:
    """
    Location table entry class. As specified in ETSI EN 302 636-4-1 V1.4.1 (2020-01). Section 8.1.2


    Attributes
    ----------
    mib : MIB
        MIB to use.
    position_vector : LongPositionVector
        Position vector of the ITS-S.
    ls_pending : bool
        Flag indicating that a Location Service (LS) (clause 10.2.4) is in progress.
    is_neighbour : bool
        Flag indicating that the GeoAdhoc router is in direct communication
        range, i.e. is a neighbour.
    dpl : deque[int]
        Duplicate packet list for source GN_ADDR. Stores the itsGnDPLLength most recently
        seen sequence numbers (annex A.2).
    tst : TST
        Timestamp TST(GN_ADDR): The timestamp of the last packet from the source GN_ADDR that was identified
        as 'not duplicated'
    pdr : int
        Packet data rate PDR(GN_ADDR) as Exponential Moving Average (EMA) (clause B.2).
    """

    def __init__(self, mib: MIB):
        self.mib = mib
        # In the future the version will be corrected, now if the version is not the same all packets are dropped
        self.version: int = mib.itsGnProtocolVersion
        self.position_vector_lock = Lock()
        self.position_vector: LongPositionVector = LongPositionVector()
        self.ls_pending: bool = False
        self.is_neighbour: bool = False
        self.tst_lock = Lock()
        self.tst: TST = TST()
        self.pdr_lock = Lock()
        self.pdr: float = 0.0
        self.dpl_lock = Lock()
        self.dpl_set: set[int] = set()                        # O(1) SN lookup
        self.dpl_deque: deque[int] = deque(maxlen=mib.itsGnDPLLength)  # ring buffer per A.2

    def get_gn_address(self) -> GNAddress:
        """
        Get the GN address.

        Returns
        -------
        GNAddress
            GN address.
        """
        return self.position_vector.gn_addr

    def update_position_vector(self, position_vector: LongPositionVector) -> None:
        """
        Updates the position vector.
        Annex C.2 of ETSI EN 302 636-4-1 V1.4.1 (2020-01):
        PV is updated only when the received TST is strictly newer than the stored TST
        (wrap-around handled by TST.__gt__). If not newer, the call returns silently
        and packet processing continues normally (no exception raised).

        Parameters
        ----------
        position_vector : LongPositionVector
            Position vector to update.
        """
        with self.position_vector_lock:
            if self.position_vector.tst.msec == 0:
                # §C.2: initial entry – accept first PV unconditionally.
                # TST.__gt__ comparison against TST(0) is unreliable for current
                # real-world timestamps (mod 2^32 > 2^31) due to wrap-around logic.
                self.position_vector = position_vector
            elif position_vector.tst > self.position_vector.tst:
                # §C.2: received PV is strictly newer → update
                self.position_vector = position_vector
            # §C.2 ELSE: received PV is not newer → do nothing;
            # packet processing continues normally (no exception)

    def update_pdr(self, position_vector: LongPositionVector, packet_size: int) -> None:
        """
        Updates the Packet Data Rate (PDR).
        Annex B2 of ETSI EN 302 636-4-1 V1.4.1 (2020-01)

        Parameters
        ----------
        position_vector : LongPositionVector
            Position vector of the packet.
        packet_size : int
            Size of the packet.
        """
        with self.tst_lock:
            prev_tst = self.tst
            self.tst = position_vector.tst
        time_since_last_update = (position_vector.tst - prev_tst) / 1000
        if time_since_last_update > 0:
            current_pdr = packet_size / time_since_last_update
            # Equation B1
            beta = self.mib.itsGnMaxPacketDataRateEmaBeta / 100
            with self.pdr_lock:
                self.pdr = beta * self.pdr + (1 - beta) * current_pdr

    def update_with_shb_packet(
        self, position_vector: LongPositionVector, packet: bytes
    ) -> None:
        """
        Updates the entry with a SHB packet.

        Follows the steps 4, 5 and 6 of the algorithm in ETSI EN 302 636-4-1 V1.4.1 (2020-01). Section 10.3.10.3

        Parameters
        ----------
        position_vector : LongPositionVector
            Position vector of the packet.
        packet : bytes
            SHB packet (without the basic header, the common header and the position vector).

        Raises
        ------
        IncongruentTimestampException
            If there has been another packet with posterior timestamp received before.
        DuplicatedPacketException
            If the packet is duplicated.
        """
        # NOTE: SHB has no SN field; annex A.2 DPD does NOT apply to SHB (§A.1)
        # step 4
        self.update_position_vector(position_vector)
        # step 5
        self.update_pdr(position_vector, (len(packet) + 8 + 4))
        # step 6
        self.is_neighbour = True

    def update_with_tsb_packet(
        self, packet: bytes, tsb_extended_header: TSBExtendedHeader, is_new_entry: bool
    ) -> None:
        """
        Updates the entry with a TSB packet.

        Follows steps 3-6 of §10.3.9.3 of ETSI EN 302 636-4-1 V1.4.1 (2020-01).

        Parameters
        ----------
        packet : bytes
            TSB payload (without headers).
        tsb_extended_header : TSBExtendedHeader
            TSB extended header.
        is_new_entry : bool
            True when this LocTE was just created; used to decide whether to set
            IS_NEIGHBOUR to FALSE (§10.3.9.3 step 5b) or leave it unchanged (NOTE 1).

        Raises
        ------
        IncongruentTimestampException
            If a packet with a later timestamp was received before.
        DuplicatedPacketException
            If the packet is duplicated.
        """
        position_vector = tsb_extended_header.so_pv
        # Step 3 (DPD) – SN-based duplicate check per annex A.2
        self.check_duplicate_sn(tsb_extended_header.sn)
        # Step 5a / 6a – update PV
        self.update_position_vector(position_vector)
        # Step 5c / 6b – update PDR
        self.update_pdr(position_vector, len(packet) + 8 + 4)
        # Step 5b – set IS_NEIGHBOUR = FALSE only for new entries (NOTE 1: unchanged otherwise)
        if is_new_entry:
            self.is_neighbour = False

    def update_with_gbc_packet(
        self, packet: bytes, gbc_extended_header: GBCExtendedHeader
    ) -> None:
        """
        Updates the entry with a SHB packet.

        Follows the steps 3, 4, 5 and 6 of the algorithm in ETSI EN 302 636-4-1 V1.4.1 (2020-01). Section 10.3.11.3

        Parameters
        ----------
        packet : bytes
            GBC packet (without the basic header, the common header and the extended header).
        gbc_extended_header : GBCExtendedHeader
            GBC extended header.

        Raises
        ------
        IncongruentTimestampException
            If there has been another packet with posterior timestamp received before.
        DuplicatedPacketException
            If the packet is duplicated.
        """
        position_vector = gbc_extended_header.so_pv
        # Step 3 (DPD) – SN-based duplicate check per annex A.2
        self.check_duplicate_sn(gbc_extended_header.sn)
        # step 4
        self.update_position_vector(position_vector)
        # step 5
        self.update_pdr(position_vector, (len(packet) + 8 + 4))
        # step 6
        self.is_neighbour = False

    def check_duplicate_sn(self, sn: int) -> None:
        """
        Checks if a packet with the given sequence number is a duplicate.

        Implements the SN-based DPD algorithm of annex A.2 of
        ETSI EN 302 636-4-1 V1.4.1 (2020-01).

        The DPL is a ring buffer of length itsGnDPLLength that stores the
        sequence numbers of the most recently received (non-duplicate) packets
        from this source.  When SN is already present in the DPL the packet is
        a duplicate; otherwise SN is added at the head (overwriting the oldest
        entry when the buffer is full).

        Only applicable to multi-hop packets (GUC, TSB, GBC, GAC, LS Request,
        LS Reply).  BEACON and SHB do not carry an SN field and must NOT call
        this method.

        Parameters
        ----------
        sn : int
            Sequence number field from the received GeoNetworking packet.

        Raises
        ------
        DuplicatedPacketException
            If *sn* is already present in the DPL.
        """
        with self.dpl_lock:
            if sn in self.dpl_set:
                raise DuplicatedPacketException("Packet is duplicated")
            # Evict oldest SN when the ring buffer is full
            if len(self.dpl_deque) == self.dpl_deque.maxlen:
                oldest = self.dpl_deque.popleft()
                self.dpl_set.discard(oldest)
            self.dpl_deque.append(sn)
            self.dpl_set.add(sn)


class LocationTable:
    """
    Location table class.  ETSI EN 302 636-4-1 V1.4.1 (2020-01). Section 8.1.1

    Attributes
    ----------
    mib : MIB
        MIB to use.
    loc_t : List[LocationTableEntry]
        Location table.
    """

    def __init__(self, mib: MIB):
        """
        Constructor.

        Parameters
        ----------
        mib : MIB
            MIB to use.
        """
        self.mib = mib
        self.loc_t: dict[GNAddress, LocationTableEntry] = {}
        self.loc_t_lock = RLock()

    def get_entry(self, gn_address: GNAddress) -> LocationTableEntry | None:
        """
        Gets the entry of the location table.

        Parameters
        ----------
        gn_address : GNAddress
            GN address.

        Returns
        -------
        LocationTableEntry | None
            Location table entry.
        """
        with self.loc_t_lock:
            return self.loc_t.get(gn_address, None)
        return None

    def ensure_entry(self, gn_address: GNAddress) -> LocationTableEntry:
        """
        Gets or creates a LocTE for gn_address without modifying its fields.

        Used by the Location Service to create a placeholder entry before setting ls_pending.

        Parameters
        ----------
        gn_address : GNAddress
            GN address.

        Returns
        -------
        LocationTableEntry
            Existing or newly created location table entry.
        """
        with self.loc_t_lock:
            entry = self.loc_t.get(gn_address, None)
            if entry is None:
                entry = LocationTableEntry(self.mib)
                self.loc_t[gn_address] = entry
        return entry

    def refresh_table(self) -> None:
        """
        Removes the entries that have expired.

        Temporarily solution following ETSI EN 302 636-4-1 V1.4.1 (2020-01). Section 8.1.3
        """
        current_time = TST.set_in_normal_timestamp_seconds(
            int(TimeService.time()))
        with self.loc_t_lock:
            self.loc_t = {
                gn: entry for gn, entry in self.loc_t.items()
                if (current_time - entry.position_vector.tst) <= self.mib.itsGnLifetimeLocTE * 1000
            }

    def new_shb_packet(
        self, position_vector: LongPositionVector, packet: bytes
    ) -> None:
        """
        Updates the location table with a new packet.

        Parameters
        ----------
        position_vector : LongPositionVector
            Position vector of the packet.
        packet : bytes
            SHB packet (without the basic header, the common header and the position vector).

        Raises
        ------
        IncongruentTimestampException
            If there has been another packet with posterior timestamp received before.
        DuplicatedPacketException
            If the packet is duplicated.
        """
        with self.loc_t_lock:
            entry = self.loc_t.get(position_vector.gn_addr)
            if entry is None:
                entry = LocationTableEntry(self.mib)
                self.loc_t[position_vector.gn_addr] = entry

        entry.update_with_shb_packet(position_vector, packet)
        self.refresh_table()

    def new_guc_packet(
        self, guc_extended_header: GUCExtendedHeader, packet: bytes
    ) -> None:
        """
        Updates the location table with a new GUC packet (SO LocTE).

        Follows steps 5-6 of §10.3.8.3 / §10.3.8.4 of ETSI EN 302 636-4-1 V1.4.1 (2020-01).
        IS_NEIGHBOUR is set to FALSE for new entries only; unchanged for existing ones (NOTE 2).

        Parameters
        ----------
        guc_extended_header : GUCExtendedHeader
            GUC extended header.
        packet : bytes
            GUC payload (without headers).

        Raises
        ------
        IncongruentTimestampException
            If a packet with a later timestamp was received before.
        DuplicatedPacketException
            If the packet is duplicated.
        """
        so_pv = guc_extended_header.so_pv
        with self.loc_t_lock:
            entry: LocationTableEntry | None = self.get_entry(so_pv.gn_addr)
            is_new_entry = entry is None
            if is_new_entry:
                entry = LocationTableEntry(self.mib)
                self.loc_t[so_pv.gn_addr] = entry
        assert entry is not None
        # DPD – SN-based per annex A.2
        entry.check_duplicate_sn(guc_extended_header.sn)
        # Update PV
        entry.update_position_vector(so_pv)
        # Update PDR
        entry.update_pdr(so_pv, len(packet) + 8 + 4)
        # IS_NEIGHBOUR = FALSE only for new entry (NOTE 2: unchanged otherwise)
        if is_new_entry:
            entry.is_neighbour = False
        self.refresh_table()

    def new_tsb_packet(
        self, tsb_extended_header: TSBExtendedHeader, packet: bytes
    ) -> None:
        """
        Updates the location table with a new TSB packet.

        Parameters
        ----------
        tsb_extended_header : TSBExtendedHeader
            TSB extended header.
        packet : bytes
            TSB payload (without headers).

        Raises
        ------
        IncongruentTimestampException
            If a packet with a later timestamp was received before.
        DuplicatedPacketException
            If the packet is duplicated.
        """
        with self.loc_t_lock:
            entry: LocationTableEntry | None = self.get_entry(
                tsb_extended_header.so_pv.gn_addr)
            is_new_entry = entry is None
            if is_new_entry:
                entry = LocationTableEntry(self.mib)
                self.loc_t[tsb_extended_header.so_pv.gn_addr] = entry
        assert entry is not None
        entry.update_with_tsb_packet(packet, tsb_extended_header, is_new_entry)
        self.refresh_table()

    def new_gac_packet(
        self, gbc_extended_header: GBCExtendedHeader, packet: bytes
    ) -> None:
        """
        Updates the location table with a new GAC packet (SO LocTE).

        Follows steps 5-6 of §10.3.12.3 of ETSI EN 302 636-4-1 V1.4.1 (2020-01).
        GAC and GBC share the same extended header format (§9.8.5), so GBCExtendedHeader
        is reused for GAC.
        IS_NEIGHBOUR is set to FALSE for new entries only; unchanged for existing ones (NOTE 1).

        Parameters
        ----------
        gbc_extended_header : GBCExtendedHeader
            GAC extended header (same wire format as GBC).
        packet : bytes
            GAC payload (without headers).

        Raises
        ------
        IncongruentTimestampException
            If a packet with a later timestamp was received before.
        DuplicatedPacketException
            If the packet is duplicated.
        """
        so_pv = gbc_extended_header.so_pv
        with self.loc_t_lock:
            entry: LocationTableEntry | None = self.get_entry(so_pv.gn_addr)
            is_new_entry = entry is None
            if is_new_entry:
                entry = LocationTableEntry(self.mib)
                self.loc_t[so_pv.gn_addr] = entry
        assert entry is not None
        # DPD – SN-based per annex A.2
        entry.check_duplicate_sn(gbc_extended_header.sn)
        # Update PV (step 5a / 6a)
        entry.update_position_vector(so_pv)
        # Update PDR (step 5c / 6b)
        entry.update_pdr(so_pv, len(packet) + 8 + 4)
        # IS_NEIGHBOUR = FALSE only for new entry (NOTE 1: unchanged otherwise)
        if is_new_entry:
            entry.is_neighbour = False
        self.refresh_table()

    def new_ls_request_packet(
        self, ls_request_header: LSRequestExtendedHeader, packet: bytes
    ) -> None:
        """
        Updates the location table with a new LS Request packet (SO LocTE).

        Follows steps 5-6 of §10.3.7.3 of ETSI EN 302 636-4-1 V1.4.1 (2020-01).
        IS_NEIGHBOUR is set to FALSE for new entries only; unchanged for existing ones (NOTE).

        Parameters
        ----------
        ls_request_header : LSRequestExtendedHeader
            LS Request extended header.
        packet : bytes
            LS Request payload/data (used for DPD).

        Raises
        ------
        IncongruentTimestampException
            If a packet with a later timestamp was received before.
        DuplicatedPacketException
            If the packet is duplicated.
        """
        so_pv = ls_request_header.so_pv
        with self.loc_t_lock:
            entry: LocationTableEntry | None = self.get_entry(so_pv.gn_addr)
            is_new_entry = entry is None
            if is_new_entry:
                entry = LocationTableEntry(self.mib)
                self.loc_t[so_pv.gn_addr] = entry
        assert entry is not None
        # DPD – SN-based per annex A.2
        entry.check_duplicate_sn(ls_request_header.sn)
        # Step 5a / 6a: update PV(SO)
        entry.update_position_vector(so_pv)
        # Step 5c / 6b: update PDR(SO)
        entry.update_pdr(so_pv, len(packet) + 8 + 4)
        # Step 5b: IS_NEIGHBOUR = FALSE only for new entry (NOTE: unchanged otherwise)
        if is_new_entry:
            entry.is_neighbour = False
        self.refresh_table()

    def new_ls_reply_packet(
        self, ls_reply_header: LSReplyExtendedHeader, packet: bytes
    ) -> None:
        """
        Updates the location table with a new LS Reply packet (SO LocTE).

        Follows steps 4-5 of §10.3.7.1.4 of ETSI EN 302 636-4-1 V1.4.1 (2020-01).
        The LS Reply SO PV is the replier's position; IS_NEIGHBOUR is set to FALSE for new entries.

        Parameters
        ----------
        ls_reply_header : LSReplyExtendedHeader
            LS Reply extended header.
        packet : bytes
            LS Reply payload (used for DPD).

        Raises
        ------
        IncongruentTimestampException
            If a packet with a later timestamp was received before.
        DuplicatedPacketException
            If the packet is duplicated.
        """
        so_pv = ls_reply_header.so_pv
        with self.loc_t_lock:
            entry: LocationTableEntry | None = self.get_entry(so_pv.gn_addr)
            is_new_entry = entry is None
            if is_new_entry:
                entry = LocationTableEntry(self.mib)
                self.loc_t[so_pv.gn_addr] = entry
        assert entry is not None
        # DPD – SN-based per annex A.2
        entry.check_duplicate_sn(ls_reply_header.sn)
        # Step 4: update PV(SO)
        entry.update_position_vector(so_pv)
        # Step 5: update PDR(SO)
        entry.update_pdr(so_pv, len(packet) + 8 + 4)
        if is_new_entry:
            entry.is_neighbour = False
        self.refresh_table()

    def new_gbc_packet(
        self, gbc_extended_header: GBCExtendedHeader, packet: bytes
    ) -> None:
        """
        Updates the location table with a new packet.

        Parameters
        ----------
        gbc_extended_header : GBCExtendedHeader
            GBC extended header.
        packet : bytes
            GBC packet (without the basic header, the common header and the extended header).

        Raises
        ------
        IncongruentTimestampException
            If there has been another packet with posterior timestamp received before.
        DuplicatedPacketException
            If the packet is duplicated.
        """
        with self.loc_t_lock:
            entry: LocationTableEntry | None = self.get_entry(
                gbc_extended_header.so_pv.gn_addr)
            if entry is None:
                entry = LocationTableEntry(self.mib)
                self.loc_t[gbc_extended_header.so_pv.gn_addr] = entry
        entry.update_with_gbc_packet(packet, gbc_extended_header)
        self.refresh_table()

    def get_neighbours(self) -> list[LocationTableEntry]:
        """
        Gets the neighbours.

        Returns
        -------
        List[LocationTableEntry]
            List of neighbours.
        """
        neighbours: list[LocationTableEntry] = []
        with self.loc_t_lock:
            for _, entry in self.loc_t.items():
                if entry.is_neighbour:
                    neighbours.append(entry)
        return neighbours
