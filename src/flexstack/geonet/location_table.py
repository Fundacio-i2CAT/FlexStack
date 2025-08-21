from __future__ import annotations
from ..utils.time_service import TimeService
import hashlib
from .gbc_extended_header import GBCExtendedHeader
from .gn_address import GNAddress
from .mib import MIB
from .position_vector import LongPositionVector, TST
from .exceptions import DuplicatedPacketException, IncongruentTimestampException


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
    dpl : List[bytes]
        Duplicate packet list for source GN_ADDR. (List of hashes of the packets)
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
        self.position_vector: LongPositionVector = LongPositionVector()
        self.ls_pending: bool = False
        self.is_neighbour: bool = False
        self.dpl: list[bytes] = []
        self.tst: TST = TST()
        self.pdr: int = 0

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
        Annex C2 of ETSI EN 302 636-4-1 V1.4.1 (2020-01)
        The algorithm is implemented partially on the TST

        Parameters
        ----------
        position_vector : LongPositionVector
            Position vector to update.

        Raises
        ------
        IncongruentTimestampException
            If there has been another packet with posterior timestamp received before.
        """
        if self.position_vector.tst.msec == 0:
            self.position_vector = position_vector
        elif position_vector.tst > self.position_vector.tst:
            self.position_vector = position_vector
        else:
            raise IncongruentTimestampException("Position vector not updated")

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
        time_since_last_update = (position_vector.tst - self.tst) / 1000
        self.tst = position_vector.tst
        if time_since_last_update > 0:
            current_pdr = packet_size / time_since_last_update
            # Equation B1
            beta = self.mib.itsGnMaxPacketDataRateEmaBeta / 100
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
        # Own added check (not in the standard)
        self.check_duplicate_packet(packet)
        # End own added check
        # step 4
        self.update_position_vector(position_vector)
        # step 5
        self.update_pdr(position_vector, (len(packet) + 8 + 4))
        # step 6
        self.is_neighbour = True

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
        # Own added check (not in the standard)
        self.check_duplicate_packet(packet)
        # End own added check
        # step 4
        self.update_position_vector(position_vector)
        # step 5
        self.update_pdr(position_vector, (len(packet) + 8 + 4))
        # step 6
        self.is_neighbour = False

    def check_duplicate_packet(self, packet: bytes) -> None:
        """
        Checks if the packet is duplicated.

        ETSI EN 302 636-4-1 V1.4.1 (2020-01)

        Temporary implementation. The DPL is not implemented yet.

        Parameters
        ----------
        packet : bytes
            Packet to check.

        Raises
        ------
        DuplicatedPacketException
            If the packet is duplicated.
        """
        packet_hash = hashlib.sha256(packet).digest()
        if packet_hash in self.dpl:
            raise DuplicatedPacketException("Packet is duplicated")
        self.dpl.append(packet_hash)
        if len(self.dpl) > 50:
            self.dpl.pop(0)


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
        self.loc_t: list[LocationTableEntry] = []

    def get_entry(self, gn_address: GNAddress) -> LocationTableEntry:
        """
        Gets the entry of the location table.

        Parameters
        ----------
        gn_address : GNAddress
            GN address.

        Returns
        -------
        LocationTableEntry
            Location table entry.
        """
        for entry in self.loc_t:
            if entry.get_gn_address() == gn_address:
                return entry
        return None

    def refresh_table(self) -> None:
        """
        Removes the entries that have expired.

        Temporarily solution following ETSI EN 302 636-4-1 V1.4.1 (2020-01). Section 8.1.3
        """
        current_time = TST()
        current_time.set_in_normal_timestamp_seconds(int(TimeService.time()))
        for entry in self.loc_t:
            if (current_time - entry.position_vector.tst) > self.mib.itsGnLifetimeLocTE:
                self.loc_t.remove(entry)

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
        entry: LocationTableEntry = self.get_entry(position_vector.gn_addr)
        if entry:
            entry.update_with_shb_packet(position_vector, packet)
        else:
            entry = LocationTableEntry(self.mib)
            entry.update_with_shb_packet(position_vector, packet)
            self.loc_t.append(entry)
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
        entry: LocationTableEntry = self.get_entry(
            gbc_extended_header.so_pv.gn_addr)
        if entry:
            entry.update_with_gbc_packet(packet, gbc_extended_header)
        else:
            entry = LocationTableEntry(self.mib)
            entry.update_with_gbc_packet(packet, gbc_extended_header)
            self.loc_t.append(entry)
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
        for entry in self.loc_t:
            if entry.is_neighbour:
                neighbours.append(entry)
        return neighbours
