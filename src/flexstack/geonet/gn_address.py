from enum import Enum
from dataclasses import dataclass, field

from .exceptions import DecodeError


class M(Enum):
    """
    M field of GNAddress as described in ETSI TS 103 836-4-1 V2.2.1 (2026-04)

    ...

    Attributes
    ----------
    GN_UNICAST :
        GN Unicast Address
    GN_MULTICAST :
        GN Multicast Address
    """
    GN_UNICAST = 0
    GN_MULTICAST = 1

    def encode_to_address(self) -> int:
        """
        Encodes M to int for GN address

        Returns
        -------
        int
            Encoded M
        """
        return (self.value << 7) << 8*7


class ST(Enum):
    """
    ST field of GNAddress as described in ETSI TS 103 836-4-1 V2.2.1 (2026-04)

    ...

    Attributes
    ----------
    UNKNOWN :
        Unknown
    PEDESTRIAN :
        Pedestrianremaining
    CYCLIST :
        Cyclist
    MOPED :
        Moped
    MOTORCYCLE :
        Motorcycle
    PASSENGER_CAR :
        Passenger Car
    BUS :
        Bus
    LIGHT_TRUCK :
        Light Truck
    HEAVY_TRUCK :
        Heavy Truck
    TRAILER :
        Trailer
    SPECIAL_VEHICLE :
        Special Vehicle
    TRAM :
        Tram
    ROAD_SIDE_UNIT :
        Road Side Unit
    """
    UNKNOWN = 0
    PEDESTRIAN = 1
    CYCLIST = 2
    MOPED = 3
    MOTORCYCLE = 4
    PASSENGER_CAR = 5
    BUS = 6
    LIGHT_TRUCK = 7
    HEAVY_TRUCK = 8
    TRAILER = 9
    SPECIAL_VEHICLE = 10
    TRAM = 11
    ROAD_SIDE_UNIT = 12

    def encode_to_address(self) -> int:
        """
        Encodes ST to int for GN address

        Returns
        int
        bytes
            Encoded ST
        """
        return (self.value << 2) << 8*7


class InvalidMIDLength(Exception):
    """Exception for invalid MID length"""


@dataclass(frozen=True)
class MID:
    """MID field of GNAddress as described in ETSI TS 103 836-4-1 V2.2.1 (2026-04).

    Attributes
    ----------
    mid: bytes
        MID field of GNAddress: LL_ADDR (6 bytes)
    """

    mid: bytes

    def __post_init__(self) -> None:
        if len(self.mid) != 6:
            raise InvalidMIDLength("MID must be 6 bytes long")

    @classmethod
    def from_its_g5_mac(cls, mac_address: bytes) -> "MID":
        """
        MID for GN over ITS-G5: the 48-bit MAC address of the ITS-G5 interface
        (ETSI TS 103 836-4-2 V2.1.1, clause 6.1).
        """
        return cls(bytes(mac_address))

    @classmethod
    def from_lte_v2x_l2_id(cls, l2_id: int) -> "MID":
        """
        MID for GN over LTE-V2X: the 24-bit Source Layer 2 ID in octets 2-4 of
        the GN address, octets 5-7 set to zero (ETSI TS 103 836-4-3 V2.1.1,
        clause 5.2).
        """
        if not 0 <= l2_id < 2**24:
            raise ValueError("Layer 2 ID must be a 24-bit value")
        return cls(l2_id.to_bytes(3, "big") + b"\x00\x00\x00")

    def encode_to_address(self) -> int:
        """
        Encodes MID to int for GN address

        Returns
        -------
        int
            Encoded MID
        """
        return int.from_bytes(b'\x00\x00' + self.mid, byteorder='big')


@dataclass(frozen=True)
class GNAddress:
    """GeoNetworking Address.

    Attributes
    ----------
    m : M
    st : ST
    mid : MID
    """

    m: M = M.GN_UNICAST
    st: ST = ST.UNKNOWN
    mid: MID = field(default_factory=lambda: MID(b'\x00\x00\x00\x00\x00\x00'))

    def set_m(self, m: M) -> "GNAddress":
        """
        Return a new GNAddress with updated m.

        Parameters
        ----------
        m : M
            M to set
        """
        return GNAddress(m=m, st=self.st, mid=self.mid)

    def set_st(self, st: ST) -> "GNAddress":
        """
        Return a new GNAddress with updated st.

        Parameters
        ----------
        st : ST
            ST to set
        """
        return GNAddress(m=self.m, st=st, mid=self.mid)

    def set_mid(self, mid: MID) -> "GNAddress":
        """
        Return a new GNAddress with updated mid.

        Parameters
        ----------
        mid : MID
            MID to set

        Returns
        -------
        GNAddress
            New GNAddress with updated mid
        """
        return GNAddress(m=self.m, st=self.st, mid=mid)

    def encode(self) -> bytes:
        """
        Encodes GNAddress to bytes.

        Returns
        -------
        bytes
            Encoded GNAddress as bytes
        """
        return (
            self.m.encode_to_address() | self.st.encode_to_address() | self.mid.encode_to_address()
        ).to_bytes(8, byteorder='big')

    def encode_to_int(self) -> int:
        """
        Encodes GNAddress to int

        Returns
        -------
        int
            Encoded GNAddress as int
        """
        return self.m.encode_to_address() | self.st.encode_to_address() | self.mid.encode_to_address()

    @classmethod
    def decode(cls, data: bytes) -> "GNAddress":
        """
        Decode a GNAddress from bytes and return a new instance.

        Parameters
        ----------
        data : bytes
            Bytes to decode

        Returns
        -------
        GNAddress
            Decoded GNAddress instance
        """
        if len(data) < 8:
            raise DecodeError("GNAddress must be 8 bytes long")
        m = M((data[0] & 0x80) >> 7)
        st = ST((data[0] & 0x7C) >> 2)
        mid = MID(data[2:8])
        return cls(m=m, st=st, mid=mid)

    def __eq__(self, __o: object) -> bool:
        """
        Checks if two GNAddress are equal.

        Just compares the MAC address inside the MID field

        Parameters
        ----------
        __o : object
            Object to compare
        """
        if not isinstance(__o, GNAddress):
            return False
        return self.mid.mid == __o.mid.mid

    def __str__(self) -> str:
        return f"GNAddress(M={self.m}, ST={self.st}, MID={self.mid})"
