from enum import Enum

from .exceptions import DecodeError


class M(Enum):
    """
    M field of GNAddress as described in ETSI EN 302 636-4-1 V1.4.1 (2020-01)

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
    ST field of GNAddress as described in ETSI EN 302 636-4-1 V1.4.1 (2020-01)

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
        return (self.value << 3) << 8*7


class InvalidMIDLength(Exception):
    """
    Exception for invalid MID length
    """


class MID:
    """
    MID field of GNAddress as described in ETSI EN 302 636-4-1 V1.4.1 (2020-01)

    ...

    Attributes
    ----------
    MID : bytes
        MID field of GNAddress: LL_ADDR
    """

    def __init__(self, mid: bytes):
        if len(mid) != 6:
            raise InvalidMIDLength("MID must be 6 bytes long")
        self.mid: bytes = mid

    def encode_to_address(self) -> int:
        """
        Encodes MID to int for GN address

        Returns
        -------
        int
            Encoded MID for GN address
        """
        return int.from_bytes(b'\x00\x00'+self.mid, byteorder='big')


class GNAddress:
    """
    GeoNetworking Address as described in ETSI EN 302 636-4-1 V1.4.1 (2020-01). Section 6.3

    ...

    Attributes
    ----------
    M : M
        M field of GNAddress
    ST : ST
        ST field of GNAddress
    MID : bytes
        MID field of GNAddress: LL_ADDR
    """

    def __init__(self):
        self.m: M = M.GN_UNICAST
        self.st: ST = ST.UNKNOWN
        self.mid: MID = MID(b'\x00\x00\x00\x00\x00\x00')

    def set_m(self, m: M):
        """
        Sets M field of GNAddress

        Parameters
        ----------
        m : M
            M field of GNAddress
        """
        self.m = m

    def set_st(self, st: ST):
        """
        Sets ST field of GNAddress

        Parameters
        ----------
        st : ST
            ST field of GNAddress
        """
        self.st = st

    def set_mid(self, mid: MID):
        """
        Sets MID field of GNAddress

        Parameters
        ----------
        mid : MID
            MID field of GNAddress
        """
        self.mid = mid

    def encode(self) -> bytes:
        """
        Encodes GNAddress to bytes

        Returns
        -------
        bytes
            Encoded GNAddress
        """
        return (self.m.encode_to_address() | self.st.encode_to_address() | self.mid.encode_to_address()).to_bytes(
            8, byteorder='big')

    def encode_to_int(self) -> int:
        """
        Encodes GNAddress to int

        Returns
        -------
        int
            Encoded GNAddress
        """
        return self.m.encode_to_address() | self.st.encode_to_address() | self.mid.encode_to_address()

    def decode(self, data: bytes):
        """
        Decodes GNAddress from bytes
        """
        if len(data) < 8:
            raise DecodeError("GNAddress must be 8 bytes long")
        self.m = M((data[0] & 0x80) >> 7)
        self.st = ST((data[0] & 0x78) >> 3)
        self.mid = MID(data[2:8])

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
