from enum import Enum
from dataclasses import dataclass, field

from .exceptions import DecodeError
from .mib import MIB


class BasicNH(Enum):
    """
    Next Header field class. As specified in ETSI EN 302 636-4-1 V1.4.1 (2020-01). Section 9.6.3

    Attributes
    ----------
    ANY :
        Any next header.
    COMMON_HEADER :
        Common Header.
    SECURED_PACKET :
        Secured Packet.
    """

    ANY = 0
    COMMON_HEADER = 1
    SECURED_PACKET = 2


class LTbase(Enum):
    """
    Lifetime base class. As specified in ETSI EN 302 636-4-1 V1.4.1 (2020-01). Section 9.6.4

    Attributes
    ----------
    fifty_milliseconds :
        50 ms.
    one_second :
        1 s.
    ten_seconds :
        10 s.
    one_hundred_seconds :
        100 s.
    """

    FIFTY_MILLISECONDS = 0
    ONE_SECOND = 1
    TEN_SECONDS = 2
    ONE_HUNDRED_SECONDS = 3


@dataclass(frozen=True)
class LT:
    """
    Lifetime class. As specified in ETSI EN 302 636-4-1 V1.4.1 (2020-01). Section 9.6.4

    The Lifetime (LT) field shall indicate the maximum tolerable time a packet may be buffered until it reaches
    its destination.
    The LT field shall be comprised of two sub-fields: a LTMultiplier sub-field (Multiplier)
    and a LTBase sub-field (Base) (figure 10) and shall be encoded as follows:
    LT = Multiplier * Base

    Attributes
    ----------
    multiplier : int
        (5 bit unsigned integer) Lifetime multiplier.
    base : LTbase
        (2 bit unsigned integer) Lifetime base.
    """

    multiplier: int = 0
    base: LTbase = LTbase.FIFTY_MILLISECONDS

    def set_value_in_millis(self, value: int) -> "LT":
        """
        Set the lifetime in milliseconds.

        Parameters
        ----------
        value : int
            Lifetime in milliseconds.
        """
        if value < 50:
            multiplier = 0
            base = LTbase.FIFTY_MILLISECONDS
        elif value < 100:
            multiplier = 1
            base = LTbase.FIFTY_MILLISECONDS
        elif value < 500:
            multiplier = int(value / 50 % 64)
            base = LTbase.FIFTY_MILLISECONDS
        elif value < 1000:
            multiplier = 0
            base = LTbase.ONE_SECOND
        elif value < 10000:
            multiplier = int(value / 1000 % 64)
            base = LTbase.ONE_SECOND
        elif value < 100000:
            multiplier = int(value / 10000 % 64)
            base = LTbase.TEN_SECONDS
        elif value < 1000000:
            multiplier = int(value / 100000 % 64)
            base = LTbase.ONE_HUNDRED_SECONDS
        else:
            multiplier = 0
            base = LTbase.ONE_HUNDRED_SECONDS

        return LT(multiplier=multiplier, base=base)

    def set_value_in_seconds(self, value: int) -> "LT":
        """
        Set the lifetime in seconds.

        Parameters
        ----------
        value : int
            Lifetime in seconds.
        """
        return self.set_value_in_millis(value * 1000)

    def get_value_in_millis(self) -> int:
        """
        Get the lifetime in milliseconds.

        Returns
        -------
        int
            Lifetime in milliseconds.
        """
        if self.base == LTbase.FIFTY_MILLISECONDS:
            return self.multiplier * 50
        if self.base == LTbase.ONE_SECOND:
            return self.multiplier * 1000
        if self.base == LTbase.TEN_SECONDS:
            return self.multiplier * 10000
        if self.base == LTbase.ONE_HUNDRED_SECONDS:
            return self.multiplier * 100000
        return 0

    def get_value_in_seconds(self) -> int:
        """
        Get the lifetime in seconds.

        Returns
        -------
        int
            Lifetime in seconds.
        """
        return self.get_value_in_millis() // 1000

    def encode_to_int(self) -> int:
        """
        Encode the LT to an integer.

        Returns
        -------
        int
            Encoded LT.
        """
        return self.multiplier << 2 | self.base.value

    def encode_to_bytes(self) -> bytes:
        """
        Encode the LT to bytes.

        Returns
        -------
        bytes
            Encoded LT.
        """
        return self.encode_to_int().to_bytes(1, "big")


@dataclass(frozen=True)
class BasicHeader:
    """
    Basic Header class. As specified in ETSI EN 302 636-4-1 V1.4.1 (2020-01). Section 9.6

    Attributes
    ----------
    version : int
        (4 bit unsigned intger) Version of the GeoNetworking protocol.
    nh : int
        (4 bit unsigned integer) Next Header. Indicates the type of the next header.
    reserved : int
        (8 bit unsigned integer) Reserved. All bits set to zero.
    lt : LT
        (8 bit unsigned integer) Lifetime. Indicates the lifetime of the packet.
    rhl : int
        (8 bit unsigned integer) Remaining Hop Limit. Indicates the remaining number of hops.

    """

    version: int = 1
    nh: BasicNH = BasicNH.COMMON_HEADER
    reserved: int = 0
    lt: LT = field(default_factory=LT)
    rhl: int = 0

    @classmethod
    def initialize_with_mib_and_rhl(cls, mib: MIB, rhl: int) -> "BasicHeader":
        lt = LT().set_value_in_seconds(mib.itsGnDefaultPacketLifetime)
        return cls(
            version=1,
            nh=BasicNH.COMMON_HEADER,
            reserved=0,
            lt=lt,
            rhl=rhl,
        )

    def set_version(self, version: int) -> "BasicHeader":
        """
        Set the version.

        Parameters
        ----------
        version : int
            Version of the GeoNetworking protocol.
        """
        return BasicHeader(
            version=version,
            nh=self.nh,
            reserved=self.reserved,
            lt=self.lt,
            rhl=self.rhl,
        )

    def set_nh(self, nh: BasicNH) -> "BasicHeader":
        """
        Set the next header.

        Parameters
        ----------
        nh : BasicNH
            Next Header. Indicates the type of the next header.
        """
        return BasicHeader(
            version=self.version,
            nh=nh,
            reserved=self.reserved,
            lt=self.lt,
            rhl=self.rhl,
        )

    def set_lt(self, lt: LT) -> "BasicHeader":
        """
        Set the lifetime.

        Parameters
        ----------
        lt : LT
            Lifetime. Indicates the lifetime of the packet.
        """
        return BasicHeader(
            version=self.version,
            nh=self.nh,
            reserved=self.reserved,
            lt=lt,
            rhl=self.rhl,
        )

    def set_rhl(self, rhl: int) -> "BasicHeader":
        """
        Set the remaining hop limit.

        Parameters
        ----------
        rhl : int
            Remaining Hop Limit. Indicates the remaining number of hops.
        """
        return BasicHeader(
            version=self.version,
            nh=self.nh,
            reserved=self.reserved,
            lt=self.lt,
            rhl=rhl % 256,
        )

    def encode_to_int(self) -> int:
        """
        Encode the Basic Header to an integer.

        Returns
        -------
        int
            Encoded Basic Header.
        """
        return (
            self.version << (4 + 3 * 8)
            | self.nh.value << (0 + 3 * 8)
            | self.reserved << 2 * 8
            | self.lt.encode_to_int() << 8
            | self.rhl
        )

    def encode_to_bytes(self) -> bytes:
        """
        Encode the Basic Header to bytes.

        Returns
        -------
        bytes
            Encoded Basic Header.
        """
        return self.encode_to_int().to_bytes(4, "big")

    @classmethod
    def decode_from_int(cls, value: int) -> "BasicHeader":
        """
        Decode the Basic Header from an integer.

        Parameters
        ----------
        value : int
            Encoded Basic Header.
        """
        # Return a new BasicHeader created from the integer value
        version = value >> (4 + 3 * 8) & 0xF
        nh = BasicNH((value >> (0 + 3 * 8) & 0xF))
        reserved = value >> 2 * 8 & 0xFF
        multiplier = (value >> 10) & 0x3F
        base = LTbase((value >> 8) & 0x03)
        lt = LT(multiplier=multiplier, base=base)
        rhl = value & 0xFF
        return cls(version=version, nh=nh, reserved=reserved, lt=lt, rhl=rhl)

    @classmethod
    def decode_from_bytes(cls, value: bytes) -> "BasicHeader":
        """
        Decode the Basic Header from bytes.

        Parameters
        ----------
        value : bytes
            Encoded Basic Header.
        """
        if len(value) < 4:
            raise DecodeError("Basic Header must be 4 bytes long")
        return cls.decode_from_int(int.from_bytes(value[0:4], "big"))

    @classmethod
    def initialize_with_mib(cls, mib: MIB) -> "BasicHeader":
        """
        Initialize the Basic Header with the MIB.

        Parameters
        ----------
        mib : MIB
            MIB.
        """
        # Return a new BasicHeader initialized using values from the MIB
        lt = LT().set_value_in_seconds(mib.itsGnDefaultPacketLifetime)
        return cls(
            version=mib.itsGnProtocolVersion,
            nh=BasicNH.COMMON_HEADER,
            reserved=0,
            lt=lt,
            rhl=mib.itsGnDefaultHopLimit,
        )

    # dataclass provides an appropriate __eq__ implementation
