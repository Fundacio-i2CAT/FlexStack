from dataclasses import dataclass, field
from .exceptions import DecodeError
from .position_vector import LongPositionVector, ShortPositionVector
from .gn_address import GNAddress


@dataclass(frozen=True)
class LSRequestExtendedHeader:
    """
    LS Request Extended Header. §9.8.7 Table 16 of ETSI EN 302 636-4-1 V1.4.1 (2020-01).

    Layout (36 bytes, after Basic + Common headers):
        SN               2 octets  (octets 12-13 of full LS Request packet)
        Reserved         2 octets  (octets 14-15)
        SO PV           24 octets  (octets 16-39)  Long Position Vector
        Request GN_ADDR  8 octets  (octets 40-47)  GN address being sought

    Attributes
    ----------
    sn : int
        Sequence number (16-bit unsigned).
    reserved : int
        Reserved. Set to 0.
    so_pv : LongPositionVector
        Source Long Position Vector (ego GeoAdhoc router).
    request_gn_addr : GNAddress
        GN_ADDR of the GeoAdhoc router whose location is being requested.
    """

    sn: int = 0
    reserved: int = 0
    so_pv: LongPositionVector = field(default_factory=LongPositionVector)
    request_gn_addr: GNAddress = field(default_factory=GNAddress)

    @classmethod
    def initialize(
        cls,
        sequence_number: int,
        ego_pv: LongPositionVector,
        request_gn_addr: GNAddress,
    ) -> "LSRequestExtendedHeader":
        """
        Initialise an LS Request Extended Header for a new outgoing LS Request.

        Parameters
        ----------
        sequence_number : int
            Local sequence number (clause 8.3).
        ego_pv : LongPositionVector
            Ego position vector (SO PV field, clause 8.2).
        request_gn_addr : GNAddress
            GN_ADDR of the sought GeoAdhoc router (table 23).
        """
        return cls(sn=sequence_number, so_pv=ego_pv, request_gn_addr=request_gn_addr)

    def encode(self) -> bytes:
        """Encode the LS Request Extended Header to bytes (36 bytes)."""
        return (
            self.sn.to_bytes(2, "big")
            + self.reserved.to_bytes(2, "big")
            + self.so_pv.encode()
            + self.request_gn_addr.encode_to_int().to_bytes(8, "big")
        )

    @classmethod
    def decode(cls, header: bytes) -> "LSRequestExtendedHeader":
        """
        Decode the LS Request Extended Header from bytes.

        Parameters
        ----------
        header : bytes
            At least 36 bytes.

        Raises
        ------
        DecodeError
            If the header is shorter than 36 bytes.
        """
        if len(header) < 36:
            raise DecodeError(
                f"LS Request Extended Header too short: expected 36 bytes, got {len(header)}"
            )
        sn = int.from_bytes(header[0:2], "big")
        reserved = int.from_bytes(header[2:4], "big")
        so_pv = LongPositionVector.decode(header[4:28])
        request_gn_addr = GNAddress.decode(header[28:36])
        return cls(sn=sn, reserved=reserved, so_pv=so_pv, request_gn_addr=request_gn_addr)


@dataclass(frozen=True)
class LSReplyExtendedHeader:
    """
    LS Reply Extended Header. §9.8.8 Table 17 of ETSI EN 302 636-4-1 V1.4.1 (2020-01).

    Layout (48 bytes, after Basic + Common headers):
        SN        2 octets  (octets 12-13)  Sequence number
        Reserved  2 octets  (octets 14-15)
        SO PV    24 octets  (octets 16-39)  Long Position Vector (source = replier)
        DE PV    20 octets  (octets 40-59)  Short Position Vector (destination = requester)

    NOTE: This layout is identical to the GUC Extended Header (§9.8.2).

    Attributes
    ----------
    sn : int
        Sequence number (16-bit unsigned).
    reserved : int
        Reserved. Set to 0.
    so_pv : LongPositionVector
        Source Long Position Vector (the replier's own position).
    de_pv : ShortPositionVector
        Destination Short Position Vector (the requester's position from LocT).
    """

    sn: int = 0
    reserved: int = 0
    so_pv: LongPositionVector = field(default_factory=LongPositionVector)
    de_pv: ShortPositionVector = field(default_factory=ShortPositionVector)

    @classmethod
    def initialize(
        cls,
        sequence_number: int,
        ego_pv: LongPositionVector,
        de_pv: ShortPositionVector,
    ) -> "LSReplyExtendedHeader":
        """
        Initialise an LS Reply Extended Header for a new outgoing LS Reply.

        Parameters
        ----------
        sequence_number : int
            Local sequence number (clause 8.3).
        ego_pv : LongPositionVector
            Ego position vector of the replier (SO PV field, table 25).
        de_pv : ShortPositionVector
            Short Position Vector of the requester, from LocT (DE PV field, table 25).
        """
        return cls(sn=sequence_number, so_pv=ego_pv, de_pv=de_pv)

    def encode(self) -> bytes:
        """Encode the LS Reply Extended Header to bytes (48 bytes)."""
        return (
            self.sn.to_bytes(2, "big")
            + self.reserved.to_bytes(2, "big")
            + self.so_pv.encode()
            + self.de_pv.encode()
        )

    @classmethod
    def decode(cls, header: bytes) -> "LSReplyExtendedHeader":
        """
        Decode the LS Reply Extended Header from bytes.

        Parameters
        ----------
        header : bytes
            At least 48 bytes.

        Raises
        ------
        DecodeError
            If the header is shorter than 48 bytes.
        """
        if len(header) < 48:
            raise DecodeError(
                f"LS Reply Extended Header too short: expected 48 bytes, got {len(header)}"
            )
        sn = int.from_bytes(header[0:2], "big")
        reserved = int.from_bytes(header[2:4], "big")
        so_pv = LongPositionVector.decode(header[4:28])
        de_pv = ShortPositionVector.decode(header[28:48])
        return cls(sn=sn, reserved=reserved, so_pv=so_pv, de_pv=de_pv)
