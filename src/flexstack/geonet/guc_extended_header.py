from dataclasses import dataclass, field
from .exceptions import DecodeError
from .position_vector import LongPositionVector, ShortPositionVector


@dataclass(frozen=True)
class GUCExtendedHeader:
    """
    GUC Extended Header class. As specified in ETSI EN 302 636-4-1 V1.4.1 (2020-01). Section 9.8.2 (Table 11).

    Layout (48 bytes after Basic + Common headers):
        SN         2 octets  (octets 12-13 of full GUC packet)
        Reserved   2 octets  (octets 14-15)
        SO PV     24 octets  (octets 16-39)  Long Position Vector
        DE PV     20 octets  (octets 40-59)  Short Position Vector

    Attributes
    ----------
    sn : int
        Sequence number (16-bit unsigned).
    reserved : int
        Reserved. Set to 0.
    so_pv : LongPositionVector
        Source Long Position Vector (ego GeoAdhoc router).
    de_pv : ShortPositionVector
        Destination Short Position Vector (position of the destination GeoAdhoc router).
    """

    sn: int = 0
    reserved: int = 0
    so_pv: LongPositionVector = field(default_factory=LongPositionVector)
    de_pv: ShortPositionVector = field(default_factory=ShortPositionVector)

    @classmethod
    def initialize_with_request_sequence_number_ego_pv_de_pv(
        cls,
        sequence_number: int,
        ego_pv: LongPositionVector,
        de_pv: ShortPositionVector,
    ) -> "GUCExtendedHeader":
        """
        Initialize the GUC Extended Header for a new outgoing GUC packet.

        Parameters
        ----------
        sequence_number : int
            The current local sequence number (clause 8.3).
        ego_pv : LongPositionVector
            The ego position vector (SO PV field, clause 8.2).
        de_pv : ShortPositionVector
            The destination Short Position Vector (DE PV field, clause 8.5 / LocT).
        """
        return cls(sn=sequence_number, so_pv=ego_pv, de_pv=de_pv)

    def with_de_pv(self, de_pv: ShortPositionVector) -> "GUCExtendedHeader":
        """Return a copy of this header with an updated DE PV (used by forwarder step 8)."""
        return GUCExtendedHeader(
            sn=self.sn,
            reserved=self.reserved,
            so_pv=self.so_pv,
            de_pv=de_pv,
        )

    def encode(self) -> bytes:
        """
        Encode the GUC Extended Header to bytes (48 bytes).

        Returns
        -------
        bytes
            Encoded bytes.
        """
        return (
            self.sn.to_bytes(2, "big")
            + self.reserved.to_bytes(2, "big")
            + self.so_pv.encode()
            + self.de_pv.encode()
        )

    @classmethod
    def decode(cls, header: bytes) -> "GUCExtendedHeader":
        """
        Decode the GUC Extended Header from bytes.

        Parameters
        ----------
        header : bytes
            48 bytes of the GUC Extended Header.

        Returns
        -------
        GUCExtendedHeader
            Decoded GUC Extended Header.

        Raises
        ------
        DecodeError
            If the header is too short.
        """
        if len(header) < 48:
            raise DecodeError(
                f"GUC Extended Header too short: expected 48 bytes, got {len(header)}")
        sn = int.from_bytes(header[0:2], "big")
        reserved = int.from_bytes(header[2:4], "big")
        so_pv = LongPositionVector.decode(header[4:28])
        de_pv = ShortPositionVector.decode(header[28:48])
        return cls(sn=sn, reserved=reserved, so_pv=so_pv, de_pv=de_pv)
