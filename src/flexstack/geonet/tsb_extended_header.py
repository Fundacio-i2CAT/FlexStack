from dataclasses import dataclass, field
from .exceptions import DecodeError
from .position_vector import LongPositionVector
from .service_access_point import GNDataRequest


@dataclass(frozen=True)
class TSBExtendedHeader:
    """
    TSB Extended Header class. As specified in ETSI EN 302 636-4-1 V1.4.1 (2020-01). Section 9.8.3 (Table 12).

    Layout (28 bytes):
        SN         2 octets  (octets 12-13 of full TSB packet)
        Reserved   2 octets  (octets 14-15)
        SO PV     24 octets  (octets 16-39)

    Attributes
    ----------
    sn : int
        Sequence number (16-bit unsigned).
    reserved : int
        Reserved. Set to 0.
    so_pv : LongPositionVector
        Source Long Position Vector.
    """

    sn: int = 0
    reserved: int = 0
    so_pv: LongPositionVector = field(default_factory=LongPositionVector)

    @classmethod
    def initialize_with_request_sequence_number_ego_pv(
        cls,
        request: GNDataRequest,  # noqa: ARG003  (kept for API symmetry with GBCExtendedHeader)
        sequence_number: int,
        ego_pv: LongPositionVector,
    ) -> "TSBExtendedHeader":
        """
        Initialize the TSB Extended Header for a new outgoing TSB packet.

        Parameters
        ----------
        request : GNDataRequest
            The GN Data Request (unused for TSB but kept for API symmetry).
        sequence_number : int
            The current local sequence number (clause 8.3).
        ego_pv : LongPositionVector
            The ego position vector.
        """
        return cls(sn=sequence_number, so_pv=ego_pv)

    def encode(self) -> bytes:
        """
        Encode the TSB Extended Header to bytes (28 bytes).

        Returns
        -------
        bytes
            Encoded bytes.
        """
        return (
            self.sn.to_bytes(2, "big")
            + self.reserved.to_bytes(2, "big")
            + self.so_pv.encode()
        )

    @classmethod
    def decode(cls, header: bytes) -> "TSBExtendedHeader":
        """
        Decode the TSB Extended Header from bytes.

        Parameters
        ----------
        header : bytes
            28 bytes of the TSB Extended Header.

        Returns
        -------
        TSBExtendedHeader
            Decoded TSB Extended Header.

        Raises
        ------
        DecodeError
            If the header is too short.
        """
        if len(header) < 28:
            raise DecodeError(
                f"TSB Extended Header too short: expected 28 bytes, got {len(header)}")
        sn = int.from_bytes(header[0:2], "big")
        reserved = int.from_bytes(header[2:4], "big")
        so_pv = LongPositionVector.decode(header[4:28])
        return cls(sn=sn, reserved=reserved, so_pv=so_pv)
