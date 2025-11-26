from dataclasses import dataclass, field
from .exceptions import DecodeError
from .position_vector import LongPositionVector
from .service_access_point import GNDataRequest


@dataclass(frozen=True)
class GBCExtendedHeader:
    """
    GBC Extended Header class. As specified in ETSI EN 302 636-4-1 V1.4.1 (2020-01). Section 9.8 (Table 14 & Table 36)

    Attributes
    ----------
    sn : int
        Sequence number.
    reserved : int
        Reserved. All bits set to zero.
    so_pv : LongPositionVector
        Source Long Position Vector.
    latitude : int
        Latitude of the center of the area. In 1/10 micro degree.
    longitude : int
        Longitude of the center of the area. In 1/10 micro degree.
    a : int
        Length of the semi-major axis. In meters.
    b : int
        Length of the semi-minor axis. In meters.
    angle : int
        In degrees from North
    reserved2 : int
        Reserved. All bits set to zero.
    """

    sn: int = 0
    reserved: int = 0
    so_pv: LongPositionVector = field(default_factory=LongPositionVector)
    latitude: int = 0
    longitude: int = 0
    a: int = 0
    b: int = 0
    angle: int = 0
    reserved2: int = 0

    @classmethod
    def initialize_with_request_sequence_number_ego_pv(cls, request: GNDataRequest, sequence_number: int, ego_pv: LongPositionVector) -> "GBCExtendedHeader":
        """
        Initialize the GBC Extended Header with a GN Data Request, sequence number, and ego position vector.

        Parameters
        ----------
        request : GNDataRequest
            The GN Data Request.
        sequence_number : int
            The sequence number.
        ego_pv : LongPositionVector
            The ego position vector.

        Returns
        -------
        GBCExtendedHeader
            GeoBroadcast Extended Header.
        """
        return cls(
            sn=sequence_number,
            so_pv=ego_pv,
            latitude=request.area.latitude,
            longitude=request.area.longitude,
            a=request.area.a,
            b=request.area.b,
            angle=request.area.angle,
        )

    @classmethod
    def initialize_with_request(cls, request: GNDataRequest) -> "GBCExtendedHeader":
        """
        Initialize the GBC Extended Header with a GN Data Request.

        Parameters
        ----------
        request : GNDataRequest
            The GN Data Request.

        Returns
        -------
        GBCExtendedHeader
            GeoBroadcast Extended Header.
        """
        latitude = request.area.latitude
        longitude = request.area.longitude
        a = request.area.a
        b = request.area.b
        angle = request.area.angle
        return cls(latitude=latitude, longitude=longitude, a=a, b=b, angle=angle)

    def encode(self) -> bytes:
        """
        Encode the GBC Extended Header to bytes.

        Returns
        -------
        bytes
            The encoded bytes.
        """
        return (
            self.sn.to_bytes(2, "big")
            + self.reserved.to_bytes(2, "big")
            + self.so_pv.encode()
            + self.latitude.to_bytes(4, "big")
            + self.longitude.to_bytes(4, "big")
            + self.a.to_bytes(2, "big")
            + self.b.to_bytes(2, "big")
            + self.angle.to_bytes(2, "big")
            + self.reserved2.to_bytes(2, "big")
        )

    @classmethod
    def decode(cls, header: bytes) -> "GBCExtendedHeader":
        """
        Decode the GBC Extended Header from bytes.

        Parameters
        ----------
        header : bytes
            The header bytes.

        Raises
        ------
        DecodeError
            If the header is not 44 bytes long.
        """
        if len(header) < 44:
            raise DecodeError("GBC Extended Header must be 44 bytes long")
        sn = int.from_bytes(header[0:2], "big")
        reserved = int.from_bytes(header[2:4], "big")
        so_pv = LongPositionVector.decode(header[4:28])
        latitude = int.from_bytes(header[28:32], "big")
        longitude = int.from_bytes(header[32:36], "big")
        a = int.from_bytes(header[36:38], "big")
        b = int.from_bytes(header[38:40], "big")
        angle = int.from_bytes(header[40:42], "big")
        reserved2 = int.from_bytes(header[42:44], "big")
        return cls(sn=sn, reserved=reserved, so_pv=so_pv, latitude=latitude, longitude=longitude, a=a, b=b, angle=angle, reserved2=reserved2)

    def __str__(self) -> str:
        return (
            "GBC Extended Header"
            + "\n"
            + "Sequence number: "
            + str(self.sn)
            + "\n"
            + "Reserved: "
            + str(self.reserved)
            + "\n"
            + "Source Long Position Vector: \n"
            + str(self.so_pv)
            + "\n"
            + "Latitude: "
            + str(self.latitude)
            + "\n"
            + "Longitude: "
            + str(self.longitude)
            + "\n"
            + "Length of the semi-major axis: "
            + str(self.a)
            + "\n"
            + "Length of the semi-minor axis: "
            + str(self.b)
            + "\n"
            + "Angle: "
            + str(self.angle)
            + "\n"
            + "Reserved: "
            + str(self.reserved2)
            + "\n"
        )
