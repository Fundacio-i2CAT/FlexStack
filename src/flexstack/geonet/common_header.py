from __future__ import annotations
from dataclasses import dataclass, field
from .service_access_point import (
    CommonNH,
    HeaderType,
    HeaderSubType,
    TrafficClass,
    GNDataRequest,
    TopoBroadcastHST,
    GeoBroadcastHST,
    GeoAnycastHST,
    LocationServiceHST,
)
from .exceptions import DecodeError


@dataclass(frozen=True)
class CommonHeader:
    """
    Common Header class. As specified in ETSI EN 302 636-4-1 V1.4.1 (2020-01). Section 9.7

    Attributes
    ----------
    nh : CommonNH
        (2 bit unsigned integer) Next Header.
    reserved : int
        (4 bit unsigned integer) Reserved.
    ht : HeaderType
        (4 bit unsigned integer) Header Type (HT) Identifies the Type of Geonetworking Header.
    hst : Enum
        (4 bit unsigned integer) Header Subtype (HST) Identifies the Subtype of Geonetworking Header.
    tc : TrafficClass
        (8 bit unsigned integer) Traffic class that represents Facility-layer requirements on packet transport.
    flags : int
        (8 bit unsigned integer) Flags. Bit 0 Indicates whether the ITS-S is mobile or stationary
        (GN protocol constant itsGnIsMobile) Bit 1 to 7 Reserved.
    pl : int
        (16 bit unsigned integer) Payload Length. Indicates the length of the payload in octets.
    mhl : int
        (8 bit unsigned integer) Maximum Hop Limit. Indicates the maximum number of hops that
        the packet is allowed to traverse.
    reserved : int
        (8 bit unsigned integer) Reserved. Always set to zero.
    """

    nh: CommonNH = CommonNH.ANY
    reserved: int = 0
    ht: HeaderType = HeaderType.ANY
    hst: HeaderSubType = HeaderSubType.UNSPECIFIED
    tc: TrafficClass = field(default_factory=TrafficClass)
    flags: int = 0
    pl: int = 0
    mhl: int = 0

    @classmethod
    def initialize_with_request(cls, request: GNDataRequest) -> "CommonHeader":
        """
        Initializes the Common Header with a GNDataRequest.

        Parameters
        ----------
        request : GNDataRequest
            GNDataRequest to use.
        """
        nh = request.upper_protocol_entity
        ht = request.packet_transport_type.header_type
        hst = request.packet_transport_type.header_subtype
        tc = request.traffic_class
        pl = request.length
        if ht == HeaderType.TSB and hst == TopoBroadcastHST.SINGLE_HOP:
            mhl = 1
        else:
            # TODO: Set the maximum hop limit on other cases than SHB As specified in: Section 10.3.4 Table 20
            mhl = 1
        return cls(nh=nh, reserved=0, ht=ht, hst=hst, tc=tc, flags=0, pl=pl, mhl=mhl)  # type: ignore

    def encode_to_int(self) -> int:
        """
        Encodes the Common Header to an integer.

        Returns
        -------
        int :
            Encoded Common Header.  8 bytes.
        """
        return (
            (self.nh.value << (4 + 8 * 7))
            | (self.reserved << (8 * 7))
            | (self.ht.value << (4 + 8 * 6))
            | (self.hst.value << 8 * 6)
            | (self.tc.encode_to_int() << 8 * 5)
            | self.flags << 8 * 4
            | self.pl << 8 * 2
            | self.mhl << 8
            | self.reserved
        )

    def encode_to_bytes(self) -> bytes:
        """
        Encodes the Common Header to bytes.

        Returns
        -------
        bytes :
            Encoded Common Header. 4 bytes.
        """
        return self.encode_to_int().to_bytes(8, "big")

    @classmethod
    def decode_from_int(cls, header: int) -> "CommonHeader":
        """
        Decodes an integer to a Common Header.

        Parameters
        ----------
        header : int
            Encoded Common Header. 4 bytes.
        """
        nh = CommonNH((header >> (4 + 8 * 7)) & 15)
        ht = HeaderType((header >> (4 + 8 * 6)) & 15)
        if ht == HeaderType.GEOBROADCAST:
            hst = GeoBroadcastHST((header >> (8 * 6)) & 15)
        elif ht == HeaderType.TSB:
            hst = TopoBroadcastHST((header >> (8 * 6)) & 15)
        elif ht == HeaderType.GEOANYCAST:
            hst = GeoAnycastHST((header >> (8 * 6)) & 15)
        elif ht == HeaderType.LS:
            hst = LocationServiceHST((header >> (8 * 6)) & 15)
        else:
            hst = HeaderSubType((header >> (8 * 6)) & 15)
        tc = TrafficClass.decode_from_int((header >> 8 * 5) & 255)
        flags = (header >> 8 * 4) & 128
        pl = (header >> 8 * 2) & 65535
        mhl = (header >> 8) & 255
        reserved = header & 255
        # type: ignore
        return cls(nh=nh, reserved=reserved, ht=ht, hst=hst, tc=tc, flags=flags, pl=pl, mhl=mhl)  # type: ignore

    @classmethod
    def decode_from_bytes(cls, header: bytes) -> "CommonHeader":
        """
        Decodes bytes to a Common Header.

        Parameters
        ----------
        header : bytes
            Encoded Common Header. 8 bytes.
        """
        if len(header) < 8:
            raise DecodeError("Common Header must be 8 bytes long")
        return cls.decode_from_int(int.from_bytes(header[0:8], "big"))
