from enum import Enum
from base64 import b64encode, b64decode
from dataclasses import dataclass, field
from typing import Any
from .position_vector import LongPositionVector
from ..security.security_profiles import SecurityProfile


class CommonNH(Enum):
    """
    Common Next Header class. As specified in ETSI EN 302 636-4-1 V1.4.1 (2020-01). Section 9.7

    Attributes
    ----------
    ANY :
        Any Next Header.
    BTP-A :
        BTP-A Next Header.
    BTP-B :
        BTP-B Next Header.
    IPV6 :
        IPv6 Next Header.
    """

    ANY = 0
    BTP_A = 1
    BTP_B = 2
    IPV6 = 3


class HeaderType(Enum):
    """
    Header Type class. As specified in ETSI EN 302 636-4-1 V1.4.1 (2020-01). Section 9.7.4

    Attributes
    ----------
    ANY :
        Any Header Type.
    BEACON :
        Beacon Header Type.
    GEOUNICAST :
        GeoUnicast Header Type.
    GEOANYCAST :
        Geographically-Scoped Anycast (GAC) Header Type.
    GEOBROADCAST :
        Geographically-Scoped broadcast (GBC)  Header Type.
    TSB :
        Topologically-scoped broadcast (TSB) Header Type.
    LS :
        Location Service Header Type.
    """

    ANY = 0
    BEACON = 1
    GEOUNICAST = 2
    GEOANYCAST = 3
    GEOBROADCAST = 4
    TSB = 5
    LS = 6


class HeaderSubType(Enum):
    """
    Common Header Subtype class. As specified in ETSI EN 302 636-4-1 V1.4.1 (2020-01).
    Section 9.7.5
    """

    UNSPECIFIED = 0


class GeoAnycastHST(Enum):
    """
    Geographically-Scoped Anycast (GAC) Header Subtype class. As specified in
    ETSI EN 302 636-4-1 V1.4.1 (2020-01). Section 9.7.4

    Attributes
    ----------
    GEOANYCAST_CIRCLE :
        Geographically-Scoped Anycast (GAC) Circle Header Subtype.
    GEOANYCAST_RECT :
        Geographically-Scoped Anycast (GAC) Rectangle Header Subtype.
    GEOANYCAST_ELIP :
        Geographically-Scoped Anycast (GAC) Ellipse Header Subtype.
    """

    GEOANYCAST_CIRCLE = 0
    GEOANYCAST_RECT = 1
    GEOANYCAST_ELIP = 2


class GeoBroadcastHST(Enum):
    """
    Geographically-Scoped broadcast (GBC) Header Subtype class.
    As specified in ETSI EN 302 636-4-1 V1.4.1 (2020-01).
    Section 9.7.4

    Attributes
    ----------
    GEOBROADCAST_CIRCLE :
        Geographically-Scoped broadcast (GBC) Circle Header Subtype.
    GEOBROADCAST_RECT :
        Geographically-Scoped broadcast (GBC) Rectangle Header Subtype.
    GEOBROADCAST_ELIP :
        Geographically-Scoped broadcast (GBC) Ellipse Header Subtype.
    """

    GEOBROADCAST_CIRCLE = 0
    GEOBROADCAST_RECT = 1
    GEOBROADCAST_ELIP = 2


class TopoBroadcastHST(Enum):
    """
    Topologically-scoped broadcast (TSB) Header Subtype class. As specified in ETSI EN 302 636-4-1 V1.4.1 (2020-01).
    Section 9.7.4

    Attributes
    ----------
    SINGLE_HOP :
        Single Hop Header Subtype.
    MULTI_HOP :
        Multi Hop Header Subtype.
    """

    SINGLE_HOP = 0
    MULTI_HOP = 1


class LocationServiceHST(Enum):
    """
    Location Service Header Subtype class. As specified in ETSI EN 302 636-4-1 V1.4.1 (2020-01). Section 9.7.4

    Attributes
    ----------
    LS_REQUEST :
        Location Service Request Header Subtype.
    LS_REPLY :
        Location Service Reply Header Subtype.
    """

    LS_REQUEST = 0
    LS_REPLY = 1


@dataclass(frozen=True)
class TrafficClass:
    """
    Common Traffic class class. As specified in ETSI EN 302 636-4-1 V1.4.1 (2020-01). Section 9.7.5

    Attributes
    ----------
    scf : bool
        (1 bit) Store Carry Forward (SCF) flag. Indicates whether the packet shall be buffered when no suitable
        neighbour exists
    channel_offload : bool
        (1 bit) Channel Offload flag. Indicates whether the packet may be offloaded to another channel than
        specified in the TC ID
    tc_id : int
        (6 bit unsigned integer) Traffic class identifier. TC ID as specified in the media-dependent part of
        GeoNetworking corresponding to the interface over which the packet will be transmitted
    """

    scf: bool = False
    channel_offload: bool = False
    tc_id: int = 0

    def set_scf(self, scf: bool) -> "TrafficClass":
        """
        Set the SCF flag.

        Parameters
        ----------
        scf : bool
            SCF flag.
        """
        return TrafficClass(scf=scf, channel_offload=self.channel_offload, tc_id=self.tc_id)

    def set_tc_id(self, tc_id: int) -> "TrafficClass":
        """
        Set the traffic class identifier.

        Parameters
        ----------
        tc_id : int
            Traffic class identifier.
        """
        if tc_id < 0 or tc_id > 63:
            raise ValueError(
                "Traffic class identifier must be between 0 and 63")
        return TrafficClass(scf=self.scf, channel_offload=self.channel_offload, tc_id=tc_id)

    def set_channel_offload(self, channel_offload: bool) -> "TrafficClass":
        """
        Set the channel offload flag.

        Parameters
        ----------
        channel_offload : bool
            Channel offload flag.
        """
        return TrafficClass(scf=self.scf, channel_offload=channel_offload, tc_id=self.tc_id)

    def encode_to_int(self) -> int:
        """
        Encodes the traffic class to an integer.

        Returns
        -------
        int :
            Encoded traffic class. 1 byte.
        """
        return (self.scf << 7) | (self.channel_offload << 6) | self.tc_id

    def encode_to_bytes(self) -> bytes:
        """
        Encodes the traffic class to bytes.

        Returns
        -------
        bytes :
            Encoded traffic class. 1 byte.
        """
        return self.encode_to_int().to_bytes(1, "big")

    @classmethod
    def decode_from_int(cls, tc: int) -> "TrafficClass":
        """
        Decodes the traffic class from an integer.

        Parameters
        ----------
        tc : int
            Encoded traffic class. 1 byte.
        """
        scf = bool((tc >> 7) & 1)
        channel_offload = bool((tc >> 6) & 1)
        tc_id = tc & 63
        return cls(scf=scf, channel_offload=channel_offload, tc_id=tc_id)

    @classmethod
    def decode_from_bytes(cls, tc: bytes) -> "TrafficClass":
        """
        Decodes the traffic class from a byte array.

        Parameters
        ----------
        tc : bytes
            Byte array containing the traffic class.
        """
        return cls.decode_from_int(int.from_bytes(tc, "big"))


@dataclass(frozen=True)
class PacketTransportType:
    """
    Packet Transport Type class. As specified in ETSI EN 302 636-4-1 V1.4.1 (2020-01). Annex J2
    Uses the Header Type and Header Subtype fields from the Common Header. As specified in ETSI EN 302 636-4-1 V1.4.1
    (2020-01). Section 9.7.4 Table 9

    Attributes
    ----------
    header_type : HeaderType
        Header Type.
    header_subtype : Enum
        Header Subtype.
    """

    header_type: HeaderType = HeaderType.TSB
    header_subtype: Any = TopoBroadcastHST.SINGLE_HOP

    def to_dict(self) -> dict:
        """
        Returns a dictionary representation of the Packet Transport Type.

        Returns
        -------
        dict :
            Dictionary representation of the Packet Transport Type.
        """
        return {
            "header_type": self.header_type.value,
            "header_subtype": self.header_subtype.value,
        }

    @classmethod
    def from_dict(cls, packet_transport_type: dict) -> "PacketTransportType":
        """
        Initialize the Packet Transport Type from a dictionary.

        Parameters
        ----------
        packet_transport_type : dict
            Dictionary containing the Packet Transport Type.
        """
        header_type = HeaderType(packet_transport_type["header_type"])
        if header_type == HeaderType.GEOANYCAST:
            header_subtype = GeoAnycastHST(
                packet_transport_type["header_subtype"])
        elif header_type == HeaderType.GEOBROADCAST:
            header_subtype = GeoBroadcastHST(
                packet_transport_type["header_subtype"])
        elif header_type == HeaderType.TSB:
            header_subtype = TopoBroadcastHST(
                packet_transport_type["header_subtype"])
        elif header_type == HeaderType.LS:
            header_subtype = LocationServiceHST(
                packet_transport_type["header_subtype"])
        else:
            header_subtype = HeaderSubType(
                packet_transport_type["header_subtype"])
        return cls(header_type=header_type, header_subtype=header_subtype)


class CommunicationProfile(Enum):
    """
    Communication Profile class. As specified in ETSI EN 302 636-4-1 V1.4.1 (2020-01). Annex J2

    Attributes
    ----------
    UNSPECIFIED (0) :
        Unspecified
    """

    UNSPECIFIED = 0


@dataclass(frozen=True)
class Area:
    """
    Area class. Not specified in the standard


    Attributes
    ----------
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
    """

    latitude: int = 0
    longitude: int = 0
    a: int = 0
    b: int = 0
    angle: int = 0

    def to_dict(self) -> dict:
        """
        Returns a dictionary representation of the Area.

        Returns
        -------
        dict :
            Dictionary representation of the Area.
        """
        return {
            "latitude": self.latitude,
            "longitude": self.longitude,
            "a": self.a,
            "b": self.b,
            "angle": self.angle,
        }

    @classmethod
    def from_dict(cls, area: dict) -> "Area":
        return cls(
            latitude=area["latitude"],
            longitude=area["longitude"],
            a=area["a"],
            b=area["b"],
            angle=area["angle"],
        )


@dataclass(frozen=True)
class GNDataRequest:
    """
    GN Data Request class. As specified in ETSI EN 302 636-4-1 V1.4.1 (2020-01). Annex J2.2


    Attributes
    ----------
    upper_protocol_entity : CommonNH
        Upper Protocol Entity.
    packet_transport_type : PacketTransportType
        Packet Transport Type.
    communication_profile : CommunicationProfile
        Communication Profile.
    security_profile : SecurityProfile
        Security Profile.
    its_aid : int
        ITS AID.
    security_permissions : bytes
        Security Permissions.
    traffic_class : TrafficClass
        Traffic Class.
    length : int
        Length of the payload.
    data : bytes
        Payload.
    area : Area
        Area of the GBC algorithm. Only used when the packet transport type is GBC.

    THIS CLASS WILL BE EXTENDED WHEN FURTHER PACKET TYPES ARE IMPLEMENTED
    """

    upper_protocol_entity: CommonNH = CommonNH.ANY
    packet_transport_type: PacketTransportType = field(
        default_factory=PacketTransportType)
    communication_profile: CommunicationProfile = CommunicationProfile.UNSPECIFIED
    security_profile: SecurityProfile = SecurityProfile.NO_SECURITY
    its_aid: int = 0
    security_permissions: bytes = b"\x00"
    traffic_class: TrafficClass = field(default_factory=TrafficClass)
    length: int = 0
    data: bytes = b""
    area: Area = field(default_factory=Area)

    def to_dict(self) -> dict:
        """
        Returns a dictionary representation of the GN Data Request.

        Returns
        -------
        dict :
            Dictionary representation of the GN Data Request.
        """
        return {
            "upper_protocol_entity": self.upper_protocol_entity.value,
            "packet_transport_type": self.packet_transport_type.to_dict(),
            "communication_profile": self.communication_profile.value,
            "traffic_class": b64encode(self.traffic_class.encode_to_bytes()).decode(
                "utf-8"
            ),
            "length": self.length,
            "data": b64encode(self.data).decode("utf-8"),
            "area": self.area.to_dict(),
        }

    @classmethod
    def from_dict(cls, gn_data_request: dict) -> "GNDataRequest":
        """
        Initialize the GN Data Request from a dictionary.

        Parameters
        ----------
        gn_data_request : dict
            Dictionary containing the GN Data Request.
        """
        upper_protocol_entity = CommonNH(
            gn_data_request["upper_protocol_entity"])
        packet_transport_type = PacketTransportType.from_dict(
            gn_data_request["packet_transport_type"]
        )
        communication_profile = CommunicationProfile(
            gn_data_request["communication_profile"]
        )
        traffic_class = TrafficClass.decode_from_bytes(
            b64decode(gn_data_request["traffic_class"])
        )
        length = gn_data_request["length"]
        data = b64decode(gn_data_request["data"])
        area = Area.from_dict(gn_data_request["area"])
        return cls(
            upper_protocol_entity=upper_protocol_entity,
            packet_transport_type=packet_transport_type,
            communication_profile=communication_profile,
            traffic_class=traffic_class,
            length=length,
            data=data,
            area=area,
        )


class ResultCode(Enum):
    """
    Result Code class. As specified in ETSI EN 302 636-4-1 V1.4.1 (2020-01). Annex J3

    Attributes
    ----------
    ACCEPTED (1) :
        Accepted
    MAXIMUM_LENGTH_EXCEEDED (2) :
        The size of the T/GN6-PDU exceeds the GN protocol constant itsGnMaxSduSize;
    MAXIMUM_LIFETIME_EXCEEDED (3) :
        The lifetime exceeds the maximum value of the GN protocol constant itsGnMaxPacketLifetime;
    REPETITION_INTERVAL_TOO_SMALL (4) :
        The repetition interval is too small;
    UNSUPPORTED_TRAFFIC_CLASS (5) :
        The traffic class is not supported;
    GEOGRAPHICAL_SCOPE_TOO_LARGE (6) :
        The geographical scope is too large;
    UNSPECIFIED (7) :
        Unspecified
    """

    ACCEPTED = 1
    MAXIMUM_LENGTH_EXCEEDED = 2
    MAXIMUM_LIFETIME_EXCEEDED = 3
    REPETITION_INTERVAL_TOO_SMALL = 4
    UNSUPPORTED_TRAFFIC_CLASS = 5
    GEOGRAPHICAL_SCOPE_TOO_LARGE = 6
    UNSPECIFIED = 7


@dataclass(frozen=True)
class GNDataConfirm:
    """
    GN Data Confirm class. As specified in ETSI EN 302 636-4-1 V1.4.1 (2020-01). Annex J3

    Attributes
    ----------
    result_code : ResultCode
        Result Code.

    """

    result_code: ResultCode = ResultCode.UNSPECIFIED


@dataclass(frozen=True)
class GNDataIndication:
    """
    GN Data Indication class. As specified in ETSI EN 302 636-4-1 V1.4.1 (2020-01). Annex J4

    Attributes
    ----------
    upper_protocol_entity : CommonNH
        Upper Protocol Entity.
    packet_transport_type : PacketTransportType
        Packet Transport Type.
    source_position_vector : LongPositionVector
        Source Position Vector.
    traffic_class : TrafficClass
        Traffic Class.
    length : int
        Length of the payload.
    data : bytes
        Payload.
    """

    upper_protocol_entity: CommonNH = CommonNH.ANY
    packet_transport_type: PacketTransportType = field(
        default_factory=PacketTransportType)
    source_position_vector: LongPositionVector = field(
        default_factory=LongPositionVector)
    traffic_class: TrafficClass = field(default_factory=TrafficClass)
    length: int = 0
    data: bytes = b""

    def to_dict(self) -> dict:
        """
        Returns a dictionary representation of the GN Data Indication.

        Returns
        -------
        dict :
            Dictionary representation of the GN Data Indication.
        """
        return {
            "upper_protocol_entity": self.upper_protocol_entity.value,
            "packet_transport_type": self.packet_transport_type.to_dict(),
            "source_position_vector": b64encode(
                self.source_position_vector.encode()
            ).decode("utf-8"),
            "traffic_class": b64encode(self.traffic_class.encode_to_bytes()).decode(
                "utf-8"
            ),
            "length": self.length,
            "data": b64encode(self.data).decode("utf-8"),
        }

    @classmethod
    def from_dict(cls, gn_data_indication: dict) -> "GNDataIndication":
        """
        Initialize the GN Data Indication from a dictionary.

        Parameters
        ----------
        gn_data_indication : dict
            Dictionary containing the GN Data Indication.
        """
        upper_protocol_entity = CommonNH(
            gn_data_indication["upper_protocol_entity"])
        packet_transport_type = PacketTransportType.from_dict(
            gn_data_indication["packet_transport_type"]
        )
        source_position_vector = LongPositionVector.decode(
            b64decode(gn_data_indication["source_position_vector"])
        )
        traffic_class = TrafficClass.decode_from_bytes(
            b64decode(gn_data_indication["traffic_class"])
        )
        length = gn_data_indication["length"]
        data = b64decode(gn_data_indication["data"])
        return cls(
            upper_protocol_entity=upper_protocol_entity,
            packet_transport_type=packet_transport_type,
            source_position_vector=source_position_vector,
            traffic_class=traffic_class,
            length=length,
            data=data,
        )
