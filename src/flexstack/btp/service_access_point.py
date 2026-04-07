from base64 import b64encode, b64decode
from dataclasses import dataclass, field
from typing import Optional
from ..geonet.gn_address import GNAddress
from ..geonet.service_access_point import (
    Area,
    GNDataIndication,
    PacketTransportType,
    CommunicationProfile,
    TrafficClass,
    CommonNH,
)
from ..geonet.position_vector import LongPositionVector
from ..security.security_profiles import SecurityProfile


@dataclass(frozen=True)
class BTPDataRequest:
    """
    BTP Data Request class. As specified in
    ETSI EN 302 636-5-1 V2.2.1 (2019-05). Annex A.2

    Attributes
    ----------
    btp_type : CommonNH
        BTP Type (BTP-A for interactive, BTP-B for non-interactive transport).
    source_port : int
        (16 bit integer) Source Port. Optional; only used for BTP-A.
    destination_port : int
        (16 bit integer) Destination Port.
    destination_port_info : int
        (16 bit integer) Destination Port Info. Optional; only used for BTP-B.
    gn_packet_transport_type : PacketTransportType
        GN Packet Transport Type (GeoUnicast, SHB, TSB, GeoBroadcast, GeoAnycast).
    gn_destination_address : GNAddress
        GN Destination Address. Used for GeoUnicast or geographical area for
        GeoBroadcast/GeoAnycast.
    gn_area : Area
        GN Area for GeoBroadcast/GeoAnycast transport.
    gn_max_hop_limit : int
        GN Maximum Hop Limit. Optional; specifies the number of hops a packet
        is allowed to have in the network.
    gn_max_packet_lifetime : float or None
        GN Maximum Packet Lifetime in seconds. Optional; specifies the maximum
        tolerable time a GeoNetworking packet can be buffered until it reaches
        its destination.
    gn_repetition_interval : int or None
        GN Repetition Interval in milliseconds. Optional; specifies the duration
        between two consecutive transmissions of the same packet during the
        maximum repetition time.
    gn_max_repetition_time : int or None
        GN Maximum Repetition Time in milliseconds. Optional; specifies the
        duration for which the packet will be repeated if the repetition
        interval is set.
    communication_profile : CommunicationProfile
        GN Communication Profile; determines the LL protocol entity.
    traffic_class : TrafficClass
        GN Traffic Class.
    security_profile : SecurityProfile
        Security profile to apply when the GN router signs the packet.
        Defaults to :attr:`SecurityProfile.NO_SECURITY` (no signing).
    its_aid : int
        ITS-AID (PSID) of the service carried in this packet, used by the
        GN router to select the correct signing certificate.  Only relevant
        when *security_profile* is not ``NO_SECURITY``.
    security_permissions : bytes
        Sender permissions forwarded to the sign service.  Only relevant
        when *security_profile* is not ``NO_SECURITY``.
    length : int
        Length of the payload.
    data : bytes
        Payload.
    """

    btp_type: CommonNH = CommonNH.BTP_B
    source_port: int = 0
    destination_port: int = 0
    destination_port_info: int = 0
    gn_packet_transport_type: PacketTransportType = field(
        default_factory=PacketTransportType)
    gn_destination_address: GNAddress = field(default_factory=GNAddress)
    gn_area: Area = field(default_factory=Area)
    gn_max_hop_limit: int = 0
    gn_max_packet_lifetime: Optional[float] = None
    gn_repetition_interval: Optional[int] = None
    gn_max_repetition_time: Optional[int] = None
    communication_profile: CommunicationProfile = CommunicationProfile.UNSPECIFIED
    traffic_class: TrafficClass = field(default_factory=TrafficClass)
    security_profile: SecurityProfile = SecurityProfile.NO_SECURITY
    its_aid: int = 0
    security_permissions: bytes = b"\x00"
    length: int = 0
    data: bytes = b""

    def to_dict(self) -> dict:
        """
        Returns the BTPDataRequest as a dictionary.

        Returns
        -------
        dict
            Dictionary representation of the BTPDataRequest.
        """
        return {
            "btp_type": self.btp_type.value,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "destination_port_info": self.destination_port_info,
            "gn_packet_transport_type": self.gn_packet_transport_type.to_dict(),
            "gn_destination_address": b64encode(
                self.gn_destination_address.encode()
            ).decode("utf-8"),
            "gn_area": self.gn_area.to_dict(),
            "gn_max_packet_lifetime": self.gn_max_packet_lifetime,
            "gn_repetition_interval": self.gn_repetition_interval,
            "gn_max_repetition_time": self.gn_max_repetition_time,
            "communication_profile": self.communication_profile.value,
            "traffic_class": b64encode(self.traffic_class.encode_to_bytes()).decode(
                "utf-8"
            ),
            "length": self.length,
            "data": b64encode(self.data).decode("utf-8"),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "BTPDataRequest":
        """
        Construct a BTPDataRequest from a dictionary.

        Parameters
        ----------
        data : dict
            Dictionary to construct from.
        """
        btp_type = CommonNH(
            data["btp_type"]) if "btp_type" in data else CommonNH.BTP_B
        source_port = data.get("source_port", 0)
        destination_port = data.get("destination_port", 0)
        destination_port_info = data.get("destination_port_info", 0)
        packet_transport_type = PacketTransportType.from_dict(
            data.get("gn_packet_transport_type", {}))
        gn_dest_b64 = data.get("gn_destination_address")
        if gn_dest_b64:
            gn_destination_address = GNAddress.decode(b64decode(gn_dest_b64))
        else:
            gn_destination_address = GNAddress()
        area = Area.from_dict(data.get("gn_area", {})
                              ) if data.get("gn_area") else Area()
        communication_profile = CommunicationProfile(
            data.get("communication_profile", CommunicationProfile.UNSPECIFIED.value))
        traffic_class_b64 = data.get("traffic_class")
        if traffic_class_b64:
            traffic_class = TrafficClass.decode_from_bytes(
                b64decode(traffic_class_b64))
        else:
            traffic_class = TrafficClass()
        length = data.get("length", 0)
        data_b64 = data.get("data")
        payload = b64decode(data_b64) if data_b64 else b""
        return cls(
            btp_type=btp_type,
            source_port=source_port,
            destination_port=destination_port,
            destination_port_info=destination_port_info,
            gn_packet_transport_type=packet_transport_type,
            gn_destination_address=gn_destination_address,
            gn_area=area,
            gn_max_hop_limit=data.get("gn_max_hop_limit", 1),
            gn_max_packet_lifetime=data.get("gn_max_packet_lifetime"),
            gn_repetition_interval=data.get("gn_repetition_interval"),
            gn_max_repetition_time=data.get("gn_max_repetition_time"),
            communication_profile=communication_profile,
            traffic_class=traffic_class,
            length=length,
            data=payload,
        )


@dataclass(frozen=True)
class BTPDataIndication:
    """
    BTP Data Indication class. As specified in ETSI EN 302 636-5-1 V2.2.1 (2019-05). Annex A.3

    Attributes
    ----------
    source_port : int
        (16 bit integer) Source Port. Optional; only present for BTP-A.
    destination_port : int
        (16 bit integer) Destination Port.
    destination_port_info : int
        (16 bit integer) Destination Port Info. Optional; only present for BTP-B.
    gn_packet_transport_type : PacketTransportType
        GN Packet Transport Type.
    gn_destination_address : GNAddress
        GN Destination Address for GeoUnicast or geographical area for
        GeoBroadcast/GeoAnycast, as generated by the source.
    gn_source_position_vector : LongPositionVector
        GN Source Position Vector; geographical position of the source.
    gn_security_report : bytes or None
        GN Security Report. Optional; result of the security processing of
        the received packet.
    gn_certificate_id : bytes or None
        GN Certificate Id. Optional; identifier of the certificate used by
        the sender.
    gn_permissions : bytes or None
        GN Permissions. Optional; permissions from the sender's certificate.
    gn_traffic_class : TrafficClass
        GN Traffic Class.
    gn_remaining_packet_lifetime : float or None
        GN Remaining Packet Lifetime in seconds. Optional.
    length : int
        Length of the payload.
    data : bytes
        Payload.
    """

    source_port: int = 0
    destination_port: int = 0
    destination_port_info: int = 0
    gn_packet_transport_type: PacketTransportType = field(
        default_factory=PacketTransportType)
    gn_destination_address: GNAddress = field(default_factory=GNAddress)
    gn_source_position_vector: LongPositionVector = field(
        default_factory=LongPositionVector)
    gn_security_report: Optional[bytes] = None
    gn_certificate_id: Optional[bytes] = None
    gn_permissions: Optional[bytes] = None
    gn_traffic_class: TrafficClass = field(default_factory=TrafficClass)
    gn_remaining_packet_lifetime: Optional[float] = None
    length: int = 0
    data: bytes = b""

    @classmethod
    def initialize_with_gn_data_indication(cls, gn_data_indication: GNDataIndication) -> "BTPDataIndication":
        """
        Construct a BTPDataIndication from a GNDataIndication.

        Parameters
        ----------
        gn_data_indication : GNDataIndication
            GNDataIndication to construct from.
        """
        payload = gn_data_indication.data[4:]
        return cls(
            gn_packet_transport_type=gn_data_indication.packet_transport_type,
            gn_source_position_vector=gn_data_indication.source_position_vector,
            gn_traffic_class=gn_data_indication.traffic_class,
            length=len(payload),
            data=payload,
        )

    def set_destination_port_and_info(self, destination_port: int, destination_port_info: int) -> "BTPDataIndication":
        """
        Sets the destination port and destination port info.

        Parameters
        ----------
        destination_port : int
            Destination port to set.
        destination_port_info : int
            Destination port info to set.

        Returns
        -------
        BTPDataIndication
            New BTPDataIndication with updated destination port and info.
        """
        return BTPDataIndication(
            source_port=self.source_port,
            destination_port=destination_port,
            destination_port_info=destination_port_info,
            gn_packet_transport_type=self.gn_packet_transport_type,
            gn_destination_address=self.gn_destination_address,
            gn_source_position_vector=self.gn_source_position_vector,
            gn_security_report=self.gn_security_report,
            gn_certificate_id=self.gn_certificate_id,
            gn_permissions=self.gn_permissions,
            gn_traffic_class=self.gn_traffic_class,
            gn_remaining_packet_lifetime=self.gn_remaining_packet_lifetime,
            length=self.length,
            data=self.data,
        )

    def to_dict(self) -> dict:
        """
        Returns the BTPDataIndication as a dictionary.

        Returns
        -------
        dict
            Dictionary representation of the BTPDataIndication.
        """
        return {
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "destination_port_info": self.destination_port_info,
            "gn_packet_transport_type": self.gn_packet_transport_type.to_dict(),
            "gn_destination_address": b64encode(
                self.gn_destination_address.encode()
            ).decode("utf-8"),
            "gn_source_position_vector": b64encode(
                self.gn_source_position_vector.encode()
            ).decode("utf-8"),
            "gn_security_report": b64encode(self.gn_security_report).decode("utf-8") if self.gn_security_report is not None else None,
            "gn_certificate_id": b64encode(self.gn_certificate_id).decode("utf-8") if self.gn_certificate_id is not None else None,
            "gn_permissions": b64encode(self.gn_permissions).decode("utf-8") if self.gn_permissions is not None else None,
            "gn_traffic_class": b64encode(
                self.gn_traffic_class.encode_to_bytes()
            ).decode("utf-8"),
            "gn_remaining_packet_lifetime": self.gn_remaining_packet_lifetime,
            "length": self.length,
            "data": b64encode(self.data).decode("utf-8"),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "BTPDataIndication":
        """
        Construct a BTPDataIndication from a dictionary.

        Parameters
        ----------
        data : dict
            Dictionary to construct from.
        """
        source_port = data.get("source_port", 0)
        destination_port = data.get("destination_port", 0)
        destination_port_info = data.get(
            "destination_port_info", data.get("destination_port_info", 0))
        packet_transport_type = PacketTransportType.from_dict(
            data.get("gn_packet_transport_type", {}))
        gn_dest_b64 = data.get("gn_destination_address")
        if gn_dest_b64:
            gn_destination_address = GNAddress.decode(b64decode(gn_dest_b64))
        else:
            gn_destination_address = GNAddress()
        spv_b64 = data.get("gn_source_position_vector")
        if spv_b64:
            source_position_vector = LongPositionVector.decode(
                b64decode(spv_b64))
        else:
            source_position_vector = LongPositionVector()
        traffic_b64 = data.get("gn_traffic_class")
        if traffic_b64:
            gn_traffic_class = TrafficClass.decode_from_bytes(
                b64decode(traffic_b64))
        else:
            gn_traffic_class = TrafficClass()
        security_report_b64 = data.get("gn_security_report")
        gn_security_report = b64decode(security_report_b64) if security_report_b64 is not None else None
        certificate_id_b64 = data.get("gn_certificate_id")
        gn_certificate_id = b64decode(certificate_id_b64) if certificate_id_b64 is not None else None
        permissions_b64 = data.get("gn_permissions")
        gn_permissions = b64decode(permissions_b64) if permissions_b64 is not None else None
        gn_remaining_packet_lifetime = data.get("gn_remaining_packet_lifetime")
        length = data.get("length", 0)
        data_b64 = data.get("data")
        payload = b64decode(data_b64) if data_b64 else b""
        return cls(
            source_port=source_port,
            destination_port=destination_port,
            destination_port_info=destination_port_info,
            gn_packet_transport_type=packet_transport_type,
            gn_destination_address=gn_destination_address,
            gn_source_position_vector=source_position_vector,
            gn_security_report=gn_security_report,
            gn_certificate_id=gn_certificate_id,
            gn_permissions=gn_permissions,
            gn_traffic_class=gn_traffic_class,
            gn_remaining_packet_lifetime=gn_remaining_packet_lifetime,
            length=length,
            data=payload,
        )
