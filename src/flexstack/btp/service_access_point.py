from base64 import b64encode, b64decode
from dataclasses import dataclass, field
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


@dataclass(frozen=True)
class BTPDataRequest:
    """
    GN Data Request class. As specified in
    ETSI EN 302 636-5-1 V2.1.0 (2017-05). Annex A2

    Attributes
    ----------
    btp_type : CommonNH
        BTP Type.
    source_port : int
        (16 bit integer) Source Port.
    destination_port : int
        (16 bit integer) Destination Port.
    destination_port_info : int
        (16 bit integer) Destination Port Info.
    gn_packet_transport_type : PacketTransportType
        Packet Transport Type.
    gn_destination_address : GNAddress
        Destination Address.
    communication_profile : CommunicationProfile
        Communication Profile.
    traffic_class : TrafficClass
        Traffic Class.
    length : int
        Length of the payload.
    data : bytes
        Payload.
    """

    btp_type: CommonNH = CommonNH.BTP_B
    source_port: int = 0
    destination_port: int = 0
    destination_port_info: int = 0
    destination_port_info: int = 0
    gn_packet_transport_type: PacketTransportType = field(
        default_factory=PacketTransportType)
    gn_destination_address: GNAddress = field(default_factory=GNAddress)
    gn_area: Area = field(default_factory=Area)
    communication_profile: CommunicationProfile = CommunicationProfile.UNSPECIFIED
    traffic_class: TrafficClass = field(default_factory=TrafficClass)
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
            communication_profile=communication_profile,
            traffic_class=traffic_class,
            length=length,
            data=payload,
        )


@dataclass(frozen=True)
class BTPDataIndication:
    """
    GN Data Indication class. As specified in ETSI EN 302 636-5-1 V2.1.0 (2017-05). Annex A3

    Attributes
    ----------
    source_port : int
        (16 bit integer) Source Port.
    destination_port : int
        (16 bit integer) Destination Port.
    destination_port_info : int
        (16 bit integer) Destination Port Info.
    gn_packet_transport_type : PacketTransportType
        Packet Transport Type.
    gn_destination_address : GNAddress
        Destination Address.
    gn_source_position_vector : LongPositionVector
        Source Position Vector.
    gn_traffic_class : TrafficClass
        Traffic Class.
    length : int
        Length of the payload.
    data : bytes
        Payload.
    """

    source_port: int = 0
    destination_port: int = 0
    destination_port_info: int = 0
    destination_port_info: int = 0
    gn_packet_transport_type: PacketTransportType = field(
        default_factory=PacketTransportType)
    gn_destination_address: GNAddress = field(default_factory=GNAddress)
    gn_source_position_vector: LongPositionVector = field(
        default_factory=LongPositionVector)
    gn_traffic_class: TrafficClass = field(default_factory=TrafficClass)
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
            gn_traffic_class=self.gn_traffic_class,
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
            "gn_traffic_class": b64encode(
                self.gn_traffic_class.encode_to_bytes()
            ).decode("utf-8"),
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
            gn_traffic_class=gn_traffic_class,
            length=length,
            data=payload,
        )
