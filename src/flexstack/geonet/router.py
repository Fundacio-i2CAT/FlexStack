from __future__ import annotations
from collections.abc import Callable
from enum import Enum
from time import sleep
from threading import Thread, Lock
import math
from ..linklayer.exceptions import (
    SendingException,
    PacketTooLongException,
)
from .mib import (
    MIB,
    LocalGnAddrConfMethod,
    NonAreaForwardingAlgorithm,
    AreaForwardingAlgorithm,
)
from .gn_address import GNAddress
from .service_access_point import (
    HeaderType,
    TopoBroadcastHST,
    GeoBroadcastHST,
    GNDataRequest,
    ResultCode,
    GNDataConfirm,
    GNDataIndication,
    Area,
    PacketTransportType,
)
from .basic_header import BasicNH, BasicHeader
from .common_header import CommonHeader
from .gbc_extended_header import GBCExtendedHeader
from .position_vector import LongPositionVector
from .location_table import LocationTable
from ..linklayer.link_layer import LinkLayer
from ..security.sign_service import SignService
from ..security.security_profiles import SecurityProfile
from ..security.sn_sap import SNSIGNConfirm, SNSIGNRequest
from .exceptions import (
    DADException,
    DecapError,
    DecodeError,
    DuplicatedPacketException,
    IncongruentTimestampException,
)

EARTH_RADIUS = 6371000  # Radius of the Earth in meters


class GNForwardingAlgorithmResponse(Enum):
    """
    GN Forwarding Algorithm Selection Response. As specified in ETSI EN 302 636-4-1 V1.4.1 (2020-01). Annex D.

    Attributes
    ----------
    AREA-FORWARDING : 1
        Area Forwarding.
    NON-AREA-FORWARDING : 2
        Non-Area Forwarding.
    DISCARTED : 3
        Discarted.
    """

    AREA_FORWARDING = 1
    NON_AREA_FORWARDING = 2
    DISCARTED = 3


class Router:
    """
    Geonetworking Router

    Handles the routing of Geonetworking packets. As specified in ETSI EN 302 636-4-1 V1.4.1 (2020-01).

    """

    def __init__(self, mib: MIB, sign_service: SignService | None = None) -> None:
        """
        Initialize the router.

        Parameters
        ----------
        mib : MIB
            MIB to use.
        """
        self.mib = mib
        self.ego_position_vector_lock = Lock()
        self.ego_position_vector = LongPositionVector()
        self.setup_gn_address()
        self.link_layer: LinkLayer | None = None
        self.location_table = LocationTable(mib)
        self.sign_service: SignService | None = sign_service
        self.indication_callback = None
        self.sequence_number_lock = Lock()
        self.sequence_number = 0
        if self.mib.itsGnBeaconServiceRetransmitTimer > 0:
            self.configure_beacon_service()
        
    def configure_beacon_service(self) -> None:
        """
        Configures, set-ups threading, for the beacon service based on MIB settings.
        
        Parameters
        ----------
        None
        """

        thread = Thread(target=self.beacon_service_thread, daemon=True)
        thread.start()

    def beacon_service_thread(self) -> None:
        """
        Thread function to handle beacon service retransmissions.
        """

        while True:
            self.gn_data_request_beacon()
            sleep(self.mib.itsGnBeaconServiceRetransmitTimer / 1000)

    def gn_data_request_beacon(self) -> None:
        """
        Handle a Beacon GNDataRequest.

        Parameters
        ----------
        None
        """
        basic_header = BasicHeader.initialize_with_mib_and_rhl(self.mib, 1)
        common_header = CommonHeader.initialize_beacon()
        long_position_vector = self.ego_position_vector
        packet = (
            basic_header.encode_to_bytes()
            + common_header.encode_to_bytes()
            + long_position_vector.encode()
        )

        try:
            if self.link_layer:
                self.link_layer.send(packet)
        except PacketTooLongException:
            pass
        except SendingException:
            pass


    def get_sequence_number(self) -> int:
        """
        Get the current sequence number.

        Returns
        -------
        int
            Current sequence number.
        """
        with self.sequence_number_lock:
            self.sequence_number = (self.sequence_number + 1) % (2**16 - 1)
            return self.sequence_number

    def register_indication_callback(
        self, callback: Callable[[GNDataIndication], None]
    ) -> None:
        """
        Registers a callback for GNDataIndication.

        Parameters
        ----------
        callback : Callable[[GNDataIndication], None]
            Callback to register.
        """
        self.indication_callback = callback

    def setup_gn_address(self) -> None:
        # pylint: disable=no-else-raise
        """
        Set the GN address of the router.

        Raises
        ------
        NotImplementedError :
            If the local GN address configuration method is not implemented.
        """
        if self.mib.itsGnLocalGnAddrConfMethod == LocalGnAddrConfMethod.MANAGED:
            raise NotImplementedError(
                "Managed GN address configuration is not implemented."
            )
        elif self.mib.itsGnLocalGnAddrConfMethod == LocalGnAddrConfMethod.AUTO:
            self.ego_position_vector = self.ego_position_vector.set_gn_addr(
                self.mib.itsGnLocalGnAddr)
        elif self.mib.itsGnLocalGnAddrConfMethod == LocalGnAddrConfMethod.ANONYMOUS:
            raise NotImplementedError(
                "Anonymous GN address configuration is not implemented."
            )

    def gn_data_request_shb(self, request: GNDataRequest) -> GNDataConfirm:
        """
        Handle a Single Hop Broadcast GNDataRequest.

        Parameters
        ----------
        request : GNDataRequest
            GNDataRequest to handle.
        """
        basic_header = BasicHeader.initialize_with_mib_and_rhl(self.mib, 1)
        common_header = CommonHeader.initialize_with_request(request)
        long_position_vector = self.ego_position_vector
        media_dependant_data = b"\x00\x00\x00\x00"
        packet = b""
        if request.security_profile == SecurityProfile.COOPERATIVE_AWARENESS_MESSAGE:
            if self.sign_service is None:
                raise NotImplementedError("Security profile not implemented")
            media_dependant_data = b"\x00\x00\x00\x00"
            tbs_packet = (
                common_header.encode_to_bytes()
                + long_position_vector.encode()
                + media_dependant_data
                + request.data
            )
            sign_request = SNSIGNRequest(
                tbs_message_length=len(tbs_packet),
                tbs_message=tbs_packet,
                its_aid=request.its_aid,
                permissions=request.security_permissions,
                permissions_length=len(request.security_permissions),
            )
            sign_confirm: SNSIGNConfirm = self.sign_service.sign_cam(
                sign_request)
            basic_header = basic_header.set_nh(BasicNH.SECURED_PACKET)
            packet = basic_header.encode_to_bytes() + sign_confirm.sec_message

        else:
            packet = (
                basic_header.encode_to_bytes()
                + common_header.encode_to_bytes()
                + long_position_vector.encode()
                + media_dependant_data
                + request.data
            )

        try:
            if self.link_layer:
                self.link_layer.send(packet)
        except PacketTooLongException:
            return GNDataConfirm(result_code=ResultCode.MAXIMUM_LENGTH_EXCEEDED)
        except SendingException:
            return GNDataConfirm(result_code=ResultCode.UNSPECIFIED)

        return GNDataConfirm(result_code=ResultCode.ACCEPTED)

    @staticmethod
    def calculate_distance(
        coord1: tuple[float, float], coord2: tuple[float, float]
    ) -> tuple[float, float]:
        """
        Returns the distance between two coordinates in meters.
        As specified in ETSI EN 302 931 - V1.0.0
        Latitude -> x
        Longitude -> -y

        Returns
        -------
        Tuple[float, float]:
            Tuple of x distance, y distance
        """
        lat1, lon1 = coord1
        lat2, lon2 = coord2

        # Convert latitude and longitude to radians
        lat1 = math.radians(lat1)
        lon1 = math.radians(lon1)
        lat2 = math.radians(lat2)
        lon2 = math.radians(lon2)

        # Calculate the differences in latitude and longitude
        dlat = lat2 - lat1
        dlon = lon2 - lon1

        # Calculate the distance along the y-axis (-longitude)
        y_distance = EARTH_RADIUS * dlon * math.cos((lat1 + lat2) / 2)

        # Calculate the distance along the x-axis (latitude)
        x_distance = (-1) * EARTH_RADIUS * dlat

        return x_distance, y_distance

    @staticmethod
    def transform_distance_angle(
        distance: tuple[float, float], angle: int
    ) -> tuple[float, float]:
        """
        Adapts the X,Y pointed at north to the right angle

        Returns
        -------
        tuple[float, float]
            X and Y distances adapted to the angle
        """
        n_angle = math.radians(angle)
        new_x_distance = math.cos(n_angle) * distance[0]
        new_y_distance = math.sin(n_angle) * distance[1]
        return (new_x_distance, new_y_distance)

    def gn_geometric_function_f(
        self, area_type: GeoBroadcastHST, area: Area, lat: int, lon: int
    ) -> float:
        """
        Implements the Geometric function F to determine spatial characteristics of a point P(x,y).
        As specified in EN 302 931 - V1.0.0 Section 5

        Parameters
        ----------
        area_type : GeoBroadcastHST
            Type of the area.
        area : Area
            Area of the circle.
        lat : int
            Latitude of the point P. In 1/10 microdegrees.
        lon : int
            Longitude of the point P. In 1/10 microdegrees.
        """
        coord1 = (area.latitude / 10000000, area.longitude / 10000000)
        coord2 = (lat / 10000000, lon / 10000000)
        x_distance, y_distance = Router.calculate_distance(coord1, coord2)
        if area_type == GeoBroadcastHST.GEOBROADCAST_CIRCLE:
            return 1 - (x_distance / area.a) ** 2 - (y_distance / area.a) ** 2
        if area_type == GeoBroadcastHST.GEOBROADCAST_ELIP:
            return 1 - (x_distance / area.a) ** 2 - (y_distance / area.b) ** 2
        if area_type == GeoBroadcastHST.GEOBROADCAST_RECT:
            return min(1 - (x_distance / area.a) ** 2, (y_distance / area.b) ** 2)
        raise ValueError("Invalid area type")

    def gn_forwarding_algorithm_selection(
        self, request: GNDataRequest
    ) -> GNForwardingAlgorithmResponse:
        """

        Parameters
        ----------
        request : GNDataRequest
            GNDataRequest to handle.
        """
        result = self.gn_geometric_function_f(
            request.packet_transport_type.header_subtype,
            request.area,
            self.ego_position_vector.latitude,
            self.ego_position_vector.longitude,
        )

        if result >= 0:
            return GNForwardingAlgorithmResponse.AREA_FORWARDING
        # TODO: Parts of the forwarding algorithm selection
        return GNForwardingAlgorithmResponse.DISCARTED

    def gn_data_forward_gbc(
        self,
        basic_header: BasicHeader,
        common_header: CommonHeader,
        gbc_extended_header: GBCExtendedHeader,
        packet: bytes,
    ) -> GNDataConfirm:
        """
        Function called when a GBC packet has to be fowraded.

        Parameters
        ----------
        basic_header : BasicHeader
            Basic header of the packet.
        common_header : CommonHeader
            Common header of the packet.
        gbc_extended_header : GBCExtendedHeader
            Extended header of the packet.
        packet : bytes
            Packet to forward. (Without headers)
        """
        # TODO: Location Service (LS) packet buffers (step 8)
        basic_header = basic_header.set_rhl(basic_header.rhl - 1)
        # 10) if no neighbour exists, i.e. the LocT does not contain a LocTE with the IS_NEIGHBOUR flag set to TRUE,
        # and SCF for the traffic class in the TC field of the Common Header is set, buffer the GBC packet in the BC
        # forwarding packet buffer and omit the execution of further steps;
        if len(self.location_table.get_neighbours()) > 0 or not common_header.tc.scf:
            # 11) execute the forwarding algorithm procedures (starting with annex D);
            area = Area(
                latitude=gbc_extended_header.latitude,
                longitude=gbc_extended_header.longitude,
                a=gbc_extended_header.a,
                b=gbc_extended_header.b,
                angle=gbc_extended_header.angle,
            )
            packet_transport_type = PacketTransportType(
                header_type=common_header.ht,
                header_subtype=common_header.hst,
            )
            request = GNDataRequest(
                area=area, packet_transport_type=packet_transport_type)
            algorithm = self.gn_forwarding_algorithm_selection(request)
            # 12) if the return value of the forwarding algorithm is 0 (packet is buffered in a forwarding packet
            # buffer) or -1 (packet is discarded), omit the execution of further steps;
            if algorithm == GNForwardingAlgorithmResponse.AREA_FORWARDING:
                # TODO: step 13
                # 14) pass the GN-PDU to the LL protocol entity via the IN interface and set the destination
                # address to the LL address of the next hop LL_ADDR_NH.
                final_packet: bytes = (
                    basic_header.encode_to_bytes()
                    + common_header.encode_to_bytes()
                    + gbc_extended_header.encode()
                    + packet
                )
                try:
                    if self.link_layer:
                        self.link_layer.send(final_packet)
                except PacketTooLongException:
                    return GNDataConfirm(
                        result_code=ResultCode.MAXIMUM_LENGTH_EXCEEDED)
                except SendingException:
                    return GNDataConfirm(result_code=ResultCode.UNSPECIFIED)

        else:
            final_packet: bytes = (
                basic_header.encode_to_bytes()
                + common_header.encode_to_bytes()
                + gbc_extended_header.encode()
                + packet
            )
            try:
                if self.link_layer:
                    self.link_layer.send(final_packet)
            except PacketTooLongException:
                return GNDataConfirm(
                    result_code=ResultCode.MAXIMUM_LENGTH_EXCEEDED)
            except SendingException:
                return GNDataConfirm(result_code=ResultCode.UNSPECIFIED)
        return GNDataConfirm(result_code=ResultCode.ACCEPTED)

    def gn_data_request_gbc(self, request: GNDataRequest) -> GNDataConfirm:
        """
        Handle a Geo Broadcast GNDataRequest.

        Parameters
        ----------
        request : GNDataRequest
            GNDataRequest to handle.
        """
        # 1) create a GN-PDU with the T/GN6-SDU as payload and a GBC packet header (clause 9.8.5):
        #   a) set the fields of the Basic Header (clause 10.3.2);
        basic_header = BasicHeader.initialize_with_mib(self.mib)
        #   b) set the fields of the Common Header (clause 10.3.4);
        common_header = CommonHeader.initialize_with_request(request)
        #   c) set the fields of the GBC Extended Header (table 36);
        geo_broadcast_extended_header = GBCExtendedHeader.initialize_with_request_sequence_number_ego_pv(
            request, self.get_sequence_number(), self.ego_position_vector)
        # 2) if no neighbour exists, i.e. the LocT does not contain a LocTE with the IS_NEIGHBOUR flag set to TRUE,
        # and SCF for the traffic class in the service primitive GN-DATA.request parameter Traffic class is enabled,
        # then buffer the GBC packet in the BC forwarding packet buffer and omit the execution of further steps;
        if (
            len(self.location_table.get_neighbours()) > 0
            or not request.traffic_class.scf
        ):
            # 3) execute the forwarding algorithm procedures (starting with annex D);
            algorithm = self.gn_forwarding_algorithm_selection(request)
            # 4) if the return value of the forwarding algorithm is 0 (packet is buffered in the BC forwarding packet
            # buffer or in the CBF buffer) or -1 (packet is discarded), omit the execution of further steps;
            if algorithm == GNForwardingAlgorithmResponse.AREA_FORWARDING:
                # TODO: steps 5-7
                # 8) pass the GN-PDU to the LL protocol entity via the IN interface and set the destination address to
                # the LL address of the next hop LL_ADDR_NH.
                packet: bytes = (
                    basic_header.encode_to_bytes()
                    + common_header.encode_to_bytes()
                    + geo_broadcast_extended_header.encode()
                    + request.data
                )
                try:
                    if self.link_layer:
                        self.link_layer.send(packet)
                except PacketTooLongException:
                    return GNDataConfirm(result_code=ResultCode.MAXIMUM_LENGTH_EXCEEDED)
                except SendingException:
                    return GNDataConfirm(result_code=ResultCode.UNSPECIFIED)

        else:
            packet: bytes = (
                basic_header.encode_to_bytes()
                + common_header.encode_to_bytes()
                + geo_broadcast_extended_header.encode()
                + request.data
            )
            try:
                if self.link_layer:
                    self.link_layer.send(packet)
            except PacketTooLongException:
                return GNDataConfirm(result_code=ResultCode.MAXIMUM_LENGTH_EXCEEDED)
            except SendingException:
                return GNDataConfirm(result_code=ResultCode.UNSPECIFIED)

        return GNDataConfirm(result_code=ResultCode.ACCEPTED)

    def gn_data_request(self, request: GNDataRequest) -> GNDataConfirm:
        """
        Handle a GNDataRequest.

        Parameters
        ----------
        request : GNDataRequest
            GNDataRequest to handle.

        Raises
        ------
        NotImplementedError : PacketTransportType not implemented

        Returns
        -------
        GNDataConfirm :
            Confirmation of the process of the packet.
        """
        if (request.packet_transport_type.header_type == HeaderType.TSB) and (
            request.packet_transport_type.header_subtype == TopoBroadcastHST.SINGLE_HOP
        ):
            return self.gn_data_request_shb(request)
        if request.packet_transport_type.header_type == HeaderType.GEOBROADCAST:
            return self.gn_data_request_gbc(request)
        raise NotImplementedError("PacketTransportType not implemented")

    def gn_data_indicate_shb(
        self, packet: bytes, common_header: CommonHeader
    ) -> GNDataIndication:
        """
        Handle a Single Hop Broadcast GeoNetworking packet.

        Parameters
        ----------
        packet : bytes
            GeoNetworking packet to handle.
        common_header : CommonHeader
            CommonHeader of the packet.
        """
        # ETSI EN 302 636-4-1 V1.4.1 (2020-01). Section
        try:
            long_position_vector = LongPositionVector()
            long_position_vector.decode(packet[0:24])
            packet = packet[24:]
            # Ignore Media Dependant Data
            packet = packet[4:]
            self.location_table.new_shb_packet(long_position_vector, packet)
            return GNDataIndication(
                upper_protocol_entity=common_header.nh,
                source_position_vector=long_position_vector,
                traffic_class=common_header.tc,
                length=len(packet),
                data=packet
            )
        except DADException:
            print("Duplicate Address Detected!")
        except IncongruentTimestampException:
            print("Incongruent Timestamp Detected!")
        except DuplicatedPacketException:
            print("Packet is duplicated")
        except DecodeError as e:
            print(str(e))
        return GNDataIndication()

    def gn_data_indicate_gbc(
        self, packet: bytes, common_header: CommonHeader
    ) -> GNDataIndication:
        """
        Handle a GeobroadcastBroadcast GeoNetworking packet.

        Parameters
        ----------
        packet : bytes
            GeoNetworking packet to handle (without the basic header and common header)
        common_header : CommonHeader
            CommonHeader of the packet.
        """
        gbc_extended_header = GBCExtendedHeader.decode(packet[0:44])
        packet = packet[44:]
        area = Area(
            a=gbc_extended_header.a,
            b=gbc_extended_header.b,
            latitude=gbc_extended_header.latitude,
            longitude=gbc_extended_header.longitude,
            angle=gbc_extended_header.angle
        )
        area_f = self.gn_geometric_function_f(
            common_header.hst,  # type: ignore
            area,
            self.ego_position_vector.latitude,
            self.ego_position_vector.longitude,
        )
        if area_f < 0 and (
            self.mib.itsGnNonAreaForwardingAlgorithm
            in (
                NonAreaForwardingAlgorithm.GREEDY,
                NonAreaForwardingAlgorithm.UNSPECIFIED,
            )
        ):
            pass
        elif area_f >= 0 and (
            self.mib.itsGnAreaForwardingAlgorithm
            in (AreaForwardingAlgorithm.UNSPECIFIED, AreaForwardingAlgorithm.SIMPLE)
        ):
            pass
        try:
            self.duplicate_address_detection(gbc_extended_header.so_pv.gn_addr)
            self.location_table.new_gbc_packet(gbc_extended_header, packet)
            if area_f >= 0:
                # TODO: Extend the indication information
                return GNDataIndication(
                    upper_protocol_entity=common_header.nh,
                    packet_transport_type=PacketTransportType(
                        header_type=HeaderType.GEOBROADCAST,
                        header_subtype=common_header.hst
                    ),
                    source_position_vector=gbc_extended_header.so_pv,
                    traffic_class=common_header.tc,
                    length=len(packet),
                    data=packet
                )
        except DADException:
            print("Duplicate Address Detected!")
        except IncongruentTimestampException:
            print("Incongruent Timestamp Detected!")
        except DecodeError as e:
            print(str(e))
        return GNDataIndication()

    def gn_data_indicate_beacon(self, packet: bytes) -> None:
        """
        Method to indicate a Beacon GeoNetworking packet.

        Lower level layers should call this method to indicate a Beacon GeoNetworking packet.

        Parameters
        ----------
        packet : bytes
            GeoNetworking packet to indicate.
        common_header : CommonHeader
            CommonHeader of the packet.
        """
        # ETSI EN 302 636-4-1 V1.4.1 (2020-01). Section 10.3.6
        try:
            long_position_vector = LongPositionVector()
            long_position_vector.decode(packet[0:24])
            packet = packet[24:]
            # Receiver operations of Beacon packets are identical to the 
            # handling procedures of the SHB packet (clause 10.3.10.3)
            self.location_table.new_shb_packet(long_position_vector, packet)
        except DADException:
            print("Duplicate Address Detected!")
        except IncongruentTimestampException:
            print("Incongruent Timestamp Detected!")
        except DuplicatedPacketException:
            print("Packet is duplicated")
        except DecodeError as e:
            print(str(e))


    def gn_data_indicate(self, packet: bytes) -> None:
        # pylint: disable=no-else-raise, too-many-branches
        """
        Method to indicate a GeoNetworking packet.

        Lower level layers should call this method to indicate a GeoNetworking packet.

        Parameters
        ----------
        packet : bytes
            GeoNetworking packet to indicate.

        Raises
        ------
        NotImplementedError : Version not implemented
        """
        indication = GNDataIndication()
        # ETSI EN 302 636-4-1 V1.4.1 (2020-01). Section 10.3.3
        # Decap the common header
        basic_header = BasicHeader.decode_from_bytes(packet[0:4])
        packet = packet[4:]
        if basic_header.version != self.mib.itsGnProtocolVersion:
            raise NotImplementedError("Version not implemented")
        if basic_header.nh == BasicNH.COMMON_HEADER:
            # ETSI EN 302 636-4-1 V1.4.1 (2020-01). Section 10.3.5
            # Decap the common header
            common_header = CommonHeader.decode_from_bytes(packet[0:8])
            packet = packet[8:]
            if basic_header.rhl > self.mib.itsGnDefaultHopLimit:
                raise DecapError("Hop limit exceeded")
            # TODO: Forwarding packet buffer flush
            if common_header.ht == HeaderType.ANY:
                raise NotImplementedError(
                    "Any packet (Common Header) not implemented")
            elif common_header.ht == HeaderType.BEACON:
                self.gn_data_indicate_beacon(packet)
                return
            elif common_header.ht == HeaderType.GEOUNICAST:
                raise NotImplementedError("Geounicast not implemented")
            elif common_header.ht == HeaderType.GEOANYCAST:
                raise NotImplementedError("Geoanycast not implemented")
            elif common_header.ht == HeaderType.GEOBROADCAST:
                indication = self.gn_data_indicate_gbc(packet, common_header)
            elif common_header.ht == HeaderType.TSB:
                if common_header.hst == TopoBroadcastHST.SINGLE_HOP:
                    indication = self.gn_data_indicate_shb(
                        packet, common_header)
                else:
                    raise NotImplementedError("TopoBroadcast not implemented")
            elif common_header.ht == HeaderType.LS:
                raise NotImplementedError("Location Service not implemented")
            else:
                raise NotImplementedError(
                    "Any packet (Common Header) not implemented")

        elif basic_header.nh == BasicNH.SECURED_PACKET:
            raise NotImplementedError("Secured packet not implemented")
        else:
            raise NotImplementedError("ANY next header not implemented")
        if self.indication_callback:
            self.indication_callback(indication)

    def duplicate_address_detection(self, gn_addr: GNAddress) -> None:
        """
        Perform Duplicate Address Detection (DAD) on the given GNAddress.
        Specified in ETSI EN 302 636-4-1 V1.4.1 (2020-01). Section 10.2.1.5

        Parameters
        ----------
        gn_addr : GNAddress
            GNAddress to perform Duplicate Address Detection on.
        """
        if self.mib.itsGnLocalGnAddr == gn_addr:
            raise DADException("Duplicate Address Detected!")
            # TODO : Handle the reset of the GN address as said in the standard

    def refresh_ego_position_vector(self, tpv: dict) -> None:
        """
        Refresh the ego position vector.
        """
        with self.ego_position_vector_lock:
            self.ego_position_vector = self.ego_position_vector.refresh_with_tpv_data(
                tpv)
