from __future__ import annotations
from collections.abc import Callable
from dataclasses import replace as dataclass_replace
from enum import Enum
from threading import Thread, Lock, Event, Timer
import math
import random
from ..linklayer.exceptions import (
    SendingException,
    PacketTooLongException,
)
from .mib import (
    MIB,
    GnSecurity,
    LocalGnAddrConfMethod,
    NonAreaForwardingAlgorithm,
    AreaForwardingAlgorithm,
)
from .gn_address import GNAddress
from .service_access_point import (
    CommonNH,
    HeaderType,
    TopoBroadcastHST,
    GeoBroadcastHST,
    GeoAnycastHST,
    LocationServiceHST,
    TrafficClass,
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
from .tsb_extended_header import TSBExtendedHeader
from .guc_extended_header import GUCExtendedHeader
from .ls_extended_header import LSRequestExtendedHeader, LSReplyExtendedHeader
from .position_vector import LongPositionVector, ShortPositionVector
from .location_table import LocationTable
from ..linklayer.link_layer import LinkLayer
from ..security.sign_service import SignService
from ..security.verify_service import VerifyService
from ..security.security_profiles import SecurityProfile
from ..security.sn_sap import SNSIGNConfirm, SNSIGNRequest, SNVERIFYRequest, ReportVerify
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

    def __init__(self, mib: MIB, sign_service: SignService | None = None, verify_service: VerifyService | None = None) -> None:
        """
        Initialize the router.

        Parameters
        ----------
        mib : MIB
            MIB to use.
        sign_service : SignService | None
            Sign service used to sign outgoing secured packets. Defaults to None
            (no signing).
        verify_service : VerifyService | None
            Verify service used to verify incoming secured packets. Defaults to None
            (secured packets are discarded with a warning).
        """
        self.mib = mib
        self.ego_position_vector_lock = Lock()
        self.ego_position_vector = LongPositionVector()
        self.setup_gn_address()
        self.link_layer: LinkLayer | None = None
        self.location_table = LocationTable(mib)
        self.sign_service: SignService | None = sign_service
        self.verify_service: VerifyService | None = verify_service
        self.indication_callback = None
        self.sequence_number_lock = Lock()
        self.sequence_number = 0
        self._beacon_reset_event: Event | None = None
        # Location Service state (§10.2.4)
        self._ls_lock: Lock = Lock()
        self._ls_timers: dict = {}                  # GNAddress → threading.Timer
        self._ls_retransmit_counters: dict = {}     # GNAddress → int
        self._ls_packet_buffers: dict = {}          # GNAddress → list[GNDataRequest]
        # CBF packet buffer (§F.3): keyed by (so_gn_addr, sn)
        self._cbf_lock: Lock = Lock()
        self._cbf_buffer: dict = {}                 # (GNAddress, int) → threading.Timer
        if self.mib.itsGnBeaconServiceRetransmitTimer > 0:
            self.configure_beacon_service()

    def configure_beacon_service(self) -> None:
        """
        Configures, set-ups threading, for the beacon service based on MIB settings.

        Parameters
        ----------
        None
        """
        self._beacon_reset_event = Event()
        thread = Thread(target=self.beacon_service_thread, daemon=True)
        thread.start()

    def beacon_service_thread(self) -> None:
        """
        Thread function to handle beacon service retransmissions.

        Sends a beacon then waits for the retransmit interval plus a random
        jitter in [0, itsGnBeaconServiceMaxJitter] ms as required by
        §10.3.6.2 step 5 of ETSI EN 302 636-4-1 V1.4.1 (2020-01).
        If an SHB transmission resets the beacon timer (§10.3.10.2 step 7)
        during the wait the interval is restarted so that no unnecessary
        beacon is sent.
        """
        assert self._beacon_reset_event is not None
        while True:
            self.gn_data_request_beacon()
            # §10.3.6.2 step 5: TBeacon = itsGnBeaconServiceRetransmitTimer
            #                            + RAND[0, itsGnBeaconServiceMaxJitter]
            jitter_ms = random.uniform(0, self.mib.itsGnBeaconServiceMaxJitter)
            timeout = (self.mib.itsGnBeaconServiceRetransmitTimer +
                       jitter_ms) / 1000
            # If SHB fires during the wait it sets the event, causing wait() to
            # return True.  Clear the event and restart the full interval so no
            # redundant beacon is emitted immediately after an SHB.
            while self._beacon_reset_event.wait(timeout):
                self._beacon_reset_event.clear()

    def gn_data_request_beacon(self) -> None:
        """
        Handle a Beacon GNDataRequest.

        Parameters
        ----------
        None
        """
        basic_header = BasicHeader.initialize_with_mib_and_rhl(self.mib, 1)
        # §10.3.4: Flags Bit 0 shall be set to itsGnIsMobile
        common_header = CommonHeader.initialize_beacon(self.mib)
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
        # Step 1a: Basic Header – LT from request when provided, else MIB default;
        #           RHL = 1 for SHB (§10.3.2)
        # Step 1b: Common Header – flags bit 0 = itsGnIsMobile (§10.3.4)
        basic_header = BasicHeader.initialize_with_mib_request_and_rhl(
            self.mib, request.max_packet_lifetime, 1)
        common_header = CommonHeader.initialize_with_request(
            request, self.mib)
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

        # Step 3: §10.3.10.2 – if no suitable neighbour exists and SCF is set,
        # buffer in the BC forwarding packet buffer (not yet implemented).
        if len(self.location_table.get_neighbours()) == 0 and request.traffic_class.scf:
            print(
                "SHB: no neighbours and SCF set; BC forwarding buffer not yet implemented")
        # Steps 5-6: media-dependent procedures and pass GN-PDU to LL
        try:
            if self.link_layer:
                self.link_layer.send(packet)
        except PacketTooLongException:
            return GNDataConfirm(result_code=ResultCode.MAXIMUM_LENGTH_EXCEEDED)
        except SendingException:
            return GNDataConfirm(result_code=ResultCode.UNSPECIFIED)

        # Step 7: reset beacon timer to prevent an unnecessary beacon (§10.3.10.2)
        if self._beacon_reset_event is not None:
            self._beacon_reset_event.set()

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
        if area_type in (GeoBroadcastHST.GEOBROADCAST_CIRCLE, GeoAnycastHST.GEOANYCAST_CIRCLE):
            return 1 - (x_distance / area.a) ** 2 - (y_distance / area.a) ** 2
        if area_type in (GeoBroadcastHST.GEOBROADCAST_ELIP, GeoAnycastHST.GEOANYCAST_ELIP):
            return 1 - (x_distance / area.a) ** 2 - (y_distance / area.b) ** 2
        if area_type in (GeoBroadcastHST.GEOBROADCAST_RECT, GeoAnycastHST.GEOANYCAST_RECT):
            return min(1 - (x_distance / area.a) ** 2, 1 - (y_distance / area.b) ** 2)
        raise ValueError("Invalid area type")

    @staticmethod
    def _compute_area_size_m2(
        area_type: GeoBroadcastHST | GeoAnycastHST, area: Area
    ) -> float:
        """
        Compute the geographical area size in m² for §B.3 area size control.

        Parameters
        ----------
        area_type : GeoBroadcastHST | GeoAnycastHST
            Shape type obtained from the Common Header HST field.
        area : Area
            Area parameters (a, b in metres).
        """
        if area_type in (GeoBroadcastHST.GEOBROADCAST_CIRCLE, GeoAnycastHST.GEOANYCAST_CIRCLE):
            return math.pi * area.a ** 2
        if area_type in (GeoBroadcastHST.GEOBROADCAST_ELIP, GeoAnycastHST.GEOANYCAST_ELIP):
            return math.pi * area.a * area.b
        # RECT: a and b are distances from centre to edge → full area = (2a) × (2b)
        return 4.0 * area.a * area.b

    @staticmethod
    def _distance_m(lat1: int, lon1: int, lat2: int, lon2: int) -> float:
        """Euclidean distance in metres between two points (coordinates in 1/10 µdeg)."""
        coord1 = (lat1 / 10_000_000, lon1 / 10_000_000)
        coord2 = (lat2 / 10_000_000, lon2 / 10_000_000)
        dx, dy = Router.calculate_distance(coord1, coord2)
        return math.sqrt(dx * dx + dy * dy)

    def gn_greedy_forwarding(
        self, dest_lat: int, dest_lon: int, traffic_class: TrafficClass
    ) -> bool:
        """
        §E.2 Greedy Forwarding algorithm (ETSI EN 302 636-4-1 V1.4.1 Annex E).

        Selects the neighbour with the smallest distance to the destination
        (Most Forward within Radius policy). Returns True if the packet should
        be transmitted (greedy next hop or BCAST fallback at local optimum),
        False if it should be buffered (local optimum and SCF is enabled).
        """
        mfr = Router._distance_m(
            dest_lat, dest_lon,
            self.ego_position_vector.latitude,
            self.ego_position_vector.longitude,
        )
        progress_found = False
        for entry in self.location_table.get_neighbours():
            pv = entry.position_vector
            d = Router._distance_m(dest_lat, dest_lon, pv.latitude, pv.longitude)
            if d < mfr:
                mfr = d
                progress_found = True
        if progress_found:
            return True  # §E.2: send to greedy NH (NH_LL_ADDR = NH.LL_ADDR)
        # §E.2: local optimum – no neighbour with positive progress towards destination
        if traffic_class.scf:
            return False  # §E.2: buffer (NH_LL_ADDR = 0); stub: omit send
        return True       # §E.2: BCAST fallback (NH_LL_ADDR = BCAST)

    def _cbf_compute_timeout_ms(self, dist_m: float) -> float:
        """
        §F.3 equation (F.1): compute CBF timeout in milliseconds.

        TO_CBF = TO_CBF_MAX + (TO_CBF_MIN - TO_CBF_MAX) / DIST_MAX * DIST
        Clamped to TO_CBF_MIN when DIST >= DIST_MAX.
        """
        dist_max = float(self.mib.itsGnDefaultMaxCommunicationRange)
        to_min = float(self.mib.itsGnCbfMinTime)
        to_max = float(self.mib.itsGnCbfMaxTime)
        if dist_m >= dist_max:
            return to_min
        return to_max + (to_min - to_max) / dist_max * dist_m

    def _cbf_timeout(
        self,
        cbf_key: tuple,
        full_packet: bytes,
    ) -> None:
        """
        §F.3 timer expiry callback: re-broadcast the buffered GBC/GAC packet.

        Called by the per-packet Timer when TO_CBF expires.  The packet is
        removed from the CBF buffer and sent to the LL as BCAST.
        """
        with self._cbf_lock:
            if cbf_key not in self._cbf_buffer:
                return  # duplicate already arrived and discarded us
            del self._cbf_buffer[cbf_key]
        try:
            if self.link_layer:
                self.link_layer.send(full_packet)
        except (PacketTooLongException, SendingException):
            pass

    def gn_area_cbf_forwarding(
        self,
        basic_header: BasicHeader,
        common_header: CommonHeader,
        gbc_extended_header: GBCExtendedHeader,
        packet: bytes,
    ) -> bool:
        """
        §F.3 Area CBF forwarding algorithm for GBC/GAC forwarder operations.

        Returns True if the packet was buffered (timer started) so that the
        caller should NOT send immediately.  Returns False when a duplicate
        arrives and the buffered copy is discarded (packet fully suppressed).

        The CBF key is ``(so_gn_addr, sn)`` uniquely identifying the GN-PDU.
        If the key is already in the CBF buffer (duplicate reception):
          - stop the timer and remove the entry → return False (discard).
        If the key is new:
          - compute timeout from sender-to-ego distance (§F.3 eq. F.1),
          - store the full re-encoded packet in the CBF buffer,
          - start a threading.Timer that calls ``_cbf_timeout`` on expiry,
          - return True (packet buffered, do not send immediately).
        """
        cbf_key = (gbc_extended_header.so_pv.gn_addr, gbc_extended_header.sn)
        with self._cbf_lock:
            if cbf_key in self._cbf_buffer:
                # §F.3: duplicate arrived while buffering → stop timer, discard
                old_timer = self._cbf_buffer.pop(cbf_key)
                old_timer.cancel()
                return False  # §F.3: return -1 (discard)
            # New packet – compute timeout
            se_entry = self.location_table.get_entry(gbc_extended_header.so_pv.gn_addr)
            se_pos_valid = (
                se_entry is not None and se_entry.position_vector.pai
                and self.ego_position_vector.pai
            )
            if se_pos_valid and se_entry is not None:
                dist = Router._distance_m(
                    se_entry.position_vector.latitude,
                    se_entry.position_vector.longitude,
                    self.ego_position_vector.latitude,
                    self.ego_position_vector.longitude,
                )
                timeout_ms = self._cbf_compute_timeout_ms(dist)
            else:
                # §F.3: use TO_CBF_MAX when sender position unavailable
                timeout_ms = float(self.mib.itsGnCbfMaxTime)
            full_packet = (
                basic_header.encode_to_bytes()
                + common_header.encode_to_bytes()
                + gbc_extended_header.encode()
                + packet
            )
            timer = Timer(
                timeout_ms / 1000.0,
                self._cbf_timeout,
                args=[cbf_key, full_packet],
            )
            timer.daemon = True
            self._cbf_buffer[cbf_key] = timer
        timer.start()
        return True  # §F.3: return 0 (packet buffered)

    def gn_forwarding_algorithm_selection(
        self, request: GNDataRequest, sender_gn_addr: GNAddress | None = None
    ) -> GNForwardingAlgorithmResponse:
        """
        Annex D of ETSI EN 302 636-4-1 V1.4.1 (2020-01).

        Parameters
        ----------
        request : GNDataRequest
            GNDataRequest to handle.
        sender_gn_addr : GNAddress | None
            GN address of the sender of the packet being forwarded.  Used to
            look up the sender's LocTE for the §D SE_POS_VALID / F_SE check.
            None for source operations (ego is the originator).
        """
        f_ego = self.gn_geometric_function_f(
            request.packet_transport_type.header_subtype,
            request.area,
            self.ego_position_vector.latitude,
            self.ego_position_vector.longitude,
        )

        if f_ego >= 0:
            # §D: ego inside or at border of area → area forwarding
            return GNForwardingAlgorithmResponse.AREA_FORWARDING

        # §D: ego is outside the area – check sender position (Annex D lines 14-22)
        se_pv = None
        if sender_gn_addr is not None:
            se_entry = self.location_table.get_entry(sender_gn_addr)
            if se_entry is not None:
                se_pv = se_entry.position_vector
        # SE_POS_VALID = PV_SE EXISTS AND PAI_SE = TRUE
        if se_pv is not None and se_pv.pai:
            f_se = self.gn_geometric_function_f(
                request.packet_transport_type.header_subtype,
                request.area,
                se_pv.latitude,
                se_pv.longitude,
            )
            if f_se >= 0:
                # Sender was inside/at border → discard to prevent area→non-area transition
                return GNForwardingAlgorithmResponse.DISCARTED
        return GNForwardingAlgorithmResponse.NON_AREA_FORWARDING

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
            algorithm = self.gn_forwarding_algorithm_selection(
                request, sender_gn_addr=gbc_extended_header.so_pv.gn_addr)
            # 12) if the return value of the forwarding algorithm is 0 (packet is buffered in a forwarding packet
            # buffer) or -1 (packet is discarded), omit the execution of further steps;
            if algorithm == GNForwardingAlgorithmResponse.AREA_FORWARDING:
                # TODO: step 13
                # 14) pass the GN-PDU to the LL protocol entity; dispatch to §F.2 (SIMPLE/UNSPECIFIED)
                # or §F.3 (CBF) based on itsGnAreaForwardingAlgorithm.
                if self.mib.itsGnAreaForwardingAlgorithm == AreaForwardingAlgorithm.CBF:
                    # §F.3: buffer with timer; _cbf_timeout fires the BCAST re-transmission
                    self.gn_area_cbf_forwarding(
                        basic_header, common_header, gbc_extended_header, packet)
                    return GNDataConfirm(result_code=ResultCode.ACCEPTED)
                # §F.2 / UNSPECIFIED: simple re-broadcast (BCAST) immediately
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
            elif algorithm == GNForwardingAlgorithmResponse.NON_AREA_FORWARDING:
                # §E.2: Greedy Forwarding towards area centre (ego outside area)
                if self.gn_greedy_forwarding(area.latitude, area.longitude, common_header.tc):
                    naf_packet: bytes = (
                        basic_header.encode_to_bytes()
                        + common_header.encode_to_bytes()
                        + gbc_extended_header.encode()
                        + packet
                    )
                    try:
                        if self.link_layer:
                            self.link_layer.send(naf_packet)
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

    def gn_data_request_gac(self, request: GNDataRequest) -> GNDataConfirm:
        """
        Handle a GeoAnycast (GAC) GNDataRequest.

        Implements §10.3.12.2 source operations of ETSI EN 302 636-4-1 V1.4.1 (2020-01).
        The source operations for GAC are identical to those for GBC (§10.3.11.2).

        Parameters
        ----------
        request : GNDataRequest
            GNDataRequest to handle.
        """
        return self.gn_data_request_gbc(request)

    def gn_data_request_gbc(self, request: GNDataRequest) -> GNDataConfirm:
        """
        Handle a Geo Broadcast GNDataRequest.

        Parameters
        ----------
        request : GNDataRequest
            GNDataRequest to handle.
        """
        # §B.3: Geographical area size control – do not send if area exceeds itsGnMaxGeoAreaSize
        if Router._compute_area_size_m2(
            request.packet_transport_type.header_subtype, request.area  # type: ignore
        ) > self.mib.itsGnMaxGeoAreaSize * 1_000_000:
            return GNDataConfirm(result_code=ResultCode.GEOGRAPHICAL_SCOPE_TOO_LARGE)
        # 1) create a GN-PDU with the T/GN6-SDU as payload and a GBC packet header (clause 9.8.5):
        #   a) set the fields of the Basic Header (clause 10.3.2):
        #      LT from request when provided, else itsGnDefaultPacketLifetime;
        #      RHL = itsGnDefaultHopLimit for GBC (§10.3.2).
        hop_limit = self.mib.itsGnDefaultHopLimit if request.max_hop_limit <= 1 else request.max_hop_limit
        basic_header = BasicHeader.initialize_with_mib_request_and_rhl(
            self.mib, request.max_packet_lifetime, hop_limit)
        #   b) set the fields of the Common Header (clause 10.3.4);
        #      Flags Bit 0 = itsGnIsMobile (§10.3.4)
        _req_with_hl = dataclass_replace(request, max_hop_limit=hop_limit)
        common_header = CommonHeader.initialize_with_request(
            _req_with_hl, self.mib)
        #   c) set the fields of the GBC Extended Header (table 36);
        geo_broadcast_extended_header = GBCExtendedHeader.initialize_with_request_sequence_number_ego_pv(
            request, self.get_sequence_number(), self.ego_position_vector)
        # Security encapsulation – §7.1.2 DENM profile
        # Sign the inner payload (common_header + ext_header + data) once, before
        # forwarding-algorithm packet assembly, so both AREA_FORWARDING and
        # NON_AREA_FORWARDING branches share the same signed bytes.
        sec_payload: bytes | None = None
        if request.security_profile == SecurityProfile.DECENTRALIZED_ENVIRONMENTAL_NOTIFICATION_MESSAGE:
            if self.sign_service is None:
                raise NotImplementedError(
                    "DENM security profile requires a SignService"
                )
            tbs_payload = (
                common_header.encode_to_bytes()
                + geo_broadcast_extended_header.encode()
                + request.data
            )
            sign_request = SNSIGNRequest(
                tbs_message_length=len(tbs_payload),
                tbs_message=tbs_payload,
                its_aid=request.its_aid,
                permissions=request.security_permissions,
                permissions_length=len(request.security_permissions),
                generation_location={
                    "latitude": self.ego_position_vector.latitude,
                    "longitude": self.ego_position_vector.longitude,
                    "elevation": 0xF000,  # Uint16 unavailable per IEEE 1609.2
                },
            )
            sign_confirm: SNSIGNConfirm = self.sign_service.sign_denm(sign_request)
            basic_header = basic_header.set_nh(BasicNH.SECURED_PACKET)
            sec_payload = sign_confirm.sec_message
        # 2) if no neighbour exists, i.e. the LocT does not contain a LocTE with the IS_NEIGHBOUR flag set to TRUE,
        # and SCF for the traffic class in the service primitive GN-DATA.request parameter Traffic class is enabled,
        # then buffer the GBC packet in the BC forwarding packet buffer and omit the execution of further steps;
        if len(self.location_table.get_neighbours()) == 0 and request.traffic_class.scf:
            print(
                "GBC: no neighbours and SCF set; BC forwarding buffer not yet implemented")
            return GNDataConfirm(result_code=ResultCode.ACCEPTED)
        # 3) execute the forwarding algorithm procedures (starting with annex D);
        algorithm = self.gn_forwarding_algorithm_selection(request)
        # 4) if the return value of the forwarding algorithm is 0 (packet is buffered in the BC forwarding packet
        # buffer or in the CBF buffer) or -1 (packet is discarded), omit the execution of further steps;
        if algorithm == GNForwardingAlgorithmResponse.AREA_FORWARDING:
            # TODO: steps 6-7 (repetition)
            # 8) pass the GN-PDU to the LL protocol entity via the IN interface and set the destination address to
            # the LL address of the next hop LL_ADDR_NH.
            inner: bytes = (
                sec_payload
                if sec_payload is not None
                else (
                    common_header.encode_to_bytes()
                    + geo_broadcast_extended_header.encode()
                    + request.data
                )
            )
            packet: bytes = basic_header.encode_to_bytes() + inner
            try:
                if self.link_layer:
                    self.link_layer.send(packet)
            except PacketTooLongException:
                return GNDataConfirm(result_code=ResultCode.MAXIMUM_LENGTH_EXCEEDED)
            except SendingException:
                return GNDataConfirm(result_code=ResultCode.UNSPECIFIED)
        elif algorithm == GNForwardingAlgorithmResponse.NON_AREA_FORWARDING:
            # §E.2: Greedy Forwarding towards area centre (source outside target area)
            if self.gn_greedy_forwarding(
                request.area.latitude, request.area.longitude, request.traffic_class
            ):
                naf_inner: bytes = (
                    sec_payload
                    if sec_payload is not None
                    else (
                        common_header.encode_to_bytes()
                        + geo_broadcast_extended_header.encode()
                        + request.data
                    )
                )
                naf_packet: bytes = basic_header.encode_to_bytes() + naf_inner
                try:
                    if self.link_layer:
                        self.link_layer.send(naf_packet)
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
        if request.packet_transport_type.header_type == HeaderType.GEOANYCAST:
            return self.gn_data_request_gac(request)
        if request.packet_transport_type.header_type == HeaderType.GEOUNICAST:
            return self.gn_data_request_guc(request)
        raise NotImplementedError("PacketTransportType not implemented")

    def gn_data_indicate_shb(
        self, packet: bytes, common_header: CommonHeader, basic_header: BasicHeader
    ) -> GNDataIndication | None:
        """
        Handle a Single Hop Broadcast GeoNetworking packet.

        Implements §10.3.10.3 receiver operations.

        Parameters
        ----------
        packet : bytes
            GeoNetworking packet to handle (without Basic and Common headers).
        common_header : CommonHeader
            CommonHeader of the packet.
        basic_header : BasicHeader
            BasicHeader of the packet; used for remaining LT and RHL (Table 35).
        """
        try:
            long_position_vector = LongPositionVector.decode(packet[0:24])
            packet = packet[24:]
            # Ignore Media Dependant Data
            packet = packet[4:]
            # Step 3: execute DAD (§10.2.1.5)
            self.duplicate_address_detection(long_position_vector.gn_addr)
            # Steps 4, 5, 6: update SO LocTE (PV, PDR, IS_NEIGHBOUR)
            self.location_table.new_shb_packet(long_position_vector, packet)
            # Step 7: pass payload to upper entity via GN-DATA.indication (Table 35)
            return GNDataIndication(
                upper_protocol_entity=common_header.nh,
                packet_transport_type=PacketTransportType(
                    header_type=HeaderType.TSB,
                    header_subtype=TopoBroadcastHST.SINGLE_HOP,
                ),
                source_position_vector=long_position_vector,
                traffic_class=common_header.tc,
                remaining_packet_lifetime=float(
                    basic_header.lt.get_value_in_seconds()),
                remaining_hop_limit=basic_header.rhl,
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
        return None

    def gn_data_request_guc(self, request: GNDataRequest) -> GNDataConfirm:
        """
        Handle a GeoUnicast (GUC) GNDataRequest.

        Implements §10.3.8.2 source operations of ETSI EN 302 636-4-1 V1.4.1 (2020-01).

        Parameters
        ----------
        request : GNDataRequest
            GNDataRequest to handle. Must have ``destination`` set to the target GNAddress.
        """
        # Step 1a: Basic Header – LT from request, RHL = itsGnDefaultHopLimit
        hop_limit = self.mib.itsGnDefaultHopLimit if request.max_hop_limit <= 1 else request.max_hop_limit
        basic_header = BasicHeader.initialize_with_mib_request_and_rhl(
            self.mib, request.max_packet_lifetime, hop_limit)
        # Step 1b: Common Header
        _req_with_hl = dataclass_replace(request, max_hop_limit=hop_limit)
        common_header = CommonHeader.initialize_with_request(
            _req_with_hl, self.mib)
        # Step 2: look up DE PV from LocT
        de_entry = self.location_table.get_entry(
            request.destination) if request.destination else None
        if de_entry is None:
            # No LocTE for destination → invoke Location Service (§10.3.7.1.2)
            self.gn_ls_request(request.destination, request)
            return GNDataConfirm(result_code=ResultCode.ACCEPTED)
        de_lpv = de_entry.position_vector
        de_pv = ShortPositionVector(
            gn_addr=de_lpv.gn_addr,
            tst=de_lpv.tst,
            latitude=de_lpv.latitude,
            longitude=de_lpv.longitude,
        )
        # Step 1c: GUC Extended Header
        guc_extended_header = GUCExtendedHeader.initialize_with_request_sequence_number_ego_pv_de_pv(
            self.get_sequence_number(), self.ego_position_vector, de_pv)
        # Step 3: if no neighbours and SCF → buffer (stub)
        if len(self.location_table.get_neighbours()) == 0 and request.traffic_class.scf:
            print("GUC: no neighbours and SCF set; UC forwarding buffer not yet implemented")
            return GNDataConfirm(result_code=ResultCode.ACCEPTED)
        # Step 4: forwarding algorithm (§10.3.8.2 step 4, Annex E.2 – Greedy Forwarding)
        if not self.gn_greedy_forwarding(de_pv.latitude, de_pv.longitude, request.traffic_class):
            # §E.2: local optimum + SCF → buffer in UC forwarding packet buffer (stub)
            return GNDataConfirm(result_code=ResultCode.ACCEPTED)
        # Step 9: pass the GN-PDU to the LL entity
        packet: bytes = (
            basic_header.encode_to_bytes()
            + common_header.encode_to_bytes()
            + guc_extended_header.encode()
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

    def gn_data_indicate_guc(
        self, packet: bytes, common_header: CommonHeader, basic_header: BasicHeader
    ) -> GNDataIndication | None:
        """
        Handle a GeoUnicast (GUC) GeoNetworking packet.

        Implements §10.3.8.3 forwarder and §10.3.8.4 destination operations of
        ETSI EN 302 636-4-1 V1.4.1 (2020-01).

        Parameters
        ----------
        packet : bytes
            GeoNetworking packet to handle (without Basic and Common headers).
        common_header : CommonHeader
            CommonHeader of the packet.
        basic_header : BasicHeader
            BasicHeader of the packet.
        """
        guc_extended_header = GUCExtendedHeader.decode(packet[0:48])
        packet = packet[48:]
        try:
            # Step 3: execute DAD (§10.2.1.5)
            self.duplicate_address_detection(guc_extended_header.so_pv.gn_addr)
            # Steps 5-6: create/update SO LocTE (PV, PDR, IS_NEIGHBOUR per NOTE 2)
            self.location_table.new_guc_packet(guc_extended_header, packet)
            # TODO step 7/8 (forwarder): flush SO LS packet buffer and UC forwarding packet buffer
            is_destination = (
                guc_extended_header.de_pv.gn_addr == self.mib.itsGnLocalGnAddr
            )
            if is_destination:
                # §10.3.8.4: pass payload to upper entity via GN-DATA.indication (Table 29)
                return GNDataIndication(
                    upper_protocol_entity=common_header.nh,
                    packet_transport_type=PacketTransportType(
                        header_type=HeaderType.GEOUNICAST,
                    ),
                    source_position_vector=guc_extended_header.so_pv,
                    traffic_class=common_header.tc,
                    remaining_packet_lifetime=float(
                        basic_header.lt.get_value_in_seconds()),
                    remaining_hop_limit=basic_header.rhl,
                    length=len(packet),
                    data=packet,
                )
            # §10.3.8.3 forwarder operations
            # §B.2: PDR enforcement – do not forward if SO PDR exceeds itsGnMaxPacketDataRate
            so_entry = self.location_table.get_entry(guc_extended_header.so_pv.gn_addr)
            if so_entry is not None and so_entry.pdr > self.mib.itsGnMaxPacketDataRate * 1000:
                return None
            # Step 7: update DE LocTE from packet if not a neighbour, or
            # Step 8: update DE PV in packet from LocT if DE is a neighbour
            de_entry = self.location_table.get_entry(guc_extended_header.de_pv.gn_addr)
            if de_entry is not None and de_entry.is_neighbour:
                # §C.3: only update DE PV in forwarded packet if LocT PV is strictly newer
                if de_entry.position_vector.tst > guc_extended_header.de_pv.tst:
                    # Step 8: refresh DE PV in the forwarded packet from LocT
                    de_lpv = de_entry.position_vector
                    updated_de_pv = ShortPositionVector(
                        gn_addr=de_lpv.gn_addr,
                        tst=de_lpv.tst,
                        latitude=de_lpv.latitude,
                        longitude=de_lpv.longitude,
                    )
                    guc_extended_header = guc_extended_header.with_de_pv(updated_de_pv)
            # Step 9: decrement RHL; if RHL == 0 discard
            new_rhl = basic_header.rhl - 1
            if new_rhl > 0:
                updated_basic_header = basic_header.set_rhl(new_rhl)
                # Step 10: if no neighbour AND SCF: buffer in UC forwarding packet buffer
                if len(self.location_table.get_neighbours()) == 0 and common_header.tc.scf:
                    print(
                        "GUC: no neighbours and SCF set; UC forwarding buffer not yet implemented")
                else:
                    # Step 12: forwarding algorithm (§10.3.8.3, Annex E.2 – Greedy Forwarding)
                    if self.gn_greedy_forwarding(
                        guc_extended_header.de_pv.latitude,
                        guc_extended_header.de_pv.longitude,
                        common_header.tc,
                    ):
                        # Steps 14-15: media-dependent procedures + pass to LL
                        forward_packet = (
                            updated_basic_header.encode_to_bytes()
                            + common_header.encode_to_bytes()
                            + guc_extended_header.encode()
                            + packet
                        )
                        try:
                            if self.link_layer:
                                self.link_layer.send(forward_packet)
                        except PacketTooLongException:
                            pass
                        except SendingException:
                            pass
        except DADException:
            print("Duplicate Address Detected!")
        except IncongruentTimestampException:
            print("Incongruent Timestamp Detected!")
        except DuplicatedPacketException:
            print("Packet is duplicated")
        except DecodeError as e:
            print(str(e))
        return None

    def gn_data_indicate_gac(
        self, packet: bytes, common_header: CommonHeader, basic_header: BasicHeader
    ) -> GNDataIndication | None:
        """
        Handle a GeoAnycast (GAC) GeoNetworking packet.

        Implements §10.3.12.3 forwarder and receiver operations of
        ETSI EN 302 636-4-1 V1.4.1 (2020-01).

        GAC and GBC share the same extended header format (§9.8.5).
        Key distinction from GBC:
          - Inside/at border of area (F ≥ 0): deliver to upper entity and STOP – do NOT forward.
          - Outside area (F < 0): forward only – do NOT deliver to upper layer.

        Parameters
        ----------
        packet : bytes
            GeoNetworking packet to handle (without Basic and Common headers).
        common_header : CommonHeader
            CommonHeader of the packet.
        basic_header : BasicHeader
            BasicHeader of the packet.
        """
        # Header is same wire format as GBC (§9.8.5)
        gbc_extended_header = GBCExtendedHeader.decode(packet[0:44])
        packet = packet[44:]
        area = Area(
            a=gbc_extended_header.a,
            b=gbc_extended_header.b,
            latitude=gbc_extended_header.latitude,
            longitude=gbc_extended_header.longitude,
            angle=gbc_extended_header.angle,
        )
        # Step 7: determine function F(x,y) per ETSI EN 302 931 §5
        area_f = self.gn_geometric_function_f(
            common_header.hst,  # type: ignore
            area,
            self.ego_position_vector.latitude,
            self.ego_position_vector.longitude,
        )
        try:
            # Step 3: DPD – duplicate packet detection (via location table)
            # Step 4: execute DAD (§10.2.1.5)
            self.duplicate_address_detection(gbc_extended_header.so_pv.gn_addr)
            # Steps 5-6: create/update SO LocTE (PV, PDR, IS_NEIGHBOUR per NOTE 1)
            self.location_table.new_gac_packet(gbc_extended_header, packet)
            # TODO Step 8: flush SO LS packet buffer and UC forwarding packet buffer
            # Step 9: inside or at border (F ≥ 0) → deliver to upper entity and STOP
            if area_f >= 0:
                return GNDataIndication(
                    upper_protocol_entity=common_header.nh,
                    packet_transport_type=PacketTransportType(
                        header_type=HeaderType.GEOANYCAST,
                        header_subtype=common_header.hst,
                    ),
                    destination_area=area,
                    source_position_vector=gbc_extended_header.so_pv,
                    traffic_class=common_header.tc,
                    remaining_packet_lifetime=float(
                        basic_header.lt.get_value_in_seconds()),
                    remaining_hop_limit=basic_header.rhl,
                    length=len(packet),
                    data=packet,
                )
            # Step 10: outside area (F < 0) → forward only, no delivery to upper layer
            # §B.3: Geographical area size control – do not forward if area exceeds itsGnMaxGeoAreaSize
            if Router._compute_area_size_m2(common_header.hst, area) > self.mib.itsGnMaxGeoAreaSize * 1_000_000:  # type: ignore
                return None
            # §B.2: PDR enforcement – do not forward if SO PDR exceeds itsGnMaxPacketDataRate
            so_entry = self.location_table.get_entry(gbc_extended_header.so_pv.gn_addr)
            if so_entry is not None and so_entry.pdr > self.mib.itsGnMaxPacketDataRate * 1000:
                return None
            # §D (Annex D): discard if sender is inside/at border of area (SE_POS_VALID AND F_SE ≥ 0)
            if so_entry is not None and so_entry.position_vector.pai:
                f_se = self.gn_geometric_function_f(
                    common_header.hst, area,  # type: ignore
                    so_entry.position_vector.latitude,
                    so_entry.position_vector.longitude,
                )
                if f_se >= 0:
                    return None
            # Step 10a: decrement RHL
            new_rhl = basic_header.rhl - 1
            if new_rhl == 0:
                # Step 10a(i): RHL reached 0 → discard
                return None
            updated_basic_header = basic_header.set_rhl(new_rhl)
            # Step 10b: no neighbours AND SCF → buffer in BC forwarding packet buffer (stub)
            if len(self.location_table.get_neighbours()) == 0 and common_header.tc.scf:
                print(
                    "GAC: no neighbours and SCF set; BC forwarding buffer not yet implemented")
                return None
            # Steps 11-13: §E.2 Greedy Forwarding (NON_AREA) → media-dependent → LL
            if self.gn_greedy_forwarding(area.latitude, area.longitude, common_header.tc):
                forward_packet = (
                    updated_basic_header.encode_to_bytes()
                    + common_header.encode_to_bytes()
                    + gbc_extended_header.encode()
                    + packet
                )
                try:
                    if self.link_layer:
                        self.link_layer.send(forward_packet)
                except PacketTooLongException:
                    pass
                except SendingException:
                    pass
        except DADException:
            print("Duplicate Address Detected!")
        except IncongruentTimestampException:
            print("Incongruent Timestamp Detected!")
        except DuplicatedPacketException:
            print("Packet is duplicated")
        except DecodeError as e:
            print(str(e))
        return None

    # -------------------------------------------------------------------------
    # Location Service (LS) – §10.3.7
    # -------------------------------------------------------------------------

    def _send_ls_request_packet(self, sought_gn_addr: GNAddress) -> None:
        """
        Build and broadcast an LS Request packet for *sought_gn_addr*.

        §10.3.7.1.2 step 2 of ETSI EN 302 636-4-1 V1.4.1 (2020-01).
        The packet uses HT=LS / HST=LS_REQUEST and travels on the broadcast LL
        address (same distribution as TSB multi-hop).
        """
        with self.ego_position_vector_lock:
            ego_pv = self.ego_position_vector
        basic_header = BasicHeader.initialize_with_mib_request_and_rhl(
            self.mib, None, self.mib.itsGnDefaultHopLimit)
        common_header = CommonHeader(
            nh=CommonNH.ANY,
            ht=HeaderType.LS,
            hst=LocationServiceHST.LS_REQUEST,
            tc=TrafficClass(),
            flags=self.mib.itsGnIsMobile.value,
            pl=0,
            mhl=self.mib.itsGnDefaultHopLimit,
        )
        ls_req_header = LSRequestExtendedHeader.initialize(
            self.get_sequence_number(), ego_pv, sought_gn_addr)
        packet = (
            basic_header.encode_to_bytes()
            + common_header.encode_to_bytes()
            + ls_req_header.encode()
        )
        try:
            if self.link_layer:
                self.link_layer.send(packet)
        except (PacketTooLongException, SendingException):
            pass

    def gn_ls_request(
        self, sought_gn_addr: GNAddress, buffered_request: GNDataRequest | None = None
    ) -> None:
        """
        Initiate or update a Location Service (LS) request for *sought_gn_addr*.

        Implements source operations of §10.3.7.1.2 of
        ETSI EN 302 636-4-1 V1.4.1 (2020-01):

        * If an LS is already in progress (ls_pending=TRUE) for the sought
          address, the optional *buffered_request* is queued for later delivery
          and the method returns immediately.
        * Otherwise a new LS Request packet is built and broadcast, a
          retransmit timer TLS is started and the LocTE ls_pending flag is set
          to TRUE.

        Parameters
        ----------
        sought_gn_addr : GNAddress
            GN address of the sought GeoAdhoc router.
        buffered_request : GNDataRequest | None
            Optional GNDataRequest whose processing triggered this LS. It will
            be (re-)processed automatically when the LS Reply is received.
        """
        with self._ls_lock:
            entry = self.location_table.get_entry(sought_gn_addr)
            if entry is not None and entry.ls_pending:
                # LS already in-progress → just queue the request
                if buffered_request is not None:
                    self._ls_packet_buffers.setdefault(sought_gn_addr, []).append(buffered_request)
                return
            # Create or fetch LocTE and set ls_pending
            entry = self.location_table.ensure_entry(sought_gn_addr)
            entry.ls_pending = True
            self._ls_packet_buffers[sought_gn_addr] = (
                [buffered_request] if buffered_request is not None else []
            )
            self._ls_retransmit_counters[sought_gn_addr] = 0
        # Send LS Request and start retransmit timer (outside lock to avoid deadlock)
        self._send_ls_request_packet(sought_gn_addr)
        timer = Timer(
            self.mib.itsGnLocationServiceRetransmitTimer / 1000.0,
            self._ls_retransmit, args=[sought_gn_addr]
        )
        timer.daemon = True
        timer.start()
        with self._ls_lock:
            old = self._ls_timers.pop(sought_gn_addr, None)
            if old:
                old.cancel()
            self._ls_timers[sought_gn_addr] = timer

    def _ls_retransmit(self, sought_gn_addr: GNAddress) -> None:
        """
        Retransmit timer callback for an ongoing LS Request.

        Implements §10.3.7.1.3 of ETSI EN 302 636-4-1 V1.4.1 (2020-01):

        * If the retransmit counter is below *itsGnLocationServiceMaxRetrans*,
          the LS Request is resent and the timer is restarted.
        * Otherwise the LS is abandoned: buffered requests are discarded and
          ls_pending is set back to FALSE.
        """
        with self._ls_lock:
            count = self._ls_retransmit_counters.get(sought_gn_addr, 0)
            if count >= self.mib.itsGnLocationServiceMaxRetrans:
                # Give up
                self._ls_packet_buffers.pop(sought_gn_addr, None)
                self._ls_timers.pop(sought_gn_addr, None)
                self._ls_retransmit_counters.pop(sought_gn_addr, None)
                entry = self.location_table.get_entry(sought_gn_addr)
                if entry is not None:
                    entry.ls_pending = False
                return
            self._ls_retransmit_counters[sought_gn_addr] = count + 1
        # Resend and restart timer
        self._send_ls_request_packet(sought_gn_addr)
        timer = Timer(
            self.mib.itsGnLocationServiceRetransmitTimer / 1000.0,
            self._ls_retransmit, args=[sought_gn_addr]
        )
        timer.daemon = True
        timer.start()
        with self._ls_lock:
            self._ls_timers[sought_gn_addr] = timer

    def gn_data_indicate_ls_request(
        self, packet: bytes, common_header: CommonHeader, basic_header: BasicHeader
    ) -> None:
        """
        Handle an incoming LS Request packet.

        Implements §10.3.7.2 (forwarder) and §10.3.7.3 (destination) of
        ETSI EN 302 636-4-1 V1.4.1 (2020-01).

        * **Destination** (Request_GN_ADDR == own address): perform DPD/DAD,
          update SO LocTE, then send an LS Reply unicast back to the requester.
        * **Forwarder** (all other nodes): perform DPD/DAD, update SO LocTE,
          decrement RHL and re-broadcast without delivering to the upper layer.

        Parameters
        ----------
        packet : bytes
            GeoNetworking packet body after Basic and Common headers.
        common_header : CommonHeader
            Common header of the received packet.
        basic_header : BasicHeader
            Basic header of the received packet.
        """
        ls_request_header = LSRequestExtendedHeader.decode(packet[0:36])
        payload = packet[36:]
        try:
            # Step 3-4: DPD + DAD
            self.duplicate_address_detection(ls_request_header.so_pv.gn_addr)
            # Step 5-6: update SO LocTE
            self.location_table.new_ls_request_packet(ls_request_header, payload)
            # Step 7: check if we are the destination
            if ls_request_header.request_gn_addr == self.mib.itsGnLocalGnAddr:
                # §10.3.7.3: we are the destination – send LS Reply
                so_entry = self.location_table.get_entry(ls_request_header.so_pv.gn_addr)
                if so_entry is None:
                    return
                so_lpv = so_entry.position_vector
                de_pv = ShortPositionVector(
                    gn_addr=so_lpv.gn_addr,
                    tst=so_lpv.tst,
                    latitude=so_lpv.latitude,
                    longitude=so_lpv.longitude,
                )
                with self.ego_position_vector_lock:
                    ego_pv = self.ego_position_vector
                reply_basic = BasicHeader.initialize_with_mib_request_and_rhl(
                    self.mib, None, self.mib.itsGnDefaultHopLimit)
                reply_common = CommonHeader(
                    nh=CommonNH.ANY,
                    ht=HeaderType.LS,
                    hst=LocationServiceHST.LS_REPLY,
                    tc=TrafficClass(),
                    flags=self.mib.itsGnIsMobile.value,
                    pl=0,
                    mhl=self.mib.itsGnDefaultHopLimit,
                )
                reply_header = LSReplyExtendedHeader.initialize(
                    self.get_sequence_number(), ego_pv, de_pv)
                reply_packet = (
                    reply_basic.encode_to_bytes()
                    + reply_common.encode_to_bytes()
                    + reply_header.encode()
                )
                try:
                    if self.link_layer:
                        self.link_layer.send(reply_packet)
                except (PacketTooLongException, SendingException):
                    pass
            else:
                # §10.3.7.2 forwarder: re-broadcast like TSB but no upper-layer delivery
                # §B.2: PDR enforcement – do not forward if SO PDR exceeds itsGnMaxPacketDataRate
                so_entry = self.location_table.get_entry(ls_request_header.so_pv.gn_addr)
                if so_entry is not None and so_entry.pdr > self.mib.itsGnMaxPacketDataRate * 1000:
                    return
                new_rhl = basic_header.rhl - 1
                if new_rhl > 0:
                    updated_basic_header = basic_header.set_rhl(new_rhl)
                    forward_packet = (
                        updated_basic_header.encode_to_bytes()
                        + common_header.encode_to_bytes()
                        + ls_request_header.encode()
                        + payload
                    )
                    try:
                        if self.link_layer:
                            self.link_layer.send(forward_packet)
                    except (PacketTooLongException, SendingException):
                        pass
        except DADException:
            print("Duplicate Address Detected!")
        except IncongruentTimestampException:
            print("Incongruent Timestamp Detected!")
        except DuplicatedPacketException:
            print("Packet is duplicated")
        except DecodeError as e:
            print(str(e))

    def gn_data_indicate_ls_reply(
        self, packet: bytes, common_header: CommonHeader, basic_header: BasicHeader
    ) -> None:
        """
        Handle an incoming LS Reply packet.

        Implements §10.3.7.1.4 (source receives reply) and §10.3.7.2 (forwarder)
        of ETSI EN 302 636-4-1 V1.4.1 (2020-01).

        * **Source** (DE_GN_ADDR == own address): update SO LocTE, stop the
          retransmit timer, reset the counter, set ls_pending=FALSE and flush
          the LS packet buffer by re-invoking each buffered ``GNDataRequest``.
        * **Forwarder**: update SO LocTE, decrement RHL and forward like GUC.

        Parameters
        ----------
        packet : bytes
            GeoNetworking packet body after Basic and Common headers.
        common_header : CommonHeader
            Common header of the received packet.
        basic_header : BasicHeader
            Basic header of the received packet.
        """
        ls_reply_header = LSReplyExtendedHeader.decode(packet[0:48])
        payload = packet[48:]
        try:
            # Steps 2-3: DPD + DAD
            self.duplicate_address_detection(ls_reply_header.so_pv.gn_addr)
            # Steps 4-5: update SO LocTE
            self.location_table.new_ls_reply_packet(ls_reply_header, payload)
            # Determine role: source vs. forwarder
            sought_gn_addr = ls_reply_header.so_pv.gn_addr
            if ls_reply_header.de_pv.gn_addr == self.mib.itsGnLocalGnAddr:
                # §10.3.7.1.4: we are the original requester
                buffered: list[GNDataRequest] = []
                with self._ls_lock:
                    timer = self._ls_timers.pop(sought_gn_addr, None)
                    self._ls_retransmit_counters.pop(sought_gn_addr, None)
                    buffered = self._ls_packet_buffers.pop(sought_gn_addr, [])
                    entry = self.location_table.get_entry(sought_gn_addr)
                    if entry is not None:
                        entry.ls_pending = False
                if timer is not None:
                    timer.cancel()
                # Flush LS packet buffer: re-process each buffered request now
                # that the LocTE is available
                for req in buffered:
                    self.gn_data_request_guc(req)
            else:
                # §10.3.7.2 forwarder: forward like GUC forwarder
                # §B.2: PDR enforcement – do not forward if SO PDR exceeds itsGnMaxPacketDataRate
                so_entry = self.location_table.get_entry(ls_reply_header.so_pv.gn_addr)
                if so_entry is not None and so_entry.pdr > self.mib.itsGnMaxPacketDataRate * 1000:
                    return
                de_entry = self.location_table.get_entry(ls_reply_header.de_pv.gn_addr)
                if de_entry is not None and de_entry.is_neighbour:
                    # §C.3: only update DE PV in forwarded packet if LocT PV is strictly newer
                    if de_entry.position_vector.tst > ls_reply_header.de_pv.tst:
                        de_lpv = de_entry.position_vector
                        updated_de_pv = ShortPositionVector(
                            gn_addr=de_lpv.gn_addr,
                            tst=de_lpv.tst,
                            latitude=de_lpv.latitude,
                            longitude=de_lpv.longitude,
                        )
                        ls_reply_header = ls_reply_header.__class__(
                            sn=ls_reply_header.sn,
                            reserved=ls_reply_header.reserved,
                            so_pv=ls_reply_header.so_pv,
                            de_pv=updated_de_pv,
                        )
                new_rhl = basic_header.rhl - 1
                if new_rhl > 0:
                    updated_basic_header = basic_header.set_rhl(new_rhl)
                    forward_packet = (
                        updated_basic_header.encode_to_bytes()
                        + common_header.encode_to_bytes()
                        + ls_reply_header.encode()
                        + payload
                    )
                    try:
                        if self.link_layer:
                            self.link_layer.send(forward_packet)
                    except (PacketTooLongException, SendingException):
                        pass
        except DADException:
            print("Duplicate Address Detected!")
        except IncongruentTimestampException:
            print("Incongruent Timestamp Detected!")
        except DuplicatedPacketException:
            print("Packet is duplicated")
        except DecodeError as e:
            print(str(e))

    def gn_data_indicate_ls(
        self, packet: bytes, common_header: CommonHeader, basic_header: BasicHeader
    ) -> None:
        """
        Dispatch an incoming Location Service (LS) packet.

        Calls either :meth:`gn_data_indicate_ls_request` or
        :meth:`gn_data_indicate_ls_reply` based on the Common Header HST field.

        Parameters
        ----------
        packet : bytes
            GeoNetworking packet body after Basic and Common headers.
        common_header : CommonHeader
            Common header of the received packet.
        basic_header : BasicHeader
            Basic header of the received packet.
        """
        if common_header.hst == LocationServiceHST.LS_REQUEST:
            self.gn_data_indicate_ls_request(packet, common_header, basic_header)
        elif common_header.hst == LocationServiceHST.LS_REPLY:
            self.gn_data_indicate_ls_reply(packet, common_header, basic_header)
        else:
            raise NotImplementedError(f"Unknown LS HST: {common_header.hst}")

    def gn_data_indicate_gbc(
        self, packet: bytes, common_header: CommonHeader, basic_header: BasicHeader
    ) -> GNDataIndication | None:
        """
        Handle a GeoBroadcast GeoNetworking packet.

        Implements §10.3.11.3 forwarder and receiver operations.

        Parameters
        ----------
        packet : bytes
            GeoNetworking packet to handle (without Basic and Common headers).
        common_header : CommonHeader
            CommonHeader of the packet.
        basic_header : BasicHeader
            BasicHeader of the packet; used for remaining LT and RHL (Table 38).
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
        # Step 3: DPD (Duplicate Packet Detection) – run before DAD for GREEDY/SIMPLE/UNSPECIFIED
        # forwarding algorithms (§10.3.11.3 step 3a/3b)
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
            # Step 4: execute DAD (§10.2.1.5)
            self.duplicate_address_detection(gbc_extended_header.so_pv.gn_addr)
            # Steps 5-6: update SO LocTE
            self.location_table.new_gbc_packet(gbc_extended_header, packet)
            indication: GNDataIndication | None = None
            # Step 7: if inside/at border of area, pass payload to upper entity via GN-DATA.indication (Table 38)
            if area_f >= 0:
                indication = GNDataIndication(
                    upper_protocol_entity=common_header.nh,
                    packet_transport_type=PacketTransportType(
                        header_type=HeaderType.GEOBROADCAST,
                        header_subtype=common_header.hst
                    ),
                    destination_area=area,
                    source_position_vector=gbc_extended_header.so_pv,
                    traffic_class=common_header.tc,
                    remaining_packet_lifetime=float(
                        basic_header.lt.get_value_in_seconds()),
                    remaining_hop_limit=basic_header.rhl,
                    length=len(packet),
                    data=packet
                )
            # TODO: Step 8: flush LS packet buffer and UC forwarding packet buffer for SO
            # §B.3: Geographical area size control – do not forward if area exceeds itsGnMaxGeoAreaSize
            if Router._compute_area_size_m2(common_header.hst, area) > self.mib.itsGnMaxGeoAreaSize * 1_000_000:  # type: ignore
                return indication
            # §B.2: PDR enforcement – do not forward if SO PDR exceeds itsGnMaxPacketDataRate
            so_entry = self.location_table.get_entry(gbc_extended_header.so_pv.gn_addr)
            if so_entry is not None and so_entry.pdr > self.mib.itsGnMaxPacketDataRate * 1000:
                return indication
            # Step 9: decrement RHL; if RHL == 0 discard
            new_rhl = basic_header.rhl - 1
            if new_rhl > 0:
                # Steps 10-14: forward according to §10.3.11.3
                self.gn_data_forward_gbc(
                    basic_header, common_header, gbc_extended_header, packet)
            return indication
        except DADException:
            print("Duplicate Address Detected!")
        except IncongruentTimestampException:
            print("Incongruent Timestamp Detected!")
        except DuplicatedPacketException:
            print("Packet is duplicated")
        except DecodeError as e:
            print(str(e))
        return None

    def gn_data_indicate_tsb(
        self, packet: bytes, common_header: CommonHeader, basic_header: BasicHeader
    ) -> GNDataIndication | None:
        """
        Handle a Topologically-Scoped Broadcast (multi-hop) GeoNetworking packet.

        Implements §10.3.9.3 forwarder and receiver operations.

        Parameters
        ----------
        packet : bytes
            GeoNetworking packet to handle (without Basic and Common headers).
        common_header : CommonHeader
            CommonHeader of the packet.
        basic_header : BasicHeader
            BasicHeader of the packet; used for remaining LT and RHL (Table 32).
        """
        tsb_extended_header = TSBExtendedHeader.decode(packet[0:28])
        packet = packet[28:]
        try:
            # Step 3: DPD – duplicate packet detection (via location table)
            # Step 4: execute DAD (§10.2.1.5)
            self.duplicate_address_detection(tsb_extended_header.so_pv.gn_addr)
            # Steps 5-6: create/update SO LocTE (PV, PDR, IS_NEIGHBOUR per NOTE 1)
            self.location_table.new_tsb_packet(tsb_extended_header, packet)
            # Step 7: pass payload to upper entity via GN-DATA.indication (Table 32)
            indication = GNDataIndication(
                upper_protocol_entity=common_header.nh,
                packet_transport_type=PacketTransportType(
                    header_type=HeaderType.TSB,
                    header_subtype=TopoBroadcastHST.MULTI_HOP,
                ),
                source_position_vector=tsb_extended_header.so_pv,
                traffic_class=common_header.tc,
                remaining_packet_lifetime=float(
                    basic_header.lt.get_value_in_seconds()),
                remaining_hop_limit=basic_header.rhl,
                length=len(packet),
                data=packet
            )
            # TODO Step 8: flush SO LS packet buffer and UC forwarding packet buffer
            # §B.2: PDR enforcement – do not forward if SO PDR exceeds itsGnMaxPacketDataRate
            so_entry = self.location_table.get_entry(tsb_extended_header.so_pv.gn_addr)
            if so_entry is not None and so_entry.pdr > self.mib.itsGnMaxPacketDataRate * 1000:
                return indication
            # Step 9: decrement RHL; if RHL == 0 discard
            new_rhl = basic_header.rhl - 1
            if new_rhl > 0:
                updated_basic_header = basic_header.set_rhl(new_rhl)
                # Step 10: if no neighbour AND SCF: buffer in BC forwarding packet buffer
                if len(self.location_table.get_neighbours()) == 0 and common_header.tc.scf:
                    print(
                        "TSB: no neighbours and SCF set; BC forwarding buffer not yet implemented")
                else:
                    # Steps 11-12: execute media-dependent procedures and pass to LL
                    forward_packet = (
                        updated_basic_header.encode_to_bytes()
                        + common_header.encode_to_bytes()
                        + tsb_extended_header.encode()
                        + packet
                    )
                    try:
                        if self.link_layer:
                            self.link_layer.send(forward_packet)
                    except PacketTooLongException:
                        pass
                    except SendingException:
                        pass
            return indication
        except DADException:
            print("Duplicate Address Detected!")
        except IncongruentTimestampException:
            print("Incongruent Timestamp Detected!")
        except DuplicatedPacketException:
            print("Packet is duplicated")
        except DecodeError as e:
            print(str(e))
        return None

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
        # ETSI EN 302 636-4-1 V1.4.1 (2020-01). Section 10.3.6.3:
        # Receiver operations are identical to SHB (§10.3.10.3) except step 8.
        try:
            long_position_vector = LongPositionVector.decode(packet[0:24])
            packet = packet[24:]
            # Step 3: execute DAD (§10.2.1.5)
            self.duplicate_address_detection(long_position_vector.gn_addr)
            # Steps 4-6: update SO LocTE (PV, PDR, IS_NEIGHBOUR)
            self.location_table.new_shb_packet(long_position_vector, packet)
        except DADException:
            print("Duplicate Address Detected!")
        except IncongruentTimestampException:
            print("Incongruent Timestamp Detected!")
        except DuplicatedPacketException:
            print("Packet is duplicated")
        except DecodeError as e:
            print(str(e))

    def process_basic_header(self, packet: bytes) -> None:
        # ETSI EN 302 636-4-1 V1.4.1 (2020-01). Section 10.3.3
        # Decap the basic header
        basic_header = BasicHeader.decode_from_bytes(packet[0:4])
        remaining = packet[4:]
        if basic_header.version != self.mib.itsGnProtocolVersion:
            raise NotImplementedError("Version not implemented")
        if basic_header.nh == BasicNH.COMMON_HEADER:
            # When itsGnSecurity is ENABLED, unsecured packets must be discarded
            # (only secured packets with NH=SECURED_PACKET are accepted).
            if self.mib.itsGnSecurity == GnSecurity.ENABLED:
                return
            self.process_common_header(remaining, basic_header)
        elif basic_header.nh == BasicNH.SECURED_PACKET:
            self.process_security_header(remaining, basic_header)
        else:
            raise NotImplementedError("ANY next header not implemented")

    def process_common_header(self, packet: bytes, basic_header: BasicHeader) -> None:
        indication = GNDataIndication()
        # ETSI EN 302 636-4-1 V1.4.1 (2020-01). Section 10.3.5
        # Decap the common header
        common_header = CommonHeader.decode_from_bytes(packet[0:8])
        packet = packet[8:]
        if basic_header.rhl > common_header.mhl:
            raise DecapError("Hop limit exceeded")
        # TODO: Forwarding packet buffer flush
        if common_header.ht == HeaderType.ANY:
            raise NotImplementedError(
                "Any packet (Common Header) not implemented")
        elif common_header.ht == HeaderType.BEACON:
            self.gn_data_indicate_beacon(packet)
            return
        elif common_header.ht == HeaderType.GEOUNICAST:
            indication = self.gn_data_indicate_guc(
                packet, common_header, basic_header)
        elif common_header.ht == HeaderType.GEOANYCAST:
            indication = self.gn_data_indicate_gac(
                packet, common_header, basic_header)
        elif common_header.ht == HeaderType.GEOBROADCAST:
            indication = self.gn_data_indicate_gbc(
                packet, common_header, basic_header)
        elif common_header.ht == HeaderType.TSB:
            if common_header.hst == TopoBroadcastHST.SINGLE_HOP:
                indication = self.gn_data_indicate_shb(
                    packet, common_header, basic_header)
            elif common_header.hst == TopoBroadcastHST.MULTI_HOP:
                indication = self.gn_data_indicate_tsb(
                    packet, common_header, basic_header)
            else:
                raise NotImplementedError("TopoBroadcast not implemented")
        elif common_header.ht == HeaderType.LS:
            self.gn_data_indicate_ls(packet, common_header, basic_header)
            return  # LS handling never delivers to upper entity callback
        else:
            raise NotImplementedError(
                "Any packet (Common Header) not implemented")
        if self.indication_callback and indication is not None:
            self.indication_callback(indication)

    def process_security_header(self, packet: bytes, basic_header: BasicHeader) -> None:
        # ETSI EN 302 636-4-1 V1.4.1 (2020-01). Section 10.3.3 - Secured packet processing
        # 1) If no verify service is configured, discard the packet silently.
        if self.verify_service is None:
            print("Secured packet received but no VerifyService configured, discarding")
            return
        # 2) Verify the secured packet using the SN-VERIFY service (ETSI TS 102 723-8).
        verify_confirm = self.verify_service.verify(
            SNVERIFYRequest(
                sec_header=b"",
                sec_header_length=0,
                message=packet,
                message_length=len(packet),
            )
        )
        if verify_confirm.report != ReportVerify.SUCCESS:
            print(
                f"Secured packet verification failed: {verify_confirm.report}")
            return
        # 3) Dispatch directly from the decrypted plain_message without byte
        #    reconstruction or recursive calls.
        #    plain_message layout: Common Header (8 bytes) | Extended Header + payload
        processed_packet = verify_confirm.plain_message
        self.process_common_header(processed_packet, basic_header.set_nh(BasicNH.COMMON_HEADER))

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
        self.process_basic_header(packet)

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
