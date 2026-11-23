from __future__ import annotations
from collections.abc import Callable
from dataclasses import dataclass, replace as dataclass_replace
from enum import Enum
from threading import Thread, Lock, RLock, Event
from typing import Optional, Tuple, Union, cast
import logging
import math
import random
import time
from ..linklayer.exceptions import (
    SendingException,
    PacketTooLongException,
)
from .mib import (
    MIB,
    GnIfType,
    GnSecurity,
    LocalGnAddrConfMethod,
    NonAreaForwardingAlgorithm,
    AreaForwardingAlgorithm,
)
from .gn_address import MID, GNAddress
from .dcc_net import DccNet
from .service_access_point import (
    CommonNH,
    HeaderType,
    HeaderSubType,
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
from .basic_header import BasicNH, BasicHeader, LT
from .common_header import CommonHeader
from .gbc_extended_header import GBCExtendedHeader
from .tsb_extended_header import TSBExtendedHeader
from .guc_extended_header import GUCExtendedHeader
from .ls_extended_header import LSRequestExtendedHeader, LSReplyExtendedHeader
from .position_vector import LongPositionVector, ShortPositionVector
from .location_table import LocationTable, LocationTableEntry
from .packet_buffer import (
    CbfPacketBuffer,
    PacketBuffer,
    cbf_timeout_ms,
    cbf_timeout_update_ms,
)
from ..linklayer.link_layer import LinkLayer
from ..security.sign_service import SignService, SigningError
from ..security.verify_service import VerifyService
from ..security.security_profiles import SecurityProfile
from ..security.sn_sap import SNSIGNConfirm, SNSIGNRequest, SNVERIFYConfirm, SNVERIFYRequest, ReportVerify
from .exceptions import (
    DADException,
    DecapError,
    DecodeError,
    DuplicatedPacketException,
    IncongruentTimestampException,
)

EARTH_RADIUS = 6371000  # Radius of the Earth in meters
# Octets of a Basic + Common + GUC Extended Header, used to size LS-buffered requests.
_GUC_HEADERS_LENGTH = 4 + 8 + 48
# ITS-AID of GeoNetworking management (Beacons), ETSI TS 103 836-4-1 V2.2.1
# clause 10.3.6.2 table 22.
ITS_AID_GN_MGMT = 141


class RouteKind(Enum):
    """How a buffered GN-PDU is forwarded when its buffer is flushed."""

    BROADCAST = 1   # SHB, TSB and LS Request: no forwarding algorithm
    AREA = 2        # GBC and GAC: Annex D, then area or non-area forwarding
    UNICAST = 3     # GUC and LS Reply: non-area forwarding towards the DE PV


@dataclass
class BufferedPacket:
    """
    A GN-PDU together with the information needed to (re-)execute its
    forwarding algorithm (ETSI TS 103 836-4-1 V2.2.1, clauses 8.5, 8.6 and
    10.3.5 NOTE 1).

    ``body`` holds the octets that follow the Basic Header: the Common Header,
    Extended Header and payload or, for a secured packet, the Secured Packet,
    which forwarders relay unmodified.
    """

    basic_header: BasicHeader
    body: bytes
    traffic_class: TrafficClass
    kind: RouteKind
    so_pv: Optional[LongPositionVector] = None
    sn: Optional[int] = None
    area_type: Optional[Union[GeoBroadcastHST, GeoAnycastHST]] = None
    area: Optional[Area] = None
    destination: Optional[ShortPositionVector] = None
    sender_ll_address: Optional[bytes] = None
    area_mode: bool = False
    # Originated by this router: a buffered source packet is sent as a source
    # when flushed (clause 10.3.5 step 2 re-executes the source operation).
    origin: bool = False

    def encode(self) -> bytes:
        """The GN-PDU: Basic Header followed by the body."""
        return self.basic_header.encode_to_bytes() + self.body

    @property
    def key(self) -> Tuple[GNAddress, int]:
        """Packet identifier (source GN_ADDR, sequence number)."""
        assert self.so_pv is not None and self.sn is not None
        return (self.so_pv.gn_addr, self.sn)


class GNForwardingAlgorithmResponse(Enum):
    """
    GN Forwarding Algorithm Selection Response. As specified in ETSI TS 103 836-4-1 V2.2.1 (2026-04). Annex D.

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

    Handles the routing of Geonetworking packets. As specified in ETSI TS 103 836-4-1 V2.2.1 (2026-04).

    """

    def __init__(
        self,
        mib: MIB,
        sign_service: SignService | None = None,
        verify_service: VerifyService | None = None,
        clock: Callable[[], int] | None = None,
        dcc_net: DccNet | None = None,
    ) -> None:
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
        clock : Callable[[], int] | None
            Monotonic clock in milliseconds driving the packet-buffer and
            Location Service timers. When given, no timer thread is started and
            the caller drives the timers with :meth:`tick`.
        dcc_net : DccNet | None
            DCC_NET entity for GN over ITS-G5 (ETSI TS 103 836-4-2 clauses 5
            to 7): SHBs carry the DCC-MCO field and received SHBs update the
            LocTEX-G5. Without it the DCC-MCO field is zero-filled.
        """
        self.mib = mib
        self.dcc_net: DccNet | None = dcc_net
        self.ego_position_vector_lock = Lock()
        self.ego_position_vector = LongPositionVector()
        self.setup_gn_address()
        self.link_layer: LinkLayer | None = None
        self.location_table = LocationTable(mib, clock=lambda: self._clock())
        self.sign_service: SignService | None = sign_service
        self.verify_service: VerifyService | None = verify_service
        # Called with (secured message, SN-VERIFY.confirm) for every received
        # secured packet, verified or not (see set_verify_observer).
        self.verify_observer: Callable[[bytes, SNVERIFYConfirm], None] | None = None
        self.indication_callback = None
        # Called with the new GN address after a duplicate address (clause
        # 10.2.1.5 step 3), e.g. to set the ITS-G5 interface MAC to the new MID.
        self.address_change_callback: Callable[[GNAddress], None] | None = None
        self.sequence_number_lock = Lock()
        self.sequence_number = 0
        self._clock: Callable[[], int] = clock or (lambda: int(time.monotonic() * 1000))
        self._run_timer_thread = clock is None
        self._timer_thread: Thread | None = None
        self._timer_wakeup = Event()
        # Packet buffers and Location Service state (clauses 8.5, 8.6, 10.2.4),
        # guarded by one re-entrant lock.
        self._buffers_lock = RLock()
        self._ls_deadlines: dict[GNAddress, int] = {}           # TLS expiry (ms)
        self._ls_retransmit_counters: dict[GNAddress, int] = {}  # RTCLS
        self._ls_packet_buffers: dict[GNAddress, PacketBuffer[GNDataRequest]] = {}
        self._uc_buffers: dict[GNAddress, PacketBuffer[BufferedPacket]] = {}
        self._bc_buffer: PacketBuffer[BufferedPacket] = PacketBuffer(
            self.mib.itsGnBcForwardingPacketBufferSize * 1024)
        self._cbf_buffer: CbfPacketBuffer[Tuple[GNAddress, int], BufferedPacket] = (
            CbfPacketBuffer(self.mib.itsGnCbfPacketBufferSize * 1024))
        # Beacon service (clause 10.3.6.2) on the router clock; the first
        # Beacon is sent after half a period.
        self._beacon_deadline: int | None = (
            self._clock() + self.mib.itsGnBeaconServiceRetransmitTimer // 2
            if self.mib.itsGnBeaconServiceRetransmitTimer > 0 else None)
        if self.dcc_net is not None or self._beacon_deadline is not None:
            self._schedule_timers()       # CBR_G trigger (clause 5.3), TBeacon

    def _restart_beacon_timer(self, now_ms: int) -> None:
        """
        Restart TBeacon = itsGnBeaconServiceRetransmitTimer +
        RAND[0, itsGnBeaconServiceMaxJitter] (clause 10.3.6.2 step 5); also
        called when an SHB is sent (clause 10.3.10.2 step 7).
        """
        if self._beacon_deadline is None:
            return
        jitter_ms = random.uniform(0, self.mib.itsGnBeaconServiceMaxJitter or 0)
        self._beacon_deadline = now_ms + self.mib.itsGnBeaconServiceRetransmitTimer + int(jitter_ms)

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
        body = common_header.encode_to_bytes() + self.ego_position_vector.encode()
        packet = basic_header.encode_to_bytes() + body
        # Clause 10.3.6.2 step 2: with itsGnSecurity ENABLED the Common Header
        # and Beacon Extended Header are signed with ITS-AID 141 (GN-MGMT,
        # table 22). No AT may sign: no Beacon.
        secured = self._sign_mgmt(basic_header, body)
        if secured is None:
            return
        packet = secured[0].encode_to_bytes() + secured[1]

        try:
            if self.link_layer:
                self.link_layer.send(packet)
        except PacketTooLongException:
            pass
        except SendingException:
            pass

    def get_sequence_number(self) -> int:
        """
        Sequence number of the next multi-hop packet (clause 8.4): the local SEQN,
        initialized to 0, then incremented modulo 2^16.

        Returns
        -------
        int
            Sequence number to include in the packet.
        """
        with self.sequence_number_lock:
            sequence_number = self.sequence_number
            self.sequence_number = (sequence_number + 1) % 2**16
            return sequence_number

    # -------------------------------------------------------------------------
    # Timers (Location Service TLS and CBF timers), clock-driven
    # -------------------------------------------------------------------------

    def next_deadline(self) -> int | None:
        """Earliest pending LS, CBF or DCC_NET (CBR_G) timer expiry (ms on the router clock)."""
        with self._buffers_lock:
            deadlines = list(self._ls_deadlines.values())
            cbf = self._cbf_buffer.next_deadline()
        if cbf is not None:
            deadlines.append(cbf)
        if self.dcc_net is not None:
            deadlines.append(self.dcc_net.next_trigger(self._clock()))
        if self._beacon_deadline is not None:
            deadlines.append(self._beacon_deadline)
        return min(deadlines, default=None)

    def tick(self, now_ms: int | None = None) -> None:
        """
        Process the expired timers: Beacon (clause 10.3.6.2), LS Request
        retransmission (clause 10.3.7.1.3) and CBF timer expiry (clauses E.3.5,
        F.3.5).
        """
        now = self._clock() if now_ms is None else now_ms
        # DCC_NET: CBR_G every itsGNCBRGTriggerInterval (TS 103 836-4-2 clause 5.3)
        if self.dcc_net is not None and self.dcc_net.next_trigger(now) <= now:
            self.dcc_net.trigger(now)
        # Beacon service (clause 10.3.6.2): send a Beacon when TBeacon expires.
        if self._beacon_deadline is not None and self._beacon_deadline <= now:
            self.gn_data_request_beacon()
            self._restart_beacon_timer(now)
        with self._buffers_lock:
            for gn_addr, deadline in list(self._ls_deadlines.items()):
                if deadline <= now:
                    self._ls_retransmit(gn_addr, now)
            expired = self._cbf_buffer.pop_expired(now)
        # TO_ACC is not provided by the Access Layer (set to zero): re-broadcast.
        for _, packet, remaining_ms in expired:
            self._send_to_link_layer(self._with_remaining_lifetime(packet, remaining_ms).encode())

    def _schedule_timers(self) -> None:
        """Wake (or start) the timer thread after a timer was (re)started."""
        if not self._run_timer_thread:
            return
        if self._timer_thread is None:
            self._timer_thread = Thread(target=self._timer_loop, daemon=True)
            self._timer_thread.start()
        self._timer_wakeup.set()

    def _timer_loop(self) -> None:
        while True:
            deadline = self.next_deadline()
            timeout = None if deadline is None else max(0, deadline - self._clock()) / 1000
            if self._timer_wakeup.wait(timeout):
                self._timer_wakeup.clear()
            self.tick()

    # -------------------------------------------------------------------------
    # Packet buffers (clauses 8.5, 8.6)
    # -------------------------------------------------------------------------

    def _send_to_link_layer(self, packet: bytes, destination: bytes | None = None) -> GNDataConfirm:
        """
        Pass a GN-PDU to the ALI with the link-layer address of the next hop,
        or with the Broadcast address when ``destination`` is None.
        """
        try:
            if self.link_layer:
                if destination is None:
                    self.link_layer.send(packet)
                else:
                    self.link_layer.send(packet, destination)
        except PacketTooLongException:
            return GNDataConfirm(result_code=ResultCode.MAXIMUM_LENGTH_EXCEEDED)
        except SendingException:
            return GNDataConfirm(result_code=ResultCode.UNSPECIFIED)
        return GNDataConfirm(result_code=ResultCode.ACCEPTED)

    @staticmethod
    def _with_remaining_lifetime(packet: BufferedPacket, remaining_ms: int) -> BufferedPacket:
        """Clauses 8.5.3 / 8.6.3 step 5a: LT reduced by the queuing time."""
        return dataclass_replace(
            packet, basic_header=packet.basic_header.set_lt(LT().set_value_in_millis(remaining_ms)))

    def _buffer_packet(self, packet: BufferedPacket) -> None:
        """Queue a packet in the UC (per destination) or BC forwarding packet buffer."""
        now = self._clock()
        lifetime = packet.basic_header.lt.get_value_in_millis()
        with self._buffers_lock:
            if packet.kind == RouteKind.UNICAST and packet.destination is not None:
                buffer = self._uc_buffers.setdefault(
                    packet.destination.gn_addr,
                    PacketBuffer(self.mib.itsGnUcForwardingPacketBufferSize * 1024))
            else:
                buffer = self._bc_buffer
            buffer.push(packet, len(packet.encode()), lifetime, now)

    def _flush_forwarding_buffers(self) -> None:
        """
        Clause 10.3.5 step 2: forward the BC-buffered packets, re-executing the
        forwarding algorithm that caused the buffering. The UC-buffered packets
        are re-attempted as well (clause 10.3.11.3 NOTE 6: buffered packets may
        be further processed when a packet is received), so that a new
        neighbour can serve as next hop; packets still without a next hop are
        buffered again with their remaining lifetime.
        """
        with self._buffers_lock:
            now = self._clock()
            flushed = self._bc_buffer.flush(now)
            for buffer in self._uc_buffers.values():
                flushed.extend(buffer.flush(now))
            self._uc_buffers.clear()
        for packet, remaining in flushed:
            self._forward(self._with_remaining_lifetime(packet, remaining), origin=packet.origin)

    def _flush_source_buffers(self, so_gn_addr: GNAddress) -> None:
        """
        Step "flush packet buffers" of the receiver/forwarder operations
        (e.g. clause 10.3.11.3 step 8): the LS packet buffer of SO when
        LS_pending(SO) is TRUE, and the UC forwarding packet buffer of SO.
        """
        with self._buffers_lock:
            entry = self.location_table.get_entry(so_gn_addr)
            if entry is not None and entry.ls_pending:
                self._complete_ls(so_gn_addr)
            uc_buffer = self._uc_buffers.pop(so_gn_addr, None)
            flushed = uc_buffer.flush(self._clock()) if uc_buffer is not None else []
        for packet, remaining in flushed:
            self._forward(self._with_remaining_lifetime(packet, remaining), origin=packet.origin)

    # -------------------------------------------------------------------------
    # Forwarding (Annexes D, E and F)
    # -------------------------------------------------------------------------

    def _sender_entry(self, packet: BufferedPacket) -> LocationTableEntry | None:
        """
        LocTE of the previous sender (PV_SE). The sender is identified by the
        link-layer source address when the ALI provides it; otherwise the
        source (SO) is used, which is exact for packets received from the
        originator.
        """
        if packet.sender_ll_address is not None:
            return self.location_table.get_entry_by_mid(packet.sender_ll_address)
        if packet.so_pv is None:
            return None
        return self.location_table.get_entry(packet.so_pv.gn_addr)

    def _sender_gn_addr(self, packet: BufferedPacket) -> GNAddress | None:
        entry = self._sender_entry(packet)
        if entry is not None:
            return entry.position_vector.gn_addr
        return None

    def _destination_position(self, packet: BufferedPacket) -> Tuple[int, int]:
        """PV_P: DE PV of a GUC packet, or the centre of the GBC/GAC area."""
        if packet.kind == RouteKind.UNICAST and packet.destination is not None:
            return packet.destination.latitude, packet.destination.longitude
        assert packet.area is not None
        return packet.area.latitude, packet.area.longitude

    def _forward(self, packet: BufferedPacket, origin: bool) -> GNDataConfirm:
        """
        Execute the forwarding procedure of a source (``origin``) or forwarder:
        SCF buffering when no neighbour exists, then the forwarding algorithm
        (Annex D, E or F) and the transmission to the ALI.
        """
        if not self.location_table.get_neighbours() and packet.traffic_class.scf:
            self._buffer_packet(dataclass_replace(packet, origin=origin))
            return GNDataConfirm(result_code=ResultCode.ACCEPTED)
        if packet.kind == RouteKind.BROADCAST:
            return self._send_to_link_layer(packet.encode())
        if packet.kind == RouteKind.AREA:
            assert packet.area is not None and packet.area_type is not None
            selection = self.gn_forwarding_algorithm_selection(
                GNDataRequest(area=packet.area, packet_transport_type=PacketTransportType(
                    header_type=(HeaderType.GEOANYCAST if isinstance(packet.area_type, GeoAnycastHST)
                                 else HeaderType.GEOBROADCAST),
                    header_subtype=packet.area_type)),
                sender_gn_addr=None if origin else self._sender_gn_addr(packet),
            )
            if selection == GNForwardingAlgorithmResponse.DISCARTED:
                return GNDataConfirm(result_code=ResultCode.ACCEPTED)
            if selection == GNForwardingAlgorithmResponse.AREA_FORWARDING:
                if self.mib.itsGnAreaForwardingAlgorithm == AreaForwardingAlgorithm.CBF:
                    return self._cbf_forward(packet, area_mode=True, origin=origin)
                # F.2 Simple GeoBroadcast forwarding: re-broadcast
                return self._send_to_link_layer(packet.encode())
        # Non-area forwarding towards PV_P (Annex E)
        if self.mib.itsGnNonAreaForwardingAlgorithm == NonAreaForwardingAlgorithm.CBF:
            return self._cbf_forward(packet, area_mode=False, origin=origin)
        dest_lat, dest_lon = self._destination_position(packet)
        next_hop = self.greedy_next_hop(dest_lat, dest_lon)
        if next_hop is not None:
            # E.2: NH_LL_ADDR = NH.LL_ADDR, the MID of the neighbour's GN
            # address (the MAC address over ITS-G5, TS 103 836-4-2 clause 6.1).
            return self._send_to_link_layer(packet.encode(), next_hop.position_vector.gn_addr.mid.mid)
        if self.gn_greedy_forwarding(dest_lat, dest_lon, packet.traffic_class):
            return self._send_to_link_layer(packet.encode())     # E.2: BCAST at local optimum
        # E.2: local optimum with SCF -> UC (GUC) or BC (GBC/GAC) forwarding buffer
        self._buffer_packet(dataclass_replace(packet, origin=origin))
        return GNDataConfirm(result_code=ResultCode.ACCEPTED)

    def _cbf_timeout(self, distance_m: float) -> float:
        return cbf_timeout_ms(distance_m, self.mib.itsGnCbfMinTime, self.mib.itsGnCbfMaxTime,
                              self.mib.itsGnDefaultMaxCommunicationRange)

    def _cbf_progress(self, packet: BufferedPacket, sender: LocationTableEntry | None) -> float | None:
        """PROG (clause E.3.2.2), or None when PV_SE or EPV is not reliable."""
        if sender is None or not sender.position_vector.pai or not self.ego_position_vector.pai:
            return None
        dest_lat, dest_lon = self._destination_position(packet)
        se = sender.position_vector
        ego = self.ego_position_vector
        return (Router._distance_m(dest_lat, dest_lon, se.latitude, se.longitude)
                - Router._distance_m(dest_lat, dest_lon, ego.latitude, ego.longitude))

    def _cbf_forward(self, packet: BufferedPacket, area_mode: bool, origin: bool) -> GNDataConfirm:
        """
        Non-area (E.3.5) and area (F.3.5) CBF for a source or a newly received
        packet. Returns after transmission (source) or after buffering.
        """
        packet = dataclass_replace(packet, area_mode=area_mode)
        lifetime = packet.basic_header.lt.get_value_in_millis()
        size = len(packet.encode())
        now = self._clock()
        if origin:
            # The source broadcasts immediately and buffers its own packet with TO_CBF_MAX.
            confirm = self._send_to_link_layer(packet.encode())
            with self._buffers_lock:
                self._cbf_buffer.insert(packet.key, packet, size, lifetime, now,
                                        float(self.mib.itsGnCbfMaxTime))
            self._schedule_timers()
            return confirm
        sender = self._sender_entry(packet)
        if area_mode:
            # F.3.5: F_DIST = DIST(PV_SE, EPV), or 0 when not reliable.
            reliable = (sender is not None and sender.position_vector.pai
                        and self.ego_position_vector.pai)
            distance = 0.0
            if reliable and sender is not None:
                distance = Router._distance_m(
                    sender.position_vector.latitude, sender.position_vector.longitude,
                    self.ego_position_vector.latitude, self.ego_position_vector.longitude)
        else:
            # E.3.5: buffer only with forwarding progress; PROG = 0 when not reliable.
            progress = self._cbf_progress(packet, sender)
            if progress is not None and progress <= 0:
                return GNDataConfirm(result_code=ResultCode.ACCEPTED)   # discarded
            distance = progress or 0.0
        with self._buffers_lock:
            self._cbf_buffer.insert(packet.key, packet, size, lifetime, now,
                                    self._cbf_timeout(distance))
        self._schedule_timers()
        return GNDataConfirm(result_code=ResultCode.ACCEPTED)

    def _cbf_handle_duplicate(self, received: BufferedPacket) -> bool:
        """
        Duplicate of a packet held in the CBF packet buffer (E.3.5 lines 18-37,
        F.3.5 lines 21-39): cancel the timer when the sender is a better
        forwarder, otherwise update the timeout with equation (E.4).

        Returns False when the packet is not in the CBF packet buffer.
        """
        now = self._clock()
        with self._buffers_lock:
            if received.key not in self._cbf_buffer:
                return False
            buffered = self._cbf_buffer.get(received.key)
            assert buffered is not None
            sender = self._sender_entry(received)
            reliable = (sender is not None and sender.position_vector.pai
                        and self.ego_position_vector.pai)
            ego = self.ego_position_vector
            if buffered.area_mode:
                assert buffered.so_pv is not None
                so = buffered.so_pv
                d1 = Router._distance_m(ego.latitude, ego.longitude, so.latitude, so.longitude)
                d2 = d3 = 0.0
                if reliable and sender is not None:
                    se = sender.position_vector
                    d2 = Router._distance_m(se.latitude, se.longitude, so.latitude, so.longitude)
                    d3 = Router._distance_m(ego.latitude, ego.longitude, se.latitude, se.longitude)
                if d1 == 0 or (d1 < d2 and d2 > d3):
                    self._cbf_buffer.remove(received.key)     # better forwarder: discard
                    return True
                distance = d3
            else:
                # E.3.5 line 20 reads "SE_POS_VALID = FALSE"; PROG can only be
                # computed with a valid sender position, as in line 46.
                progress = self._cbf_progress(buffered, sender)
                if progress is not None and progress < 0:
                    self._cbf_buffer.remove(received.key)     # better forwarder: discard
                    return True
                distance = progress or 0.0
            remaining = self._cbf_buffer.remaining_timeout_ms(received.key, now) or 0
            self._cbf_buffer.restart(received.key, now, cbf_timeout_update_ms(
                remaining, self._cbf_timeout(distance), self.mib.itsGnCbfMaxTime))
        self._schedule_timers()
        return True

    def _cbf_applies(self, inside_area: bool) -> bool:
        """Whether CBF handles duplicates (clause 10.3.11.3 step 3 NOTEs 1a/1b)."""
        if inside_area:
            return self.mib.itsGnAreaForwardingAlgorithm == AreaForwardingAlgorithm.CBF
        return self.mib.itsGnNonAreaForwardingAlgorithm == NonAreaForwardingAlgorithm.CBF

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

    def _generation_location(self) -> dict:
        """ThreeDLocation of the ego position for the security header (elevation unavailable)."""
        return {
            "latitude": self.ego_position_vector.latitude,
            "longitude": self.ego_position_vector.longitude,
            "elevation": 0xF000,  # Uint16 unavailable per IEEE 1609.2
        }

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
        # DCC-MCO field (TS 103 836-4-2 clauses 6.3.3, 7.2.1); zero-filled
        # without DCC_NET.
        media_dependant_data = (self.dcc_net.dcc_mco() if self.dcc_net is not None
                                else b"\x00\x00\x00\x00")
        packet = b""
        if self._signed(request):
            if self.sign_service is None:
                raise ValueError(
                    "MIB requires security but no SignService provided to Router")
            if request.security_profile in (
                SecurityProfile.COOPERATIVE_AWARENESS_MESSAGE,
                SecurityProfile.VRU_AWARENESS_MESSAGE,
            ):
                # ETSI TS 103 836-4-1 V2.2.1 §9.4 / ETSI TS 103 097 §7.1.1:
                # the signed payload is Common Header + Extended Header + GN-SDU.
                # The Basic Header is NOT part of the signed content.
                # Both CAM (PSID 36) and VAM (PSID 638) follow the §7.1.1
                # profile: signer alternates certificate/digest on a 1-second
                # timer so Wireshark and receivers always obtain the full cert.
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
                    generation_location=self._generation_location(),
                )
                sign_confirm: SNSIGNConfirm = self.sign_service.sign_cam(
                    sign_request)
                basic_header = basic_header.set_nh(BasicNH.SECURED_PACKET)
                packet = basic_header.encode_to_bytes() + sign_confirm.sec_message

            else:
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
                    generation_location=self._generation_location(),
                )
                sign_confirm = self.sign_service.sign_request(sign_request)
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

        # Step 3 (clause 10.3.10.2): no neighbour and SCF set -> BC forwarding buffer.
        if not self.location_table.get_neighbours() and request.traffic_class.scf:
            self._buffer_packet(BufferedPacket(
                basic_header=BasicHeader.decode_from_bytes(packet[0:4]), body=packet[4:],
                traffic_class=request.traffic_class, kind=RouteKind.BROADCAST))
            return GNDataConfirm(result_code=ResultCode.ACCEPTED)
        # Steps 5-6: media-dependent procedures and pass GN-PDU to LL
        confirm = self._send_to_link_layer(packet)
        if confirm.result_code != ResultCode.ACCEPTED:
            return confirm

        # Step 7: reset beacon timer to prevent an unnecessary beacon (§10.3.10.2)
        self._restart_beacon_timer(self._clock())
        self._schedule_timers()

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
        self, area_type: GeoBroadcastHST | GeoAnycastHST, area: Area, lat: int, lon: int
    ) -> float:
        """
        Geometric function F(x, y) of a point P relative to a geographical area
        (ETSI EN 302 931, clause 5; ETSI TS 103 899, clause 5): F = 1 at the
        centre, F > 0 inside, F = 0 at the border and F < 0 outside.

        The point is expressed in Cartesian coordinates centred on the area
        centre with the x axis along the long side ``a``, which is rotated by
        ``area.angle`` degrees clockwise from North (azimuth).

        Parameters
        ----------
        area_type : GeoBroadcastHST | GeoAnycastHST
            Shape of the area.
        area : Area
            Area (centre in 1/10 microdegree, a and b in metres, angle in degrees).
        lat : int
            Latitude of the point P. In 1/10 microdegrees.
        lon : int
            Longitude of the point P. In 1/10 microdegrees.
        """
        x, y = Router._area_coordinates(area, lat, lon)
        if area_type in (GeoBroadcastHST.GEOBROADCAST_CIRCLE, GeoAnycastHST.GEOANYCAST_CIRCLE):
            return 1 - (x / area.a) ** 2 - (y / area.a) ** 2
        if area_type in (GeoBroadcastHST.GEOBROADCAST_ELIP, GeoAnycastHST.GEOANYCAST_ELIP):
            return 1 - (x / area.a) ** 2 - (y / area.b) ** 2
        if area_type in (GeoBroadcastHST.GEOBROADCAST_RECT, GeoAnycastHST.GEOANYCAST_RECT):
            return min(1 - (x / area.a) ** 2, 1 - (y / area.b) ** 2)
        raise ValueError("Invalid area type")

    @staticmethod
    def _area_coordinates(area: Area, lat: int, lon: int) -> tuple[float, float]:
        """(x, y) in metres of a point in the frame of the area, x along side a."""
        lat_c, lon_c = math.radians(area.latitude / 1e7), math.radians(area.longitude / 1e7)
        lat_p, lon_p = math.radians(lat / 1e7), math.radians(lon / 1e7)
        north = EARTH_RADIUS * (lat_p - lat_c)
        east = EARTH_RADIUS * (lon_p - lon_c) * math.cos((lat_p + lat_c) / 2)
        theta = math.radians(area.angle)
        return (north * math.cos(theta) + east * math.sin(theta),
                -north * math.sin(theta) + east * math.cos(theta))

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
        §E.2 Greedy Forwarding algorithm (ETSI TS 103 836-4-1 V2.2.1 clause E.2).

        Selects the neighbour with the smallest distance to the destination
        (Most Forward within Radius policy). Returns True if the packet should
        be transmitted (greedy next hop or BCAST fallback at local optimum),
        False if it should be buffered (local optimum and SCF is enabled).
        """
        if self.greedy_next_hop(dest_lat, dest_lon) is not None:
            return True   # §E.2: send to the greedy NH (see greedy_next_hop)
        # §E.2: local optimum – no neighbour with positive progress towards destination
        if traffic_class.scf:
            return False  # §E.2: buffer (NH_LL_ADDR = 0)
        return True       # §E.2: BCAST fallback (NH_LL_ADDR = BCAST)

    def greedy_next_hop(self, dest_lat: int, dest_lon: int) -> LocationTableEntry | None:
        """
        §E.2 Most Forward within Radius: the neighbour closest to the
        destination, provided it is closer than the ego position; None at a
        local optimum.
        """
        mfr = Router._distance_m(
            dest_lat, dest_lon,
            self.ego_position_vector.latitude,
            self.ego_position_vector.longitude,
        )
        best: LocationTableEntry | None = None
        for entry in self.location_table.get_neighbours():
            pv = entry.position_vector
            d = Router._distance_m(dest_lat, dest_lon, pv.latitude, pv.longitude)
            if d < mfr:
                mfr = d
                best = entry
        return best

    def _cbf_compute_timeout_ms(self, dist_m: float) -> float:
        """
        CBF timeout without Access Layer constraints for a progress or
        forwarding distance ``dist_m`` (equations E.1/E.2, F.1/F.2).
        """
        return self._cbf_timeout(dist_m)

    def gn_forwarding_algorithm_selection(
        self, request: GNDataRequest, sender_gn_addr: GNAddress | None = None
    ) -> GNForwardingAlgorithmResponse:
        """
        Annex D of ETSI TS 103 836-4-1 V2.2.1 (2026-04).

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
        secured_body: bytes | None = None,
        sender_ll_address: bytes | None = None,
    ) -> GNDataConfirm:
        """
        Forwarder steps 9 to 14 of clause 10.3.11.3 (GBC) / 10.3.12.3 (GAC):
        decrement the RHL, buffer when no neighbour exists and SCF is set,
        then execute the forwarding algorithm (Annex D, E, F).

        Parameters
        ----------
        basic_header : BasicHeader
            Basic header of the received packet.
        common_header : CommonHeader
            Common header of the packet.
        gbc_extended_header : GBCExtendedHeader
            Extended header of the packet.
        packet : bytes
            Payload (without headers).
        secured_body : bytes | None
            Secured Packet as received; relayed unmodified when given.
        sender_ll_address : bytes | None
            Link-layer address of the previous sender, when known.
        """
        if basic_header.rhl <= 1:
            return GNDataConfirm(result_code=ResultCode.ACCEPTED)
        body = secured_body if secured_body is not None else (
            common_header.encode_to_bytes() + gbc_extended_header.encode() + packet)
        return self._forward(BufferedPacket(
            basic_header=basic_header.set_rhl(basic_header.rhl - 1),
            body=body,
            traffic_class=common_header.tc,
            kind=RouteKind.AREA,
            so_pv=gbc_extended_header.so_pv,
            sn=gbc_extended_header.sn,
            area_type=cast(Union[GeoBroadcastHST, GeoAnycastHST], common_header.hst),
            area=Area(latitude=gbc_extended_header.latitude, longitude=gbc_extended_header.longitude,
                      a=gbc_extended_header.a, b=gbc_extended_header.b,
                      angle=gbc_extended_header.angle),
            sender_ll_address=sender_ll_address,
        ), origin=False)

    def gn_data_request_gac(self, request: GNDataRequest) -> GNDataConfirm:
        """
        Handle a GeoAnycast (GAC) GNDataRequest.

        Implements §10.3.12.2 source operations of ETSI TS 103 836-4-1 V2.2.1 (2026-04).
        The source operations for GAC are identical to those for GBC (§10.3.11.2).

        Parameters
        ----------
        request : GNDataRequest
            GNDataRequest to handle.
        """
        return self.gn_data_request_gbc(request)

    def _sign_mgmt(self, basic_header: BasicHeader, body: bytes) -> Tuple[BasicHeader, bytes] | None:
        """
        Security encapsulation of a GN management packet (Common Header and
        Extended Header): Beacon, LS Request and LS Reply are signed with ITS-AID
        141 (GN-MGMT), SSP absent (ETSI TS 103 836-4-1 V2.2.1 tables 22, 24 and
        26). Unchanged without ``itsGnSecurity``; None when it is ENABLED and no
        AT may sign (the packet is then not sent).
        """
        if self.mib.itsGnSecurity != GnSecurity.ENABLED:
            return basic_header, body
        if self.sign_service is None:
            return None
        try:
            confirm = self.sign_service.sign_request(SNSIGNRequest(
                tbs_message_length=len(body), tbs_message=body, its_aid=ITS_AID_GN_MGMT,
                permissions=b"", permissions_length=0,
                generation_location=self._generation_location()))
        except SigningError:
            return None
        return basic_header.set_nh(BasicNH.SECURED_PACKET), confirm.sec_message

    def _signed(self, request: GNDataRequest) -> bool:
        """Whether the packet of ``request`` is secured: ``itsGnSecurity`` ENABLED and
        the Security profile not ``UNSECURED`` (ETSI TS 103 836-4-1 V2.2.1 table 18:
        NH = Common Header when the Security profile indicates an unsecured packet)."""
        return (self.mib.itsGnSecurity == GnSecurity.ENABLED
                and request.security_profile != SecurityProfile.UNSECURED)

    def _secure(self, basic_header: BasicHeader, body: bytes,
                request: GNDataRequest) -> Tuple[BasicHeader, bytes]:
        """
        Security encapsulation of a GBC, GAC or GUC packet (Common Header,
        Extended Header and payload) when ``itsGnSecurity`` is enabled
        (ETSI TS 103 836-4-1 V2.2.1 clause 9.4). The signer profile follows the
        ITS-AID (:meth:`SignService.sign_request`): DENM profile (ETSI TS 103 097
        V2.2.1 clause 7.1.2) for ITS-AID 37, generic profile (clause 7.1.3)
        otherwise. When no AT may sign the message, :class:`SigningError`
        propagates and the packet is not sent.
        """
        if not self._signed(request):
            return basic_header, body
        if self.sign_service is None:
            raise ValueError("MIB requires security but no SignService provided to Router")
        sign_request = SNSIGNRequest(
            tbs_message_length=len(body),
            tbs_message=body,
            its_aid=request.its_aid,
            permissions=request.security_permissions,
            permissions_length=len(request.security_permissions),
            generation_location=self._generation_location(),
        )
        confirm = self.sign_service.sign_request(sign_request)
        return basic_header.set_nh(BasicNH.SECURED_PACKET), confirm.sec_message

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
        # Step 2 (clauses 10.3.11.2 / 10.3.12.2): security encapsulation.
        basic_header, body = self._secure(
            basic_header,
            common_header.encode_to_bytes() + geo_broadcast_extended_header.encode() + request.data,
            request)
        # Steps 3-8: SCF buffering, forwarding algorithm (Annex D) and transmission.
        return self._forward(BufferedPacket(
            basic_header=basic_header,
            body=body,
            traffic_class=request.traffic_class,
            kind=RouteKind.AREA,
            so_pv=geo_broadcast_extended_header.so_pv,
            sn=geo_broadcast_extended_header.sn,
            area_type=cast(Union[GeoBroadcastHST, GeoAnycastHST],
                           request.packet_transport_type.header_subtype),
            area=request.area,
        ), origin=True)

    def gn_data_request_tsb(self, request: GNDataRequest) -> GNDataConfirm:
        """
        Handle a multi-hop Topologically-Scoped Broadcast GNDataRequest
        (ETSI TS 103 836-4-1 V2.2.1, clause 10.3.9.2).

        Parameters
        ----------
        request : GNDataRequest
            GNDataRequest to handle.
        """
        # Step 1: Basic Header (RHL = itsGnDefaultHopLimit unless requested),
        # Common Header and TSB Extended Header (table 30).
        hop_limit = self.mib.itsGnDefaultHopLimit if request.max_hop_limit <= 1 else request.max_hop_limit
        basic_header = BasicHeader.initialize_with_mib_request_and_rhl(
            self.mib, request.max_packet_lifetime, hop_limit)
        common_header = CommonHeader.initialize_with_request(
            dataclass_replace(request, max_hop_limit=hop_limit), self.mib)
        tsb_extended_header = TSBExtendedHeader(
            sn=self.get_sequence_number(), so_pv=self.ego_position_vector)
        body = common_header.encode_to_bytes() + tsb_extended_header.encode() + request.data
        # Step 2: security encapsulation.
        if self._signed(request):
            if self.sign_service is None:
                raise ValueError("MIB requires security but no SignService provided to Router")
            sign_confirm = self.sign_service.sign_request(SNSIGNRequest(
                tbs_message_length=len(body),
                tbs_message=body,
                its_aid=request.its_aid,
                permissions=request.security_permissions,
                permissions_length=len(request.security_permissions),
                generation_location=self._generation_location(),
            ))
            basic_header = basic_header.set_nh(BasicNH.SECURED_PACKET)
            body = sign_confirm.sec_message
        # Steps 3-6: SCF buffering, then broadcast.
        return self._forward(BufferedPacket(
            basic_header=basic_header, body=body, traffic_class=request.traffic_class,
            kind=RouteKind.BROADCAST, so_pv=tsb_extended_header.so_pv,
            sn=tsb_extended_header.sn), origin=True)

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
        try:
            return self._gn_data_request(request)
        except SigningError:
            # No AT may sign this message (validity, region or permissions):
            # it is not sent (IEEE Std 1609.2-2016 clause 5.2.3.2.2).
            return GNDataConfirm(result_code=ResultCode.UNSPECIFIED)

    def _gn_data_request(self, request: GNDataRequest) -> GNDataConfirm:
        if (request.packet_transport_type.header_type == HeaderType.TSB) and (
            request.packet_transport_type.header_subtype == TopoBroadcastHST.SINGLE_HOP
        ):
            return self.gn_data_request_shb(request)
        if (request.packet_transport_type.header_type == HeaderType.TSB) and (
            request.packet_transport_type.header_subtype == TopoBroadcastHST.MULTI_HOP
        ):
            return self.gn_data_request_tsb(request)
        if request.packet_transport_type.header_type == HeaderType.GEOBROADCAST:
            return self.gn_data_request_gbc(request)
        if request.packet_transport_type.header_type == HeaderType.GEOANYCAST:
            return self.gn_data_request_gac(request)
        if request.packet_transport_type.header_type == HeaderType.GEOUNICAST:
            return self.gn_data_request_guc(request)
        raise NotImplementedError("PacketTransportType not implemented")

    @staticmethod
    def _shb_indication(long_position_vector: LongPositionVector, payload: bytes,
                        common_header: CommonHeader, basic_header: BasicHeader) -> GNDataIndication:
        """GN-DATA.indication of a SHB (table 35)."""
        return GNDataIndication(
            upper_protocol_entity=common_header.nh,
            packet_transport_type=PacketTransportType(
                header_type=HeaderType.TSB,
                header_subtype=TopoBroadcastHST.SINGLE_HOP,
            ),
            source_position_vector=long_position_vector,
            traffic_class=common_header.tc,
            remaining_packet_lifetime=float(basic_header.lt.get_value_in_seconds()),
            remaining_hop_limit=basic_header.rhl,
            length=len(payload),
            data=payload,
        )

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
            dcc_mco = packet[24:28]
            packet = packet[28:]
            # Step 3: execute DAD (§10.2.1.5): an SHB is single-hop, so an SO
            # with our address is another station.
            if long_position_vector.gn_addr == self.mib.itsGnLocalGnAddr:
                self.resolve_address_conflict()
            # Steps 4, 5, 6: update SO LocTE (PV, PDR, IS_NEIGHBOUR)
            self.location_table.new_shb_packet(long_position_vector, packet)
            # TS 103 836-4-2 clause 7.2.2 (between steps 6 and 7): LocTEX-G5
            if self.dcc_net is not None and self.mib.itsGnIfType != GnIfType.LTE_V2X:
                self.dcc_net.update_loctex(long_position_vector.gn_addr,
                                           long_position_vector.tst.msec, dcc_mco, self._clock())
            # Flush the LS and UC forwarding packet buffers of SO
            self._flush_source_buffers(long_position_vector.gn_addr)
            # Step 7: pass payload to upper entity via GN-DATA.indication (Table 35)
            return self._shb_indication(long_position_vector, packet, common_header, basic_header)
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

        Implements §10.3.8.2 source operations of ETSI TS 103 836-4-1 V2.2.1 (2026-04).

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
        if de_entry is None or de_entry.ls_pending:
            # No PV for the destination → Location Service (clause 10.3.7.1.2)
            assert request.destination is not None
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
        # Step 3 (clause 10.3.8.2): security encapsulation.
        basic_header, body = self._secure(
            basic_header, common_header.encode_to_bytes() + guc_extended_header.encode() + request.data,
            request)
        # Steps 4-9: SCF buffering, forwarding algorithm (Annex E) and transmission.
        return self._forward(BufferedPacket(
            basic_header=basic_header,
            body=body,
            traffic_class=request.traffic_class,
            kind=RouteKind.UNICAST,
            so_pv=guc_extended_header.so_pv,
            sn=guc_extended_header.sn,
            destination=de_pv,
        ), origin=True)

    def gn_data_indicate_guc(
        self, packet: bytes, common_header: CommonHeader, basic_header: BasicHeader,
        secured_body: bytes | None = None, sender_ll_address: bytes | None = None,
    ) -> GNDataIndication | None:
        """
        Handle a GeoUnicast (GUC) GeoNetworking packet.

        Implements the forwarder (clause 10.3.8.3) and destination
        (clause 10.3.8.4) operations of ETSI TS 103 836-4-1 V2.2.1 (2026-04).

        Parameters
        ----------
        packet : bytes
            GeoNetworking packet to handle (without Basic and Common headers).
        common_header : CommonHeader
            CommonHeader of the packet.
        basic_header : BasicHeader
            BasicHeader of the packet.
        secured_body : bytes | None
            Secured Packet as received (relayed unmodified when forwarding).
        sender_ll_address : bytes | None
            Link-layer address of the previous sender, when known.
        """
        guc_extended_header = GUCExtendedHeader.decode(packet[0:48])
        packet = packet[48:]
        is_destination = guc_extended_header.de_pv.gn_addr == self.mib.itsGnLocalGnAddr
        # Forwarder step 3: with non-area CBF, duplicates are handled by the
        # forwarding algorithm (NOTE 1).
        if not is_destination and self._cbf_applies(False) and self._cbf_handle_duplicate(
                BufferedPacket(basic_header=basic_header, body=b"", traffic_class=common_header.tc,
                               kind=RouteKind.UNICAST, so_pv=guc_extended_header.so_pv,
                               sn=guc_extended_header.sn, destination=guc_extended_header.de_pv,
                               sender_ll_address=sender_ll_address)):
            return None
        try:
            # DAD (§10.2.1.5)
            self.duplicate_address_detection(guc_extended_header.so_pv.gn_addr)
            # DPD and create/update SO LocTE (PV, PDR, IS_NEIGHBOUR per NOTE 2)
            self.location_table.new_guc_packet(guc_extended_header, packet)
            # Flush the LS and UC forwarding packet buffers of SO
            self._flush_source_buffers(guc_extended_header.so_pv.gn_addr)
            if is_destination:
                # §10.3.8.4: pass payload to upper entity via GN-DATA.indication (Table 29)
                return GNDataIndication(
                    upper_protocol_entity=common_header.nh,
                    packet_transport_type=PacketTransportType(
                        header_type=HeaderType.GEOUNICAST,
                    ),
                    # Annex J4: the destination address the source generated the GUC with.
                    destination=guc_extended_header.de_pv.gn_addr,
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
            # Step 7: DE not a neighbour: update PV(DE) in the LocT from the DE PV
            if secured_body is None:
                self.location_table.update_with_de_pv(guc_extended_header.de_pv)
            # Step 8: update the DE PV of an unsecured packet from the LocT when DE
            # is a neighbour (signatures of forwarded packets are not updated)
            de_entry = self.location_table.get_entry(guc_extended_header.de_pv.gn_addr)
            if secured_body is None and de_entry is not None and de_entry.is_neighbour:
                # §C.3: only update DE PV in forwarded packet if LocT PV is strictly newer
                if de_entry.position_vector.tst > guc_extended_header.de_pv.tst:
                    de_lpv = de_entry.position_vector
                    guc_extended_header = guc_extended_header.with_de_pv(ShortPositionVector(
                        gn_addr=de_lpv.gn_addr,
                        tst=de_lpv.tst,
                        latitude=de_lpv.latitude,
                        longitude=de_lpv.longitude,
                    ))
            # Step 9: decrement RHL; if RHL == 0 discard
            if basic_header.rhl > 1:
                # Steps 10-15: SCF buffering, forwarding algorithm and transmission
                body = secured_body if secured_body is not None else (
                    common_header.encode_to_bytes() + guc_extended_header.encode() + packet)
                self._forward(BufferedPacket(
                    basic_header=basic_header.set_rhl(basic_header.rhl - 1), body=body,
                    traffic_class=common_header.tc, kind=RouteKind.UNICAST,
                    so_pv=guc_extended_header.so_pv, sn=guc_extended_header.sn,
                    destination=guc_extended_header.de_pv,
                    sender_ll_address=sender_ll_address), origin=False)
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
        self, packet: bytes, common_header: CommonHeader, basic_header: BasicHeader,
        secured_body: bytes | None = None, sender_ll_address: bytes | None = None,
    ) -> GNDataIndication | None:
        """
        Handle a GeoAnycast (GAC) GeoNetworking packet.

        Implements the forwarder and receiver operations of
        ETSI TS 103 836-4-1 V2.2.1 (2026-04), clause 10.3.12.3.

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
        secured_body : bytes | None
            Secured Packet as received (relayed unmodified when forwarding).
        sender_ll_address : bytes | None
            Link-layer address of the previous sender, when known.
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
        area_type = cast(Union[GeoBroadcastHST, GeoAnycastHST], common_header.hst)
        # Function F(x,y) (ETSI TS 103 899, clause 5)
        area_f = self.gn_geometric_function_f(
            area_type, area, self.ego_position_vector.latitude, self.ego_position_vector.longitude)
        # Outside the area with non-area CBF, duplicates are handled by the forwarding algorithm.
        if area_f < 0 and self._cbf_applies(False) and self._cbf_handle_duplicate(BufferedPacket(
                basic_header=basic_header, body=b"", traffic_class=common_header.tc,
                kind=RouteKind.AREA, so_pv=gbc_extended_header.so_pv, sn=gbc_extended_header.sn,
                area_type=area_type, area=area, sender_ll_address=sender_ll_address)):
            return None
        try:
            # DAD (§10.2.1.5)
            self.duplicate_address_detection(gbc_extended_header.so_pv.gn_addr)
            # DPD and create/update SO LocTE (PV, PDR, IS_NEIGHBOUR per NOTE 1)
            self.location_table.new_gac_packet(gbc_extended_header, packet)
            # Flush the LS and UC forwarding packet buffers of SO
            self._flush_source_buffers(gbc_extended_header.so_pv.gn_addr)
            # Inside or at border (F ≥ 0) → deliver to upper entity and STOP
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
            # Outside area (F < 0) → forward only, no delivery to upper layer
            # §B.3: Geographical area size control – do not forward if area exceeds itsGnMaxGeoAreaSize
            if Router._compute_area_size_m2(area_type, area) > self.mib.itsGnMaxGeoAreaSize * 1_000_000:
                return None
            # §B.2: PDR enforcement – do not forward if SO PDR exceeds itsGnMaxPacketDataRate
            so_entry = self.location_table.get_entry(gbc_extended_header.so_pv.gn_addr)
            if so_entry is not None and so_entry.pdr > self.mib.itsGnMaxPacketDataRate * 1000:
                return None
            # Decrement RHL, SCF buffering, Annex D (a packet from a sender inside
            # the area is discarded) and non-area forwarding
            self.gn_data_forward_gbc(basic_header, common_header, gbc_extended_header, packet,
                                     secured_body, sender_ll_address)
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

        §10.3.7.1.2 step 2 of ETSI TS 103 836-4-1 V2.2.1 (2026-04).
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
            hst=cast(HeaderSubType, LocationServiceHST.LS_REQUEST),
            tc=TrafficClass(),
            flags=self.mib.itsGnIsMobile.value,
            pl=0,
            mhl=self.mib.itsGnDefaultHopLimit,
        )
        # Request GN_ADDR: the MID of the sought router, the other bits 0
        # (TP/GEONW/PON/LOS/BV-01; the destination matches the MID, clause 10.3.7.3).
        ls_req_header = LSRequestExtendedHeader.initialize(
            self.get_sequence_number(), ego_pv, GNAddress(mid=sought_gn_addr.mid))
        # Step 3: security encapsulation with ITS-AID 141 (table 24).
        secured = self._sign_mgmt(basic_header, common_header.encode_to_bytes() + ls_req_header.encode())
        if secured is None:
            return
        packet = secured[0].encode_to_bytes() + secured[1]
        try:
            if self.link_layer:
                self.link_layer.send(packet)
        except (PacketTooLongException, SendingException):
            pass

    def gn_ls_request(
        self, sought_gn_addr: GNAddress, buffered_request: GNDataRequest | None = None
    ) -> None:
        """
        Initiate a Location Service request for *sought_gn_addr*, or queue
        *buffered_request* while one is in progress
        (ETSI TS 103 836-4-1 V2.2.1, clauses 10.2.4 and 10.3.7.1.2).

        Parameters
        ----------
        sought_gn_addr : GNAddress
            GN address of the sought GeoAdhoc router.
        buffered_request : GNDataRequest | None
            GNDataRequest queued in the LS packet buffer (clause 8.5) and sent
            when the LS completes.
        """
        with self._buffers_lock:
            entry = self.location_table.get_entry(sought_gn_addr)
            if entry is not None and entry.ls_pending:
                if buffered_request is not None:
                    self._ls_buffer_request(sought_gn_addr, buffered_request)
                return
            # Step 7: LocTE for the sought GN_ADDR with LS_pending = TRUE
            entry = self.location_table.ensure_entry(sought_gn_addr)
            entry.ls_pending = True
            self._ls_packet_buffers.setdefault(
                sought_gn_addr, PacketBuffer(self.mib.itsGnLocationServicePacketBufferSize))
            if buffered_request is not None:
                self._ls_buffer_request(sought_gn_addr, buffered_request)
            # Steps 5-6: start TLS and initialise RTCLS
            self._ls_retransmit_counters[sought_gn_addr] = 0
            self._ls_deadlines[sought_gn_addr] = (
                self._clock() + self.mib.itsGnLocationServiceRetransmitTimer)
        self._send_ls_request_packet(sought_gn_addr)
        self._schedule_timers()

    def _ls_buffer_request(self, sought_gn_addr: GNAddress, request: GNDataRequest) -> None:
        """Queue a request in the LS packet buffer of the sought GN_ADDR (clause 8.5.3)."""
        lifetime_s = (request.max_packet_lifetime if request.max_packet_lifetime is not None
                      else self.mib.itsGnDefaultPacketLifetime)
        buffer = self._ls_packet_buffers.setdefault(
            sought_gn_addr, PacketBuffer(self.mib.itsGnLocationServicePacketBufferSize))
        buffer.push(request, len(request.data) + _GUC_HEADERS_LENGTH,
                    int(lifetime_s * 1000), self._clock())

    def _complete_ls(self, sought_gn_addr: GNAddress) -> None:
        """
        LS completion (clause 10.3.7.1.4 steps 6-10): stop TLS, reset RTCLS,
        clear LS_pending and send the LS-buffered packets in FIFO order with
        their lifetime reduced by the queuing time.
        """
        with self._buffers_lock:
            self._ls_deadlines.pop(sought_gn_addr, None)
            self._ls_retransmit_counters.pop(sought_gn_addr, None)
            buffer = self._ls_packet_buffers.pop(sought_gn_addr, None)
            entry = self.location_table.get_entry(sought_gn_addr)
            if entry is not None:
                entry.ls_pending = False
            flushed = buffer.flush(self._clock()) if buffer is not None else []
        for request, remaining_ms in flushed:
            self.gn_data_request_guc(
                dataclass_replace(request, max_packet_lifetime=remaining_ms / 1000))

    def _ls_retransmit(self, sought_gn_addr: GNAddress, now_ms: int | None = None) -> None:
        """
        Expiry of TLS for *sought_gn_addr* (clause 10.3.7.1.3): re-issue the
        LS Request while RTCLS < itsGnLocationServiceMaxRetrans; otherwise
        discard the LS-buffered packets and remove the LocTE.
        """
        now = self._clock() if now_ms is None else now_ms
        with self._buffers_lock:
            count = self._ls_retransmit_counters.get(sought_gn_addr, 0)
            if count >= self.mib.itsGnLocationServiceMaxRetrans:
                self._ls_packet_buffers.pop(sought_gn_addr, None)
                self._ls_deadlines.pop(sought_gn_addr, None)
                self._ls_retransmit_counters.pop(sought_gn_addr, None)
                self.location_table.remove_entry(sought_gn_addr)
                return
            self._ls_retransmit_counters[sought_gn_addr] = count + 1
            self._ls_deadlines[sought_gn_addr] = now + self.mib.itsGnLocationServiceRetransmitTimer
        self._send_ls_request_packet(sought_gn_addr)
        self._schedule_timers()

    def gn_data_indicate_ls_request(
        self, packet: bytes, common_header: CommonHeader, basic_header: BasicHeader,
        secured_body: bytes | None = None, sender_ll_address: bytes | None = None,
    ) -> None:
        """
        Handle an incoming LS Request packet: forwarder (clause 10.3.7.2,
        handled as TSB without delivery) or destination (clause 10.3.7.3,
        answered with an LS Reply).

        Parameters
        ----------
        packet : bytes
            GeoNetworking packet body after Basic and Common headers.
        common_header : CommonHeader
            Common header of the received packet.
        basic_header : BasicHeader
            Basic header of the received packet.
        secured_body : bytes | None
            Secured Packet as received (relayed unmodified when forwarding).
        sender_ll_address : bytes | None
            Link-layer address of the previous sender, when known.
        """
        ls_request_header = LSRequestExtendedHeader.decode(packet[0:36])
        payload = packet[36:]
        try:
            # DPD + DAD
            self.duplicate_address_detection(ls_request_header.so_pv.gn_addr)
            # Update SO LocTE
            self.location_table.new_ls_request_packet(ls_request_header, payload)
            self._flush_source_buffers(ls_request_header.so_pv.gn_addr)
            # Clause 10.3.7.3: destination when the MID field of Request GN_ADDR matches.
            if ls_request_header.request_gn_addr.mid == self.mib.itsGnLocalGnAddr.mid:
                # §10.3.7.3: destination – send LS Reply
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
                    hst=cast(HeaderSubType, LocationServiceHST.LS_REPLY),
                    tc=TrafficClass(),
                    flags=self.mib.itsGnIsMobile.value,
                    pl=0,
                    mhl=self.mib.itsGnDefaultHopLimit,
                )
                reply_header = LSReplyExtendedHeader.initialize(
                    self.get_sequence_number(), ego_pv, de_pv)
                # Step 10: security encapsulation with ITS-AID 141 (table 26).
                secured = self._sign_mgmt(reply_basic, reply_common.encode_to_bytes() + reply_header.encode())
                if secured is None:
                    return
                reply_basic, reply_body = secured
                self._forward(BufferedPacket(
                    basic_header=reply_basic,
                    body=reply_body,
                    traffic_class=reply_common.tc, kind=RouteKind.UNICAST,
                    so_pv=ego_pv, sn=reply_header.sn, destination=de_pv), origin=True)
                return
            # §10.3.7.2 forwarder: TSB handling without delivery
            so_entry = self.location_table.get_entry(ls_request_header.so_pv.gn_addr)
            if so_entry is not None and so_entry.pdr > self.mib.itsGnMaxPacketDataRate * 1000:
                return
            if basic_header.rhl > 1:
                body = secured_body if secured_body is not None else (
                    common_header.encode_to_bytes() + ls_request_header.encode() + payload)
                self._forward(BufferedPacket(
                    basic_header=basic_header.set_rhl(basic_header.rhl - 1), body=body,
                    traffic_class=common_header.tc, kind=RouteKind.BROADCAST,
                    so_pv=ls_request_header.so_pv, sn=ls_request_header.sn,
                    sender_ll_address=sender_ll_address), origin=False)
        except DADException:
            print("Duplicate Address Detected!")
        except IncongruentTimestampException:
            print("Incongruent Timestamp Detected!")
        except DuplicatedPacketException:
            print("Packet is duplicated")
        except DecodeError as e:
            print(str(e))

    def gn_data_indicate_ls_reply(
        self, packet: bytes, common_header: CommonHeader, basic_header: BasicHeader,
        secured_body: bytes | None = None, sender_ll_address: bytes | None = None,
    ) -> None:
        """
        Handle an incoming LS Reply packet: source of the LS
        (clause 10.3.7.1.4) or forwarder (clause 10.3.7.2, handled as GUC).

        Parameters
        ----------
        packet : bytes
            GeoNetworking packet body after Basic and Common headers.
        common_header : CommonHeader
            Common header of the received packet.
        basic_header : BasicHeader
            Basic header of the received packet.
        secured_body : bytes | None
            Secured Packet as received (relayed unmodified when forwarding).
        sender_ll_address : bytes | None
            Link-layer address of the previous sender, when known.
        """
        ls_reply_header = LSReplyExtendedHeader.decode(packet[0:48])
        payload = packet[48:]
        is_source = ls_reply_header.de_pv.gn_addr == self.mib.itsGnLocalGnAddr
        if not is_source and self._cbf_applies(False) and self._cbf_handle_duplicate(
                BufferedPacket(basic_header=basic_header, body=b"", traffic_class=common_header.tc,
                               kind=RouteKind.UNICAST, so_pv=ls_reply_header.so_pv,
                               sn=ls_reply_header.sn, destination=ls_reply_header.de_pv,
                               sender_ll_address=sender_ll_address)):
            return
        try:
            # DPD + DAD
            self.duplicate_address_detection(ls_reply_header.so_pv.gn_addr)
            # Update PV(SO) and PDR(SO)
            self.location_table.new_ls_reply_packet(ls_reply_header, payload)
            sought_gn_addr = ls_reply_header.so_pv.gn_addr
            if is_source:
                # Steps 6-10: flush the LS buffer, stop TLS, reset RTCLS, LS_pending = FALSE
                self._complete_ls(sought_gn_addr)
                self._flush_source_buffers(sought_gn_addr)
                return
            # §10.3.7.2 forwarder: GUC forwarder operations
            self._flush_source_buffers(sought_gn_addr)
            so_entry = self.location_table.get_entry(sought_gn_addr)
            if so_entry is not None and so_entry.pdr > self.mib.itsGnMaxPacketDataRate * 1000:
                return
            # GUC forwarder step 7: DE not a neighbour: update PV(DE) from the DE PV
            if secured_body is None:
                self.location_table.update_with_de_pv(ls_reply_header.de_pv)
            de_entry = self.location_table.get_entry(ls_reply_header.de_pv.gn_addr)
            if secured_body is None and de_entry is not None and de_entry.is_neighbour:
                # §C.3: only update DE PV in forwarded packet if LocT PV is strictly newer
                if de_entry.position_vector.tst > ls_reply_header.de_pv.tst:
                    de_lpv = de_entry.position_vector
                    ls_reply_header = ls_reply_header.__class__(
                        sn=ls_reply_header.sn,
                        reserved=ls_reply_header.reserved,
                        so_pv=ls_reply_header.so_pv,
                        de_pv=ShortPositionVector(
                            gn_addr=de_lpv.gn_addr,
                            tst=de_lpv.tst,
                            latitude=de_lpv.latitude,
                            longitude=de_lpv.longitude,
                        ),
                    )
            if basic_header.rhl > 1:
                body = secured_body if secured_body is not None else (
                    common_header.encode_to_bytes() + ls_reply_header.encode() + payload)
                self._forward(BufferedPacket(
                    basic_header=basic_header.set_rhl(basic_header.rhl - 1), body=body,
                    traffic_class=common_header.tc, kind=RouteKind.UNICAST,
                    so_pv=ls_reply_header.so_pv, sn=ls_reply_header.sn,
                    destination=ls_reply_header.de_pv,
                    sender_ll_address=sender_ll_address), origin=False)
        except DADException:
            print("Duplicate Address Detected!")
        except IncongruentTimestampException:
            print("Incongruent Timestamp Detected!")
        except DuplicatedPacketException:
            print("Packet is duplicated")
        except DecodeError as e:
            print(str(e))

    def gn_data_indicate_ls(
        self, packet: bytes, common_header: CommonHeader, basic_header: BasicHeader,
        secured_body: bytes | None = None, sender_ll_address: bytes | None = None,
    ) -> None:
        """
        Dispatch an incoming Location Service (LS) packet on its HST.

        Parameters
        ----------
        packet : bytes
            GeoNetworking packet body after Basic and Common headers.
        common_header : CommonHeader
            Common header of the received packet.
        basic_header : BasicHeader
            Basic header of the received packet.
        secured_body : bytes | None
            Secured Packet as received (relayed unmodified when forwarding).
        sender_ll_address : bytes | None
            Link-layer address of the previous sender, when known.
        """
        if common_header.hst == LocationServiceHST.LS_REQUEST:
            self.gn_data_indicate_ls_request(
                packet, common_header, basic_header, secured_body, sender_ll_address)
        elif common_header.hst == LocationServiceHST.LS_REPLY:
            self.gn_data_indicate_ls_reply(
                packet, common_header, basic_header, secured_body, sender_ll_address)
        else:
            raise NotImplementedError(f"Unknown LS HST: {common_header.hst}")

    def gn_data_indicate_gbc(
        self, packet: bytes, common_header: CommonHeader, basic_header: BasicHeader,
        secured_body: bytes | None = None, sender_ll_address: bytes | None = None,
    ) -> GNDataIndication | None:
        """
        Handle a GeoBroadcast GeoNetworking packet.

        Implements the forwarder and receiver operations of
        ETSI TS 103 836-4-1 V2.2.1 (2026-04), clause 10.3.11.3.

        Parameters
        ----------
        packet : bytes
            GeoNetworking packet to handle (without Basic and Common headers).
        common_header : CommonHeader
            CommonHeader of the packet.
        basic_header : BasicHeader
            BasicHeader of the packet; used for remaining LT and RHL (Table 38).
        secured_body : bytes | None
            Secured Packet as received (relayed unmodified when forwarding).
        sender_ll_address : bytes | None
            Link-layer address of the previous sender, when known.
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
        area_type = cast(Union[GeoBroadcastHST, GeoAnycastHST], common_header.hst)
        area_f = self.gn_geometric_function_f(
            area_type, area, self.ego_position_vector.latitude, self.ego_position_vector.longitude)
        # Step 3: with CBF, duplicates are handled by the forwarding algorithm
        # (NOTEs 1a/1b); otherwise DPD (clause A.2) runs in the LocT update.
        if self._cbf_applies(area_f >= 0) and self._cbf_handle_duplicate(BufferedPacket(
                basic_header=basic_header, body=b"", traffic_class=common_header.tc,
                kind=RouteKind.AREA, so_pv=gbc_extended_header.so_pv, sn=gbc_extended_header.sn,
                area_type=area_type, area=area, sender_ll_address=sender_ll_address)):
            return None
        try:
            # Step 4: execute DAD (§10.2.1.5)
            self.duplicate_address_detection(gbc_extended_header.so_pv.gn_addr)
            # Steps 5-6: update SO LocTE (with DPD)
            self.location_table.new_gbc_packet(gbc_extended_header, packet)
            indication: GNDataIndication | None = None
            # Step 7: inside/at border of the area -> GN-DATA.indication (Table 38)
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
            # Step 8: flush the LS and UC forwarding packet buffers of SO
            self._flush_source_buffers(gbc_extended_header.so_pv.gn_addr)
            # §B.3: Geographical area size control – do not forward if area exceeds itsGnMaxGeoAreaSize
            if Router._compute_area_size_m2(area_type, area) > self.mib.itsGnMaxGeoAreaSize * 1_000_000:
                return indication
            # §B.2: PDR enforcement – do not forward if SO PDR exceeds itsGnMaxPacketDataRate
            so_entry = self.location_table.get_entry(gbc_extended_header.so_pv.gn_addr)
            if so_entry is not None and so_entry.pdr > self.mib.itsGnMaxPacketDataRate * 1000:
                return indication
            # Steps 9-14: decrement RHL and forward
            self.gn_data_forward_gbc(basic_header, common_header, gbc_extended_header, packet,
                                     secured_body, sender_ll_address)
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
        self, packet: bytes, common_header: CommonHeader, basic_header: BasicHeader,
        secured_body: bytes | None = None, sender_ll_address: bytes | None = None,
    ) -> GNDataIndication | None:
        """
        Handle a multi-hop Topologically-Scoped Broadcast GeoNetworking packet.

        Implements the forwarder and receiver operations of
        ETSI TS 103 836-4-1 V2.2.1 (2026-04), clause 10.3.9.3.

        Parameters
        ----------
        packet : bytes
            GeoNetworking packet to handle (without Basic and Common headers).
        common_header : CommonHeader
            CommonHeader of the packet.
        basic_header : BasicHeader
            BasicHeader of the packet; used for remaining LT and RHL (Table 32).
        secured_body : bytes | None
            Secured Packet as received (relayed unmodified when forwarding).
        sender_ll_address : bytes | None
            Link-layer address of the previous sender, when known.
        """
        tsb_extended_header = TSBExtendedHeader.decode(packet[0:28])
        packet = packet[28:]
        try:
            # Step 4: execute DAD (§10.2.1.5)
            self.duplicate_address_detection(tsb_extended_header.so_pv.gn_addr)
            # Steps 3, 5-6: DPD and create/update SO LocTE (PV, PDR, IS_NEIGHBOUR per NOTE 1)
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
            # Step 8: flush the LS and UC forwarding packet buffers of SO
            self._flush_source_buffers(tsb_extended_header.so_pv.gn_addr)
            # §B.2: PDR enforcement – do not forward if SO PDR exceeds itsGnMaxPacketDataRate
            so_entry = self.location_table.get_entry(tsb_extended_header.so_pv.gn_addr)
            if so_entry is not None and so_entry.pdr > self.mib.itsGnMaxPacketDataRate * 1000:
                return indication
            # Step 9: decrement RHL; if RHL == 0 discard
            if basic_header.rhl > 1:
                # Steps 10-12: SCF buffering or broadcast
                body = secured_body if secured_body is not None else (
                    common_header.encode_to_bytes() + tsb_extended_header.encode() + packet)
                self._forward(BufferedPacket(
                    basic_header=basic_header.set_rhl(basic_header.rhl - 1), body=body,
                    traffic_class=common_header.tc, kind=RouteKind.BROADCAST,
                    so_pv=tsb_extended_header.so_pv, sn=tsb_extended_header.sn,
                    sender_ll_address=sender_ll_address), origin=False)
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
        # ETSI TS 103 836-4-1 V2.2.1 (2026-04). Section 10.3.6.3:
        # Receiver operations are identical to SHB (§10.3.10.3) except step 8.
        try:
            long_position_vector = LongPositionVector.decode(packet[0:24])
            packet = packet[24:]
            # Step 3: execute DAD (§10.2.1.5): a Beacon is single-hop, so an SO
            # with our address is another station.
            if long_position_vector.gn_addr == self.mib.itsGnLocalGnAddr:
                self.resolve_address_conflict()
            # Steps 4-6: update SO LocTE (PV, PDR, IS_NEIGHBOUR)
            self.location_table.new_shb_packet(long_position_vector, packet)
            # Flush the LS and UC forwarding packet buffers of SO
            self._flush_source_buffers(long_position_vector.gn_addr)
        except DADException:
            print("Duplicate Address Detected!")
        except IncongruentTimestampException:
            print("Incongruent Timestamp Detected!")
        except DuplicatedPacketException:
            print("Packet is duplicated")
        except DecodeError as e:
            print(str(e))

    def _link_layer_dad(self, sender_ll_address: bytes | None) -> None:
        """DAD of clause 10.2.1.5 step 1b: a frame whose sender link-layer address is
        ours comes from another station using our address."""
        if sender_ll_address is not None and bytes(sender_ll_address) == self.mib.itsGnLocalGnAddr.mid.mid:
            self.resolve_address_conflict()

    def _process_unsecured(self, packet: bytes, basic_header: BasicHeader) -> None:
        """
        An unsecured packet received with ``itsGnSecurity`` ENABLED. Clause 10.3.3
        step 2a would process it like any packet; this implementation restricts it
        so that unauthenticated packets cannot alter the GeoNetworking state: only
        a SHB is accepted, and it is passed to the upper entity without DAD, LocT
        update, buffer flush or forwarding (no Beacon, LS, GUC, GAC, GBC or
        multi-hop TSB). Its GN-DATA.indication carries no security report; BTP
        delivers it only to the ports open to unsecured packets (the CRL / CTL
        broadcast of ETSI TS 103 601 V2.1.1 clause 5.4.2, sent as SHB, CPS_003).
        """
        try:
            common_header = CommonHeader.decode_from_bytes(packet[0:8])
            if (common_header.ht != HeaderType.TSB or common_header.hst != TopoBroadcastHST.SINGLE_HOP
                    or basic_header.rhl > common_header.mhl):
                return
            body = packet[8:]
            indication = self._shb_indication(
                LongPositionVector.decode(body[0:24]), body[28:], common_header, basic_header)
        except (DecodeError, ValueError, IndexError):
            return
        if self.indication_callback:
            self.indication_callback(indication)

    def process_basic_header(self, packet: bytes, sender_ll_address: bytes | None = None) -> None:
        """Basic Header processing (clause 10.3.3) and dispatch."""
        basic_header = BasicHeader.decode_from_bytes(packet[0:4])
        remaining = packet[4:]
        if basic_header.version != self.mib.itsGnProtocolVersion:
            raise NotImplementedError("Version not implemented")
        if basic_header.nh == BasicNH.COMMON_HEADER:
            if self.mib.itsGnSecurity == GnSecurity.ENABLED:
                self._process_unsecured(remaining, basic_header)
                return
            self.process_common_header(remaining, basic_header, sender_ll_address=sender_ll_address)
        elif basic_header.nh == BasicNH.SECURED_PACKET:
            self.process_security_header(remaining, basic_header, sender_ll_address=sender_ll_address)
        else:
            raise NotImplementedError("ANY next header not implemented")

    def process_common_header(
        self, packet: bytes, basic_header: BasicHeader,
        secured_body: bytes | None = None, sender_ll_address: bytes | None = None,
        security: SNVERIFYConfirm | None = None,
    ) -> None:
        """
        Common Header processing (clause 10.3.5) and dispatch on the HT field.

        ``secured_body`` is the Secured Packet the plain ``packet`` was
        verified from; forwarders relay it unmodified.
        """
        indication: GNDataIndication | None = GNDataIndication()
        common_header = CommonHeader.decode_from_bytes(packet[0:8])
        packet = packet[8:]
        # Step 1: MHL check
        if basic_header.rhl > common_header.mhl:
            raise DecapError("Hop limit exceeded")
        rx_args = (secured_body, sender_ll_address)
        if common_header.ht == HeaderType.ANY:
            raise NotImplementedError(
                "Any packet (Common Header) not implemented")
        if common_header.ht == HeaderType.BEACON:
            self.gn_data_indicate_beacon(packet)
            indication = None
        elif common_header.ht == HeaderType.GEOUNICAST:
            indication = self.gn_data_indicate_guc(packet, common_header, basic_header, *rx_args)
        elif common_header.ht == HeaderType.GEOANYCAST:
            indication = self.gn_data_indicate_gac(packet, common_header, basic_header, *rx_args)
        elif common_header.ht == HeaderType.GEOBROADCAST:
            indication = self.gn_data_indicate_gbc(packet, common_header, basic_header, *rx_args)
        elif common_header.ht == HeaderType.TSB:
            if common_header.hst == TopoBroadcastHST.SINGLE_HOP:
                indication = self.gn_data_indicate_shb(packet, common_header, basic_header)
            elif common_header.hst == TopoBroadcastHST.MULTI_HOP:
                indication = self.gn_data_indicate_tsb(packet, common_header, basic_header, *rx_args)
            else:
                raise NotImplementedError("TopoBroadcast not implemented")
        elif common_header.ht == HeaderType.LS:
            self.gn_data_indicate_ls(packet, common_header, basic_header, *rx_args)
            indication = None   # LS handling never delivers to the upper entity
        else:
            raise NotImplementedError(
                "Any packet (Common Header) not implemented")
        # Step 2: forward the buffered packets, re-executing their forwarding
        # algorithm. Done after the packet updated the LocT, so that a new
        # neighbour announced by this very packet is taken into account.
        self._flush_forwarding_buffers()
        if indication is not None and security is not None:
            # Table 38: results of the security processing (SN-DECAP / SN-VERIFY)
            indication = dataclass_replace(
                indication,
                security_report=security.report.value,
                certificate_id=security.certificate_id,
                its_aid=int.from_bytes(security.its_aid, "big") if security.its_aid else None,
                security_permissions=security.permissions,
            )
        if self.indication_callback and indication is not None:
            self.indication_callback(indication)

    def set_verify_observer(self, observer: Callable[[bytes, SNVERIFYConfirm], None]) -> None:
        """
        Call ``observer`` with the outcome of every verification of a received
        secured packet (SN-VERIFY.confirm, ETSI TS 102 723-8), whatever the
        report: the secured message (Ieee1609Dot2Data after the Basic Header)
        and the confirm. For logging and test instrumentation; it does not change
        the processing of the packet. Mirrors ``Router::set_verify_observer``
        in RustFlexstack.
        """
        self.verify_observer = observer

    def process_security_header(
        self, packet: bytes, basic_header: BasicHeader, sender_ll_address: bytes | None = None
    ) -> None:
        """Secured packet processing (clause 10.3.3): verify, then process the plain packet."""
        if self.verify_service is None:
            print("Secured packet received but no VerifyService configured, discarding")
            return
        verify_confirm = self.verify_service.verify(
            SNVERIFYRequest(
                sec_header=b"",
                sec_header_length=0,
                message=packet,
                message_length=len(packet),
            )
        )
        if self.verify_observer is not None:
            self.verify_observer(packet, verify_confirm)
        if verify_confirm.report != ReportVerify.SUCCESS:
            print(
                f"Secured packet verification failed: {verify_confirm.report}")
            return
        # DAD (clause 10.2.1.5 step 1b) on a verified packet only (see gn_data_indicate).
        self._link_layer_dad(sender_ll_address)
        # plain_message layout: Common Header (8 bytes) | Extended Header + payload.
        # The Secured Packet is kept so that forwarders relay it unmodified.
        # The Basic Header keeps NH = SECURED_PACKET for the relayed packet.
        self.process_common_header(
            verify_confirm.plain_message, basic_header,
            secured_body=packet, sender_ll_address=sender_ll_address, security=verify_confirm)

    def gn_data_indicate(self, packet: bytes, sender_ll_address: bytes | None = None) -> None:
        """
        Indicate a GeoNetworking packet received from the ALI.

        Parameters
        ----------
        packet : bytes
            GeoNetworking packet to indicate.
        sender_ll_address : bytes | None
            Link-layer source address of the frame (the previous sender), when
            the ALI provides it; used by the CBF algorithms (PV_SE).

        Raises
        ------
        NotImplementedError : Version not implemented
        """
        # DAD (clause 10.2.1.5 step 1b): another station sends with our link-layer
        # address. With itsGnSecurity ENABLED only after the packet verified
        # (process_security_header): a forged frame cannot change our address.
        if self.mib.itsGnSecurity != GnSecurity.ENABLED:
            self._link_layer_dad(sender_ll_address)
        try:
            self.process_basic_header(packet, sender_ll_address)
        except (NotImplementedError, DecapError, DecodeError, ValueError, IndexError) as error:
            # A malformed or unsupported packet (e.g. wrong version, clause
            # 10.3.3; RHL > MHL, clause 10.3.5) is discarded, never propagated
            # to the link layer's receive loop.
            logging.getLogger("geonet").debug("Discarded GN packet: %s", error)

    def resolve_address_conflict(self) -> None:
        """
        Duplicate address detected (clause 10.2.1.5 steps 2-3): with
        auto-address configuration, take a new random MID (unicast, locally
        administered) for the GN address, update itsGnLocalGnAddr and the ego
        position vector, and notify :attr:`address_change_callback`.
        """
        if self.mib.itsGnLocalGnAddrConfMethod != LocalGnAddrConfMethod.AUTO:
            return
        mid = bytearray(random.getrandbits(8) for _ in range(6))
        mid[0] = (mid[0] | 0x02) & 0xFE
        new_addr = dataclass_replace(self.mib.itsGnLocalGnAddr, mid=MID(bytes(mid)))
        self.mib = dataclass_replace(self.mib, itsGnLocalGnAddr=new_addr)
        with self.ego_position_vector_lock:
            self.ego_position_vector = dataclass_replace(self.ego_position_vector, gn_addr=new_addr)
        if self.address_change_callback is not None:
            self.address_change_callback(new_addr)

    def media_dependent_address_ok(self, link_layer_mid: MID | None = None) -> bool:
        """
        :meth:`MIB.media_dependent_address_ok` with ``link_layer_mid``
        defaulting to the MID reported by the attached link layer (ETSI TS
        103 836-4-2 clause 6.1, TS 103 836-4-3 clause 5.2).
        """
        if link_layer_mid is None and isinstance(self.link_layer, LinkLayer):
            link_layer_mid = self.link_layer.media_dependent_mid()
        return self.mib.media_dependent_address_ok(link_layer_mid)

    def duplicate_address_detection(self, gn_addr: GNAddress) -> None:
        """
        Perform Duplicate Address Detection (DAD) on the given GNAddress.
        Specified in ETSI TS 103 836-4-1 V2.2.1 (2026-04). Section 10.2.1.5

        Parameters
        ----------
        gn_addr : GNAddress
            GNAddress to perform Duplicate Address Detection on.
        """
        if self.mib.itsGnLocalGnAddr == gn_addr:
            # Multi-hop packets with our address as SO are our own packets
            # relayed back by a forwarder: not processed. Conflicts are
            # resolved on single-hop packets and link-layer addresses
            # (resolve_address_conflict).
            raise DADException("Duplicate Address Detected!")

    def refresh_ego_position_vector(self, tpv: dict) -> None:
        """
        Refresh the ego position vector.
        """
        with self.ego_position_vector_lock:
            self.ego_position_vector = self.ego_position_vector.refresh_with_tpv_data(
                tpv)
