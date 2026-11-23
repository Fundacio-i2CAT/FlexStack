from __future__ import annotations
from dataclasses import replace as dataclass_replace
from collections.abc import Callable
from types import MappingProxyType
import logging

from .btp_header import BTPAHeader, BTPBHeader
from .service_access_point import BTPDataIndication, BTPDataRequest
from ..geonet.common_header import CommonNH
from ..geonet.service_access_point import HeaderType
from ..geonet.mib import GnSecurity
from ..geonet.service_access_point import GNDataIndication, GNDataRequest
from ..geonet.router import Router as GNRouter


class Router:
    """
    BTP Router.

    Handles the routing of BTP packets. As specified in ETSI EN 302 636-5-1 V2.1.0 (2017-05).

    Attributes
    ----------
    indication_callbacks : MappingProxyType[int, Callable[[BTPDataIndication], None]] | None
        MappingProxyType of indication callbacks. The key is the port and the value is the callback.
    gn_router : GNRouter
        Geonetworking Router.
    """

    def __init__(self, gn_router: GNRouter) -> None:
        self.logging = logging.getLogger("btp")
        self.pre_indication_callbacks: dict[int,
                                            Callable[[BTPDataIndication], None]] = {}
        self.indication_callbacks: MappingProxyType[int, Callable[[
            BTPDataIndication], None]] | None = None
        self.gn_router = gn_router
        # Ports whose service accepts unsecured packets although itsGnSecurity is
        # ENABLED (the CRL / CTL broadcast, ETSI TS 103 601 V2.1.1 clause 5.4.2).
        self.unsecured_ports: set[int] = set()

        self.logging.info("BTP Router Initialized!")

    def freeze_callbacks(self):
        """
        Freezes the indication callbacks. After calling this method, no more callbacks can be registered.
        """
        self.indication_callbacks = MappingProxyType(
            dict(self.pre_indication_callbacks))

    def register_indication_callback_btp(
        self, port: int, callback: Callable[[BTPDataIndication], None], *, accept_unsecured: bool = False
    ) -> None:
        """
        Registers a callback for a given port.

        Parameters
        ----------
        port : int
            Port to register the callback for.
        callback : Callable[[BTPDataIndication], None]
            Callback to register.
        accept_unsecured : bool
            Deliver unsecured packets to this port although ``itsGnSecurity`` is
            ENABLED (a service whose payload authenticates itself). Otherwise an
            unsecured packet is discarded when GN security is enabled.
        """
        if self.indication_callbacks is not None:
            raise RuntimeError("Cannot register callbacks after freezing")
        self.pre_indication_callbacks[port] = callback
        if accept_unsecured:
            self.unsecured_ports.add(port)
        self.logging.info("Indication callback registered")

    def btp_data_request(self, request: BTPDataRequest) -> None:
        """
        Handles a BTPDataRequest.

        Parameters
        ----------
        request : BTPDataRequest
            BTPDataRequest to handle.
        """
        if request.btp_type == CommonNH.BTP_B:
            header = BTPBHeader(
                destination_port=request.destination_port,
                destination_port_info=request.destination_port_info,
            )
            data = header.encode() + request.data
            gn_data_request = GNDataRequest(
                upper_protocol_entity=request.btp_type,
                packet_transport_type=request.gn_packet_transport_type,
                area=request.gn_area,
                # EN 302 636-5-1 table 6: Destination address (GeoUnicast).
                destination=(request.gn_destination_address
                             if request.gn_packet_transport_type.header_type == HeaderType.GEOUNICAST else None),
                communication_profile=request.communication_profile,
                traffic_class=request.traffic_class,
                security_profile=request.security_profile,
                its_aid=request.its_aid,
                security_permissions=request.security_permissions,
                data=data,
                length=len(data),
                max_hop_limit=request.gn_max_hop_limit,
                max_packet_lifetime=request.gn_max_packet_lifetime,
            )
            self.logging.debug(
                "Sending BTP Data Request: %s", gn_data_request.data)
            self.gn_router.gn_data_request(gn_data_request)
        elif request.btp_type == CommonNH.BTP_A:
            header = BTPAHeader(
                destination_port=request.destination_port,
                source_port=request.source_port,
            )
            data = header.encode() + request.data
            gn_data_request = GNDataRequest(
                upper_protocol_entity=request.btp_type,
                packet_transport_type=request.gn_packet_transport_type,
                area=request.gn_area,
                # EN 302 636-5-1 table 6: Destination address (GeoUnicast).
                destination=(request.gn_destination_address
                             if request.gn_packet_transport_type.header_type == HeaderType.GEOUNICAST else None),
                communication_profile=request.communication_profile,
                traffic_class=request.traffic_class,
                security_profile=request.security_profile,
                its_aid=request.its_aid,
                security_permissions=request.security_permissions,
                data=data,
                length=len(data),
                max_hop_limit=request.gn_max_hop_limit,
                max_packet_lifetime=request.gn_max_packet_lifetime,
            )
            self.logging.debug(
                "Sending BTP-A Data Request: %s", gn_data_request.data)
            self.gn_router.gn_data_request(gn_data_request)
        else:
            raise ValueError("Unknown BTP Header Type")

    def btp_b_data_indication(self, gn_data_indication: GNDataIndication) -> None:
        """
        Handles a BTPBDataIndication.

        Parameters
        ----------
        gn_data_indication : GNDataIndication
            GNDataIndication to handle.
        """
        indication = BTPDataIndication.initialize_with_gn_data_indication(
            gn_data_indication)
        header = BTPBHeader.decode(gn_data_indication.data)
        indication = indication.set_destination_port_and_info(
            destination_port=header.destination_port,
            destination_port_info=header.destination_port_info
        )
        self._deliver(indication)

    def btp_a_data_indication(self, gn_data_indication: GNDataIndication) -> None:
        """
        Handles a BTPADataIndication.

        Parameters
        ----------
        gn_data_indication : GNDataIndication
            GNDataIndication to handle.
        """
        base = BTPDataIndication.initialize_with_gn_data_indication(
            gn_data_indication)
        header = BTPAHeader.decode(gn_data_indication.data)
        indication = dataclass_replace(
            base,
            source_port=header.source_port,
            destination_port=header.destination_port,
            destination_port_info=0,
        )
        self._deliver(indication)

    def _deliver(self, indication: BTPDataIndication) -> None:
        """Hand ``indication`` to the service of its destination port. With
        ``itsGnSecurity`` ENABLED an unsecured packet (no security report) reaches
        only a port registered with ``accept_unsecured``."""
        if self.indication_callbacks is None:
            raise RuntimeError("Indication callbacks not frozen")
        if (indication.gn_security_report is None
                and self.gn_router.mib.itsGnSecurity == GnSecurity.ENABLED
                and indication.destination_port not in self.unsecured_ports):
            self.logging.debug("Unsecured packet to port %d discarded", indication.destination_port)
            return
        callback = self.indication_callbacks.get(indication.destination_port)
        if callback:
            callback(indication)

    def btp_data_indication(self, gn_data_indication: GNDataIndication) -> None:
        """
        Handles a BTPDataIndication.

        Parameters
        ----------
        gn_data_indication : GNDataIndication
            GNDataIndication to handle.
        """
        if gn_data_indication.upper_protocol_entity == CommonNH.BTP_B:
            self.btp_b_data_indication(gn_data_indication)
        elif gn_data_indication.upper_protocol_entity == CommonNH.BTP_A:
            self.btp_a_data_indication(gn_data_indication)
        else:
            raise ValueError("Unknown BTP Header Type")
