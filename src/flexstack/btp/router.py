from __future__ import annotations
from collections.abc import Callable
from types import MappingProxyType
import logging

from .btp_header import BTPBHeader
from .service_access_point import BTPDataIndication, BTPDataRequest
from ..geonet.common_header import CommonNH
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

        self.logging.info("BTP Router Initialized!")

    def freeze_callbacks(self):
        """
        Freezes the indication callbacks. After calling this method, no more callbacks can be registered.
        """
        self.indication_callbacks = MappingProxyType(
            dict(self.pre_indication_callbacks))

    def register_indication_callback_btp(
        self, port: int, callback: Callable[[BTPDataIndication], None]
    ) -> None:
        """
        Registers a callback for a given port.

        Parameters
        ----------
        port : int
            Port to register the callback for.
        callback : Callable[[BTPDataIndication], None]
            Callback to register.
        """
        if self.indication_callbacks is not None:
            raise RuntimeError("Cannot register callbacks after freezing")
        self.pre_indication_callbacks[port] = callback
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
                communication_profile=request.communication_profile,
                traffic_class=request.traffic_class,
                data=data,
                length=len(data)
            )
            self.logging.debug(
                "Sending BTP Data Request: %s", gn_data_request.data)
            self.gn_router.gn_data_request(gn_data_request)
        elif request.btp_type == CommonNH.BTP_A:
            raise NotImplementedError("BTPADataRequest not implemented")
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
        if self.indication_callbacks:
            callback = self.indication_callbacks.get(
                indication.destination_port)
            if callback:
                callback(indication)
        else:
            raise RuntimeError("Indication callbacks not frozen")

    def btp_a_data_indication(self, gn_data_indication: GNDataIndication) -> None:
        """
        Handles a BTPADataIndication.

        Parameters
        ----------
        gn_data_indication : GNDataIndication
            GNDataIndication to handle.
        """
        raise NotImplementedError("BTPADataIndication not implemented")

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
