from __future__ import annotations
from collections.abc import Callable
from typing import TYPE_CHECKING
import inspect

if TYPE_CHECKING:  # pragma: no cover
    from ..geonet.gn_address import MID


class LinkLayer:
    """
    Link Layer class to connect layer 2 and layer 3.

    Attributes
    ----------
    receive_callback : Callable[[bytes], None]
        Callback function to receive packets.

    Methods
    -------
    send(bytes)
        Send a packet to the LL.
    receive()
        Receive a packet from the LL. (To be called in a thread)


    """

    def __init__(self, receive_callback: Callable[[bytes], None]) -> None:
        """
        Create a Link Layer object.

        Parameters
        ----------
        iface : str
            Interface to use. (Linux only)
        mac_address : bytes
            MAC address of the interface.
        receive_callback : Callable[[bytes], None]
            Callback function to receive packets.

        Raises
        ------
        OSError:
            If the interface is not found.
        Exception:
            If the MAC address is not 6 bytes long.
        """
        self.receive_callback = receive_callback
        self._callback_takes_sender = _accepts_sender(receive_callback)

    def deliver(self, packet: bytes, sender_ll_address: bytes | None = None) -> None:
        """
        Pass a received packet to the receive callback. The link-layer source
        address is passed as ``sender_ll_address`` when the callback declares
        that parameter (e.g. ``Router.gn_data_indicate``), which lets the
        GeoNetworking CBF algorithms identify the previous sender.
        """
        if self._callback_takes_sender and sender_ll_address is not None:
            self.receive_callback(packet, sender_ll_address=sender_ll_address)  # type: ignore[call-arg]
        else:
            self.receive_callback(packet)

    def media_dependent_mid(self) -> MID | None:
        """
        MID that the GeoNetworking address shall carry on this access layer
        (ETSI TS 103 836-4-2 clause 6.1, TS 103 836-4-3 clause 5.2), or None
        when the link layer does not know its address.
        """
        return None

    def send(self, packet: bytes, destination: bytes | None = None) -> None:
        """
        Send a packet to the lower layer.

        Parameters
        ----------
        packet : bytes
            Packet to send.
        destination : bytes | None
            Link-layer address of the next hop (6 octets) for a GeoNetworking
            unicast forwarding step (ETSI TS 103 836-4-1 clause E.2,
            NH_LL_ADDR); None for the broadcast address.

        Raises
        ------
        SendingException:
            If the packet cannot be sent.
        PacketTooLongException:
            If the packet is too long.
        NotImplementedError:
            If the method is not implemented.
        """
        raise NotImplementedError("All the Link Layers should implement this")


def _accepts_sender(callback: Callable) -> bool:
    """True when ``callback`` has a ``sender_ll_address`` parameter."""
    try:
        return "sender_ll_address" in inspect.signature(callback).parameters
    except (TypeError, ValueError):
        return False
