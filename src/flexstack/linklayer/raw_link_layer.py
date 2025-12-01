from __future__ import annotations
import socket
import platform
from collections.abc import Callable
import threading
from .exceptions import (
    WindowsNotSupportedException,
    InvalidMACAddressException,
    PacketTooLongException,
)
from .link_layer import LinkLayer


def raise_exception_if_windows(func):
    """
    Decorator to raise an exception if the function is called on a Windows system.
    """

    def wrapper(*args, **kwargs):
        if platform.system() == "Windows":
            raise WindowsNotSupportedException(
                "Can't currently run RawLinkLayer on a Windows system"
            )
        return func(*args, **kwargs)

    return wrapper


@raise_exception_if_windows
class RawLinkLayer(LinkLayer):
    """
    Link Layer class to connect layer 2 and layer 3.

    Attributes
    ----------
    receive_callback : Callable[[bytes], None]
        Callback function to receive packets.
    sock : socket
        Socket to send and receive packets.
    mac_address : bytes
        MAC address of the interface.

    Methods
    -------
    send(bytes)
        Send a packet to the LL.
    receive()
        Receive a packet from the LL. (To be called in a thread)


    """

    def __init__(
        self, iface: str, mac_address: bytes, receive_callback: Callable[[bytes], None]
    ) -> None:
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
        super().__init__(receive_callback)
        self.sock = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x8947)
        )
        self.sock.bind((iface, 0))
        if len(mac_address) != 6:
            raise InvalidMACAddressException("MAC address must be 6 bytes long")
        self.mac_address = mac_address
        self.receiving_thread = threading.Thread(target=self.receive, daemon=True)
        self.receiving_thread.start()

    def __del__(self) -> None:
        """
        Close the socket.
        """
        self.sock.close()

    def send(self, packet: bytes) -> None:
        """
        Send a packet to the LL.

        Parameters
        ----------
        packet : bytes
            Packet to send.
        """
        dest = b"\xff\xff\xff\xff\xff\xff"
        ethertype = b"\x89\x47"
        packet = dest + self.mac_address + ethertype + packet
        if len(packet) > 1500:
            raise PacketTooLongException("Packet too long")
        self.sock.send(packet)

    def receive(self) -> None:
        """
        Receive a packet from the LL.
        """
        while True:
            try:
                m = self.sock.recv(1500)
                try:
                    if m[0:6] == self.mac_address:
                        self.receive_callback(m[14:])
                    elif (
                        m[0:6] == b"\xff\xff\xff\xff\xff\xff"
                        and m[6:12] != self.mac_address
                    ):
                        self.receive_callback(m[14:])
                except NotImplementedError as e:
                    print("Error decoding packet: " + str(e))
            except OSError:
                break
