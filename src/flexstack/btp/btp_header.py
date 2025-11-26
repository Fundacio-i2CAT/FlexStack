from .service_access_point import BTPDataRequest
from dataclasses import dataclass


@dataclass(frozen=True)
class BTPAHeader:
    """
    BTP-A Header class.

    Specified in ETSI EN 302 636-5-1 V2.1.0 (2017-05). Section 7.2

    Attributes
    ----------
    destination_port : int
        (16 bit integer) Destination Port field of BTP-A Header
    source_port : int
        (16 bit integer) Source Port field of BTP-A Header
    """

    destination_port: int = 0
    source_port: int = 0

    @classmethod
    def initialize_with_request(cls, request: BTPDataRequest) -> "BTPAHeader":
        """
        Initialize a BTP-A Header from a BTPDataRequest.

        Parameters
        ----------
        request : BTPDataRequest
            Request to use for initialization.
        """
        return cls(destination_port=request.destination_port, source_port=request.source_port)

    def encode_to_int(self) -> int:
        """
        Encodes the BTP-A Header to an integer.

        Returns
        -------
        int
            Encoded BTP-A Header
        """
        return (self.destination_port << 16) | self.source_port

    def encode(self) -> bytes:
        """
        Encodes the BTP-A Header to bytes.

        Returns
        -------
        bytes
            Encoded BTP-A Header
        """
        return self.encode_to_int().to_bytes(4, byteorder='big')

    @classmethod
    def decode(cls, data: bytes) -> "BTPAHeader":
        """
        Decodes the BTP-A Header from bytes and returns a new instance.

        Parameters
        ----------
        data : bytes
            Bytes to decode.
        """
        destination_port = int.from_bytes(data[0:2], byteorder='big')
        source_port = int.from_bytes(data[2:4], byteorder='big')
        return cls(destination_port=destination_port, source_port=source_port)


@dataclass(frozen=True)
class BTPBHeader:
    """
    BTP-B Header class.

    Specified in ETSI EN 302 636-5-1 V2.1.0 (2017-05). Section 7.3

    Attributes
    ----------
    destination_port : int
        (16 bit integer) Destination Port field of BTP-B Header
    destination_port_info : int
        (16 bit integer) Destination Port Info field of BTP-B Header
    """

    destination_port: int = 0
    destination_port_info: int = 0

    @classmethod
    def initialize_with_request(cls, request: BTPDataRequest) -> "BTPBHeader":
        """
        Initialize a BTP-B Header from a BTPDataRequest.

        Parameters
        ----------
        request : BTPDataRequest
            Request to use for initialization.
        """
        return cls(destination_port=request.destination_port, destination_port_info=getattr(request, 'destination_port_info', 0))

    def encode_to_int(self) -> int:
        """
        Encodes the BTP-B Header to an integer.

        Returns
        -------
        int
            Encoded BTP-B Header
        """
        return (self.destination_port << 16) | self.destination_port_info

    def encode(self) -> bytes:
        """
        Encodes the BTP-B Header to bytes.

        Returns
        -------
        bytes
            Encoded BTP-B Header
        """
        return self.encode_to_int().to_bytes(4, byteorder='big')

    @classmethod
    def decode(cls, data: bytes) -> "BTPBHeader":
        """
        Decodes the BTP-B Header from bytes and returns a new instance.

        Parameters
        ----------
        data : bytes
            Bytes to decode.
        """
        destination_port = int.from_bytes(data[0:2], byteorder='big')
        destination_port_info = int.from_bytes(data[2:4], byteorder='big')
        return cls(destination_port=destination_port, destination_port_info=destination_port_info)
