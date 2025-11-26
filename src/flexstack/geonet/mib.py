from enum import Enum
from dataclasses import dataclass, field
from typing import Optional

from .gn_address import GNAddress


class LocalGnAddrConfMethod(Enum):
    """
    LocalGnAddrConfMethod. As specified in ETSI EN 302 636-4-1 V1.4.1 (2020-01). Annex H.

    Attributes
    ----------
    AUTO (0) :
        Local GN_ADDR is configured from MIB
    MANAGED (1) :
        Local GN_ADDR is configured via the GN management using the service primitive GN-MGMT (annex K)
    ANONYMOUS (2) : Local GN_ADDR is configured by the Security entity
    """

    AUTO = 0
    MANAGED = 1
    ANONYMOUS = 2


class GnIsMobile(Enum):
    """
    GnIsMobile. As specified in ETSI EN 302 636-4-1 V1.4.1 (2020-01). Annex H.

    Attributes
    ----------
    STATIONARY (0) :
        The GeoAdhoc router is stationary
    MOBILE (1) :
        The GeoAdhoc router is mobile
    """

    STATIONARY = 0
    MOBILE = 1


class GnIfType(Enum):
    """
    GnIfType. As specified in ETSI EN 302 636-4-1 V1.4.1 (2020-01). Annex H.

    Attributes
    ----------
    UNSPECIFIED (0) :
        The interface type is unspecified
    ITS-G5 (1) :
        The interface is an ITS-G5 interface
    LTE-V2X (2) :
        The interface is an LTE-V2X interface
    """

    UNSPECIFIED = 0
    ITS_G5 = 1
    LTE_V2X = 2


class GnSecurity(Enum):
    """
    GnSecurity. As specified in ETSI EN 302 636-4-1 V1.4.1 (2020-01). Annex H.

    Attributes
    ----------
    DISABLED (0) :
        Security is disabled
    ENABLED (1) :
        Security is enabled
    """

    DISABLED = 0
    ENABLED = 1


class SnDecapResultHandling(Enum):
    """
    SnDecapResultHandling. As specified in ETSI EN 302 636-4-1 V1.4.1 (2020-01). Annex H.

    Attributes
    ----------
    STRICT (0) :
        The packet is dropped
    NON-STRICT (1) :
        The packet is forwarded
    """

    STRICT = 0
    NON_STRICT = 1


class NonAreaForwardingAlgorithm(Enum):
    """
    NonAreaForwardingAlgorithm. As specified in ETSI EN 302 636-4-1 V1.4.1 (2020-01). Annex H.

    Attributes
    ----------
    UNSPECIFIED (0) :
        The forwarding algorithm is unspecified
    GREEDY (1) :
        Default forwarding algorithm outside target area
    """

    UNSPECIFIED = 0
    GREEDY = 1


class AreaForwardingAlgorithm(Enum):
    """
    AreaForwardingAlgorithm. As specified in ETSI EN 302 636-4-1 V1.4.1 (2020-01). Annex H.

    Attributes
    ----------
    UNSPECIFIED (0) :
        The forwarding algorithm is unspecified
    SIMPLE (1) :
        The simple forwarding algorithm inside target area
    CBF (1) :
        Default forwarding algorithm inside target area
    """

    UNSPECIFIED = 0
    SIMPLE = 1
    CBF = 2


@dataclass(frozen=True)
class MIB:
    # pylint: disable=too-many-instance-attributes, invalid-name
    """Management Information Base (MIB) for GeoNetworking. As specified in ETSI EN 302 636-4-1 V1.4.1 (2020-01).
    Annex H.

    Attributes
    ----------
    itsGnLocalGnAddr : GNAddress
        GeoNetworking address of the GeoAdhoc router
    itsGnLocalGnAddrConfMethod : LocalGnAddrConfMethod
        Configuration method for the GeoNetworking address of the GeoAdhoc router
    itsGnProtocolVersion : int
        GeoNetworking protocol version
    itsGnIsMobile : GnIsMobile
        Mobility status of the GeoAdhoc router
    itsGnIfType : GnIfType
        Interface type
    itsGnMinUpdateFrequencyEPV : int
        Minimum update frequency of EPV in [1/ms]
    itsGnPaiInterval : int
        Distance related to the confidence interval for latitude and longitude [m].
    itsGnMaxSduSize : int
        Maximum size of an SDU in [byte].
    itsGnMaxGeoNetworkingHeaderSize : int
        Maximum size of a GeoNetworking header in [byte].
    itsGnLifetimeLocTE : int
        Lifetime of location table entry [s]
    itsGnSecurity : GnSecurity
        Security status
    itsGnSnDecapResultHandling : SnDecapResultHandling
        Handling of the result of the security decapsulation
    itsGnLocationServiceMaxRetrans : int
        Maximum number of retransmissions for location service requests
    itsGnLocationServiceRetransmitTimer : int
        Duration of Location service retransmit timer [ms]
    itsGnLocationServicePacketBufferSize : int
        Size of Location service packet buffer [Octets]
    itsGnBeaconServiceRetransmitTimer : int
        Duration of Beacon service retransmit timer [ms]
    itsGnBeaconServiceMaxJitter : int
        Maximum jitter for Beacon service retransmission [ms]
    itsGnDefaultHopLimit : int
        Default hop limit
    itsGnDPLLength : int
        Length of Duplicate Packet List (DPL) per source
    itsGnMaxPacketLifetime : int
        Maximum packet lifetime [s]
    itsGnDefaultPacketLifetime : int
        Default packet lifetime [s]
    itsGnMaxPacketDataRate : int
        Maximum packet data rate [ko/s]
    itsGnMaxPacketDataRateEmaBeta : int
        Weight factor for the Exponential Moving Average of the packet data rate PDR in percent
    itsGnMaxGeoAreaSize : int
        Maximum size of the geographical area for a GBC and GAC packet [km2]
    itsGnMinPacketRepetitionInterval : int
        Lower limit of the packet repetition interval [ms]
    itsGnNonAreaForwardingAlgorithm : NonAreaForwardingAlgorithm
        Forwarding algorithm outside target area
    itsGnAreaForwardingAlgorithm : AreaForwardingAlgorithm
        Forwarding algorithm inside target area
    itsGnCbfMinTime : int
        Minimum duration a GN packet shall be buffered in the CBF packet buffer [ms]
    itsGnCbfMaxTime : int
        Maximum duration a GN packet shall be buffered in the CBF packet buffer [ms]
    itsGnDefaultMaxCommunicationRange : int
        Default maximum communication range [m]
    itsGnBroadcastCBFDefSectorAngle : int
        Default threshold angle for advanced GeoBroadcast algorithm in clause F.4 [degrees]
    itsGnUcForwardingPacketBufferSize : int
        Size of UC forwarding packet buffer [Ko]
    itsGnBcForwardingPacketBufferSize : int
        Size of BC forwarding packet buffer [Ko]
    itsGnCbfPacketBufferSize : int
        Size of CBF packet buffer [Ko]
    itsGnDefaultTrafficClass : int
        Default traffic class
    """

    itsGnLocalGnAddr: GNAddress = field(default_factory=GNAddress)
    itsGnLocalGnAddrConfMethod: LocalGnAddrConfMethod = LocalGnAddrConfMethod.AUTO
    itsGnProtocolVersion: int = 1
    itsGnIsMobile: GnIsMobile = GnIsMobile.MOBILE
    itsGnIfType: GnIfType = GnIfType.UNSPECIFIED
    itsGnMinUpdateFrequencyEPV: int = 1000
    itsGnPaiInterval: int = 80
    itsGnMaxSduSize: int = 1398
    itsGnMaxGeoNetworkingHeaderSize: int = 88
    itsGnLifetimeLocTE: int = 20
    itsGnSecurity: GnSecurity = GnSecurity.DISABLED
    itsGnSnDecapResultHandling: SnDecapResultHandling = SnDecapResultHandling.STRICT
    itsGnLocationServiceMaxRetrans: int = 10
    itsGnLocationServiceRetransmitTimer: int = 1000
    itsGnLocationServicePacketBufferSize: int = 1024
    itsGnBeaconServiceRetransmitTimer: int = 3000
    itsGnBeaconServiceMaxJitter: Optional[float] = None
    itsGnDefaultHopLimit: int = 10
    itsGnDPLLength: int = 8
    itsGnMaxPacketLifetime: int = 600
    itsGnDefaultPacketLifetime: int = 60
    itsGnMaxPacketDataRate: int = 100
    itsGnMaxPacketDataRateEmaBeta: int = 90
    itsGnMaxGeoAreaSize: int = 10
    itsGnMinPacketRepetitionInterval: int = 100
    itsGnNonAreaForwardingAlgorithm: NonAreaForwardingAlgorithm = NonAreaForwardingAlgorithm.GREEDY
    itsGnAreaForwardingAlgorithm: AreaForwardingAlgorithm = AreaForwardingAlgorithm.CBF
    itsGnCbfMinTime: int = 1
    itsGnCbfMaxTime: int = 100
    itsGnDefaultMaxCommunicationRange: int = 1000
    itsGnBroadcastCBFDefSectorAngle: int = 30
    itsGnUcForwardingPacketBufferSize: int = 256
    itsGnBcForwardingPacketBufferSize: int = 1024
    itsGnCbfPacketBufferSize: int = 256
    itsGnDefaultTrafficClass: int = 0

    def __post_init__(self) -> None:
        # compute dependent default
        if self.itsGnBeaconServiceMaxJitter is None:
            object.__setattr__(self, "itsGnBeaconServiceMaxJitter", self.itsGnBeaconServiceRetransmitTimer / 4)
