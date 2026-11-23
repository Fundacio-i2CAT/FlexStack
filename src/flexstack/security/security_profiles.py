from enum import Enum


class SecurityProfile(Enum):
    """
    Security profile of a message (parameter Security profile of GN-DATA.request,
    ETSI TS 103 836-4-1 V2.2.1 clause J.2).

    ``NO_SECURITY`` means the parameter is not set: with ``itsGnSecurity``
    ENABLED the default profile signs the packet (NOTE of table 37). ``UNSECURED``
    requests an unsecured packet (Basic Header NH = Common Header, table 18) even
    with ``itsGnSecurity`` ENABLED, as for the CRL / CTL broadcast, whose SM-PDU is
    signed by the issuing authority (ETSI TS 103 601 V2.1.1 clause 5.4.2).
    """
    NO_SECURITY = 0
    COOPERATIVE_AWARENESS_MESSAGE = 1
    DECENTRALIZED_ENVIRONMENTAL_NOTIFICATION_MESSAGE = 2
    VRU_AWARENESS_MESSAGE = 3
    UNSECURED = 4
