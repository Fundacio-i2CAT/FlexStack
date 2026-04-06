from enum import Enum


class SecurityProfile(Enum):
    """
    Security profile of a message.
    """
    NO_SECURITY = 0
    COOPERATIVE_AWARENESS_MESSAGE = 1
    DECENTRALIZED_ENVIRONMENTAL_NOTIFICATION_MESSAGE = 2
    VRU_AWARENESS_MESSAGE = 3
