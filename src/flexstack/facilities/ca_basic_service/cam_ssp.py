"""
CAM Service Specific Permissions (ETSI TS 103 900 V2.3.1 (2026-05), clause 6.2.2.2).

The SSP of a CAM Authorization Ticket is a BitmapSsp: octet 0 is the SSP
version, octets 1 and 2 hold one bit per protected CAM content (Table 3). A
CAM is consistent with the SSP when every protected content it carries has its
bit set; otherwise it "shall be considered as invalid from security
perspective".

Mirrors ``rustflexstack::facilities::ca_basic_service::cam_ssp``.
"""

from __future__ import annotations

from typing import Callable, List, Optional, Tuple

# vehicleRole value -> SpecialVehicleContainer alternative (clause 7.6).
ROLE_SPECIAL_CONTAINER = {
    1: "publicTransportContainer",
    2: "specialTransportContainer",
    3: "dangerousGoodsContainer",
    4: "roadWorksContainerBasic",
    5: "rescueContainer",
    6: "emergencyContainer",
    7: "safetyCarContainer",
}
# SpecialVehicleContainer alternative -> octet 1 bit (Table 3).
_CONTAINER_BIT = {
    "publicTransportContainer": 0x40,
    "specialTransportContainer": 0x20,
    "dangerousGoodsContainer": 0x10,
    "roadWorksContainerBasic": 0x08,
    "rescueContainer": 0x04,
    "emergencyContainer": 0x02,
    "safetyCarContainer": 0x01,
}
STATION_TYPE_ROAD_SIDE_UNIT = 15
TWO_WHEELER_CONTAINER_ID = 1
# Table 3: the two-wheeler bits require an SSP version greater than 2.
TWO_WHEELER_MIN_SSP_VERSION = 3

Permission = Tuple[int, int, int]
"""(octet, bit mask, minimum SSP version)."""


def required_permissions(
    cam: dict, decode_two_wheeler: Optional[Callable[[bytes], dict]] = None
) -> List[Permission]:
    """
    SSP bits needed by the protected content of a CAM (Table 3).

    ``decode_two_wheeler`` decodes the containerData of a TwoWheelerContainer
    (e.g. ``CAMCoder.decode_extension_container`` bound to id 1), used for the
    ``twoWheeler-cyclist`` bit; without it only the ``twoWheeler`` bit is derived.
    """
    params = cam["cam"]["camParameters"]
    needed: List[Permission] = []
    station_type = params["basicContainer"].get("stationType")
    hf_kind, hf = params["highFrequencyContainer"]
    if (station_type == STATION_TYPE_ROAD_SIDE_UNIT and hf_kind == "rsuContainerHighFrequency"
            and "protectedCommunicationZonesRSU" in hf):
        needed.append((1, 0x80, 0))
    special = params.get("specialVehicleContainer")
    if special is not None:
        kind, content = special
        needed.append((1, _CONTAINER_BIT[kind], 0))
        if kind == "roadWorksContainerBasic" and "closedLanes" in content:
            needed.append((2, 0x80, 0))
        if kind == "emergencyContainer" and "emergencyPriority" in content:
            bits = content["emergencyPriority"][0]
            if bits and bits[0] & 0x80:
                needed.append((2, 0x40, 0))          # requestForRightOfWay
            if bits and bits[0] & 0x40:
                needed.append((2, 0x20, 0))          # requestForFreeCrossingAtATrafficLight
        if kind == "safetyCarContainer":
            if content.get("trafficRule") == "noPassing":
                needed.append((2, 0x10, 0))
            if content.get("trafficRule") == "noPassingForTrucks":
                needed.append((2, 0x08, 0))
            if "speedLimit" in content:
                needed.append((2, 0x04, 0))
    for container in params.get("extensionContainers", []) or []:
        if container["containerId"] != TWO_WHEELER_CONTAINER_ID:
            continue
        needed.append((2, 0x02, TWO_WHEELER_MIN_SSP_VERSION))
        if decode_two_wheeler is not None:
            info = decode_two_wheeler(container["containerData"]).get("typeSpecificInformation")
            if info is not None and info[0] == "cyclist":
                needed.append((2, 0x01, TWO_WHEELER_MIN_SSP_VERSION))
    return needed


def ssp_permits(ssp: bytes, permission: Permission) -> bool:
    """True when the SSP sets the bit. Bits defined for a later SSP version
    than the SSP's own are not evaluated (they cannot be expressed)."""
    octet, mask, min_version = permission
    if len(ssp) < 1:
        return False
    if ssp[0] < min_version:
        return True
    return octet < len(ssp) and bool(ssp[octet] & mask)


def ssp_consistent(
    ssp: Optional[bytes], cam: dict, decode_two_wheeler: Optional[Callable[[bytes], dict]] = None
) -> bool:
    """
    SSP check of a received CAM (clause 6.2.2.1): True when no SSP is available
    (unsecured, or not provided by the security entity) or when every protected
    content of the CAM is permitted.
    """
    if not ssp:
        return True
    return all(ssp_permits(ssp, p) for p in required_permissions(cam, decode_two_wheeler))


def permissions_bitmap(
    cam: dict, decode_two_wheeler: Optional[Callable[[bytes], dict]] = None
) -> bytes:
    """
    SSP bits a CAM needs (Table 3), as the ``permissions`` of the signing
    request: the sign service only signs with an AT whose SSP grants them
    (clause 6.2.2.1, TP/CAM/MSD/SSP/BO-02-X). Octet 0 (SSP version) is not
    requested. The two-wheeler bits are requested whatever the SSP version
    of the AT, so a CAM with a TwoWheelerContainer is only sent when the AT
    grants them.
    """
    bitmap = bytearray(3)
    for octet, mask, _ in required_permissions(cam, decode_two_wheeler):
        bitmap[octet] |= mask
    return bytes(bitmap) if any(bitmap) else b"\x00"
