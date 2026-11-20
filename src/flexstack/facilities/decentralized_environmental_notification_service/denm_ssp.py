"""
DENM Service Specific Permissions (ETSI TS 103 831 V2.3.1 (2025-11), clause 6.2.2.2).

The SSP of a DENM Authorization Ticket is a BitmapSsp: octet 0 is the SSP
version, octets 1 to 4 hold one bit per cause code (Table 10). A DENM is
consistent with the SSP when the bit of its cause code is set.

Mirrors ``rustflexstack::facilities::decentralized_environmental_notification_service::denm_ssp``.
"""

from __future__ import annotations

import re
from typing import Optional

# cause code value -> (octet index, bit mask), ETSI TS 103 831 V2.3.1 Table 10.
CAUSE_CODE_SSP_BIT = {
    1: (1, 0x80), 2: (1, 0x40), 3: (1, 0x20), 6: (1, 0x10),
    9: (1, 0x08), 10: (1, 0x04), 11: (1, 0x02), 12: (1, 0x01),
    14: (2, 0x80), 15: (2, 0x40), 17: (2, 0x20), 18: (2, 0x10),
    19: (2, 0x08), 26: (2, 0x04), 27: (2, 0x02), 91: (2, 0x01),
    92: (3, 0x80), 93: (3, 0x40), 94: (3, 0x20), 95: (3, 0x10),
    96: (3, 0x08), 97: (3, 0x04), 98: (3, 0x02), 99: (3, 0x01),
    5: (4, 0x80), 7: (4, 0x40), 28: (4, 0x20), 100: (4, 0x10),
    4: (4, 0x08), 20: (4, 0x04),
}
SSP_VERSION_1_LENGTH = 4
SSP_VERSION_2_LENGTH = 5


def cause_code_value(denm: dict) -> Optional[int]:
    """
    Cause code value of a DENM, from the CauseCodeChoice alternative name
    (e.g. ``accident2`` -> 2); None for a DENM without situation container.
    """
    situation = denm["denm"].get("situation")
    if situation is None:
        return None
    name = situation["eventType"]["ccAndScc"][0]
    match = re.search(r"(\d+)$", name)
    return int(match.group(1)) if match else None


def ssp_permits_cause_code(ssp: bytes, cause_code: int) -> bool:
    """
    True when the DENM SSP allows signing DENMs with ``cause_code``. A cause
    code without a Table 10 bit, or whose octet lies beyond the SSP length
    (e.g. a Release 2 code under a version 1 SSP), is not permitted.
    """
    position = CAUSE_CODE_SSP_BIT.get(cause_code)
    if position is None or len(ssp) < 1:
        return False
    octet, mask = position
    return octet < len(ssp) and bool(ssp[octet] & mask)


def ssp_consistent(ssp: Optional[bytes], denm: dict) -> bool:
    """
    SSP check of the receiving ITS-S (clause 8.4.2): True when no SSP is
    available (unsecured or not provided by the security entity), when the DENM
    has no cause code (termination DENM), or when the SSP permits the cause code.
    """
    if not ssp:
        return True
    cause = cause_code_value(denm)
    return True if cause is None else ssp_permits_cause_code(ssp, cause)


def permissions_bitmap(denm: dict) -> bytes:
    """
    SSP bits a DENM needs (Table 10), as the ``permissions`` of the signing
    request: the sign service only signs with an AT whose SSP grants them.
    Octet 0 (SSP version) is not requested. A DENM without cause code (a
    termination) or with a cause code without Table 10 bit requests none.
    """
    cause = cause_code_value(denm)
    position = CAUSE_CODE_SSP_BIT.get(cause) if cause is not None else None
    if position is None:
        return b"\x00"
    octet, mask = position
    bitmap = bytearray(octet + 1)
    bitmap[octet] = mask
    return bytes(bitmap)
