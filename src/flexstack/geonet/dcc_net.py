"""
DCC_NET: the GeoNetworking part of Decentralized Congestion Control over
ITS-G5 (ETSI TS 103 836-4-2 V2.1.1 (2025-04), clauses 5 to 7).

- DCC variables CBR_L_0_Hop, CBR_L_1_Hop, CBR_L_2_Hop and the global CBR_G,
  calculated every ``itsGNCBRGTriggerInterval`` with a random start offset
  (clauses 5.2 and 5.3);
- Location Table Entry Extension for ITS-G5 (LocTEX-G5) per neighbour,
  soft-state with lifetime ``itsGnLifetimeLocTEX`` (clause 6.2);
- the DCC-MCO field of the SHB Extended Header (clause 6.3.3, table 3).

The local CBR (CBR_L_0_Hop) is measured by the access layer and read from a
:class:`~flexstack.management.cbr.CbrProvider`, e.g.
:class:`~flexstack.management.cbr.Nl80211SurveyCbr` on a Linux ITS-G5
interface. CBR_G is published in :attr:`DccNet.global_cbr` (a
:class:`~flexstack.management.cbr.SharedCbr`) so that the DCC entity uses it
as input (clause 5.3, DCC_CROSS).

Wiring on a Linux ITS-G5 interface::

    from flexstack.management.cbr import Nl80211SurveyCbr, nl80211_tx_power_dbm
    from flexstack.management.dcc_entity import DccEntity, DccMode

    dcc_net = DccNet(local_cbr=Nl80211SurveyCbr("wlan0"),
                     tx_power_dbm=nl80211_tx_power_dbm("wlan0") or 0)
    router = Router(MIB(itsGnIfType=GnIfType.ITS_G5, ...), dcc_net=dcc_net)
    dcc = DccEntity(DccMode.reactive(), dcc_net.global_cbr)     # DCC on CBR_G

Mirrors ``rustflexstack::geonet::dcc_net``.
"""

from __future__ import annotations

import math
import random
import threading
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

from ..management.cbr import CbrProvider, SharedCbr
from .gn_address import GNAddress

# Annex A, table A.1
ITS_GN_LIFETIME_LOCTEX_MS = 1000
ITS_GN_CBR_TARGET = 0.62
ITS_GN_CBR_G_TRIGGER_INTERVAL_MS = 100
ITS_GN_CBR_LIFETIME_MS = 1000
# Table 3: E.I.R.P. range of the Transmit power sub-field [dBm]
_TX_POWER_MAX_DBM = 31


def encode_dcc_mco(cbr_l_0_hop: float, cbr_l_1_hop: float, tx_power_dbm: float) -> bytes:
    """
    DCC-MCO field (octets 40-43 of the SHB packet header, table 3): CBRs as
    floor(CBR x 255), transmit power in dBm clamped to [0, 31], octet 43
    reserved for MCO.
    """
    def cbr_octet(cbr: float) -> int:
        return min(255, max(0, math.floor(cbr * 255)))
    power = min(_TX_POWER_MAX_DBM, max(0, math.floor(tx_power_dbm)))
    return bytes([cbr_octet(cbr_l_0_hop), cbr_octet(cbr_l_1_hop), power & 0x1F, 0])


def decode_dcc_mco(field: bytes) -> Optional[Tuple[float, float, int]]:
    """
    (CBR_R_0_Hop, CBR_R_1_Hop, transmit power [dBm]) of a received DCC-MCO
    field, or None when the field is absent: a sender without DCC_NET leaves
    the four octets zero-filled (TS 103 836-4-1 reserved field).
    """
    if len(field) != 4 or field == b"\x00\x00\x00\x00":
        return None
    return field[0] / 255, field[1] / 255, field[2] & 0x1F


@dataclass(frozen=True)
class LocTexG5:
    """Location Table Entry Extension for ITS-G5 (clause 6.2.2)."""

    tst_g5_ms: int                  # local time of the last update
    tst_so_pv: int                  # TST of the SO PV of the updating SHB [ms, mod 2^32]
    tx_power_dbm: int
    rssi_dbm: Optional[float]
    cbr_r_0_hop: float
    cbr_r_1_hop: float


def _reduce(values: List[float], target: float) -> float:
    """
    Steps 1-2 / 3-4 of clause 5.3: the maximum when the average exceeds
    CBR_Target, otherwise the second largest value (the only value when
    there is one, 0 when there is none).
    """
    if not values:
        return 0.0
    ordered = sorted(values, reverse=True)
    if sum(values) / len(values) > target or len(ordered) == 1:
        return ordered[0]
    return ordered[1]


class DccNet:
    """
    DCC_NET entity of a GeoAdhoc router over ITS-G5.

    Parameters
    ----------
    local_cbr : CbrProvider | None
        Source of CBR_L_0_Hop, polled at every trigger; None when the
        application reports it with :meth:`report_local_cbr`.
    tx_power_dbm : float
        E.I.R.P. of the transmitted packets, e.g. from
        :func:`~flexstack.management.cbr.nl80211_tx_power_dbm`.
    cbr_target, trigger_interval_ms, cbr_lifetime_ms, loctex_lifetime_ms
        GN protocol constants of annex A.
    rng : Callable[[], float]
        Uniform [0, 1) source of the random trigger offset.
    """

    def __init__(self, local_cbr: Optional[CbrProvider] = None, tx_power_dbm: float = 0, *,  # pylint: disable=too-many-arguments
                 cbr_target: float = ITS_GN_CBR_TARGET,
                 trigger_interval_ms: int = ITS_GN_CBR_G_TRIGGER_INTERVAL_MS,
                 cbr_lifetime_ms: int = ITS_GN_CBR_LIFETIME_MS,
                 loctex_lifetime_ms: int = ITS_GN_LIFETIME_LOCTEX_MS,
                 rng: Callable[[], float] = random.random) -> None:
        self.local_cbr = local_cbr
        self.tx_power_dbm = tx_power_dbm
        self.cbr_target = cbr_target
        self.trigger_interval_ms = trigger_interval_ms
        self.cbr_lifetime_ms = cbr_lifetime_ms
        self.loctex_lifetime_ms = loctex_lifetime_ms
        self._rng = rng
        self._lock = threading.Lock()
        self.cbr_l_0_hop = 0.0
        self.cbr_l_1_hop = 0.0
        self.cbr_l_2_hop = 0.0
        self.cbr_g = 0.0
        self.global_cbr = SharedCbr()
        self.loctex: Dict[GNAddress, LocTexG5] = {}
        self._next_trigger_ms: Optional[int] = None

    # -- local CBR and DCC-MCO -------------------------------------------------

    def report_local_cbr(self, cbr: float) -> None:
        """Set CBR_L_0_Hop from an access layer that pushes measurements."""
        if 0.0 <= cbr <= 1.0:
            with self._lock:
                self.cbr_l_0_hop = cbr

    def dcc_mco(self) -> bytes:
        """DCC-MCO field for the next SHB (clause 7.2.1)."""
        with self._lock:
            return encode_dcc_mco(self.cbr_l_0_hop, self.cbr_l_1_hop, self.tx_power_dbm)

    # -- LocTEX-G5 ---------------------------------------------------------------

    def update_loctex(self, gn_addr: GNAddress, tst_so_pv: int, field: bytes, now_ms: int,
                      rssi_dbm: Optional[float] = None) -> bool:
        """
        Update the LocTEX-G5 of a neighbour from a received, non-duplicate SHB
        (clauses 6.2.3 and 7.2.2). Not updated when the SHB has no DCC-MCO.
        """
        decoded = decode_dcc_mco(field)
        if decoded is None:
            return False
        cbr_r_0, cbr_r_1, power = decoded
        with self._lock:
            self.loctex[gn_addr] = LocTexG5(tst_g5_ms=now_ms, tst_so_pv=tst_so_pv, tx_power_dbm=power,
                                            rssi_dbm=rssi_dbm, cbr_r_0_hop=cbr_r_0, cbr_r_1_hop=cbr_r_1)
        return True

    # -- CBR_G (clause 5.3) --------------------------------------------------------

    def next_trigger(self, now_ms: int) -> int:
        """Next T_Trig expiry; the first one has a random offset within T_Trig."""
        with self._lock:
            if self._next_trigger_ms is None:
                self._next_trigger_ms = now_ms + int(self._rng() * self.trigger_interval_ms)
            return self._next_trigger_ms

    def trigger(self, now_ms: int) -> float:
        """
        Calculate CBR_G (steps 1 to 5 of clause 5.3), expire LocTEX-G5 entries,
        read the new CBR_L_0_Hop and publish CBR_G. Returns CBR_G.
        """
        local = self.local_cbr.measure_cbr() if self.local_cbr is not None else None
        with self._lock:
            self.loctex = {addr: entry for addr, entry in self.loctex.items()
                           if now_ms - entry.tst_g5_ms <= self.loctex_lifetime_ms}
            recent = [e for e in self.loctex.values() if now_ms - e.tst_g5_ms <= self.cbr_lifetime_ms]
            self.cbr_l_1_hop = _reduce([e.cbr_r_0_hop for e in recent], self.cbr_target)
            self.cbr_l_2_hop = _reduce([e.cbr_r_1_hop for e in recent], self.cbr_target)
            # Step 5: CBR_G(n) = max(CBR_L_0_Hop(n-1), CBR_L_1_Hop(n), CBR_L_2_Hop(n))
            self.cbr_g = max(self.cbr_l_0_hop, self.cbr_l_1_hop, self.cbr_l_2_hop)
            if local is not None and 0.0 <= local <= 1.0:
                self.cbr_l_0_hop = local
            self._next_trigger_ms = now_ms + self.trigger_interval_ms
            cbr_g = self.cbr_g
        self.global_cbr.report(cbr_g)
        return cbr_g
