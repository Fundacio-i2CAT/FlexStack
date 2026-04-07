"""
Reactive Decentralized Congestion Control algorithm.

Implements the reactive approach specified in ETSI TS 102 687 V1.2.1 (2018-04)
clause 5.3 and Annex A.

The algorithm consists of five states (Relaxed, Active 1, Active 2, Active 3,
Restrictive) arranged in a linear sequence.  On each evaluation the state may
advance at most *one* step toward the state dictated by the current CBR, which
enforces the "one state can only be reached by a neighbouring state" requirement
from clause 5.3.  Each state maps directly to a maximum allowed packet rate and
a minimum inter-packet gap (T_off).

Two parameter tables are defined in Annex A depending on the assumed maximum
packet transmission duration (T_on):

* **Table A.1** – used when T_on is at most 1 ms
* **Table A.2** – used when T_on is at most 500 µs
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class DccState(Enum):
    """
    Ordered states of the reactive DCC algorithm.

    As specified in ETSI TS 102 687 V1.2.1 (2018-04) clause 5.3.

    Attributes
    ----------
    RELAXED (0) :
        Lowest utilisation state.  Fewest restrictions on transmissions.
    ACTIVE_1 (1) :
        First active state.  Moderate CBR detected.
    ACTIVE_2 (2) :
        Second active state.  Elevated CBR detected.
    ACTIVE_3 (3) :
        Third active state.  High CBR detected.
    RESTRICTIVE (4) :
        Most stringent state.  Very high CBR detected.
    """

    RELAXED = 0
    ACTIVE_1 = 1
    ACTIVE_2 = 2
    ACTIVE_3 = 3
    RESTRICTIVE = 4


@dataclass(frozen=True)
class DccStateConfig:
    """
    Channel Busy Ratio thresholds and output parameters for a single state.

    As specified in ETSI TS 102 687 V1.2.1 (2018-04) Annex A, Tables A.1 and A.2.

    Attributes
    ----------
    cbr_min : float
        Inclusive lower CBR bound for this state (0.0 for Relaxed).
    cbr_max : float
        Exclusive upper CBR bound for this state (1.0 for Restrictive).
    packet_rate_hz : float
        Maximum allowed packet transmission rate in packets per second.
    t_off_ms : float
        Minimum required inter-packet gap in milliseconds.
    """

    cbr_min: float
    cbr_max: float
    packet_rate_hz: float
    t_off_ms: float


# ---------------------------------------------------------------------------
# Standard parameter tables (Annex A)
# ---------------------------------------------------------------------------

#: Table A.1 – T_on at most 1 ms.
#: States ordered from RELAXED to RESTRICTIVE.
_TABLE_A1: dict[DccState, DccStateConfig] = {
    DccState.RELAXED: DccStateConfig(0.00, 0.30, 10.0, 100.0),
    DccState.ACTIVE_1: DccStateConfig(0.30, 0.40, 5.0, 200.0),
    DccState.ACTIVE_2: DccStateConfig(0.40, 0.50, 2.5, 400.0),
    DccState.ACTIVE_3: DccStateConfig(0.50, 0.60, 2.0, 500.0),
    DccState.RESTRICTIVE: DccStateConfig(0.60, 1.01, 1.0, 1000.0),
}

#: Table A.2 – T_on at most 500 µs.
_TABLE_A2: dict[DccState, DccStateConfig] = {
    DccState.RELAXED: DccStateConfig(0.00, 0.30, 20.0, 50.0),
    DccState.ACTIVE_1: DccStateConfig(0.30, 0.40, 10.0, 100.0),
    DccState.ACTIVE_2: DccStateConfig(0.40, 0.50, 5.0, 200.0),
    DccState.ACTIVE_3: DccStateConfig(0.50, 0.65, 4.0, 250.0),
    DccState.RESTRICTIVE: DccStateConfig(0.65, 1.01, 1.0, 1000.0),
}

# Ordered list of states used for single-step transitions.
_STATE_ORDER: list[DccState] = [
    DccState.RELAXED,
    DccState.ACTIVE_1,
    DccState.ACTIVE_2,
    DccState.ACTIVE_3,
    DccState.RESTRICTIVE,
]


@dataclass(frozen=True)
class DccReactiveOutput:
    """
    Output produced by a single reactive DCC evaluation.

    Attributes
    ----------
    state : DccState
        Current DCC state after the evaluation.
    packet_rate_hz : float
        Maximum allowed packet transmission rate in packets per second.
    t_off_ms : float
        Minimum required inter-packet gap in milliseconds (T_off).
    """

    state: DccState
    packet_rate_hz: float
    t_off_ms: float


class DccReactive:
    """
    Reactive DCC algorithm as specified in ETSI TS 102 687 V1.2.1 (2018-04)
    clause 5.3 and Annex A.

    The algorithm is evaluated periodically (at least every 200 ms, per
    clause 5.2) by calling :meth:`update` with the most recently measured
    Channel Busy Ratio (CBR).  On each call the state may advance by at most
    one step toward the state inferred from the CBR table, enforcing the
    adjacency constraint of clause 5.3.

    Parameters
    ----------
    t_on_max_us : int
        Assumed maximum packet transmission duration in microseconds.  When
        this value is at most 500 the parameter table from Annex A Table A.2
        is used; otherwise Table A.1 is used.  Defaults to 1000 (1 ms), which
        selects Table A.1.

    Attributes
    ----------
    state : DccState
        Current algorithm state.  Starts at :attr:`DccState.RELAXED`.

    Examples
    --------
    >>> dcc = DccReactive()
    >>> out = dcc.update(cbr=0.35)
    >>> out.state
    <DccState.ACTIVE_1: 1>
    >>> out.packet_rate_hz
    5.0
    """

    def __init__(self, t_on_max_us: int = 1000) -> None:
        """
        Initialise the reactive DCC algorithm.

        Parameters
        ----------
        t_on_max_us : int, optional
            Maximum packet transmission duration in microseconds.  Values
            ≤ 500 select Annex A Table A.2; all other values select Table A.1.
            Defaults to 1000.
        """
        self._table: dict[DccState, DccStateConfig] = (
            _TABLE_A2 if t_on_max_us <= 500 else _TABLE_A1
        )
        self.state: DccState = DccState.RELAXED

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _target_state(self, cbr: float) -> DccState:
        """Return the state whose CBR band contains *cbr*."""
        for state, cfg in self._table.items():
            if cfg.cbr_min <= cbr < cfg.cbr_max:
                return state
        # CBR == 1.0 (or floating-point rounding above 1.0) → Restrictive
        return DccState.RESTRICTIVE

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def update(self, cbr: float) -> DccReactiveOutput:
        """
        Evaluate the algorithm with the current Channel Busy Ratio.

        The state advances by at most one step toward the state implied by
        *cbr*, satisfying the adjacency constraint from clause 5.3.

        Parameters
        ----------
        cbr : float
            Current Channel Busy Ratio value in the range ``[0.0, 1.0]``.

        Returns
        -------
        DccReactiveOutput
            Updated state together with the corresponding transmission
            constraints (maximum packet rate and minimum T_off).

        Raises
        ------
        ValueError
            If *cbr* is outside the range ``[0.0, 1.0]``.
        """
        if not 0.0 <= cbr <= 1.0:
            raise ValueError(f"cbr must be in [0.0, 1.0], got {cbr!r}")

        target = self._target_state(cbr)
        current_idx = _STATE_ORDER.index(self.state)
        target_idx = _STATE_ORDER.index(target)

        if target_idx > current_idx:
            current_idx += 1
        elif target_idx < current_idx:
            current_idx -= 1
        # else: target_idx == current_idx → no change

        self.state = _STATE_ORDER[current_idx]
        cfg = self._table[self.state]
        return DccReactiveOutput(
            state=self.state,
            packet_rate_hz=cfg.packet_rate_hz,
            t_off_ms=cfg.t_off_ms,
        )
