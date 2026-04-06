"""
Adaptive Decentralized Congestion Control algorithm and Gate Keeper.

Implements the adaptive approach specified in ETSI TS 102 687 V1.2.1 (2018-04)
clause 5.4 and the gate-keeping packet admission mechanism described in
Annex B.

Overview
--------
The adaptive algorithm (LIMERIC) maintains a smoothed estimate of the local
Channel Busy Ratio (``cbr_its_s``) and adjusts a *duty-cycle fraction*
parameter ``delta`` so that the ITS-S's own channel occupancy converges toward
a configurable target CBR.  ``delta`` represents the maximum fraction of the
wireless medium that this ITS-S is allowed to occupy over any given interval.

The :class:`DccAdaptive` class implements the five algorithmic steps of
clause 5.4 and is intended to be called at every UTC-modulo-200 ms boundary.

The :class:`GateKeeper` class implements the packet admission logic of Annex B.
It uses the current ``delta`` value to compute the earliest time at which the
next packet may be admitted to the access layer.  When ``delta`` is updated by
the adaptive algorithm, the gate-opening time is recalculated according to
equation B.2 to avoid synchronised transmissions across stations.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class DccAdaptiveParameters:
    """
    Tunable parameters of the adaptive DCC algorithm.

    Default values are taken from Table 3 of ETSI TS 102 687 V1.2.1 (2018-04)
    clause 5.4.

    Attributes
    ----------
    alpha : float
        Exponential averaging coefficient used in step 3 (equation 4).
        Default: 0.016.
    beta : float
        Proportional gain applied to the CBR error in step 2
        (equations 2 and 3).  Default: 0.0012.
    cbr_target : float
        Target Channel Busy Ratio toward which ``delta`` is steered.
        Default: 0.68.
    delta_max : float
        Hard upper bound on the duty-cycle fraction ``delta`` (step 4,
        equation 5).  Corresponds to the maximum duty cycle permitted by
        ETSI EN 302 571.  Default: 0.03.
    delta_min : float
        Hard lower bound on ``delta`` (step 5, equation 6).  Prevents
        complete starvation under extreme congestion.  Default: 0.0006.
    delta_up_max : float
        Upper clamp on the per-step offset when CBR is below the target
        (equation 2).  Default: 0.0005.
    delta_down_max : float
        Lower clamp on the per-step offset when CBR is at or above the target
        (equation 3).  Must be negative.  Default: -0.00025.
    """

    alpha: float = 0.016
    beta: float = 0.0012
    cbr_target: float = 0.68
    delta_max: float = 0.03
    delta_min: float = 0.0006
    delta_up_max: float = 0.0005
    delta_down_max: float = -0.00025


@dataclass
class DccAdaptive:
    """
    Adaptive DCC algorithm as specified in ETSI TS 102 687 V1.2.1 (2018-04)
    clause 5.4 (LIMERIC).

    The algorithm shall be evaluated at every UTC-modulo-200 ms boundary
    (clause 5.2).  Each evaluation executes five ordered steps that update the
    duty-cycle fraction ``delta``:

    * **Step 1** – Compute a smoothed CBR estimate (``cbr_its_s``) from the
      two most recent local (or global, if available) CBR measurements.
    * **Step 2** – Compute a signed per-step correction (``delta_offset``)
      proportional to the distance between ``cbr_target`` and ``cbr_its_s``,
      clamped to ``[delta_down_max, delta_up_max]``.
    * **Step 3** – Apply an exponential filter to blend the new offset into the
      current ``delta``.
    * **Steps 4–5** – Clamp ``delta`` to ``[delta_min, delta_max]``.

    Parameters
    ----------
    parameters : DccAdaptiveParameters, optional
        Algorithm tuning parameters.  If not supplied the standard default
        values from Table 3 are used.

    Attributes
    ----------
    cbr_its_s : float
        Current smoothed CBR estimate (initialised to 0.0).
    delta : float
        Current duty-cycle fraction (initialised to ``parameters.delta_min``).

    Examples
    --------
    >>> alg = DccAdaptive()
    >>> delta = alg.update(cbr_local=0.5, cbr_local_previous=0.5)
    >>> 0.0006 <= delta <= 0.03
    True
    """

    parameters: DccAdaptiveParameters = field(
        default_factory=DccAdaptiveParameters
    )
    cbr_its_s: float = field(default=0.0, init=False)
    delta: float = field(default=0.0, init=False)

    def __post_init__(self) -> None:
        self.delta = self.parameters.delta_min

    def update(
        self,
        cbr_local: float,
        cbr_local_previous: float,
        cbr_global: float | None = None,
        cbr_global_previous: float | None = None,
    ) -> float:
        """
        Execute one full adaptive DCC evaluation (steps 1–5 of clause 5.4).

        Parameters
        ----------
        cbr_local : float
            Most recent local CBR measurement (``CBR_L_0_Hop``).
        cbr_local_previous : float
            Second most recent local CBR measurement
            (``CBR_L_0_Hop_Previous``).
        cbr_global : float or None, optional
            Most recent global CBR (``CBR_G``), received from a neighbouring
            ITS-S via GeoNetworking header as described in the NOTE of
            clause 5.4.  When provided, replaces the local value in step 1.
        cbr_global_previous : float or None, optional
            Second most recent global CBR (``CBR_G_Previous``).  When provided
            together with *cbr_global*, replaces the previous local value in
            step 1.

        Returns
        -------
        float
            Updated ``delta`` value after clamping.

        Raises
        ------
        ValueError
            If any CBR argument is outside ``[0.0, 1.0]``.
        """
        for name, val in (
            ("cbr_local", cbr_local),
            ("cbr_local_previous", cbr_local_previous),
        ):
            if not 0.0 <= val <= 1.0:
                raise ValueError(
                    f"{name} must be in [0.0, 1.0], got {val!r}"
                )
        p = self.parameters

        # Step 1 (equation 1) – CBR averaging
        # Use global CBR if both global measurements are available (NOTE 1).
        if cbr_global is not None and cbr_global_previous is not None:
            cbr_avg = (cbr_global + cbr_global_previous) / 2.0
        else:
            cbr_avg = (cbr_local + cbr_local_previous) / 2.0
        self.cbr_its_s = 0.5 * self.cbr_its_s + 0.5 * cbr_avg

        # Step 2 (equations 2–3) – compute delta_offset
        diff = p.cbr_target - self.cbr_its_s
        if diff > 0.0:
            # CBR below target → increase delta (more transmission allowed)
            delta_offset = min(p.beta * diff, p.delta_up_max)
        else:
            # CBR at or above target → decrease delta (fewer transmissions)
            delta_offset = max(p.beta * diff, p.delta_down_max)

        # Step 3 (equation 4) – exponential filter
        self.delta = (1.0 - p.alpha) * self.delta + delta_offset

        # Steps 4–5 (equations 5–6) – clamp to permitted range
        if self.delta > p.delta_max:
            self.delta = p.delta_max
        if self.delta < p.delta_min:
            self.delta = p.delta_min

        return self.delta


class GateKeeper:
    """
    Packet admission gate keeper as described in ETSI TS 102 687 V1.2.1
    (2018-04) Annex B.

    The gate keeper controls which packets may pass from the Network &
    Transport layer to the Access layer queue.  The gate is **open** when the
    Access layer will accept a new packet and **closed** otherwise.

    Lifecycle
    ---------
    1. A packet arrives at the gate. If the gate is open the packet is
       *admitted*: the gate closes and a gate-opening time ``t_go`` is
       scheduled using equation B.1.
    2. From time ``t_go`` onward the gate is open again.
    3. Whenever ``delta`` is updated by the adaptive algorithm, ``t_go`` is
       recalculated per equation B.2 to preserve relative ordering of gate
       openings without introducing synchronisation artefacts.

    The minimum inter-admission interval is 25 ms and the maximum is 1 s
    (both from the constraints in ETSI EN 302 571 referenced in Annex B).

    Parameters
    ----------
    delta : float
        Initial duty-cycle fraction value obtained from :class:`DccAdaptive`.

    Attributes
    ----------
    GATE_OPEN_MIN_INTERVAL_S : float
        Minimum allowed gate-open interval in seconds (25 ms).
    GATE_OPEN_MAX_INTERVAL_S : float
        Maximum allowed gate-open interval in seconds (1 s).

    Examples
    --------
    >>> gk = GateKeeper(delta=0.01)
    >>> gk.is_open(t=0.0)
    True
    >>> admitted = gk.admit_packet(t=0.0, t_on=0.001)
    >>> admitted
    True
    >>> gk.is_open(t=0.0)
    False
    >>> gk.is_open(t=0.1)
    True
    """

    GATE_OPEN_MIN_INTERVAL_S: float = 0.025
    GATE_OPEN_MAX_INTERVAL_S: float = 1.0
    _T_EPSILON: float = 1e-9  # 1 ns tolerance for floating-point rounding

    def __init__(self, delta: float) -> None:
        """
        Initialise the gate keeper with an initial ``delta`` value.

        Parameters
        ----------
        delta : float
            Duty-cycle fraction from the adaptive DCC algorithm.
        """
        self._delta: float = delta
        self._t_pg: float | None = None   # time when gate last closed
        self._t_go: float | None = None   # scheduled gate-opening time

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_open(self, t: float) -> bool:
        """
        Return ``True`` if the gate is currently open at time *t*.

        The gate is open on first use (before any packet has been admitted)
        and from ``t_go`` onward after each admission.

        Parameters
        ----------
        t : float
            Current time in seconds.

        Returns
        -------
        bool
            ``True`` if a packet may be admitted, ``False`` otherwise.
        """
        if self._t_go is None:
            return True
        return t >= self._t_go - self._T_EPSILON

    def admit_packet(self, t: float, t_on: float) -> bool:
        """
        Attempt to admit one packet at time *t*.

        If the gate is open the packet is accepted, the gate closes, and the
        next gate-opening time is scheduled per equation B.1:

        .. math::

            t_{go} = t_{pg} + \\min\\!\\left(\\max\\!\\left(
                \\frac{T_{on\\_pp}}{\\delta}, 0.025
            \\right), 1 \\right)

        Parameters
        ----------
        t : float
            Current time in seconds.
        t_on : float
            Transmission duration of this packet in seconds
            (``T_on_pp`` in Annex B).

        Returns
        -------
        bool
            ``True`` if the packet was admitted; ``False`` if the gate was
            closed and the packet is rejected.

        Raises
        ------
        ValueError
            If *t_on* is not positive.
        """
        if t_on <= 0.0:
            raise ValueError(f"t_on must be positive, got {t_on!r}")
        if not self.is_open(t):
            return False

        self._t_pg = t
        interval = min(
            max(t_on / self._delta, self.GATE_OPEN_MIN_INTERVAL_S),
            self.GATE_OPEN_MAX_INTERVAL_S,
        )
        self._t_go = t + interval
        return True

    def update_delta(self, t: float, delta_new: float) -> None:
        """
        Update the duty-cycle fraction and reschedule the gate-opening time.

        When ``delta`` changes, the gate-opening time is recalculated per
        equation B.2 to avoid synchronising gate openings across stations:

        .. math::

            t_{go} = t_{pg} + \\min\\!\\left(\\max\\!\\left(
                \\frac{\\delta_{old}}{\\delta_{new}} \\cdot (t_{go} - t_{pg}),
                0.025
            \\right), 1 \\right)

        If the gate is currently open (no packet has been admitted yet, or
        ``t_go`` has already passed) only ``delta`` is updated.

        Parameters
        ----------
        t : float
            Current time in seconds (used to determine whether the gate is
            still closed).
        delta_new : float
            Updated duty-cycle fraction from the adaptive DCC algorithm.

        Raises
        ------
        ValueError
            If *delta_new* is not positive.
        """
        if delta_new <= 0.0:
            raise ValueError(f"delta_new must be positive, got {delta_new!r}")

        delta_old = self._delta
        self._delta = delta_new

        # Gate is already open → no rescheduling needed
        if self._t_pg is None or self._t_go is None or self.is_open(t):
            return

        # B.2 – rescale remaining closed interval by delta ratio
        old_interval = self._t_go - self._t_pg
        new_interval = (delta_old / delta_new) * old_interval
        self._t_go = self._t_pg + min(
            max(new_interval, self.GATE_OPEN_MIN_INTERVAL_S),
            self.GATE_OPEN_MAX_INTERVAL_S,
        )
