"""
DCC entity: couples a :class:`~flexstack.management.cbr.CbrProvider` (access
layer) with a DCC algorithm and the facilities layer.

On each evaluation (every 200 ms, aligned to UTC-modulo-200 ms boundaries per
ETSI TS 102 687 V1.2.1 clause 5.2) the entity:

1. polls the CBR provider;
2. runs the reactive (clause 5.3) or adaptive (clause 5.4) algorithm;
3. converts the result into ``T_GenCam_DCC``, the minimum CAM generation
   interval provided to the CA basic service (ETSI TS 103 900 §6.1.3),
   bounded to ``[T_GenCamMin, T_GenCamMax] = [100, 1000]`` ms;
4. notifies every registered listener with the new ``T_GenCam_DCC``.

Conversion:

* **Reactive**: ``T_GenCam_DCC = T_off`` of the current state (Annex A tables).
* **Adaptive**: ``T_GenCam_DCC = T_on / delta`` (gate interval of equation B.1).

Mirrors ``rustflexstack::management::dcc_entity``.

Examples
--------
>>> from flexstack.management.cbr import SharedCbr
>>> cbr = SharedCbr()
>>> dcc = DccEntity(DccMode.reactive(), cbr)
>>> # dcc.add_t_gen_cam_dcc_listener(ca_basic_service.set_t_gen_cam_dcc)
>>> cbr.report(0.9)
>>> dcc.evaluate().t_gen_cam_dcc_ms
200
"""

from __future__ import annotations

import math
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from .cbr import CbrProvider
from .dcc_adaptive import DccAdaptive, DccAdaptiveParameters
from .dcc_reactive import DccReactive, DccState

DCC_EVALUATION_PERIOD_MS = 200
"""DCC evaluation period in milliseconds (clause 5.2)."""
T_GEN_CAM_DCC_MIN_MS = 100
"""Lower bound of ``T_GenCam_DCC`` (``T_GenCamMin``, ETSI TS 103 900 §6.1.3) [ms]."""
T_GEN_CAM_DCC_MAX_MS = 1000
"""Upper bound of ``T_GenCam_DCC`` (``T_GenCamMax``, ETSI TS 103 900 §6.1.3) [ms]."""


@dataclass(frozen=True)
class DccMode:
    """
    DCC algorithm selection.  Use :meth:`reactive` or :meth:`adaptive`.

    Attributes
    ----------
    kind : str
        ``"reactive"`` or ``"adaptive"``.
    t_on_max_us : int
        Reactive only: maximum packet airtime in µs; ``<= 500`` selects
        Table A.2, otherwise Table A.1.
    parameters : DccAdaptiveParameters
        Adaptive only: LIMERIC parameters (Table 3 defaults).
    t_on_ms : float
        Adaptive only: nominal CAM airtime ``T_on`` in ms used for ``T_on / delta``.
    """

    kind: str
    t_on_max_us: int = 1000
    parameters: DccAdaptiveParameters = field(default_factory=DccAdaptiveParameters)
    t_on_ms: float = 1.0

    @staticmethod
    def reactive(t_on_max_us: int = 1000) -> "DccMode":
        """Reactive DCC (default: Table A.1, ``T_on`` ≤ 1 ms)."""
        return DccMode(kind="reactive", t_on_max_us=t_on_max_us)

    @staticmethod
    def adaptive(
        parameters: Optional[DccAdaptiveParameters] = None, t_on_ms: float = 1.0
    ) -> "DccMode":
        """Adaptive DCC (default: Table 3 parameters, ``T_on`` = 1 ms)."""
        return DccMode(
            kind="adaptive",
            parameters=parameters if parameters is not None else DccAdaptiveParameters(),
            t_on_ms=t_on_ms,
        )


@dataclass(frozen=True)
class DccEntityOutput:
    """
    Result of one DCC entity evaluation.

    Attributes
    ----------
    cbr : float
        CBR used for this evaluation.
    t_gen_cam_dcc_ms : int
        Resulting ``T_GenCam_DCC`` in ms, within ``[100, 1000]``.
    state : DccState or None
        Reactive state (reactive mode only).
    delta : float or None
        Duty-cycle fraction ``delta`` (adaptive mode only).
    """

    cbr: float
    t_gen_cam_dcc_ms: int
    state: Optional[DccState] = None
    delta: Optional[float] = None


def clamp_t_gen_cam_dcc(interval_ms: float) -> int:
    """Bound an interval in ms to ``[T_GEN_CAM_DCC_MIN_MS, T_GEN_CAM_DCC_MAX_MS]``."""
    if not math.isfinite(interval_ms):
        return T_GEN_CAM_DCC_MAX_MS
    # Round half away from zero, matching Rust's f64::round.
    rounded = int(math.floor(max(interval_ms, 0.0) + 0.5))
    return max(T_GEN_CAM_DCC_MIN_MS, min(T_GEN_CAM_DCC_MAX_MS, rounded))


def _ms_to_next_boundary() -> int:
    now_ms = int(time.time() * 1000)
    return DCC_EVALUATION_PERIOD_MS - (now_ms % DCC_EVALUATION_PERIOD_MS)


class DccEntity:
    """
    DCC entity of the ITS-S management layer.

    Parameters
    ----------
    mode : DccMode
        Algorithm selection.
    provider : CbrProvider
        CBR source (access layer).
    """

    def __init__(self, mode: DccMode, provider: CbrProvider) -> None:
        if mode.kind == "reactive":
            self._reactive: Optional[DccReactive] = DccReactive(mode.t_on_max_us)
            self._adaptive: Optional[DccAdaptive] = None
        elif mode.kind == "adaptive":
            self._reactive = None
            self._adaptive = DccAdaptive(mode.parameters)
        else:
            raise ValueError(f"unknown DCC mode {mode.kind!r}")
        self._t_on_ms = mode.t_on_ms
        self._provider = provider
        self._previous_cbr: Optional[float] = None
        self._last_output: Optional[DccEntityOutput] = None
        self._listeners: List[Callable[[int], None]] = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def add_t_gen_cam_dcc_listener(self, listener: Callable[[int], None]) -> None:
        """
        Register a callback receiving ``T_GenCam_DCC`` (ms) after every
        evaluation, e.g. ``ca_basic_service.set_t_gen_cam_dcc``.
        """
        self._listeners.append(listener)

    def last_output(self) -> Optional[DccEntityOutput]:
        """Output of the most recent successful evaluation."""
        return self._last_output

    def evaluate(self) -> Optional[DccEntityOutput]:
        """
        Run one evaluation.

        Returns ``None`` (and leaves the previous output in place) when the
        provider has no measurement or returns a value outside ``[0.0, 1.0]``.
        """
        with self._lock:
            cbr = self._provider.measure_cbr()
            if cbr is None or not 0.0 <= cbr <= 1.0:
                return None
            if self._reactive is not None:
                out = self._reactive.update(cbr)
                output = DccEntityOutput(
                    cbr=cbr,
                    t_gen_cam_dcc_ms=clamp_t_gen_cam_dcc(out.t_off_ms),
                    state=out.state,
                )
            else:
                assert self._adaptive is not None
                previous = self._previous_cbr if self._previous_cbr is not None else cbr
                delta = self._adaptive.update(cbr, previous)
                output = DccEntityOutput(
                    cbr=cbr,
                    t_gen_cam_dcc_ms=clamp_t_gen_cam_dcc(self._t_on_ms / delta),
                    delta=delta,
                )
            self._previous_cbr = cbr
            self._last_output = output
        for listener in self._listeners:
            listener(output.t_gen_cam_dcc_ms)
        return output

    def start(self) -> None:
        """
        Run the entity on a background thread, evaluating at every
        UTC-modulo-200 ms boundary until :meth:`stop` is called.
        """
        if self._thread is not None:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop the background thread and wait for it to finish (≤ one period)."""
        self._stop.set()
        if self._thread is not None:
            self._thread.join()
            self._thread = None

    def _run(self) -> None:
        while not self._stop.is_set():
            if self._stop.wait(_ms_to_next_boundary() / 1000.0):
                break
            self.evaluate()
