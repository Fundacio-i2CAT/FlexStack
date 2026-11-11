"""
Channel Busy Ratio (CBR) sources for the DCC entity.

The DCC algorithms of ETSI TS 102 687 V1.2.1 (2018-04) are access-technology
independent, but the CBR they consume is measured by the access layer
(clause 5.2).  This module decouples the two through the :class:`CbrProvider`
interface, which the :class:`~flexstack.management.dcc_entity.DccEntity` polls
once per evaluation.

Provided implementations:

* :class:`SharedCbr` – a thread-safe cell for access layers that *push* CBR
  measurements (e.g. a radio SDK callback or an external process).
* :class:`Nl80211SurveyCbr` – derives CBR on Linux IEEE 802.11p (ITS-G5)
  interfaces from the nl80211 channel survey counters
  (``iw dev <iface> survey dump``).

Mirrors ``rustflexstack::management::cbr``.
"""

from __future__ import annotations

import subprocess
import threading
from dataclasses import dataclass
from typing import Optional


class CbrProvider:
    """
    A source of Channel Busy Ratio measurements.

    Subclasses return the most recent CBR in ``[0.0, 1.0]``, or ``None`` when
    no (new) measurement is available.  The DCC entity keeps its previous
    output when ``None`` is returned.
    """

    def measure_cbr(self) -> Optional[float]:
        """Return the current CBR measurement, if any."""
        raise NotImplementedError("All CBR providers should implement this")


class SharedCbr(CbrProvider):
    """
    Thread-safe CBR cell for push-based access layers.

    The access layer calls :meth:`report`; the DCC entity polls the same
    object as its :class:`CbrProvider`.  The latest reported value is returned
    on every poll.

    Examples
    --------
    >>> cell = SharedCbr()
    >>> cell.measure_cbr() is None
    True
    >>> cell.report(0.42)
    >>> cell.measure_cbr()
    0.42
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._latest: Optional[float] = None

    def report(self, cbr: float) -> None:
        """Report a new CBR measurement.  Values outside ``[0.0, 1.0]`` (or NaN) are ignored."""
        if not 0.0 <= cbr <= 1.0:
            return
        with self._lock:
            self._latest = cbr

    def latest(self) -> Optional[float]:
        """Latest reported CBR, if any."""
        with self._lock:
            return self._latest

    def measure_cbr(self) -> Optional[float]:
        return self.latest()


@dataclass(frozen=True)
class SurveySample:
    """
    Cumulative channel-time counters of the in-use channel, in milliseconds.

    Attributes
    ----------
    active_ms : int
        ``channel active time`` (time the radio was on the channel).
    busy_ms : int
        ``channel busy time`` (time the channel was sensed busy, own TX included).
    """

    active_ms: int
    busy_ms: int


def _parse_ms(value: str) -> Optional[int]:
    value = value.strip()
    if value.endswith("ms"):
        value = value[:-2]
    try:
        return int(value.strip())
    except ValueError:
        return None


def parse_survey_dump(text: str) -> Optional[SurveySample]:
    """
    Parse the output of ``iw dev <iface> survey dump`` and return the counters
    of the channel marked ``[in use]``.

    Returns ``None`` if no in-use channel with both counters is present (some
    drivers do not report survey data).
    """
    in_use = False
    active: Optional[int] = None
    busy: Optional[int] = None

    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("Survey data from"):
            if in_use:
                break
            active = None
            busy = None
            continue
        if line.startswith("frequency:"):
            if in_use:
                break  # next channel block of the same dump
            in_use = "[in use]" in line
            continue
        if not in_use:
            continue
        if line.startswith("channel active time:"):
            active = _parse_ms(line[len("channel active time:"):])
        elif line.startswith("channel busy time:"):
            busy = _parse_ms(line[len("channel busy time:"):])

    if in_use and active is not None and busy is not None:
        return SurveySample(active_ms=active, busy_ms=busy)
    return None


def cbr_from_samples(previous: SurveySample, current: SurveySample) -> Optional[float]:
    """
    CBR between two consecutive survey samples: ``Δbusy / Δactive``, clamped to ``[0, 1]``.

    Returns ``None`` if the active-time counter did not advance (or was reset).
    """
    if current.active_ms <= previous.active_ms or current.busy_ms < previous.busy_ms:
        return None
    d_active = current.active_ms - previous.active_ms
    d_busy = current.busy_ms - previous.busy_ms
    return min(1.0, max(0.0, d_busy / d_active))


class Nl80211SurveyCbr(CbrProvider):
    """
    CBR provider for Linux IEEE 802.11p (ITS-G5) interfaces based on nl80211
    channel survey counters, as exposed by e.g. the ``ath9k`` driver.

    Each poll runs ``iw dev <iface> survey dump`` and returns the busy fraction
    of the in-use channel since the previous poll, so the measurement window
    equals the DCC evaluation period.  The first poll only records a reference
    sample and returns ``None``.

    **Approximation**: the driver's busy time is based on the radio's CCA
    threshold, not the −85 dBm threshold that ETSI TS 102 687 §5.2 (via ETSI
    TS 102 917) uses to define CBR.  The ``iw`` binary must be installed.

    Parameters
    ----------
    iface : str
        Wireless interface name (e.g. ``"wlan0"``).
    """

    def __init__(self, iface: str) -> None:
        self.iface = iface
        self._previous: Optional[SurveySample] = None

    def ingest(self, sample: SurveySample) -> Optional[float]:
        """
        Feed one survey sample and return the CBR since the previous one.

        Exposed so the delta logic can be driven without running ``iw``.
        """
        cbr = None
        if self._previous is not None:
            cbr = cbr_from_samples(self._previous, sample)
        self._previous = sample
        return cbr

    def _read_survey(self) -> Optional[SurveySample]:
        try:
            out = subprocess.run(
                ["iw", "dev", self.iface, "survey", "dump"],
                capture_output=True,
                text=True,
                check=False,
                timeout=1.0,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        if out.returncode != 0:
            return None
        return parse_survey_dump(out.stdout)

    def measure_cbr(self) -> Optional[float]:
        sample = self._read_survey()
        if sample is None:
            return None
        return self.ingest(sample)
