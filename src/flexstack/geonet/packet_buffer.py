"""
GeoNetworking packet buffers (ETSI TS 103 836-4-1 V2.2.1 (2026-04), clauses 8.5 and 8.6).

``PacketBuffer`` implements the maintenance rules shared by the Location Service
packet buffer (clause 8.5.3) and the UC/BC forwarding packet buffers
(clause 8.6.3):

1. packets are queued at the tail;
2. on overflow, packets are removed from the head (head drop);
3. a flush returns the stored packets in FIFO order;
4. packets whose queuing time exceeds their lifetime are discarded;
5. a flushed packet carries its lifetime reduced by the queuing time.

``CbfPacketBuffer`` is the CBF packet buffer (clause 8.6.3), in which every
packet is associated with a timer, as set by the CBF algorithms of clauses E.3
and F.3.

Both buffers are clock-agnostic: all operations take the current time in
milliseconds, so the router decides which clock drives them.

Mirrors ``rustflexstack::geonet::packet_buffer``.
"""

from __future__ import annotations

import math
from collections import OrderedDict, deque
from collections.abc import Hashable
from dataclasses import dataclass
from typing import Deque, Generic, List, Optional, Tuple, TypeVar

T = TypeVar("T")
K = TypeVar("K", bound=Hashable)


@dataclass
class _Entry(Generic[T]):
    item: T
    size: int
    lifetime_ms: int
    enqueued_ms: int

    def remaining_lifetime_ms(self, now_ms: int) -> int:
        """Lifetime left after the queuing time."""
        return self.lifetime_ms - (now_ms - self.enqueued_ms)


class PacketBuffer(Generic[T]):
    """
    FIFO packet buffer with head drop and lifetime expiry (clauses 8.5.3, 8.6.3).

    Parameters
    ----------
    capacity : int
        Buffer capacity in octets.
    """

    def __init__(self, capacity: int) -> None:
        self.capacity = capacity
        self._entries: Deque[_Entry[T]] = deque()
        self._size = 0

    def __len__(self) -> int:
        return len(self._entries)

    @property
    def size(self) -> int:
        """Octets currently stored."""
        return self._size

    def push(self, item: T, size: int, lifetime_ms: int, now_ms: int) -> int:
        """
        Queue a packet at the tail; remove packets from the head while the
        capacity is exceeded. Returns the number of packets dropped (a packet
        larger than the whole buffer drops itself).
        """
        self._entries.append(_Entry(item, size, lifetime_ms, now_ms))
        self._size += size
        dropped = 0
        while self._size > self.capacity and self._entries:
            self._size -= self._entries.popleft().size
            dropped += 1
        return dropped

    def purge(self, now_ms: int) -> int:
        """Discard the packets whose queuing time reached their lifetime."""
        kept: Deque[_Entry[T]] = deque()
        dropped = 0
        for entry in self._entries:
            if entry.remaining_lifetime_ms(now_ms) > 0:
                kept.append(entry)
            else:
                self._size -= entry.size
                dropped += 1
        self._entries = kept
        return dropped

    def flush(self, now_ms: int) -> List[Tuple[T, int]]:
        """
        Empty the buffer, returning ``(packet, remaining lifetime in ms)`` in
        FIFO order; expired packets are discarded.
        """
        out = [
            (entry.item, entry.remaining_lifetime_ms(now_ms))
            for entry in self._entries
            if entry.remaining_lifetime_ms(now_ms) > 0
        ]
        self.clear()
        return out

    def clear(self) -> None:
        """Discard every stored packet."""
        self._entries.clear()
        self._size = 0


@dataclass
class _CbfEntry(_Entry[T]):
    deadline_ms: int = 0


class CbfPacketBuffer(Generic[K, T]):
    """
    CBF packet buffer (clause 8.6.3): packets keyed by their identifier
    (source GN_ADDR, sequence number), each with its own CBF timer.

    Parameters
    ----------
    capacity : int
        Buffer capacity in octets.
    """

    def __init__(self, capacity: int) -> None:
        self.capacity = capacity
        self._entries: "OrderedDict[K, _CbfEntry[T]]" = OrderedDict()
        self._size = 0

    def __len__(self) -> int:
        return len(self._entries)

    def __contains__(self, key: object) -> bool:
        return key in self._entries

    def insert(self, key: K, item: T, size: int, lifetime_ms: int, now_ms: int,  # pylint: disable=too-many-arguments,too-many-positional-arguments
               timeout_ms: float) -> int:
        """Buffer a packet and start its timer; head drop on overflow."""
        self.remove(key)
        self._entries[key] = _CbfEntry(item, size, lifetime_ms, now_ms,
                                       now_ms + math.ceil(timeout_ms))
        self._size += size
        dropped = 0
        while self._size > self.capacity and self._entries:
            _, entry = self._entries.popitem(last=False)
            self._size -= entry.size
            dropped += 1
        return dropped

    def remove(self, key: K) -> Optional[T]:
        """Stop the timer of a packet and remove it from the buffer."""
        entry = self._entries.pop(key, None)
        if entry is None:
            return None
        self._size -= entry.size
        return entry.item

    def get(self, key: K) -> Optional[T]:
        """The buffered packet of ``key``, if any."""
        entry = self._entries.get(key)
        return None if entry is None else entry.item

    def remaining_timeout_ms(self, key: K, now_ms: int) -> Optional[int]:
        """Time left until the timer of ``key`` expires."""
        entry = self._entries.get(key)
        return None if entry is None else max(0, entry.deadline_ms - now_ms)

    def restart(self, key: K, now_ms: int, timeout_ms: float) -> None:
        """Restart the timer of a buffered packet."""
        entry = self._entries.get(key)
        if entry is not None:
            entry.deadline_ms = now_ms + math.ceil(timeout_ms)

    def next_deadline(self) -> Optional[int]:
        """Earliest timer expiry, in ms, or None when the buffer is empty."""
        return min((e.deadline_ms for e in self._entries.values()), default=None)

    def pop_expired(self, now_ms: int) -> List[Tuple[K, T, int]]:
        """
        Remove the packets whose timer expired, returning ``(key, packet,
        remaining lifetime in ms)`` in queue order; packets whose lifetime ran
        out while buffered are discarded.
        """
        out: List[Tuple[K, T, int]] = []
        for key in [k for k, e in self._entries.items() if e.deadline_ms <= now_ms]:
            entry = self._entries.pop(key)
            self._size -= entry.size
            remaining = entry.remaining_lifetime_ms(now_ms)
            if remaining > 0:
                out.append((key, entry.item, remaining))
        return out


def cbf_timeout_ms(distance_m: float, to_cbf_min: float, to_cbf_max: float,
                   dist_max: float, to_acc: float = 0.0) -> float:
    """
    Segment-based CBF timeout TO_CBF (equations E.1 to E.3, and F.1, F.2).

    ``distance_m`` is the forwarding progress PROG (non-area CBF, clause E.3.2)
    or the forwarding distance F_DIST (area CBF, clause F.3.2); ``to_acc`` is the
    optional Access Layer constraint TO_ACC.

    SEGN = max(1, ceil(D / DIST_MAX))
    TO_CBF_WO_ACC = TO_CBF_MAX * SEGN
                    + (TO_CBF_MIN - TO_CBF_MAX) / DIST_MAX * (D - DIST_MAX * (SEGN - 1))
    TO_CBF = max(TO_CBF_WO_ACC, TO_ACC)
    """
    distance_m = max(0.0, distance_m)
    segn = max(1, math.ceil(distance_m / dist_max))
    wo_acc = (to_cbf_max * segn
              + (to_cbf_min - to_cbf_max) / dist_max * (distance_m - dist_max * (segn - 1)))
    return max(wo_acc, to_acc)


def cbf_timeout_update_ms(to_cbf: float, to_cbf_rp: float, to_cbf_max: float) -> float:
    """
    Recalculated timeout TO_CBF_UPDATE (equation E.4) on reception of a
    forwarded copy from a sender that is not a better forwarder.
    """
    if abs(to_cbf - to_cbf_rp) < to_cbf_max:
        return min(to_cbf, to_cbf_rp)
    return max(to_cbf, to_cbf_rp)
