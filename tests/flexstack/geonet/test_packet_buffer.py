"""
GeoNetworking packet buffers and CBF timeouts
(ETSI TS 103 836-4-1 V2.2.1, clauses 8.5.3, 8.6.3, E.3.2, E.3.3, F.3.2).

Mirrors ``rustflexstack::geonet::packet_buffer`` tests.
"""

import unittest

from flexstack.geonet.packet_buffer import (
    CbfPacketBuffer,
    PacketBuffer,
    cbf_timeout_ms,
    cbf_timeout_update_ms,
)

TO_MIN, TO_MAX, DIST_MAX = 1.0, 100.0, 1000.0


class TestPacketBuffer(unittest.TestCase):

    def test_fifo_flush_with_reduced_lifetime(self):
        buffer: PacketBuffer[str] = PacketBuffer(100)
        buffer.push("a", 10, 1000, now_ms=0)
        buffer.push("b", 10, 1000, now_ms=100)
        self.assertEqual(buffer.flush(now_ms=300), [("a", 700), ("b", 800)])
        self.assertEqual(len(buffer), 0)
        self.assertEqual(buffer.size, 0)

    def test_head_drop_on_overflow(self):
        buffer: PacketBuffer[str] = PacketBuffer(25)
        buffer.push("a", 10, 1000, 0)
        buffer.push("b", 10, 1000, 0)
        self.assertEqual(buffer.push("c", 10, 1000, 0), 1)
        self.assertEqual([item for item, _ in buffer.flush(0)], ["b", "c"])

    def test_packet_larger_than_buffer_is_dropped(self):
        buffer: PacketBuffer[str] = PacketBuffer(5)
        self.assertEqual(buffer.push("a", 10, 1000, 0), 1)
        self.assertEqual(len(buffer), 0)

    def test_expired_packets_are_discarded(self):
        buffer: PacketBuffer[str] = PacketBuffer(100)
        buffer.push("short", 10, 50, 0)
        buffer.push("long", 10, 5000, 0)
        self.assertEqual(buffer.purge(now_ms=50), 1)
        buffer.push("short2", 10, 50, 0)
        self.assertEqual(buffer.flush(now_ms=60), [("long", 4940)])


class TestCbfPacketBuffer(unittest.TestCase):

    def test_timer_expiry_and_restart(self):
        buffer: CbfPacketBuffer[tuple, str] = CbfPacketBuffer(1000)
        buffer.insert(("so", 1), "p1", 10, 1000, now_ms=0, timeout_ms=50)
        buffer.insert(("so", 2), "p2", 10, 1000, now_ms=0, timeout_ms=80)
        self.assertEqual(buffer.next_deadline(), 50)
        self.assertEqual(buffer.remaining_timeout_ms(("so", 1), 20), 30)
        buffer.restart(("so", 1), now_ms=20, timeout_ms=100)
        self.assertEqual(buffer.pop_expired(80), [(("so", 2), "p2", 920)])
        self.assertIn(("so", 1), buffer)
        self.assertEqual(buffer.get(("so", 1)), "p1")
        self.assertEqual(buffer.remove(("so", 1)), "p1")
        self.assertIsNone(buffer.next_deadline())

    def test_head_drop_and_lifetime(self):
        buffer: CbfPacketBuffer[int, str] = CbfPacketBuffer(15)
        buffer.insert(1, "a", 10, 1000, 0, 10)
        buffer.insert(2, "b", 10, 5, 0, 10)
        self.assertNotIn(1, buffer)
        self.assertEqual(buffer.pop_expired(10), [])     # lifetime ran out


class TestCbfTimeout(unittest.TestCase):
    """Equations (E.1)-(E.4) and the example table of clause E.3.2.3 NOTE 3."""

    def test_example_values(self):
        self.assertAlmostEqual(cbf_timeout_ms(DIST_MAX, TO_MIN, TO_MAX, DIST_MAX), TO_MIN)
        self.assertAlmostEqual(cbf_timeout_ms(0, TO_MIN, TO_MAX, DIST_MAX), TO_MAX)
        self.assertAlmostEqual(cbf_timeout_ms(2 * DIST_MAX, TO_MIN, TO_MAX, DIST_MAX), TO_MAX + TO_MIN)
        self.assertAlmostEqual(cbf_timeout_ms(2.0001 * DIST_MAX, TO_MIN, TO_MAX, DIST_MAX),
                               3 * TO_MAX, places=1)

    def test_first_segment_is_linear(self):
        self.assertAlmostEqual(cbf_timeout_ms(DIST_MAX / 2, TO_MIN, TO_MAX, DIST_MAX),
                               (TO_MIN + TO_MAX) / 2)

    def test_access_layer_constraint(self):
        self.assertEqual(cbf_timeout_ms(DIST_MAX, TO_MIN, TO_MAX, DIST_MAX, to_acc=40), 40)

    def test_timeout_update(self):
        self.assertEqual(cbf_timeout_update_ms(30, 60, TO_MAX), 30)    # close: min
        self.assertEqual(cbf_timeout_update_ms(30, 150, TO_MAX), 150)  # far apart: max


if __name__ == "__main__":
    unittest.main()
