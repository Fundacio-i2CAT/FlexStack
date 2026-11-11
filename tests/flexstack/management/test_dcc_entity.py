import time
import unittest

from flexstack.management.cbr import SharedCbr
from flexstack.management.dcc_adaptive import DccAdaptive
from flexstack.management.dcc_entity import (
    DCC_EVALUATION_PERIOD_MS,
    DccEntity,
    DccMode,
    _ms_to_next_boundary,
    clamp_t_gen_cam_dcc,
)
from flexstack.management.dcc_reactive import DccState


def _entity(mode):
    cbr = SharedCbr()
    return DccEntity(mode, cbr), cbr


class TestClampTGenCamDcc(unittest.TestCase):
    def test_bounds_and_rounding(self):
        self.assertEqual(clamp_t_gen_cam_dcc(10.0), 100)
        self.assertEqual(clamp_t_gen_cam_dcc(400.4), 400)
        self.assertEqual(clamp_t_gen_cam_dcc(5000.0), 1000)
        self.assertEqual(clamp_t_gen_cam_dcc(float("inf")), 1000)
        self.assertEqual(clamp_t_gen_cam_dcc(float("nan")), 1000)


class TestDccEntityReactive(unittest.TestCase):
    def test_no_measurement_returns_none(self):
        dcc, _ = _entity(DccMode.reactive())
        self.assertIsNone(dcc.evaluate())
        self.assertIsNone(dcc.last_output())

    def test_relaxed_maps_to_t_gen_cam_min(self):
        dcc, cbr = _entity(DccMode.reactive())
        cbr.report(0.1)
        out = dcc.evaluate()
        self.assertEqual(out.state, DccState.RELAXED)
        self.assertEqual(out.t_gen_cam_dcc_ms, 100)
        self.assertIsNone(out.delta)

    def test_steps_one_state_per_evaluation(self):
        # Table A.1 T_off: 100, 200, 400, 500, 1000 ms.
        dcc, cbr = _entity(DccMode.reactive())
        cbr.report(0.9)
        for ms in (200, 400, 500, 1000, 1000):
            self.assertEqual(dcc.evaluate().t_gen_cam_dcc_ms, ms)
        self.assertEqual(dcc.last_output().state, DccState.RESTRICTIVE)
        # Channel clears: one step down per evaluation.
        cbr.report(0.0)
        self.assertEqual(dcc.evaluate().t_gen_cam_dcc_ms, 500)
        self.assertEqual(dcc.evaluate().t_gen_cam_dcc_ms, 400)

    def test_table_a2(self):
        dcc, cbr = _entity(DccMode.reactive(t_on_max_us=500))
        cbr.report(0.35)
        # Table A.2 Active1 T_off = 100 ms.
        self.assertEqual(dcc.evaluate().t_gen_cam_dcc_ms, 100)


class TestDccEntityAdaptive(unittest.TestCase):
    def test_low_cbr_allows_t_gen_cam_min(self):
        dcc, cbr = _entity(DccMode.adaptive())
        cbr.report(0.0)
        out = dcc.evaluate()
        for _ in range(2000):
            out = dcc.evaluate()
        # delta converges to delta_max = 0.03 -> 1 ms / 0.03 = 33 ms -> clamped to 100 ms.
        self.assertAlmostEqual(out.delta, 0.03, places=9)
        self.assertEqual(out.t_gen_cam_dcc_ms, 100)
        self.assertIsNone(out.state)

    def test_high_cbr_reaches_t_gen_cam_max(self):
        dcc, cbr = _entity(DccMode.adaptive())
        cbr.report(1.0)
        # The CBR_ITS_S smoothing (step 1) starts below the target, so delta
        # first rises; it then converges to delta_min under a saturated channel.
        out = dcc.evaluate()
        for _ in range(2000):
            out = dcc.evaluate()
        # delta = delta_min = 0.0006 -> 1 ms / 0.0006 = 1667 ms -> clamped to 1000 ms.
        self.assertAlmostEqual(out.delta, 0.0006, places=12)
        self.assertEqual(out.t_gen_cam_dcc_ms, 1000)

    def test_uses_previous_cbr(self):
        dcc, cbr = _entity(DccMode.adaptive())
        cbr.report(0.2)
        dcc.evaluate()
        cbr.report(0.6)
        out = dcc.evaluate()
        alg = DccAdaptive()
        alg.update(0.2, 0.2)
        delta = alg.update(0.6, 0.2)
        self.assertAlmostEqual(out.delta, delta, places=15)
        other, _ = _entity(DccMode.adaptive())
        self.assertIsNone(other.evaluate())


class TestDccEntityListenersAndThread(unittest.TestCase):
    def test_listeners_receive_t_gen_cam_dcc(self):
        dcc, cbr = _entity(DccMode.reactive())
        seen = []
        dcc.add_t_gen_cam_dcc_listener(seen.append)
        cbr.report(0.9)
        dcc.evaluate()
        self.assertEqual(seen, [200])

    def test_invalid_mode_rejected(self):
        with self.assertRaises(ValueError):
            DccEntity(DccMode(kind="bogus"), SharedCbr())

    def test_start_evaluates_periodically_and_stops(self):
        dcc, cbr = _entity(DccMode.reactive())
        seen = []
        dcc.add_t_gen_cam_dcc_listener(seen.append)
        cbr.report(0.9)
        dcc.start()
        time.sleep((3 * DCC_EVALUATION_PERIOD_MS + 50) / 1000.0)
        dcc.stop()
        # At least two evaluations happened: Relaxed -> Active1 (200) -> Active2 (400) ...
        self.assertGreaterEqual(max(seen), 400)
        count = len(seen)
        time.sleep(DCC_EVALUATION_PERIOD_MS / 1000.0 * 1.5)
        self.assertEqual(len(seen), count)

    def test_ms_to_next_boundary_in_range(self):
        ms = _ms_to_next_boundary()
        self.assertTrue(1 <= ms <= DCC_EVALUATION_PERIOD_MS)


if __name__ == "__main__":
    unittest.main()
