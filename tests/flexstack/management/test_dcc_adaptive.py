import unittest

from flexstack.management.dcc_adaptive import (
    DccAdaptive,
    DccAdaptiveParameters,
    GateKeeper,
)


class TestDccAdaptiveInit(unittest.TestCase):
    """Tests for DccAdaptive initialisation."""

    def test_default_parameters(self):
        """Default parameters match Table 3 of §5.4."""
        alg = DccAdaptive()
        p = alg.parameters
        self.assertAlmostEqual(p.alpha, 0.016)
        self.assertAlmostEqual(p.beta, 0.0012)
        self.assertAlmostEqual(p.cbr_target, 0.68)
        self.assertAlmostEqual(p.delta_max, 0.03)
        self.assertAlmostEqual(p.delta_min, 0.0006)
        self.assertAlmostEqual(p.delta_up_max, 0.0005)
        self.assertAlmostEqual(p.delta_down_max, -0.00025)

    def test_initial_cbr_its_s_is_zero(self):
        """cbr_its_s starts at 0.0 before the first update."""
        alg = DccAdaptive()
        self.assertEqual(alg.cbr_its_s, 0.0)

    def test_initial_delta_is_delta_min(self):
        """delta is initialised to delta_min (conservative start)."""
        alg = DccAdaptive()
        self.assertAlmostEqual(alg.delta, alg.parameters.delta_min)

    def test_custom_parameters_accepted(self):
        """Custom DccAdaptiveParameters are stored correctly."""
        params = DccAdaptiveParameters(alpha=0.1, beta=0.05, cbr_target=0.5)
        alg = DccAdaptive(parameters=params)
        self.assertAlmostEqual(alg.parameters.alpha, 0.1)
        self.assertAlmostEqual(alg.parameters.cbr_target, 0.5)


class TestDccAdaptiveStep1(unittest.TestCase):
    """Step 1: CBR smoothing (equation 1 of §5.4)."""

    def test_cbr_its_s_uses_local_average(self):
        """
        cbr_its_s = 0.5*cbr_its_s + 0.5*((cbr_local + cbr_local_previous)/2).
        Starting from 0.0 with both measurements = 0.4, result = 0.1.
        """
        alg = DccAdaptive()
        alg.update(cbr_local=0.4, cbr_local_previous=0.4)
        # 0.5*0.0 + 0.5*(0.4+0.4)/2 = 0.5*0.4 = 0.2
        self.assertAlmostEqual(alg.cbr_its_s, 0.2)

    def test_cbr_its_s_accumulates_over_calls(self):
        """cbr_its_s accumulates correctly across multiple updates."""
        alg = DccAdaptive()
        alg.update(cbr_local=0.4, cbr_local_previous=0.4)
        # After first call: cbr_its_s = 0.2
        alg.update(cbr_local=0.4, cbr_local_previous=0.4)
        # After second call: 0.5*0.2 + 0.5*0.4 = 0.1 + 0.2 = 0.3
        self.assertAlmostEqual(alg.cbr_its_s, 0.3)

    def test_cbr_its_s_uses_global_when_provided(self):
        """
        When global CBR is supplied, it replaces local in step 1 (NOTE 1 of §5.4).
        """
        alg = DccAdaptive()
        alg.update(
            cbr_local=0.1,           # should be ignored
            cbr_local_previous=0.1,   # should be ignored
            cbr_global=0.6,
            cbr_global_previous=0.6,
        )
        # 0.5*0.0 + 0.5*(0.6+0.6)/2 = 0.5*0.6 = 0.3
        self.assertAlmostEqual(alg.cbr_its_s, 0.3)

    def test_cbr_its_s_ignores_global_when_only_one_provided(self):
        """
        Only one global measurement → local values are used instead.
        """
        alg = DccAdaptive()
        alg.update(
            cbr_local=0.4,
            cbr_local_previous=0.4,
            cbr_global=0.9,       # cbr_global_previous is missing
        )
        # Falls back to local: 0.5*(0.4+0.4)/2 = 0.2
        self.assertAlmostEqual(alg.cbr_its_s, 0.2)


class TestDccAdaptiveStep2(unittest.TestCase):
    """Step 2: delta_offset clamping (equations 2–3 of §5.4)."""

    def _alg_with_cbr(self, cbr_its_s: float) -> DccAdaptive:
        """Return an algorithm whose cbr_its_s is already set to cbr_its_s."""
        # Inject the value directly to isolate step 2 behaviour.
        alg = DccAdaptive()
        alg.cbr_its_s = cbr_its_s
        return alg

    def test_positive_diff_uses_equation_2(self):
        """
        When cbr_its_s < cbr_target: delta_offset = min(β*(target-cbr), upmax).
        With cbr_its_s=0.0, diff=0.68, β*diff=0.000816 > delta_up_max=0.0005
        → clamped to 0.0005.
        """
        alg = self._alg_with_cbr(0.0)
        alg.update(cbr_local=0.0, cbr_local_previous=0.0)
        # After update, delta should have been incremented by delta_up_max
        # delta = (1-0.016)*delta_min + 0.0005
        expected_delta = (1 - 0.016) * 0.0006 + 0.0005
        self.assertAlmostEqual(alg.delta, expected_delta, places=10)

    def test_negative_diff_uses_equation_3(self):
        """
        When cbr_its_s > cbr_target: delta_offset = max(β*(target-cbr), downmax).
        With cbr_its_s=1.0, diff=-0.32, β*diff=-0.000384 > delta_down_max=-0.00025
        → delta_offset=-0.000384, which is between downmax and 0.
        """
        alg = self._alg_with_cbr(1.0)
        initial_delta = alg.delta
        alg.update(cbr_local=1.0, cbr_local_previous=1.0)
        # cbr_its_s after step 1: 0.5*1.0 + 0.5*(1.0+1.0)/2 = 1.0
        # diff = 0.68 - 1.0 = -0.32; beta*diff = -0.000384; downmax=-0.00025
        # Since -0.000384 < -0.00025, delta_offset = -0.00025
        expected_delta = (1 - 0.016) * initial_delta + (-0.00025)
        expected_delta = max(0.0006, min(0.03, expected_delta))
        self.assertAlmostEqual(alg.delta, expected_delta, places=10)

    def test_small_positive_diff_not_clamped(self):
        """
        A small positive difference produces delta_offset = β*diff (no clamping).
        With cbr_its_s=0.679, diff=0.001, β*diff=0.0000012 < upmax=0.0005
        → offset=0.0000012 (not clamped).
        """
        p = DccAdaptiveParameters()
        alg = DccAdaptive(parameters=p)
        alg.cbr_its_s = 0.679
        alg.delta = 0.01   # known value to simplify assertion
        alg.update(cbr_local=0.679, cbr_local_previous=0.679)
        # step 1: cbr_its_s = 0.5*0.679 + 0.5*0.679 = 0.679
        # step 2: diff=0.001, offset=0.0000012
        # step 3: delta = (1-0.016)*0.01 + 0.0000012 ≈ 0.0098412
        diff = 0.68 - 0.679
        expected_offset = p.beta * diff
        expected_delta = (1 - p.alpha) * 0.01 + expected_offset
        self.assertAlmostEqual(alg.delta, expected_delta, places=10)

    def test_large_negative_diff_clamped_to_down_max(self):
        """
        A large negative diff is clamped to delta_down_max.
        cbr_its_s set to 0.99, diff=-0.31, β*diff=-0.000372 < downmax=-0.00025
        → delta_offset = -0.00025.
        """
        alg = DccAdaptive()
        alg.cbr_its_s = 0.99
        alg.delta = 0.02
        alg.update(cbr_local=0.99, cbr_local_previous=0.99)
        # cbr_its_s after step1: 0.5*0.99 + 0.5*0.99 = 0.99
        # diff=0.68-0.99=-0.31; beta*diff=-0.000372; clamped to -0.00025
        expected_delta = (1 - 0.016) * 0.02 + (-0.00025)
        self.assertAlmostEqual(alg.delta, expected_delta, places=10)


class TestDccAdaptiveSteps3to5(unittest.TestCase):
    """Steps 3–5: exponential filter and clamping."""

    def test_step3_exponential_filter(self):
        """delta = (1-α)*delta + delta_offset."""
        alg = DccAdaptive()
        alg.cbr_its_s = 0.68   # exactly at target → diff=0, offset=0
        alg.delta = 0.01
        alg.update(cbr_local=0.68, cbr_local_previous=0.68)
        # offset will be 0 (diff=0 → positive branch → min(0, upmax)=0)
        expected = (1 - 0.016) * 0.01 + 0.0
        self.assertAlmostEqual(alg.delta, expected, places=10)

    def test_step4_clamps_delta_to_max(self):
        """delta greater than delta_max is clamped to delta_max."""
        alg = DccAdaptive()
        alg.delta = 0.029  # close to max
        alg.cbr_its_s = 0.0   # far below target → large positive offset
        alg.update(cbr_local=0.0, cbr_local_previous=0.0)
        self.assertLessEqual(alg.delta, alg.parameters.delta_max)

    def test_step5_clamps_delta_to_min(self):
        """delta less than delta_min is clamped to delta_min."""
        alg = DccAdaptive()
        alg.delta = alg.parameters.delta_min  # at floor
        alg.cbr_its_s = 1.0   # far above target → large negative offset
        # Force cbr_its_s to stay at 1.0 so step 1 keeps it there
        alg.update(cbr_local=1.0, cbr_local_previous=1.0)
        self.assertGreaterEqual(alg.delta, alg.parameters.delta_min)

    def test_delta_converges_toward_target(self):
        """
        After many evaluations at exactly cbr_target, delta stabilises
        within the permitted range.
        """
        alg = DccAdaptive()
        cbr = 0.68
        for _ in range(500):
            alg.update(cbr_local=cbr, cbr_local_previous=cbr)
        self.assertGreaterEqual(alg.delta, alg.parameters.delta_min)
        self.assertLessEqual(alg.delta, alg.parameters.delta_max)

    def test_delta_increases_when_cbr_below_target(self):
        """
        Sustained low CBR causes delta to increase toward delta_max over time.
        """
        alg = DccAdaptive()
        prev_delta = alg.delta
        for _ in range(50):
            alg.update(cbr_local=0.0, cbr_local_previous=0.0)
        self.assertGreater(alg.delta, prev_delta)

    def test_delta_decreases_when_cbr_above_target(self):
        """
        Sustained high CBR causes delta to decrease toward delta_min.
        """
        alg = DccAdaptive()
        alg.delta = 0.02   # start above min
        for _ in range(200):
            alg.update(cbr_local=1.0, cbr_local_previous=1.0)
        self.assertEqual(alg.delta, alg.parameters.delta_min)


class TestDccAdaptiveValidation(unittest.TestCase):
    """Input validation tests for DccAdaptive.update."""

    def test_cbr_local_below_zero_raises(self):
        alg = DccAdaptive()
        with self.assertRaises(ValueError):
            alg.update(cbr_local=-0.01, cbr_local_previous=0.5)

    def test_cbr_local_above_one_raises(self):
        alg = DccAdaptive()
        with self.assertRaises(ValueError):
            alg.update(cbr_local=1.01, cbr_local_previous=0.5)

    def test_cbr_local_previous_below_zero_raises(self):
        alg = DccAdaptive()
        with self.assertRaises(ValueError):
            alg.update(cbr_local=0.5, cbr_local_previous=-0.01)

    def test_cbr_local_previous_above_one_raises(self):
        alg = DccAdaptive()
        with self.assertRaises(ValueError):
            alg.update(cbr_local=0.5, cbr_local_previous=1.01)

    def test_boundary_values_valid(self):
        alg = DccAdaptive()
        alg.update(cbr_local=0.0, cbr_local_previous=0.0)
        alg.update(cbr_local=1.0, cbr_local_previous=1.0)


# ---------------------------------------------------------------------------
# GateKeeper tests
# ---------------------------------------------------------------------------

class TestGateKeeperInit(unittest.TestCase):
    """Tests for GateKeeper initialisation."""

    def test_gate_is_open_initially(self):
        """Before any packet is admitted the gate is open."""
        gk = GateKeeper(delta=0.01)
        self.assertTrue(gk.is_open(t=0.0))

    def test_gate_is_open_at_any_time_initially(self):
        """is_open() returns True at any time before first admission."""
        gk = GateKeeper(delta=0.01)
        for t in [0.0, 100.0, -1.0]:
            self.assertTrue(gk.is_open(t=t))


class TestGateKeeperAdmit(unittest.TestCase):
    """Tests for GateKeeper.admit_packet (equation B.1)."""

    def test_first_packet_admitted(self):
        """The first packet is always admitted when the gate is open."""
        gk = GateKeeper(delta=0.01)
        self.assertTrue(gk.admit_packet(t=0.0, t_on=0.001))

    def test_gate_closed_after_admission(self):
        """Gate closes immediately after a packet is admitted."""
        gk = GateKeeper(delta=0.01)
        gk.admit_packet(t=0.0, t_on=0.001)
        self.assertFalse(gk.is_open(t=0.0))

    def test_second_packet_rejected_when_gate_closed(self):
        """A second admission attempt while the gate is closed is rejected."""
        gk = GateKeeper(delta=0.01)
        gk.admit_packet(t=0.0, t_on=0.001)
        self.assertFalse(gk.admit_packet(t=0.0, t_on=0.001))

    def test_gate_opens_after_t_go(self):
        """
        Gate opens exactly at t_go = t_pg + t_on/delta.
        delta=0.01, t_on=0.001 → interval=0.1 s ≥ 0.025 → t_go=0.1.
        """
        gk = GateKeeper(delta=0.01)
        gk.admit_packet(t=0.0, t_on=0.001)   # t_go = 0.0 + 0.1 = 0.1
        self.assertFalse(gk.is_open(t=0.099))
        self.assertTrue(gk.is_open(t=0.1))

    def test_minimum_interval_enforced(self):
        """
        t_on/delta < 0.025 s → interval clamped to 0.025 s.
        delta=1.0, t_on=0.001 → t_on/delta=0.001 < 0.025 → t_go=0.025.
        """
        gk = GateKeeper(delta=1.0)
        gk.admit_packet(t=0.0, t_on=0.001)
        self.assertFalse(gk.is_open(t=0.024))
        self.assertTrue(gk.is_open(t=0.025))

    def test_maximum_interval_enforced(self):
        """
        t_on/delta > 1 s → interval clamped to 1.0 s.
        delta=0.0006, t_on=0.001 → t_on/delta ≈ 1.667 > 1.0 → t_go=1.0.
        """
        gk = GateKeeper(delta=0.0006)
        gk.admit_packet(t=0.0, t_on=0.001)
        self.assertFalse(gk.is_open(t=0.99))
        self.assertTrue(gk.is_open(t=1.0))

    def test_t_on_zero_raises(self):
        gk = GateKeeper(delta=0.01)
        with self.assertRaises(ValueError):
            gk.admit_packet(t=0.0, t_on=0.0)

    def test_t_on_negative_raises(self):
        gk = GateKeeper(delta=0.01)
        with self.assertRaises(ValueError):
            gk.admit_packet(t=0.0, t_on=-0.001)


class TestGateKeeperUpdateDelta(unittest.TestCase):
    """Tests for GateKeeper.update_delta (equation B.2)."""

    def test_update_delta_when_gate_open_only_changes_delta(self):
        """
        When the gate is open, update_delta only changes the stored delta
        without rescheduling t_go.
        """
        gk = GateKeeper(delta=0.01)
        # Gate is open (no packet admitted) → no rescheduling
        gk.update_delta(t=0.0, delta_new=0.02)
        # Gate should still be open
        self.assertTrue(gk.is_open(t=0.0))

    def test_update_delta_rescales_interval_when_delta_increases(self):
        """
        Increasing delta reduces the remaining gate-closed interval per B.2.
        Original: delta=0.01, t_on=0.001 → interval=0.1 s.
        New delta=0.02 → new_interval = (0.01/0.02)*0.1 = 0.05 s.
        """
        gk = GateKeeper(delta=0.01)
        gk.admit_packet(t=0.0, t_on=0.001)   # t_go = 0.1
        gk.update_delta(t=0.0, delta_new=0.02)  # t_go → 0.05
        self.assertFalse(gk.is_open(t=0.049))
        self.assertTrue(gk.is_open(t=0.05))

    def test_update_delta_rescales_interval_when_delta_decreases(self):
        """
        Decreasing delta increases the remaining gate-closed interval per B.2.
        Original: delta=0.02, t_on=0.001 → interval=0.05 s.
        New delta=0.01 → new_interval = (0.02/0.01)*0.05 = 0.1 s.
        """
        gk = GateKeeper(delta=0.02)
        gk.admit_packet(t=0.0, t_on=0.001)   # t_go = 0.05
        gk.update_delta(t=0.0, delta_new=0.01)  # t_go → 0.1
        self.assertFalse(gk.is_open(t=0.099))
        self.assertTrue(gk.is_open(t=0.1))

    def test_update_delta_minimum_interval_enforced(self):
        """
        New interval below 0.025 s is clamped to 0.025 s in B.2.
        Original: delta=0.01, interval=0.1.
        New delta=0.1 → (0.01/0.1)*0.1 = 0.01 < 0.025 → clamped to 0.025.
        """
        gk = GateKeeper(delta=0.01)
        gk.admit_packet(t=0.0, t_on=0.001)
        gk.update_delta(t=0.0, delta_new=0.1)
        self.assertFalse(gk.is_open(t=0.024))
        self.assertTrue(gk.is_open(t=0.025))

    def test_update_delta_maximum_interval_enforced(self):
        """
        New interval above 1.0 s is clamped to 1.0 s in B.2.
        Original: delta=0.02, interval=0.05.
        New delta=0.0001 → (0.02/0.0001)*0.05 = 10 > 1.0 → clamped to 1.0.
        """
        gk = GateKeeper(delta=0.02)
        gk.admit_packet(t=0.0, t_on=0.001)
        gk.update_delta(t=0.0, delta_new=0.0001)
        self.assertFalse(gk.is_open(t=0.99))
        self.assertTrue(gk.is_open(t=1.0))

    def test_update_delta_zero_raises(self):
        gk = GateKeeper(delta=0.01)
        with self.assertRaises(ValueError):
            gk.update_delta(t=0.0, delta_new=0.0)

    def test_update_delta_negative_raises(self):
        gk = GateKeeper(delta=0.01)
        with self.assertRaises(ValueError):
            gk.update_delta(t=0.0, delta_new=-0.01)

    def test_update_after_gate_reopens_no_rescheduling(self):
        """
        If the gate has already opened by the time update_delta is called,
        only the stored delta value changes (no rescheduling needed).
        """
        gk = GateKeeper(delta=0.01)
        gk.admit_packet(t=0.0, t_on=0.001)   # t_go = 0.1
        # Advance time past t_go so the gate is now open
        gk.update_delta(t=0.5, delta_new=0.005)
        # Gate should still be open
        self.assertTrue(gk.is_open(t=0.5))


class TestGateKeeperAndAdaptiveIntegration(unittest.TestCase):
    """Integration: GateKeeper paces transmissions driven by DccAdaptive."""

    def test_gate_keeper_uses_updated_delta(self):
        """
        After update_delta, subsequent admissions use the new delta to compute
        t_go per equation B.1.
        """
        gk = GateKeeper(delta=0.01)
        gk.admit_packet(t=0.0, t_on=0.001)   # t_go = 0.1 (first admission)

        # Gate opens at 0.1; admit a second packet
        self.assertTrue(gk.is_open(t=0.1))
        gk.update_delta(t=0.1, delta_new=0.02)  # delta now 0.02
        gk.admit_packet(t=0.1, t_on=0.001)      # t_go = 0.1 + 0.001/0.02 = 0.1+0.05=0.15
        self.assertFalse(gk.is_open(t=0.14))
        self.assertTrue(gk.is_open(t=0.15))


if __name__ == "__main__":
    unittest.main()
