import unittest

from flexstack.management.dcc_reactive import (
    DccReactive,
    DccReactiveOutput,
    DccState,
)


class TestDccReactiveInit(unittest.TestCase):
    """Tests for DccReactive initialisation."""

    def test_initial_state_is_relaxed(self):
        """Algorithm starts in the RELAXED state."""
        dcc = DccReactive()
        self.assertEqual(dcc.state, DccState.RELAXED)

    def test_table_a1_selected_by_default(self):
        """t_on_max_us=1000 (default) selects Table A.1 (10 Hz relaxed rate)."""
        dcc = DccReactive(t_on_max_us=1000)
        out = dcc.update(cbr=0.0)
        self.assertEqual(out.packet_rate_hz, 10.0)
        self.assertEqual(out.t_off_ms, 100.0)

    def test_table_a2_selected_for_500us(self):
        """t_on_max_us=500 selects Table A.2 (20 Hz relaxed rate)."""
        dcc = DccReactive(t_on_max_us=500)
        out = dcc.update(cbr=0.0)
        self.assertEqual(out.packet_rate_hz, 20.0)
        self.assertEqual(out.t_off_ms, 50.0)

    def test_table_a2_selected_for_below_500us(self):
        """t_on_max_us < 500 also selects Table A.2."""
        dcc = DccReactive(t_on_max_us=250)
        out = dcc.update(cbr=0.0)
        self.assertEqual(out.packet_rate_hz, 20.0)


class TestDccReactiveTableA1(unittest.TestCase):
    """Tests for the Table A.1 parameter set (T_on ≤ 1 ms)."""

    def _dcc(self) -> DccReactive:
        return DccReactive(t_on_max_us=1000)

    # ------------------------------------------------------------------
    # Output parameter correctness per state
    # ------------------------------------------------------------------

    def test_relaxed_output_params(self):
        """RELAXED → 10 Hz, 100 ms T_off (Table A.1)."""
        dcc = self._dcc()
        out = dcc.update(cbr=0.0)
        self.assertEqual(out.state, DccState.RELAXED)
        self.assertEqual(out.packet_rate_hz, 10.0)
        self.assertEqual(out.t_off_ms, 100.0)

    def test_active1_output_params(self):
        """ACTIVE_1 → 5 Hz, 200 ms T_off (Table A.1)."""
        dcc = self._dcc()
        out = dcc.update(cbr=0.35)
        self.assertEqual(out.state, DccState.ACTIVE_1)
        self.assertEqual(out.packet_rate_hz, 5.0)
        self.assertEqual(out.t_off_ms, 200.0)

    def test_active2_output_params(self):
        """ACTIVE_2 → 2.5 Hz, 400 ms T_off (Table A.1)."""
        dcc = self._dcc()
        dcc.update(cbr=0.45)   # Relaxed → Active1
        out = dcc.update(cbr=0.45)  # Active1 → Active2
        self.assertEqual(out.state, DccState.ACTIVE_2)
        self.assertEqual(out.packet_rate_hz, 2.5)
        self.assertEqual(out.t_off_ms, 400.0)

    def test_active3_output_params(self):
        """ACTIVE_3 → 2 Hz, 500 ms T_off (Table A.1)."""
        dcc = self._dcc()
        # Step up: Relaxed→A1→A2→A3
        for _ in range(3):
            dcc.update(cbr=0.55)
        out = dcc.update(cbr=0.55)
        self.assertEqual(out.state, DccState.ACTIVE_3)
        self.assertEqual(out.packet_rate_hz, 2.0)
        self.assertEqual(out.t_off_ms, 500.0)

    def test_restrictive_output_params(self):
        """RESTRICTIVE → 1 Hz, 1000 ms T_off (Table A.1)."""
        dcc = self._dcc()
        # Step up to Restrictive (4 steps needed from Relaxed)
        for _ in range(4):
            dcc.update(cbr=0.65)
        out = dcc.update(cbr=0.65)
        self.assertEqual(out.state, DccState.RESTRICTIVE)
        self.assertEqual(out.packet_rate_hz, 1.0)
        self.assertEqual(out.t_off_ms, 1000.0)

    # ------------------------------------------------------------------
    # Transition correctness
    # ------------------------------------------------------------------

    def test_low_cbr_stays_relaxed(self):
        """Repeated low-CBR evaluations keep the state RELAXED."""
        dcc = self._dcc()
        for _ in range(5):
            out = dcc.update(cbr=0.10)
            self.assertEqual(out.state, DccState.RELAXED)

    def test_cbr_at_lower_threshold_triggers_active1(self):
        """CBR exactly at 0.30 transitions RELAXED → ACTIVE_1."""
        dcc = self._dcc()
        out = dcc.update(cbr=0.30)
        self.assertEqual(out.state, DccState.ACTIVE_1)

    def test_adjacent_only_from_relaxed_to_active1(self):
        """
        From RELAXED, even a very high CBR advances only one step to ACTIVE_1
        (adjacency constraint of §5.3).
        """
        dcc = self._dcc()
        out = dcc.update(cbr=0.99)
        self.assertEqual(out.state, DccState.ACTIVE_1)

    def test_two_steps_from_relaxed_to_active2(self):
        """Two consecutive high-CBR evaluations from RELAXED reach ACTIVE_2."""
        dcc = self._dcc()
        dcc.update(cbr=0.55)  # Relaxed → Active1
        out = dcc.update(cbr=0.55)  # Active1 → Active2
        self.assertEqual(out.state, DccState.ACTIVE_2)

    def test_step_down_from_active1_to_relaxed(self):
        """Low CBR from ACTIVE_1 steps down to RELAXED."""
        dcc = self._dcc()
        dcc.update(cbr=0.35)   # → Active1
        out = dcc.update(cbr=0.10)  # → Relaxed
        self.assertEqual(out.state, DccState.RELAXED)

    def test_same_state_when_cbr_in_band(self):
        """No transition when CBR stays within the current state's band."""
        dcc = self._dcc()
        dcc.update(cbr=0.35)  # → Active1
        out = dcc.update(cbr=0.32)  # still in Active1 band
        self.assertEqual(out.state, DccState.ACTIVE_1)

    def test_upward_then_downward_transition_sequence(self):
        """Full round-trip: Relaxed → A1 → A2 → A1 → Relaxed."""
        dcc = self._dcc()
        states = []
        for cbr in [0.45, 0.45, 0.10, 0.10]:
            states.append(dcc.update(cbr=cbr).state)
        self.assertEqual(states, [
            DccState.ACTIVE_1,
            DccState.ACTIVE_2,
            DccState.ACTIVE_1,
            DccState.RELAXED,
        ])

    def test_cannot_skip_states_going_up(self):
        """No state is ever skipped regardless of CBR magnitude."""
        dcc = self._dcc()
        previous_idx = 0
        for _ in range(6):
            out = dcc.update(cbr=1.0)  # always maximum CBR
            current_idx = list(DccState).index(out.state)
            self.assertLessEqual(current_idx - previous_idx, 1)
            previous_idx = current_idx

    def test_cannot_skip_states_going_down(self):
        """No state is ever skipped when descending."""
        dcc = self._dcc()
        # Drive to Restrictive
        for _ in range(5):
            dcc.update(cbr=1.0)
        previous_idx = list(DccState).index(dcc.state)
        for _ in range(6):
            out = dcc.update(cbr=0.0)  # always minimum CBR
            current_idx = list(DccState).index(out.state)
            self.assertGreaterEqual(previous_idx - current_idx, 0)
            self.assertLessEqual(previous_idx - current_idx, 1)
            previous_idx = current_idx

    def test_cbr_boundary_at_060_table_a1(self):
        """CBR = 0.60 (Table A.1) should target RESTRICTIVE (>= 0.60)."""
        dcc = self._dcc()
        # Drive to Active3 first
        for _ in range(3):
            dcc.update(cbr=0.65)
        out = dcc.update(cbr=0.60)
        self.assertEqual(out.state, DccState.RESTRICTIVE)


class TestDccReactiveTableA2(unittest.TestCase):
    """Tests for Table A.2 parameter set (T_on ≤ 500 µs)."""

    def _dcc(self) -> DccReactive:
        return DccReactive(t_on_max_us=500)

    def test_relaxed_output_params_table_a2(self):
        """RELAXED → 20 Hz, 50 ms T_off (Table A.2)."""
        dcc = self._dcc()
        out = dcc.update(cbr=0.10)
        self.assertEqual(out.state, DccState.RELAXED)
        self.assertEqual(out.packet_rate_hz, 20.0)
        self.assertEqual(out.t_off_ms, 50.0)

    def test_active3_output_params_table_a2(self):
        """ACTIVE_3 → 4 Hz, 250 ms T_off (Table A.2)."""
        dcc = self._dcc()
        for _ in range(3):
            dcc.update(cbr=0.60)
        out = dcc.update(cbr=0.60)
        self.assertEqual(out.state, DccState.ACTIVE_3)
        self.assertEqual(out.packet_rate_hz, 4.0)
        self.assertEqual(out.t_off_ms, 250.0)

    def test_restrictive_threshold_table_a2(self):
        """Table A.2 RESTRICTIVE threshold is 0.65 (not 0.60)."""
        dcc = self._dcc()
        # Drive to Active3 (0.60 is still in A3 band for Table A.2)
        for _ in range(3):
            dcc.update(cbr=0.70)
        out = dcc.update(cbr=0.65)
        self.assertEqual(out.state, DccState.RESTRICTIVE)


class TestDccReactiveValidation(unittest.TestCase):
    """Tests for input validation."""

    def test_cbr_below_zero_raises(self):
        dcc = DccReactive()
        with self.assertRaises(ValueError):
            dcc.update(cbr=-0.01)

    def test_cbr_above_one_raises(self):
        dcc = DccReactive()
        with self.assertRaises(ValueError):
            dcc.update(cbr=1.01)

    def test_cbr_zero_valid(self):
        dcc = DccReactive()
        out = dcc.update(cbr=0.0)
        self.assertEqual(out.state, DccState.RELAXED)

    def test_cbr_one_valid(self):
        dcc = DccReactive()
        out = dcc.update(cbr=1.0)
        self.assertEqual(out.state, DccState.ACTIVE_1)


class TestDccReactiveOutput(unittest.TestCase):
    """Tests for DccReactiveOutput dataclass."""

    def test_output_is_frozen(self):
        """DccReactiveOutput instances are immutable."""
        out = DccReactiveOutput(
            state=DccState.RELAXED, packet_rate_hz=10.0, t_off_ms=100.0
        )
        with self.assertRaises(Exception):
            out.state = DccState.ACTIVE_1  # type: ignore[misc]

    def test_output_equality(self):
        a = DccReactiveOutput(DccState.ACTIVE_1, 5.0, 200.0)
        b = DccReactiveOutput(DccState.ACTIVE_1, 5.0, 200.0)
        self.assertEqual(a, b)


if __name__ == "__main__":
    unittest.main()
