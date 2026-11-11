import unittest
from unittest.mock import MagicMock, patch

from flexstack.management.cbr import (
    CbrProvider,
    Nl80211SurveyCbr,
    SharedCbr,
    SurveySample,
    cbr_from_samples,
    parse_survey_dump,
)

DUMP = (
    "Survey data from wlan0\n"
    "\tfrequency:\t\t\t5880 MHz\n"
    "\tnoise:\t\t\t\t-95 dBm\n"
    "\tchannel active time:\t\t999 ms\n"
    "\tchannel busy time:\t\t111 ms\n"
    "Survey data from wlan0\n"
    "\tfrequency:\t\t\t5900 MHz [in use]\n"
    "\tnoise:\t\t\t\t-92 dBm\n"
    "\tchannel active time:\t\t20000 ms\n"
    "\tchannel busy time:\t\t5000 ms\n"
    "\tchannel receive time:\t\t4000 ms\n"
    "\tchannel transmit time:\t\t500 ms\n"
    "Survey data from wlan0\n"
    "\tfrequency:\t\t\t5910 MHz\n"
    "\tchannel active time:\t\t7 ms\n"
    "\tchannel busy time:\t\t7 ms\n"
)


class TestCbrProvider(unittest.TestCase):
    def test_base_class_not_implemented(self):
        with self.assertRaises(NotImplementedError):
            CbrProvider().measure_cbr()


class TestSharedCbr(unittest.TestCase):
    def test_empty_then_reported(self):
        cell = SharedCbr()
        self.assertIsNone(cell.measure_cbr())
        cell.report(0.42)
        self.assertEqual(cell.measure_cbr(), 0.42)
        # Latest value is returned on every poll.
        self.assertEqual(cell.measure_cbr(), 0.42)

    def test_ignores_invalid_values(self):
        cell = SharedCbr()
        cell.report(0.3)
        cell.report(1.5)
        cell.report(-0.1)
        cell.report(float("nan"))
        self.assertEqual(cell.latest(), 0.3)


class TestParseSurveyDump(unittest.TestCase):
    def test_selects_in_use_channel(self):
        self.assertEqual(parse_survey_dump(DUMP), SurveySample(active_ms=20000, busy_ms=5000))

    def test_without_in_use_channel(self):
        text = (
            "Survey data from wlan0\n\tfrequency:\t5880 MHz\n"
            "\tchannel active time:\t10 ms\n\tchannel busy time:\t1 ms\n"
        )
        self.assertIsNone(parse_survey_dump(text))
        self.assertIsNone(parse_survey_dump(""))

    def test_missing_busy_counter(self):
        text = "Survey data from wlan0\n\tfrequency:\t5900 MHz [in use]\n\tchannel active time:\t10 ms\n"
        self.assertIsNone(parse_survey_dump(text))


class TestCbrFromSamples(unittest.TestCase):
    def test_ratio(self):
        cbr = cbr_from_samples(SurveySample(1000, 100), SurveySample(1200, 160))
        self.assertAlmostEqual(cbr, 0.3, places=12)

    def test_rejects_stalled_or_reset_counters(self):
        a = SurveySample(1000, 100)
        self.assertIsNone(cbr_from_samples(a, a))
        self.assertIsNone(cbr_from_samples(a, SurveySample(10, 1)))

    def test_clamps_to_one(self):
        self.assertEqual(cbr_from_samples(SurveySample(1000, 100), SurveySample(1100, 300)), 1.0)


class TestNl80211SurveyCbr(unittest.TestCase):
    def test_ingest_first_sample_is_reference(self):
        p = Nl80211SurveyCbr("wlan0")
        self.assertEqual(p.iface, "wlan0")
        self.assertIsNone(p.ingest(SurveySample(0, 0)))
        self.assertAlmostEqual(p.ingest(SurveySample(200, 50)), 0.25, places=12)
        self.assertAlmostEqual(p.ingest(SurveySample(400, 150)), 0.5, places=12)

    @patch("flexstack.management.cbr.subprocess.run")
    def test_measure_cbr_runs_iw(self, mock_run):
        first = DUMP
        second = DUMP.replace("20000 ms", "20200 ms").replace("5000 ms", "5100 ms")
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout=first),
            MagicMock(returncode=0, stdout=second),
        ]
        p = Nl80211SurveyCbr("wlan0")
        self.assertIsNone(p.measure_cbr())
        self.assertAlmostEqual(p.measure_cbr(), 0.5, places=12)
        args = mock_run.call_args[0][0]
        self.assertEqual(args, ["iw", "dev", "wlan0", "survey", "dump"])

    @patch("flexstack.management.cbr.subprocess.run", side_effect=OSError("no iw"))
    def test_measure_cbr_without_iw(self, _mock_run):
        self.assertIsNone(Nl80211SurveyCbr("wlan0").measure_cbr())

    @patch("flexstack.management.cbr.subprocess.run")
    def test_measure_cbr_iw_error(self, mock_run):
        mock_run.return_value = MagicMock(returncode=237, stdout="")
        self.assertIsNone(Nl80211SurveyCbr("wlan0").measure_cbr())


if __name__ == "__main__":
    unittest.main()
