import unittest
from unittest.mock import patch
from dateutil import parser
from flexstack.utils.time_service import (
    TimeService, ITS_EPOCH, ITS_EPOCH_MS, ELAPSED_SECONDS, ELAPSED_MILLISECONDS)


class TestTimeService(unittest.TestCase):

    def test_its_epoch(self):
        # Check if ITS_EPOCH is correctly defined
        self.assertEqual(ITS_EPOCH, int(
            parser.parse("2004-01-01T00:00:00Z").timestamp()))

    def test_its_epoch_ms(self):
        # Check if ITS_EPOCH_MS is correctly defined
        self.assertEqual(ITS_EPOCH_MS, int(parser.parse(
            "2004-01-01T00:00:00Z").timestamp()*1000))

    def test_elapsed_seconds(self):
        # Check if ELAPSED_SECONDS is correctly defined
        self.assertEqual(ELAPSED_SECONDS, 5)

    def test_elapsed_milliseconds(self):
        # Check if ELAPSED_MILLISECONDS is correctly defined
        self.assertEqual(ELAPSED_MILLISECONDS, 5000)

    def test_timestamp_its(self):
        # Mock TimeService.time to return a fixed time
        fixed_time = parser.parse("2023-01-01T12:00:00Z").timestamp()
        with patch.object(TimeService, 'time', return_value=fixed_time):
            its_timestamp = TimeService.timestamp_its()
            expected_its_timestamp = int((fixed_time - ITS_EPOCH + 5) * 1000)
            self.assertEqual(its_timestamp, expected_its_timestamp)

    def test_2007_standard_example(self):
        time_2007 = parser.parse("2007-01-01T00:00:00Z").timestamp()
        its_timestamp = int(
            (time_2007 - parser.parse("2004-01-01T00:00:00Z").timestamp() + 1) * 1000)
        self.assertEqual(its_timestamp, 94_694_401_000)
