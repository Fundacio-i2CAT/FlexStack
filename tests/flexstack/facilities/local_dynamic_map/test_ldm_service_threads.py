import unittest
from unittest.mock import MagicMock, patch

from flexstack.facilities.local_dynamic_map.ldm_service_threads import (
    LDMServiceThreads,
)


class TestLDMServiceThreads(unittest.TestCase):
    @patch("threading.Thread")
    @patch("threading.Event")
    @patch("threading.Lock")
    @patch("flexstack.facilities.local_dynamic_map.ldm_service.LDMService")
    def setUp(self, mock_ldm_service, mock_lock, mock_event, mock_thread):
        self.threading_thread = MagicMock()
        self.threading_thread.start = MagicMock(return_value=None)
        mock_thread.return_value = self.threading_thread
        self.mock_thread = mock_thread
        self.mock_lock = mock_lock
        self.mock_event = mock_event

        self.ldm_maintenance = MagicMock()
        self.stop_event = MagicMock()
        self.stop_event.is_set = MagicMock(return_value=False)
        mock_event.return_value = self.stop_event
        self.ldm_service = LDMServiceThreads(self.ldm_maintenance)

    def test__init__(self):
        self.mock_lock.assert_called_once()
        self.threading_thread.start.assert_called_once()
        self.mock_event.assert_called_once()

    def test_subscriptions_service(self):
        self.ldm_service.attend_subscriptions = MagicMock()
        self.stop_event.is_set.return_value = True
        self.ldm_service.subscriptions_service()
        self.stop_event.is_set.assert_called_once()
        self.ldm_service.attend_subscriptions.assert_not_called()
