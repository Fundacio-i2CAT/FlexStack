import unittest
from unittest.mock import MagicMock, patch

from flexstack.facilities.local_dynamic_map.ldm_classes import AddDataProviderReq
from flexstack.facilities.local_dynamic_map.ldm_service_reactive import (
    LDMServiceReactive,
)


class TestLDMServiceReactive(unittest.TestCase):
    @patch("time.monotonic")
    def setUp(self, mock_monotonic):
        mock_monotonic.return_value = 0.0
        self.ldm_maintenance = MagicMock()
        self.ldm_service = LDMServiceReactive(self.ldm_maintenance)

    @patch("flexstack.facilities.local_dynamic_map.ldm_service.LDMService.add_provider_data")
    @patch("time.monotonic")
    def test_add_provider_data(self, mock_monotonic, mock_parent_add_provider_data):
        mock_monotonic.return_value = 1000.0
        mock_parent_add_provider_data.return_value = 1
        self.ldm_service.attend_subscriptions = MagicMock()
        test_dict = {"a": 1, "b": 2}

        provider_data_request = AddDataProviderReq(
            application_id=1,
            timestamp=MagicMock(),
            location=MagicMock(),
            data_object=test_dict,
            time_validity=MagicMock(),)
        self.ldm_service.add_provider_data(provider_data_request)
        mock_parent_add_provider_data.assert_called_once_with(provider_data_request)
        self.ldm_service.attend_subscriptions.assert_called_once()
