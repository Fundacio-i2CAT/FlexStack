import unittest
from unittest.mock import MagicMock, patch

from flexstack.facilities.local_dynamic_map.ldm_maintenance_reactive import (
    LDMMaintenanceReactive,
)


class TestLDMMaintenanceReactive(unittest.TestCase):
    @patch("time.monotonic")
    def setUp(self, mock_monotonic):
        mock_monotonic.return_value = 0.0
        self.location = MagicMock()
        self.database = MagicMock()
        self.ldm_maintenance_reactive = LDMMaintenanceReactive(
            self.location, self.database
        )

    @patch("time.monotonic")
    @patch("flexstack.facilities.local_dynamic_map.ldm_maintenance.LDMMaintenance.add_provider_data")
    def test_add_provider_data(self, mock_parent_add_provider_data, mock_monotonic):
        mock_monotonic.return_value = 1000.0
        mock_parent_add_provider_data.return_value = 1
        self.ldm_maintenance_reactive.collect_trash = MagicMock()
        test_add_data_provider_req = MagicMock()

        self.ldm_maintenance_reactive.add_provider_data(test_add_data_provider_req)
        mock_parent_add_provider_data.assert_called_once_with(test_add_data_provider_req)
        self.ldm_maintenance_reactive.collect_trash.assert_called_once()
