import unittest
from unittest.mock import MagicMock, patch

from flexstack.facilities.local_dynamic_map.ldm_classes import AddDataProviderReq, ComparisonOperators, Filter, FilterStatement, Location, RequestDataObjectsReq, TimeValidity, TimestampIts
from flexstack.facilities.local_dynamic_map.ldm_constants import CAM
from flexstack.facilities.local_dynamic_map.ldm_maintenance_thread import (
    LDMMaintenanceThread,
)

TEST_DATA = {"key": "value"}


class TestLDMMaintenanceThread(unittest.TestCase):
    @patch("threading.Lock")
    @patch("threading.Thread")
    def setUp(self, mock_thread: MagicMock, mock_lock: MagicMock):
        self.threading_thread = MagicMock()
        self.threading_thread.start = MagicMock(return_value=None)
        mock_thread.return_value = self.threading_thread
        self.mock_thread = mock_thread
        self.mock_lock = mock_lock

        self.location = MagicMock()
        self.database = MagicMock()
        self.ldm_maintenance_thread = LDMMaintenanceThread(
            self.location, self.database
        )

    def test__init__(self):
        self.threading_thread.start.assert_called_once()
        self.mock_lock.assert_called()

    @patch("builtins.super")
    def test_add_data_provider(self, mock_super):
        mock_super().add_provider_data = MagicMock(return_value=1)
        add_data_provider_request = AddDataProviderReq(
            application_id=1,
            timestamp=TimestampIts(1000),
            location=Location.initializer(),
            data_object=TEST_DATA,
            time_validity=TimeValidity(1000),
        )
        self.assertEqual(self.ldm_maintenance_thread.add_provider_data(
            add_data_provider_request), 1)

    @patch("builtins.super")
    def test_get_provider_data(self, mock_super):
        mock_super().get_provider_data = MagicMock(return_value=1)
        self.assertEqual(self.ldm_maintenance_thread.get_provider_data(1), 1)

    @patch("builtins.super")
    def test_update_provider_data(self, mock_super):
        mock_super().update_provider_data = MagicMock(return_value=1)
        self.ldm_maintenance_thread.update_provider_data(1, TEST_DATA)
        mock_super().update_provider_data.assert_called_once_with(1, TEST_DATA)

    @patch("builtins.super")
    def test_del_provider_data(self, mock_super):
        mock_super().del_provider_data = MagicMock(return_value=1)
        self.ldm_maintenance_thread.del_provider_data(TEST_DATA)
        mock_super().del_provider_data.assert_called_once_with(TEST_DATA)

    @patch("builtins.super")
    def test_get_all_data_containers(self, mock_super):
        mock_super().get_all_data_containers = MagicMock(return_value=1)
        self.assertEqual(
            self.ldm_maintenance_thread.get_all_data_containers(), 1)

    @patch("builtins.super")
    def test_search_data_contaier(self, mock_super):
        mock_super().search_data_containers = MagicMock(return_value=1)
        request_data_objects_req = RequestDataObjectsReq(
            application_id=CAM,
            data_object_type=(CAM,),
            priority=1,
            filter=Filter(FilterStatement(
                "cam.generationDeltaTime", ComparisonOperators.EQUAL, 2)),
            order=(),
        )
        self.assertEqual(self.ldm_maintenance_thread.search_data_containers(
            request_data_objects_req), 1)

    @patch("builtins.super")
    def test_check_data_container(self, mock_super):
        mock_super().check_new_data_recieved = MagicMock(return_value=1)
        self.assertEqual(
            self.ldm_maintenance_thread.check_new_data_recieved(), 1)
