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

    @patch("flexstack.facilities.local_dynamic_map.ldm_maintenance.LDMMaintenance.add_provider_data")
    def test_add_data_provider(self, mock_parent_add_provider_data):
        mock_parent_add_provider_data.return_value = 1
        add_data_provider_request = AddDataProviderReq(
            application_id=1,
            timestamp=TimestampIts(1000),
            location=Location.initializer(),
            data_object=TEST_DATA,
            time_validity=TimeValidity(1000),
        )
        self.assertEqual(self.ldm_maintenance_thread.add_provider_data(
            add_data_provider_request), 1)

    @patch("flexstack.facilities.local_dynamic_map.ldm_maintenance.LDMMaintenance.get_provider_data")
    def test_get_provider_data(self, mock_parent_get_provider_data):
        mock_parent_get_provider_data.return_value = 1
        self.assertEqual(self.ldm_maintenance_thread.get_provider_data(1), 1)

    @patch("flexstack.facilities.local_dynamic_map.ldm_maintenance.LDMMaintenance.update_provider_data")
    def test_update_provider_data(self, mock_parent_update_provider_data):
        mock_parent_update_provider_data.return_value = 1
        self.ldm_maintenance_thread.update_provider_data(1, TEST_DATA)
        mock_parent_update_provider_data.assert_called_once_with(1, TEST_DATA)

    @patch("flexstack.facilities.local_dynamic_map.ldm_maintenance.LDMMaintenance.del_provider_data")
    def test_del_provider_data(self, mock_parent_del_provider_data):
        mock_parent_del_provider_data.return_value = 1
        self.ldm_maintenance_thread.del_provider_data(TEST_DATA)
        mock_parent_del_provider_data.assert_called_once_with(TEST_DATA)

    @patch("flexstack.facilities.local_dynamic_map.ldm_maintenance.LDMMaintenance.get_all_data_containers")
    def test_get_all_data_containers(self, mock_parent_get_all_data_containers):
        mock_parent_get_all_data_containers.return_value = 1
        self.assertEqual(
            self.ldm_maintenance_thread.get_all_data_containers(), 1)

    @patch("flexstack.facilities.local_dynamic_map.ldm_maintenance.LDMMaintenance.search_data_containers")
    def test_search_data_contaier(self, mock_parent_search_data_containers):
        mock_parent_search_data_containers.return_value = 1
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

    @patch("flexstack.facilities.local_dynamic_map.ldm_maintenance.LDMMaintenance.check_new_data_recieved")
    def test_check_data_container(self, mock_parent_check_new_data_recieved):
        mock_parent_check_new_data_recieved.return_value = 1
        self.assertEqual(
            self.ldm_maintenance_thread.check_new_data_recieved(), 1)
