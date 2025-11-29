import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from tinydb.table import Document

from flexstack.facilities.local_dynamic_map.tinydb_database import TinyDB

_SAMPLE_RECORD = {
    "applicationId": 36,
    "dataObject": {
        "cam": {
            "camParameters": {
                "basicContainer": {
                    "stationType": 0,
                    "referencePosition": {
                        "latitude": 900000001,
                        "longitude": 1800000001,
                    },
                }
            }
        }
    },
    "timeValidity": 1000,
}


class TestTinyDB(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.database_path = self.temp_dir.name
        self.database_name = "test_database.json"

        tinydb_ctor_patcher = patch(
            "flexstack.facilities.local_dynamic_map.tinydb_database.tinydb.TinyDB"
        )
        self.addCleanup(tinydb_ctor_patcher.stop)
        self.mock_tinydb_ctor = tinydb_ctor_patcher.start()

        self.mock_database = MagicMock()
        self.mock_tinydb_ctor.return_value = self.mock_database

        self.tinydb = TinyDB(self.database_name, self.database_path)

    def test__init__(self):
        self.assertEqual(self.tinydb.database_name, self.database_name)
        self.assertEqual(self.tinydb.database_path,
                         os.path.abspath(self.database_path))
        self.mock_tinydb_ctor.assert_called_once_with(
            os.path.join(os.path.abspath(
                self.database_path), self.database_name)
        )

    @patch("flexstack.facilities.local_dynamic_map.tinydb_database.os.remove")
    @patch("flexstack.facilities.local_dynamic_map.tinydb_database.print")
    def test_delete(self, mock_print, mock_remove):
        mock_remove.return_value = True
        self.mock_database.close = MagicMock()

        self.assertTrue(self.tinydb.delete())
        self.mock_database.close.assert_called_once()
        self.mock_tinydb_ctor.assert_called_with(
            os.path.join(os.path.abspath(
                self.database_path), self.database_name)
        )
        mock_print.assert_not_called()

    @patch("flexstack.facilities.local_dynamic_map.tinydb_database.os.remove")
    @patch("flexstack.facilities.local_dynamic_map.tinydb_database.print")
    def test_delete_file_not_found(self, mock_print, mock_remove):
        mock_remove.side_effect = FileNotFoundError("missing")

        self.assertFalse(self.tinydb.delete())
        mock_print.assert_called_once()

    def test_create_query_search_value_error(self):
        with self.assertRaises(ValueError):
            self.tinydb.create_query_search(MagicMock(), "invalid", 1)

    def test_insert(self):
        self.mock_database.insert.return_value = 42
        self.assertEqual(self.tinydb.insert(_SAMPLE_RECORD), 42)
        self.mock_database.insert.assert_called_once_with(_SAMPLE_RECORD)

    def test_get(self):
        self.mock_database.get.return_value = _SAMPLE_RECORD
        self.assertEqual(self.tinydb.get(1), _SAMPLE_RECORD)
        self.mock_database.get.assert_called_once_with(doc_id=1)

    def test_get_missing(self):
        self.mock_database.get.return_value = None
        self.assertIsNone(self.tinydb.get(99))

    def test_update(self):
        self.assertTrue(self.tinydb.update(_SAMPLE_RECORD, 5))
        self.mock_database.update.assert_called_once_with(
            _SAMPLE_RECORD, doc_ids=[5])

    def test_remove(self):
        stored_document = Document(_SAMPLE_RECORD, doc_id=7)
        self.mock_database.all.return_value = [stored_document]

        self.assertTrue(self.tinydb.remove(dict(stored_document)))
        self.mock_database.remove.assert_called_once_with(doc_ids=[7])

    def test_remove_not_found(self):
        self.mock_database.all.return_value = []
        self.assertFalse(self.tinydb.remove(_SAMPLE_RECORD))
        self.mock_database.remove.assert_not_called()

    def test_all(self):
        stored_document = Document(_SAMPLE_RECORD, doc_id=1)
        self.mock_database.all.return_value = [stored_document]
        self.assertEqual(self.tinydb.all(), (dict(stored_document),))

    def test_search_without_filter(self):
        stored_document = Document(_SAMPLE_RECORD, doc_id=1)
        self.mock_database.all.return_value = [stored_document]

        request = MagicMock()
        request.filter = None
        request.data_object_type = (2,)

        self.assertEqual(self.tinydb.search(request), (dict(stored_document),))

    def test_exists_by_id(self):
        self.mock_database.contains.return_value = True
        self.assertTrue(self.tinydb.exists("dataObjectID", 10))
        self.mock_database.contains.assert_called_once_with(doc_id=10)

    def test_exists_nested_field(self):
        stored_document = Document(_SAMPLE_RECORD, doc_id=1)
        self.mock_database.get.return_value = stored_document
        self.assertTrue(self.tinydb.exists("dataObject.cam", 1))

    def test_exists_nested_field_not_found(self):
        stored_document = Document({}, doc_id=1)
        self.mock_database.get.return_value = stored_document
        self.assertFalse(self.tinydb.exists("dataObject.cam", 1))
