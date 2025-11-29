import unittest
from unittest.mock import MagicMock

from flexstack.facilities.local_dynamic_map.database import DataBase

EXAMPLE_DATA = {"key": "value"}


class TestDatabase(unittest.TestCase):

    def test_delete(self):
        database = DataBase()
        self.assertRaises(NotImplementedError, database.delete)

    def test_search(self):
        database = DataBase()
        self.assertRaises(NotImplementedError, database.search, data_request=MagicMock())

    def test_insert(self):
        database = DataBase()
        self.assertRaises(NotImplementedError, database.insert, data=EXAMPLE_DATA)

    def test_get(self):
        database = DataBase()
        self.assertRaises(NotImplementedError, database.get, index=0)

    def test_update(self):
        database = DataBase()
        self.assertRaises(NotImplementedError, database.update, data=EXAMPLE_DATA, index=0)

    def test_remove(self):
        database = DataBase()
        self.assertRaises(NotImplementedError, database.remove, data_object=EXAMPLE_DATA)

    def test_all(self):
        database = DataBase()
        self.assertRaises(NotImplementedError, database.all)

    def test_exists(self):
        database = DataBase()
        self.assertRaises(NotImplementedError, database.exists, field_name="test_field_name", data_object_id=0)


if __name__ == "__main__":
    unittest.main()
