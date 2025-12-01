import unittest
import threading
from flexstack.facilities.local_dynamic_map.dictionary_database import DictionaryDataBase


class TestDictionaryDatabaseConcurrency(unittest.TestCase):
    def setUp(self):
        self.db = DictionaryDataBase()

    def test_concurrent_inserts(self):
        def insert_data(thread_id):
            for i in range(100):
                self.db.insert({"thread": thread_id, "value": i})

        threads = []
        for i in range(10):
            t = threading.Thread(target=insert_data, args=(i,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        self.assertEqual(len(self.db.all()), 1000)
        # Check if IDs are unique and sequential (0 to 999)
        self.assertEqual(sorted(self.db.database.keys()), list(range(1000)))

    def test_concurrent_read_write(self):
        def write_data():
            for i in range(100):
                self.db.insert({"value": i})

        def read_data():
            for _ in range(100):
                _ = self.db.all()

        t1 = threading.Thread(target=write_data)
        t2 = threading.Thread(target=read_data)

        t1.start()
        t2.start()

        t1.join()
        t2.join()

        self.assertEqual(len(self.db.all()), 100)


if __name__ == '__main__':
    unittest.main()
