from __future__ import annotations
from threading import RLock
from typing import Any

from .database import DataBase
from .ldm_classes import Filter, RequestDataObjectsReq, Utils
from .ldm_constants import OPERATOR_MAPPING


class DictionaryDataBase(DataBase):
    """
    Class inherting from DataBase.

    This class is used to store data in a dictionary. Its a simple implemenation that can be used for testing or when
    code runs in environments where creating a database (file) is not possible.
    """

    def __init__(self):
        """
        Initialize the database.
        """
        self.database = {}
        self._lock = RLock()
        self._next_id = 0

    def delete(self) -> bool:
        """
        Delete database with a given name, returns a boolean stating if deletion has been succesful.

        Parameters
        ----------
        database_name : str
            Name of the database to be deleted.
        """
        with self._lock:
            self.database = {}
            self._next_id = 0
        return True

    def _get_nested(self, data: dict, path: str) -> Any:
        data = data["dataObject"]
        keys = path.split(".")

        for key in keys:
            data = data[key]
        return data

    def _create_query_search(self, query_with_attribute, operator, ref_value):
        if operator in OPERATOR_MAPPING:
            return OPERATOR_MAPPING[operator](query_with_attribute, ref_value)
        raise ValueError(f"Invalid operator: {operator}")

    def _filter_data(self, data_filter: Filter, database: list[dict]) -> tuple[dict, ...]:
        list_of_data = []
        if data_filter.filter_statement_2 is not None:
            if str(data_filter.logical_operator) == "and":
                for data in database:
                    if self._create_query_search(
                        self._get_nested(
                            data, str(data_filter.filter_statement_1.attribute)),
                        str(data_filter.filter_statement_1.operator),
                        data_filter.filter_statement_1.ref_value,
                    ) & self._create_query_search(
                        self._get_nested(
                            data, str(data_filter.filter_statement_2.attribute)),
                        str(data_filter.filter_statement_2.operator),
                        data_filter.filter_statement_2.ref_value,
                    ):
                        list_of_data.append(data)
            else:
                for data in database:
                    if self._create_query_search(
                        self._get_nested(
                            data, str(data_filter.filter_statement_1.attribute)),
                        str(data_filter.filter_statement_1.operator),
                        data_filter.filter_statement_1.ref_value,
                    ) | self._create_query_search(
                        self._get_nested(
                            data, str(data_filter.filter_statement_2.attribute)),
                        str(data_filter.filter_statement_2.operator),
                        data_filter.filter_statement_2.ref_value,
                    ):
                        list_of_data.append(data)
        else:
            for data in database:
                if self._create_query_search(
                    self._get_nested(
                        data, str(data_filter.filter_statement_1.attribute)),
                    str(data_filter.filter_statement_1.operator),
                    data_filter.filter_statement_1.ref_value,
                ):
                    list_of_data.append(data)
        return tuple(list_of_data)

    def search(self, data_request: RequestDataObjectsReq) -> tuple[dict, ...]:
        """
        Search for data with a Filter (from ETSI ETSI EN 302 895 V1.1.1 (2014-09).

        Parameters
        ----------
        data_request : RequestDataObjectsReq
            Data request to be used for the search.

        Returns
        -------
        tuple
            Search result.
        """
        with self._lock:
            if data_request.filter is None:
                return RequestDataObjectsReq.filter_out_by_data_object_type(self.all(), data_request.data_object_type)
            try:
                return self._filter_data(
                    data_request.filter,
                    RequestDataObjectsReq.filter_out_by_data_object_type(
                        tuple(self.all()), data_request.data_object_type),
                )
            except KeyError as e:
                print(f"[ListDatabase] KeyError searching data: {str(e)}")
                return tuple()
            except TypeError as e:
                print(f"[ListDatabase] TypeError searching data: {str(e)}")
                return tuple()

    def insert(self, data: dict) -> int:
        """
        Insert data into the database, returns the index of the inserted data.

        Parameters
        ----------
        data : dict
            Data to be inserted into the database.
        """
        with self._lock:
            index = self._next_id
            self.database[index] = data
            self._next_id += 1
            return index

    def get(self, index: int) -> dict | None:
        """
        Get data from the database with a given index.

        Parameters
        ----------
        index : int
            Index of the data to be retrieved.
        """
        with self._lock:
            try:
                return self.database[index]
            except KeyError:
                return None

    def update(self, data: dict, index: int) -> bool:
        """
        Update data in the database with a given index, returns a boolean stating if update has been succesful.

        Parameters
        ----------
        data : dict
            Data to be updated in the database.
        index : int
            Index of the data to be updated.
        """
        with self._lock:
            self.database[index] = data
            return True

    def remove(self, data_object: dict) -> bool:
        """
        Remove data from the database with a given index, returns a boolean stating if removal has been succesful.

        Parameters
        ----------
        index : int
            Index of the data to be removed.
        """
        with self._lock:
            for key, value in self.database.items():
                if value == data_object:
                    del self.database[key]
                    return True
            return False

    def all(self) -> tuple:
        """
        Get all data from the database.

        Returns
        -------
        list[dict]
            All data from the database.
        """
        with self._lock:
            return tuple(self.database.values())

    def exists(self, field_name: str, data_object_id: int) -> bool:
        """
        Check if specific field exists

        Parameters
        ----------
        field_name : str
            Name of field to be checked
        Returns
        -------
        bool
            Indicates whether field exists
        """
        with self._lock:
            if field_name == "dataObjectID":
                return data_object_id in self.database
            for data in self.database.values():
                if Utils.check_field(data, field_name):
                    return True
            return False
