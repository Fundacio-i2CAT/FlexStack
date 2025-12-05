from __future__ import annotations
import os
from threading import RLock
from typing import Any

import tinydb

from .ldm_constants import OPERATOR_MAPPING
from .database import DataBase
from .ldm_classes import Filter, FilterStatement, RequestDataObjectsReq


class TinyDB(DataBase):
    """
    Class inherting from DataBase.

    This class is used to store data in a TinyDB database. TinyDB is a lightweight document oriented database.
    """

    def __init__(self, database_name: str | None = None, database_path: str | None = None):
        """
        Parameters
        ----------
        path : str
            Path to the database file.
        """
        handled_database_path = database_path
        if handled_database_path is None:
            handled_database_path = os.getcwd()
        self.database_path = os.path.abspath(handled_database_path)
        os.makedirs(self.database_path, exist_ok=True)
        self.database_name = database_name
        if self.database_name is None:
            self.database_name = "ldm_tinydb.json"
        self._database_file = os.path.join(
            self.database_path, self.database_name)
        self._lock = RLock()
        self.database = tinydb.TinyDB(self._database_file)

    def delete(self) -> bool:
        """
        Delete database with a given name, returns a boolean stating if deletion has been succesful.

        Returns
        -------
        bool
            Indicates whether deletion was successful.
        """
        with self._lock:
            self.database.close()
            success = True
            try:
                os.remove(self._database_file)
            except FileNotFoundError as e:
                print("File not found: " + str(e))
                success = False
            except OSError as e:
                print("Failed to delete database: " + str(e))
                success = False
            finally:
                self.database = tinydb.TinyDB(self._database_file)
            return success

    def _create_query_from_filter_statement(
        self, query: tinydb.Query, attribute: str
    ) -> Any:
        """
        Method to create querry from filter statement.
        i.e. "cam.camParameters.basicContainer.stationType" == 1

        Parameters
        ----------
        query: tinydb.Query
            TinyDB query object
        attribute: str
            attribute to be searched for
        """
        nested_fields = attribute.split(".")
        # Dynamically build the query
        for field in nested_fields:
            query = getattr(query, field)

        return query

    def create_query_search(
        self, query_with_attribute: tinydb.Query, operator: str, ref_value: Any
    ) -> Any:
        """
        Method to create querry from filter statement (i.e. "cam.camParameters.basicContainer.stationType" == 1)

        Parameters
        ----------

        """
        compare_function = OPERATOR_MAPPING.get(operator)
        if compare_function is not None:
            return compare_function(query_with_attribute, ref_value)

        raise ValueError(
            "Operator not supported according to ETSI TS 102 894-2 V2.2.1 (2023-10)"
        )

    def parse_filter_statement(self, query: tinydb.Query, filter: Filter) -> Any:
        """
        Method to parse filter statement to the TinyDB query language.

        Parameters
        ----------
        query : tinydb.Query
            TinyDB query object
        filter : Filter
            Filter to be parsed

        Returns
        -------
        tinydb.Query
            TinyDB query language object
        """
        return self._build_filter_condition(query, filter)

    def _build_filter_condition(
        self, query: tinydb.Query, node: Filter | FilterStatement
    ) -> Any:
        """Recursively translate Filter definitions into TinyDB query objects."""
        if isinstance(node, Filter):
            if node.filter_statement_1 is None:
                raise ValueError(
                    "Filter requires at least one filter statement")
            left_condition = self._build_filter_condition(
                query, node.filter_statement_1
            )
            if node.filter_statement_2 is None:
                return left_condition
            logical_operator = str(node.logical_operator or "and")
            right_operand = node.filter_statement_2
            if isinstance(right_operand, (list, tuple)):
                combined_condition = left_condition
                for sub_statement in right_operand:
                    sub_condition = self._build_filter_condition(
                        query, sub_statement)
                    if logical_operator == "and":
                        combined_condition = combined_condition & sub_condition
                    elif logical_operator == "or":
                        combined_condition = combined_condition | sub_condition
                    else:
                        raise ValueError(
                            f"Unsupported logical operator: {logical_operator}"
                        )
                return combined_condition
            right_condition = self._build_filter_condition(
                query, right_operand)
            if logical_operator == "and":
                return left_condition & right_condition
            if logical_operator == "or":
                return left_condition | right_condition
            raise ValueError(
                f"Unsupported logical operator: {logical_operator}")

        attribute_query = self._create_query_from_filter_statement(
            query, str(node.attribute)
        )
        return self.create_query_search(
            attribute_query, str(node.operator), node.ref_value
        )

    def search(self, data_request: RequestDataObjectsReq) -> tuple[dict, ...]:
        """
        Search for data with a Filter (from ETSI ETSI EN 302 895 V1.1.1 (2014-09).

        Parameters
        ----------
        query : Filter
            Filter to be used for the search.
        """
        with self._lock:
            if data_request.filter is None:
                documents: tuple[dict, ...] = tuple(
                    dict(document) for document in self.database.all())
                return tuple(
                    RequestDataObjectsReq.filter_out_by_data_object_type(
                        documents,
                        data_request.data_object_type,
                    )
                )
            query = self.parse_filter_statement(
                tinydb.Query(), data_request.filter
            )
            result = self.database.search(query)
            result_documents: tuple[dict, ...] = tuple(
                dict(document) for document in result)
            return tuple(
                RequestDataObjectsReq.filter_out_by_data_object_type(
                    result_documents,
                    data_request.data_object_type,
                )
            )

    def insert(self, data: dict) -> int:
        """
        Insert data into the database, returns the index of the inserted data.

        Parameters
        ----------
        data : dict
            Data to be inserted into the database.

        Returns
        -------
        int
            Index of the inserted data.
        """
        with self._lock:
            return self.database.insert(data)

    def get(self, index: int) -> dict | None:
        """
        Get data from the database with a given index.

        Parameters
        ----------
        index : int
            Index of the data to be retrieved.

        Returns
        -------
        dict | None
            Data retrieved from the database or None if not found.
        """
        with self._lock:
            document = self.database.get(doc_id=index)
            if document is None:
                return None
            return dict(document)

    def update(self, data: dict, index: int) -> bool:
        """
        Update data in the database with a given index, returns a boolean stating if update has been succesful.

        Parameters
        ----------
        data : dict
            Data to be updated in the database.
        index : int
            Index of the data to be updated.

        Returns
        -------
        bool
            Indicates whether update was successful.
        """
        with self._lock:
            self.database.update(data, doc_ids=[index])
            return True

    def remove(self, data_object: dict) -> bool:
        """
        Remove the first document matching the provided dictionary.

        Parameters
        ----------
        data_object : dict
            Data to be removed from the database.

        Returns
        -------
        bool
            Indicates whether removal was successful.
        """
        with self._lock:
            for document in self.database.all():
                if dict(document) == data_object:
                    self.database.remove(doc_ids=[document.doc_id])
                    return True
            return False

    def all(self) -> tuple[dict, ...]:
        """
        Get all data from the database.

        Returns
        -------
        list
            All data from the database.
        """
        with self._lock:
            return tuple([dict(document) for document in self.database.all()])

    def exists(self, field_name: str, data_object_id: int) -> bool:
        """
        Check if specific field exists

        Parameters
        ----------
        field_name : str
            Name of field to be checked
        data_object_id : int
            Index of the data object to be checked

        Returns
        -------
        bool
            Indicates whether field exists
        """
        with self._lock:
            if field_name == "dataObjectID":
                return self.database.contains(doc_id=data_object_id)

            to_check: list[dict]
            if data_object_id is not None:
                document = self.database.get(doc_id=data_object_id)
                to_check = [dict(document)] if document is not None else []
            else:
                to_check = [dict(document) for document in self.database.all()]

            nested_fields = field_name.split(".")
            for document in to_check:
                if self._field_exists(document, nested_fields):
                    return True
            return False

    def _field_exists(self, document: dict, path: list[str]) -> bool:
        """Return True when the dotted ``path`` exists within ``document``."""
        current: Any = document
        for part in path:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return False
        return True
