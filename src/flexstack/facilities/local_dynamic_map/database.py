from __future__ import annotations
from .ldm_classes import RequestDataObjectsReq


class DataBase:
    """
    Generic DataBase class that will be implemented by various classes (i.e. TinyDBDatabase, ListDatabase).
    """

    def delete(self) -> bool:
        """
        Delete database, returns a boolean stating if deletion has been succesful.
        """
        raise NotImplementedError("Delete Method not overriden")

    def search(self, data_request: RequestDataObjectsReq) -> tuple:
        """
        Search for data with a Filter (from ETSI ETSI EN 302 895 V1.1.1 (2014-09).

        Parameters
        ----------
        data_request : RequestDataObjectsReq
            Data request to be used for the search.
        """
        raise NotImplementedError("Search Method not overriden")

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
        raise NotImplementedError("Insert Method not overriden")

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
        raise NotImplementedError("Get Method not overriden")

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
        raise NotImplementedError("Update Method not overriden")

    def remove(self, data_object: dict) -> bool:
        """
        Remove data from the database with a given index, returns a boolean stating if removal has been succesful.

        Parameters
        ----------
        data_object : int
            Index of the data to be removed.

        Returns
        -------
        bool
            Indicates whether removal was successful.
        """
        raise NotImplementedError("Remove Method not overriden")

    def all(self) -> tuple:
        """
        Get all data from the database.

        Returns
        -------
        list
            List with all data stored in the database
        """
        raise NotImplementedError("All Method not overriden")

    def exists(self, field_name: str, data_object_id: int) -> bool:
        """
        Check if specific field exists.

        Key word field_name = "dataObjectID" will search for the "data_object_id" (index) in the database.

        Parameters
        ----------
        field_name : str
            Name of field to be checked

        Returns
        -------
        bool
            Indicates whether field exists
        """
        raise NotImplementedError("Exists Method not overriden")
