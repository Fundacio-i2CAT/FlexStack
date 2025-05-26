from __future__ import annotations
import time
import json
import logging

from .ldm_classes import Location, RequestDataObjectsReq, TimestampIts, AddDataProviderReq
from .ldm_constants import (
    MAINTENANCE_AREA_MAX_ALTITUDE_DIFFERENCE,
    NEW_DATA_RECIEVED,
    NO_NEW_DATA_RECIEVED,
)
from .database import DataBase
from .ldm_classes import Utils


class LDMMaintenance:
    """
    Class specified in the ETSI EN 302 895 V1.1.1 (2014-09). Section 5.3.2
    The LDM Maintenance component (see clause 5.3.2) is responsible for storing and maintaining the
    data and its integrity as well as for the garbage collection of persistent data held within the LDM.

    Attributes
    ----------
    TODO: Add attributes
    """

    def __init__(self, area_of_maintenance: Location, data_base: DataBase) -> None:
        self.logging = logging.getLogger("local_dynamic_map")

        self.data_containers = data_base
        self.area_of_maintenance = area_of_maintenance
        self.new_data_recieved_flag = NO_NEW_DATA_RECIEVED

    def run(self) -> None:
        """
        Method specified in the ETSI 302 895 V1.1.1 (2014-09). Section 5.3.2.
        This method is called when the thread is started and has to mantain the data containers
        according to the timestamp, location and area of maintenance.

        Parameters
        ----------
        None
        """
        self.logging.info("LDMMaintenance trash collection initiated")

        while True:
            time.sleep(1)
            self.collect_trash()

    def delete_all_database(self) -> None:
        """
        Method created in order to delete all the data containers.

        Parameters
        ----------
        None
        """
        self.data_containers.delete()

    def add_provider_data(self, data: AddDataProviderReq) -> int:
        """
        Method created in order to add data into the data containers.

        Parameters
        ----------
        data : dict
        """
        try:
            doc_id = self.data_containers.insert(data.to_dict())
            self.new_data_recieved_flag = NEW_DATA_RECIEVED
        except (KeyError, json.decoder.JSONDecodeError) as e:
            print(f"Error adding data container: {str(e)}")
            doc_id = None

        return doc_id

    def get_provider_data(self, data_object_id) -> dict:
        """
        Method created in order to get data from the data containers.

        Parameters
        ----------
        data_object_id : int
        """
        try:
            provider_data = self.data_containers.get(doc_id=data_object_id)
        except (KeyError, json.decoder.JSONDecodeError) as e:
            print(f"Error getting data container: {str(e)}")
            provider_data = None

        return provider_data

    def update_provider_data(self, data_object_id, data_object) -> None:
        """
        Method created in order to update data from the data containers.

        Parameters
        ----------
        data_object_id : int
        data_object : dict
        """
        try:
            self.data_containers.update(
                data_object,
                doc_ids=[
                    data_object_id,
                ],
            )
            self.logging.debug("Data container updated: %s", data_object_id)
        except (KeyError, json.decoder.JSONDecodeError) as e:
            print(f"Error updating data container: {str(e)}")

    def del_provider_data(self, data_object: dict = None) -> None:
        """
        Method created in order to delete data from the data containers.

        Parameters
        ----------
        id : int
        """
        try:
            self.data_containers.remove(data_object)
        except (ValueError, KeyError, json.decoder.JSONDecodeError) as e:
            print(f"Error deleting data container: {str(e)}, data_containers {len(self.data_containers.all())}")

    def get_all_data_containers(self) -> list[dict]:
        """
        Method created in order to get all the data containers.

        Parameters
        ----------
        None
        """
        try:
            data_containers = self.data_containers.all()
        except (KeyError, json.decoder.JSONDecodeError) as e:
            print(f"Error getting all data containers: {str(e)}")
            data_containers = []

        return data_containers

    def search_data_containers(self, data_request: RequestDataObjectsReq) -> list[dict]:
        """
        Method created in order to search data from the data containers.
        It redirects the search of the data containers to the database.

        Parameters
        ----------
        filter : Filter

        Returns
        -------
        search_result : list[dict]
        """

        search_result = self.data_containers.search(data_request)

        return search_result

    def check_and_delete_time_validity(self) -> list[int]:
        """
        Method according to ETSI EN 302 895 V1.1.1 (2014-09). Section 5.3.2

        Method checks if the data is still valid according to the time validity period.

        Parameters
        ----------
        None
        """

        time_invalidity_data_containers = []
        try:
            for data_container in self.get_all_data_containers():
                if TimestampIts.initialize_with_timestamp_its(data_container["timeValidity"] + data_container["timestamp"]) < TimestampIts():
                    self.del_provider_data(data_container)
                    time_invalidity_data_containers.append(data_container)
        except json.decoder.JSONDecodeError as e:
            print(f"Error checking time validity: {str(e)}")
        return time_invalidity_data_containers

    def check_and_delete_area_of_maintenance(self) -> list[int]:
        """
        Method according to ETSI EN 302 895 V1.1.1 (2014-09). Section 5.3.2

        Method checks if the data is still valid according to the area of maintenance.

        Parameters
        ----------
        None
        """
        area_maintenance_invalidity_data_containers = []
        for data_container in self.get_all_data_containers():
            distance_between_points_and_maintenance_area = Utils.euclidian_distance(
                (
                    data_container["location"]["referencePosition"]["latitude"],
                    data_container["location"]["referencePosition"]["longitude"],
                ),
                (
                    self.area_of_maintenance.reference_position.latitude,
                    self.area_of_maintenance.reference_position.longitude,
                ),
            )
            if (
                self.area_of_maintenance.reference_area.relevance_area.relevance_distance.compare_with_int(
                    distance_between_points_and_maintenance_area
                )
                and (
                    data_container["location"]["referencePosition"]["altitude"]["altitudeValue"]
                    - self.area_of_maintenance.reference_position.altitude.altitude_value
                )
                ^ 2
                < MAINTENANCE_AREA_MAX_ALTITUDE_DIFFERENCE
            ):
                self.del_provider_data(data_container)
                area_maintenance_invalidity_data_containers.append(data_container)

        return area_maintenance_invalidity_data_containers

    def collect_trash(self) -> None:
        """
        Method according to ETSI EN 302 895 V1.1.1 (2014-09). Section 5.3.2

        Method should be called periodically to delete expired data from the data containers.
        Expired data consists of:
        - Data that doesn't meet its time validity (time validity period): Clause 6.2.3
        - Data that is not within the LDM Area of Maintance

        Parameters
        ----------
        None
        """
        initial_data_containers = len(self.get_all_data_containers())
        self.check_and_delete_time_validity()
        # Check data is within the LDM Area of Maintenance
        self.check_and_delete_area_of_maintenance()

        self.logging.debug(
            "Deleted %s/%s data containers in trash collection",
            initial_data_containers - len(self.get_all_data_containers()),
            initial_data_containers
        )

    def update_area_of_maintenance(self, area_of_maintenance) -> None:
        """
        Method according to ETSI EN 302 895 V1.1.1 (2014-09). Section 5.3.2

        Method should be called periodically to update the area of maintance.

        Parameters
        ----------
        area_of_maintenance : list[int, int, int]
        """
        self.area_of_maintenance = area_of_maintenance

    def check_new_data_recieved(self) -> int:
        """
        Method used to verify if new data has been recieved. Uses threading locks to avoid any type of overwritting.

        Parameters
        ----------
        None
        """
        if self.new_data_recieved_flag == NEW_DATA_RECIEVED:
            self.new_data_recieved_flag = NO_NEW_DATA_RECIEVED
            return NEW_DATA_RECIEVED
        return NO_NEW_DATA_RECIEVED
