from __future__ import annotations
import threading
import time

from .ldm_classes import AddDataProviderReq, Location, RequestDataObjectsReq
from .database import DataBase
from .ldm_maintenance import LDMMaintenance


class LDMMaintenanceThread(LDMMaintenance):
    """
    Class that inherits from LDMMaintenance (class specified in the ETSI ETSI EN 302 895 V1.1.1 (2014-09).

    This class is used to run the maintenance of the LDM in a seperate thread. This is done to ensure that the LDM
    is always up to date and that the data is always valid. This is done by overriding the add_provider_data method.
    """

    def __init__(
        self,
        area_of_maintenance: Location,
        data_base: DataBase,
        stop_event: threading.Event,
    ) -> None:
        super().__init__(area_of_maintenance, data_base)
        self.data_containers_lock = threading.Lock()
        self.stop_event = stop_event
        self.ldm_maintenance_thread = threading.Thread(
            target=self.run, daemon=True)
        self.ldm_maintenance_thread.start()

    def run(self) -> None:
        while not self.stop_event.is_set():
            time.sleep(1)
            self.collect_trash()

    def add_provider_data(self, data: AddDataProviderReq) -> int | None:
        with self.data_containers_lock:
            doc_id = super().add_provider_data(data)

        return doc_id

    def get_provider_data(self, data_object_id: int) -> dict | None:
        with self.data_containers_lock:
            provider_data = super().get_provider_data(data_object_id)

        return provider_data

    def update_provider_data(self, data_object_id: int, data_object: dict) -> None:
        with self.data_containers_lock:
            super().update_provider_data(data_object_id, data_object)

    def del_provider_data(self, data_object: dict) -> None:
        with self.data_containers_lock:
            super().del_provider_data(data_object)

    def get_all_data_containers(self) -> tuple[dict, ...]:
        with self.data_containers_lock:
            data_containers = super().get_all_data_containers()

        return data_containers

    def search_data_containers(self, data_request: RequestDataObjectsReq) -> tuple[dict, ...]:
        with self.data_containers_lock:
            search_result = super().search_data_containers(data_request)

        return search_result

    def check_new_data_recieved(self) -> int:
        with self.data_containers_lock:
            state = super().check_new_data_recieved()

        return state
