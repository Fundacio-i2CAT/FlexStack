from __future__ import annotations
import time
import threading
from .ldm_maintenance import LDMMaintenance
from .ldm_classes import AddDataProviderReq, Location
from .database import DataBase

TRASH_COLLECTION_INTERVAL = 1.0  # seconds


class LDMMaintenanceReactive(LDMMaintenance):
    """
    Class inheritence from class specified in the ETSI ETSI EN 302 895 V1.1.1 (2014-09).

    In this implementation a reactive apporach is taken to the maintenance of the LDM. This means that the LDM will
    delete data that is not within the area of maintenance only when new data is added. This is done by overriding the
    add_provider_data method.

    """

    def __init__(self, area_of_maintenance: Location, data_base: DataBase) -> None:
        super().__init__(area_of_maintenance, data_base)
        self.last_trash_collection_time: float = time.monotonic()
        self.lock = threading.Lock()

    def add_provider_data(self, data: AddDataProviderReq) -> int | None:
        index = super().add_provider_data(data)
        self.logging.debug("Adding provider data; %s", data.data_object)
        if time.monotonic() - self.last_trash_collection_time >= TRASH_COLLECTION_INTERVAL:
            self.collect_trash()
            with self.lock:
                self.last_trash_collection_time = time.monotonic()
        return index
