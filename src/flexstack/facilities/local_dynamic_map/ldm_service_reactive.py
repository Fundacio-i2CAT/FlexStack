from __future__ import annotations
import time
import threading
from .ldm_service import LDMService
from .ldm_classes import AddDataProviderReq
from .ldm_maintenance import LDMMaintenance

ATTEND_SUBSCRIPTIONS_INTERVAL = 0.5  # seconds


class LDMServiceReactive(LDMService):
    """
    Class that inherits from LDMService (class specified in the ETSI ETSI EN 302 895 V1.1.1 (2014-09).

    This class is used to run the service of the LDM in a reactive manner. This is done by attending subscriptions
    only when new data is recieved. This is done by overriding the add_provider_data method.
    """

    def __init__(self, ldm_maintenance: LDMMaintenance) -> None:
        super().__init__(ldm_maintenance)
        self.last_subscription_time: float = time.monotonic()
        self.lock = threading.Lock()

    def add_provider_data(self, data: AddDataProviderReq) -> int | None:
        """
        (Reactive LDMService) Method to add data to the Database and attending subscriptions if necessary.

        Parameters
        ----------
        data : AddDataProviderReq
            AddDataProviderReq object that contains the data to be added to the database.

        Returns
        -------
        int | None
            Index of the added data in the database or None if the data could not be added.
        """
        index = super().add_provider_data(data)
        if time.monotonic() - self.last_subscription_time >= ATTEND_SUBSCRIPTIONS_INTERVAL:
            self.attend_subscriptions()
            with self.lock:
                self.last_subscription_time = time.monotonic()
        return index
