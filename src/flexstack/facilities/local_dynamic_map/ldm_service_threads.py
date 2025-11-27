from __future__ import annotations
import threading

from .ldm_maintenance import LDMMaintenance
from .ldm_service import LDMService


class LDMServiceThreads(LDMService):
    """
    Class that inherits from LDMService (class specified in the ETSI ETSI EN 302 895 V1.1.1 (2014-09).

    Class that is used to run the service of the LDM in a seperate thread. This is done by running the
    subscription_service function in a seperate thread.
    """

    def __init__(
        self,
        ldm_maintenance: LDMMaintenance,
    ) -> None:
        super().__init__(ldm_maintenance)
        self.data_containers_lock = threading.Lock()
        self.stop_event = threading.Event()

        self.subscriptions_service_thread = threading.Thread(
            target=super().subscriptions_service, daemon=True
        )
        self.subscriptions_service_thread.start()

    def subscriptions_service(self) -> None:
        while not self.stop_event.is_set():
            self.attend_subscriptions()
