from __future__ import annotations
from .ldm_maintenance import LDMMaintenance
from .ldm_classes import AddDataProviderReq


class LDMMaintenanceReactive(LDMMaintenance):
    """
    Class inheritence from class specified in the ETSI ETSI EN 302 895 V1.1.1 (2014-09).

    In this implementation a reactive apporach is taken to the maintenance of the LDM. This means that the LDM will
    delete data that is not within the area of maintenance only when new data is added. This is done by overriding the
    add_provider_data method.

    """

    def add_provider_data(self, data: AddDataProviderReq) -> int:
        index = super().add_provider_data(data)
        self.logging.debug("Adding provider data; %s", data.data_object)
        self.collect_trash()
        return index
