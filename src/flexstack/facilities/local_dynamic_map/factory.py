from __future__ import annotations
from collections.abc import Callable
import logging

from .ldm_classes import (
    GeometricArea,
    Location,
    SubscribeDataobjectsReq,
    SubscribeDataObjectsResp,
    RequestDataObjectsResp,
    RegisterDataConsumerReq,
    RegisterDataConsumerResp,
    Filter,
    FilterStatement,
    ComparisonOperators,
    AccessPermission,
)

from .ldm_maintenance_reactive import LDMMaintenanceReactive
from .ldm_maintenance_thread import LDMMaintenanceThread

from .ldm_service_reactive import LDMServiceReactive
from .ldm_service_threads import LDMServiceThreads

from .dictionary_database import DictionaryDataBase
from .tinydb_database import TinyDB

from .ldm_facility import LDMFacility

from .exceptions import LDMMaintenanceKeyError, LDMServiceKeyError, LDMDatabaseKeyError


class LDMFactory:
    """Factory class to create a Local Dynamic Map Facility."""

    def __init__(self) -> None:
        self.ldm = None

    def create_ldm(
        self,
        ldm_location: Location,
        ldm_maintenance_type: str = "Reactive",
        ldm_service_type: str = "Reactive",
        ldm_database_type: str = "Dictionary",
    ) -> LDMFacility:
        """
        Factory function to create a Local Dynamic Map Facility.

        Parameters
        ----------
        ldm_location : Location
            Location object to be used by the LDM Facility.
        ldm_maintenance_type : str, optional
            Type of LDM Maintenance to be used. Defaults to "Reactive".
        ldm_service_type : str, optional
            Type of LDM Service to be used. Defaults to "Reactive".
        ldm_database_type : str, optional
            Type of LDM Database to be used. Defaults to "Dictionary".
        """

        logs = logging.getLogger("local_dynamic_map")

        if ldm_database_type == "Dictionary":
            ldm_database = DictionaryDataBase()
            logs.info('LDM Database "Dictionary" configured.')
        elif ldm_database_type == "TinyDB":
            ldm_database = TinyDB()
            logs.info('LDM Database "TinyDB" configured.')
        else:
            logs.error(
                'LDM Database must be either "Dictionary" or "TinyDB". %s is an invalid type for LDM Database.',
                ldm_database_type,
            )
            raise LDMDatabaseKeyError(
                f'LDM Database must be either "Dictionary" or "TinyDB". {ldm_database_type} is an invalid type.'
            )

        if ldm_maintenance_type == "Reactive":
            ldm_maintenance = LDMMaintenanceReactive(ldm_location, ldm_database)
            logs.info('LDM Maintenance "Reactive" configured.')
        elif ldm_maintenance_type == "Thread":
            ldm_maintenance = LDMMaintenanceThread(ldm_location, ldm_database)
            logs.info('LDM Maintenance "Thread" configured.')
        else:
            logs.error(
                'LDM Maintenance must be either "Reactive" or "Thread". %s is an invalid type for LDM Maintenance.',
                ldm_maintenance_type,
            )
            raise LDMMaintenanceKeyError(
                f'LDM Maintenance must be either "Reactive" or "Thread". {ldm_maintenance_type} is an invalid type.'
            )

        if ldm_service_type == "Reactive":
            ldm_service = LDMServiceReactive(ldm_maintenance)
            logs.info('LDM Service "Reactive" configured.')
        elif ldm_service_type == "Thread":
            ldm_service = LDMServiceThreads(ldm_maintenance)
            logs.info('LDM Service "Thread" configured.')
        else:
            logs.error(
                'LDM Service must be either "Reactive" or "Thread". %s is an invalid type for LDM Service.',
                ldm_service_type,
            )
            raise LDMServiceKeyError(
                f'LDM Service must be either "Reactive" or "Thread". {ldm_service_type} is an invalid type for LDM Service.'
            )

        ldm_facility = LDMFacility(ldm_maintenance, ldm_service)
        logs.info(
            'LDM Facility configured with: LDM Maintenance: "%s", LDM Service: "%s", LDM Database: "%s".',
            ldm_maintenance_type,
            ldm_service_type,
            ldm_database_type,
        )
        self.ldm = ldm_facility
        return ldm_facility

    def subscribe_to_ldm(
        self,
        own_station_id: int,
        area_of_interest: GeometricArea,
        callback_function: Callable[[RequestDataObjectsResp], None],
    ) -> None:
        """
        Method to subscribe to the LDM Facility.

        Parameters
        ----------
        subscription_request : SubscribeDataobjectsReq
            Subscription request object.
        callback_function : Callable
            Callback function to be called when new data is available.

        Returns
        -------
        int
            Subscription ID.
        """
        if self.ldm is None:
            raise Exception("LDM Facility not initialized. Please create an LDM Facility first.")

        register_data_consumer_reponse: RegisterDataConsumerResp = self.ldm.if_ldm_4.register_data_consumer(
            RegisterDataConsumerReq(
                application_id=AccessPermission.CAM,
                access_permisions=(AccessPermission.CAM, AccessPermission.VAM),
                area_of_interest=area_of_interest,
            )
        )
        if register_data_consumer_reponse.result == 2:
            raise Exception(f"Failed to register data consumer: {str(register_data_consumer_reponse)}")

        subscribe_data_consumer_response: SubscribeDataObjectsResp = self.ldm.if_ldm_4.subscribe_data_consumer(
            SubscribeDataobjectsReq(
                application_id=AccessPermission.CAM,
                data_object_type=(AccessPermission.CAM, AccessPermission.VAM),
                filter=Filter(FilterStatement("header.stationId", ComparisonOperators.NOT_EQUAL, own_station_id)),
            ),
            callback_function,
        )
        if subscribe_data_consumer_response.result != 0:
            raise Exception(f"Failed to subscribe to data objects: {str(subscribe_data_consumer_response.result)}")
