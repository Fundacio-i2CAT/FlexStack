import logging

from .ldm_constants import (
    DENM,
    REGISTER_DATA_PROVIDER_RESULT_REJECTED,
    REGISTER_DATA_PROVIDER_RESULT_ACCEPTED,
    ADD_DATA_PROVIDER_RESULT_REJECTED,
    DELETE_DATA_PROVIDER_RESULT_ACCEPTED,
    DELETE_DATA_PROVIDER_RESULT_REJECTED,
    VALID_ITS_AID,
)
from .ldm_classes import (
    RegisterDataProviderReq,
    RegisterDataProviderResp,
    DeregisterDataProviderReq,
    DeregisterDataProviderResp,
    DeregisterDataProviderAck,
    AddDataProviderReq,
    AddDataProviderResp,
    UpdateDataProviderReq,
    UpdateDataProviderResp,
    UpdateDataProviderResult,
    DeleteDataProviderReq,
    DeleteDataProviderResp,
)
from .ldm_service import LDMService


class InterfaceLDM3:
    """
    Class specified is described in ETSI EN 302 895 V1.1.1 (2014-09). Section 5.4.3.
    The LDM shall provide an interface IF.LDM.3 to enable an application or facility to register as a LDM Data Provider
    and, subsequently, to send LDM Data Objects to the LDM.
    TODO: Add Revoke funciontality once security entity is implemented.

    Data providers, in our implementation, send data in form of messages (CAM, DENM, etc.).

    Attributes
    ----------
    ldm_service : LDMService
    """

    def __init__(self, ldm_service: LDMService) -> None:
        self.logging = logging.getLogger("local_dynamic_map")
        self.ldm_service = ldm_service

    def check_its_aid(self, its_application_identifier: int) -> bool:
        """
        Method specified in ETSI EN 302 895 V1.1.1 (2014-09). Section 6.2.1
        It checks the ITS-AID of the application that wants to register as a data provider.

        Parameters
        ----------
        its_application_identifier : int
            ITS-AID of the application that wants to register as a data provider
        """
        return its_application_identifier in VALID_ITS_AID

    def check_permissions(self, permissions_granted: list, data_object_id: int) -> bool:
        """
        Method that checks permissions to grant access to the data provider as specified in
        ETSI EN 302 895 V1.1.1 (2014-09). Section 6.2.1.
        TODO: Implement better security. Currently very basic security is implemented.

        Parameters
        ----------
        permissions_granted : list
            List of permissions granted to the data provider
        dataObjectID : int
        """
        if isinstance(permissions_granted, list):
            if len(permissions_granted) == 0:
                return False
            if data_object_id == DENM:
                return True
            if any(permission == data_object_id for permission in permissions_granted):
                return True
        return False

    def register_data_provider(self, data_provider: RegisterDataProviderReq) -> RegisterDataProviderResp:
        """
        Method specified in ETSI EN 302 895 V1.1.1 (2014-09). Section 6.2.1.1
        TODO: Apply Security. Currenly gives access to anyone sending valid information.
        TODO: Validate check permissions and its_aid.

        Parameters
        ----------
        data_provider : RegisterDataProviderReq
            Data provider that wants to register as specified in ETSI EN 302 895 V1.1.1 (2014-09). Section Annex B.
        """

        if (
            data_provider is None
            or self.check_its_aid(data_provider.application_id) is False
            or self.check_permissions(data_provider.access_permisions, data_provider.application_id) is False
        ):
            return RegisterDataProviderResp(
                data_provider.application_id,
                None,
                REGISTER_DATA_PROVIDER_RESULT_REJECTED,
            )
        self.ldm_service.add_data_provider_its_aid(data_provider.application_id)
        self.logging.debug("Registered new LDM Data Provider, with application id: %d", data_provider.application_id)
        return RegisterDataProviderResp(data_provider.application_id, None, REGISTER_DATA_PROVIDER_RESULT_ACCEPTED)

    def deregister_data_provider(self, data_provider: DeregisterDataProviderReq) -> DeregisterDataProviderResp:
        """
        Method specified in ETSI EN 302 895 V1.1.1 (2014-09). Section 6.2.2.1
        Returning ACK 0 if the application is registered (and now will be unregistered) and ACK 1 if it is not
        (and will not be unregistered).

        Parameters
        ----------
        data_provider : DeregisterDataProviderReq
            Data provider that wants to deregister as specified in ETSI EN 302 895 V1.1.1 (2014-09). Section Annex B.
        """
        self.logging.debug("Registring LDM Data Provider with application id %d", data_provider.application_id)
        if data_provider.application_id in self.ldm_service.get_data_provider_its_aid():
            self.ldm_service.del_data_provider_its_aid(data_provider.application_id)
            return DeregisterDataProviderResp(data_provider.application_id, DeregisterDataProviderAck(0))
        return DeregisterDataProviderResp(data_provider.application_id, DeregisterDataProviderAck(1))

    def add_provider_data(self, data_provider: AddDataProviderReq) -> AddDataProviderResp:
        """
        Method specified in ETSI EN 302 895 V1.1.1 (2014-09). Section 6.2.3
        TODO: Check if the message type is the same as the requested in the registration process

        Parameters
        ----------
        data_provider : AddDataProviderReq
            Data provider that wants to add data as specified in ETSI EN 302 895 V1.1.1 (2014-09). Section Annex B.
        """
        self.logging.debug("Adding provider data to LDM from application_id: %d", data_provider.application_id)

        if data_provider.application_id in self.ldm_service.get_data_provider_its_aid():
            data_object_id = self.ldm_service.add_provider_data(data_provider)  # Add data to LDM
            return AddDataProviderResp(data_provider.application_id, data_object_id)
        return AddDataProviderResp(data_provider.application_id, ADD_DATA_PROVIDER_RESULT_REJECTED)

    def update_provider_data(self, data_provider: UpdateDataProviderReq) -> UpdateDataProviderResp:
        """
        Method specified in ETSI EN 302 895 V1.1.1 (2014-09). Section 6.2.4
        TODO: Check if the messages have the same structure

        Parameters
        ----------
        data_provider : UpdateDataProviderReq
            Data provider that wants to update data as specified in ETSI EN 302 895 V1.1.1 (2014-09). Section Annex B.
        """
        self.logging.debug("Updating provider data from application_id %d", data_provider.application_id)
        if self.ldm_service.ldm_maintenance.data_containers.exists("dataObjectID", data_provider.data_object_id):
            data_object_type_str = self.ldm_service.get_object_type_from_data_object(data_provider.data_object)
            if self.ldm_service.ldm_maintenance.data_containers.exists(
                data_object_type_str, data_provider.data_object_id
            ):
                new_data_object_id = self.ldm_service.update_provider_data(
                    data_provider.data_object_id, data_provider.data_object
                )  # Update data
                return UpdateDataProviderResp(
                    data_provider.application_id,
                    new_data_object_id,
                    UpdateDataProviderResult(0),
                )
            return UpdateDataProviderResp(
                data_provider.application_id,
                data_provider.data_object_id,
                UpdateDataProviderResult(2),
            )
        return UpdateDataProviderResp(
            data_provider.application_id,
            data_provider.data_object_id,
            UpdateDataProviderResult(1),
        )

    def delete_provider_data(self, data_provider: DeleteDataProviderReq) -> DeleteDataProviderResp:
        """
        Method specified in ETSI EN 302 895 V1.1.1 (2014-09). Section 6.2.3.3

        Parameters
        ----------
        data_provider : DeleteDataProviderReq
            Data provider that wants to delete data as specified in ETSI EN 302 895 V1.1.1 (2014-09). Section Annex B.
        """
        self.logging.debug("Deleting provider data from application id %d", data_provider.application_id)
        if self.ldm_service.ldm_maintenance.data_containers.exists("dataObjectID", data_provider.data_object_id):
            self.ldm_service.del_provider_data(data_provider.data_object_id)
            return DeleteDataProviderResp(
                data_provider.application_id,
                data_provider.data_object_id,
                DELETE_DATA_PROVIDER_RESULT_ACCEPTED,
            )
        return DeleteDataProviderResp(
            data_provider.application_id,
            data_provider.data_object_id,
            DELETE_DATA_PROVIDER_RESULT_REJECTED,
        )
