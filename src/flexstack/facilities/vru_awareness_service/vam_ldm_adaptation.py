import logging

from ...facilities.local_dynamic_map.ldm_classes import (
    AddDataProviderReq,
    Location,
    RegisterDataProviderReq,
    TimeValidity,
    TimestampIts,
)
from ...facilities.local_dynamic_map.ldm_constants import VAM

from ...facilities.local_dynamic_map.ldm_facility import LDMFacility


class VRUBasicServiceLDM:
    """
    Class to simplify the operation of the LDM for the VRU Basic Service Component.

    It will handle registry and adding data to the LDM.

    Attributes
    ----------
    ldm_facility: LDMFacility
        Local Dynamic Map Facility
    access_permissions: list
        List containing the application ID of all the applications that want to be accessed.
    time_validity: int
        Time that the messages stored in the LDM will be mantained.
    """

    def __init__(self, ldm: LDMFacility, access_permissions: list, time_validity: int):
        self.logging = logging.getLogger("vru_basic_service")
        self.ldm_if_ldm_3 = ldm.if_ldm_3
        self.access_permissions = access_permissions
        self.time_validity = time_validity
        self.ldm_if_ldm_3.register_data_provider(
            RegisterDataProviderReq(
                application_id=VAM,
                access_permissions=self.access_permissions,
                time_validity=TimeValidity(self.time_validity),
            )
        )

    def add_provider_data_to_ldm(self, vam: dict) -> None:
        """
        Function to add VRU Awareness Messages to the LDM.

        Parameters
        ----------
        vam: dict
            VRU Awareness Message in a python dictionary format

        Returns
        --------
        None
        """
        timestamp = TimestampIts()
        data = AddDataProviderReq(
            application_id=VAM,
            timestamp=timestamp,
            location=Location.location_builder_circle(
                latitude=vam["vam"]["vamParameters"]["basicContainer"]["referencePosition"]["latitude"],
                longitude=vam["vam"]["vamParameters"]["basicContainer"]["referencePosition"]["longitude"],
                altitude=vam["vam"]["vamParameters"]["basicContainer"]["referencePosition"]["altitude"][
                    "altitudeValue"
                ],
                radius=0,
            ),
            data_object=vam,
            time_validity=TimeValidity(self.time_validity),
        )
        self.logging.debug(
            "Adding VAM message to LDM with; time_stamp=%d latitude=%f longitude=%f altitude=%d time_validity=%d",
            int(TimestampIts().timestamp),
            vam["vam"]["vamParameters"]["basicContainer"]["referencePosition"]["latitude"],
            vam["vam"]["vamParameters"]["basicContainer"]["referencePosition"]["longitude"],
            vam["vam"]["vamParameters"]["basicContainer"]["referencePosition"]["altitude"]["altitudeValue"],
            self.time_validity
        )

        response = self.ldm_if_ldm_3.add_provider_data(data)
        if not isinstance(response.data_object_id, int):
            raise TypeError(response.data_object_id)
