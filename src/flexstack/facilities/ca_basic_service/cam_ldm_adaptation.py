import logging
from ...facilities.local_dynamic_map.ldm_classes import (
    AddDataProviderReq,
    Location,
    RegisterDataProviderReq,
    TimeValidity,
    TimestampIts,
)
from ...facilities.local_dynamic_map.ldm_constants import CAM
from ...facilities.local_dynamic_map.ldm_facility import LDMFacility


class CABasicServiceLDM:
    """
    Class to simplify the operation of the LDM for the CA Basic Service Component.

    It will handle registry and adding data to the LDM.

    Attributes
    ----------
    ldm_if_ldm_3: InterfaceLDM3
        Interface to provide data to the LDM.
    access_permissions: list
        List containing the application ID of all the applications that want to be accessed.
    time_validity: int
        Time that the messages stored in the LDM will be mantained.
    """

    def __init__(self, ldm: LDMFacility, access_permissions: list, time_validity: int):
        self.logging = logging.getLogger("ca_basic_service")
        self.ldm_if_ldm_3 = ldm.if_ldm_3
        self.access_permissions = access_permissions
        self.time_validity = time_validity

        self.ldm_if_ldm_3.register_data_provider(
            RegisterDataProviderReq(
                application_id=CAM,
                access_permissions=self.access_permissions,
                time_validity=TimeValidity(self.time_validity),
            )
        )

    def add_provider_data_to_ldm(self, cam: dict) -> None:
        """
        Function to add Cooperative Awareness Messages to the LDM.

        Parameters
        ----------
        cam: dict
            Cooperative Awareness Message in a python dictionary format.
        """
        timestamp = TimestampIts()
        data = AddDataProviderReq(
            application_id=CAM,
            timestamp=timestamp,
            location=Location.location_builder_circle(
                latitude=cam["cam"]["camParameters"]["basicContainer"][
                    "referencePosition"
                ]["latitude"],
                longitude=cam["cam"]["camParameters"]["basicContainer"][
                    "referencePosition"
                ]["longitude"],
                altitude=cam["cam"]["camParameters"]["basicContainer"][
                    "referencePosition"
                ]["altitude"]["altitudeValue"],
                radius=0,
            ),
            data_object=cam,
            time_validity=TimeValidity(self.time_validity),
        )

        self.logging.debug(
            "Adding CAM message to LDM with; "
            "time_stamp=%d latitude=%d longitude=%d altitude=%d time_validity=%d",
            int(TimestampIts().timestamp),
            cam["cam"]["camParameters"]["basicContainer"]["referencePosition"][
                "latitude"
            ],
            cam["cam"]["camParameters"]["basicContainer"]["referencePosition"][
                "longitude"
            ],
            cam["cam"]["camParameters"]["basicContainer"]["referencePosition"][
                "altitude"
            ]["altitudeValue"],
            self.time_validity,
        )

        response = self.ldm_if_ldm_3.add_provider_data(data)
        if not isinstance(response.data_object_id, int):
            raise response.data_object_id
