import logging
from .denm_coder import DENMCoder
from ...btp.service_access_point import BTPDataIndication
from ...btp.router import Router as BTPRouter

from ..local_dynamic_map.ldm_facility import LDMFacility
from ..local_dynamic_map.ldm_classes import (
    RegisterDataProviderReq,
    AddDataProviderReq,
    TimeValidity,
    TimestampIts,
    Location,
)
from ..local_dynamic_map.ldm_constants import DENM


class DENMReceptionManagement:
    """
    This class is responsible for the DENM reception management.

    Attributes
    ----------
    denm_coder : DENMCoder
        DENM Coder object.

    """

    def __init__(
        self, denm_coder: DENMCoder, btp_router: BTPRouter, ldm: LDMFacility
    ) -> None:
        """
        Initialize the DENM Reception Management.

        Parameters
        ----------
        denm_coder : DENMCoder
            DENM Coder object.
        """

        self.logging = logging.getLogger("denm_service")

        self.denm_coder = denm_coder
        self.btp_router = btp_router
        self.btp_router.register_indication_callback_btp(
            port=2002, callback=self.reception_callback
        )
        self.ldm_facility = ldm
        if self.ldm_facility is not None:
            self.ldm_facility.if_ldm_3.register_data_provider(
                RegisterDataProviderReq(
                    application_id=DENM,
                    access_permissions=[
                        DENM,
                    ],
                    time_validity=TimeValidity(1000),
                )
            )

    def feed_ldm(self, denm: dict) -> None:
        """
        Send DENM to LDM Facility.

        Parameters
        ----------
        denm : dict
            DENM message.
        """
        if self.ldm_facility is not None:
            data = AddDataProviderReq(
                application_id=DENM,
                timestamp=TimestampIts.initialize_with_timestamp_its(denm["denm"]["management"]["detectionTime"]),
                location=Location.location_builder_circle(
                    latitude=denm["denm"]["management"]["eventPosition"]["latitude"],
                    longitude=denm["denm"]["management"]["eventPosition"]["longitude"],
                    altitude=denm["denm"]["management"]["eventPosition"]["altitude"][
                        "altitudeValue"
                    ],
                    radius=0,
                ),
                data_object=denm,
                time_validity=TimeValidity(3),
            )
            self.ldm_facility.if_ldm_3.add_provider_data(data)
            # if not isinstance(response.dataObjectID, int):
            #     raise response.dataObjectID
            self.logging.debug("Added DENM data to the LDM. Data: %s", data)

    def reception_callback(self, btp_indication: BTPDataIndication) -> None:
        """
        Callback for the reception of a DENM.

        Parameters
        ----------
        btp_indication : BTPDataIndication
            BTP Data Indication.
        """
        denm = self.denm_coder.decode(btp_indication.data)
        self.feed_ldm(denm)
        self.logging.debug(
            "Received DENM with timestamp: %s, station_id: %s",
            denm["denm"]["management"]["referenceTime"],
            denm["header"]["stationId"],
        )
