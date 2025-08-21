"""
CA Reception Management.

This file contains the class for the CA Reception Management.
"""

import logging

from flexstack.facilities.ca_basic_service.cam_transmission_management import GenerationDeltaTime

from .cam_ldm_adaptation import CABasicServiceLDM
from .cam_coder import CAMCoder
from ...btp.service_access_point import BTPDataIndication
from ...btp.router import Router as BTPRouter
from ...utils.time_service import TimeService


class CAMReceptionManagement:
    """
    This class is responsible for the CAM reception management.

    Attributes
    ----------
    cam_coder : CAMCoder
        CAM Coder object.
    btp_router : BTPRouter
        BTP Router object.
    ca_basic_service_ldm : CABasicServiceLDM
        CA Basic Service LDM.
    """

    def __init__(
        self,
        cam_coder: CAMCoder,
        btp_router: BTPRouter,
        ca_basic_service_ldm: CABasicServiceLDM = None,
    ) -> None:
        """
        Initialize the CAM Reception Management.

        Parameters
        ----------
        cam_coder : CAMCoder
            CAM Coder object.
        btp_router : BTPRouter
            BTP Router object.
        ldm: LDMFacility
            Local Dynamic Map where the data will be stashed.
        """
        self.logging = logging.getLogger("ca_basic_service")

        self.cam_coder = cam_coder
        self.btp_router = btp_router
        self.btp_router.register_indication_callback_btp(
            port=2001, callback=self.reception_callback
        )
        self.ca_basic_service_ldm = ca_basic_service_ldm

    def reception_callback(self, btp_indication: BTPDataIndication) -> None:
        """
        Callback for the reception of a CAM.

        Parameters
        ----------
        btp_indication : BTPDataIndication
            BTP Data Indication.
        """
        cam = self.cam_coder.decode(btp_indication.data)
        generation_delta_time = GenerationDeltaTime()
        generation_delta_time.msec = cam["cam"]["generationDeltaTime"]
        utc_timestamp = generation_delta_time.as_timestamp_in_certain_point(
            int(TimeService.time()*1000))
        cam["utc_timestamp"] = utc_timestamp
        if self.ca_basic_service_ldm is not None:
            self.ca_basic_service_ldm.add_provider_data_to_ldm(cam)
        self.logging.debug(
            "Received CAM with timestamp: %s, station_id: %s",
            cam["cam"]["generationDeltaTime"],
            cam["header"]["stationId"],
        )
