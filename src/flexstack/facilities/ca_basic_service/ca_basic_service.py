"""
Cooperative Awareness Basic Service

This file contains the class for the Cooperative Awareness Basic Service,
strictly following ETSI TS 103 900 V2.2.1 (2025-02).
"""
from __future__ import annotations
import logging
from ..local_dynamic_map.ldm_facility import LDMFacility
from ..local_dynamic_map.ldm_classes import AccessPermission
from .cam_transmission_management import (
    CAMTransmissionManagement,
    VehicleData,
)
from ...btp.router import Router as BTPRouter
from .cam_coder import CAMCoder
from .cam_reception_management import (
    CAMReceptionManagement,
)
from .cam_ldm_adaptation import CABasicServiceLDM


class CooperativeAwarenessBasicService:
    """
    Cooperative Awareness Basic Service — ETSI TS 103 900 V2.2.1.

    Call :meth:`start` to activate the service and :meth:`stop` to deactivate
    it in accordance with §6.1.2.

    Attributes
    ----------
    btp_router : BTPRouter
        BTP Router.
    cam_coder : CAMCoder
        CAM Coder.
    cam_transmission_management : CAMTransmissionManagement
        CAM Transmission Management.
    cam_reception_management : CAMReceptionManagement
        CAM Reception Management.
    """

    def __init__(
        self,
        btp_router: BTPRouter,
        vehicle_data: VehicleData,
        ldm: LDMFacility | None = None,
    ) -> None:
        """
        Initialise the Cooperative Awareness Basic Service.

        Parameters
        ----------
        btp_router : BTPRouter
            BTP Router.
        vehicle_data : VehicleData
            Vehicle Data.
        ldm : LDMFacility or None
            Local Dynamic Map (LDM) Service.
        """
        self.logging = logging.getLogger("ca_basic_service")
        self.cam_coder = CAMCoder()
        ca_basic_service_ldm = None
        if ldm is not None:
            ca_basic_service_ldm = CABasicServiceLDM(
                ldm, (AccessPermission.CAM,), 5)
        self.cam_transmission_management = CAMTransmissionManagement(
            btp_router=btp_router,
            cam_coder=self.cam_coder,
            vehicle_data=vehicle_data,
            ca_basic_service_ldm=ca_basic_service_ldm,
        )
        self.cam_reception_management = CAMReceptionManagement(
            cam_coder=self.cam_coder,
            btp_router=btp_router,
            ca_basic_service_ldm=ca_basic_service_ldm,
        )

        self.logging.info("CA Basic Service initialised.")

    def start(self) -> None:
        """
        Activate the CA service (§6.1.2).

        Starts the T_CheckCamGen timer in the transmission management.
        """
        self.cam_transmission_management.start()
        self.logging.info("CA Basic Service started.")

    def stop(self) -> None:
        """
        Deactivate the CA service (§6.1.2).

        Stops the T_CheckCamGen timer in the transmission management.
        """
        self.cam_transmission_management.stop()
        self.logging.info("CA Basic Service stopped.")
