"""
Cooperatie Awareness Basic Service

This file contains the class for the Cooperative Awareness Basic Service.
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
    Cooperative Awareness Basic Service

    Attributes
    ----------
    btp_router : BTPRouter
        BTP Router.
    cam_coder : CAMCoder
        CAM Coder.
    vehicle_data : VehicleData
        Vehicle Data.
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
        Initialize the Cooperative Awareness Basic Service.

        Parameters
        ----------
        btp_router : BTPRouter
            BTP Router.
        vehicle_data : VehicleData
            Vehicle Data.
        ldm: LDMFacility
            Local Dynamic Map (LDM) Service.
        """
        self.logging = logging.getLogger("ca_basic_service")

        self.btp_router = btp_router
        self.cam_coder = CAMCoder()
        self.vehicle_data = vehicle_data
        ca_basic_service_ldm = None
        if ldm is not None:
            ca_basic_service_ldm = CABasicServiceLDM(ldm, (AccessPermission.CAM,), 5)
        self.cam_transmission_management = CAMTransmissionManagement(
            btp_router=btp_router,
            cam_coder=self.cam_coder,
            vehicle_data=self.vehicle_data,
            ca_basic_service_ldm=ca_basic_service_ldm,
        )
        self.cam_reception_management = CAMReceptionManagement(
            cam_coder=self.cam_coder,
            btp_router=self.btp_router,
            ca_basic_service_ldm=ca_basic_service_ldm,
        )

        self.logging.info("CA Basic Service Started!")
