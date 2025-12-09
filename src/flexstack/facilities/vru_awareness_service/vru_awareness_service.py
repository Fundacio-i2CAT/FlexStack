from __future__ import annotations
import logging

from ..local_dynamic_map.ldm_classes import AccessPermission
from .vam_ldm_adaptation import VRUBasicServiceLDM
from .vam_transmission_management import VAMTransmissionManagement, DeviceDataProvider
from ...btp.router import Router as BTPRouter
from .vam_coder import VAMCoder
from .vam_reception_management import VAMReceptionManagement
from ..local_dynamic_map.ldm_facility import LDMFacility


class VRUAwarenessService:
    """
    VRU Basis Service

    Attributes
    ----------
    btp_router : BTPRouter
        BTP Router.
    vam_coder : VAMCoder
        vam Coder.
    device_data_provider : DeviceDataProvider
        Vehicle Data.
    vam_transmission_management : vamTransmissionManagement
        vam Transmission Management.
    vam_reception_management : vamReceptionManagement
        vam Reception Management.
    """

    def __init__(
        self,
        btp_router: BTPRouter,
        device_data_provider: DeviceDataProvider,
        ldm: LDMFacility | None = None,
    ) -> None:
        """
        Initialize the Cooperative Awareness Basic Service.

        Parameters
        ----------
        btp_router : BTPRouter
            BTP Router.
        device_data_provider : DeviceDataProvider
            Vehicle Data.
        ldm: LDM Facility
            Local Dynamic Map Facility that will be used to provide data to the LDM.
        """
        self.logging = logging.getLogger("vru_basic_service")

        self.btp_router = btp_router
        self.vam_coder = VAMCoder()
        self.device_data_provider = device_data_provider
        vru_basic_service_ldm = None
        if ldm is not None:
            vru_basic_service_ldm = VRUBasicServiceLDM(ldm, (AccessPermission.VAM,), 5)

        self.vam_transmission_management = VAMTransmissionManagement(
            btp_router=btp_router,
            vam_coder=self.vam_coder,
            device_data_provider=self.device_data_provider,
            vru_basic_service_ldm=vru_basic_service_ldm,
        )
        self.vam_reception_management = VAMReceptionManagement(
            vam_coder=self.vam_coder,
            btp_router=self.btp_router,
            vru_basic_service_ldm=vru_basic_service_ldm,
        )

        self.logging.info("VRU Basic Service Started!")
