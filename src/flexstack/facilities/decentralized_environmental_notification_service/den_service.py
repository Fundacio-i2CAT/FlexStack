from __future__ import annotations
import logging
from .denm_coder import DENMCoder
from .denm_transmission_management import DENMTransmissionManagement, VehicleData
from ...btp.router import Router as BTPRouter
from .denm_reception_management import DENMReceptionManagement
from ..local_dynamic_map.ldm_facility import LDMFacility


class DecentralizedEnvironmentalNotificationService:
    """
    Decentralized Environmental Notification (DEN) Service.

    Attributes
    ----------
    btp_router : BTPRouter
        BTP Router.
    denm_coder : DENMCoder
        DENM Coder.
    vehicle_data : VehicleData
        Vehicle Data.
    ldm : LDMFacility
        Local Dynamic Map (LDM) Service.
    denm_transmission_management : DENMTransmissionManagement
        DENM Transmission Management.
    denm_reception_management : DENMReceptionManagement
        DENM Reception Management.
    """

    def __init__(
        self, btp_router: BTPRouter, vehicle_data: VehicleData, ldm: LDMFacility | None = None
    ) -> None:
        """
        Initialize the Decentralized Environmental Notification Service.

        Parameters
        ----------
        btp_router : BTPRouter
            BTP Router.
        vehicle_data : VehicleData
            Vehicle Data.
        ldm: LDMFacility
            Local Dynamic Map (LDM) Service.
        """

        self.logging = logging.getLogger("denm_service")

        self.btp_router = btp_router
        self.denm_coder = DENMCoder()
        self.vehicle_data = vehicle_data
        self.ldm = ldm
        self.denm_transmission_management = DENMTransmissionManagement(
            btp_router=btp_router,
            denm_coder=self.denm_coder,
            vehicle_data=self.vehicle_data,
        )
        self.denm_reception_management = DENMReceptionManagement(
            denm_coder=self.denm_coder, btp_router=self.btp_router, ldm=ldm
        )

        self.logging.info("DENM Service Started!")
