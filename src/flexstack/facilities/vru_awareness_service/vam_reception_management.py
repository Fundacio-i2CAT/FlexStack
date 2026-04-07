from __future__ import annotations
import logging
from typing import Optional
from .vam_coder import VAMCoder
from ...btp.service_access_point import BTPDataIndication
from ...btp.router import Router as BTPRouter

from .vam_ldm_adaptation import VRUBasicServiceLDM
from .vru_clustering import VBSClusteringManager
from ..ca_basic_service.cam_transmission_management import GenerationDeltaTime
from ...utils.time_service import TimeService


class VAMReceptionManagement:
    """
    This class is responsible for the vam reception management.

    Attributes
    ----------
    vam_coder : vamCoder
        vam Coder object.

    """

    def __init__(
        self,
        vam_coder: VAMCoder,
        btp_router: BTPRouter,
        vru_basic_service_ldm: VRUBasicServiceLDM | None = None,
        clustering_manager: Optional[VBSClusteringManager] = None,
    ) -> None:
        """
        Initialise the VAM Reception Management.

        Parameters
        ----------
        vam_coder:
            VAM ASN.1 coder.
        btp_router:
            BTP Router.
        vru_basic_service_ldm:
            Optional LDM adapter.
        clustering_manager:
            Optional VBS clustering state machine.  When provided, each
            received VAM is forwarded to
            :meth:`~.vru_clustering.VBSClusteringManager.on_received_vam`
            so that nearby-VRU and cluster tables stay up to date.
        """
        self.logging = logging.getLogger("vru_basic_service")
        self.vam_coder = vam_coder
        self.btp_router = btp_router
        self.btp_router.register_indication_callback_btp(
            port=2018, callback=self.reception_callback
        )
        self.vru_basic_service_ldm = vru_basic_service_ldm
        self.clustering_manager: Optional[VBSClusteringManager] = clustering_manager

    def reception_callback(self, btp_indication: BTPDataIndication) -> None:
        """
        Callback for the reception of a vam. Connected to LDM Facility in order to feed data.

        Parameters
        ----------
        btp_indication : BTPDataIndication
            BTP Data Indication.
        """
        vam = self.vam_coder.decode(btp_indication.data)
        generation_delta_time = GenerationDeltaTime(msec=vam["vam"]["generationDeltaTime"])
        utc_timestamp = generation_delta_time.as_timestamp_in_certain_point(
            int(TimeService.time()*1000))
        vam["utc_timestamp"] = utc_timestamp
        if self.vru_basic_service_ldm is not None:
            self.vru_basic_service_ldm.add_provider_data_to_ldm(vam)
        if self.clustering_manager is not None:
            self.clustering_manager.on_received_vam(vam)
        self.logging.debug("Recieved message; %s", vam)
        self.logging.info(
            "Recieved VAM message with timestamp: %s, station_id: %s",
            vam["vam"]["generationDeltaTime"],
            vam["header"]["stationId"],
        )
