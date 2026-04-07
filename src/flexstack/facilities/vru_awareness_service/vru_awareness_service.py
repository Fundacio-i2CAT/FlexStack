from __future__ import annotations
import logging

from ..local_dynamic_map.ldm_classes import AccessPermission
from .vam_ldm_adaptation import VRUBasicServiceLDM
from .vam_transmission_management import VAMTransmissionManagement, DeviceDataProvider
from ...btp.router import Router as BTPRouter
from .vam_coder import VAMCoder
from .vam_reception_management import VAMReceptionManagement
from .vru_clustering import VBSClusteringManager
from ..local_dynamic_map.ldm_facility import LDMFacility


class VRUAwarenessService:
    """VRU Awareness Basic Service (VBS).

    Top-level service object that wires together encoding, transmission,
    reception, LDM storage, and the optional VBS clustering state machine
    defined in ETSI TS 103 300-3 V2.3.1 (2025-12), clause 5.4.

    Attributes
    ----------
    btp_router:
        BTP Router used to send and receive VAMs.
    vam_coder:
        ASN.1 encoder/decoder for VAMs.
    device_data_provider:
        Static device parameters (station ID, station type, etc.).
    vam_transmission_management:
        VAM generation and transmission engine.
    vam_reception_management:
        VAM reception and LDM injection engine.
    clustering_manager:
        VBS clustering state machine (``None`` when
        ``cluster_support=False``).
    """

    def __init__(
        self,
        btp_router: BTPRouter,
        device_data_provider: DeviceDataProvider,
        ldm: LDMFacility | None = None,
        cluster_support: bool = True,
        own_vru_profile: str = "pedestrian",
    ) -> None:
        """Initialise the VRU Awareness Basic Service.

        Parameters
        ----------
        btp_router:
            BTP Router.
        device_data_provider:
            Static device parameters.
        ldm:
            Local Dynamic Map Facility.  When provided, transmitted and
            received VAMs are stored for other facilities to query.
        cluster_support:
            When ``True`` (default), the VBS clustering state machine is
            instantiated and integrated with transmission and reception
            management per clause 5.4 of ETSI TS 103 300-3 V2.3.1.
        own_vru_profile:
            ASN.1 VRU profile string, e.g. ``"pedestrian"``.  Used by the
            clustering manager to populate ``clusterProfiles`` in transmitted
            cluster VAMs.
        """
        self.logging = logging.getLogger("vru_basic_service")

        self.btp_router = btp_router
        self.vam_coder = VAMCoder()
        self.device_data_provider = device_data_provider
        vru_basic_service_ldm = None
        if ldm is not None:
            vru_basic_service_ldm = VRUBasicServiceLDM(ldm, (AccessPermission.VAM,), 5)

        self.clustering_manager: VBSClusteringManager | None = None
        if cluster_support:
            self.clustering_manager = VBSClusteringManager(
                own_station_id=device_data_provider.station_id,
                own_vru_profile=own_vru_profile,
            )

        self.vam_transmission_management = VAMTransmissionManagement(
            btp_router=btp_router,
            vam_coder=self.vam_coder,
            device_data_provider=self.device_data_provider,
            vru_basic_service_ldm=vru_basic_service_ldm,
            clustering_manager=self.clustering_manager,
        )
        self.vam_reception_management = VAMReceptionManagement(
            vam_coder=self.vam_coder,
            btp_router=self.btp_router,
            vru_basic_service_ldm=vru_basic_service_ldm,
            clustering_manager=self.clustering_manager,
        )

        self.logging.info("VRU Basic Service Started!")
