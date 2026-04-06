"""
CA Reception Management.

This file contains the class for the CA Reception Management,
strictly following ETSI TS 103 900 V2.2.1 (2025-02).

Key standard-compliance additions:
  - Decoding exceptions are caught and logged; the LDM/applications are NOT
    updated with corrupt data (Annex B.3.3.1).
  - Application callbacks (IF.CAM) can be registered via
    :meth:`add_application_callback`.
"""
from __future__ import annotations
import logging
from typing import Callable

from .cam_transmission_management import GenerationDeltaTime
from .cam_ldm_adaptation import CABasicServiceLDM
from .cam_coder import CAMCoder
from ...btp.service_access_point import BTPDataIndication
from ...btp.router import Router as BTPRouter
from ...utils.time_service import TimeService


class CAMReceptionManagement:
    """
    CAM Reception Management — ETSI TS 103 900 V2.2.1 §6.2 / Annex B.3.

    Attributes
    ----------
    cam_coder : CAMCoder
        CAM Coder object.
    btp_router : BTPRouter
        BTP Router object.
    ca_basic_service_ldm : CABasicServiceLDM or None
        CA Basic Service LDM.
    """

    def __init__(
        self,
        cam_coder: CAMCoder,
        btp_router: BTPRouter,
        ca_basic_service_ldm: CABasicServiceLDM | None = None,
    ) -> None:
        self.logging = logging.getLogger("ca_basic_service")

        self.cam_coder = cam_coder
        self.btp_router = btp_router
        self.btp_router.register_indication_callback_btp(
            port=2001, callback=self.reception_callback
        )
        self.ca_basic_service_ldm = ca_basic_service_ldm
        self._application_callbacks: list[Callable[[dict], None]] = []

    def add_application_callback(self, callback: Callable[[dict], None]) -> None:
        """
        Register an application callback (IF.CAM — §6.2).

        The callback receives the decoded CAM dict (with an added
        ``utc_timestamp`` key) whenever a valid CAM is received.

        Parameters
        ----------
        callback : callable
            Function accepting a single CAM dict argument.
        """
        self._application_callbacks.append(callback)

    def reception_callback(self, btp_indication: BTPDataIndication) -> None:
        """
        BTP indication callback for received CAMs.

        Decoding exceptions are caught here so that the LDM and application
        layers are never updated with malformed data (Annex B.3.3.1).

        Parameters
        ----------
        btp_indication : BTPDataIndication
            BTP Data Indication carrying the raw CAM payload.
        """
        try:
            cam = self.cam_coder.decode(btp_indication.data)
        except Exception:
            self.logging.exception(
                "CAM decoding failed (Annex B.3.3.1) — discarding packet"
            )
            return

        generation_delta_time = GenerationDeltaTime(
            msec=cam["cam"]["generationDeltaTime"]
        )
        utc_timestamp = generation_delta_time.as_timestamp_in_certain_point(
            int(TimeService.time() * 1000)
        )
        cam["utc_timestamp"] = utc_timestamp

        if self.ca_basic_service_ldm is not None:
            self.ca_basic_service_ldm.add_provider_data_to_ldm(cam)

        for cb in self._application_callbacks:
            try:
                cb(cam)
            except Exception:
                self.logging.exception("Application CAM callback raised an exception")

        self.logging.info(
            "Received CAM: generationDeltaTime=%s, stationId=%s",
            cam["cam"]["generationDeltaTime"],
            cam["header"]["stationId"],
        )
