import unittest
from unittest.mock import MagicMock
from flexstack.facilities.ca_basic_service.cam_reception_management import (
    CAMReceptionManagement,
)


class TestCamReceptionManagement(unittest.TestCase):
    def test__init__(self):
        # Arrange
        cam_coder = MagicMock()
        btp_router = MagicMock()
        btp_router.register_indication_callback_btp = MagicMock()
        ldm_facility = MagicMock()
        ca_basic_service_ldm = MagicMock()
        # Act
        cam_reception_management = CAMReceptionManagement(
            cam_coder, btp_router, ldm_facility
        )
        # Assert
        cam_reception_management.cam_coder = cam_coder
        cam_reception_management.btp_router = btp_router
        cam_reception_management.ca_basic_service_ldm = ca_basic_service_ldm
        btp_router.register_indication_callback_btp.assert_called_once()

    def test_reception_callback(self):
        # Arrange
        cam_coder = MagicMock()
        cam = {"cam": {"generationDeltaTime": 24856},
               "header": {"stationId": 1}}
        cam_coder.decode = MagicMock(return_value=cam)
        btp_router = MagicMock()
        btp_router.register_indication_callback_btp = MagicMock()
        ca_basic_service_ldm = MagicMock()
        ca_basic_service_ldm.add_provider_data_to_ldm = MagicMock()
        # Act
        cam_reception_management = CAMReceptionManagement(
            cam_coder, btp_router, ca_basic_service_ldm
        )
        data = MagicMock()
        data.data = MagicMock()
        cam_reception_management.reception_callback(data)
        # Assert
        ca_basic_service_ldm.add_provider_data_to_ldm.assert_called_once()
        cam_coder.decode.assert_called_once()
