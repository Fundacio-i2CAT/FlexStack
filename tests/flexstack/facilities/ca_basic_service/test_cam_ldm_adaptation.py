import unittest
from unittest.mock import MagicMock, patch
from flexstack.facilities.ca_basic_service.cam_ldm_adaptation import (
    CABasicServiceLDM,
)

white_cam = {
    "header": {
        "protocolVersion": 2,
        "messageID": 2,
        "stationID": 0,
    },
    "cam": {
        "generationDeltaTime": 0,
        "camParameters": {
            "basicContainer": {
                "stationType": 0,
                "referencePosition": {
                    "latitude": 900000001,
                    "longitude": 1800000001,
                    "positionConfidenceEllipse": {
                        "semiMajorConfidence": 4095,
                        "semiMinorConfidence": 4095,
                        "semiMajorOrientation": 3601,
                    },
                    "altitude": {
                        "altitudeValue": 800001,
                        "altitudeConfidence": "unavailable",
                    },
                },
            },
            "highFrequencyContainer": (
                "basicVehicleContainerHighFrequency",
                {
                    "heading": {"headingValue": 3601, "headingConfidence": 127},
                    "speed": {"speedValue": 16383, "speedConfidence": 127},
                    "driveDirection": "unavailable",
                    "vehicleLength": {
                        "vehicleLengthValue": 1023,
                        "vehicleLengthConfidenceIndication": "unavailable",
                    },
                    "vehicleWidth": 62,
                    "longitudinalAcceleration": {
                        "longitudinalAccelerationValue": 161,
                        "longitudinalAccelerationConfidence": 102,
                    },
                    "curvature": {
                        "curvatureValue": 1023,
                        "curvatureConfidence": "unavailable",
                    },
                    "curvatureCalculationMode": "unavailable",
                    "yawRate": {
                        "yawRateValue": 32767,
                        "yawRateConfidence": "unavailable",
                    },
                },
            ),
        },
    },
}


class TestCABasicServiceLDM(unittest.TestCase):
    def setUp(self):
        self.local_dynamic_map = MagicMock()
        self.ldm_if_ldm_3 = MagicMock()
        self.local_dynamic_map.if_ldm_3 = self.ldm_if_ldm_3
        self.ldm_if_ldm_3.register_data_provider = MagicMock()

        self.access_permissions = MagicMock()
        self.time_validity = MagicMock()
        self.cam_basic_service_ldm = CABasicServiceLDM(
            self.local_dynamic_map, self.access_permissions, self.time_validity
        )

    def test__init__(self):
        self.ldm_if_ldm_3.register_data_provider.assert_called()

    @patch("flexstack.facilities.local_dynamic_map.ldm_classes.TimeValidity")
    @patch(
        "flexstack.facilities.local_dynamic_map.ldm_classes.Location.location_builder_circle"
    )
    @patch("flexstack.utils.time_service.TimeService.time")
    def test_add_provider_data_to_ldm(
        self,
        mock_time,
        mock_location_builer_circle,
        mock_time_validity,
    ):
        mock_time.return_value = 1
        mock_location_builer_circle.return_value = MagicMock()
        mock_time_validity.return_value = MagicMock()

        add_provider_data = MagicMock()
        add_provider_data.data_object_id = 1
        self.ldm_if_ldm_3.add_provider_data = MagicMock(return_value=add_provider_data)
        cam = white_cam
        self.cam_basic_service_ldm.add_provider_data_to_ldm(cam)
        mock_time.assert_called()
        mock_location_builer_circle.assert_called()

        # Add provder fails
        add_provider_data.data_object_id = "unsuccessful"
        self.assertRaises(
            Exception, self.cam_basic_service_ldm.add_provider_data_to_ldm, cam
        )
