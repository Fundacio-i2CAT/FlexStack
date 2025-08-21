import unittest
from unittest.mock import MagicMock, patch
from flexstack.facilities.vru_awareness_service.vam_ldm_adaptation import (
    VRUBasicServiceLDM,
)

white_vam = {
    "header": {"protocolVersion": 3, "messageId": 16, "stationId": 0},
    "vam": {
        "generationDeltaTime": 0,
        "vamParameters": {
            "basicContainer": {
                # roadSideUnit(15), cyclist(2)
                "stationType": 15,
                "referencePosition": {
                    "latitude": 900000001,
                    "longitude": 1800000001,
                    "positionConfidenceEllipse": {
                        "semiMajorAxisLength": 4095,
                        "semiMinorAxisLength": 4095,
                        "semiMajorAxisOrientation": 3601,
                    },
                    "altitude": {
                        "altitudeValue": 800001,
                        "altitudeConfidence": "unavailable",
                    },
                },
            },
            "vruHighFrequencyContainer": {
                "heading": {"value": 3601, "confidence": 127},
                "speed": {"speedValue": 16383, "speedConfidence": 127},
                "longitudinalAcceleration": {
                    "longitudinalAccelerationValue": 161,
                    "longitudinalAccelerationConfidence": 102,
                },
            },
        },
    },
}


class TestVRUBasicServiceLDM(unittest.TestCase):
    def setUp(self):
        self.ldm = MagicMock()
        self.ldm.if_ldm_3.register_data_provider = MagicMock()

        self.access_permissions = MagicMock()
        self.time_validity = MagicMock()
        self.vru_basic_service_ldm = VRUBasicServiceLDM(
            self.ldm, self.access_permissions, self.time_validity
        )

    def test__init__(self):
        self.ldm.if_ldm_3.register_data_provider.assert_called()

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
        time_stamp_its = MagicMock()
        time_stamp_its.timestamp = 1
        mock_location_builer_circle.return_value = MagicMock()
        mock_time_validity.return_value = MagicMock()

        add_provider_data = MagicMock()
        add_provider_data.data_object_id = 1
        self.vru_basic_service_ldm.ldm_if_ldm_3.add_provider_data = MagicMock(return_value=add_provider_data)
        vam = white_vam
        self.vru_basic_service_ldm.add_provider_data_to_ldm(vam)
        mock_time.assert_called()
        mock_location_builer_circle.assert_called()

        # Add provder fails
        add_provider_data.data_object_id = "unsuccessful"
        self.assertRaises(
            Exception, self.vru_basic_service_ldm.add_provider_data_to_ldm, vam
        )
