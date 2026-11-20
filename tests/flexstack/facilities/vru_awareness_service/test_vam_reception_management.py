import unittest
from unittest.mock import patch, MagicMock

from flexstack.facilities.vru_awareness_service.vam_reception_management import (
    VAMReceptionManagement,
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


class TestVAMReceptionManagement(unittest.TestCase):
    def setUp(self) -> None:
        vam_coder_mock = MagicMock()
        vam_coder_mock.decode = MagicMock(return_value=white_vam)
        btp_router_mock = MagicMock()
        self.vru_service_ldm_adaptation = MagicMock()
        response_mock = MagicMock()
        response_mock.data_object_id = 0
        self.vru_service_ldm_adaptation.add_provider_data_to_ldm = MagicMock(
            return_value=response_mock
        )

        self.reception_management = VAMReceptionManagement(
            vam_coder_mock, btp_router_mock, self.vru_service_ldm_adaptation
        )

    @patch(
        "flexstack.facilities.local_dynamic_map.ldm_classes.AddDataProviderReq"
    )
    @patch("flexstack.facilities.local_dynamic_map.ldm_classes.TimeValidity")
    @patch("flexstack.facilities.local_dynamic_map.ldm_classes.Location")
    @patch("flexstack.facilities.local_dynamic_map.ldm_classes.TimestampIts")
    def test_reception_callback(
        self,
        mock_timestamp,
        mock_location,
        mock_time_validity,
        mock_add_data_provider_req,
    ):
        btp_indication_mock = MagicMock()
        btp_indication_mock.data = "test"
        btp_indication_mock.gn_its_aid = None
        self.reception_management.reception_callback(btp_indication_mock)
        self.vru_service_ldm_adaptation.add_provider_data_to_ldm.assert_called_once()


if __name__ == "__main__":
    unittest.main()
