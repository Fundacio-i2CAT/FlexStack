import unittest
from unittest.mock import MagicMock, patch

from flexstack.facilities.vru_awareness_service.vam_transmission_management import (
    VAMMessage,
    VAMTransmissionManagement,
    DeviceDataProvider,
    PathHistory,
    PathPoint,
    PathPrediction,
    PathPointPredicted,
)
from flexstack.facilities.vru_awareness_service.vam_coder import VAMCoder

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


class TestPathHistory(unittest.TestCase):
    def __init__(self, methodName: str = ...):
        super().__init__(methodName)
        # Hardcoded values for testing purposes
        self.path_point = PathPoint(41.2, 1.6, 100, 123)

    def test_append(self):
        # Try to append a path history with a path point more than 40 times and check that the path history is not appended
        path_history = PathHistory()
        for _ in range(0, 44):
            path_history.append(self.path_point)
        self.assertEqual(len(path_history.path_points), 40)

    def test_generate_path_history_message(self):
        path_history = PathHistory()
        path_history.append(self.path_point)
        self.assertEqual(
            path_history.generate_path_history_dict(),
            [
                {
                    "pathPosition": {
                        "latitude": 41.2,
                        "longitude": 1.6,
                        "altitude": 100,
                    },
                    "pathDeltaTime": 123,
                }
            ],
        )


class TestPathPrediction(unittest.TestCase):
    def __init__(self, methodName: str = ...):
        super().__init__(methodName)
        # Hardcoded values for testing purposes
        self.path_predicted_point = PathPointPredicted(0.2, 0.6, 10)

    def test_append(self):
        # Try to append a path prediction with a path point more than 15 times and check that the path prediction is not appended
        path_prediction = PathPrediction()
        for _ in range(0, 22):
            path_prediction.append(self.path_predicted_point)
        self.assertEqual(len(path_prediction.path_point_predicted), 15)

    def test_generate_path_prediction_message(self):
        path_prediction = PathPrediction()
        path_prediction.append(self.path_predicted_point)
        self.assertEqual(
            path_prediction.generate_path_prediction_dict(),
            {
                "pathPointPredicted": [
                    {"deltaLatitude": 0.2, "deltaLongitude": 0.6, "pathDeltaTime": 10}
                ]
            },
        )


class TestVAMMessage(unittest.TestCase):
    def __init__(self, methodName: str = ...) -> None:
        super().__init__(methodName)
        self.coder = VAMCoder()

    def test__init__(self):
        vam_message = VAMMessage()
        encoded_white = self.coder.encode(vam_message.vam)
        expected_vam = b"\x03\x10\x00\x00\x00\x00\x00\x00\x00?ZN\x90\x0e\xb4\x9d \x0f\xff\xff\xff\x08\xed\xdd\x0f\x80\x07\x08\xfe\xff\xff\xf5\x070"
        self.assertEqual(encoded_white, expected_vam)

    def test_fullfill_with_vehicle_data(self):
        device_data_provider = DeviceDataProvider()
        device_data_provider.station_id = 30
        device_data_provider.station_type = 5
        device_data_provider.heading["value"] = "3601"
        device_data_provider.heading["confidence"] = "127"
        device_data_provider.speed["speedValue"] = 16383
        device_data_provider.speed["speedConfidence"] = 127
        device_data_provider.longitudinal_acceleration[
            "longitudinalAccelerationValue"
        ] = 161
        device_data_provider.longitudinal_acceleration[
            "longitudinalAccelerationConfidence"
        ] = 102

        vam_message = VAMMessage()
        vam_message.fullfill_with_device_data(device_data_provider)
        self.assertEqual(
            vam_message.vam["header"]["stationId"], device_data_provider.station_id
        )
        self.assertEqual(
            vam_message.vam["vam"]["vamParameters"]["basicContainer"]["stationType"],
            device_data_provider.station_type,
        )
        self.assertEqual(
            vam_message.vam["vam"]["vamParameters"]["vruHighFrequencyContainer"][
                "heading"
            ]["value"],
            device_data_provider.heading["value"],
        )
        self.assertEqual(
            vam_message.vam["vam"]["vamParameters"]["vruHighFrequencyContainer"][
                "speed"
            ]["speedValue"],
            device_data_provider.speed["speedValue"],
        )
        self.assertEqual(
            vam_message.vam["vam"]["vamParameters"]["vruHighFrequencyContainer"][
                "longitudinalAcceleration"
            ]["longitudinalAccelerationValue"],
            device_data_provider.longitudinal_acceleration[
                "longitudinalAccelerationValue"
            ],
        )

    def test_fullfill_with_tpv_data(self):
        tpv_data = {
            "class": "TPV",
            "device": "/dev/ttyACM0",
            "mode": 3,
            "time": "2020-03-13T13:01:14.000Z",
            "ept": 0.005,
            "lat": 41.453606167,
            "lon": 2.073707333,
            "alt": 163.500,
            "epx": 8.754,
            "epy": 10.597,
            "epv": 31.970,
            "epd": 0.000,
            "altHAE": 163.500,
            "track": 0.0000,
            "speed": 0.011,
            "climb": 0.000,
            "eps": 0.57,
        }
        vam_message = VAMMessage()
        vam_message.fullfill_with_tpv_data(tpv_data)
        self.assertEqual(vam_message.vam["vam"]["generationDeltaTime"], 24856)
        self.assertEqual(
            vam_message.vam["vam"]["vamParameters"]["basicContainer"][
                "referencePosition"
            ]["latitude"],
            int(tpv_data["lat"] * 10000000),
        )
        self.assertEqual(
            vam_message.vam["vam"]["vamParameters"]["basicContainer"][
                "referencePosition"
            ]["longitude"],
            int(tpv_data["lon"] * 10000000),
        )


class TestVAMTransmissionManagement(unittest.TestCase):
    def setUp(self) -> None:
        btp_router = MagicMock()
        vam_coder = MagicMock()
        device_data_provider = DeviceDataProvider()
        device_data_provider.station_id = 30
        device_data_provider.station_type = 5
        device_data_provider.heading["value"] = "3601"
        device_data_provider.heading["confidence"] = "127"
        device_data_provider.speed["speedValue"] = 16383
        device_data_provider.speed["speedConfidence"] = 127
        device_data_provider.longitudinal_acceleration[
            "longitudinalAccelerationValue"
        ] = 161
        device_data_provider.longitudinal_acceleration[
            "longitudinalAccelerationConfidence"
        ] = 102

        self.tpv_data = {
            "class": "TPV",
            "device": "/dev/ttyACM0",
            "mode": 3,
            "time": "2020-03-13T13:01:14.000Z",
            "ept": 0.005,
            "lat": 41.453606167,
            "lon": 2.073707333,
            "alt": 163.500,
            "epx": 8.754,
            "epy": 10.597,
            "epv": 31.970,
            "track": 0.0000,
            "speed": 0.011,
            "climb": 0.000,
            "eps": 0.57,
        }
        self.vam_transmission_management = VAMTransmissionManagement(
            btp_router, vam_coder, device_data_provider
        )
        self.vam_transmission_management.current_vam_to_send.vam = white_vam

    def test_location_service_callback_setup(self):
        """
        Internal function to setup the test.
        """
        self.vam_transmission_management.current_vam_to_send.fullfill_with_tpv_data = (
            MagicMock()
        )
        self.vam_transmission_management.last_vam_sent = (
            self.vam_transmission_management.current_vam_to_send
        )
        self.vam_transmission_management.last_vam_sent.vam["vam"]["vamParameters"][
            "vruHighFrequencyContainer"
        ]["speed"]["speedValue"] = 0.5

    def test_location_service_callback_first_sending(self):
        """
        Tests the location service callback.

        Mocks the call to fullfill_with_tpv_data and checks that the method is called with the correct parameters.
        Mocks the call to send_next_vam and checks that the method is called with the correct parameters.
        """
        self.vam_transmission_management.send_next_vam = MagicMock()

        self.assertIsNone(self.vam_transmission_management.last_vam_sent)
        self.vam_transmission_management.current_vam_to_send.fullfill_with_tpv_data = (
            MagicMock()
        )
        self.vam_transmission_management.location_service_callback(self.tpv_data)
        self.vam_transmission_management.current_vam_to_send.fullfill_with_tpv_data.assert_called_with(
            self.tpv_data
        )
        self.vam_transmission_management.send_next_vam.assert_called_once()

    @patch(
        "flexstack.facilities.local_dynamic_map.ldm_classes.Utils.euclidian_distance"
    )
    def test_location_service_callback_sending_second_vam(
        self, mock_euclidian_distance
    ):
        """
        Tests the location service callback.

        Mocks the call to fullfill_with_tpv_data and checks that the method is called with the correct parameters.
        Mocks the call to send_next_vam and checks that the method is called with the correct parameters.
        """
        self.test_location_service_callback_setup()
        self.vam_transmission_management.send_next_vam = MagicMock()

        mock_euclidian_distance.return_value = 0
        self.vam_transmission_management.t_genvam = 0
        self.vam_transmission_management.location_service_callback(self.tpv_data)
        self.vam_transmission_management.current_vam_to_send.fullfill_with_tpv_data.assert_called_with(
            self.tpv_data
        )
        self.vam_transmission_management.send_next_vam.assert_called_once()

    @patch(
        "flexstack.facilities.local_dynamic_map.ldm_classes.Utils.euclidian_distance"
    )
    def test_location_service_callback_euclidian_distance_not_met(
        self, mock_euclidian_distance
    ):
        """
        Test that the VAM is not sent if the euclidian distance is less than vam_constants.MINREFERENCEPOINTPOSITIONCHANGETHRESHOLD meters
        """
        self.test_location_service_callback_setup()
        self.vam_transmission_management.send_next_vam = MagicMock()
        self.vam_transmission_management.last_vam_sent.vam["vam"]["vamParameters"][
            "basicContainer"
        ]["referencePosition"]["latitude"] = (42.1 * 10000000)

        mock_euclidian_distance.return_value = 0
        self.vam_transmission_management.t_genvam = 500000000000
        self.vam_transmission_management.location_service_callback(self.tpv_data)

        self.vam_transmission_management.send_next_vam.assert_not_called()

    @patch(
        "flexstack.facilities.local_dynamic_map.ldm_classes.Utils.euclidian_distance"
    )
    def test_location_service_callback_euclidian_is_met(self, mock_euclidian_distance):
        """
        Test that the VAM is not sent if the euclidian distance is more than vam_constants.MINREFERENCEPOINTPOSITIONCHANGETHRESHOLD meters
        """
        self.test_location_service_callback_setup()
        self.vam_transmission_management.send_next_vam = MagicMock()

        mock_euclidian_distance.return_value = 5
        self.vam_transmission_management.t_genvam = 500000000000
        self.vam_transmission_management.location_service_callback(self.tpv_data)
        self.vam_transmission_management.current_vam_to_send.fullfill_with_tpv_data.assert_called_with(
            self.tpv_data
        )
        self.vam_transmission_management.send_next_vam.assert_called_once()

    @patch(
        "flexstack.facilities.local_dynamic_map.ldm_classes.Utils.euclidian_distance"
    )
    def test_location_service_callback_euclidian_distance_met(
        self, mock_euclidian_distance
    ):
        """
        Test that the VAM is sent if the euclidian distance is less than vam_constants.MINREFERENCEPOINTPOSITIONCHANGETHRESHOLD meters
        """
        self.test_location_service_callback_setup()
        self.vam_transmission_management.send_next_vam = MagicMock()

        mock_euclidian_distance.return_value = 5
        self.vam_transmission_management.t_genvam = 500000000000
        self.vam_transmission_management.location_service_callback(self.tpv_data)
        self.vam_transmission_management.current_vam_to_send.fullfill_with_tpv_data.assert_called_with(
            self.tpv_data
        )
        self.vam_transmission_management.send_next_vam.assert_called_once()

    @patch(
        "flexstack.facilities.local_dynamic_map.ldm_classes.Utils.euclidian_distance"
    )
    def test_location_service_callback_speed_difference_met(
        self, mock_euclidian_distance
    ):
        """
        Test that the VAM is sent if the difference between tpv[]"speed"] and vam speed are bigger than vam_constants.MINGROUNDSPEEDCHANGETHRESHOLD
        """
        self.test_location_service_callback_setup()
        self.vam_transmission_management.send_next_vam = MagicMock()
        self.vam_transmission_management.last_vam_sent.vam["vam"]["vamParameters"][
            "vruHighFrequencyContainer"
        ]["speed"]["speedValue"] = 3
        mock_euclidian_distance.return_value = 0
        self.vam_transmission_management.t_genvam = 500000000000
        self.vam_transmission_management.location_service_callback(self.tpv_data)
        self.vam_transmission_management.current_vam_to_send.fullfill_with_tpv_data.assert_called_with(
            self.tpv_data
        )
        self.vam_transmission_management.send_next_vam.assert_called_once()

    @patch(
        "flexstack.facilities.local_dynamic_map.ldm_classes.Utils.euclidian_distance"
    )
    def test_location_service_callback_speed_not_met(self, mock_euclidian_distance):
        """
        Test that the VAM is not sent if the difference between tpv[]"speed"] and vam speed is smaller than vam_constants.MINGROUNDSPEEDCHANGETHRESHOLD
        """
        self.test_location_service_callback_setup()
        self.vam_transmission_management.send_next_vam = MagicMock()

        self.vam_transmission_management.last_vam_sent.vam["vam"]["vamParameters"][
            "vruHighFrequencyContainer"
        ]["speed"]["speedValue"] = 0.5

        mock_euclidian_distance.return_value = 3
        self.vam_transmission_management.t_genvam = 500000000000
        self.vam_transmission_management.location_service_callback(self.tpv_data)

        self.vam_transmission_management.current_vam_to_send.fullfill_with_tpv_data.assert_called_with(
            self.tpv_data
        )
        self.vam_transmission_management.send_next_vam.assert_not_called()

    def test_send_next_vam(self):
        btp_router = MagicMock()
        btp_router.btp_data_request = MagicMock()
        vam_coder = MagicMock()
        vam_coder.encode = MagicMock(
            return_value=b"\x03\x10\x00\x00\x00\x00\x00\x00\x00?ZN\x90\x0e\xb4\x9d \x0f\xff\xff\xff\x08\xed\xdd\x0f\x80\x07\x08\xfe\xff\xff\xf5\x070"
        )
        device_data_provider = DeviceDataProvider()
        device_data_provider.station_id = 30
        device_data_provider.station_type = 5
        device_data_provider.heading["value"] = "3601"
        device_data_provider.heading["confidence"] = "127"
        device_data_provider.speed["speedValue"] = 16383
        device_data_provider.speed["speedConfidence"] = 127
        device_data_provider.longitudinal_acceleration[
            "longitudinalAccelerationValue"
        ] = 161
        device_data_provider.longitudinal_acceleration[
            "longitudinalAccelerationConfidence"
        ] = 102

        vam_transmission_management = VAMTransmissionManagement(
            btp_router, vam_coder, device_data_provider
        )
        vam_transmission_management.send_next_vam()
        btp_router.btp_data_request.assert_called()
        vam_coder.encode.assert_called_with(
            vam_transmission_management.current_vam_to_send.vam
        )


if __name__ == "__main__":
    unittest.main()
