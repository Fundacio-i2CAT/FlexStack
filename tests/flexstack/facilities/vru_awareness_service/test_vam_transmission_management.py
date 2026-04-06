import unittest
from unittest.mock import MagicMock, patch

from typing import Optional

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
from flexstack.facilities.ca_basic_service.cam_transmission_management import (
    GenerationDeltaTime,
)
from flexstack.facilities.vru_awareness_service import vam_constants

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
        self.path_point = PathPoint(41.2, 1.6, 100, 123)

    def test_append(self):
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
        self.path_predicted_point = PathPointPredicted(0.2, 0.6, 10)

    def test_append(self):
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
        device_data_provider = DeviceDataProvider(
            station_id=30,
            station_type=5,
            heading={"value": 3601, "confidence": 127},
            speed={"speedValue": 16383, "speedConfidence": 127},
            longitudinal_acceleration={
                "longitudinalAccelerationValue": 161,
                "longitudinalAccelerationConfidence": 102,
            },
        )

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
        self.btp_router = MagicMock()
        self.vam_coder = MagicMock()
        self.device_data_provider = DeviceDataProvider(
            station_id=30,
            station_type=5,
            heading={"value": 3601, "confidence": 127},
            speed={"speedValue": 16383, "speedConfidence": 127},
            longitudinal_acceleration={
                "longitudinalAccelerationValue": 161,
                "longitudinalAccelerationConfidence": 102,
            },
        )
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
            "epd": 0.000,
            "altHAE": 163.500,
            "track": 0.0000,
            "speed": 0.011,
            "climb": 0.000,
            "eps": 0.57,
        }
        self.vam_transmission_management = VAMTransmissionManagement(
            self.btp_router, self.vam_coder, self.device_data_provider
        )

    def _set_previous_vam_state(
        self,
        generation_delta_time: int = 24855,
        speed: Optional[float] = None,
    ) -> None:
        self.vam_transmission_management.last_vam_generation_delta_time = GenerationDeltaTime(
            msec=generation_delta_time
        )
        self.vam_transmission_management.last_sent_position = (
            self.tpv_data["lat"],
            self.tpv_data["lon"],
        )
        self.vam_transmission_management.last_vam_speed = (
            self.tpv_data["speed"] if speed is None else speed
        )

    def test_location_service_callback_first_sending(self) -> None:
        self.vam_transmission_management.send_next_vam = MagicMock()

        self.vam_transmission_management.location_service_callback(
            self.tpv_data)

        self.vam_transmission_management.send_next_vam.assert_called_once()
        sent_vam: VAMMessage = self.vam_transmission_management.send_next_vam.call_args.kwargs[
            "vam"]
        self.assertIsInstance(sent_vam, VAMMessage)
        self.assertEqual(
            sent_vam.vam["header"]["stationId"],
            self.device_data_provider.station_id,
        )
        self.assertEqual(
            sent_vam.vam["vam"]["vamParameters"]["basicContainer"]["referencePosition"]["latitude"],
            int(self.tpv_data["lat"] * 10000000),
        )

    @patch(
        "flexstack.facilities.vru_awareness_service.vam_transmission_management.Utils.euclidian_distance",
        return_value=0,
    )
    def test_location_service_callback_generation_time_threshold(
        self, _mock_distance: MagicMock
    ) -> None:
        self._set_previous_vam_state(generation_delta_time=0)
        self.vam_transmission_management.t_genvam = vam_constants.T_GENVAMMIN
        self.vam_transmission_management.send_next_vam = MagicMock()

        self.vam_transmission_management.location_service_callback(
            self.tpv_data)

        self.vam_transmission_management.send_next_vam.assert_called_once()

    @patch(
        "flexstack.facilities.vru_awareness_service.vam_transmission_management.Utils.euclidian_distance",
        return_value=0,
    )
    def test_location_service_callback_thresholds_not_met(
        self, _mock_distance: MagicMock
    ) -> None:
        self._set_previous_vam_state()
        self.vam_transmission_management.send_next_vam = MagicMock()

        self.vam_transmission_management.location_service_callback(
            self.tpv_data)

        self.vam_transmission_management.send_next_vam.assert_not_called()

    @patch(
        "flexstack.facilities.vru_awareness_service.vam_transmission_management.Utils.euclidian_distance",
        return_value=vam_constants.MINREFERENCEPOINTPOSITIONCHANGETHRESHOLD + 1,
    )
    def test_location_service_callback_distance_threshold(
        self, _mock_distance: MagicMock
    ) -> None:
        self._set_previous_vam_state()
        self.vam_transmission_management.send_next_vam = MagicMock()

        self.vam_transmission_management.location_service_callback(
            self.tpv_data)

        self.vam_transmission_management.send_next_vam.assert_called_once()

    @patch(
        "flexstack.facilities.vru_awareness_service.vam_transmission_management.Utils.euclidian_distance",
        return_value=0,
    )
    def test_location_service_callback_speed_threshold(
        self, _mock_distance: MagicMock
    ) -> None:
        self._set_previous_vam_state(speed=-1.0)
        self.vam_transmission_management.send_next_vam = MagicMock()

        self.vam_transmission_management.location_service_callback(
            self.tpv_data)

        self.vam_transmission_management.send_next_vam.assert_called_once()

    @patch(
        "flexstack.facilities.vru_awareness_service.vam_transmission_management.Utils.euclidian_distance",
        return_value=0,
    )
    def test_location_service_callback_speed_threshold_not_met(
        self, _mock_distance: MagicMock
    ) -> None:
        self._set_previous_vam_state(speed=0.2)
        self.vam_transmission_management.send_next_vam = MagicMock()

        self.vam_transmission_management.location_service_callback(
            self.tpv_data)

        self.vam_transmission_management.send_next_vam.assert_not_called()

    def test_send_next_vam(self) -> None:
        self.btp_router.btp_data_request = MagicMock()
        self.vam_coder.encode = MagicMock(return_value=b"encoded")
        vam_message = VAMMessage()

        self.vam_transmission_management.send_next_vam(vam_message)

        self.vam_coder.encode.assert_called_once_with(vam_message.vam)
        self.btp_router.btp_data_request.assert_called_once()
        self.assertEqual(
            self.vam_transmission_management.last_vam_generation_delta_time,
            GenerationDeltaTime(
                msec=vam_message.vam["vam"]["generationDeltaTime"]),
        )

    def test_send_next_vam_updates_ldm(self) -> None:
        ldm_adapter = MagicMock()
        manager = VAMTransmissionManagement(
            self.btp_router,
            self.vam_coder,
            self.device_data_provider,
            vru_basic_service_ldm=ldm_adapter,
        )
        self.vam_coder.encode = MagicMock(return_value=b"encoded")
        vam_message = VAMMessage()

        manager.send_next_vam(vam_message)

        ldm_adapter.add_provider_data_to_ldm.assert_called_once_with(
            vam_message.vam)

    # ------------------------------------------------------------------
    # Condition 4: heading-change trigger (clause 6.4.1)
    # ------------------------------------------------------------------

    @patch(
        "flexstack.facilities.vru_awareness_service.vam_transmission_management.Utils.euclidian_distance",
        return_value=0,
    )
    def test_location_service_callback_heading_threshold(
        self, _mock_distance: MagicMock
    ) -> None:
        """A heading change > MINGROUNDVELOCITYORIENTATIONCHANGETHRESHOLD triggers a VAM."""
        self._set_previous_vam_state()
        # Set last heading to 0°; new track is well above the 4° threshold.
        self.vam_transmission_management.last_vam_heading = 0.0
        tpv = dict(self.tpv_data)
        tpv["track"] = vam_constants.MINGROUNDVELOCITYORIENTATIONCHANGETHRESHOLD + 5.0
        self.vam_transmission_management.send_next_vam = MagicMock()

        self.vam_transmission_management.location_service_callback(tpv)

        self.vam_transmission_management.send_next_vam.assert_called_once()

    @patch(
        "flexstack.facilities.vru_awareness_service.vam_transmission_management.Utils.euclidian_distance",
        return_value=0,
    )
    def test_location_service_callback_heading_threshold_not_met(
        self, _mock_distance: MagicMock
    ) -> None:
        """A heading change <= threshold should NOT trigger a VAM on its own."""
        self._set_previous_vam_state()
        self.vam_transmission_management.last_vam_heading = 0.0
        tpv = dict(self.tpv_data)
        tpv["track"] = vam_constants.MINGROUNDVELOCITYORIENTATIONCHANGETHRESHOLD - 1.0
        self.vam_transmission_management.send_next_vam = MagicMock()

        self.vam_transmission_management.location_service_callback(tpv)

        self.vam_transmission_management.send_next_vam.assert_not_called()

    @patch(
        "flexstack.facilities.vru_awareness_service.vam_transmission_management.Utils.euclidian_distance",
        return_value=0,
    )
    def test_heading_wrap_around_360(self, _mock_distance: MagicMock) -> None:
        """Heading diff of 355° vs 5° should resolve to 10°, which is > 4°."""
        self._set_previous_vam_state()
        self.vam_transmission_management.last_vam_heading = 355.0
        tpv = dict(self.tpv_data)
        tpv["track"] = 5.0  # 10° difference across 0°/360° boundary
        self.vam_transmission_management.send_next_vam = MagicMock()

        self.vam_transmission_management.location_service_callback(tpv)

        self.vam_transmission_management.send_next_vam.assert_called_once()

    def test_heading_fields_use_value_and_confidence(self) -> None:
        """VAMMessage heading dict uses 'value'/'confidence', not legacy names."""
        tpv = dict(self.tpv_data)
        tpv["track"] = 180.0
        tpv["epd"] = 5.0
        vam_message = VAMMessage()
        vam_message.fullfill_high_frequency_container_with_tpv_data(tpv)
        heading = vam_message.vam["vam"]["vamParameters"]["vruHighFrequencyContainer"]["heading"]
        self.assertIn("value", heading)
        self.assertIn("confidence", heading)
        self.assertNotIn("headingValue", heading)
        self.assertNotIn("headingConfidence", heading)
        self.assertEqual(heading["value"], int(180.0 * 10))

    def test_send_next_vam_updates_heading_tracking(self) -> None:
        """send_next_vam stores the transmitted heading for future diff checks."""
        self.vam_coder.encode = MagicMock(return_value=b"encoded")
        vam_message = VAMMessage()
        vam_message.vam["vam"]["vamParameters"]["vruHighFrequencyContainer"]["heading"][
            "value"
        ] = 900  # 90.0°
        self.vam_transmission_management.send_next_vam(vam_message)
        self.assertAlmostEqual(
            self.vam_transmission_management.last_vam_heading, 90.0)

    # ------------------------------------------------------------------
    # LF container (clause 6.2)
    # ------------------------------------------------------------------

    def test_lf_container_included_on_first_vam(self) -> None:
        """The VRU Low-Frequency Container must be present in the first VAM."""
        self.vam_coder.encode = MagicMock(return_value=b"encoded")
        vam_message = VAMMessage()
        self.vam_transmission_management.send_next_vam(vam_message)
        self.assertIn(
            "vruLowFrequencyContainer",
            vam_message.vam["vam"]["vamParameters"],
        )

    def test_lf_container_not_included_when_not_due(self) -> None:
        """After first VAM, LF container should NOT be included until T_GenVamLFMin expires."""
        self.vam_coder.encode = MagicMock(return_value=b"encoded")
        # Send first VAM (sets last_lf_vam_time and is_first_vam=False)
        self.vam_transmission_management.send_next_vam(VAMMessage())
        # Immediately send a second VAM — LF timeout has not elapsed
        vam2 = VAMMessage()
        self.vam_transmission_management.send_next_vam(vam2)
        # LF container should be absent on the second VAM
        self.assertNotIn(
            "vruLowFrequencyContainer",
            vam2.vam["vam"]["vamParameters"],
        )

    def test_lf_container_included_after_timeout(self) -> None:
        """LF container re-appears once T_GenVamLFMin has elapsed."""
        import time as _time_module

        self.vam_coder.encode = MagicMock(return_value=b"encoded")
        self.vam_transmission_management.send_next_vam(VAMMessage())
        # Backdate last_lf_vam_time so the timeout has expired
        self.vam_transmission_management.last_lf_vam_time = (
            _time_module.time() - vam_constants.T_GENVAM_LFMIN / 1000.0 - 1.0
        )
        vam2 = VAMMessage()
        self.vam_transmission_management.send_next_vam(vam2)
        self.assertIn(
            "vruLowFrequencyContainer",
            vam2.vam["vam"]["vamParameters"],
        )

    # ------------------------------------------------------------------
    # Clustering integration
    # ------------------------------------------------------------------

    def test_passive_vru_suppresses_transmission(self) -> None:
        """VAM must not be sent when clustering manager says not to transmit."""
        clustering_manager = MagicMock()
        clustering_manager.should_transmit_vam.return_value = False
        manager = VAMTransmissionManagement(
            self.btp_router,
            self.vam_coder,
            self.device_data_provider,
            clustering_manager=clustering_manager,
        )
        manager.send_next_vam = MagicMock()

        manager.location_service_callback(self.tpv_data)

        manager.send_next_vam.assert_not_called()

    def test_cluster_info_container_attached_on_send(self) -> None:
        """Cluster information container from manager is injected into outgoing VAM."""
        clustering_manager = MagicMock()
        clustering_manager.get_cluster_information_container.return_value = {
            "vruClusterInformation": {"clusterId": 7, "clusterCardinalitySize": 3,
                                      "clusterBoundingBoxShape": {"circular": {"radius": 5}}}
        }
        clustering_manager.get_cluster_operation_container.return_value = None
        manager = VAMTransmissionManagement(
            self.btp_router,
            self.vam_coder,
            self.device_data_provider,
            clustering_manager=clustering_manager,
        )
        self.vam_coder.encode = MagicMock(return_value=b"encoded")
        vam_message = VAMMessage()
        manager.send_next_vam(vam_message)
        self.assertIn(
            "vruClusterInformationContainer",
            vam_message.vam["vam"]["vamParameters"],
        )

    def test_cluster_op_container_attached_on_send(self) -> None:
        """Cluster operation container from manager is injected into outgoing VAM."""
        clustering_manager = MagicMock()
        clustering_manager.get_cluster_information_container.return_value = None
        clustering_manager.get_cluster_operation_container.return_value = {
            "clusterJoinInfo": {"clusterId": 5, "joinTime": 10}
        }
        manager = VAMTransmissionManagement(
            self.btp_router,
            self.vam_coder,
            self.device_data_provider,
            clustering_manager=clustering_manager,
        )
        self.vam_coder.encode = MagicMock(return_value=b"encoded")
        vam_message = VAMMessage()
        manager.send_next_vam(vam_message)
        self.assertIn(
            "vruClusterOperationContainer",
            vam_message.vam["vam"]["vamParameters"],
        )


if __name__ == "__main__":
    unittest.main()
