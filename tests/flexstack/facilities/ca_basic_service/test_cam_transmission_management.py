import threading
import unittest
from unittest.mock import MagicMock, patch, call


from flexstack.facilities.ca_basic_service.cam_transmission_management import (
    GenerationDeltaTime,
    CAMTransmissionManagement,
    CooperativeAwarenessMessage,
    VehicleData,
    T_GEN_CAM_MIN,
    T_GEN_CAM_MAX,
    T_GEN_CAM_DCC,
    N_GEN_CAM_DEFAULT,
    T_GEN_CAM_LF_MS,
    T_GEN_CAM_SPECIAL_MS,
    T_GEN_CAM_VLF_MS,
    TWO_WHEELER_STATION_TYPES,
    _haversine_m,
)
from flexstack.facilities.ca_basic_service.cam_coder import CAMCoder


# ---------------------------------------------------------------------------
# Helpers shared across test classes
# ---------------------------------------------------------------------------

def _make_vehicle_data(**kwargs):
    defaults = dict(
        station_id=1,
        station_type=5,
        drive_direction="forward",
        vehicle_length={
            "vehicleLengthValue": 50,
            "vehicleLengthConfidenceIndication": "unavailable",
        },
        vehicle_width=30,
    )
    defaults.update(kwargs)
    return VehicleData(**defaults)


def _make_tpv(lat=41.0, lon=2.0, track=90.0, speed=5.0):
    return {
        "lat": lat,
        "lon": lon,
        "track": track,
        "speed": speed,
        "time": "2020-01-01T00:00:00Z",
    }


def _make_ctm(vehicle_data=None, ldm=None):
    btp_router = MagicMock()
    cam_coder = MagicMock()
    cam_coder.encode.return_value = b"\x00" * 10
    cam_coder.encode_extension_container.return_value = b"\x00"
    if vehicle_data is None:
        vehicle_data = _make_vehicle_data()
    ctm = CAMTransmissionManagement(btp_router, cam_coder, vehicle_data, ldm)
    return ctm, btp_router, cam_coder, vehicle_data


# ---------------------------------------------------------------------------
# TestGenerationDeltaTime — unchanged
# ---------------------------------------------------------------------------

class TestGenerationDeltaTime(unittest.TestCase):

    def test_set_in_normal_timestamp(self):
        timestamp = 1675871599
        generation_delta_time = GenerationDeltaTime.from_timestamp(timestamp)
        self.assertEqual(generation_delta_time.msec,
                         (((timestamp * 1000) - 1072915200000 + 5000) % 65536))

    def test_as_timestamp_in_certain_point(self):
        timestamp = 1755763553.722
        reception_timestamp_millis = (timestamp + 0.3) * 1000
        generation_delta_time = GenerationDeltaTime.from_timestamp(timestamp)
        self.assertEqual(
            generation_delta_time.as_timestamp_in_certain_point(
                int(reception_timestamp_millis)
            ),
            timestamp * 1000,
        )

    def test__gt__(self):
        ts1 = GenerationDeltaTime.from_timestamp(1675871599)
        ts2 = GenerationDeltaTime.from_timestamp(1675871600)
        self.assertTrue(ts2 > ts1)
        self.assertFalse(ts1 > ts2)

    def test__lt__(self):
        ts1 = GenerationDeltaTime.from_timestamp(1675871599)
        ts2 = GenerationDeltaTime.from_timestamp(1675871600)
        self.assertTrue(ts1 < ts2)
        self.assertFalse(ts2 < ts1)

    def test__ge__(self):
        ts1 = GenerationDeltaTime.from_timestamp(1675871599)
        ts2 = GenerationDeltaTime.from_timestamp(1675871600)
        self.assertTrue(ts1 >= ts1)
        self.assertTrue(ts2 >= ts1)
        self.assertFalse(ts1 >= ts2)

    def test__le__(self):
        ts1 = GenerationDeltaTime.from_timestamp(1675871599)
        ts2 = GenerationDeltaTime.from_timestamp(1675871600)
        self.assertTrue(ts1 <= ts1)
        self.assertTrue(ts1 <= ts2)
        self.assertFalse(ts2 <= ts1)

    def test__add__(self):
        gdt = GenerationDeltaTime.from_timestamp(1675871599)
        result = gdt + GenerationDeltaTime(msec=30)
        self.assertEqual(result, (gdt.msec + 30) % 65536)

    def test__sub__(self):
        gdt1 = GenerationDeltaTime(msec=20)
        gdt2 = GenerationDeltaTime(msec=30)
        self.assertEqual(gdt1 - gdt2, -10 + 65536)


# ---------------------------------------------------------------------------
# TestCooperativeAwarenessMessage — unchanged
# ---------------------------------------------------------------------------

class TestCooperativeAwarenessMessage(unittest.TestCase):

    def __init__(self, methodName: str = ...) -> None:
        super().__init__(methodName)
        self.coder = CAMCoder()

    def test__init__(self):
        cam = CooperativeAwarenessMessage()
        encoded = self.coder.encode(cam.cam)
        expected = (
            b'\x02\x02\x00\x00\x00\x00\x00\x00\x00\ri:@:\xd2t\x80'
            b'?\xff\xff\xfc#\xb7t>\x00\xe1\x1f\xdf\xff\xfe\xbf\xe9'
            b'\xed\x077\xfe\xeb\xff\xf6\x00'
        )
        self.assertEqual(encoded, expected)

    def test_fullfill_with_vehicle_data(self):
        vd = _make_vehicle_data()
        cam = CooperativeAwarenessMessage()
        cam.fullfill_with_vehicle_data(vd)
        params = cam.cam["cam"]["camParameters"]
        self.assertEqual(cam.cam["header"]["stationId"], vd.station_id)
        self.assertEqual(params["basicContainer"]["stationType"], vd.station_type)
        self.assertEqual(
            params["highFrequencyContainer"][1]["driveDirection"],
            vd.drive_direction,
        )
        self.assertEqual(
            params["highFrequencyContainer"][1]["vehicleLength"]["vehicleLengthValue"],
            vd.vehicle_length["vehicleLengthValue"],
        )
        self.assertEqual(params["highFrequencyContainer"][1]["vehicleWidth"], vd.vehicle_width)

    def test_fullfill_with_tpv_data(self):
        tpv = {
            "class": "TPV", "device": "/dev/ttyACM0", "mode": 3,
            "time": "2020-03-13T13:01:14.000Z", "ept": 0.005,
            "lat": 41.453606167, "lon": 2.073707333, "alt": 163.500,
            "epx": 8.754, "epy": 10.597, "epv": 31.970,
            "track": 0.0000, "speed": 0.011, "climb": 0.000, "eps": 0.57,
        }
        cam = CooperativeAwarenessMessage()
        cam.fullfill_with_tpv_data(tpv)
        self.assertEqual(cam.cam["cam"]["generationDeltaTime"], 24856)
        pos = cam.cam["cam"]["camParameters"]["basicContainer"]["referencePosition"]
        self.assertEqual(pos["latitude"], int(tpv["lat"] * 10000000))
        self.assertEqual(pos["longitude"], int(tpv["lon"] * 10000000))


# ---------------------------------------------------------------------------
# TestVehicleData — new fields
# ---------------------------------------------------------------------------

class TestVehicleData(unittest.TestCase):

    def test_default_new_fields(self):
        vd = VehicleData()
        self.assertEqual(vd.vehicle_role, 0)
        self.assertEqual(vd.exterior_lights, b"\x00")
        self.assertIsNone(vd.special_vehicle_data)

    def test_invalid_vehicle_role_raises(self):
        with self.assertRaises(ValueError):
            VehicleData(vehicle_role=16)
        with self.assertRaises(ValueError):
            VehicleData(vehicle_role=-1)

    def test_invalid_exterior_lights_raises(self):
        with self.assertRaises(ValueError):
            VehicleData(exterior_lights=b"")

    def test_valid_non_default_role(self):
        vd = VehicleData(vehicle_role=6, exterior_lights=b"\x80")
        self.assertEqual(vd.vehicle_role, 6)
        self.assertEqual(vd.exterior_lights, b"\x80")


# ---------------------------------------------------------------------------
# TestHaversine
# ---------------------------------------------------------------------------

class TestHaversine(unittest.TestCase):

    def test_zero_distance(self):
        self.assertAlmostEqual(_haversine_m(41.0, 2.0, 41.0, 2.0), 0.0, places=3)

    def test_known_distance_approx(self):
        # ~5 m north at latitude 41°
        d = _haversine_m(41.0, 2.0, 41.000045, 2.0)
        self.assertGreater(d, 4.5)
        self.assertLess(d, 5.5)

    def test_direction_symmetry(self):
        d1 = _haversine_m(41.0, 2.0, 41.001, 2.001)
        d2 = _haversine_m(41.001, 2.001, 41.0, 2.0)
        self.assertAlmostEqual(d1, d2, places=6)


# ---------------------------------------------------------------------------
# TestCAMTransmissionManagementInit
# ---------------------------------------------------------------------------

class TestCAMTransmissionManagementInit(unittest.TestCase):

    def test_t_gen_cam_starts_at_max(self):
        """§6.1.3: T_GenCam default = T_GenCamMax."""
        ctm, _, _, _ = _make_ctm()
        self.assertEqual(ctm.t_gen_cam, T_GEN_CAM_MAX)

    def test_not_active_on_init(self):
        ctm, _, _, _ = _make_ctm()
        self.assertFalse(ctm._active)

    def test_cam_count_zero_on_init(self):
        ctm, _, _, _ = _make_ctm()
        self.assertEqual(ctm._cam_count, 0)

    def test_last_cam_time_none_on_init(self):
        ctm, _, _, _ = _make_ctm()
        self.assertIsNone(ctm._last_cam_time_ms)


# ---------------------------------------------------------------------------
# TestStartStop — §6.1.2
# ---------------------------------------------------------------------------

class TestStartStop(unittest.TestCase):

    def test_start_sets_active(self):
        ctm, _, _, _ = _make_ctm()
        with patch(
            "flexstack.facilities.ca_basic_service.cam_transmission_management.threading.Timer"
        ) as mock_timer_cls:
            mock_timer_cls.return_value = MagicMock()
            ctm.start()
            self.assertTrue(ctm._active)

    def test_start_schedules_timer(self):
        ctm, _, _, _ = _make_ctm()
        with patch(
            "flexstack.facilities.ca_basic_service.cam_transmission_management.threading.Timer"
        ) as mock_timer_cls:
            mock_inst = MagicMock()
            mock_timer_cls.return_value = mock_inst
            ctm.start()
            mock_timer_cls.assert_called_once()
            mock_inst.start.assert_called_once()

    def test_stop_clears_active(self):
        ctm, _, _, _ = _make_ctm()
        with patch(
            "flexstack.facilities.ca_basic_service.cam_transmission_management.threading.Timer"
        ) as mock_timer_cls:
            mock_timer_cls.return_value = MagicMock()
            ctm.start()
        ctm.stop()
        self.assertFalse(ctm._active)

    def test_stop_cancels_timer(self):
        ctm, _, _, _ = _make_ctm()
        mock_timer = MagicMock()
        ctm._timer = mock_timer
        ctm._active = True
        ctm.stop()
        mock_timer.cancel.assert_called_once()
        self.assertIsNone(ctm._timer)

    def test_start_resets_cam_count(self):
        ctm, _, _, _ = _make_ctm()
        ctm._cam_count = 5
        with patch(
            "flexstack.facilities.ca_basic_service.cam_transmission_management.threading.Timer"
        ) as mock_timer_cls:
            mock_timer_cls.return_value = MagicMock()
            ctm.start()
        self.assertEqual(ctm._cam_count, 0)

    def test_double_start_is_idempotent(self):
        ctm, _, _, _ = _make_ctm()
        call_count = []
        with patch(
            "flexstack.facilities.ca_basic_service.cam_transmission_management.threading.Timer"
        ) as mock_timer_cls:
            mock_timer_cls.return_value = MagicMock()
            ctm.start()
            ctm.start()  # second start should be a no-op
        self.assertEqual(mock_timer_cls.call_count, 1)


# ---------------------------------------------------------------------------
# TestLocationServiceCallback
# ---------------------------------------------------------------------------

class TestLocationServiceCallback(unittest.TestCase):

    def test_callback_updates_current_tpv(self):
        """location_service_callback only caches the TPV (§6.1.3)."""
        ctm, _, _, _ = _make_ctm()
        tpv = _make_tpv()
        ctm.location_service_callback(tpv)
        self.assertEqual(ctm._current_tpv, tpv)

    def test_callback_does_not_trigger_send(self):
        """Callback must NOT directly trigger CAM transmission."""
        ctm, btp_router, _, _ = _make_ctm()
        tpv = _make_tpv()
        ctm.location_service_callback(tpv)
        btp_router.btp_data_request.assert_not_called()


# ---------------------------------------------------------------------------
# TestSendCam
# ---------------------------------------------------------------------------

class TestSendCam(unittest.TestCase):

    def test_send_cam_encodes_and_calls_btp(self):
        ctm, btp_router, cam_coder, _ = _make_ctm()
        cam = CooperativeAwarenessMessage()
        ctm._send_cam(cam)
        cam_coder.encode.assert_called_with(cam.cam)
        btp_router.btp_data_request.assert_called_once()

    def test_send_cam_sets_gn_max_packet_lifetime(self):
        """§5.3.4.1: GN max packet lifetime shall not exceed 1000 ms."""
        ctm, btp_router, cam_coder, _ = _make_ctm()
        cam = CooperativeAwarenessMessage()
        ctm._send_cam(cam)
        request = btp_router.btp_data_request.call_args[0][0]
        self.assertEqual(request.gn_max_packet_lifetime, 1.0)

    def test_send_cam_destination_port_2001(self):
        """§5.3.4.1: destination port shall be 2001."""
        ctm, btp_router, _, _ = _make_ctm()
        ctm._send_cam(CooperativeAwarenessMessage())
        request = btp_router.btp_data_request.call_args[0][0]
        self.assertEqual(request.destination_port, 2001)

    def test_send_cam_updates_ldm_if_present(self):
        ldm = MagicMock()
        ctm, _, _, _ = _make_ctm(ldm=ldm)
        ctm._send_cam(CooperativeAwarenessMessage())
        ldm.add_provider_data_to_ldm.assert_called_once()


# ---------------------------------------------------------------------------
# TestCheckDynamics — §6.1.3 Condition 1
# ---------------------------------------------------------------------------

class TestCheckDynamics(unittest.TestCase):

    def _ctm_with_last_cam(self, heading, lat, lon, speed):
        ctm, _, _, _ = _make_ctm()
        ctm._last_cam_heading = heading
        ctm._last_cam_lat = lat
        ctm._last_cam_lon = lon
        ctm._last_cam_speed = speed
        return ctm

    def test_no_previous_data_returns_true(self):
        ctm, _, _, _ = _make_ctm()
        # _last_cam_heading is None → True
        self.assertTrue(ctm._check_dynamics(_make_tpv()))

    def test_heading_diff_over_4_deg_returns_true(self):
        ctm = self._ctm_with_last_cam(90.0, 41.0, 2.0, 5.0)
        self.assertTrue(ctm._check_dynamics(_make_tpv(track=95.0)))

    def test_heading_diff_under_4_deg_returns_false(self):
        ctm = self._ctm_with_last_cam(90.0, 41.0, 2.0, 5.0)
        self.assertFalse(ctm._check_dynamics(_make_tpv(track=93.0, lat=41.0, lon=2.0, speed=5.0)))

    def test_heading_wrap_around_360(self):
        ctm = self._ctm_with_last_cam(358.0, 41.0, 2.0, 5.0)
        # 2 - 358 ... wraps to 4° difference exactly; 5° should trigger
        self.assertTrue(ctm._check_dynamics(_make_tpv(track=3.0, lat=41.0, lon=2.0, speed=5.0)))

    def test_position_diff_over_4m_returns_true(self):
        ctm = self._ctm_with_last_cam(90.0, 41.0, 2.0, 5.0)
        # Shift ~5 m north
        tpv = _make_tpv(lat=41.000045, lon=2.0, track=90.0, speed=5.0)
        self.assertTrue(ctm._check_dynamics(tpv))

    def test_position_diff_under_4m_no_other_change(self):
        ctm = self._ctm_with_last_cam(90.0, 41.0, 2.0, 5.0)
        # 1 m shift
        tpv = _make_tpv(lat=41.000009, lon=2.0, track=90.0, speed=5.0)
        self.assertFalse(ctm._check_dynamics(tpv))

    def test_speed_diff_over_half_ms_returns_true(self):
        ctm = self._ctm_with_last_cam(90.0, 41.0, 2.0, 5.0)
        tpv = _make_tpv(speed=5.6, lat=41.0, lon=2.0, track=90.0)
        self.assertTrue(ctm._check_dynamics(tpv))

    def test_speed_diff_under_half_ms_no_other_change(self):
        ctm = self._ctm_with_last_cam(90.0, 41.0, 2.0, 5.0)
        tpv = _make_tpv(speed=5.4, lat=41.0, lon=2.0, track=90.0)
        self.assertFalse(ctm._check_dynamics(tpv))


# ---------------------------------------------------------------------------
# TestContainerInclusion — §6.1.3 optional containers
# ---------------------------------------------------------------------------

class TestContainerInclusion(unittest.TestCase):

    # --- Low Frequency Container ---

    def test_lf_on_first_cam(self):
        ctm, _, _, _ = _make_ctm()
        self.assertEqual(ctm._cam_count, 0)
        self.assertTrue(ctm._should_include_lf(1000))

    def test_lf_after_500ms(self):
        ctm, _, _, _ = _make_ctm()
        ctm._cam_count = 1
        ctm._last_lf_time_ms = 500
        self.assertTrue(ctm._should_include_lf(1000))   # elapsed = 500 ms ≥ 500 ms

    def test_lf_not_before_500ms(self):
        ctm, _, _, _ = _make_ctm()
        ctm._cam_count = 1
        ctm._last_lf_time_ms = 600
        self.assertFalse(ctm._should_include_lf(1000))  # elapsed = 400 ms < 500 ms

    # --- Special Vehicle Container ---

    def test_special_not_included_for_default_role(self):
        ctm, _, _, _ = _make_ctm(vehicle_data=_make_vehicle_data(vehicle_role=0))
        self.assertFalse(ctm._should_include_special_vehicle(1000))

    def test_special_on_first_cam_non_default_role(self):
        ctm, _, _, _ = _make_ctm(vehicle_data=_make_vehicle_data(vehicle_role=6))
        ctm._cam_count = 0
        self.assertTrue(ctm._should_include_special_vehicle(1000))

    def test_special_after_500ms(self):
        ctm, _, _, _ = _make_ctm(vehicle_data=_make_vehicle_data(vehicle_role=6))
        ctm._cam_count = 1
        ctm._last_special_time_ms = 400
        self.assertTrue(ctm._should_include_special_vehicle(900))   # 500 ms elapsed

    def test_special_not_before_500ms(self):
        ctm, _, _, _ = _make_ctm(vehicle_data=_make_vehicle_data(vehicle_role=6))
        ctm._cam_count = 1
        ctm._last_special_time_ms = 700
        self.assertFalse(ctm._should_include_special_vehicle(900))  # 200 ms elapsed

    # --- Very Low Frequency Container ---

    def test_vlf_on_second_cam(self):
        ctm, _, _, _ = _make_ctm()
        ctm._cam_count = 1  # second CAM about to be sent
        self.assertTrue(ctm._should_include_vlf(1000, False, False))

    def test_vlf_not_on_first_cam(self):
        ctm, _, _, _ = _make_ctm()
        ctm._cam_count = 0
        self.assertFalse(ctm._should_include_vlf(1000, False, False))

    def test_vlf_after_10s_no_lf_no_special(self):
        ctm, _, _, _ = _make_ctm()
        ctm._cam_count = 5
        ctm._last_vlf_time_ms = 0
        self.assertTrue(ctm._should_include_vlf(10001, False, False))

    def test_vlf_not_if_lf_included(self):
        ctm, _, _, _ = _make_ctm()
        ctm._cam_count = 5
        ctm._last_vlf_time_ms = 0
        self.assertFalse(ctm._should_include_vlf(10001, include_lf=True, include_special=False))

    def test_vlf_not_if_special_included(self):
        ctm, _, _, _ = _make_ctm()
        ctm._cam_count = 5
        ctm._last_vlf_time_ms = 0
        self.assertFalse(ctm._should_include_vlf(10001, include_lf=False, include_special=True))

    def test_vlf_not_before_10s(self):
        ctm, _, _, _ = _make_ctm()
        ctm._cam_count = 5
        ctm._last_vlf_time_ms = 0
        self.assertFalse(ctm._should_include_vlf(9999, False, False))

    # --- Two-Wheeler Container ---

    def test_two_wheeler_for_cyclist(self):
        ctm, _, _, _ = _make_ctm(vehicle_data=_make_vehicle_data(station_type=2))
        self.assertTrue(ctm._should_include_two_wheeler())

    def test_two_wheeler_for_moped(self):
        ctm, _, _, _ = _make_ctm(vehicle_data=_make_vehicle_data(station_type=3))
        self.assertTrue(ctm._should_include_two_wheeler())

    def test_two_wheeler_for_motorcycle(self):
        ctm, _, _, _ = _make_ctm(vehicle_data=_make_vehicle_data(station_type=4))
        self.assertTrue(ctm._should_include_two_wheeler())

    def test_two_wheeler_not_for_passenger_car(self):
        ctm, _, _, _ = _make_ctm(vehicle_data=_make_vehicle_data(station_type=5))
        self.assertFalse(ctm._should_include_two_wheeler())


# ---------------------------------------------------------------------------
# TestGenerateAndSendCam — CAM building, containers, state update
# ---------------------------------------------------------------------------

class TestGenerateAndSendCam(unittest.TestCase):

    def _ctm_with_send_capture(self, vehicle_data=None):
        ctm, btp_router, cam_coder, vd = _make_ctm(vehicle_data=vehicle_data)
        sent = []
        def capture(cam_obj):
            sent.append(cam_obj)
        ctm._send_cam = capture
        return ctm, sent, cam_coder, vd

    @patch("flexstack.facilities.ca_basic_service.cam_transmission_management.TimeService.time",
           return_value=1000.0)
    def test_first_cam_includes_lf_container(self, _mock_time):
        ctm, sent, _, _ = self._ctm_with_send_capture()
        tpv = _make_tpv()
        ctm._generate_and_send_cam(tpv, 1_000_000, condition=1)
        self.assertEqual(len(sent), 1)
        params = sent[0].cam["cam"]["camParameters"]
        self.assertIn("lowFrequencyContainer", params)

    @patch("flexstack.facilities.ca_basic_service.cam_transmission_management.TimeService.time",
           return_value=1000.0)
    def test_lf_container_content(self, _mock_time):
        ctm, sent, _, _ = self._ctm_with_send_capture(
            vehicle_data=_make_vehicle_data(vehicle_role=0, exterior_lights=b"\x80")
        )
        tpv = _make_tpv()
        ctm._generate_and_send_cam(tpv, 1_000_000, condition=1)
        lf_choice, lf_data = sent[0].cam["cam"]["camParameters"]["lowFrequencyContainer"]
        self.assertEqual(lf_choice, "basicVehicleContainerLowFrequency")
        self.assertEqual(lf_data["vehicleRole"], "default")
        self.assertEqual(lf_data["exteriorLights"], (b"\x80", 8))

    @patch("flexstack.facilities.ca_basic_service.cam_transmission_management.TimeService.time",
           return_value=1000.0)
    def test_second_cam_includes_vlf_extension_container(self, _mock_time):
        ctm, sent, cam_coder, _ = self._ctm_with_send_capture()
        ctm._cam_count = 1   # about to send second CAM
        ctm._last_cam_time_ms = 999_000
        ctm._last_cam_heading = 90.0
        ctm._last_cam_lat = 41.0
        ctm._last_cam_lon = 2.0
        ctm._last_cam_speed = 5.0
        ctm._last_lf_time_ms = 500_000  # LF not due yet
        tpv = _make_tpv()
        ctm._generate_and_send_cam(tpv, 1_000_000, condition=2)
        params = sent[0].cam["cam"]["camParameters"]
        ext = params.get("extensionContainers", [])
        container_ids = [e["containerId"] for e in ext]
        self.assertIn(3, container_ids)   # VLF = container id 3

    @patch("flexstack.facilities.ca_basic_service.cam_transmission_management.TimeService.time",
           return_value=1000.0)
    def test_two_wheeler_extension_container_in_every_cam(self, _mock_time):
        vd = _make_vehicle_data(station_type=2)  # cyclist
        ctm, sent, cam_coder, _ = self._ctm_with_send_capture(vehicle_data=vd)
        ctm._cam_count = 5
        ctm._last_cam_time_ms = 0
        ctm._last_lf_time_ms = 999_600  # LF recently sent
        tpv = _make_tpv()
        ctm._generate_and_send_cam(tpv, 1_000_000, condition=2)
        ext = sent[0].cam["cam"]["camParameters"].get("extensionContainers", [])
        container_ids = [e["containerId"] for e in ext]
        self.assertIn(1, container_ids)  # TwoWheeler = container id 1

    @patch("flexstack.facilities.ca_basic_service.cam_transmission_management.TimeService.time",
           return_value=1000.0)
    def test_special_vehicle_container_included(self, _mock_time):
        vd = _make_vehicle_data(
            vehicle_role=6,
            special_vehicle_data=("emergencyContainer", {
                "lightBarSirenInUse": (b"\x00", 8),
            }),
        )
        ctm, sent, _, _ = self._ctm_with_send_capture(vehicle_data=vd)
        ctm._generate_and_send_cam(_make_tpv(), 1_000_000, condition=1)
        params = sent[0].cam["cam"]["camParameters"]
        self.assertIn("specialVehicleContainer", params)

    @patch("flexstack.facilities.ca_basic_service.cam_transmission_management.TimeService.time",
           return_value=1000.0)
    def test_cam_count_increments_after_send(self, _mock_time):
        ctm, _, _, _ = _make_ctm()
        ctm._send_cam = MagicMock()
        self.assertEqual(ctm._cam_count, 0)
        ctm._generate_and_send_cam(_make_tpv(), 1_000_000, condition=1)
        self.assertEqual(ctm._cam_count, 1)

    @patch("flexstack.facilities.ca_basic_service.cam_transmission_management.TimeService.time",
           return_value=1000.0)
    def test_last_cam_time_updated_after_send(self, _mock_time):
        ctm, _, _, _ = _make_ctm()
        ctm._send_cam = MagicMock()
        ctm._generate_and_send_cam(_make_tpv(), 1_000_500, condition=1)
        self.assertEqual(ctm._last_cam_time_ms, 1_000_500)

    @patch("flexstack.facilities.ca_basic_service.cam_transmission_management.TimeService.time",
           return_value=1000.0)
    def test_dynamics_state_updated_after_send(self, _mock_time):
        ctm, _, _, _ = _make_ctm()
        ctm._send_cam = MagicMock()
        tpv = _make_tpv(lat=41.5, lon=2.5, track=135.0, speed=10.0)
        ctm._generate_and_send_cam(tpv, 1_000_000, condition=1)
        self.assertAlmostEqual(ctm._last_cam_heading, 135.0)
        self.assertAlmostEqual(ctm._last_cam_lat, 41.5)
        self.assertAlmostEqual(ctm._last_cam_lon, 2.5)
        self.assertAlmostEqual(ctm._last_cam_speed, 10.0)


# ---------------------------------------------------------------------------
# TestAnnexB25ConstructionException
# ---------------------------------------------------------------------------

class TestAnnexB25ConstructionException(unittest.TestCase):

    @patch("flexstack.facilities.ca_basic_service.cam_transmission_management.TimeService.time",
           return_value=1000.0)
    def test_encode_exception_skips_state_update(self, _mock_time):
        """Annex B.2.5: on construction/encoding failure, state must NOT be updated."""
        ctm, btp_router, cam_coder, _ = _make_ctm()
        cam_coder.encode.side_effect = ValueError("encode error")
        initial_cam_count = ctm._cam_count

        ctm._generate_and_send_cam(_make_tpv(), 1_000_000, condition=1)

        # State must remain unchanged
        self.assertEqual(ctm._cam_count, initial_cam_count)
        self.assertIsNone(ctm._last_cam_time_ms)
        btp_router.btp_data_request.assert_not_called()


# ---------------------------------------------------------------------------
# TestTGenCamManagement — §6.1.3 T_GenCam state machine
# ---------------------------------------------------------------------------

class TestTGenCamManagement(unittest.TestCase):

    def _ctm_with_prior_cam(self, last_cam_time_ms=0):
        ctm, _, _, _ = _make_ctm()
        ctm._send_cam = MagicMock()
        # Simulate one previous CAM
        ctm._last_cam_time_ms = last_cam_time_ms
        ctm._last_cam_heading = 90.0
        ctm._last_cam_lat = 41.0
        ctm._last_cam_lon = 2.0
        ctm._last_cam_speed = 5.0
        ctm._cam_count = 1
        ctm._last_lf_time_ms = last_cam_time_ms
        return ctm

    @patch("flexstack.facilities.ca_basic_service.cam_transmission_management.TimeService.time",
           return_value=1.5)
    def test_condition1_sets_t_gen_cam_to_elapsed(self, _mock_time):
        """§6.1.3: condition-1 CAM sets T_GenCam = elapsed time."""
        ctm = self._ctm_with_prior_cam(last_cam_time_ms=1000)
        # elapsed = 1500 - 1000 = 500 ms
        ctm._generate_and_send_cam(_make_tpv(), 1500, condition=1)
        self.assertEqual(ctm.t_gen_cam, 500)

    @patch("flexstack.facilities.ca_basic_service.cam_transmission_management.TimeService.time",
           return_value=2.0)
    def test_condition2_resets_t_gen_cam_to_max(self, _mock_time):
        """§6.1.3: condition-2 CAM resets T_GenCam to T_GenCamMax."""
        ctm = self._ctm_with_prior_cam(last_cam_time_ms=0)
        ctm.t_gen_cam = 400  # artificially lowered
        ctm._generate_and_send_cam(_make_tpv(), 2000, condition=2)
        self.assertEqual(ctm.t_gen_cam, T_GEN_CAM_MAX)

    @patch("flexstack.facilities.ca_basic_service.cam_transmission_management.TimeService.time",
           return_value=2.0)
    def test_n_gen_cam_resets_after_default_consecutive(self, _mock_time):
        """
        §6.1.3: after N_GenCam consecutive condition-1 CAMs,
        T_GenCam is reset to T_GenCamMax and the counter is reset.
        """
        ctm = self._ctm_with_prior_cam(last_cam_time_ms=0)
        ctm._n_gen_cam_counter = N_GEN_CAM_DEFAULT - 1  # one short of reset

        # Elapsed = 2000 ms (clamped to T_GEN_CAM_MAX)
        ctm._generate_and_send_cam(_make_tpv(), 2000, condition=1)

        # Counter reached N_GenCam → reset
        self.assertEqual(ctm.t_gen_cam, T_GEN_CAM_MAX)
        self.assertEqual(ctm._n_gen_cam_counter, 0)

    @patch("flexstack.facilities.ca_basic_service.cam_transmission_management.TimeService.time",
           return_value=2.0)
    def test_t_gen_cam_clamped_to_min(self, _mock_time):
        """T_GenCam must not go below T_GenCamMin."""
        ctm = self._ctm_with_prior_cam(last_cam_time_ms=1950)
        # elapsed = 2000 - 1950 = 50 ms < T_GenCamMin
        ctm._generate_and_send_cam(_make_tpv(), 2000, condition=1)
        self.assertEqual(ctm.t_gen_cam, T_GEN_CAM_MIN)


# ---------------------------------------------------------------------------
# TestEvaluateConditions — §6.1.3 conditions integration
# ---------------------------------------------------------------------------

class TestEvaluateConditions(unittest.TestCase):

    def test_first_cam_sent_when_tpv_available(self):
        ctm, _, _, _ = _make_ctm()
        ctm._send_cam = MagicMock()
        ctm._current_tpv = _make_tpv()
        # No previous CAM → sends immediately
        with patch("flexstack.facilities.ca_basic_service.cam_transmission_management.TimeService.time",
                   return_value=1000.0):
            ctm._evaluate_and_maybe_send()
        ctm._send_cam.assert_called_once()

    def test_no_cam_without_tpv(self):
        ctm, _, _, _ = _make_ctm()
        ctm._send_cam = MagicMock()
        ctm._current_tpv = None
        with patch("flexstack.facilities.ca_basic_service.cam_transmission_management.TimeService.time",
                   return_value=1000.0):
            ctm._evaluate_and_maybe_send()
        ctm._send_cam.assert_not_called()

    def test_condition2_triggers_after_t_gen_cam_elapsed(self):
        ctm, _, _, _ = _make_ctm()
        ctm._send_cam = MagicMock()
        ctm._current_tpv = _make_tpv()
        ctm._last_cam_time_ms = 0
        ctm._last_cam_heading = 90.0
        ctm._last_cam_lat = 41.0
        ctm._last_cam_lon = 2.0
        ctm._last_cam_speed = 5.0
        ctm._cam_count = 1
        ctm._last_lf_time_ms = 0
        ctm.t_gen_cam = T_GEN_CAM_MAX
        # elapsed = 1001 ms ≥ T_GEN_CAM_MAX (1000) → condition 2
        with patch("flexstack.facilities.ca_basic_service.cam_transmission_management.TimeService.time",
                   return_value=1.001):
            ctm._evaluate_and_maybe_send()
        ctm._send_cam.assert_called_once()

    def test_no_cam_before_t_gen_cam_and_no_dynamics(self):
        ctm, _, _, _ = _make_ctm()
        ctm._send_cam = MagicMock()
        ctm._current_tpv = _make_tpv()
        ctm._last_cam_time_ms = 999_000
        ctm._last_cam_heading = 90.0
        ctm._last_cam_lat = 41.0
        ctm._last_cam_lon = 2.0
        ctm._last_cam_speed = 5.0
        ctm._cam_count = 1
        ctm.t_gen_cam = T_GEN_CAM_MAX
        # elapsed = 100 ms < T_GEN_CAM_DCC → no condition satisfied
        with patch("flexstack.facilities.ca_basic_service.cam_transmission_management.TimeService.time",
                   return_value=999.1):
            ctm._evaluate_and_maybe_send()
        ctm._send_cam.assert_not_called()

    def test_condition1_triggers_on_heading_change(self):
        ctm, _, _, _ = _make_ctm()
        ctm._send_cam = MagicMock()
        ctm._current_tpv = _make_tpv(track=96.0)  # 6° change from last
        ctm._last_cam_time_ms = 999_800
        ctm._last_cam_heading = 90.0
        ctm._last_cam_lat = 41.0
        ctm._last_cam_lon = 2.0
        ctm._last_cam_speed = 5.0
        ctm._cam_count = 1
        ctm._last_lf_time_ms = 0
        ctm.t_gen_cam = T_GEN_CAM_MAX
        # elapsed = 100 ms = T_GEN_CAM_DCC, heading diff = 6° > 4° → condition 1
        with patch("flexstack.facilities.ca_basic_service.cam_transmission_management.TimeService.time",
                   return_value=999.9):
            ctm._evaluate_and_maybe_send()
        ctm._send_cam.assert_called_once()


# ---------------------------------------------------------------------------
# TestPathHistory
# ---------------------------------------------------------------------------

class TestPathHistory(unittest.TestCase):

    @patch("flexstack.facilities.ca_basic_service.cam_transmission_management.TimeService.time",
           return_value=1000.0)
    def test_path_history_added_after_send(self, _mock_time):
        ctm, _, _, _ = _make_ctm()
        ctm._send_cam = MagicMock()
        tpv = _make_tpv(lat=41.5, lon=2.5)
        ctm._generate_and_send_cam(tpv, 1_000_000, condition=1)
        self.assertEqual(len(ctm._path_history), 1)
        self.assertAlmostEqual(ctm._path_history[0][0], 41.5)
        self.assertAlmostEqual(ctm._path_history[0][1], 2.5)

    @patch("flexstack.facilities.ca_basic_service.cam_transmission_management.TimeService.time",
           return_value=1000.0)
    def test_get_path_history_returns_relative_delta(self, _mock_time):
        ctm, _, _, _ = _make_ctm()
        # Manually add a history point
        ctm._path_history = [(41.0001, 2.0, 999_000_000)]  # 0.0001° north
        tpv = _make_tpv(lat=41.0, lon=2.0)
        result = ctm._get_path_history(tpv)
        self.assertEqual(len(result), 1)
        # delta_lat = round((41.0001 - 41.0) * 10_000_000) = 1000
        self.assertEqual(result[0]["pathPosition"]["deltaLatitude"], 1000)
        self.assertEqual(result[0]["pathPosition"]["deltaLongitude"], 0)

    @patch("flexstack.facilities.ca_basic_service.cam_transmission_management.TimeService.time",
           return_value=1000.0)
    def test_path_history_empty_without_lat_lon(self, _mock_time):
        ctm, _, _, _ = _make_ctm()
        ctm._path_history = [(41.0, 2.0, 999_000)]
        result = ctm._get_path_history({"track": 90.0})  # no lat/lon
        self.assertEqual(result, [])

    @patch("flexstack.facilities.ca_basic_service.cam_transmission_management.TimeService.time",
           return_value=1000.0)
    def test_path_history_capped_at_23_entries(self, _mock_time):
        ctm, _, _, _ = _make_ctm()
        ctm._path_history = [(41.0 + i * 0.000001, 2.0, 900_000 + i * 1000) for i in range(30)]
        tpv = _make_tpv(lat=41.0, lon=2.0)
        result = ctm._get_path_history(tpv)
        self.assertLessEqual(len(result), 23)


if __name__ == "__main__":
    unittest.main()

