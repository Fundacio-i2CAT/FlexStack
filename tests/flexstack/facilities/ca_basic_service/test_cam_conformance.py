"""
CA basic service conformance tests: one test per Test Purpose of
ETSI TS 102 868-2 V2.1.1 (2025-07), against ETSI TS 103 900 V2.3.1 (2026-05).

Each test is named after its TP and quotes the TP identifier, so that a search
for the identifier finds it. The tests drive a complete station (CA basic
service -> BTP -> GeoNetworking -> link layer) and check the frames that
leave the station, decoded from the wire. The CA service clock is injected;
the T_CheckCamGen evaluation is run explicitly at each test instant.

Mirrors ``rustflexstack::facilities::ca_basic_service::conformance``.
"""

import time
import unittest
from unittest.mock import MagicMock, patch

from flexstack.btp.router import Router as BTPRouter
from flexstack.facilities.ca_basic_service.ca_basic_service import CooperativeAwarenessBasicService
from flexstack.facilities.ca_basic_service.cam_coder import CAMCoder
from flexstack.facilities.ca_basic_service.cam_transmission_management import (
    ACCELERATION_CONTROL_BITS,
    EXTERIOR_LIGHTS_BITS,
    T_GEN_CAM_MAX,
    T_GEN_CAM_MIN,
    VehicleData,
)
from flexstack.geonet.basic_header import BasicHeader, BasicNH
from flexstack.geonet.common_header import CommonHeader
from flexstack.geonet.gn_address import MID, GNAddress
from flexstack.geonet.mib import MIB, GnSecurity
from flexstack.geonet.position_vector import TST, LongPositionVector
from flexstack.geonet.router import Router as GNRouter
from flexstack.geonet.service_access_point import CommonNH, HeaderType, TopoBroadcastHST
from flexstack.security.certificate import SECURITY_CODER, OwnCertificate
from flexstack.security.certificate_library import CertificateLibrary
from flexstack.security.ecdsa_backend import PythonECDSABackend
from flexstack.security.sign_service import SignService
from flexstack.security.verify_service import VerifyService
from flexstack.utils.time_service import TimeService

from tests.flexstack.facilities.ca_basic_service.test_cam_ssp import CONTAINERS, SIREN, vehicle
from tests.flexstack.security.test_security_checks import _at_tbs, _ca

CODER = CAMCoder()
_TIME = "flexstack.facilities.ca_basic_service.cam_transmission_management.TimeService.time"
TPV = {"lat": 41.552, "lon": 2.134, "track": 90.0, "speed": 5.0, "time": "2026-01-01T00:00:00Z"}
ROLE_NAMES = {1: "publicTransport", 2: "specialTransport", 3: "dangerousGoods", 4: "roadWork",
              5: "rescue", 6: "emergency", 7: "safetyCar"}
SPECIAL_ROLES = {1: "publicTransportContainer", 2: "specialTransportContainer",
                 3: "dangerousGoodsContainer", 4: "roadWorksContainerBasic",
                 5: "rescueContainer", 6: "emergencyContainer", 7: "safetyCarContainer"}
STATION_CYCLIST, STATION_MOPED, STATION_MOTORCYCLE, STATION_PASSENGER_CAR = 2, 3, 4, 5


def _addr(n):
    return GNAddress(mid=MID(bytes([0x02, 0, 0, 0, 0, n])))


def _bit(bit_string, position):
    """Value of bit ``position`` (0 = MSB) of a decoded BIT STRING (bytes, length)."""
    data, _ = bit_string
    return (data[position // 8] >> (7 - position % 8)) & 1


class _Frame:
    """A GeoNetworking SHB frame carrying a CAM, decoded from the wire."""

    def __init__(self, raw: bytes):
        self.raw = raw
        self.basic = BasicHeader.decode_from_bytes(raw[0:4])
        self.common = CommonHeader.decode_from_bytes(raw[4:12])
        self.so_pv = LongPositionVector.decode(raw[12:36])
        btp = raw[40:44]
        self.destination_port = int.from_bytes(btp[0:2], "big")
        self.destination_port_info = int.from_bytes(btp[2:4], "big")
        self.cam = CODER.decode(raw[44:])           # raises if the CAM is not valid UPER
        self.params = self.cam["cam"]["camParameters"]

    def extension(self, container_id):
        for item in self.params.get("extensionContainers", []):
            if item["containerId"] == container_id:
                return CODER.decode_extension_container(container_id, item["containerData"])
        return None


class _Station:
    """
    A complete ITS-S: CA basic service on BTP on GeoNetworking, with the link
    layer captured. ``at`` (seconds since the start of the test) drives the
    CA service clock; the T_CheckCamGen evaluation runs at each :meth:`tick`.
    """

    def __init__(self, vehicle_data=None, n=1, sign_service=None, verify_service=None):
        self.base = time.time()
        security = GnSecurity.ENABLED if (sign_service or verify_service) else GnSecurity.DISABLED
        mib = MIB(itsGnBeaconServiceRetransmitTimer=0, itsGnLocalGnAddr=_addr(n),
                  itsGnSecurity=security)
        self.gn = GNRouter(mib, sign_service=sign_service, verify_service=verify_service,
                           clock=lambda: int((time.time() - self.base) * 1000))
        self.gn.ego_position_vector = LongPositionVector(
            gn_addr=_addr(n), tst=TST.set_in_normal_timestamp_seconds(time.time()),
            latitude=int(TPV["lat"] * 1e7), longitude=int(TPV["lon"] * 1e7), pai=True)
        self.gn.link_layer = MagicMock()
        self.btp = BTPRouter(self.gn)
        self.gn.register_indication_callback(self.btp.btp_data_indication)
        self.ca = CooperativeAwarenessBasicService(self.btp, vehicle_data or vehicle(0))
        self.btp.freeze_callbacks()
        self.ctm = self.ca.cam_transmission_management
        self.received = []
        self.ca.cam_reception_management.add_application_callback(self.received.append)
        self.ldm = MagicMock()
        self.ca.cam_reception_management.ca_basic_service_ldm = self.ldm
        self.tpv = dict(TPV)
        self.times = []

    def activate(self):
        """CA_Activation (TS 103 900 clause 5.3.1); the timer thread is not used."""
        self.ctm.start()
        if self.ctm._timer is not None:                # pylint: disable=protected-access
            self.ctm._timer.cancel()                   # pylint: disable=protected-access

    def tick(self, at_s, **tpv):
        """Run the T_CheckCamGen evaluation at ``at_s``; returns the new frame, if any."""
        self.tpv.update(tpv)
        self.ctm.location_service_callback(dict(self.tpv))
        before = len(self.sent())
        with patch(_TIME, return_value=self.base + at_s):
            self.ctm._evaluate_and_maybe_send()        # pylint: disable=protected-access
        sent = self.sent()
        if len(sent) > before:
            self.times.append(round(at_s * 1000))
            return _Frame(sent[-1]) if BasicHeader.decode_from_bytes(sent[-1][0:4]).nh == BasicNH.COMMON_HEADER else sent[-1]
        return None

    def sent(self):
        """Raw frames passed to the link layer."""
        return [c[0][0] for c in self.gn.link_layer.send.call_args_list]

    def frames(self):
        return [_Frame(raw) for raw in self.sent()]


class TestCamMessageFormat(unittest.TestCase):
    """TP/CAM/MSD/FMT: CAM format and container inclusion (TS 103 900 clauses 6.1.2, 6.1.3, Annex B)."""

    def test_tp_cam_msd_fmt_bv_01(self):
        """TP/CAM/MSD/FMT/BV-01: protocolVersion 2 and messageID 2 in the ITS PDU header."""
        station = _Station()
        station.activate()
        frame = station.tick(0)
        self.assertEqual(frame.cam["header"]["protocolVersion"], 2)
        self.assertEqual(frame.cam["header"]["messageId"], 2)

    def test_tp_cam_msd_fmt_bv_02(self):
        """TP/CAM/MSD/FMT/BV-02: the first CAM since activation contains the LF container."""
        station = _Station()
        station.activate()
        frame = station.tick(0)
        self.assertEqual(len(station.frames()), 1)
        self.assertIn("lowFrequencyContainer", frame.params)

    def test_tp_cam_msd_fmt_bv_03(self):
        """TP/CAM/MSD/FMT/BV-03: LF container again when >= 500 ms elapsed since the
        last CAM with it (and not before)."""
        station = _Station()
        station.activate()
        self.assertIn("lowFrequencyContainer", station.tick(0).params)          # TIME_1
        for step in range(1, 5):                                                 # 100..400 ms
            frame = station.tick(step * 0.1, track=90.0 + 5 * step)
            self.assertNotIn("lowFrequencyContainer", frame.params)
        frame = station.tick(0.5, track=120.0)                                   # TIME_1 + 500 ms
        self.assertIn("lowFrequencyContainer", frame.params)

    def test_tp_cam_msd_fmt_bv_04(self):
        """TP/CAM/MSD/FMT/BV-04: a special vehicle's first CAM contains the special vehicle container."""
        for role, container in SPECIAL_ROLES.items():
            with self.subTest(role=role):
                station = _Station(vehicle(role, container))
                station.activate()
                frame = station.tick(0)
                self.assertEqual(frame.params["specialVehicleContainer"][0], container)

    def test_tp_cam_msd_fmt_bv_05(self):
        """TP/CAM/MSD/FMT/BV-05: special vehicle container again when >= 500 ms elapsed
        since the last CAM with it (and not before)."""
        station = _Station(vehicle(6, "emergencyContainer"))
        station.activate()
        self.assertIn("specialVehicleContainer", station.tick(0).params)
        for step in range(1, 5):
            frame = station.tick(step * 0.1, track=90.0 + 5 * step)
            self.assertNotIn("specialVehicleContainer", frame.params)
        self.assertIn("specialVehicleContainer", station.tick(0.5, track=120.0).params)

    def test_tp_cam_msd_fmt_bv_06(self):
        """TP/CAM/MSD/FMT/BV-06: the second CAM since activation contains the VLF
        extension container (containerId 3); the first does not."""
        station = _Station()
        station.activate()
        self.assertIsNone(station.tick(0).extension(3))
        frame = station.tick(0.1, track=95.0)
        ids = [c["containerId"] for c in frame.params["extensionContainers"]]
        self.assertIn(3, ids)
        self.assertIsNotNone(frame.extension(3))

    def test_tp_cam_msd_fmt_bv_07(self):
        """TP/CAM/MSD/FMT/BV-07: VLF container again when >= 10 s elapsed since the last
        CAM with it and the CAM carries neither the LF nor the special vehicle container."""
        station = _Station()
        station.activate()
        vlf_times = []
        for step in range(0, 106):                                               # 0 .. 10.5 s
            frame = station.tick(step * 0.1, track=(90.0 + 5 * step) % 360)
            if frame.extension(3) is not None:
                vlf_times.append(step * 100)
                if step > 1:
                    self.assertNotIn("lowFrequencyContainer", frame.params)
                    self.assertNotIn("specialVehicleContainer", frame.params)
        self.assertEqual(vlf_times[0], 100)                                      # TIME_1 (second CAM)
        self.assertEqual(len(vlf_times), 2)
        self.assertGreaterEqual(vlf_times[1] - vlf_times[0], 10_000)

    def test_tp_cam_msd_fmt_bv_08(self):
        """TP/CAM/MSD/FMT/BV-08 (both TPs with this identifier, variants cyclist, moped,
        motorcycle): the first and the following CAMs contain the TwoWheelerContainer
        (containerId 1); a passenger car does not send it."""
        for station_type in (STATION_CYCLIST, STATION_MOPED, STATION_MOTORCYCLE):
            with self.subTest(station_type=station_type):
                station = _Station(_two_wheeler(station_type))
                station.activate()
                for step, frame in enumerate((station.tick(0), station.tick(0.1, track=95.0))):
                    self.assertIsNotNone(frame.extension(1), f"CAM {step}")
                    self.assertEqual(frame.params["basicContainer"]["stationType"], station_type)
        car = _Station()
        car.activate()
        self.assertIsNone(car.tick(0).extension(1))


def _two_wheeler(station_type):
    return VehicleData(station_id=1, station_type=station_type, drive_direction="forward",
                       vehicle_length={"vehicleLengthValue": 20,
                                       "vehicleLengthConfidenceIndication": "unavailable"},
                       vehicle_width=8)


# INA/BV-01-X variants: (number, bit name, value).
_ACCEL_VARIANTS = [(2 + 2 * i + (0 if on else 1), name, on)
                   for i, name in enumerate(ACCELERATION_CONTROL_BITS) for on in (True, False)]
_LIGHT_VARIANTS = [(16 + 2 * i + (0 if on else 1), name, on)
                   for i, name in enumerate(EXTERIOR_LIGHTS_BITS) for on in (True, False)]


class TestCamInVehicleData(unittest.TestCase):
    """TP/CAM/MSD/INA: in-vehicle data and special vehicle containers (TS 103 900 clauses 5.2, 7.1, Annex B)."""

    def _next_cam(self, station, **alert):
        """CAM at 0 s, alert, CAM at 0.6 s (LF container due again)."""
        station.activate()
        station.tick(0)
        if alert:
            station.ca.update_in_vehicle_data(**alert)
        return station.tick(0.6, track=100.0)

    def test_tp_cam_msd_ina_bv_01_x(self):
        """TP/CAM/MSD/INA/BV-01-X (variants 01-35): after the IUT is alerted about new
        in-vehicle data, the next CAM carries the latest value."""
        # 01: curvature
        station = _Station()
        frame = self._next_cam(station, curvature_value=-30, curvature_confidence="onePerMeter-0-0001")
        hf = frame.params["highFrequencyContainer"][1]
        self.assertEqual(hf["curvature"], {"curvatureValue": -30, "curvatureConfidence": "onePerMeter-0-0001"})
        # 02-15: accelerationControl bits engaged / disengaged
        for number, name, on in _ACCEL_VARIANTS:
            with self.subTest(variant=f"{number:02d}", field=name, value=int(on)):
                station = _Station()
                station.ca.update_in_vehicle_data(acceleration_control={name: not on})
                frame = self._next_cam(station, acceleration_control={name: on})
                control = frame.params["highFrequencyContainer"][1]["accelerationControl"]
                self.assertEqual(_bit(control, ACCELERATION_CONTROL_BITS.index(name)), int(on))
        # 16-31: exteriorLights bits on / off (LF container)
        for number, name, on in _LIGHT_VARIANTS:
            with self.subTest(variant=f"{number:02d}", field=name, value=int(on)):
                station = _Station()
                station.ca.update_in_vehicle_data(exterior_lights={name: not on})
                frame = self._next_cam(station, exterior_lights={name: on})
                lights = frame.params["lowFrequencyContainer"][1]["exteriorLights"]
                self.assertEqual(_bit(lights, EXTERIOR_LIGHTS_BITS.index(name)), int(on))
        # 32: heading, 33: speed (from the position service)
        station = _Station()
        station.activate()
        station.tick(0)
        frame = station.tick(0.6, track=123.4, speed=17.25)
        hf = frame.params["highFrequencyContainer"][1]
        self.assertEqual(hf["heading"]["headingValue"], 1234)
        self.assertEqual(hf["speed"]["speedValue"], 1725)
        # 34: drive direction
        frame = self._next_cam(_Station(), drive_direction="backward")
        self.assertEqual(frame.params["highFrequencyContainer"][1]["driveDirection"], "backward")
        # 35: yaw rate
        frame = self._next_cam(_Station(), yaw_rate_value=-150, yaw_rate_confidence="degSec-001-00")
        self.assertEqual(frame.params["highFrequencyContainer"][1]["yawRate"],
                         {"yawRateValue": -150, "yawRateConfidence": "degSec-001-00"})

    def _special(self, role):
        container = SPECIAL_ROLES[role]
        station = _Station(vehicle(role, container))
        station.activate()
        frame = station.tick(0)
        self.assertEqual(frame.params["lowFrequencyContainer"][1]["vehicleRole"], ROLE_NAMES[role])
        self.assertEqual(frame.params["specialVehicleContainer"], (container, CONTAINERS[container]))

    def test_tp_cam_msd_ina_bv_02(self):
        """TP/CAM/MSD/INA/BV-02: vehicleRole publicTransport(1) -> publicTransportContainer."""
        self._special(1)

    def test_tp_cam_msd_ina_bv_03(self):
        """TP/CAM/MSD/INA/BV-03: vehicleRole specialTransport(2) -> specialTransportContainer."""
        self._special(2)

    def test_tp_cam_msd_ina_bv_04(self):
        """TP/CAM/MSD/INA/BV-04: vehicleRole dangerousGoods(3) -> dangerousGoodsContainer."""
        self._special(3)

    def test_tp_cam_msd_ina_bv_05(self):
        """TP/CAM/MSD/INA/BV-05: vehicleRole roadWork(4) -> roadWorksContainerBasic."""
        self._special(4)

    def test_tp_cam_msd_ina_bv_06(self):
        """TP/CAM/MSD/INA/BV-06: vehicleRole rescue(5) -> rescueContainer."""
        self._special(5)

    def test_tp_cam_msd_ina_bv_07(self):
        """TP/CAM/MSD/INA/BV-07: vehicleRole emergency(6) -> emergencyContainer."""
        self._special(6)

    def test_tp_cam_msd_ina_bv_08(self):
        """TP/CAM/MSD/INA/BV-08: vehicleRole safetyCar(7) -> safetyCarContainer."""
        self._special(7)


class TestCamGenerationFrequency(unittest.TestCase):
    """TP/CAM/MSD/GFQ: CAM generation frequency (TS 103 900 clause 6.1.3)."""

    @staticmethod
    def _intervals(station):
        return [b - a for a, b in zip(station.times, station.times[1:])]

    def test_tp_cam_msd_gfq_ti_01(self):
        """TP/CAM/MSD/GFQ/TI-01: no CAM before T_GenCamMin (100 ms), even when the
        dynamics change at every 10 ms evaluation."""
        station = _Station()
        station.activate()
        for step in range(0, 200):
            station.tick(step * 0.01, track=(90.0 + 10 * step) % 360)
        self.assertGreater(len(station.times), 10)
        self.assertGreaterEqual(min(self._intervals(station)), T_GEN_CAM_MIN)

    def test_tp_cam_msd_gfq_ti_02(self):
        """TP/CAM/MSD/GFQ/TI-02: another CAM by T_GenCamMax (1000 ms) when nothing changes."""
        station = _Station()
        station.activate()
        for step in range(0, 500):
            station.tick(step * 0.01)
        self.assertGreater(len(station.times), 3)
        self.assertLessEqual(max(self._intervals(station)), T_GEN_CAM_MAX)

    def test_tp_cam_msd_gfq_ti_03(self):
        """TP/CAM/MSD/GFQ/TI-03: after a CAM at TIME_1, a CAM due to condition 1 at
        TIME_1 + INTERVAL_1 and N_GenCam - 1 (= 2) subsequent CAMs every INTERVAL_1 (due
        to condition 2), the next CAM (the N_GenCam-th due to condition 2) sets T_GenCam to
        T_GenCamMax: the following CAM comes T_GenCamMax later."""
        station = _Station()
        station.activate()
        station.tick(0)                                                  # TIME_1
        self.assertIsNotNone(station.tick(0.2, track=100.0))             # condition 1, INTERVAL_1 = 200 ms
        for step in range(21, 200):                                      # no dynamics afterwards
            station.tick(step * 0.01)
        self.assertEqual(station.times[:6], [0, 200, 400, 600, 800, 1800])

    def _condition_1(self, change, unchanged):
        """CAM at 0; the IUT is alerted at 50 ms; with T_GenCam_DCC = 100 ms and then
        300 ms the CAM is sent as soon as T_GenCam_DCC expires. ``unchanged`` (at the
        threshold) does not trigger a CAM."""
        for dcc_ms in (100, 300):
            with self.subTest(t_gen_cam_dcc=dcc_ms):
                station = _Station()
                station.activate()
                station.ca.set_t_gen_cam_dcc(dcc_ms)
                station.tick(0)
                station.tick(0.05, **change)
                for step in range(6, 40):
                    station.tick(step * 0.01, **change)
                self.assertEqual(station.times[1], dcc_ms)
        station = _Station()
        station.activate()
        station.tick(0)
        for step in range(1, 99):
            station.tick(step * 0.01, **unchanged)
        self.assertEqual(station.times, [0])

    def test_tp_cam_msd_gfq_bv_04(self):
        """TP/CAM/MSD/GFQ/BV-04: heading change > 4 deg -> CAM when T_GenCam_DCC expires."""
        self._condition_1({"track": 94.5}, {"track": 94.0})

    def test_tp_cam_msd_gfq_bv_05(self):
        """TP/CAM/MSD/GFQ/BV-05: position change > 4 m -> CAM when T_GenCam_DCC expires."""
        self._condition_1({"lat": TPV["lat"] + 4.5 / 111_195}, {"lat": TPV["lat"] + 3.9 / 111_195})

    def test_tp_cam_msd_gfq_bv_06(self):
        """TP/CAM/MSD/GFQ/BV-06: speed change > 0,5 m/s -> CAM when T_GenCam_DCC expires."""
        self._condition_1({"speed": 5.6}, {"speed": 5.5})

    def test_tp_cam_msd_gfq_ti_07(self):
        """TP/CAM/MSD/GFQ/TI-07: without dynamics a CAM is sent when both T_GenCam and
        T_GenCam_DCC have expired: at T_GenCam = 1000 ms with T_GenCam_DCC = 100 ms, and
        at T_GenCam_DCC = 500 ms when T_GenCam = 200 ms."""
        station = _Station()
        station.activate()
        for step in range(0, 150):
            station.tick(step * 0.01)
        self.assertEqual(station.times[:2], [0, 1000])
        station = _Station()
        station.activate()
        station.tick(0)
        station.tick(0.2, track=100.0)                                   # T_GenCam = 200 ms
        station.ca.set_t_gen_cam_dcc(500)
        for step in range(21, 100):
            station.tick(step * 0.01)
        self.assertEqual(station.times[:3], [0, 200, 700])


class TestCamPacketParameters(unittest.TestCase):
    """TP/CAM/MSD/PAR: CAM transport (TS 103 900 V2.2.1 clause 5.3.4.1)."""

    def _frame(self):
        station = _Station()
        station.activate()
        return station.tick(0)

    def test_tp_cam_msd_par_bv_01(self):
        """TP/CAM/MSD/PAR/BV-01: CAM encapsulated in a BTP-B packet (destination port 2001)."""
        frame = self._frame()
        self.assertEqual(frame.common.nh, CommonNH.BTP_B)
        self.assertEqual(frame.destination_port, 2001)

    def test_tp_cam_msd_par_bv_02(self):
        """TP/CAM/MSD/PAR/BV-02: CAM encapsulated in a SHB packet."""
        frame = self._frame()
        self.assertEqual((frame.common.ht, frame.common.hst), (HeaderType.TSB, TopoBroadcastHST.SINGLE_HOP))
        self.assertEqual((frame.basic.rhl, frame.common.mhl), (1, 1))

    def test_tp_cam_msd_par_bv_03(self):
        """TP/CAM/MSD/PAR/BV-03: Basic Header lifetime less than 1 s."""
        frame = self._frame()
        self.assertEqual(frame.basic.nh, BasicNH.COMMON_HEADER)
        self.assertLess(frame.basic.lt.get_value_in_seconds(), 1.0)


# -- Security (SSP) -------------------------------------------------------------------

class _Pki:
    """Root and AA; ATs with a chosen CAM SSP."""

    def __init__(self):
        self.backend = PythonECDSABackend()
        self.root = _ca(self.backend, "root", None, 2)
        self.aa = _ca(self.backend, "aa", self.root, 1)

    def at(self, app_permissions):
        return OwnCertificate.initialize_certificate(
            backend=self.backend, to_be_signed_certificate=_at_tbs(appPermissions=app_permissions),
            issuer=self.aa)

    def library(self, own=None):
        library = CertificateLibrary(ecdsa_backend=self.backend, root_certificates=[self.root],
                                     aa_certificates=[self.aa], at_certificates=[])
        if own is not None:
            library.add_own_certificate(own)
        return library


def _cam_ssp(octet1, octet2, version=2):
    return [{"psid": 36, "ssp": ("bitmapSsp", bytes([version, octet1, octet2]))}]


def _secured_shb(at, backend, cam_bytes, psid=36):
    """Secured SHB carrying ``cam_bytes``, signed with ``at`` regardless of its permissions."""
    common = CommonHeader(nh=CommonNH.BTP_B, ht=HeaderType.TSB, hst=TopoBroadcastHST.SINGLE_HOP,
                          mhl=1, pl=4 + len(cam_bytes))  # type: ignore
    so = LongPositionVector(gn_addr=_addr(9), tst=TST.set_in_normal_timestamp_seconds(time.time()),
                            latitude=int(TPV["lat"] * 1e7), longitude=int(TPV["lon"] * 1e7), pai=True)
    body = common.encode_to_bytes() + so.encode() + bytes(4) + (2001).to_bytes(2, "big") + bytes(2) + cam_bytes
    tbs = {"payload": {"data": {"protocolVersion": 3, "content": ("unsecuredData", body)}},
           "headerInfo": {"psid": psid, "generationTime": TimeService.timestamp_its() * 1000}}
    signed = {"protocolVersion": 3, "content": ("signedData", {
        "hashId": "sha256", "tbsData": tbs, "signer": ("certificate", [at.certificate]),
        "signature": at.sign_message(backend, SECURITY_CODER.encode_to_be_signed_data(tbs))})}
    basic = BasicHeader.initialize_with_mib(MIB()).set_rhl(1).set_nh(BasicNH.SECURED_PACKET)
    return basic.encode_to_bytes() + SECURITY_CODER.encode_etsi_ts_103097_data_signed(signed)


def _cam_bytes(vehicle_data):
    station = _Station(vehicle_data)
    station.activate()
    return station.tick(0).raw[44:]


# MSP/SSP/BV-02-X variants: (number, octet, bit, CAM content)
def _rsu_cam():
    cam = CODER.decode(_cam_bytes(vehicle(0)))
    cam["cam"]["camParameters"]["basicContainer"]["stationType"] = 15
    cam["cam"]["camParameters"]["highFrequencyContainer"] = (
        "rsuContainerHighFrequency", {"protectedCommunicationZonesRSU": [
            {"protectedZoneType": "permanentCenDsrcTolling", "protectedZoneLatitude": 415520000,
             "protectedZoneLongitude": 21340000}]})
    cam["cam"]["camParameters"].pop("lowFrequencyContainer", None)
    return CODER.encode(cam)


_SSP_VARIANTS = [
    (1, 1, 0x80, _rsu_cam),
    (2, 1, 0x40, lambda: _cam_bytes(vehicle(1, "publicTransportContainer"))),
    (3, 1, 0x20, lambda: _cam_bytes(vehicle(2, "specialTransportContainer"))),
    (4, 1, 0x10, lambda: _cam_bytes(vehicle(3, "dangerousGoodsContainer"))),
    (5, 1, 0x08, lambda: _cam_bytes(vehicle(4, "roadWorksContainerBasic"))),
    (6, 1, 0x04, lambda: _cam_bytes(vehicle(5, "rescueContainer"))),
    (7, 1, 0x02, lambda: _cam_bytes(vehicle(6, "emergencyContainer"))),
    (8, 1, 0x01, lambda: _cam_bytes(vehicle(7, "safetyCarContainer"))),
    (9, 2, 0x80, lambda: _cam_bytes(vehicle(4, "roadWorksContainerBasic",
                                            {"lightBarSirenInUse": SIREN, "closedLanes": {}}))),
    (10, 2, 0x40, lambda: _cam_bytes(vehicle(6, "emergencyContainer",
                                             {"lightBarSirenInUse": SIREN, "emergencyPriority": (b"\x80", 2)}))),
    (11, 2, 0x20, lambda: _cam_bytes(vehicle(6, "emergencyContainer",
                                             {"lightBarSirenInUse": SIREN, "emergencyPriority": (b"\x40", 2)}))),
    (12, 2, 0x10, lambda: _cam_bytes(vehicle(7, "safetyCarContainer",
                                             {"lightBarSirenInUse": SIREN, "trafficRule": "noPassing"}))),
    (13, 2, 0x08, lambda: _cam_bytes(vehicle(7, "safetyCarContainer",
                                             {"lightBarSirenInUse": SIREN, "trafficRule": "noPassingForTrucks"}))),
    (14, 2, 0x04, lambda: _cam_bytes(vehicle(7, "safetyCarContainer",
                                             {"lightBarSirenInUse": SIREN, "speedLimit": 50}))),
]
# Octet 2 bits also need their octet 1 container bit (Table 3).
_OCTET1_FOR = {9: 0x08, 10: 0x02, 11: 0x02, 12: 0x01, 13: 0x01, 14: 0x01}


class TestCamSecurity(unittest.TestCase):
    """TP/CAM/MSD/SSP and TP/CAM/MSP: SSP and reception (TS 103 900 clauses 4.4, 6.2.2)."""

    def test_tp_cam_msd_ssp_bo_02_x(self):
        """TP/CAM/MSD/SSP/BO-02-X (variant 01): the IUT does not send a CAM with a
        TwoWheelerContainer when its AT's CAM SSP has the twoWheeler bit (octet 2, 02h) at 0.
        TS 103 900 V2.3.1 Table 3 defines this bit for SSP versions greater than 2, so the
        AT uses SSP version 3 (the TP, older, says version 2). Variant 02 (cyclist type
        information) is not generated by the stacks."""
        for granted, sent in ((0x00, False), (0x02, True)):
            with self.subTest(octet2=granted):
                pki = _Pki()
                at = pki.at(_cam_ssp(0x00, granted, version=3))
                sign = SignService(backend=pki.backend, certificate_library=pki.library(at))
                station = _Station(_two_wheeler(STATION_CYCLIST), sign_service=sign)
                station.activate()
                station.tick(0)
                self.assertEqual(len(station.sent()), int(sent))

    def test_tp_cam_msp_bv_01(self):
        """TP/CAM/MSP/BV-01: a received valid CAM is passed to the applications and to
        the other facilities (LDM)."""
        sender = _Station(n=1)
        sender.activate()
        frame = sender.tick(0)
        receiver = _Station(n=2)
        receiver.gn.gn_data_indicate(frame.raw)
        self.assertEqual(len(receiver.received), 1)
        self.assertEqual(receiver.received[0]["header"], frame.cam["header"])
        self.assertEqual(receiver.received[0]["cam"], frame.cam["cam"])
        receiver.ldm.add_provider_data_to_ldm.assert_called_once()
        self.assertEqual(receiver.ldm.add_provider_data_to_ldm.call_args[0][0]["cam"], frame.cam["cam"])

    def _receiver(self, pki):
        return _Station(n=2, verify_service=VerifyService(backend=pki.backend,
                                                          certificate_library=pki.library()))

    def test_tp_cam_msp_ssp_bv_02(self):
        """TP/CAM/MSP/SSP/BV-02: a secured CAM whose signing AT has no CAM ITS-AID in its
        appPermissions is discarded (not passed to applications nor to the LDM); the same
        CAM signed with an AT permitting it is accepted."""
        pki = _Pki()
        cam = _cam_bytes(vehicle(0))
        for permissions, accepted in (([{"psid": 37}], False), (_cam_ssp(0, 0), True)):
            with self.subTest(accepted=accepted):
                receiver = self._receiver(pki)
                receiver.gn.gn_data_indicate(_secured_shb(pki.at(permissions), pki.backend, cam))
                self.assertEqual(len(receiver.received), int(accepted))
                self.assertEqual(receiver.ldm.add_provider_data_to_ldm.call_count, int(accepted))

    def test_tp_cam_msp_ssp_bv_02_x(self):
        """TP/CAM/MSP/SSP/BV-02-X (variants 01-14): a secured CAM with container X whose
        signer's CAM SSP lacks bit X is discarded; with the bit set it is accepted."""
        pki = _Pki()
        for number, octet, bit, build in _SSP_VARIANTS:
            cam = build()
            octet1_with = bit if octet == 1 else _OCTET1_FOR[number]
            octet2_with = bit if octet == 2 else 0
            for granted, accepted in (((octet1_with & ~bit if octet == 1 else octet1_with, 0), False),
                                      ((octet1_with, octet2_with), True)):
                with self.subTest(variant=f"{number:02d}", accepted=accepted):
                    receiver = self._receiver(pki)
                    at = pki.at(_cam_ssp(*granted))
                    receiver.gn.gn_data_indicate(_secured_shb(at, pki.backend, cam))
                    self.assertEqual(len(receiver.received), int(accepted))
                    self.assertEqual(receiver.ldm.add_provider_data_to_ldm.call_count, int(accepted))


if __name__ == "__main__":
    unittest.main()
