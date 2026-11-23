"""
DEN basic service conformance tests: one test per Test Purpose of
ETSI TS 102 869-2 V1.6.1, against ETSI TS 103 831 V2.3.1 (2025-11).

Each test is named after its TP and quotes the TP identifier, so that a search
for the identifier finds it. The tests drive complete stations (DEN service ->
BTP -> GeoNetworking -> link layer) on one virtual clock (the ``clock`` of the
DEN service and of the GN router; security uses the real time) and check the
GeoBroadcast frames that leave the IUT, decoded from the wire. A second
station plays the test system: it triggers real events, or sends DENMs it
builds itself (outdated, terminated, unknown actionIds) through its own stack.

Mirrors ``rustflexstack::facilities::decentralized_environmental_notification_service::conformance``.
"""

import random
import unittest
from unittest.mock import MagicMock

from flexstack.btp.router import Router as BTPRouter
from flexstack.btp.service_access_point import CommonNH
from flexstack.facilities.ca_basic_service.cam_transmission_management import VehicleData
from flexstack.facilities.decentralized_environmental_notification_service.den_protocol import (
    DEFAULT_VALIDITY_DURATION_S,
    ActionId,
    DenFailure,
    DENMRequest,
    OutgoingDENM,
    default_area,
)
from flexstack.facilities.decentralized_environmental_notification_service.den_service import (
    DecentralizedEnvironmentalNotificationService,
)
from flexstack.facilities.decentralized_environmental_notification_service.denm_coder import DENMCoder
from flexstack.facilities.decentralized_environmental_notification_service.denm_ssp import (
    CAUSE_CODE_SSP_BIT,
)
from flexstack.geonet.basic_header import BasicHeader, BasicNH
from flexstack.geonet.common_header import CommonHeader
from flexstack.geonet.gbc_extended_header import GBCExtendedHeader
from flexstack.geonet.gn_address import MID, GNAddress
from flexstack.geonet.mib import MIB, GnSecurity
from flexstack.geonet.position_vector import TST, LongPositionVector
from flexstack.geonet.router import Router as GNRouter
from flexstack.geonet.service_access_point import GeoBroadcastHST, HeaderType, TrafficClass
from flexstack.security.certificate import SECURITY_CODER
from flexstack.security.sign_service import SignService
from flexstack.security.verify_service import VerifyService
from flexstack.utils.time_service import TimeService

from tests.flexstack.facilities.ca_basic_service.test_cam_conformance import _Pki

CODER = DENMCoder()
LAT, LON = 415520000, 21340000
POSITION = {
    "latitude": LAT, "longitude": LON,
    "positionConfidenceEllipse": {"semiMajorConfidence": 4095, "semiMinorConfidence": 4095,
                                  "semiMajorOrientation": 3601},
    "altitude": {"altitudeValue": 800001, "altitudeConfidence": "unavailable"},
}
LOCATION = {"detectionZonesToEventPosition": [[{"pathPosition": {
    "deltaLatitude": 131072, "deltaLongitude": 131072, "deltaAltitude": 12800}}]]}
ALACARTE = {"lanePosition": 2, "externalTemperature": 21}
IUT_ID, TESTER_ID = 0x1001, 0x2002
KAF_SEED = 7
PSID_DENM = 37
# TP/DEN/SSP/BV-01-X, MSRV/BO-08-X, MSRV/BO-09-X variants 01-24 (octets 1-3 of Table 10),
# with the CauseCodeChoice names of the DENM v2 ASN.1 (the TP names follow EN 302 637-3).
CAUSE_NAMES = {
    1: "trafficCondition1", 2: "accident2", 3: "roadworks3", 6: "adhesion6",
    9: "hazardousLocation-SurfaceCondition9", 10: "hazardousLocation-ObstacleOnTheRoad10",
    11: "hazardousLocation-AnimalOnTheRoad11", 12: "humanPresenceOnTheRoad12",
    14: "wrongWayDriving14", 15: "rescueRecoveryAndMaintenanceWorkInProgress15",
    17: "adverseWeatherCondition-Wind17",
    18: "adverseWeatherCondition-Visibility18", 19: "adverseWeatherCondition-Precipitation19",
    26: "slowVehicle26", 27: "dangerousEndOfQueue27", 91: "vehicleBreakdown91", 92: "postCrash92",
    93: "humanProblem93", 94: "stationaryVehicle94", 95: "emergencyVehicleApproaching95",
    96: "hazardousLocation-DangerousCurve96", 97: "collisionRisk97", 98: "signalViolation98",
    99: "dangerousSituation99",
}
SSP_VARIANTS = sorted(((CAUSE_CODE_SSP_BIT[c], c) for c in CAUSE_NAMES), key=lambda v: (v[0][0], -v[0][1]))
SSP_VARIANTS = [(number, octet, mask, cause)
                for number, ((octet, mask), cause) in enumerate(SSP_VARIANTS, start=1)]


def _addr(n):
    return GNAddress(mid=MID(bytes([0x02, 0, 0, 0, 0, n])))


def _situation(cause="accident2", sub_cause=0):
    return {"informationQuality": 3, "eventType": {"ccAndScc": (cause, sub_cause)}}


def _denm_ssp(clear=None):
    """DENM BitmapSsp version 2 granting every cause code but ``clear`` (octet, mask)."""
    ssp = bytearray([2, 0xFF, 0xFF, 0xFF, 0xFF])
    if clear is not None:
        ssp[clear[0]] &= ~clear[1] & 0xFF
    return [{"psid": PSID_DENM, "ssp": ("bitmapSsp", bytes(ssp))}]


class _Clock:
    """Virtual clock shared by all the stations of a test (TimestampIts in ms)."""

    def __init__(self):
        self.start = int(TimeService.timestamp_its())
        self.offset = 0

    @property
    def its(self):
        return self.start + self.offset


class _Frame:
    """A GeoBroadcast frame carrying a DENM, decoded from the wire (secured or not)."""

    def __init__(self, raw: bytes):
        self.raw = raw
        self.basic = BasicHeader.decode_from_bytes(raw[0:4])
        body = raw[4:]
        self.secured = self.basic.nh == BasicNH.SECURED_PACKET
        if self.secured:
            signed = SECURITY_CODER.decode_etsi_ts_103097_data_signed(body)["content"][1]
            self.psid = signed["tbsData"]["headerInfo"]["psid"]
            body = signed["tbsData"]["payload"]["data"]["content"][1]
        self.plain = body                                   # Common Header .. DENM
        self.common = CommonHeader.decode_from_bytes(body[0:8])
        self.gbc = GBCExtendedHeader.decode(body[8:52])
        self.destination_port = int.from_bytes(body[52:54], "big")
        self.denm = CODER.decode(body[56:])                 # raises if the DENM is not valid UPER
        self.management = self.denm["denm"]["management"]
        self.action_id = ActionId.from_dict(self.management["actionId"])


class _Station:
    """
    A complete ITS-S: DEN service on BTP on GeoNetworking, the link layer
    captured with the virtual time of each frame.
    """

    def __init__(self, clock, station_id, n, kaf=False, sign_service=None, verify_service=None):
        self.clock = clock
        self.addr = _addr(n)
        security = GnSecurity.ENABLED if (sign_service or verify_service) else GnSecurity.DISABLED
        mib = MIB(itsGnBeaconServiceRetransmitTimer=0, itsGnLocalGnAddr=self.addr, itsGnSecurity=security)
        self.gn = GNRouter(mib, sign_service=sign_service, verify_service=verify_service,
                           clock=lambda: clock.offset)
        self.gn.ego_position_vector = LongPositionVector(
            gn_addr=self.addr, tst=TST.set_in_normal_timestamp_seconds(TimeService.time()),
            latitude=LAT, longitude=LON, pai=True)
        self.log = []
        self.gn.link_layer = MagicMock()
        self.gn.link_layer.send.side_effect = lambda raw, *_a, **_k: self.log.append((clock.offset, raw))
        self.btp = BTPRouter(self.gn)
        self.gn.register_indication_callback(self.btp.btp_data_indication)
        self.ldm = MagicMock()
        self.den = DecentralizedEnvironmentalNotificationService(
            self.btp, VehicleData(station_id=station_id, station_type=5), ldm=self.ldm,
            kaf_enabled=kaf, start_scheduler=False, clock=lambda: clock.its)
        self.den.protocol.set_seed(KAF_SEED)
        self.btp.freeze_callbacks()
        self.received = []
        self.den.add_application_callback(self.received.append)
        self.den.set_ego_position(LAT, LON)

    # -- IUT side -------------------------------------------------------------

    def denms(self):
        """DENMs originated by this station (GN source = own address), in order."""
        frames = [_Frame(raw) for _, raw in self.log]
        return [f for f in frames if f.gbc.so_pv.gn_addr == self.addr]

    def times(self):
        """Virtual times (ms) of the DENMs originated by this station."""
        return [t for t, raw in self.log if _Frame(raw).gbc.so_pv.gn_addr == self.addr]

    def last(self):
        return self.denms()[-1]

    def deliver(self, raw):
        """A frame received from the radio."""
        self.gn.gn_data_indicate(raw)

    def ldm_count(self):
        return self.ldm.if_ldm_3.add_provider_data.call_count

    # -- test system side -----------------------------------------------------

    def send(self, denm):
        """Send a DENM built by the test, over this station's BTP and GN; returns the frame."""
        self.den.denm_transmission_management.transmit(OutgoingDENM(
            denm, default_area(POSITION), GeoBroadcastHST.GEOBROADCAST_CIRCLE, TrafficClass()))
        return self.log[-1][1]


def _request(cause="accident2", sub_cause=0, **kwargs):
    return DENMRequest(POSITION, situation=_situation(cause, sub_cause), location=LOCATION, **kwargs)


class _DenTest(unittest.TestCase):
    """Virtual clock, the IUT and a test system station."""

    def setUp(self):
        self.clock = _Clock()
        self.stations = []

    def station(self, station_id=IUT_ID, n=1, **kwargs):
        station = _Station(self.clock, station_id, n, **kwargs)
        self.stations.append(station)
        return station

    def iut(self, **kwargs):
        return self.station(IUT_ID, 1, **kwargs)

    def tester(self, **kwargs):
        return self.station(TESTER_ID, 9, **kwargs)

    def at(self, offset_ms):
        """Advance the virtual clock to ``offset_ms``, firing every DEN timer due on the way."""
        while True:
            due = [(s.den.protocol.next_deadline(), i) for i, s in enumerate(self.stations)]
            due = [(d, i) for d, i in due if d is not None and d - self.clock.start <= offset_ms]
            if not due:
                break
            deadline, index = min(due)
            self.clock.offset = max(self.clock.offset, deadline - self.clock.start)
            self.stations[index].den.process_timers(deadline)
        self.clock.offset = offset_ms

    def denm(self, station_id, sequence_number, reference=None, detection=None, termination=None,
             transmission_interval=None, validity=None, cause="accident2", alacarte=None):
        """A DENM as the test system builds it; times are virtual offsets in ms."""
        reference = self.clock.offset if reference is None else reference
        detection = reference if detection is None else detection
        management = {
            "actionId": {"originatingStationId": station_id, "sequenceNumber": sequence_number},
            "detectionTime": self.clock.start + detection,
            "referenceTime": self.clock.start + reference,
            "eventPosition": POSITION,
            "validityDuration": DEFAULT_VALIDITY_DURATION_S if validity is None else validity,
            "stationType": 5,
        }
        if termination is not None:
            management["termination"] = termination
        if transmission_interval is not None:
            management["transmissionInterval"] = transmission_interval
        body = {"management": management}
        if termination is None:
            body["situation"] = _situation(cause)
            body["location"] = LOCATION
            if alacarte is not None:
                body["alacarte"] = alacarte
        return {"header": {"protocolVersion": 2, "messageId": 1, "stationId": TESTER_ID}, "denm": body}


class TestDenMessageFormat(_DenTest):
    """TP/DEN/MSGF: message format (EN 302 637-3 clauses B.1, 6.1.3.2; TS 103 831 V2.3.1)."""

    def test_tp_den_msgf_bv_01(self):
        """TP/DEN/MSGF/BV-01: the DENM sent on an AppDENM_trigger request has an ITS PDU
        header with protocolVersion 2 and messageID 1 (denm)."""
        iut = self.iut()
        self.assertTrue(iut.den.trigger_denm(_request()).ok)
        header = iut.denms()[0].denm["header"]
        self.assertEqual((header["protocolVersion"], header["messageId"]), (2, 1))

    def test_tp_den_msgf_bv_02(self):
        """TP/DEN/MSGF/BV-02: the location container of the DENM sent contains at least one
        trace (detectionZonesToEventPosition, the Traces of TS 103 831 V2.3.1)."""
        iut = self.iut()
        self.assertTrue(iut.den.trigger_denm(_request()).ok)
        location = iut.denms()[0].denm["denm"]["location"]
        self.assertGreaterEqual(len(location["detectionZonesToEventPosition"]), 1)


class TestDenEventGeneration(_DenTest):
    """TP/DEN/EVGN: new event generation (TS 103 831 clauses 6.1.1, 6.1.2.1, 8.2.1)."""

    def test_tp_den_evgn_bv_01(self):
        """TP/DEN/EVGN/BV-01: an AppDENM_trigger request makes the IUT send a valid DENM."""
        iut = self.iut()
        result = iut.den.trigger_denm(_request())
        self.assertTrue(result.ok)
        frames = iut.denms()
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].denm["header"], {"protocolVersion": 2, "messageId": 1, "stationId": IUT_ID})
        self.assertEqual(frames[0].action_id, result.action_id)
        self.assertIn("situation", frames[0].denm["denm"])
        self.assertIn("location", frames[0].denm["denm"])

    def test_tp_den_evgn_bv_02(self):
        """TP/DEN/EVGN/BV-02: each new event gets an actionID not used before."""
        iut = self.iut()
        for step in range(5):
            self.at(step * 100)
            iut.den.trigger_denm(_request())
        action_ids = [f.action_id for f in iut.denms()]
        self.assertEqual(len(set(action_ids)), 5)

    def test_tp_den_evgn_bv_03(self):
        """TP/DEN/EVGN/BV-03: the new actionID carries the IUT StationID as originatingStationID."""
        iut = self.iut()
        iut.den.trigger_denm(_request())
        self.assertEqual(iut.last().management["actionId"]["originatingStationId"], IUT_ID)

    def test_tp_den_evgn_bv_04(self):
        """TP/DEN/EVGN/BV-04: causeCode and subCauseCode are those given by the application."""
        iut = self.iut()
        for cause, sub_cause in (("accident2", 3), ("roadworks3", 4), ("dangerousSituation99", 5)):
            with self.subTest(cause=cause):
                iut.den.trigger_denm(_request(cause, sub_cause))
                self.assertEqual(iut.last().denm["denm"]["situation"]["eventType"]["ccAndScc"],
                                 (cause, sub_cause))

    def test_tp_den_evgn_bv_05(self):
        """TP/DEN/EVGN/BV-05: referenceTime of a new event is the current time (CLT)."""
        iut = self.iut()
        for step in range(3):
            self.at(step * 100)
            iut.den.trigger_denm(_request())
        self.at(437)
        iut.den.trigger_denm(_request())
        self.assertEqual(iut.last().management["referenceTime"], self.clock.its)

    def test_tp_den_evgn_bv_07(self):
        """TP/DEN/EVGN/BV-07: the new event gets sequenceNumber SEQ1 + 1 when unused."""
        iut = self.iut()
        for _ in range(3):
            iut.den.trigger_denm(_request())
        seq1 = iut.last().management["actionId"]["sequenceNumber"]
        iut.den.trigger_denm(_request())
        self.assertEqual(iut.last().management["actionId"]["sequenceNumber"], seq1 + 1)

    def test_tp_den_evgn_bv_08(self):
        """TP/DEN/EVGN/BV-08: SEQ1 + 1 being used by an active event, the new event gets
        SEQ1 + 2, also across the 65535 -> 0 wrap-around."""
        for seq1 in (0, 65534):
            with self.subTest(seq1=seq1):
                iut = self.iut()
                # Event on SEQ1 + 1, actionId assigned by a central entity (Table 2 note 10).
                busy = ActionId(IUT_ID, (seq1 + 1) % 65536)
                iut.den.trigger_denm(_request(action_id=busy))
                iut.den.protocol.set_next_sequence_number(seq1)
                iut.den.trigger_denm(_request())
                self.assertEqual(iut.last().management["actionId"]["sequenceNumber"], seq1)
                iut.den.trigger_denm(_request())
                self.assertEqual(iut.last().management["actionId"]["sequenceNumber"], (seq1 + 2) % 65536)

    def test_tp_den_evgn_bv_10(self):
        """TP/DEN/EVGN/BV-10: after a StationID change, new actionIDs use the new StationID."""
        iut = self.iut()
        for _ in range(2):
            iut.den.trigger_denm(_request())
        self.assertEqual(iut.last().management["actionId"]["originatingStationId"], IUT_ID)
        iut.den.update_station_id(0x3003)
        iut.den.trigger_denm(_request())
        self.assertEqual(iut.last().management["actionId"]["originatingStationId"], 0x3003)
        self.assertEqual(iut.last().denm["header"]["stationId"], 0x3003)


class TestDenEventUpdate(_DenTest):
    """TP/DEN/EVUP: event update (TS 103 831 clauses 6.1.2.2, 8.2.1.2, 8.2.1.3)."""

    def _event(self):
        iut = self.iut()
        result = iut.den.trigger_denm(_request())
        return iut, result.action_id, iut.last()

    def test_tp_den_evup_bv_01(self):
        """TP/DEN/EVUP/BV-01: an AppDENM_update request makes the IUT send a valid DENM."""
        iut, action_id, _ = self._event()
        self.at(100)
        self.assertTrue(iut.den.update_denm(action_id, _request(sub_cause=2)).ok)
        self.assertEqual(len(iut.denms()), 2)
        self.assertEqual(iut.last().denm["denm"]["situation"]["eventType"]["ccAndScc"], ("accident2", 2))

    def test_tp_den_evup_bv_02(self):
        """TP/DEN/EVUP/BV-02: the update DENM keeps ACTION_ID1 (StationID unchanged)."""
        iut, action_id, first = self._event()
        self.at(100)
        iut.den.update_denm(action_id, _request(sub_cause=2))
        self.assertEqual(iut.last().action_id, action_id)
        self.assertEqual(iut.last().management["actionId"], first.management["actionId"])

    def test_tp_den_evup_bv_03(self):
        """TP/DEN/EVUP/BV-03: the update DENM has referenceTime = CLT > REFERENCETIME1."""
        iut, action_id, first = self._event()
        self.at(250)
        iut.den.update_denm(action_id, _request(sub_cause=2))
        reference = iut.last().management["referenceTime"]
        self.assertEqual(reference, self.clock.its)
        self.assertGreater(reference, first.management["referenceTime"])

    def test_tp_den_evup_bo_04(self):
        """TP/DEN/EVUP/BO-04: no DENM for an update of an actionID not in the originating
        ITS-S message table."""
        iut, _, _ = self._event()
        iut.den.trigger_denm(_request())
        result = iut.den.update_denm(ActionId(IUT_ID, 77), _request())
        self.assertEqual(result.failure, DenFailure.UNKNOWN_ACTION_ID)
        self.assertEqual(len(iut.denms()), 2)


class TestDenEventTermination(_DenTest):
    """TP/DEN/EVTR: cancellation and negation (TS 103 831 clauses 6.1.2.4, 7.1.1, 8.2.1.3, 8.2.2)."""

    def _received_event(self, updates=0):
        """The IUT has received an event of the test system (and ``updates`` updates of it)."""
        iut, tester = self.iut(), self.tester()
        result = tester.den.trigger_denm(_request())
        iut.deliver(tester.log[-1][1])
        for step in range(1, updates + 1):
            self.at(step * 100)
            tester.den.update_denm(result.action_id, _request(sub_cause=step))
            iut.deliver(tester.log[-1][1])
        self.assertEqual(len(iut.received), updates + 1)
        return iut, tester, result.action_id

    def test_tp_den_evtr_bv_01(self):
        """TP/DEN/EVTR/BV-01: AppDENM_termination of an own event: cancellation DENM with ACTION_ID1."""
        iut = self.iut()
        action_id = iut.den.trigger_denm(_request(validity_duration=30)).action_id
        self.at(100)
        self.assertTrue(iut.den.terminate_denm(action_id, DENMRequest(POSITION)).ok)
        self.assertEqual(iut.last().action_id, action_id)
        self.assertEqual(iut.last().management["termination"], "isCancellation")

    def test_tp_den_evtr_bv_02(self):
        """TP/DEN/EVTR/BV-02: AppDENM_termination of a received event: negation DENM with ACTION_ID1."""
        iut, tester, action_id = self._received_event()
        self.assertNotEqual(action_id.station_id, IUT_ID)
        self.at(100)
        self.assertTrue(iut.den.terminate_denm(action_id, DENMRequest(POSITION)).ok)
        self.assertEqual(iut.last().action_id, action_id)
        self.assertEqual(iut.last().management["termination"], "isNegation")
        del tester

    def test_tp_den_evtr_bv_03(self):
        """TP/DEN/EVTR/BV-03: the negation DENM carries the latest referenceTime received
        for the event (REFERENCETIME2)."""
        iut, _, action_id = self._received_event(updates=1)
        reference2 = iut.received[-1].denm["denm"]["management"]["referenceTime"]
        self.assertGreater(reference2, iut.received[0].denm["denm"]["management"]["referenceTime"])
        self.at(300)
        iut.den.terminate_denm(action_id, DENMRequest(POSITION))
        self.assertEqual(iut.last().management["referenceTime"], reference2)
        self.assertEqual(iut.last().management["termination"], "isNegation")

    def test_tp_den_evtr_bv_04(self):
        """TP/DEN/EVTR/BV-04: a cancellation DENM has no situation, location nor a la carte container."""
        iut = self.iut()
        action_id = iut.den.trigger_denm(_request(alacarte=ALACARTE)).action_id
        self.assertIn("alacarte", iut.last().denm["denm"])
        self.at(100)
        iut.den.terminate_denm(action_id, DENMRequest(POSITION))
        self.assertEqual(iut.last().management["termination"], "isCancellation")
        self.assertEqual(set(iut.last().denm["denm"]), {"management"})

    def test_tp_den_evtr_bv_05(self):
        """TP/DEN/EVTR/BV-05: a negation DENM has no situation, location nor a la carte container."""
        iut, tester = self.iut(), self.tester()
        iut.deliver(tester.send(self.denm(TESTER_ID, 4, alacarte=ALACARTE)))
        self.at(100)
        iut.den.terminate_denm(ActionId(TESTER_ID, 4), DENMRequest(POSITION))
        self.assertEqual(iut.last().management["termination"], "isNegation")
        self.assertEqual(set(iut.last().denm["denm"]), {"management"})

    def test_tp_den_evtr_bo_06(self):
        """TP/DEN/EVTR/BO-06: no termination DENM for an own-StationID actionID the IUT never sent."""
        iut = self.iut()
        for _ in range(3):
            iut.den.trigger_denm(_request())
        result = iut.den.terminate_denm(ActionId(IUT_ID, 50), DENMRequest(POSITION))
        self.assertEqual(result.failure, DenFailure.UNKNOWN_ACTION_ID)
        self.assertEqual(len(iut.denms()), 3)

    def test_tp_den_evtr_bo_07(self):
        """TP/DEN/EVTR/BO-07: no termination DENM for a non-IUT actionID the IUT never received."""
        iut, tester = self.iut(), self.tester()
        for seq in range(3):
            iut.deliver(tester.send(self.denm(TESTER_ID, seq)))
        self.assertEqual(len(iut.received), 3)
        result = iut.den.terminate_denm(ActionId(TESTER_ID, 50), DENMRequest(POSITION))
        self.assertEqual(result.failure, DenFailure.UNKNOWN_ACTION_ID)
        self.assertEqual(iut.denms(), [])

    def test_tp_den_evtr_bv_08(self):
        """TP/DEN/EVTR/BV-08: the cancellation DENM has referenceTime = CLT."""
        iut = self.iut()
        action_id = iut.den.trigger_denm(_request(validity_duration=30)).action_id
        self.at(321)
        iut.den.terminate_denm(action_id, DENMRequest(POSITION))
        self.assertEqual(iut.last().management["termination"], "isCancellation")
        self.assertEqual(iut.last().management["referenceTime"], self.clock.its)


class TestDenRepetition(_DenTest):
    """TP/DEN/EVRP: DENM repetition (TS 103 831 clauses 6.1.1.2, 6.1.2.3, 8.1.1.1, 8.2.1.5, 8.2.2)."""

    def test_tp_den_evrp_ti_01(self):
        """TP/DEN/EVRP/TI-01: the DENM is repeated every repetitionInterval (INTERVAL_1)."""
        iut = self.iut()
        action_id = iut.den.trigger_denm(_request(repetition_interval=100, repetition_duration=1000,
                                                  validity_duration=10)).action_id
        self.at(1000)
        self.assertEqual(iut.times(), list(range(0, 1001, 100)))
        self.assertTrue(all(f.action_id == action_id for f in iut.denms()))

    def test_tp_den_evrp_bv_02(self):
        """TP/DEN/EVRP/BV-02: after an update, the repetitions carry the most up-to-date DENM."""
        iut = self.iut()
        action_id = iut.den.trigger_denm(_request(repetition_interval=100, repetition_duration=2000,
                                                  validity_duration=10)).action_id
        self.at(250)
        iut.den.update_denm(action_id, _request(sub_cause=4))
        update_reference = iut.last().management["referenceTime"]
        self.at(800)
        for time_ms, frame in zip(iut.times(), iut.denms()):
            if time_ms >= 250:
                self.assertEqual(frame.denm["denm"]["situation"]["eventType"]["ccAndScc"], ("accident2", 4))
                self.assertEqual(frame.management["referenceTime"], update_reference)
        self.assertGreater(len([t for t in iut.times() if t > 250]), 3)

    def test_tp_den_evrp_bv_03(self):
        """TP/DEN/EVRP/BV-03: no repetition after validityDuration (DURATION_2) expires, also when
        repetitionDuration is longer than validityDuration."""
        for duration, last in ((1500, 1500), (5000, 1900)):
            with self.subTest(repetition_duration=duration):
                iut = self.iut()
                start = self.clock.offset
                iut.den.trigger_denm(_request(repetition_interval=100, repetition_duration=duration,
                                              validity_duration=2))
                self.at(start + 4000)
                self.assertEqual(iut.times()[-1] - start, last)
                self.assertEqual(iut.den.protocol.originating, {})
                self.stations.remove(iut)

    def test_tp_den_evrp_bv_04(self):
        """TP/DEN/EVRP/BV-04: no repetition after repetitionDuration (DURATION_1) expires."""
        iut = self.iut()
        iut.den.trigger_denm(_request(repetition_interval=100, repetition_duration=500, validity_duration=10))
        self.at(3000)
        self.assertEqual(iut.times(), list(range(0, 501, 100)))

    def test_tp_den_evrp_bv_05(self):
        """TP/DEN/EVRP/BV-05: no repetition without repetitionInterval."""
        iut = self.iut()
        iut.den.trigger_denm(_request(repetition_duration=1000, validity_duration=5))
        self.at(6000)
        self.assertEqual(iut.times(), [0])

    def test_tp_den_evrp_bv_06(self):
        """TP/DEN/EVRP/BV-06: no repetition without repetitionDuration."""
        iut = self.iut()
        iut.den.trigger_denm(_request(repetition_interval=100, validity_duration=5))
        self.at(6000)
        self.assertEqual(iut.times(), [0])

    def test_tp_den_evrp_bv_08(self):
        """TP/DEN/EVRP/BV-08: after a StationID change, the repetitions carry the new StationID
        as originatingStationID."""
        iut = self.iut()
        iut.den.trigger_denm(_request(repetition_interval=100, repetition_duration=1000, validity_duration=10))
        self.at(150)
        iut.den.update_station_id(0x3003)
        self.at(200)
        self.assertEqual(iut.times()[-1], 200)
        self.assertEqual(iut.last().management["actionId"]["originatingStationId"], 0x3003)
        self.assertEqual(iut.last().denm["header"]["stationId"], 0x3003)
        self.assertEqual(iut.denms()[1].management["actionId"]["originatingStationId"], IUT_ID)

    def test_tp_den_evrp_bv_09(self):
        """TP/DEN/EVRP/BV-09: repetitions keep ACTION_ID_1 (StationID unchanged)."""
        iut = self.iut()
        action_id = iut.den.trigger_denm(_request(repetition_interval=100, repetition_duration=1000,
                                                  validity_duration=10)).action_id
        self.at(1000)
        self.assertEqual({f.action_id for f in iut.denms()}, {action_id})

    def test_tp_den_evrp_bv_10(self):
        """TP/DEN/EVRP/BV-10: repetitions keep REFERENCE_TIME_1."""
        iut = self.iut()
        iut.den.trigger_denm(_request(repetition_interval=100, repetition_duration=1000, validity_duration=10))
        self.at(1000)
        self.assertEqual({f.management["referenceTime"] for f in iut.denms()}, {self.clock.start})
        self.assertEqual(len(iut.denms()), 11)

    def test_tp_den_evrp_bv_11(self):
        """TP/DEN/EVRP/BV-11: without validityDuration, repetition stops when the default
        validityDuration (600 s) expires: never with INTERVAL_1 > 600 s, and none at or
        after 600 s with a shorter interval."""
        for interval, expected in ((700_000, [0]), (100_000, [0, 100_000, 200_000, 300_000, 400_000, 500_000])):
            with self.subTest(repetition_interval=interval):
                iut = self.iut()
                iut.den.trigger_denm(_request(repetition_interval=interval, repetition_duration=1_000_000))
                self.at(self.clock.offset + 1_200_000)
                start = iut.times()[0]
                self.assertEqual([t - start for t in iut.times()], expected)
                self.assertEqual(iut.den.protocol.originating, {})
                self.stations.remove(iut)


class TestDenPacketParameters(_DenTest):
    """TP/DEN/PAR: DENM encapsulation (TS 103 831 clause 5.4.2.2)."""

    def test_tp_den_par_bv_01(self):
        """TP/DEN/PAR/BV-01: the DENM is carried in a BTP-B packet (destination port 2002)."""
        iut = self.iut()
        iut.den.trigger_denm(_request())
        self.assertEqual(iut.last().common.nh, CommonNH.BTP_B)
        self.assertEqual(iut.last().destination_port, 2002)

    def test_tp_den_par_bv_02(self):
        """TP/DEN/PAR/BV-02: the DENM is carried in a GeoBroadcast packet."""
        iut = self.iut()
        iut.den.trigger_denm(_request())
        self.assertEqual(iut.last().common.ht, HeaderType.GEOBROADCAST)
        self.assertEqual(iut.last().common.hst, GeoBroadcastHST.GEOBROADCAST_CIRCLE)


class TestDenSsp(_DenTest):
    """TP/DEN/SSP: sender-side SSP check (TS 103 831 clause 6.2.2.2, Table 10)."""

    def test_tp_den_ssp_bv_01_x(self):
        """TP/DEN/SSP/BV-01-X (variants 01-24): the IUT does not send a DENM with CAUSE_CODE_X
        when its AT's DENM SSP has SSP_BIT_X at 0; with the bit set it sends it, signed."""
        pki = _Pki()
        for number, octet, mask, cause in SSP_VARIANTS:
            for clear, sent in (((octet, mask), False), (None, True)):
                with self.subTest(variant=f"{number:02d}", sent=sent):
                    at = pki.at(_denm_ssp(clear))
                    iut = self.iut(sign_service=SignService(backend=pki.backend,
                                                            certificate_library=pki.library(at)))
                    iut.den.trigger_denm(_request(CAUSE_NAMES[cause]))
                    self.assertEqual(len(iut.log), int(sent))
                    if sent:
                        self.assertTrue(iut.last().secured)
                        self.assertEqual(iut.last().psid, PSID_DENM)
                    self.stations.remove(iut)


def _secured(at, backend, frame, psid=PSID_DENM):
    """Re-sign the GN payload of an unsecured GBC ``frame`` with ``at``, regardless of its permissions."""
    plain = _Frame(frame).plain
    tbs = {"payload": {"data": {"protocolVersion": 3, "content": ("unsecuredData", plain)}},
           "headerInfo": {"psid": psid, "generationTime": TimeService.timestamp_its() * 1000,
                          "generationLocation": {"latitude": LAT, "longitude": LON, "elevation": 0xF000}}}
    signed = {"protocolVersion": 3, "content": ("signedData", {
        "hashId": "sha256", "tbsData": tbs, "signer": ("certificate", [at.certificate]),
        "signature": at.sign_message(backend, SECURITY_CODER.encode_to_be_signed_data(tbs))})}
    basic = BasicHeader.decode_from_bytes(frame[0:4]).set_nh(BasicNH.SECURED_PACKET)
    return basic.encode_to_bytes() + SECURITY_CODER.encode_etsi_ts_103097_data_signed(signed)


class TestDenReception(_DenTest):
    """TP/DEN/MSRV: receiving ITS-S (TS 103 831 clauses 6.2.2.2, 8.4.2)."""

    def _pair(self, **kwargs):
        return self.iut(**kwargs), self.tester()

    def _accepted(self, iut, count):
        self.assertEqual(len(iut.received), count)
        self.assertEqual(iut.ldm_count(), count)

    def test_tp_den_msrv_bv_01(self):
        """TP/DEN/MSRV/BV-01: a DENM with an unknown actionID that is not a termination is
        passed to the application (and the LDM)."""
        iut, tester = self._pair()
        iut.den.trigger_denm(_request())                            # the IUT has sent events
        tester.den.trigger_denm(_request("roadworks3"))
        iut.deliver(tester.log[-1][1])
        self._accepted(iut, 1)
        self.assertEqual(iut.received[0].denm, _Frame(tester.log[-1][1]).denm)

    def test_tp_den_msrv_bv_02(self):
        """TP/DEN/MSRV/BV-02: a known actionID with referenceTime greater than the highest
        received is passed to the application."""
        iut, tester = self._pair()
        iut.deliver(tester.send(self.denm(TESTER_ID, 1, reference=0)))
        self.at(100)
        iut.deliver(tester.send(self.denm(TESTER_ID, 1, reference=100)))
        self._accepted(iut, 2)
        self.assertEqual(iut.received[1].denm["denm"]["management"]["referenceTime"], self.clock.start + 100)

    def test_tp_den_msrv_bo_03(self):
        """TP/DEN/MSRV/BO-03: a termination DENM for an unknown actionID with the IUT
        StationID is discarded."""
        iut, tester = self._pair()
        for _ in range(2):
            iut.den.trigger_denm(_request())
        iut.deliver(tester.send(self.denm(IUT_ID, 40, termination="isNegation")))
        self._accepted(iut, 0)
        self.assertNotIn(ActionId(IUT_ID, 40), iut.den.protocol.receiving)

    def test_tp_den_msrv_bo_04(self):
        """TP/DEN/MSRV/BO-04: a termination DENM for an unknown actionID with a non-IUT
        StationID is discarded."""
        iut, tester = self._pair()
        for seq in range(2):
            iut.deliver(tester.send(self.denm(TESTER_ID, seq)))
        iut.deliver(tester.send(self.denm(TESTER_ID, 40, termination="isCancellation")))
        self._accepted(iut, 2)
        self.assertNotIn(ActionId(TESTER_ID, 40), iut.den.protocol.receiving)

    def test_tp_den_msrv_bo_05(self):
        """TP/DEN/MSRV/BO-05: a DENM with referenceTime less than the highest received is discarded."""
        iut, tester = self._pair()
        self.at(500)
        iut.deliver(tester.send(self.denm(TESTER_ID, 1, reference=500)))
        self.at(600)
        iut.deliver(tester.send(self.denm(TESTER_ID, 1, reference=400)))
        self._accepted(iut, 1)

    def test_tp_den_msrv_bo_06(self):
        """TP/DEN/MSRV/BO-06: same referenceTime and detectionTime less than the highest
        received: discarded."""
        iut, tester = self._pair()
        self.at(500)
        iut.deliver(tester.send(self.denm(TESTER_ID, 1, reference=500, detection=300)))
        iut.deliver(tester.send(self.denm(TESTER_ID, 1, reference=500, detection=200)))
        self._accepted(iut, 1)

    def test_tp_den_msrv_bv_07(self):
        """TP/DEN/MSRV/BV-07: same referenceTime and detectionTime greater than the highest
        received: passed to the application."""
        iut, tester = self._pair()
        self.at(500)
        iut.deliver(tester.send(self.denm(TESTER_ID, 1, reference=500, detection=300)))
        iut.deliver(tester.send(self.denm(TESTER_ID, 1, reference=500, detection=400)))
        self._accepted(iut, 2)

    def _secured_pair(self):
        pki = _Pki()
        iut = self.iut(verify_service=VerifyService(backend=pki.backend, certificate_library=pki.library()))
        return pki, iut, self.tester()

    def test_tp_den_msrv_bo_08(self):
        """TP/DEN/MSRV/BO-08: a secured DENM whose signing AT has no DENM ITS-AID in its
        appPermissions is discarded; the same DENM signed with an AT permitting it is accepted."""
        for permissions, accepted in (([{"psid": 36}], False), (_denm_ssp(), True)):
            with self.subTest(accepted=accepted):
                pki, iut, tester = self._secured_pair()
                frame = tester.send(self.denm(TESTER_ID, 1))
                iut.deliver(_secured(pki.at(permissions), pki.backend, frame))
                self._accepted(iut, int(accepted))

    def test_tp_den_msrv_bo_08_x(self):
        """TP/DEN/MSRV/BO-08-X (variants 01-24): a secured DENM for a new event with CAUSE_CODE_X,
        signed with an AT whose DENM SSP lacks SSP_BIT_X, is discarded; with the bit it is accepted."""
        for number, octet, mask, cause in SSP_VARIANTS:
            for clear, accepted in (((octet, mask), False), (None, True)):
                with self.subTest(variant=f"{number:02d}", accepted=accepted):
                    pki, iut, tester = self._secured_pair()
                    frame = tester.send(self.denm(TESTER_ID, 1, cause=CAUSE_NAMES[cause]))
                    iut.deliver(_secured(pki.at(_denm_ssp(clear)), pki.backend, frame))
                    self._accepted(iut, int(accepted))
                    self.stations.clear()

    def test_tp_den_msrv_bo_09_x(self):
        """TP/DEN/MSRV/BO-09-X (variants 01-24): for an existing event with CAUSE_CODE_X received
        under an SSP with SSP_BIT_X, a newer DENM signed with an AT lacking SSP_BIT_X is
        discarded; signed with the bit, it is accepted."""
        for number, octet, mask, cause in SSP_VARIANTS:
            for clear, accepted in (((octet, mask), False), (None, True)):
                with self.subTest(variant=f"{number:02d}", accepted=accepted):
                    pki, iut, tester = self._secured_pair()
                    name = CAUSE_NAMES[cause]
                    first = tester.send(self.denm(TESTER_ID, 1, reference=0, cause=name))
                    iut.deliver(_secured(pki.at(_denm_ssp()), pki.backend, first))
                    self._accepted(iut, 1)
                    second = tester.send(self.denm(TESTER_ID, 1, reference=1, cause=name))
                    iut.deliver(_secured(pki.at(_denm_ssp(clear)), pki.backend, second))
                    self._accepted(iut, 1 + int(accepted))
                    self.stations.clear()


class TestDenKeepAliveForwarding(_DenTest):
    """TP/DEN/KAFW: Keep-Alive Forwarding (TS 103 831 clauses 8.3.2, 8.3.3)."""

    @staticmethod
    def _timeout(transmission_interval, validity_s=DEFAULT_VALIDITY_DURATION_S):
        """T_Forwarding of the first KAF reception of a station seeded with KAF_SEED."""
        return min(2 * transmission_interval + random.Random(KAF_SEED).randint(0, 150), validity_s * 1000)

    def _received(self, **denm):
        """IUT with KAF, having received at 0 the test system DENM ACTION_ID1 = (TESTER_ID, 1)."""
        iut, tester = self.iut(kaf=True), self.tester()
        denm.setdefault("transmission_interval", 200)
        sent = self.denm(TESTER_ID, 1, **denm)
        iut.deliver(tester.send(sent))
        self.assertEqual(len(iut.received), 1)
        return iut, tester, sent

    def test_tp_den_kafw_bv_01(self):
        """TP/DEN/KAFW/BV-01: with no further DENM of ACTION_ID1 during T_Forwarding, the IUT
        reconstructs and sends it when T_Forwarding expires; a repetition received in the
        meantime restarts the timer."""
        iut, tester, sent = self._received(validity=10)
        timeout = self._timeout(200)
        self.at(timeout - 1)
        self.assertEqual(iut.denms(), [])
        self.at(timeout)
        self.assertEqual(iut.times(), [timeout])
        self.assertEqual(iut.last().action_id, ActionId(TESTER_ID, 1))
        # Counter-check: the same DENM received again at timeout / 2 restarts T_Forwarding.
        other = self.station(0x4004, 3, kaf=True)
        other.deliver(tester.send(sent))
        restart = self.clock.offset + timeout // 2
        self.at(restart)
        other.deliver(tester.send(sent))
        self.at(restart + timeout - 1)
        self.assertEqual(other.denms(), [])
        self.at(restart + timeout)
        self.assertEqual(len(other.denms()), 1)

    def test_tp_den_kafw_bv_02(self):
        """TP/DEN/KAFW/BV-02: a DENM of ACTION_ID1 with an older referenceTime does not restart
        T_Forwarding: the IUT forwards when the timer started at REFERENCETIME_1 expires."""
        iut, tester, _ = self._received(reference=0, validity=10)
        timeout = self._timeout(200)
        self.at(100)
        iut.deliver(tester.send(self.denm(TESTER_ID, 1, reference=-50, transmission_interval=200, validity=10)))
        self.at(timeout)
        self.assertEqual(iut.times(), [timeout])
        self.assertEqual(iut.last().management["referenceTime"], self.clock.start)

    def test_tp_den_kafw_ti_03(self):
        """TP/DEN/KAFW/TI-03: the forwarding delay is min(2 x transmissionInterval + rnd(0, 150 ms),
        validityDuration), from the reception and again after each forwarding."""
        for interval in (100, 500, 1000):
            with self.subTest(transmission_interval=interval):
                self.clock.offset = 0
                iut, _, _ = self._received(transmission_interval=interval, validity=10)
                timeout = self._timeout(interval, 10)
                self.at(timeout - 1)
                self.assertEqual(iut.denms(), [])
                self.at(2 * timeout)
                self.assertEqual(iut.times(), [timeout, 2 * timeout])
                self.assertGreaterEqual(timeout, 2 * interval)
                self.assertLessEqual(timeout, 2 * interval + 150)
                self.stations.clear()

    def test_tp_den_kafw_bv_04(self):
        """TP/DEN/KAFW/BV-04: the forwarded DENM has the IUT StationID in the ITS PDU header."""
        iut, _, _ = self._received(validity=10)
        self.at(self._timeout(200))
        self.assertEqual(iut.last().denm["header"]["stationId"], IUT_ID)

    def test_tp_den_kafw_bv_05(self):
        """TP/DEN/KAFW/BV-05: the forwarded DENM keeps ACTION_ID1."""
        iut, _, sent = self._received(validity=10)
        self.at(self._timeout(200))
        self.assertEqual(iut.last().management["actionId"], sent["denm"]["management"]["actionId"])

    def test_tp_den_kafw_bv_06(self):
        """TP/DEN/KAFW/BV-06: the forwarded DENM keeps REFERENCETIME_1."""
        iut, _, sent = self._received(reference=0, validity=10)
        self.at(self._timeout(200))
        self.assertEqual(iut.last().management["referenceTime"], sent["denm"]["management"]["referenceTime"])

    def test_tp_den_kafw_bv_07(self):
        """TP/DEN/KAFW/BV-07: a received negation DENM is forwarded with termination isNegation."""
        iut, tester, _ = self._received(reference=0, validity=10)
        self.at(100)
        negation = self.denm(TESTER_ID, 1, reference=0, termination="isNegation",
                             transmission_interval=200, validity=10)
        iut.deliver(tester.send(negation))
        self.assertEqual(len(iut.received), 2)
        self.at(100 + self._timeout(200) + 500)
        self.assertGreater(len(iut.denms()), 0)
        self.assertEqual(iut.last().management["termination"], "isNegation")
        self.assertTrue(all(t > 100 for t in iut.times()))

    def test_tp_den_kafw_bv_08(self):
        """TP/DEN/KAFW/BV-08: the forwarded DENM keeps the management, situation, location
        and a la carte containers."""
        iut, _, sent = self._received(validity=10, alacarte=ALACARTE)
        self.at(self._timeout(200))
        forwarded = iut.last().denm["denm"]
        received = iut.received[0].denm["denm"]
        for container in ("management", "situation", "location", "alacarte"):
            self.assertEqual(forwarded[container], received[container], container)
        self.assertEqual(forwarded["alacarte"], sent["denm"]["alacarte"])

    def test_tp_den_kafw_bv_09(self):
        """TP/DEN/KAFW/BV-09: the IUT stops forwarding when validityDuration (DURATION_1) expires."""
        iut, _, _ = self._received(reference=0, validity=2)
        self.at(5000)
        self.assertGreaterEqual(len(iut.times()), 3)
        self.assertLess(iut.times()[-1], 2000)
        self.assertEqual(iut.den.protocol.forwarding, {})

    def test_tp_den_kafw_bv_10(self):
        """TP/DEN/KAFW/BV-10: the IUT stops forwarding once its position is outside the
        relevance (destination) area."""
        iut, _, _ = self._received(validity=10)
        timeout = self._timeout(200)
        self.at(timeout)
        self.assertEqual(len(iut.denms()), 1)
        iut.den.set_ego_position(LAT + 1_000_000, LON)              # 0.1 degree (~11 km) north
        self.at(10_000)
        self.assertEqual(len(iut.denms()), 1)

    def test_tp_den_kafw_bv_11(self):
        """TP/DEN/KAFW/BV-11: a DENM without transmissionInterval is not forwarded."""
        iut, _, _ = self._received(transmission_interval=None, validity=10)
        self.at(12_000)
        self.assertEqual(iut.denms(), [])
        self.assertEqual(iut.den.protocol.forwarding, {})


if __name__ == "__main__":
    unittest.main()
