"""
Security conformance tests: one test per Test Purpose of ETSI TS 103 096-2
V2.1.1, against ETSI TS 103 097 V2.2.1 and IEEE Std 1609.2.

Each test is named after its TP and quotes the TP identifier, so that a search
for the identifier finds it. A TP with a permutation table (``_XX``) is one
test with a subtest per permutation; TP_SEC_ITSS_SND_CAM_23_BV and
TP_SEC_ITSS_SND_CAM_24_BV, which TS 103 096-2 defines twice, are one test each
covering both definitions.

The tests drive complete stations: the CA basic service, the DEN service and
the GeoNetworking Beacon on BTP on a secured GeoNetworking router, sharing one
virtual clock (GeoNetworking timers, CA generation, DEN timestamps and the
sign service: generationTime, certificate timers, AT validity). Frames are
captured at the link layer and decoded from the wire. On the receiving side
the test system is another complete station; a message it sends with a
deliberate fault is re-signed, so that the fault is the only reason for a
discard, and every discard is followed by a valid message that is accepted.

Mirrors ``rustflexstack::security::conformance``.
"""

import dataclasses
import hashlib
import unittest
from copy import deepcopy
from unittest.mock import MagicMock, Mock, patch

import ecdsa

from flexstack.btp.router import Router as BTPRouter
from flexstack.facilities.ca_basic_service.ca_basic_service import CooperativeAwarenessBasicService
from flexstack.facilities.ca_basic_service.cam_transmission_management import VehicleData
from flexstack.facilities.decentralized_environmental_notification_service.den_service import (
    DecentralizedEnvironmentalNotificationService,
)
from flexstack.geonet.basic_header import BasicHeader, BasicNH
from flexstack.geonet.common_header import CommonHeader
from flexstack.geonet.gn_address import MID, GNAddress
from flexstack.geonet.mib import MIB, GnSecurity
from flexstack.geonet.position_vector import TST, LongPositionVector
from flexstack.geonet.router import Router as GNRouter
from flexstack.geonet.service_access_point import (
    CommonNH, GNDataRequest, HeaderType, LocationServiceHST, PacketTransportType)
from flexstack.linklayer.link_layer import LinkLayer
from flexstack.security.certificate import SECURITY_CODER, Certificate, OwnCertificate
from flexstack.security.certificate_library import CertificateLibrary
from flexstack.security.ecdsa_backend import PythonECDSABackend
from flexstack.security.sign_service import SignService
from flexstack.security.validity import (
    app_permission,
    location_permitted,
    register_identified_region,
    unregister_identified_region,
    validity_window_us,
)
from flexstack.security.verify_service import VerifyService
from flexstack.utils.time_service import ELAPSED_SECONDS, ITS_EPOCH, TimeService

from tests.flexstack.facilities.ca_basic_service.test_cam_conformance import _TIME, TPV
from tests.flexstack.facilities.ca_basic_service.test_cam_ssp import vehicle
from tests.flexstack.facilities.decentralized_environmental_notification_service.test_den_conformance import (
    _denm_ssp,
    _request,
)
from tests.flexstack.security.test_security_checks import _at_tbs, _ca, _validity

AID_CAM, AID_DENM, AID_GNMGMT = 36, 37, 141
INSIDE = {"latitude": 415520000, "longitude": 21340000}
APP_PERMISSIONS = [{"psid": AID_CAM, "ssp": ("bitmapSsp", bytes([2, 0x02, 0x00]))},
                   _denm_ssp()[0], {"psid": AID_GNMGMT}]
IUT_ID, TS_ID = 0x1001, 0x2002
ONE_S_US = 1_000_000
# AT, AA and RCA curves of the CAM_05, CAM_21/22, DENM_13 and GENMSG_08 permutations
CURVES = {"A": ("nistP256", True), "AN": ("nistP256", False),
          "B": ("brainpoolP256r1", True), "BN": ("brainpoolP256r1", False),
          "C": ("brainpoolP384r1", True), "CN": ("brainpoolP384r1", False)}
SIGNATURES = {"nistP256": "ecdsaNistP256Signature", "brainpoolP256r1": "ecdsaBrainpoolP256r1Signature",
              "brainpoolP384r1": "ecdsaBrainpoolP384r1Signature", "nistP384": "ecdsaNistP384Signature"}
KEYS = {"nistP256": "ecdsaNistP256", "brainpoolP256r1": "ecdsaBrainpoolP256r1",
        "brainpoolP384r1": "ecdsaBrainpoolP384r1", "nistP384": "ecdsaNistP384"}
IDENTIFIED_IDS = range(9600, 9608)


def _point(lat, lon):
    return {"latitude": lat, "longitude": lon}


# Region restrictions (TS 103 096-2 certificates B, C, D, E and their 8-entry
# variants), all around INSIDE; identified regions use synthetic geometry
# registered for UnCountryId 9600..9607 (the 6th contains INSIDE).
CIRCLE = ("circularRegion", {"center": _point(INSIDE["latitude"], INSIDE["longitude"]), "radius": 5000})
RECTANGLE = ("rectangularRegion", [{"northWest": _point(416000000, 20340000),
                                    "southEast": _point(415000000, 22340000)}])
RECTANGLES_8 = ("rectangularRegion", [{"northWest": _point(416000000, 5340000 + i * 3000000),
                                       "southEast": _point(415000000, 7340000 + i * 3000000)}
                                      for i in range(8)])
POLYGON_8 = ("polygonalRegion", [_point(INSIDE["latitude"] + a, INSIDE["longitude"] + b) for a, b in (
    (1000000, -400000), (1000000, 400000), (400000, 1000000), (-400000, 1000000),
    (-1000000, 400000), (-1000000, -400000), (-400000, -1000000), (400000, -1000000))])
IDENTIFIED = ("identifiedRegion", [("countryOnly", 9605)])
IDENTIFIED_8 = ("identifiedRegion", [("countryOnly", i) for i in IDENTIFIED_IDS])
FAR_RECTANGLE = ("rectangularRegion", [{"northWest": _point(400000000, 20340000),     # 39.0-40.0 N
                                        "southEast": _point(390000000, 22340000)}])
REGIONS = {"B": CIRCLE, "C": RECTANGLE, "D": POLYGON_8, "E": IDENTIFIED}


def _register_identified_regions(test):
    for i, country in enumerate(IDENTIFIED_IDS):
        south = 340000000 + i * 15000000
        register_identified_region(country, [[(south, 0), (south + 10000000, 0),
                                              (south + 10000000, 30000000), (south, 30000000)]])
        test.addCleanup(unregister_identified_region, country)


class _Clock:
    """Virtual clock of a test: ``ms`` after a real UTC instant taken at start."""

    def __init__(self):
        self.base = TimeService.time()
        self.ms = 0

    def unix(self) -> float:
        return self.base + self.ms / 1000

    def its_ms(self) -> int:
        return int((self.unix() - ITS_EPOCH + ELAPSED_SECONDS) * 1000)

    def its_us(self) -> int:
        return round((self.unix() - ITS_EPOCH + ELAPSED_SECONDS) * 1e6)


class _Pki:
    """Root CA and AAs; ATs on demand. Every station trusts ``roots`` and ``aas``."""

    def __init__(self, algorithm="nistP256", **aa_extra):
        self.backend = PythonECDSABackend()
        self.root = _ca(self.backend, "root", None, 2, algorithm)
        self.aa = _ca(self.backend, "aa", self.root, 1, algorithm, **aa_extra)
        self.roots = [self.root]
        self.aas = [self.aa]

    def new_aa(self, name, algorithm="nistP256", trusted=True, **extra):
        aa = _ca(self.backend, name, self.root, 1, algorithm, **extra)
        if trusted:
            self.aas.append(aa)
        return aa

    def at(self, aa=None, algorithm="nistP256", compressed=True, **extra):
        extra.setdefault("appPermissions", APP_PERMISSIONS)
        return OwnCertificate.initialize_certificate(
            backend=self.backend, to_be_signed_certificate=_at_tbs(**extra), issuer=aa or self.aa,
            algorithm=algorithm, compressed_key=compressed)

    def implicit_at(self, **extra):
        extra.setdefault("appPermissions", APP_PERMISSIONS)
        return self.aa.issue_implicit_certificate(self.backend, _at_tbs(**extra))


class _Secured:
    """A secured GeoNetworking packet, decoded from the wire."""

    def __init__(self, raw: bytes):
        self.raw = raw
        self.basic = BasicHeader.decode_from_bytes(raw[0:4])
        if self.basic.nh != BasicNH.SECURED_PACKET:
            raise AssertionError("not a secured packet")
        self.protocol_version = raw[4]                          # COER Uint8, first octet
        self.data = SECURITY_CODER.decode_etsi_ts_103097_data_signed(raw[4:])
        self.content = self.data["content"]
        self.signed = self.content[1]
        self.header = self.signed["tbsData"]["headerInfo"]
        self.signer = self.signed["signer"]
        self.signature = self.signed["signature"]
        self.inner = self.signed["tbsData"]["payload"]["data"]
        self.common = CommonHeader.decode_from_bytes(self.inner["content"][1][0:8])

    @property
    def certificate(self) -> dict:
        """The signer certificate (signer choice ``certificate``)."""
        if self.signer[0] != "certificate":
            raise AssertionError(f"signer is {self.signer[0]}")
        return self.signer[1][0]


class _Station:
    """
    A complete ITS-S: CA basic service and DEN service on BTP on a secured
    GeoNetworking router, its own ATs ``ats`` and the trust anchors of ``pki``
    (plus ``extra_aas``). The link layer is captured with the virtual time.
    """

    def __init__(self, clock, pki, ats=(), n=1, station_id=IUT_ID, position=INSIDE,  # pylint: disable=too-many-arguments
                 beacon=False, aas=None, known_ats=(), before_freeze=None):
        self.clock, self.pki = clock, pki
        self.addr = GNAddress(mid=MID(bytes([0x02, 0, 0, 0, 0, n])))
        aas = list(pki.aas if aas is None else aas)
        library = CertificateLibrary(ecdsa_backend=pki.backend, root_certificates=list(pki.roots),
                                     aa_certificates=aas, at_certificates=[])
        for at in ats:
            library.add_own_certificate(at)
        self.ats = list(ats)
        self.sign_service = SignService(pki.backend, library, clock=clock.unix)
        self.verify_service = VerifyService(
            backend=pki.backend, sign_service=self.sign_service,
            certificate_library=CertificateLibrary(
                ecdsa_backend=pki.backend, root_certificates=list(pki.roots), aa_certificates=aas,
                at_certificates=list(known_ats)))
        mib = MIB(itsGnLocalGnAddr=self.addr, itsGnSecurity=GnSecurity.ENABLED,
                  itsGnBeaconServiceRetransmitTimer=3000 if beacon else 0)
        self.gn = GNRouter(mib, sign_service=self.sign_service, verify_service=self.verify_service,
                           clock=lambda: clock.ms)
        self.gn.ego_position_vector = LongPositionVector(
            gn_addr=self.addr, tst=TST.set_in_normal_timestamp_seconds(clock.unix()),
            latitude=position["latitude"], longitude=position["longitude"], pai=True)
        self.log = []
        self.gn.link_layer = Mock(spec=LinkLayer)
        self.gn.link_layer.send.side_effect = lambda raw, *_a, **_k: self.log.append((clock.ms, raw))
        self.btp = BTPRouter(self.gn)
        self.gn.register_indication_callback(self.btp.btp_data_indication)
        self.ca = CooperativeAwarenessBasicService(
            self.btp, dataclasses.replace(vehicle(0), station_id=station_id))
        self.den = DecentralizedEnvironmentalNotificationService(
            self.btp, VehicleData(station_id=station_id, station_type=5), ldm=MagicMock(),
            start_scheduler=False, clock=clock.its_ms)
        if before_freeze is not None:                       # more BTP ports
            before_freeze(self)
        self.btp.freeze_callbacks()
        self.cams, self.denms = [], []
        self.ca.cam_reception_management.add_application_callback(self.cams.append)
        self.ca.cam_reception_management.ca_basic_service_ldm = MagicMock()
        self.den.add_application_callback(self.denms.append)
        self.den.set_ego_position(position["latitude"], position["longitude"])
        self.ctm = self.ca.cam_transmission_management
        self.tpv = dict(TPV, lat=position["latitude"] / 1e7, lon=position["longitude"] / 1e7)
        self.ctm.start()
        if self.ctm._timer is not None:                     # pylint: disable=protected-access
            self.ctm._timer.cancel()                        # pylint: disable=protected-access

    # -- requests to the station ---------------------------------------------

    def cam(self, at_ms):
        """CA generation check at ``at_ms`` after a heading change of 10 degrees
        (TS 103 900 clause 6.1.3), i.e. a CAM is due; the frame sent, or None."""
        self.clock.ms = at_ms
        self.tpv["track"] = (self.tpv["track"] + 10) % 360
        self.ctm.location_service_callback(dict(self.tpv))
        before = len(self.log)
        with patch(_TIME, return_value=self.clock.unix()):
            self.ctm._evaluate_and_maybe_send()             # pylint: disable=protected-access
        return _Secured(self.log[-1][1]) if len(self.log) > before else None

    def cams_every_100_ms(self, until_ms, start_ms=0):
        """CAMs requested every 100 ms (more than one per second)."""
        return [self.cam(t) for t in range(start_ms, until_ms + 1, 100)]

    def denm(self, at_ms=None):
        """DENM triggered by the application (TS 103 831 clause 6.1.2); the frame sent, or None."""
        if at_ms is not None:
            self.clock.ms = at_ms
        before = len(self.log)
        self.den.trigger_denm(_request())
        return _Secured(self.log[-1][1]) if len(self.log) > before else None

    def beacon(self):
        """Advance to the Beacon timer and fire it; the Beacon sent, or None."""
        deadline = self.gn.next_deadline()
        self.clock.ms = deadline
        before = len(self.log)
        self.gn.tick(deadline)
        return _Secured(self.log[-1][1]) if len(self.log) > before else None

    def deliver(self, raw, at_ms=None):
        """A frame received from the radio."""
        if at_ms is not None:
            self.clock.ms = at_ms
        self.gn.gn_data_indicate(raw)

    def certificate_cam(self, at_ms):
        """A CAM signed with the certificate (as after a request of the certificate)."""
        self.sign_service.cam_handler.requested_own_certificate = True
        return self.cam(at_ms)


def _h3(certificate) -> bytes:
    return certificate.as_hashedid8()[-3:]


def _hash(name):
    return hashlib.sha384 if name == "sha384" else hashlib.sha256


def _compressed(point: tuple) -> tuple:
    if point[0] in ("uncompressedP256", "uncompressedP384"):
        return ("compressed-y-0" if point[1]["y"][-1] % 2 == 0 else "compressed-y-1", point[1]["x"])
    return point


def _canonical_bytes(certificate: dict) -> bytes:
    """COER of the canonical certificate (IEEE 1609.2 clause 6.4.3): every point
    of toBeSigned (verification key or reconstruction value, encryption key) in
    compressed form and the r of the ECDSA signature in x-only form."""
    canonical = deepcopy(certificate)
    indicator = canonical["toBeSigned"]["verifyKeyIndicator"]
    if indicator[0] == "verificationKey":
        canonical["toBeSigned"]["verifyKeyIndicator"] = (
            "verificationKey", (indicator[1][0], _compressed(indicator[1][1])))
    else:
        canonical["toBeSigned"]["verifyKeyIndicator"] = ("reconstructionValue", _compressed(indicator[1]))
    encryption_key = canonical["toBeSigned"].get("encryptionKey")
    if encryption_key:
        encryption_key["publicKey"] = (encryption_key["publicKey"][0], _compressed(encryption_key["publicKey"][1]))
    signature = canonical.get("signature")
    if signature is not None and signature[1]["rSig"][0] != "x-only":
        signature[1]["rSig"] = ("x-only", _compressed(signature[1]["rSig"])[1])
    return SECURITY_CODER.encode_etsi_ts_103097_certificate(canonical)


def _digest(certificate: dict, hash_name="sha256") -> bytes:
    """HashedId8: last 8 octets of the hash of the canonical certificate."""
    return _hash(hash_name)(_canonical_bytes(certificate)).digest()[-8:]


def _verifies(frame: _Secured, signer: dict, key: tuple, backend) -> bool:
    """IEEE 1609.2 clause 5.3.1, computed here: the signature over
    Hash(Hash(tbsData) || Hash(signer certificate)) verifies with ``key``."""
    hash_name = "sha384" if key[0].endswith("384r1") or key[0].endswith("P384") else "sha256"
    h = _hash(hash_name)
    tbs = SECURITY_CODER.encode_to_be_signed_data(frame.signed["tbsData"])
    data = h(tbs).digest() + h(_canonical_bytes(signer)).digest()
    return backend.verify_with_pk(data, frame.signature, key)


def _resign(raw, at: OwnCertificate, backend, mutate=None, sign=True, protocol_version=None):
    """``raw`` with ``mutate`` applied to its SignedData, signed again by ``at``
    (unless ``sign`` is False); ``protocol_version`` patches the outer octet."""
    data = SECURITY_CODER.decode_etsi_ts_103097_data_signed(raw[4:])
    signed = data["content"][1]
    if mutate is not None:
        mutate(signed)
    if sign:
        signed["signature"] = at.sign_message(
            backend, SECURITY_CODER.encode_to_be_signed_data(signed["tbsData"]))
    encoded = SECURITY_CODER.encode_etsi_ts_103097_data_signed(data)
    if protocol_version is not None:
        encoded = bytes([protocol_version]) + encoded[1:]
    return raw[:4] + encoded


def _header(field, value):
    return lambda signed: signed["tbsData"]["headerInfo"].__setitem__(field, value)


def _drop_header(field):
    return lambda signed: signed["tbsData"]["headerInfo"].pop(field)


class _SecTest(unittest.TestCase):
    """A virtual clock and the PKI of the test."""

    def setUp(self):
        self.clock = _Clock()
        self.pki = _Pki()

    def iut(self, *ats, **kwargs):
        """The IUT, authorized with ``ats`` (CERT_IUT_A_AT by default)."""
        return _Station(self.clock, self.pki, ats or (self.pki.at(),), **kwargs)

    def tester(self, *ats, n=9, **kwargs):
        """A test system station, authorized with ``ats`` (CERT_TS_A_AT by default)."""
        return _Station(self.clock, self.pki, ats or (self.pki.at(),), n=n, station_id=TS_ID, **kwargs)

    def assert_generation_time(self, frame, tolerance_us):
        """generationTime realistic (CUR_TIME +- tolerance) and inside the
        validity period of the signer certificate (IEEE 1609.2 5.2.3.2.2)."""
        generation_time = frame.header["generationTime"]
        self.assertLessEqual(abs(generation_time - self.clock.its_us()), tolerance_us)
        start, end = validity_window_us(frame.certificate["toBeSigned"])
        self.assertLessEqual(start, generation_time)
        self.assertGreater(end - start, generation_time - start)


# ─── Sending: all messages ──────────────────────────────────────────────────


class TestSecSndMessage(_SecTest):
    """TP_SEC_ITSS_SND_MSG: Ieee1609Dot2Data protocol version (TS 103 097 clause 5.1)."""

    def test_tp_sec_itss_snd_msg_01_bv(self):
        """TP_SEC_ITSS_SND_MSG_01_BV: a secured message has protocolVersion 3."""
        iut = self.iut(beacon=True)
        for frame in (iut.cam(0), iut.denm(100), iut.beacon()):
            self.assertEqual(frame.protocol_version, 3)
            self.assertEqual(frame.data["protocolVersion"], 3)


# ─── Sending: CAM ───────────────────────────────────────────────────────────


class TestSecSndCam(_SecTest):
    """TP_SEC_ITSS_SND_CAM: secured CAMs sent by the IUT (TS 103 097 clause 7.1.1)."""

    def test_tp_sec_itss_snd_cam_01_bv(self):
        """TP_SEC_ITSS_SND_CAM_01_BV: the CAM is sent in a signedData container."""
        self.assertEqual(self.iut().cam(0).content[0], "signedData")

    def test_tp_sec_itss_snd_cam_02_bv(self):
        """TP_SEC_ITSS_SND_CAM_02_BV: headerInfo psid is AID_CAM."""
        self.assertEqual(self.iut().cam(0).header["psid"], AID_CAM)

    def test_tp_sec_itss_snd_cam_03_bv(self):
        """TP_SEC_ITSS_SND_CAM_03_BV: headerInfo contains generationTime and none of
        expiryTime, generationLocation, encryptionKey, p2pcdLearningRequest,
        missingCrlIdentifier (certificate and digest CAMs)."""
        iut = self.iut()
        for frame in (iut.cam(0), iut.cam(100)):
            self.assertIn("generationTime", frame.header)
            for field in ("expiryTime", "generationLocation", "encryptionKey", "p2pcdLearningRequest",
                          "missingCrlIdentifier"):
                self.assertNotIn(field, frame.header)

    def test_tp_sec_itss_snd_cam_04_bv(self):
        """TP_SEC_ITSS_SND_CAM_04_BV: signer is a digest or a certificate with id
        'none', appPermissions containing AID_CAM and no certIssuePermissions."""
        at = self.pki.at()
        iut = self.iut(at)
        with_certificate, with_digest = iut.cam(0), iut.cam(100)
        tbs = with_certificate.certificate["toBeSigned"]
        self.assertEqual(tbs["id"], ("none", None))
        self.assertIn(AID_CAM, [item["psid"] for item in tbs["appPermissions"]])
        self.assertNotIn("certIssuePermissions", tbs)
        self.assertEqual(with_digest.signer, ("digest", _digest(at.certificate)))

    def test_tp_sec_itss_snd_cam_05_bv(self):
        """TP_SEC_ITSS_SND_CAM_05_BV: the digest signer is the last 8 octets of
        the X_HASH of the canonical X_CERTIFICATE (A, AN: NIST P-256 compressed and
        uncompressed, SHA-256; B, BN: brainpoolP256r1, SHA-256; C, CN:
        brainpoolP384r1, SHA-384); the certificate and its chain use X_KEY."""
        for variant, (algorithm, compressed) in CURVES.items():
            with self.subTest(variant=variant):
                self.clock, self.pki = _Clock(), _Pki(algorithm)
                at = self.pki.at(algorithm=algorithm, compressed=compressed)
                iut = self.iut(at)
                first = iut.cam(0)
                key = first.certificate["toBeSigned"]["verifyKeyIndicator"]
                self.assertEqual(key[0], "verificationKey")
                self.assertEqual(key[1][0], KEYS[algorithm])
                point = key[1][1][0]
                if compressed:
                    self.assertIn(point, ("compressed-y-0", "compressed-y-1"))
                else:
                    self.assertEqual(point, "uncompressedP384" if "384" in algorithm else "uncompressedP256")
                hash_name = "sha384" if "384" in algorithm else "sha256"
                subsequent = iut.cam(100)
                self.assertEqual(subsequent.signer, ("digest", _digest(first.certificate, hash_name)))

    def test_tp_sec_itss_snd_cam_06_bv(self):
        """TP_SEC_ITSS_SND_CAM_06_BV: with CAMs every 100 ms, a CAM containing the
        certificate is at least 1 s after the previous one (TIME >= TIME_LAST + 1 s)."""
        frames = self.iut().cams_every_100_ms(3500)
        times = [f.header["generationTime"] for f in frames if f.signer[0] == "certificate"]
        self.assertGreaterEqual(len(times), 3)
        self.assertTrue(any(f.signer[0] == "digest" for f in frames))
        for last, time in zip(times, times[1:]):
            self.assertGreaterEqual(time - last, ONE_S_US)

    def test_tp_sec_itss_snd_cam_07_bv(self):
        """TP_SEC_ITSS_SND_CAM_07_BV: a CAM with generationTime >= TIME_LAST + 1 s
        (TIME_LAST: the last CAM containing the certificate) contains the certificate."""
        frames = self.iut().cams_every_100_ms(3500)
        last = None
        for frame in frames:
            time = frame.header["generationTime"]
            if last is not None and time >= last + ONE_S_US:
                self.assertEqual(frame.signer[0], "certificate", time - last)
            if frame.signer[0] == "certificate":
                last = time
        self.assertEqual([f.signer[0] for f in frames[:11]], ["certificate"] + ["digest"] * 9 + ["certificate"])

    def unknown_digest(self, iut, at_ms):
        """The test system, with CERT_TS_F_AT unknown to the IUT, sends a CAM signed
        with its digest at ``at_ms``; returns the test system."""
        tester = self.tester()
        tester.cam(at_ms - 100)                                   # certificate, not received
        frame = tester.cam(at_ms)
        self.assertEqual(frame.signer, ("digest", tester.ats[0].as_hashedid8()))
        iut.deliver(frame.raw, at_ms)
        self.assertEqual(iut.cams, [])                            # unknown signer: discarded
        return tester

    def test_tp_sec_itss_snd_cam_08_bv(self):
        """TP_SEC_ITSS_SND_CAM_08_BV: after a CAM signed with the digest of an unknown
        certificate (TIME_1 < TIME_2 < TIME_1 + 1 s), the next CAM contains the
        certificate (TIME_3 < TIME_1 + 1 s)."""
        iut = self.iut()
        self.assertEqual(iut.cam(0).signer[0], "certificate")    # TIME_1
        self.assertEqual(iut.cam(100).signer[0], "digest")
        self.unknown_digest(iut, 200)                             # TIME_2
        self.assertEqual(iut.cam(400).signer[0], "certificate")  # TIME_3

    def test_tp_sec_itss_snd_cam_09_bv(self):
        """TP_SEC_ITSS_SND_CAM_09_BV: the certificate sent because of an unknown signer
        (TIME_3) restarts the timer: the next CAM with the certificate is 1 s later."""
        iut = self.iut()
        iut.cam(0)                                                # TIME_1
        self.unknown_digest(iut, 300)                             # TIME_2
        self.assertEqual(iut.cam(400).signer[0], "certificate")  # TIME_3
        signers = [f.signer[0] for f in iut.cams_every_100_ms(1400, start_ms=500)]
        self.assertEqual(signers, ["digest"] * 9 + ["certificate"])  # TIME_4 = TIME_3 + 1 s

    def test_tp_sec_itss_snd_cam_10_bv(self):
        """TP_SEC_ITSS_SND_CAM_10_BV: after a message signed with the digest DIGEST_F of
        an unknown certificate, the CAM contains inlineP2pcdRequest with the last 3
        octets of DIGEST_F."""
        iut = self.iut()
        iut.cam(0)
        tester = self.unknown_digest(iut, 200)
        frame = iut.cam(300)
        self.assertEqual(frame.header["inlineP2pcdRequest"], [tester.ats[0].as_hashedid8()[-3:]])

    def test_tp_sec_itss_snd_cam_11_bv_xx(self):
        """TP_SEC_ITSS_SND_CAM_11_BV_XX: after a CAM signed with a certificate whose
        issuer (X_FIELD_1: A sha256AndDigest, B sha384AndDigest) DIGEST_F is unknown,
        the CAM contains inlineP2pcdRequest with the last 3 octets of DIGEST_F."""
        for variant, algorithm, field in (("A", "nistP256", "sha256AndDigest"),
                                          ("B", "nistP384", "sha384AndDigest")):
            with self.subTest(variant=variant):
                self.clock, self.pki = _Clock(), _Pki()
                iut = self.iut()
                unknown_aa = self.pki.new_aa("aa-f", algorithm, trusted=False)
                tester = self.tester(self.pki.at(unknown_aa), aas=[self.pki.aa, unknown_aa])
                iut.cam(0)
                frame = tester.cam(100)
                issuer = frame.certificate["issuer"]
                self.assertEqual(issuer[0], field)
                self.assertEqual(issuer[1], unknown_aa.as_hashedid8())
                iut.deliver(frame.raw, 100)
                self.assertEqual(iut.cams, [])
                self.assertEqual(iut.cam(200).header["inlineP2pcdRequest"], [issuer[1][-3:]])

    def request(self, tester, h3, at_ms):
        """A test system CAM with inlineP2pcdRequest [h3] (signed with its certificate)."""
        frame = tester.certificate_cam(at_ms)
        return _resign(frame.raw, tester.ats[0], self.pki.backend, _header("inlineP2pcdRequest", [h3]))

    def test_tp_sec_itss_snd_cam_12_bv(self):
        """TP_SEC_ITSS_SND_CAM_12_BV: after a request of the current AT (HashedId3 in
        inlineP2pcdRequest, TIME_1 < TIME_2 < TIME_1 + 1 s), the next CAM contains that
        certificate (TIME_3 < TIME_1 + 1 s)."""
        at = self.pki.at()
        iut, tester = self.iut(at), self.tester()
        iut.cam(0)                                                # TIME_1
        self.assertEqual(iut.cam(100).signer[0], "digest")
        iut.deliver(self.request(tester, _h3(at), 200), 200)      # TIME_2
        self.assertEqual(len(iut.cams), 1)
        frame = iut.cam(300)                                      # TIME_3
        self.assertEqual(_digest(frame.certificate), at.as_hashedid8())
        self.assertEqual(_digest(frame.certificate)[-3:], _h3(at))

    def test_tp_sec_itss_snd_cam_13_bv(self):
        """TP_SEC_ITSS_SND_CAM_13_BV: after a request of the AA that issued the current
        AT, the CAM contains requestedCertificate with CERT_IUT_A_AA."""
        iut, tester = self.iut(), self.tester()
        iut.cam(0)
        iut.deliver(self.request(tester, _h3(self.pki.aa), 200), 200)
        frame = iut.cam(300)
        self.assertEqual(frame.signer[0], "digest")
        self.assertEqual(_digest(frame.header["requestedCertificate"]), self.pki.aa.as_hashedid8())

    def test_tp_sec_itss_snd_cam_14_bv(self):
        """TP_SEC_ITSS_SND_CAM_14_BV: after a request of a known AA (CERT_IUT_A_N_AA)
        that did not issue the current AT, the CAM contains requestedCertificate with it."""
        aa_n = self.pki.new_aa("aa-n")
        iut, tester = self.iut(), self.tester()
        iut.cam(0)
        iut.deliver(self.request(tester, _h3(aa_n), 200), 200)
        frame = iut.cam(300)
        self.assertEqual(_digest(frame.header["requestedCertificate"]), aa_n.as_hashedid8())

    def test_tp_sec_itss_snd_cam_15_bv(self):
        """TP_SEC_ITSS_SND_CAM_15_BV: a request of CERT_IUT_A_AA (TIME_2 < TIME_1 + 0.8 s)
        already answered by another station (requestedCertificate, TIME_3 < TIME_2 +
        0.1 s) is not answered: no requestedCertificate (TIME_4 < TIME_1 + 0.9 s)."""
        iut, tester = self.iut(), self.tester()
        answering = self.tester(n=10)
        iut.cam(0)                                                # TIME_1
        iut.deliver(answering.cam(50).raw, 50)                      # its AT is now known
        iut.deliver(self.request(tester, _h3(self.pki.aa), 200), 200)          # TIME_2
        answer = _resign(answering.cam(250).raw, answering.ats[0], self.pki.backend,
                         _header("requestedCertificate", deepcopy(self.pki.aa.certificate)))
        iut.deliver(answer, 250)                                  # TIME_3
        self.assertEqual(len(iut.cams), 3)
        frame = iut.cam(300)                                      # TIME_4
        self.assertEqual(frame.signer[0], "digest")
        self.assertNotIn("requestedCertificate", frame.header)

    def test_tp_sec_itss_snd_cam_16_bv(self):
        """TP_SEC_ITSS_SND_CAM_16_BV: a request of CERT_IUT_A_AA at TIME_2 = TIME_1 + 0.9 s:
        the CAM containing the certificate does not contain requestedCertificate.
        The certificate is due one second after TIME_1, so TIME_3 = TIME_1 + 1 s
        (the TP's TIME_3 < TIME_1 + 1 s leaves no CAM with the certificate)."""
        iut, tester = self.iut(), self.tester()
        iut.cams_every_100_ms(800)                                # TIME_1 = 0
        iut.deliver(self.request(tester, _h3(self.pki.aa), 900), 900)          # TIME_2
        frame = iut.cam(1000)                                     # TIME_3
        self.assertEqual(frame.signer[0], "certificate")
        self.assertNotIn("requestedCertificate", frame.header)

    def test_tp_sec_itss_snd_cam_17_bv(self):
        """TP_SEC_ITSS_SND_CAM_17_BV: a request of CERT_IUT_A_AA at TIME_1 + 0.9 s <
        TIME_2 < TIME_1 + 1 s is answered in the first subsequent CAM signed with digest."""
        iut, tester = self.iut(), self.tester()
        iut.cams_every_100_ms(900)                                # TIME_1 = 0
        iut.deliver(self.request(tester, _h3(self.pki.aa), 950), 950)          # TIME_2
        self.assertNotIn("requestedCertificate", iut.cam(1000).header)        # certificate
        frame = iut.cam(1100)
        self.assertEqual(frame.signer[0], "digest")
        self.assertEqual(_digest(frame.header["requestedCertificate"]), self.pki.aa.as_hashedid8())

    def test_tp_sec_itss_snd_cam_18_bv(self):
        """TP_SEC_ITSS_SND_CAM_18_BV: generationTime within CUR_TIME +- 5 min and inside
        the validity period of the signer certificate."""
        self.assert_generation_time(self.iut().cam(0), 300 * ONE_S_US)

    def test_tp_sec_itss_snd_cam_19_bv(self):
        """TP_SEC_ITSS_SND_CAM_19_BV: the signed payload is 'data' with an
        unsecuredData EtsiTs103097Data containing the (non-empty) CAM packet."""
        frame = self.iut().cam(0)
        self.assertEqual(frame.inner["protocolVersion"], 3)
        self.assertEqual(frame.inner["content"][0], "unsecuredData")
        self.assertGreater(len(frame.inner["content"][1]), 44 - 4)
        self.assertEqual(frame.common.ht, HeaderType.TSB)

    def test_tp_sec_itss_snd_cam_20_bv(self):
        """TP_SEC_ITSS_SND_CAM_20_BV: the signer certificate's appPermissions contain AID_CAM."""
        tbs = self.iut().cam(0).certificate["toBeSigned"]
        self.assertTrue(app_permission(tbs, AID_CAM)[0])

    def test_tp_sec_itss_snd_cam_21_bv_xx(self):
        """TP_SEC_ITSS_SND_CAM_21_BV_XX: the signature (A ecdsaNistP256Signature, B
        ecdsaBrainpoolP256r1Signature, C ecdsaBrainpoolP384r1Signature) verifies with
        the key of X_CERTIFICATE, for certificate and digest signers."""
        for variant in ("A", "B", "C"):
            with self.subTest(variant=variant):
                algorithm = CURVES[variant][0]
                self.clock, self.pki = _Clock(), _Pki(algorithm)
                at = self.pki.at(algorithm=algorithm)
                iut = self.iut(at)
                key = at.certificate["toBeSigned"]["verifyKeyIndicator"][1]
                for frame in (iut.cam(0), iut.cam(100)):
                    self.assertEqual(frame.signed["hashId"], at.hash_name())
                    self.assertEqual(frame.signature[0], SIGNATURES[algorithm])
                    self.assertTrue(_verifies(frame, at.certificate, key, self.pki.backend))
                    if frame.signer[0] == "digest":
                        self.assertEqual(frame.signer[1], at.as_hashedid8())

    def test_tp_sec_itss_snd_cam_22_bv_xx(self):
        """TP_SEC_ITSS_SND_CAM_22_BV_XX: the signature's rSig is x-only,
        compressed-y-0 or compressed-y-1 (A, B, C as CAM_21)."""
        for variant in ("A", "B", "C"):
            with self.subTest(variant=variant):
                algorithm = CURVES[variant][0]
                self.clock, self.pki = _Clock(), _Pki(algorithm)
                frame = self.iut(self.pki.at(algorithm=algorithm)).cam(0)
                self.assertEqual(frame.signature[0], SIGNATURES[algorithm])
                self.assertIn(frame.signature[1]["rSig"][0], ("x-only", "compressed-y-0", "compressed-y-1"))

    def test_tp_sec_itss_snd_cam_23_bv(self):
        """TP_SEC_ITSS_SND_CAM_23_BV (both definitions): (1) an AT with 8 appPermissions,
        AID_CAM the last, signs the CAM (psid AID_CAM); (2) the only AT has a
        rectangular region not containing the IUT position: no CAM."""
        permissions = [{"psid": 130 + i} for i in range(7)] + [APP_PERMISSIONS[0]]
        frame = self.iut(self.pki.at(appPermissions=permissions)).cam(0)
        self.assertEqual(frame.header["psid"], AID_CAM)
        self.assertEqual(len(frame.certificate["toBeSigned"]["appPermissions"]), 8)
        iut = self.iut(self.pki.at(region=FAR_RECTANGLE))
        self.assertIsNone(iut.cam(100))
        self.assertEqual(iut.log, [])

    def test_tp_sec_itss_snd_cam_24_bv(self):
        """TP_SEC_ITSS_SND_CAM_24_BV (both definitions): (1) an AT issued by an AA with 8
        certIssuePermissions, AID_CAM the last, signs the CAM; (2) the only AT has no
        region and its AA a rectangular region not containing the IUT position: no CAM."""
        def group(psid):
            return {"subjectPermissions": ("explicit", [{"psid": psid}]), "minChainLength": 0,
                    "chainLengthRange": 0, "eeType": (b"\x80", 8)}
        groups = [group(130 + i) for i in range(7)] + [group(AID_CAM)]
        aa8 = self.pki.new_aa("aa-a8", certIssuePermissions=groups)
        frame = self.iut(self.pki.at(aa8, appPermissions=[APP_PERMISSIONS[0]])).cam(0)
        self.assertEqual(frame.header["psid"], AID_CAM)
        aa_c3 = self.pki.new_aa("aa-c3", region=FAR_RECTANGLE)
        iut = self.iut(self.pki.at(aa_c3))
        self.assertIsNone(iut.cam(100))
        self.assertEqual(iut.log, [])

    def assert_no_cam(self, at):
        iut = self.iut(at)
        self.assertIsNone(iut.cam(0))
        self.assertEqual(iut.log, [])

    def test_tp_sec_itss_snd_cam_25_bv(self):
        """TP_SEC_ITSS_SND_CAM_25_BV: the only AT is expired (start + duration < now): no CAM."""
        self.assert_no_cam(self.pki.at(validityPeriod=_validity(-7200, ("hours", 1))))

    def test_tp_sec_itss_snd_cam_26_bv(self):
        """TP_SEC_ITSS_SND_CAM_26_BV: the only AT starts in the future: no CAM."""
        self.assert_no_cam(self.pki.at(validityPeriod=_validity(3600, ("hours", 1))))

    def test_tp_sec_itss_snd_cam_27_bv(self):
        """TP_SEC_ITSS_SND_CAM_27_BV: the only AT has no appPermissions for AID_CAM: no CAM."""
        self.assert_no_cam(self.pki.at(appPermissions=[APP_PERMISSIONS[1], APP_PERMISSIONS[2]]))


# ─── Sending: DENM ──────────────────────────────────────────────────────────


class TestSecSndDenm(_SecTest):
    """TP_SEC_ITSS_SND_DENM: secured DENMs sent by the IUT (TS 103 097 clause 7.1.2)."""

    def setUp(self):
        super().setUp()
        _register_identified_regions(self)

    def assert_inside(self, frame, region, position=INSIDE):
        """generationLocation is the IUT position and lies inside ``region``."""
        location = frame.header["generationLocation"]
        self.assertEqual((location["latitude"], location["longitude"]),
                         (position["latitude"], position["longitude"]))
        tbs = _at_tbs(region=region)
        self.assertTrue(location_permitted(Certificate.from_dict(
            {"version": 3, "type": "explicit", "issuer": ("self", "sha256"), "toBeSigned": tbs}),
            location["latitude"], location["longitude"]))

    def test_tp_sec_itss_snd_denm_01_bv(self):
        """TP_SEC_ITSS_SND_DENM_01_BV: the DENM is sent in a signedData container."""
        self.assertEqual(self.iut().denm().content[0], "signedData")

    def test_tp_sec_itss_snd_denm_02_bv(self):
        """TP_SEC_ITSS_SND_DENM_02_BV: headerInfo psid is AID_DENM."""
        self.assertEqual(self.iut().denm().header["psid"], AID_DENM)

    def test_tp_sec_itss_snd_denm_03_bv(self):
        """TP_SEC_ITSS_SND_DENM_03_BV: headerInfo contains generationTime and
        generationLocation and none of expiryTime, encryptionKey, p2pcdLearningRequest,
        missingCrlIdentifier, inlineP2pcdRequest, requestedCertificate."""
        iut, tester = self.iut(), self.tester()
        iut.cam(0)
        tester.cam(0)                                     # certificate, not received
        iut.deliver(tester.cam(100).raw, 100)             # unknown digest: pending P2PCD request
        self.assertIn("inlineP2pcdRequest", iut.cam(200).header)
        frame = iut.denm(300)
        self.assertIn("generationTime", frame.header)
        self.assertIn("generationLocation", frame.header)
        for field in ("expiryTime", "encryptionKey", "p2pcdLearningRequest", "missingCrlIdentifier",
                      "inlineP2pcdRequest", "requestedCertificate"):
            self.assertNotIn(field, frame.header)

    def test_tp_sec_itss_snd_denm_04_bv(self):
        """TP_SEC_ITSS_SND_DENM_04_BV: signer is a certificate whose appPermissions
        contain AID_DENM (every DENM, also within 1 s)."""
        iut = self.iut()
        for frame in (iut.denm(0), iut.denm(100)):
            psids = [item["psid"] for item in frame.certificate["toBeSigned"]["appPermissions"]]
            self.assertIn(AID_DENM, psids)

    def test_tp_sec_itss_snd_denm_05_bv(self):
        """TP_SEC_ITSS_SND_DENM_05_BV: generationTime within CUR_TIME +- 10 min and inside
        the validity period of the signer certificate."""
        self.assert_generation_time(self.iut().denm(), 600 * ONE_S_US)

    def test_tp_sec_itss_snd_denm_06_bv(self):
        """TP_SEC_ITSS_SND_DENM_06_BV: AT, AA and RCA without region: the DENM contains
        generationLocation."""
        frame = self.iut().denm()
        self.assertNotIn("region", frame.certificate["toBeSigned"])
        for ca in (self.pki.aa, self.pki.root):
            self.assertNotIn("region", ca.certificate["toBeSigned"])
        self.assertEqual(frame.header["generationLocation"]["latitude"], INSIDE["latitude"])

    def test_tp_sec_itss_snd_denm_07_bv_xx(self):
        """TP_SEC_ITSS_SND_DENM_07_BV_XX: AT with region (B circularRegion, C
        rectangularRegion, D polygonalRegion, E identifiedRegion): generationLocation
        inside the region."""
        for variant, region in REGIONS.items():
            with self.subTest(variant=variant):
                frame = self.iut(self.pki.at(region=region)).denm()
                self.assertEqual(frame.certificate["toBeSigned"]["region"][0], region[0])
                self.assert_inside(frame, region)

    def test_tp_sec_itss_snd_denm_09_bv(self):
        """TP_SEC_ITSS_SND_DENM_09_BV: AT without region, AA and RCA with a circular
        REGION: generationLocation inside REGION."""
        self.pki = _Pki(region=CIRCLE)
        self.pki.root = _ca(self.pki.backend, "root-c", None, 2, region=CIRCLE)
        self.pki.aa = _ca(self.pki.backend, "aa-cc", self.pki.root, 1, region=CIRCLE)
        self.pki.roots, self.pki.aas = [self.pki.root], [self.pki.aa]
        frame = self.iut().denm()
        self.assertNotIn("region", frame.certificate["toBeSigned"])
        self.assert_inside(frame, CIRCLE)

    def test_tp_sec_itss_snd_denm_10_bv(self):
        """TP_SEC_ITSS_SND_DENM_10_BV: AT and AA without region, RCA with a circular
        REGION: generationLocation inside REGION."""
        self.pki.root = _ca(self.pki.backend, "root-c", None, 2, region=CIRCLE)
        self.pki.aa = _ca(self.pki.backend, "aa-ca", self.pki.root, 1)
        self.pki.roots, self.pki.aas = [self.pki.root], [self.pki.aa]
        frame = self.iut().denm()
        self.assertNotIn("region", self.pki.aa.certificate["toBeSigned"])
        self.assert_inside(frame, CIRCLE)

    def test_tp_sec_itss_snd_denm_11_bv(self):
        """TP_SEC_ITSS_SND_DENM_11_BV: the signed payload is 'data' with an
        unsecuredData EtsiTs103097Data containing the (non-empty) DENM packet."""
        frame = self.iut().denm()
        self.assertEqual(frame.inner["content"][0], "unsecuredData")
        self.assertGreater(len(frame.inner["content"][1]), 56)
        self.assertEqual(frame.common.ht, HeaderType.GEOBROADCAST)

    def test_tp_sec_itss_snd_denm_12_bv(self):
        """TP_SEC_ITSS_SND_DENM_12_BV: the signer certificate's appPermissions contain AID_DENM."""
        self.assertTrue(app_permission(self.iut().denm().certificate["toBeSigned"], AID_DENM)[0])

    def test_tp_sec_itss_snd_denm_13_bv(self):
        """TP_SEC_ITSS_SND_DENM_13_BV: the signer certificate is X_CERTIFICATE with X_KEY
        and the signature X_SIGNATURE verifies with it (A NIST P-256, B
        brainpoolP256r1, C brainpoolP384r1)."""
        for variant in ("A", "B", "C"):
            with self.subTest(variant=variant):
                algorithm = CURVES[variant][0]
                self.clock, self.pki = _Clock(), _Pki(algorithm)
                at = self.pki.at(algorithm=algorithm)
                frame = self.iut(at).denm()
                key = frame.certificate["toBeSigned"]["verifyKeyIndicator"][1]
                self.assertEqual(key[0], KEYS[algorithm])
                self.assertEqual(_digest(frame.certificate, at.hash_name()), at.as_hashedid8())
                self.assertEqual(frame.signed["hashId"], "sha384" if "384" in algorithm else "sha256")
                self.assertEqual(frame.signature[0], SIGNATURES[algorithm])
                self.assertTrue(_verifies(frame, frame.certificate, key, self.pki.backend))

    def test_tp_sec_itss_snd_denm_14_bv(self):
        """TP_SEC_ITSS_SND_DENM_14_BV: AT rectangularRegion with 8 entries, one containing
        the IUT: generationLocation inside that entry."""
        frame = self.iut(self.pki.at(region=RECTANGLES_8)).denm()
        self.assertEqual(len(frame.certificate["toBeSigned"]["region"][1]), 8)
        self.assert_inside(frame, ("rectangularRegion", [RECTANGLES_8[1][5]]))

    def test_tp_sec_itss_snd_denm_15_bv(self):
        """TP_SEC_ITSS_SND_DENM_15_BV: AT polygonalRegion with 8 points containing the
        IUT: generationLocation inside the polygon."""
        frame = self.iut(self.pki.at(region=POLYGON_8)).denm()
        self.assertEqual(len(frame.certificate["toBeSigned"]["region"][1]), 8)
        self.assert_inside(frame, POLYGON_8)

    def test_tp_sec_itss_snd_denm_16_bv(self):
        """TP_SEC_ITSS_SND_DENM_16_BV: AT identifiedRegion with 8 entries, one containing
        the IUT: generationLocation inside that entry."""
        frame = self.iut(self.pki.at(region=IDENTIFIED_8)).denm()
        self.assertEqual(len(frame.certificate["toBeSigned"]["region"][1]), 8)
        self.assert_inside(frame, IDENTIFIED)

    def assert_no_denm(self, at, **kwargs):
        iut = self.iut(at, **kwargs)
        self.assertIsNone(iut.denm())
        self.assertEqual(iut.log, [])

    def test_tp_sec_itss_snd_denm_17_bv(self):
        """TP_SEC_ITSS_SND_DENM_17_BV: the AT region (rectangular) does not contain the
        IUT position: no DENM."""
        self.assert_no_denm(self.pki.at(region=FAR_RECTANGLE))

    def test_tp_sec_itss_snd_denm_18_bv(self):
        """TP_SEC_ITSS_SND_DENM_18_BV: AT without region, issued by an AA whose
        rectangular region does not contain the IUT position: no DENM."""
        self.assert_no_denm(self.pki.at(self.pki.new_aa("aa-c3", region=FAR_RECTANGLE)))

    def test_tp_sec_itss_snd_denm_19_bv(self):
        """TP_SEC_ITSS_SND_DENM_19_BV: the only AT is expired: no DENM."""
        self.assert_no_denm(self.pki.at(validityPeriod=_validity(-7200, ("hours", 1))))

    def test_tp_sec_itss_snd_denm_20_bv(self):
        """TP_SEC_ITSS_SND_DENM_20_BV: the only AT starts in the future: no DENM."""
        self.assert_no_denm(self.pki.at(validityPeriod=_validity(3600, ("hours", 1))))

    def test_tp_sec_itss_snd_denm_21_bv(self):
        """TP_SEC_ITSS_SND_DENM_21_BV: the only AT has no appPermissions for AID_DENM: no DENM."""
        self.assert_no_denm(self.pki.at(appPermissions=[APP_PERMISSIONS[0], APP_PERMISSIONS[2]]))


# ─── Sending: other messages (GeoNetworking Beacon) ─────────────────────────


class TestSecSndGenMsg(_SecTest):
    """TP_SEC_ITSS_SND_GENMSG: secured Beacons sent by the IUT (TS 103 097 clause 7.1.3)."""

    def beacon(self, at=None):
        return self.iut(*([at] if at else []), beacon=True).beacon()

    def test_tp_sec_itss_snd_genmsg_01_bv(self):
        """TP_SEC_ITSS_SND_GENMSG_01_BV: the Beacon is sent in a signedData container."""
        frame = self.beacon()
        self.assertEqual(frame.content[0], "signedData")
        self.assertEqual(frame.common.ht, HeaderType.BEACON)

    def test_tp_sec_itss_snd_genmsg_02_bv(self):
        """TP_SEC_ITSS_SND_GENMSG_02_BV: headerInfo psid is AID_GNMGMT (not AID_CAM/AID_DENM)."""
        self.assertEqual(self.beacon().header["psid"], AID_GNMGMT)

    def test_tp_sec_itss_snd_genmsg_03_bv(self):
        """TP_SEC_ITSS_SND_GENMSG_03_BV: headerInfo contains generationTime and no
        p2pcdLearningRequest nor missingCrlIdentifier."""
        header = self.beacon().header
        self.assertIn("generationTime", header)
        self.assertNotIn("p2pcdLearningRequest", header)
        self.assertNotIn("missingCrlIdentifier", header)

    def test_tp_sec_itss_snd_genmsg_04_bv(self):
        """TP_SEC_ITSS_SND_GENMSG_04_BV: signer is a certificate whose appPermissions
        contain AID_GNMGMT, or its digest."""
        at = self.pki.at()
        iut = self.iut(at, beacon=True)
        first, second = iut.beacon(), iut.beacon()
        psids = [item["psid"] for item in first.certificate["toBeSigned"]["appPermissions"]]
        self.assertIn(AID_GNMGMT, psids)
        if second.signer[0] == "digest":
            self.assertEqual(second.signer[1], at.as_hashedid8())
        else:
            self.assertEqual(_digest(second.certificate), at.as_hashedid8())

    def test_tp_sec_itss_snd_genmsg_05_bv(self):
        """TP_SEC_ITSS_SND_GENMSG_05_BV: generationTime within CUR_TIME +- 10 min and
        inside the validity period of the signer certificate."""
        self.assert_generation_time(self.beacon(), 600 * ONE_S_US)

    def test_tp_sec_itss_snd_genmsg_06_bv(self):
        """TP_SEC_ITSS_SND_GENMSG_06_BV: the signed payload is 'data' with an
        unsecuredData EtsiTs103097Data containing the (non-empty) Beacon packet."""
        frame = self.beacon()
        self.assertEqual(frame.inner["content"][0], "unsecuredData")
        self.assertEqual(len(frame.inner["content"][1]), 8 + 24)

    def test_tp_sec_itss_snd_genmsg_07_bv(self):
        """TP_SEC_ITSS_SND_GENMSG_07_BV: the signer certificate's appPermissions contain AID_GNMGMT."""
        self.assertTrue(app_permission(self.beacon().certificate["toBeSigned"], AID_GNMGMT)[0])
        iut = self.iut(self.pki.at(appPermissions=APP_PERMISSIONS[:2]), beacon=True)
        self.assertIsNone(iut.beacon())                   # no AT for AID_GNMGMT: no Beacon

    def test_tp_sec_itss_snd_genmsg_08_bv(self):
        """TP_SEC_ITSS_SND_GENMSG_08_BV: the signature X_SIGNATURE verifies with the key
        of X_CERTIFICATE (A NIST P-256, B brainpoolP256r1, C brainpoolP384r1)."""
        for variant in ("A", "B", "C"):
            with self.subTest(variant=variant):
                algorithm = CURVES[variant][0]
                self.clock, self.pki = _Clock(), _Pki(algorithm)
                at = self.pki.at(algorithm=algorithm)
                frame = self.beacon(at)
                key = at.certificate["toBeSigned"]["verifyKeyIndicator"][1]
                self.assertEqual(frame.signed["hashId"], at.hash_name())
                self.assertEqual(frame.signature[0], SIGNATURES[algorithm])
                self.assertTrue(_verifies(frame, at.certificate, key, self.pki.backend))


# ─── Receiving ──────────────────────────────────────────────────────────────


class _RcvTest(_SecTest):
    """The IUT and a test system station; helpers to check acceptance."""

    def setUp(self):
        super().setUp()
        _register_identified_regions(self)

    def assert_accepted(self, iut, raw, kind="cam"):
        received = iut.cams if kind == "cam" else iut.denms
        before = len(received)
        iut.deliver(raw)
        self.assertEqual(len(received), before + 1, "the IUT accepts the message")

    def assert_discarded(self, iut, tester, raw, kind="cam"):
        """``raw`` is not passed to the facility; a valid message of the same test
        system sent afterwards is."""
        received = iut.cams if kind == "cam" else iut.denms
        before = len(received)
        iut.deliver(raw)
        self.assertEqual(len(received), before, "the IUT discards the message")
        self.clock.ms += 100
        valid = tester.certificate_cam(self.clock.ms) if kind == "cam" else tester.denm(self.clock.ms)
        self.assert_accepted(iut, valid.raw, kind)

    def brainpool(self, algorithm, kind):
        """A CAM or DENM signed with an AT on ``algorithm`` is accepted."""
        iut, tester = self.iut(), self.tester(self.pki.at(algorithm=algorithm))
        frame = tester.cam(0) if kind == "cam" else tester.denm(0)
        self.assertEqual(frame.certificate["toBeSigned"]["verifyKeyIndicator"][1][0], KEYS[algorithm])
        self.assertEqual(frame.signed["hashId"], "sha384" if "384" in algorithm else "sha256")
        self.assertEqual(frame.signature[0], SIGNATURES[algorithm])
        self.assertEqual(frame.signature[1]["rSig"][0], "x-only")
        self.assert_accepted(iut, frame.raw, kind)

    def assert_rcv_01_content(self, frame, at, kind):
        """The message of TP_SEC_ITSS_RCV_CAM_01_BV / RCV_DENM_01_BV."""
        self.assertEqual(frame.protocol_version, 3)
        self.assertEqual(frame.signed["hashId"], at.hash_name())
        self.assertEqual(frame.inner["protocolVersion"], 3)
        self.assertEqual(frame.inner["content"][0], "unsecuredData")
        expected = {"psid", "generationTime"} | ({"generationLocation"} if kind == "denm" else set())
        self.assertEqual(set(frame.header), expected)
        self.assertEqual(frame.header["psid"], AID_CAM if kind == "cam" else AID_DENM)
        self.assertLessEqual(abs(frame.header["generationTime"] - self.clock.its_us()), 2 * ONE_S_US)
        self.assertEqual(len(frame.signer[1]), 1)
        self.assertEqual(_digest(frame.certificate, at.hash_name()), at.as_hashedid8())
        self.assertEqual(frame.signature[1]["rSig"][0], "x-only")


class TestSecRcvMessage(_RcvTest):
    """TP_SEC_ITSS_RCV_MSG: protocol version of received messages (TS 103 097 clause 5.1)."""

    def test_tp_sec_itss_rcv_msg_01_bv(self):
        """TP_SEC_ITSS_RCV_MSG_01_BV: a message with protocolVersion 3 is forwarded to the facilities."""
        iut, tester = self.iut(), self.tester()
        frame = tester.cam(0)
        self.assertEqual(frame.protocol_version, 3)
        self.assert_accepted(iut, frame.raw)

    def test_tp_sec_itss_rcv_msg_01_bo(self):
        """TP_SEC_ITSS_RCV_MSG_01_BO: protocolVersion 2 is discarded."""
        iut, tester = self.iut(), self.tester()
        raw = _resign(tester.cam(0).raw, tester.ats[0], self.pki.backend, protocol_version=2)
        self.assert_discarded(iut, tester, raw)

    def test_tp_sec_itss_rcv_msg_02_bo(self):
        """TP_SEC_ITSS_RCV_MSG_02_BO: protocolVersion 4 is discarded."""
        iut, tester = self.iut(), self.tester()
        raw = _resign(tester.cam(0).raw, tester.ats[0], self.pki.backend, protocol_version=4)
        self.assert_discarded(iut, tester, raw)


def _with_compressed_r(raw, at, backend):
    """``raw`` with the NIST P-256 signature's rSig as the point R (compressed-y-0 or
    -1, IEEE 1609.2 clause 6.3.30), R = u1*G + u2*Q recomputed from the signature."""
    data = SECURITY_CODER.decode_etsi_ts_103097_data_signed(raw[4:])
    signed = data["content"][1]
    curve, n = ecdsa.NIST256p, ecdsa.NIST256p.order
    r = int.from_bytes(signed["signature"][1]["rSig"][1], "big")
    s = int.from_bytes(signed["signature"][1]["sSig"], "big")
    tbs = SECURITY_CODER.encode_to_be_signed_data(signed["tbsData"])
    e = int.from_bytes(hashlib.sha256(hashlib.sha256(tbs).digest() + hashlib.sha256(
        _canonical_bytes(signed["signer"][1][0])).digest()).digest(), "big")
    q = backend.keys[at.key_id].verifying_key.pubkey.point
    w = pow(s, -1, n)
    point = (curve.generator * (e * w % n) + q * (r * w % n)).to_affine()
    if point.x() % n != r:
        raise AssertionError("signature does not verify")
    choice = "compressed-y-0" if point.y() % 2 == 0 else "compressed-y-1"
    signed["signature"][1]["rSig"] = (choice, point.x().to_bytes(32, "big"))
    return raw[:4] + SECURITY_CODER.encode_etsi_ts_103097_data_signed(data)


class TestSecRcvCam(_RcvTest):
    """TP_SEC_ITSS_RCV_CAM: secured CAMs received by the IUT (TS 103 097 clauses 6, 7.1.1)."""

    def test_tp_sec_itss_rcv_cam_01_bv(self):
        """TP_SEC_ITSS_RCV_CAM_01_BV: a valid CAM signed with certificate CERT_TS_A_AT is accepted."""
        iut, tester = self.iut(), self.tester()
        frame = tester.cam(0)
        self.assert_rcv_01_content(frame, tester.ats[0], "cam")
        self.assertEqual(frame.signature[0], "ecdsaNistP256Signature")
        self.assert_accepted(iut, frame.raw)

    def test_tp_sec_itss_rcv_cam_02_bv(self):
        """TP_SEC_ITSS_RCV_CAM_02_BV: once CERT_TS_A_AT is known, a CAM signed with its
        digest is accepted."""
        iut, tester = self.iut(), self.tester()
        self.assert_accepted(iut, tester.cam(0).raw)
        frame = tester.cam(100)
        self.assertEqual(frame.signer, ("digest", tester.ats[0].as_hashedid8()))
        self.assert_accepted(iut, frame.raw)

    def test_tp_sec_itss_rcv_cam_03_bv(self):
        """TP_SEC_ITSS_RCV_CAM_03_BV: a CAM whose ecdsaNistP256Signature rSig is
        compressed-y-0 or compressed-y-1 is accepted."""
        iut, tester = self.iut(), self.tester()
        raw = _with_compressed_r(tester.cam(0).raw, tester.ats[0], self.pki.backend)
        self.assertIn(_Secured(raw).signature[1]["rSig"][0], ("compressed-y-0", "compressed-y-1"))
        self.assert_accepted(iut, raw)

    def test_tp_sec_itss_rcv_cam_04_bv_xx(self):
        """TP_SEC_ITSS_RCV_CAM_04_BV_XX: a CAM signed with an AT with region (01
        circularRegion, 02 rectangularRegion, 03 polygonalRegion, 04 identifiedRegion)
        containing the IUT position is accepted."""
        for number, region in zip(("01", "02", "03", "04"), REGIONS.values()):
            with self.subTest(variant=number):
                iut, tester = self.iut(), self.tester(self.pki.at(region=region))
                frame = tester.cam(self.clock.ms)
                self.assertEqual(frame.certificate["toBeSigned"]["region"][0], region[0])
                self.assertEqual(frame.signature[1]["rSig"][0], "x-only")
                self.assert_accepted(iut, frame.raw)

    def test_tp_sec_itss_rcv_cam_05_bv(self):
        """TP_SEC_ITSS_RCV_CAM_05_BV: a CAM signed with brainpoolP256r1 (CERT_TS_A_B_AT) is accepted."""
        self.brainpool("brainpoolP256r1", "cam")

    def test_tp_sec_itss_rcv_cam_06_bv(self):
        """TP_SEC_ITSS_RCV_CAM_06_BV: a CAM signed with brainpoolP384r1 (CERT_TS_A_B3_AT) is accepted."""
        self.brainpool("brainpoolP384r1", "cam")

    def discarded(self, mutate, sign=True, digest=False):
        iut, tester = self.iut(), self.tester()
        if digest:                                       # the message of RCV_CAM_02_BV
            self.assert_accepted(iut, tester.cam(0).raw)
            frame = tester.cam(100)
        else:
            frame = tester.cam(0)
        self.assert_discarded(iut, tester, _resign(frame.raw, tester.ats[0], self.pki.backend, mutate, sign))

    def test_tp_sec_itss_rcv_cam_01_bo(self):
        """TP_SEC_ITSS_RCV_CAM_01_BO: a CAM (digest signer) whose psid is not AID_CAM is discarded."""
        self.discarded(_header("psid", AID_DENM), digest=True)

    def test_tp_sec_itss_rcv_cam_02_bo(self):
        """TP_SEC_ITSS_RCV_CAM_02_BO: a CAM with generationLocation is discarded."""
        self.discarded(_header("generationLocation", dict(INSIDE, elevation=0xF000)))

    def test_tp_sec_itss_rcv_cam_03_bo(self):
        """TP_SEC_ITSS_RCV_CAM_03_BO: a CAM with expiryTime is discarded."""
        self.discarded(_header("expiryTime", self.clock.its_us() + 60 * ONE_S_US))

    def test_tp_sec_itss_rcv_cam_04_bo(self):
        """TP_SEC_ITSS_RCV_CAM_04_BO: a CAM with p2pcdLearningRequest is discarded."""
        self.discarded(_header("p2pcdLearningRequest", b"\x01\x02\x03"))

    def test_tp_sec_itss_rcv_cam_05_bo(self):
        """TP_SEC_ITSS_RCV_CAM_05_BO: a CAM with missingCrlIdentifier is discarded."""
        self.discarded(_header("missingCrlIdentifier", {"cracaId": b"\x00\x00\x00", "crlSeries": 0}))

    def test_tp_sec_itss_rcv_cam_06_bo(self):
        """TP_SEC_ITSS_RCV_CAM_06_BO: a CAM with encryptionKey is discarded."""
        self.discarded(_header("encryptionKey", ("symmetric", ("aes128Ccm", b"\x00" * 16))))

    def test_tp_sec_itss_rcv_cam_07_bo(self):
        """TP_SEC_ITSS_RCV_CAM_07_BO: a CAM whose signature algorithm does not match the
        signer key (ecdsaNistP384Signature for a NIST P-256 key) is discarded."""
        self.discarded(_invalid_signature_algorithm, sign=False)

    def test_tp_sec_itss_rcv_cam_08_bo(self):
        """TP_SEC_ITSS_RCV_CAM_08_BO: a CAM whose SignerIdentifier is 'self' is discarded."""
        self.discarded(lambda signed: signed.__setitem__("signer", ("self", None)))

    def test_tp_sec_itss_rcv_cam_09_bo(self):
        """TP_SEC_ITSS_RCV_CAM_09_BO: a CAM with an altered signature value is discarded."""
        self.discarded(_altered_signature, sign=False)


def _invalid_signature_algorithm(signed):
    signed["signature"] = ("ecdsaNistP384Signature", {"rSig": ("x-only", b"\x11" * 48),
                                                      "sSig": b"\x22" * 48})


def _altered_signature(signed):
    s = bytearray(signed["signature"][1]["sSig"])
    s[-1] ^= 0x01
    signed["signature"][1]["sSig"] = bytes(s)


class TestSecRcvDenm(_RcvTest):
    """TP_SEC_ITSS_RCV_DENM: secured DENMs received by the IUT (TS 103 097 clauses 6, 7.1.2)."""

    def test_tp_sec_itss_rcv_denm_01_bv(self):
        """TP_SEC_ITSS_RCV_DENM_01_BV: a valid DENM signed with certificate CERT_TS_A_AT is accepted."""
        iut, tester = self.iut(), self.tester()
        frame = tester.denm(0)
        self.assert_rcv_01_content(frame, tester.ats[0], "denm")
        self.assertEqual(frame.signature[0], "ecdsaNistP256Signature")
        self.assert_accepted(iut, frame.raw, "denm")

    def test_tp_sec_itss_rcv_denm_02_bv_xx(self):
        """TP_SEC_ITSS_RCV_DENM_02_BV_XX: a DENM signed with an AT with region (01..04 as
        RCV_CAM_04) and generationLocation inside it is accepted."""
        for number, region in zip(("01", "02", "03", "04"), REGIONS.values()):
            with self.subTest(variant=number):
                iut, tester = self.iut(), self.tester(self.pki.at(region=region))
                frame = tester.denm(self.clock.ms)
                self.assertEqual(frame.certificate["toBeSigned"]["region"][0], region[0])
                location = frame.header["generationLocation"]
                self.assertEqual((location["latitude"], location["longitude"]),
                                 (INSIDE["latitude"], INSIDE["longitude"]))
                self.assert_accepted(iut, frame.raw, "denm")

    def test_tp_sec_itss_rcv_denm_03_bv(self):
        """TP_SEC_ITSS_RCV_DENM_03_BV: a DENM signed with brainpoolP256r1 is accepted."""
        self.brainpool("brainpoolP256r1", "denm")

    def test_tp_sec_itss_rcv_denm_04_bv(self):
        """TP_SEC_ITSS_RCV_DENM_04_BV: a DENM signed with brainpoolP384r1 is accepted."""
        self.brainpool("brainpoolP384r1", "denm")

    def discarded(self, mutate, sign=True):
        iut, tester = self.iut(), self.tester()
        raw = _resign(tester.denm(0).raw, tester.ats[0], self.pki.backend, mutate, sign)
        self.assert_discarded(iut, tester, raw, "denm")

    def test_tp_sec_itss_rcv_denm_01_bo(self):
        """TP_SEC_ITSS_RCV_DENM_01_BO: a DENM whose psid is not AID_DENM is discarded."""
        self.discarded(_header("psid", AID_CAM))

    def test_tp_sec_itss_rcv_denm_02_bo(self):
        """TP_SEC_ITSS_RCV_DENM_02_BO: a DENM without generationLocation is discarded."""
        self.discarded(_drop_header("generationLocation"))

    def test_tp_sec_itss_rcv_denm_03_bo(self):
        """TP_SEC_ITSS_RCV_DENM_03_BO: a DENM with expiryTime is discarded."""
        self.discarded(_header("expiryTime", self.clock.its_us() + 60 * ONE_S_US))

    def test_tp_sec_itss_rcv_denm_04_bo(self):
        """TP_SEC_ITSS_RCV_DENM_04_BO: a DENM with p2pcdLearningRequest is discarded."""
        self.discarded(_header("p2pcdLearningRequest", b"\x01\x02\x03"))

    def test_tp_sec_itss_rcv_denm_05_bo(self):
        """TP_SEC_ITSS_RCV_DENM_05_BO: a DENM with missingCrlIdentifier is discarded."""
        self.discarded(_header("missingCrlIdentifier", {"cracaId": b"\x00\x00\x00", "crlSeries": 0}))

    def test_tp_sec_itss_rcv_denm_06_bo(self):
        """TP_SEC_ITSS_RCV_DENM_06_BO: a DENM with encryptionKey is discarded."""
        self.discarded(_header("encryptionKey", ("symmetric", ("aes128Ccm", b"\x00" * 16))))

    def test_tp_sec_itss_rcv_denm_07_bo(self):
        """TP_SEC_ITSS_RCV_DENM_07_BO: a DENM with an invalid signature algorithm is discarded."""
        self.discarded(_invalid_signature_algorithm, sign=False)

    def test_tp_sec_itss_rcv_denm_08_bo(self):
        """TP_SEC_ITSS_RCV_DENM_08_BO: a DENM whose SignerIdentifier is 'self' is discarded."""
        self.discarded(lambda signed: signed.__setitem__("signer", ("self", None)))

    def test_tp_sec_itss_rcv_denm_09_bo(self):
        """TP_SEC_ITSS_RCV_DENM_09_BO: a DENM with an altered signature value is discarded."""
        self.discarded(_altered_signature, sign=False)


# ─── Implicit certificates ──────────────────────────────────────────────────


class TestSecImplicitCertificates(_RcvTest):
    """TP_SEC_ITSS_*_IMPLICIT_CERT: ECQV implicit ATs (IEEE 1609.2 clause 5.3.2)."""

    def test_tp_sec_itss_snd_implicit_cert_01_bv(self):
        """TP_SEC_ITSS_SND_IMPLICIT_CERT_01_BV: authorized with an implicit AT, the IUT
        signs the CAM with it (signer certificate, ecdsaNistP256Signature verifying
        with the key reconstructed from the reconstruction value)."""
        implicit = self.pki.implicit_at()
        frame = self.iut(implicit).cam(0)
        certificate = frame.certificate
        self.assertEqual(certificate["type"], "implicit")
        self.assertEqual(certificate["toBeSigned"]["verifyKeyIndicator"][0], "reconstructionValue")
        self.assertEqual(_digest(certificate), implicit.as_hashedid8())
        self.assertEqual(frame.signature[0], "ecdsaNistP256Signature")
        key = Certificate.from_dict(certificate, issuer=self.pki.aa).verification_key()
        self.assertTrue(_verifies(frame, certificate, key, self.pki.backend))

    def test_tp_sec_itss_rcv_implicit_cert_01_bv(self):
        """TP_SEC_ITSS_RCV_IMPLICIT_CERT_01_BV: a CAM signed with a known implicit AT
        (CERT_TS_A_IMP_AT) is accepted."""
        implicit = self.pki.implicit_at()
        iut, tester = self.iut(known_ats=[implicit]), self.tester(implicit)
        frame = tester.cam(0)
        self.assertEqual(frame.signed["hashId"], "sha256")
        self.assertEqual(frame.certificate["type"], "implicit")
        self.assertEqual(frame.signature[1]["rSig"][0], "x-only")
        self.assert_accepted(iut, frame.raw)

    def test_tp_sec_itss_rcv_implicit_cert_02_bv(self):
        """TP_SEC_ITSS_RCV_IMPLICIT_CERT_02_BV: a CAM signed with an unknown implicit AT
        (CERT_TS_F_AT_IMP) is accepted."""
        iut, tester = self.iut(), self.tester(self.pki.implicit_at())
        frame = tester.cam(0)
        self.assertEqual(frame.certificate["type"], "implicit")
        self.assert_accepted(iut, frame.raw)

    def test_tp_sec_itss_rcv_implicit_cert_01_bo(self):
        """TP_SEC_ITSS_RCV_IMPLICIT_CERT_01_BO: a CAM signed with an implicit AT that
        contains a signature (CERT_TS_A_IMP_AT_BO) is discarded."""
        implicit = self.pki.implicit_at()
        iut, tester = self.iut(), self.tester(implicit)
        frame = tester.cam(0)
        data = SECURITY_CODER.decode_etsi_ts_103097_data_signed(frame.raw[4:])
        signed = data["content"][1]
        signed["signer"][1][0]["signature"] = ("ecdsaNistP256Signature", {
            "rSig": ("x-only", b"\x11" * 32), "sSig": b"\x22" * 32})
        tbs = SECURITY_CODER.encode_to_be_signed_data(signed["tbsData"])
        h = hashlib.sha256
        signing_input = h(tbs).digest() + h(_canonical_bytes(signed["signer"][1][0])).digest()
        signed["signature"] = self.pki.backend.sign(signing_input, implicit.key_id)
        raw = frame.raw[:4] + SECURITY_CODER.encode_etsi_ts_103097_data_signed(data)
        self.assertIn("signature", _Secured(raw).certificate)
        self.assert_discarded(iut, tester, raw)


class TestSecuredLocationService(_SecTest):
    """Location service with itsGnSecurity ENABLED (ETSI TS 103 836-4-1 V2.2.1 clauses
    10.3.7.1.2 and 10.3.7.3): LS Request and LS Reply are signed with ITS-AID 141,
    SSP absent (tables 24 and 26). No TS 103 096-2 TP covers them."""

    def test_ls_request_and_reply_signed_with_gn_mgmt(self):
        iut, tester = self.iut(beacon=True), self.tester()
        tester.deliver(iut.beacon().raw)                   # the tester knows the IUT, not vice versa
        iut.gn.gn_data_request(GNDataRequest(
            upper_protocol_entity=CommonNH.BTP_B,
            packet_transport_type=PacketTransportType(header_type=HeaderType.GEOUNICAST),
            destination=tester.addr, its_aid=AID_GNMGMT, security_permissions=b"",
            data=b"\x07\xd1\x00\x00guc", length=7))
        request = _Secured(iut.log[-1][1])                 # the GUC waits for the LS
        self.assertEqual((request.common.ht, request.common.hst), (HeaderType.LS, LocationServiceHST.LS_REQUEST))
        self.assertEqual(request.header["psid"], AID_GNMGMT)
        before = len(tester.log)
        tester.deliver(request.raw)
        self.assertEqual(len(tester.log), before + 1)
        reply = _Secured(tester.log[-1][1])
        self.assertEqual((reply.common.ht, reply.common.hst), (HeaderType.LS, LocationServiceHST.LS_REPLY))
        self.assertEqual(reply.header["psid"], AID_GNMGMT)
        before = len(iut.log)
        iut.deliver(reply.raw)                             # verified: the LS completes
        self.assertEqual(len(iut.log), before + 1)
        guc = _Secured(iut.log[-1][1])
        self.assertEqual(guc.common.ht, HeaderType.GEOUNICAST)

    def test_ls_not_sent_without_gn_mgmt_permission(self):
        """No AT may sign ITS-AID 141: the LS Request is not sent (as a Beacon)."""
        at = self.pki.at(appPermissions=[APP_PERMISSIONS[0]])
        iut, tester = self.iut(at), self.tester()
        before = len(iut.log)
        iut.gn.gn_data_request(GNDataRequest(
            upper_protocol_entity=CommonNH.BTP_B,
            packet_transport_type=PacketTransportType(header_type=HeaderType.GEOUNICAST),
            destination=tester.addr, its_aid=AID_CAM, data=b"x", length=1))
        self.assertEqual(len(iut.log), before)


class TestSecuredDuplicateAddressDetection(_SecTest):
    """DAD of ETSI TS 103 836-4-1 V2.2.1 clause 10.2.1.5 step 1b with itsGnSecurity
    ENABLED: a frame sent with our link-layer address makes the IUT take a new MID
    only once the packet has verified, so that a forged frame cannot change it."""

    def _frame_from_us(self, tamper):
        iut, tester = self.iut(), self.tester()
        raw = tester.certificate_cam(0).raw
        if tamper:
            raw = raw[:-1] + bytes([raw[-1] ^ 1])            # last octet of the signature
        own = iut.gn.mib.itsGnLocalGnAddr
        iut.gn.gn_data_indicate(raw, sender_ll_address=own.mid.mid)
        return own, iut.gn.mib.itsGnLocalGnAddr

    def test_verified_frame_with_our_mac_is_a_conflict(self):
        before, after = self._frame_from_us(tamper=False)
        self.assertNotEqual(after.mid, before.mid)

    def test_forged_frame_with_our_mac_is_ignored(self):
        before, after = self._frame_from_us(tamper=True)
        self.assertEqual(after.mid, before.mid)


if __name__ == "__main__":
    unittest.main()
