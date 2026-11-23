"""
Receive and send checks of the security entity with real certificate chains
(ETSI TS 103 097 V2.2.1, IEEE Std 1609.2-2016 clauses 5.2.3.2.2 and 5.3.1),
traced to ETSI TS 103 096-2 V2.1.1 test purposes.

Mirrors ``rustflexstack::security::verify_service`` (security checks) tests.
"""

import hashlib
import time
import unittest
from unittest.mock import MagicMock, patch
from copy import deepcopy

import ecdsa

from flexstack.security.certificate import Certificate, OwnCertificate, signing_input
from flexstack.security.certificate_library import CertificateLibrary
from flexstack.security.ecdsa_backend import PythonECDSABackend
from flexstack.security.security_coder import SecurityCoder
from flexstack.security.sign_service import SignService, SigningError
from flexstack.security.sn_sap import ReportVerify, SNSIGNRequest, SNVERIFYRequest
from flexstack.security.verify_service import VerifyService
from flexstack.utils.time_service import TimeService
from flexstack.geonet.basic_header import BasicHeader, BasicNH
from flexstack.geonet.common_header import CommonHeader
from flexstack.geonet.gn_address import MID, GNAddress
from flexstack.geonet.mib import MIB, GnSecurity
from flexstack.geonet.position_vector import TST, LongPositionVector
from flexstack.geonet.router import Router
from flexstack.geonet.service_access_point import HeaderType
from flexstack.security.validity import app_permission, validity_window_us
from flexstack.security.validity import register_identified_region, unregister_identified_region

ITS_EPOCH = 1072915200
PSID_CAM, PSID_DENM = 36, 37
CODER = SecurityCoder()
KEY = ("verificationKey", ("ecdsaNistP256", ("fill", None)))
INSIDE = {"latitude": 415520000, "longitude": 21340000, "elevation": 0xF000}
OUTSIDE = {"latitude": 425520000, "longitude": 21340000, "elevation": 0xF000}   # ~111 km north
CIRCLE = ("circularRegion", {"center": {"latitude": 415520000, "longitude": 21340000}, "radius": 5000})


def _its_now() -> int:
    return int(time.time()) - ITS_EPOCH


def _validity(start_offset=-60, duration=("years", 1)):
    return {"start": _its_now() + start_offset, "duration": duration}


def _ca(backend, name, issuer, min_chain, algorithm="nistP256", **extra):
    tbs = {
        "id": ("name", name), "cracaId": b"\x00\x00\x00", "crlSeries": 0,
        "validityPeriod": _validity(),
        "certIssuePermissions": [{"subjectPermissions": ("all", None),
                                  "minChainLength": min_chain, "chainLengthRange": 0,
                                  "eeType": (b"\x00", 1)}],
        "verifyKeyIndicator": KEY,
    }
    tbs.update(extra)
    return OwnCertificate.initialize_certificate(
        backend=backend, to_be_signed_certificate=tbs, issuer=issuer, algorithm=algorithm)


def _at_tbs(**extra):
    tbs = {"id": ("none", None), "cracaId": b"\x00\x00\x00", "crlSeries": 0,
           "validityPeriod": _validity(),
           "appPermissions": [{"psid": PSID_CAM, "ssp": ("bitmapSsp", bytes([2, 0x02, 0x00]))},
                              {"psid": PSID_DENM}],
           "verifyKeyIndicator": KEY}
    tbs.update(extra)
    return tbs


class _Fixture:
    def __init__(self, root_extra=None, aa_extra=None, algorithm="nistP256", **at_extra):
        self.backend = PythonECDSABackend()
        self.root = _ca(self.backend, "root", None, 2, algorithm, **(root_extra or {}))
        self.aa = _ca(self.backend, "aa", self.root, 1, algorithm, **(aa_extra or {}))
        self.at = OwnCertificate.initialize_certificate(
            backend=self.backend, to_be_signed_certificate=_at_tbs(**at_extra), issuer=self.aa,
            algorithm=algorithm)
        library = CertificateLibrary(ecdsa_backend=self.backend, root_certificates=[self.root],
                                     aa_certificates=[self.aa], at_certificates=[])
        library.add_own_certificate(self.at)
        self.sign_service = SignService(backend=self.backend, certificate_library=library)

    def sign(self, psid, payload=b"payload", location=None, permissions=b""):
        request = SNSIGNRequest(tbs_message_length=len(payload), tbs_message=payload, its_aid=psid,
                                permissions_length=len(permissions), permissions=permissions,
                                generation_location=location)
        if psid == PSID_CAM:
            self.sign_service.cam_handler.requested_own_certificate = True
            return self.sign_service.sign_cam(request).sec_message
        return self.sign_service.sign_request(request).sec_message

    def verifier(self, known_ats=()):
        library = CertificateLibrary(ecdsa_backend=self.backend, root_certificates=[self.root],
                                     aa_certificates=[self.aa], at_certificates=list(known_ats))
        return VerifyService(backend=self.backend, certificate_library=library)

    def verify(self, message, known_ats=()):
        return self.verifier(known_ats).verify(SNVERIFYRequest(
            sec_header_length=0, sec_header=b"", message_length=len(message), message=message))


def _mutated(message, mutate):
    decoded = CODER.decode_etsi_ts_103097_data_signed(message)
    mutate(decoded["content"][1])
    return CODER.encode_etsi_ts_103097_data_signed(decoded)


def _header(field, value):
    return lambda sd: sd["tbsData"]["headerInfo"].__setitem__(field, value)


class TestChainOnEveryCurve(unittest.TestCase):
    """Own chains on every IEEE 1609.2 PublicVerificationKey curve: the issuer
    choice, the self-signed hash, hashId and the signature follow the curve, and
    the messages verify."""

    def test_chain_on_every_curve_signs_and_verifies(self):
        for algorithm, signature_name, sha384 in (
                ("nistP256", "ecdsaNistP256Signature", False),
                ("brainpoolP256r1", "ecdsaBrainpoolP256r1Signature", False),
                ("brainpoolP384r1", "ecdsaBrainpoolP384r1Signature", True),
                ("nistP384", "ecdsaNistP384Signature", True)):
            fixture = _Fixture(algorithm=algorithm)
            hash_name = "sha384" if sha384 else "sha256"
            self.assertEqual(fixture.root.certificate["issuer"], ("self", hash_name))
            self.assertEqual(fixture.aa.certificate["issuer"][0], hash_name + "AndDigest")
            self.assertEqual(fixture.at.certificate["issuer"][0], hash_name + "AndDigest")
            for psid in (PSID_CAM, PSID_DENM):
                with self.subTest(algorithm=algorithm, psid=psid):
                    location = INSIDE if psid == PSID_DENM else None
                    message = fixture.sign(psid, location=location)
                    signed_data = CODER.decode_etsi_ts_103097_data_signed(message)["content"][1]
                    self.assertEqual(signed_data["hashId"], hash_name)
                    self.assertEqual(signed_data["signature"][0], signature_name)
                    self.assertEqual(fixture.verify(message).report, ReportVerify.SUCCESS)


class TestSigningInput(unittest.TestCase):
    """IEEE 1609.2 clause 5.3.1: Hash(Hash(data) || Hash(signer identifier input))."""

    @classmethod
    def setUpClass(cls):
        cls.f = _Fixture()

    def test_message_signature_covers_the_signer_certificate(self):
        """IEEE 1609.2 clause 5.3.1 (signature calculated over the right fields)."""
        signed = CODER.decode_etsi_ts_103097_data_signed(self.f.sign(PSID_CAM))["content"][1]
        tbs = CODER.encode_to_be_signed_data(signed["tbsData"])
        at_hash = hashlib.sha256(self.f.at.to_canonical().encode()).digest()
        expected = hashlib.sha256(hashlib.sha256(tbs).digest() + at_hash).digest()
        vk = self.f.backend.keys[self.f.at.key_id].verifying_key
        r = int.from_bytes(signed["signature"][1]["rSig"][1], "big")
        s = int.from_bytes(signed["signature"][1]["sSig"], "big")
        self.assertTrue(vk.verify_digest(ecdsa.util.sigencode_string(r, s, ecdsa.NIST256p.order), expected))

    def test_root_self_signature_uses_empty_signer_input(self):
        tbs = CODER.encode_ToBeSignedCertificate(self.f.root.certificate["toBeSigned"])
        payload = signing_input(tbs, b"")
        self.assertTrue(self.f.backend.verify(payload, self.f.root.certificate["signature"],
                                              self.f.root.key_id))
        self.assertFalse(self.f.backend.verify(tbs, self.f.root.certificate["signature"],
                                               self.f.root.key_id))


class TestReceiveChecks(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.f = _Fixture()

    def report(self, message):
        return self.f.verify(message).report

    def test_valid_cam_reports_its_aid_and_ssp(self):
        """ETSI TS 103 097 clause 7.1.1: the SSP of the signer is returned with the ITS-AID."""
        confirm = self.f.verify(self.f.sign(PSID_CAM))
        self.assertEqual(confirm.report, ReportVerify.SUCCESS)
        self.assertEqual(confirm.its_aid, bytes([PSID_CAM]))
        self.assertEqual(confirm.permissions, bytes([2, 0x02, 0x00]))

    def test_protocol_version_other_than_3(self):
        """ETSI TS 103 097 clause 5.1."""
        message = self.f.sign(PSID_CAM)
        for version in (2, 4):
            with self.subTest(version=version):
                bad = bytes([version]) + message[1:]
                self.assertEqual(self.report(bad), ReportVerify.INCOMPATIBLE_PROTOCOL)

    def test_cam_forbidden_header_fields(self):
        """ETSI TS 103 097 clause 7.1.1."""
        fields = {
            "generationLocation": INSIDE,
            "expiryTime": 1,
            "missingCrlIdentifier": {"cracaId": b"\x00\x00\x00", "crlSeries": 0},
            "encryptionKey": ("symmetric", ("aes128Ccm", b"\x00" * 16)),
        }
        for field, value in fields.items():
            with self.subTest(field=field):
                bad = _mutated(self.f.sign(PSID_CAM), _header(field, value))
                self.assertEqual(self.report(bad), ReportVerify.INCOMPATIBLE_PROTOCOL)

    def test_denm_forbidden_header_fields(self):
        """ETSI TS 103 097 clause 5.2, ETSI TS 103 097 clause 7.1.2."""
        for field, value in (("missingCrlIdentifier", {"cracaId": b"\x00\x00\x00", "crlSeries": 0}),
                             ("encryptionKey", ("symmetric", ("aes128Ccm", b"\x00" * 16)))):
            with self.subTest(field=field):
                bad = _mutated(self.f.sign(PSID_DENM, location=INSIDE), _header(field, value))
                self.assertEqual(self.report(bad), ReportVerify.INCOMPATIBLE_PROTOCOL)

    def test_psid_not_in_app_permissions(self):
        """IEEE 1609.2 clause 5.2.3.2.2: the AT does not permit the PSID."""
        bad = _mutated(self.f.sign(PSID_CAM), _header("psid", 99))
        self.assertEqual(self.report(bad), ReportVerify.INVALID_CERTIFICATE)

    def test_generation_time_outside_certificate_validity(self):
        """IEEE 1609.2 clause 5.2.3.2.2: generationTime inside the AT validity period."""
        start_us = self.f.at.certificate["toBeSigned"]["validityPeriod"]["start"] * 1_000_000
        bad = _mutated(self.f.sign(PSID_CAM), _header("generationTime", start_us - 10_000_000))
        self.assertEqual(self.report(bad), ReportVerify.INVALID_TIMESTAMP)

    def test_signer_self_is_unsupported(self):
        """ETSI TS 103 097 clause 6."""
        bad = _mutated(self.f.sign(PSID_CAM), lambda sd: sd.__setitem__("signer", ("self", None)))
        self.assertEqual(self.report(bad), ReportVerify.UNSUPPORTED_SIGNER_IDENTIFIER_TYPE)

    def test_signature_algorithm_not_matching_the_key(self):
        """ETSI TS 103 097 clause 6."""
        for psid, location in ((PSID_CAM, None), (PSID_DENM, INSIDE)):
            with self.subTest(psid=psid):
                def swap(sd):
                    sd["signature"] = ("ecdsaBrainpoolP256r1Signature", sd["signature"][1])
                bad = _mutated(self.f.sign(psid, location=location), swap)
                self.assertEqual(self.report(bad), ReportVerify.FALSE_SIGNATURE)

    def test_altered_signature(self):
        """ETSI TS 103 097 clause 6."""
        def alter(sd):
            s = bytearray(sd["signature"][1]["sSig"])
            s[-1] ^= 0x01
            sd["signature"] = (sd["signature"][0], {"rSig": sd["signature"][1]["rSig"], "sSig": bytes(s)})
        bad = _mutated(self.f.sign(PSID_DENM, location=INSIDE), alter)
        self.assertEqual(self.report(bad), ReportVerify.FALSE_SIGNATURE)

    def test_compressed_r_signature_accepted(self):
        """ETSI TS 103 097 clause 7.1.1: rSig as compressed-y-0 / compressed-y-1."""
        for choice in ("compressed-y-0", "compressed-y-1"):
            with self.subTest(choice=choice):
                def compress(sd, choice=choice):
                    sig = sd["signature"][1]
                    sd["signature"] = (sd["signature"][0], {"rSig": (choice, sig["rSig"][1]),
                                                            "sSig": sig["sSig"]})
                self.assertEqual(self.report(_mutated(self.f.sign(PSID_CAM), compress)),
                                 ReportVerify.SUCCESS)


class TestRegionRestriction(unittest.TestCase):
    """Region of the AT (or inherited from the AA) on reception and transmission."""

    @classmethod
    def setUpClass(cls):
        cls.f = _Fixture(region=CIRCLE)

    def test_denm_inside_region_is_signed_and_accepted(self):
        """IEEE 1609.2 clause 5.2.3.2.2 (circular), ETSI TS 103 097 clause 7.1.2."""
        message = self.f.sign(PSID_DENM, location=INSIDE)
        self.assertEqual(self.f.verify(message).report, ReportVerify.SUCCESS)

    def test_no_signing_outside_the_region(self):
        """IEEE 1609.2 clause 5.2.3.2.2 (region)."""
        with self.assertRaises(SigningError):
            self.f.sign(PSID_DENM, location=OUTSIDE)
        with self.assertRaises(SigningError):
            self.f.sign(PSID_CAM, location=OUTSIDE)

    def test_generation_location_outside_region_rejected(self):
        """IEEE 1609.2 clause 5.2.3.2.2 region consistency on reception."""
        bad = _mutated(self.f.sign(PSID_DENM, location=INSIDE), _header("generationLocation", OUTSIDE))
        self.assertEqual(self.f.verify(bad).report, ReportVerify.INVALID_MOBILITY_DATA)


class TestInheritedRegion(unittest.TestCase):
    """
    IEEE 1609.2 clause 5.2.3.2.2 (region of the AA; region of
    the root, AA without region) and IEEE 1609.2 clause 5.2.3.2.2 (no DENM outside the region
    of the AA): an AT without region inherits the closest one in its chain, on
    transmission and on reception.
    """

    def test_region_inherited_from_aa_and_root(self):
        for holder in ("root", "aa"):
            with self.subTest(holder=holder):
                extra = {"region": CIRCLE}
                f = _Fixture(root_extra=extra if holder == "root" else None,
                             aa_extra=extra if holder == "aa" else None)
                message = f.sign(PSID_DENM, location=INSIDE)
                self.assertEqual(f.verify(message).report, ReportVerify.SUCCESS)
                with self.assertRaises(SigningError):
                    f.sign(PSID_DENM, location=OUTSIDE)
                with self.assertRaises(SigningError):          # IEEE 1609.2 clause 5.2.3.2.2 (region)
                    f.sign(PSID_CAM, location=OUTSIDE)
                bad = _mutated(message, _header("generationLocation", OUTSIDE))
                self.assertEqual(f.verify(bad).report, ReportVerify.INVALID_MOBILITY_DATA)


class TestOtherItsAid(unittest.TestCase):
    """ETSI TS 103 097 clause 7.1.3."""

    def test_other_its_aid_header_has_psid_and_generation_time(self):
        f = _Fixture(appPermissions=[{"psid": PSID_CAM}, {"psid": PSID_DENM}, {"psid": 139}])
        before = TimeService.timestamp_its() * 1000    # TAI µs, as the stack
        message = f.sign(139)
        signed = CODER.decode_etsi_ts_103097_data_signed(message)["content"][1]
        header = signed["tbsData"]["headerInfo"]
        self.assertEqual(header["psid"], 139)
        self.assertLessEqual(abs(header["generationTime"] - before), 2_000_000)
        # First message: the certificate, so any receiver can verify it
        self.assertEqual(signed["signer"][0], "certificate")
        confirm = f.verify(message)
        self.assertEqual(confirm.report, ReportVerify.SUCCESS)
        self.assertEqual(confirm.its_aid, (139).to_bytes(1, "big"))
        # Within 1 s: the digest, verifiable by a receiver that knows the AT
        message = f.sign(139)
        signed = CODER.decode_etsi_ts_103097_data_signed(message)["content"][1]
        self.assertEqual(signed["signer"], ("digest", f.at.as_hashedid8()))
        self.assertEqual(f.verify(message).report, ReportVerify.SIGNER_CERTIFICATE_NOT_FOUND)
        self.assertEqual(f.verify(message, known_ats=[f.at]).report, ReportVerify.SUCCESS)


class TestSecuredBeacon(unittest.TestCase):
    """
    Secured Beacons (ETSI TS 103 836-4-1 V2.2.1 clause 10.3.6.2 step 2: signed
    with ITS-AID 141, GN-MGMT), sent by one GN router and verified by another:
    ETSI TS 103 097 clause 7.1.3 (signedData; generationTime
    inside the AT validity), GENMSG_06_BV (unsecuredData payload),
    GENMSG_07_BV (AT appPermissions contain the ITS-AID). Messages other
    than CAM and DENM carry the certificate once per second and the digest
    otherwise.
    """

    GN_MGMT = 141

    def router(self, n, sign_service=None, verify_service=None):
        mib = MIB(itsGnSecurity=GnSecurity.ENABLED, itsGnBeaconServiceRetransmitTimer=0,
                  itsGnLocalGnAddr=GNAddress(mid=MID(bytes([0x02, 0, 0, 0, 0, n]))))
        router = Router(mib, sign_service=sign_service, verify_service=verify_service)
        router.ego_position_vector = LongPositionVector(
            gn_addr=mib.itsGnLocalGnAddr, tst=TST.set_in_normal_timestamp_seconds(TimeService.time()),
            latitude=INSIDE["latitude"], longitude=INSIDE["longitude"], pai=True)
        router.link_layer = MagicMock()
        return router

    def beacon(self, fixture, count=1):
        sender = self.router(1, sign_service=fixture.sign_service)
        for _ in range(count):
            sender.gn_data_request_beacon()
        return [c[0][0] for c in sender.link_layer.send.call_args_list]

    def test_secured_beacon_sent_and_verified(self):
        f = _Fixture(appPermissions=[{"psid": PSID_CAM}, {"psid": PSID_DENM}, {"psid": self.GN_MGMT}])
        now = TimeService.timestamp_its() * 1000
        packets = self.beacon(f, count=2)
        self.assertEqual(len(packets), 2)
        self.assertEqual(BasicHeader.decode_from_bytes(packets[0][0:4]).nh, BasicNH.SECURED_PACKET)
        message = CODER.decode_etsi_ts_103097_data_signed(packets[0][4:])
        self.assertEqual(message["content"][0], "signedData")                    # GENMSG_01
        signed = message["content"][1]
        header = signed["tbsData"]["headerInfo"]
        self.assertEqual(header["psid"], self.GN_MGMT)
        self.assertEqual(signed["signer"][0], "certificate")
        signer = signed["signer"][1][0]["toBeSigned"]
        start, end = validity_window_us(signer)                                  # GENMSG_05
        self.assertTrue(start <= header["generationTime"] <= end)
        self.assertLessEqual(abs(header["generationTime"] - now), 600_000_000)
        inner = signed["tbsData"]["payload"]["data"]                             # GENMSG_06
        self.assertEqual(inner["content"][0], "unsecuredData")
        self.assertEqual(CommonHeader.decode_from_bytes(inner["content"][1][0:8]).ht, HeaderType.BEACON)
        self.assertEqual(len(inner["content"][1]), 8 + 24)
        self.assertTrue(app_permission(signer, self.GN_MGMT)[0])                # GENMSG_07
        self.assertEqual(_digest(signed["signer"][1][0]), f.at.as_hashedid8())
        # A receiver that never heard from the sender verifies it
        receiver = self.router(7, verify_service=f.verifier())
        receiver.gn_data_indicate(packets[0])
        entry = receiver.location_table.get_entry(GNAddress(mid=MID(bytes([0x02, 0, 0, 0, 0, 1]))))
        self.assertIsNotNone(entry)
        # The next Beacon within 1 s carries the digest: a stranger cannot verify it
        signed = CODER.decode_etsi_ts_103097_data_signed(packets[1][4:])["content"][1]
        self.assertEqual(signed["signer"], ("digest", f.at.as_hashedid8()))
        stranger = self.router(8, verify_service=f.verifier())
        stranger.gn_data_indicate(packets[1])
        self.assertEqual(stranger.location_table.loc_t, {})

    def test_no_beacon_without_gn_mgmt_permission(self):
        """IEEE 1609.2 clause 5.2.3.2.2 analogue for Beacons: no AT for ITS-AID 141, no Beacon."""
        self.assertEqual(self.beacon(_Fixture()), [])


class TestSenderChecks(unittest.TestCase):
    """Content of CAMs and DENMs sent by the IUT (TS 103 096-2 clauses 6.2.2, 6.2.3)."""

    @staticmethod
    def signed(message):
        return CODER.decode_etsi_ts_103097_data_signed(message)["content"][1]

    def test_generation_time_inside_at_validity(self):
        """IEEE 1609.2 clause 5.2.3.2.2: CUR_TIME - 5 min <= generationTime
        <= CUR_TIME + 5 min, inside the validity period of the signing AT."""
        f = _Fixture()
        start, end = validity_window_us(f.at.certificate["toBeSigned"])
        for psid, location in ((PSID_CAM, None), (PSID_DENM, INSIDE)):
            with self.subTest(psid=psid):
                now = TimeService.timestamp_its() * 1000
                signed = self.signed(f.sign(psid, location=location))
                generation_time = signed["tbsData"]["headerInfo"]["generationTime"]
                self.assertLessEqual(abs(generation_time - now), 300_000_000)
                self.assertTrue(start <= generation_time <= end)
                self.assertEqual(signed["signer"][0], "certificate")
                signer_start, signer_end = validity_window_us(signed["signer"][1][0]["toBeSigned"])
                self.assertTrue(signer_start <= generation_time <= signer_end)

    def test_signer_app_permissions_contain_the_psid(self):
        """IEEE 1609.2 clause 5.2.3.2.2."""
        f = _Fixture()
        for psid, location in ((PSID_CAM, None), (PSID_DENM, INSIDE)):
            with self.subTest(psid=psid):
                signer = self.signed(f.sign(psid, location=location))["signer"][1][0]
                self.assertTrue(app_permission(signer["toBeSigned"], psid)[0])

    def test_no_message_without_permitted_at(self):
        """IEEE 1609.2 clause 5.2.3.2.2: the only AT lacks the PSID."""
        f = _Fixture(appPermissions=[{"psid": 139}])
        with self.assertRaises(SigningError):
            f.sign(PSID_CAM)
        with self.assertRaises(SigningError):
            f.sign(PSID_DENM, location=INSIDE)

    def test_signature_r_is_x_only_or_compressed(self):
        """IEEE 1609.2 clause 6.3.30 (A, NIST P-256)."""
        signature = self.signed(_Fixture().sign(PSID_CAM))["signature"]
        self.assertEqual(signature[0], "ecdsaNistP256Signature")
        self.assertIn(signature[1]["rSig"][0], ("x-only", "compressed-y-0", "compressed-y-1"))

    def test_at_with_8_app_permissions(self):
        """IEEE 1609.2 clause 5.2.3.2.2 (8 appPermissions, AID_CAM last)."""
        permissions = [{"psid": 130 + i} for i in range(7)] + [{"psid": PSID_CAM}]
        f = _Fixture(appPermissions=permissions)
        message = f.sign(PSID_CAM)
        self.assertEqual(self.signed(message)["tbsData"]["headerInfo"]["psid"], PSID_CAM)
        self.assertEqual(f.verify(message).report, ReportVerify.SUCCESS)

    def test_aa_with_8_cert_issue_permissions(self):
        """IEEE 1609.2 clause 5.2.3.2.2 (8 certIssuePermissions in the AA, AID_CAM last)."""
        def group(psid):
            return {"subjectPermissions": ("explicit", [{"psid": psid}]), "minChainLength": 0,
                    "chainLengthRange": 0, "eeType": (b"\x80", 8)}
        groups = [group(130 + i) for i in range(7)] + [group(PSID_CAM)]
        f = _Fixture(aa_extra={"certIssuePermissions": groups}, appPermissions=[{"psid": PSID_CAM}])
        message = f.sign(PSID_CAM)
        self.assertEqual(self.signed(message)["tbsData"]["headerInfo"]["psid"], PSID_CAM)
        self.assertEqual(f.verify(message).report, ReportVerify.SUCCESS)
        # Without AID_CAM in the AA's 8 entries the AT is not a valid CAM signer
        f = _Fixture(aa_extra={"certIssuePermissions": [group(130 + i) for i in range(8)]},
                     appPermissions=[{"psid": PSID_CAM}])
        with self.assertRaises(SigningError):
            f.sign(PSID_CAM)


class _Station:
    """An ITS-S with its own AT (issued by ``aa``), sign service and verify service."""

    def __init__(self, backend, root, aa, known_aas=()):
        self.at = OwnCertificate.initialize_certificate(
            backend=backend, to_be_signed_certificate=_at_tbs(), issuer=aa)
        aas = [aa, *[k for k in known_aas if k is not aa]]
        library = CertificateLibrary(ecdsa_backend=backend, root_certificates=[root],
                                     aa_certificates=aas, at_certificates=[])
        library.add_own_certificate(self.at)
        self.sign_service = SignService(backend=backend, certificate_library=library)
        self.verify_service = VerifyService(
            backend=backend, sign_service=self.sign_service,
            certificate_library=CertificateLibrary(ecdsa_backend=backend, root_certificates=[root],
                                                   aa_certificates=aas, at_certificates=[]))

    def cam(self):
        request = SNSIGNRequest(tbs_message_length=3, tbs_message=b"cam", its_aid=PSID_CAM,
                                permissions_length=0, permissions=b"")
        return self.sign_service.sign_cam(request).sec_message

    def receive(self, message):
        return self.verify_service.verify(SNVERIFYRequest(
            sec_header_length=0, sec_header=b"", message_length=len(message), message=message)).report


def _digest(certificate: dict) -> bytes:
    return Certificate.from_dict(certificate).as_hashedid8()


def _cam_fields(message):
    signed = CODER.decode_etsi_ts_103097_data_signed(message)["content"][1]
    return signed["signer"], signed["tbsData"]["headerInfo"]


class TestPeerToPeerCertificateDistribution(unittest.TestCase):
    """
    P2PCD between stations (ETSI TS 103 097 V2.2.1 clause 7.1.1, IEEE 1609.2
    clause 8.2.4), the IUT being station ``a``. The 1 s certificate timer is
    driven by a clock around the real time. Mirrors the Rust ``p2pcd_*`` tests.
    """

    def setUp(self):
        self.backend = PythonECDSABackend()
        self.root = _ca(self.backend, "root", None, 2)
        self.aa1 = _ca(self.backend, "aa1", self.root, 1)
        self.aa2 = _ca(self.backend, "aa2", self.root, 1)
        self.aa_n = _ca(self.backend, "aa-n", self.root, 1)
        self.t0 = TimeService.time()
        self.clock = [self.t0]
        patcher = patch.object(TimeService, "time", side_effect=lambda: self.clock[0])
        patcher.start()
        self.addCleanup(patcher.stop)

    def at(self, seconds):
        self.clock[0] = self.t0 + seconds

    @staticmethod
    def h3(certificate):
        return certificate.as_hashedid8()[-3:]

    def test_unknown_at_signer_digest(self):
        """ETSI TS 103 097 clause 7.1.1 (certificate in the next CAM)
        (inlineP2pcdRequest with the unknown digest), CAM_09_BV (timer
        restarted); the request stops once the AT is learned."""
        a = _Station(self.backend, self.root, self.aa1, [self.aa2])
        b = _Station(self.backend, self.root, self.aa2, [self.aa1])
        self.assertEqual(_cam_fields(a.cam())[0][0], "certificate")        # TIME_1 = 0
        b_certificate = b.cam()
        self.at(0.1)
        b_digest = b.cam()
        self.assertEqual(_cam_fields(b_digest)[0][0], "digest")
        self.at(0.2)
        self.assertEqual(a.receive(b_digest), ReportVerify.SIGNER_CERTIFICATE_NOT_FOUND)
        self.at(0.4)
        signer, header = _cam_fields(a.cam())                              # TIME_3
        self.assertEqual(signer[0], "certificate")                         # CAM_08
        self.assertEqual(header["inlineP2pcdRequest"], [self.h3(b.at)])    # CAM_10
        self.at(1.3)
        self.assertEqual(_cam_fields(a.cam())[0][0], "digest")             # CAM_09: < 1 s after TIME_3
        self.at(1.45)
        self.assertEqual(_cam_fields(a.cam())[0][0], "certificate")        # about 1 s after TIME_3
        self.assertEqual(a.receive(b_certificate), ReportVerify.SUCCESS)    # B's AT learned
        self.assertNotIn("inlineP2pcdRequest", _cam_fields(a.cam())[1])

    def test_unknown_aa_of_signer_certificate(self):
        """ETSI TS 103 097 clause 7.1.1 (A, sha256AndDigest)."""
        a = _Station(self.backend, self.root, self.aa1)
        b = _Station(self.backend, self.root, self.aa2, [self.aa1])
        self.assertEqual(a.receive(b.cam()), ReportVerify.INCONSISTENT_CHAIN)
        self.at(0.3)
        self.assertEqual(_cam_fields(a.cam())[1]["inlineP2pcdRequest"], [self.h3(self.aa2)])

    def test_request_for_own_at(self):
        """ETSI TS 103 097 clause 7.1.1."""
        a = _Station(self.backend, self.root, self.aa1, [self.aa2])
        b = _Station(self.backend, self.root, self.aa2, [self.aa1])
        a.cam()                                                             # TIME_1: certificate
        b_first = b.cam()
        self.assertEqual(a.receive(b_first), ReportVerify.SUCCESS)
        self.at(0.1)
        b.receive(a.cam())                                                  # digest unknown to B
        self.at(0.15)
        b_request = b.cam()
        self.assertEqual(_cam_fields(b_request)[1]["inlineP2pcdRequest"], [self.h3(a.at)])
        self.at(0.2)
        self.assertEqual(a.receive(b_request), ReportVerify.SUCCESS)
        self.at(0.3)
        signer, _ = _cam_fields(a.cam())
        self.assertEqual(signer[0], "certificate")
        self.assertEqual(_digest(signer[1][0]), a.at.as_hashedid8())

    def request_for_aa1(self, b_at=0.2):
        """B, which does not know AA1, asks for it after A's certificate CAM."""
        a = _Station(self.backend, self.root, self.aa1, [self.aa2])
        b = _Station(self.backend, self.root, self.aa2)
        self.assertEqual(b.receive(a.cam()), ReportVerify.INCONSISTENT_CHAIN)   # TIME_1
        self.at(b_at)
        b_request = b.cam()
        self.assertEqual(_cam_fields(b_request)[1]["inlineP2pcdRequest"], [self.h3(self.aa1)])
        return a, b_request

    def test_requested_aa_is_learned_by_the_requester(self):
        """IEEE 1609.2 clause 8.2.4: once the requested AA arrives (requestedCertificate),
        the requester verifies the CAMs of its ATs. The AA is learned before the chain
        of the answering CAM is checked."""
        a = _Station(self.backend, self.root, self.aa1, [self.aa2])
        b = _Station(self.backend, self.root, self.aa2)
        self.assertEqual(b.receive(a.cam()), ReportVerify.INCONSISTENT_CHAIN)   # AA1 unknown to B
        self.at(0.2)
        self.assertEqual(a.receive(b.cam()), ReportVerify.SUCCESS)              # B asks for AA1
        self.at(0.4)
        answer = a.cam()
        self.assertEqual(_digest(_cam_fields(answer)[1]["requestedCertificate"]), self.aa1.as_hashedid8())
        b.receive(answer)
        self.assertIn(self.aa1.as_hashedid8(), b.verify_service.certificate_library.known_authorization_authorities)
        self.at(1.2)
        self.assertEqual(b.receive(a.cam()), ReportVerify.SUCCESS)              # certificate CAM of A

    def test_request_for_issuing_aa(self):
        """ETSI TS 103 097 clause 7.1.1."""
        a, b_request = self.request_for_aa1()
        self.assertEqual(a.receive(b_request), ReportVerify.SUCCESS)
        self.at(0.4)
        signer, header = _cam_fields(a.cam())
        self.assertEqual(signer[0], "digest")
        self.assertEqual(_digest(header["requestedCertificate"]), self.aa1.as_hashedid8())
        self.at(0.5)
        self.assertNotIn("requestedCertificate", _cam_fields(a.cam())[1])

    def test_request_for_known_aa_not_issuer(self):
        """ETSI TS 103 097 clause 7.1.1."""
        a = _Station(self.backend, self.root, self.aa1, [self.aa2, self.aa_n])
        a.cam()
        b = _Station(self.backend, self.root, self.aa2, [self.aa1])
        d = _Station(self.backend, self.root, self.aa_n)                    # AT issued by AA_N
        b.receive(d.cam())                                                  # B does not know AA_N
        self.at(0.2)
        b_request = b.cam()
        self.assertEqual(_cam_fields(b_request)[1]["inlineP2pcdRequest"], [self.h3(self.aa_n)])
        self.assertEqual(a.receive(b_request), ReportVerify.SUCCESS)
        self.at(0.4)
        signer, header = _cam_fields(a.cam())
        self.assertEqual(signer[0], "digest")
        self.assertEqual(_digest(header["requestedCertificate"]), self.aa_n.as_hashedid8())

    def test_request_already_answered_by_another_station(self):
        """ETSI TS 103 097 clause 7.1.1."""
        a, b_request = self.request_for_aa1()
        c = _Station(self.backend, self.root, self.aa2, [self.aa1])
        self.at(0)
        self.assertEqual(a.receive(c.cam()), ReportVerify.SUCCESS)          # A learns C's AT
        self.at(0.2)
        self.assertEqual(a.receive(b_request), ReportVerify.SUCCESS)        # TIME_2
        c.receive(b_request)
        self.at(0.25)
        c_answer = c.cam()
        self.assertEqual(_digest(_cam_fields(c_answer)[1]["requestedCertificate"]), self.aa1.as_hashedid8())
        self.assertEqual(a.receive(c_answer), ReportVerify.SUCCESS)         # TIME_3
        self.at(0.3)
        self.assertNotIn("requestedCertificate", _cam_fields(a.cam())[1])   # TIME_4

    def test_request_kept_pending_while_signer_is_certificate(self):
        """ETSI TS 103 097 clause 7.1.1."""
        a, b_request = self.request_for_aa1(b_at=0.9)
        self.assertEqual(a.receive(b_request), ReportVerify.SUCCESS)        # TIME_2 = 0.9
        self.at(1.05)
        signer, header = _cam_fields(a.cam())
        self.assertEqual(signer[0], "certificate")                          # CAM_16
        self.assertNotIn("requestedCertificate", header)
        self.at(1.2)
        signer, header = _cam_fields(a.cam())
        self.assertEqual(signer[0], "digest")                               # CAM_17
        self.assertEqual(_digest(header["requestedCertificate"]), self.aa1.as_hashedid8())


class TestIdentifiedRegionRestriction(unittest.TestCase):
    """
    IEEE 1609.2 clause 6.4.17: AT restricted to an identifiedRegion of 8
    entries, one containing the position (synthetic geometry registered for
    UnCountryId 9400..9407).
    """

    def setUp(self):
        for i in range(8):
            south = 340000000 + i * 15000000
            north = south + 10000000
            register_identified_region(9400 + i, [[(south, 0), (north, 0), (north, 30000000),
                                                   (south, 30000000)]])
            self.addCleanup(unregister_identified_region, 9400 + i)
        self.f = _Fixture(region=("identifiedRegion", [("countryOnly", 9400 + i) for i in range(8)]))

    def test_denm_inside_identified_region(self):
        message = self.f.sign(PSID_DENM, location=INSIDE)
        header = CODER.decode_etsi_ts_103097_data_signed(message)["content"][1]["tbsData"]["headerInfo"]
        location = header["generationLocation"]
        self.assertEqual((location["latitude"], location["longitude"]),
                         (INSIDE["latitude"], INSIDE["longitude"]))
        self.assertEqual(self.f.verify(message).report, ReportVerify.SUCCESS)

    def test_outside_every_identified_region(self):
        with self.assertRaises(SigningError):
            self.f.sign(PSID_DENM, location=OUTSIDE)
        bad = _mutated(self.f.sign(PSID_DENM, location=INSIDE), _header("generationLocation", OUTSIDE))
        self.assertEqual(self.f.verify(bad).report, ReportVerify.INVALID_MOBILITY_DATA)


def _point(lat, lon):
    return {"latitude": lat, "longitude": lon}


class TestEveryRegionKind(unittest.TestCase):
    """
    IEEE 1609.2 clause 5.2.3.2.2, IEEE 1609.2 clause 6.4.17,
    IEEE 1609.2 clause 6.4.17 (DENM sent with generationLocation inside the region),
    ETSI TS 103 097 clause 7.1.2 and ETSI TS 103 097 clause 7.1.1 (accepted by a receiver),
    IEEE 1609.2 clause 5.2.3.2.2 (not sent outside), for the region kinds of the TP
    permutation tables: B circular; C rectangular with 8 entries; D polygonal
    with 8 points; E identified with 8 entries (synthetic geometry for
    UnCountryId 9500..9507). Same values as the Rust test.
    """

    def setUp(self):
        for i in range(8):
            south = 340000000 + i * 15000000
            north = south + 10000000
            register_identified_region(9500 + i, [[(south, 0), (north, 0), (north, 30000000),
                                                   (south, 30000000)]])
            self.addCleanup(unregister_identified_region, 9500 + i)

    @staticmethod
    def kinds():
        # 8 boxes 41.5-41.6 N, 0.2 deg wide, 0.3 deg apart; the 6th holds INSIDE
        rects = [{"northWest": _point(416000000, 5340000 + i * 3000000),
                  "southEast": _point(415000000, 7340000 + i * 3000000)} for i in range(8)]
        c_lat, c_lon = INSIDE["latitude"], INSIDE["longitude"]
        octagon = [_point(c_lat + a, c_lon + b) for a, b in (
            (1000000, -400000), (1000000, 400000), (400000, 1000000), (-400000, 1000000),
            (-1000000, 400000), (-1000000, -400000), (-400000, -1000000), (400000, -1000000))]
        return (("B circular", CIRCLE),
                ("C rectangular x8", ("rectangularRegion", rects)),
                ("D polygonal x8", ("polygonalRegion", octagon)),
                ("E identified x8", ("identifiedRegion",
                                     [("countryOnly", 9500 + i) for i in range(8)])))

    def test_every_region_kind_end_to_end(self):
        for kind, region in self.kinds():
            with self.subTest(kind=kind):
                f = _Fixture(region=region)
                denm = f.sign(PSID_DENM, location=INSIDE)
                header = CODER.decode_etsi_ts_103097_data_signed(denm)["content"][1]["tbsData"]["headerInfo"]
                location = header["generationLocation"]
                self.assertEqual((location["latitude"], location["longitude"]),
                                 (INSIDE["latitude"], INSIDE["longitude"]))
                self.assertEqual(f.verify(denm).report, ReportVerify.SUCCESS)
                self.assertEqual(f.verify(f.sign(PSID_CAM)).report, ReportVerify.SUCCESS)
                with self.assertRaises(SigningError):
                    f.sign(PSID_DENM, location=OUTSIDE)
                bad = _mutated(denm, _header("generationLocation", OUTSIDE))
                self.assertEqual(f.verify(bad).report, ReportVerify.INVALID_MOBILITY_DATA)


class TestValidityOnTransmission(unittest.TestCase):
    """IEEE 1609.2 clause 5.2.3.2.2: no valid AT, no message."""

    def test_expired_and_not_yet_valid_at(self):
        for start in (-7200, 3600):
            with self.subTest(start=start):
                f = _Fixture(validityPeriod=_validity(start, ("hours", 1)))
                with self.assertRaises(SigningError):
                    f.sign(PSID_CAM)
                with self.assertRaises(SigningError):
                    f.sign(PSID_DENM, location=INSIDE)

    def test_ssp_not_granted(self):
        """The CAM AT SSP grants emergency (0x02) only: a safety-car request is refused."""
        f = _Fixture()
        self.assertTrue(f.sign(PSID_CAM, permissions=bytes([0, 0x02])))
        with self.assertRaises(SigningError):
            f.sign(PSID_CAM, permissions=bytes([0, 0x01]))


class TestBrainpool(unittest.TestCase):
    """ETSI TS 103 097 clause 7.1.1, ETSI TS 103 097 clause 7.1.2."""

    CURVES = {
        "brainpoolP256r1": (ecdsa.BRAINPOOLP256r1, hashlib.sha256, 32, "ecdsaBrainpoolP256r1"),
        "brainpoolP384r1": (ecdsa.BRAINPOOLP384r1, hashlib.sha384, 48, "ecdsaBrainpoolP384r1"),
    }

    def _signed(self, f, curve_name, psid, location=None):
        curve, hashfunc, size, key_choice = self.CURVES[curve_name]
        sk = ecdsa.SigningKey.generate(curve=curve)
        point = sk.verifying_key.to_string("compressed")
        tbs_cert = _at_tbs(verifyKeyIndicator=("verificationKey", (
            key_choice, ("compressed-y-0" if point[0] == 2 else "compressed-y-1", point[1:]))))
        cert = deepcopy(f.at.certificate)
        cert["toBeSigned"] = tbs_cert
        at = f.aa.issue_certificate(f.backend, Certificate.from_dict(cert, f.aa))
        header = {"psid": psid, "generationTime": (_its_now() + 5) * 1_000_000}
        if location is not None:
            header["generationLocation"] = location
        tbs = {"payload": {"data": {"protocolVersion": 3, "content": ("unsecuredData", b"payload")}},
               "headerInfo": header}
        tbs_bytes = CODER.encode_to_be_signed_data(tbs)
        signature = sk.sign(signing_input(tbs_bytes, at.to_canonical().encode(), hashfunc),
                            hashfunc=hashfunc)
        r, s = ecdsa.util.sigdecode_string(signature, curve.order)
        message = {"protocolVersion": 3, "content": ("signedData", {
            "hashId": "sha384" if size == 48 else "sha256", "tbsData": tbs,
            "signer": ("certificate", [at.certificate]),
            "signature": (key_choice + "Signature", {"rSig": ("x-only", r.to_bytes(size, "big")),
                                                     "sSig": s.to_bytes(size, "big")})})}
        return CODER.encode_etsi_ts_103097_data_signed(message)

    def test_brainpool_signed_cam_and_denm_accepted(self):
        f = _Fixture()
        for curve in self.CURVES:
            for psid, location in ((PSID_CAM, None), (PSID_DENM, INSIDE)):
                with self.subTest(curve=curve, psid=psid):
                    self.assertEqual(f.verify(self._signed(f, curve, psid, location)).report,
                                     ReportVerify.SUCCESS)


if __name__ == "__main__":
    unittest.main()


class TestImplicitCertificates(unittest.TestCase):
    """ECQV implicit authorization tickets (IEEE Std 1609.2-2016 clause 5.3.2):
    IEEE 1609.2 clause 5.3.2."""

    def setUp(self):
        self.f = _Fixture()
        self.implicit = self.f.aa.issue_implicit_certificate(self.f.backend, _at_tbs())
        self.f.sign_service.certificate_library.own_certificates = {}
        self.f.sign_service.add_own_certificate(self.implicit)

    def test_reconstructed_key_matches_private_key(self):
        key = self.implicit.verification_key()
        d_u = self.f.backend.private_scalar(self.implicit.key_id)
        q = (ecdsa.NIST256p.generator * d_u).to_affine()
        self.assertEqual(key[1][1], {"x": q.x().to_bytes(32, "big"), "y": q.y().to_bytes(32, "big")})

    def test_etsi_itscertgen_construction(self):
        """Implicit AT built as ETSI itscertgen does (ecc_recvalue / ecc_reconstruct),
        independently of FlexStack's issuer: H = SHA-256(SHA-256(tbs) || SHA-256(issuer)),
        e = H >> 1, r = e*k_eph + d_CA, d_U = e*k_req + r, P_U = (k_eph + k_req)*G."""
        curve, n = ecdsa.NIST256p, ecdsa.NIST256p.order
        k_req, k_eph = 0x1234567890ABCDEF, 0xFEDCBA0987654321
        p_u = (curve.generator * (k_req + k_eph)).to_affine()
        tbs = _at_tbs(verifyKeyIndicator=("reconstructionValue", (
            "compressed-y-0" if p_u.y() % 2 == 0 else "compressed-y-1", p_u.x().to_bytes(32, "big"))))
        cert = {"version": 3, "type": "implicit",
                "issuer": ("sha256AndDigest", self.f.aa.as_hashedid8()), "toBeSigned": tbs}
        tbs_hash = hashlib.sha256(CODER.encode_ToBeSignedCertificate(tbs)).digest()
        issuer_hash = hashlib.sha256(self.f.aa.to_canonical().encode()).digest()
        e = int.from_bytes(hashlib.sha256(tbs_hash + issuer_hash).digest(), "big") >> 1
        r = (e * k_eph + self.f.backend.private_scalar(self.f.aa.key_id)) % n
        d_u = (e * k_req + r) % n
        at = OwnCertificate(certificate=cert, issuer=self.f.aa,
                            key_id=self.f.backend.import_private_scalar(d_u))
        self.f.sign_service.certificate_library.own_certificates = {}
        self.f.sign_service.add_own_certificate(at)
        self.assertEqual(self.f.verify(self.f.sign(PSID_CAM)).report, ReportVerify.SUCCESS)

    def test_signed_cam_with_unknown_implicit_at_accepted(self):
        """IEEE 1609.2 clause 5.3.2: certificate signer."""
        message = self.f.sign(PSID_CAM)
        signer = CODER.decode_etsi_ts_103097_data_signed(message)["content"][1]["signer"]
        self.assertEqual(signer[1][0]["type"], "implicit")
        self.assertEqual(self.f.verify(message).report, ReportVerify.SUCCESS)

    def test_digest_signed_cam_with_known_implicit_at_accepted(self):
        """IEEE 1609.2 clause 5.3.2: digest signer once the implicit AT is known."""
        verifier = self.f.verifier()
        self.f.sign_service.cam_handler.requested_own_certificate = True
        first = self.f.sign(PSID_CAM)
        request = SNSIGNRequest(tbs_message_length=1, tbs_message=b"x", its_aid=PSID_CAM,
                                permissions_length=0, permissions=b"")
        second = self.f.sign_service.sign_cam(request).sec_message
        self.assertEqual(CODER.decode_etsi_ts_103097_data_signed(second)["content"][1]["signer"][0], "digest")
        for message in (first, second):
            self.assertEqual(verifier.verify(SNVERIFYRequest(
                sec_header_length=0, sec_header=b"", message_length=len(message),
                message=message)).report, ReportVerify.SUCCESS)

    def test_implicit_at_with_signature_rejected(self):
        """IEEE 1609.2 clause 5.3.2."""
        def add_signature(sd):
            cert = sd["signer"][1][0]
            cert["signature"] = ("ecdsaNistP256Signature", {"rSig": ("x-only", b"\x01" * 32),
                                                            "sSig": b"\x01" * 32})
        bad = _mutated(self.f.sign(PSID_CAM), add_signature)
        self.assertNotEqual(self.f.verify(bad).report, ReportVerify.SUCCESS)

    def test_tampered_implicit_at_yields_wrong_key(self):
        def tamper(sd):
            sd["signer"][1][0]["toBeSigned"]["crlSeries"] = 1
        self.assertNotEqual(self.f.verify(_mutated(self.f.sign(PSID_CAM), tamper)).report,
                            ReportVerify.SUCCESS)


class TestImplicitCrossStack(unittest.TestCase):
    """Cross-stack check: an implicit AT issued and a CAM signed by the Rust
    stack (``OwnCertificate::issue_implicit_certificate``, frozen vector) is
    accepted by the Python stack. Mirrors the Rust test
    ``implicit_chain_from_python_stack_accepted``."""

    ROOT = "8003008100088300000000002b07b1f586000101010081808082bbad4511ab555d8888fc75aaac649469076a41db9f3bd665119370e248845e5f8080302f306d5b64fdcd5dff198c710258356e442751eb8ecf18462f4fa93160b946f62287a2ec68ee1e12ac267f609ef081ebccfd0c90aca5ef6930412db77291ca"
    AA = "80030080e149b24b6448e9fa088300000000002b07b1f5860001010100818080838a2e6316afdf4efe38c6f9df4cf3dde8d9572a75ba239f56ffe7319ea79c39418080aabbcea688db11d981646dacebd08975158e92451b267556e0dc7334ee5b462d8c3a84268e02bc6e104ca6347f07604aa0ff7a4b2b4de0b79c604c64ae848ced"
    MSG = "038100400380077061796c6f6164400124000290962ebceefa810101000301809da750c98c9cbdd1108300000000002b07b1f58400010102800124810403020200000125818236600b00cc27914bfda04e3aa12d945059acc493d8c681450eedbd8b1d74b63a8080be408f8587764266f407c01a4f1e937243e80ca7630679ce4d706c4a4ac2c0a5256e3039e0e4cd61afaae4d2be747fe2eb7f1948b605978bf8725ec6840862ae"

    def test_implicit_chain_from_rust_stack_accepted(self):
        backend = PythonECDSABackend()
        root = Certificate().decode(bytes.fromhex(self.ROOT))
        aa = Certificate().decode(bytes.fromhex(self.AA), issuer=root)
        library = CertificateLibrary(ecdsa_backend=backend, root_certificates=[root],
                                     aa_certificates=[aa], at_certificates=[])
        message = bytes.fromhex(self.MSG)
        confirm = VerifyService(backend=backend, certificate_library=library).verify(SNVERIFYRequest(
            sec_header_length=0, sec_header=b"", message_length=len(message), message=message))
        self.assertEqual(confirm.report, ReportVerify.SUCCESS)
        self.assertEqual(confirm.permissions, bytes([2, 0x02, 0x00]))
