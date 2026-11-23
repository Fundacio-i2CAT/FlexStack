"""
End-to-end checks of secured CAM / DENM generation and reception with a real
certificate chain (Root CA -> AA -> AT), real ECDSA-P256 keys and the real
ETSI TS 103 097 coder: what the station actually puts on the wire.

Each test names the ETSI TS 103 096-2 test purposes it exercises. These are
unit tests traced to the TPs, not an execution of the ETSI ATS.

Mirrors ``rustflexstack::security::verify_service`` tests
``signed_cam_header_conformance``, ``signed_denm_header_conformance``,
``digest_signed_cam_accepted_once_certificate_known``,
``digest_signed_cam_from_unknown_at_not_accepted`` and the ``*_rejected`` tests.
"""

import time
import unittest

from flexstack.security.certificate import OwnCertificate
from flexstack.security.certificate_library import CertificateLibrary
from flexstack.security.ecdsa_backend import PythonECDSABackend
from flexstack.security.security_coder import SecurityCoder
from flexstack.security.sign_service import SignService
from flexstack.security.sn_sap import ReportVerify, SNSIGNRequest, SNVERIFYRequest
from flexstack.security.verify_service import VerifyService

ITS_EPOCH = 1072915200
PSID_CAM = 36
PSID_DENM = 37
FORBIDDEN_CAM_HEADER_FIELDS = (
    "expiryTime", "generationLocation", "encryptionKey",
    "p2pcdLearningRequest", "missingCrlIdentifier",
)


def _its_now() -> int:
    return int(time.time()) - ITS_EPOCH


def _build_chain(backend):
    validity = {"start": _its_now() - 60, "duration": ("years", 1)}
    key = ("verificationKey", ("ecdsaNistP256", ("fill", None)))
    root = OwnCertificate.initialize_certificate(
        backend=backend,
        to_be_signed_certificate={
            "id": ("name", "test-root"), "cracaId": b"\x00\x00\x00", "crlSeries": 0,
            "validityPeriod": validity,
            "certIssuePermissions": [{"subjectPermissions": ("all", None),
                                      "minChainLength": 2, "chainLengthRange": 0,
                                      "eeType": (b"\x00", 1)}],
            "verifyKeyIndicator": key,
        },
        issuer=None,
    )
    aa = OwnCertificate.initialize_certificate(
        backend=backend,
        to_be_signed_certificate={
            "id": ("name", "test-aa"), "cracaId": b"\x00\x00\x00", "crlSeries": 0,
            "validityPeriod": validity,
            "certIssuePermissions": [{
                "subjectPermissions": ("explicit", [{"psid": PSID_CAM}, {"psid": PSID_DENM}]),
                "minChainLength": 1, "chainLengthRange": 0, "eeType": (b"\x00", 1)}],
            "verifyKeyIndicator": key,
        },
        issuer=root,
    )
    at = OwnCertificate.initialize_certificate(
        backend=backend,
        to_be_signed_certificate={
            "id": ("none", None), "cracaId": b"\x00\x00\x00", "crlSeries": 0,
            "validityPeriod": validity,
            "appPermissions": [{"psid": PSID_CAM}, {"psid": PSID_DENM}],
            "verifyKeyIndicator": key,
        },
        issuer=aa,
    )
    return root, aa, at


class TestSignedMessageConformance(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        backend = PythonECDSABackend()
        cls.root, cls.aa, cls.at = _build_chain(backend)
        library = CertificateLibrary(
            ecdsa_backend=backend, root_certificates=[cls.root],
            aa_certificates=[cls.aa], at_certificates=[])
        library.add_own_certificate(cls.at)
        cls.backend = backend
        cls.sign_service = SignService(backend=backend, certificate_library=library)
        cls.coder = SecurityCoder()

    def _receiver(self):
        """A station that trusts the same Root CA and AA but has never seen the AT."""
        library = CertificateLibrary(
            ecdsa_backend=self.backend, root_certificates=[self.root],
            aa_certificates=[self.aa], at_certificates=[])
        return VerifyService(backend=self.backend, certificate_library=library)

    def _sign(self, its_aid, payload, generation_location=None):
        request = SNSIGNRequest(
            tbs_message_length=len(payload), tbs_message=payload, its_aid=its_aid,
            permissions_length=0, permissions=b"", generation_location=generation_location)
        # Same entry points as the GN router: CAMs via sign_cam(), others via
        # sign_request().
        if its_aid == PSID_CAM:
            return self.sign_service.sign_cam(request).sec_message
        return self.sign_service.sign_request(request).sec_message

    @staticmethod
    def _verify(verifier, message):
        return verifier.verify(SNVERIFYRequest(
            sec_header_length=0, sec_header=b"", message_length=len(message), message=message))

    def test_signed_cam_structure(self):
        """ETSI TS 103 097 clause 5.1, ETSI TS 103 097 clause 7.1.1,
        ETSI TS 103 097 clause 7.1.1: version 3, signedData, psid AID_CAM, generationTime only,
        unsecured inner data carrying the CAM payload."""
        self.sign_service.cam_handler.requested_own_certificate = True
        payload = b"\x02\x02cam-payload"
        decoded = self.coder.decode_etsi_ts_103097_data_signed(self._sign(PSID_CAM, payload))

        self.assertEqual(decoded["protocolVersion"], 3)
        self.assertEqual(decoded["content"][0], "signedData")
        signed = decoded["content"][1]
        header = signed["tbsData"]["headerInfo"]
        self.assertEqual(header["psid"], PSID_CAM)
        self.assertIn("generationTime", header)
        for field in FORBIDDEN_CAM_HEADER_FIELDS:
            self.assertNotIn(field, header)
        inner = signed["tbsData"]["payload"]["data"]
        self.assertEqual(inner["protocolVersion"], 3)
        self.assertEqual(inner["content"], ("unsecuredData", payload))
        self.assertEqual(signed["signer"][0], "certificate")

    def test_signed_cam_is_accepted_by_receiver(self):
        """IEEE 1609.2 clause 5.3.1, ETSI TS 103 097 clause 7.1.1: the signature verifies
        cryptographically at an independent receiver (certificate signer)."""
        self.sign_service.cam_handler.requested_own_certificate = True
        payload = b"\x02\x02cam-payload"
        confirm = self._verify(self._receiver(), self._sign(PSID_CAM, payload))
        self.assertEqual(confirm.report, ReportVerify.SUCCESS)
        self.assertEqual(confirm.plain_message, payload)

    def test_digest_signed_cam_accepted_once_certificate_known(self):
        """ETSI TS 103 097 clause 7.1.1: after a CAM with the full certificate, a
        digest-signed CAM from the same AT is accepted."""
        receiver = self._receiver()
        self.sign_service.cam_handler.requested_own_certificate = True
        self.assertEqual(self._verify(receiver, self._sign(PSID_CAM, b"first")).report,
                         ReportVerify.SUCCESS)
        second = self._sign(PSID_CAM, b"second")
        decoded = self.coder.decode_etsi_ts_103097_data_signed(second)
        self.assertEqual(decoded["content"][1]["signer"][0], "digest")
        self.assertEqual(self._verify(receiver, second).report, ReportVerify.SUCCESS)

    def test_digest_signed_cam_from_unknown_at_is_not_accepted(self):
        """ETSI TS 103 097 clause 7.1.1 (receiver side): a digest of an unknown AT
        cannot be verified; the receiver reports the signer as not found."""
        self.sign_service.cam_handler.requested_own_certificate = True
        self._sign(PSID_CAM, b"first")  # certificate CAM, not delivered
        digest_cam = self._sign(PSID_CAM, b"second")
        confirm = self._verify(self._receiver(), digest_cam)
        self.assertEqual(confirm.report, ReportVerify.SIGNER_CERTIFICATE_NOT_FOUND)

    def test_cam_with_invalid_signature_is_discarded(self):
        """ETSI TS 103 097 clause 6: a CAM whose signature does not verify is
        discarded."""
        self.sign_service.cam_handler.requested_own_certificate = True
        message = bytearray(self._sign(PSID_CAM, b"\x02\x02cam-payload"))
        message[-1] ^= 0x01  # last byte belongs to the signature's s component
        confirm = self._verify(self._receiver(), bytes(message))
        self.assertNotEqual(confirm.report, ReportVerify.SUCCESS)

    def test_signed_denm_structure_and_acceptance(self):
        """ETSI TS 103 097 clause 7.1.2: psid
        AID_DENM, generationTime and generationLocation, certificate signer,
        accepted by an independent receiver."""
        location = {"latitude": 415520000, "longitude": 21340000, "elevation": 0xF000}
        payload = b"\x02\x01denm-payload"
        message = self._sign(PSID_DENM, payload, generation_location=location)
        decoded = self.coder.decode_etsi_ts_103097_data_signed(message)
        signed = decoded["content"][1]
        header = signed["tbsData"]["headerInfo"]
        self.assertEqual(header["psid"], PSID_DENM)
        self.assertIn("generationTime", header)
        self.assertEqual(header["generationLocation"], location)
        for field in ("expiryTime", "encryptionKey", "p2pcdLearningRequest",
                      "missingCrlIdentifier"):
            self.assertNotIn(field, header)
        self.assertEqual(signed["signer"][0], "certificate")
        confirm = self._verify(self._receiver(), message)
        self.assertEqual(confirm.report, ReportVerify.SUCCESS)
        self.assertEqual(confirm.plain_message, payload)

    # ── Negative reception (checks run before signature verification) ──────
    def _mutated(self, message, mutate):
        decoded = self.coder.decode_etsi_ts_103097_data_signed(message)
        mutate(decoded["content"][1])
        return self.coder.encode_etsi_ts_103097_data_signed(decoded)

    def _denm(self):
        location = {"latitude": 415520000, "longitude": 21340000, "elevation": 0xF000}
        return self._sign(PSID_DENM, b"denm", generation_location=location)

    def _receiver_knowing_at(self):
        verifier = self._receiver()
        self.sign_service.cam_handler.requested_own_certificate = True
        self._verify(verifier, self._sign(PSID_CAM, b"learn"))  # receiver learns the AT
        return verifier

    def test_cam_with_p2pcd_learning_request_rejected(self):
        """ETSI TS 103 097 clause 7.1.1."""
        self.sign_service.cam_handler.requested_own_certificate = True
        bad = self._mutated(self._sign(PSID_CAM, b"cam"), lambda sd: sd["tbsData"]["headerInfo"]
                            .__setitem__("p2pcdLearningRequest", b"\x01\x02\x03"))
        self.assertEqual(self._verify(self._receiver(), bad).report,
                         ReportVerify.INCOMPATIBLE_PROTOCOL)

    def test_denm_without_generation_location_rejected(self):
        """ETSI TS 103 097 clause 7.1.2."""
        bad = self._mutated(self._denm(), lambda sd: sd["tbsData"]["headerInfo"]
                            .pop("generationLocation"))
        self.assertEqual(self._verify(self._receiver(), bad).report,
                         ReportVerify.INCOMPATIBLE_PROTOCOL)

    def test_denm_with_expiry_time_rejected(self):
        """ETSI TS 103 097 clause 7.1.2."""
        bad = self._mutated(self._denm(), lambda sd: sd["tbsData"]["headerInfo"]
                            .__setitem__("expiryTime", 1))
        self.assertEqual(self._verify(self._receiver(), bad).report,
                         ReportVerify.INCOMPATIBLE_PROTOCOL)

    def test_denm_with_p2pcd_learning_request_rejected(self):
        """ETSI TS 103 097 clause 5.2."""
        bad = self._mutated(self._denm(), lambda sd: sd["tbsData"]["headerInfo"]
                            .__setitem__("p2pcdLearningRequest", b"\x01\x02\x03"))
        self.assertEqual(self._verify(self._receiver(), bad).report,
                         ReportVerify.INCOMPATIBLE_PROTOCOL)

    def test_denm_signed_with_digest_rejected(self):
        """ETSI TS 103 097 clause 6 (digest case)."""
        bad = self._mutated(self._denm(), lambda sd: sd.__setitem__(
            "signer", ("digest", self.at.as_hashedid8())))
        self.assertEqual(self._verify(self._receiver_knowing_at(), bad).report,
                         ReportVerify.UNSUPPORTED_SIGNER_IDENTIFIER_TYPE)


if __name__ == "__main__":
    unittest.main()
