"""Unit tests of the ETSI TS 102 941 V2.2.1 message layer (``pki_client.messages``):
encryption, the checks applied to a response, keyTag and SSP permissions.
The end-to-end behaviour is tested by test_pki_conformance.py."""

import asyncio
import hashlib
import hmac
import unittest

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from flexstack.security.certificate import Certificate
from flexstack.security.pki_client import messages
from flexstack.security.pki_client.enrolment import EnrolmentError, enroll
from flexstack.security.pki_client.messages import PkiProtocolError

from tests.flexstack.security.pki_client.ts_pki import Authority, Transport, TsPki, decode, encode
from tests.flexstack.security.test_security_checks import _ca

NOW = 1_800_000_000.0


class TestHelpers(unittest.TestCase):

    def test_psk_id_is_hash_of_symmetric_encryption_key(self):
        """pskRecipInfo: HashedId8 of the COER SymmetricEncryptionKey (choice tag 80h + key)."""
        key = bytes(range(16))
        self.assertEqual(messages.psk_id(key), hashlib.sha256(b"\x80" + key).digest()[-8:])

    def test_request_hash(self):
        self.assertEqual(messages.request_hash(b"abc"), hashlib.sha256(b"abc").digest()[:16])

    def test_times(self):
        """Time32 / Time64 count TAI from 2004-01-01 (5 leap seconds since)."""
        self.assertEqual(messages.time32(1_072_915_200), 5)
        self.assertEqual(messages.time64(1_072_915_200.5), 5_500_000)

    def test_key_tag_with_encryption_key(self):
        """keyTag over verificationKey || encryptionKey when an encryption key is requested."""
        keys = {"verificationKey": ("ecdsaNistP256", ("compressed-y-0", b"\x01" * 32)),
                "encryptionKey": {"supportedSymmAlg": "aes128Ccm",
                                  "publicKey": ("eciesNistP256", ("compressed-y-1", b"\x02" * 32))}}
        data = encode("PublicVerificationKey", keys["verificationKey"]) + encode(
            "PublicEncryptionKey", keys["encryptionKey"])
        self.assertEqual(messages.key_tag(b"k" * 32, keys), hmac.new(b"k" * 32, data, hashlib.sha256).digest()[:16])

    def test_ssp_permits(self):
        def cert(permissions):
            return Certificate.from_dict({"toBeSigned": {"appPermissions": permissions}})
        both = [{"psid": 623, "ssp": ("bitmapSsp", bytes([1, 0xC0]))}]
        self.assertTrue(messages.ssp_permits(cert(both), messages.SSP_ENROLMENT_REQUEST))
        self.assertTrue(messages.ssp_permits(cert(both), messages.SSP_AUTHORIZATION_REQUEST))
        for permissions in ([{"psid": 623, "ssp": ("bitmapSsp", bytes([1, 0x40]))}],   # no enrolment bit
                            [{"psid": 623, "ssp": ("bitmapSsp", bytes([2, 0xC0]))}],   # unknown version
                            [{"psid": 623}], [{"psid": 36}], []):
            with self.subTest(permissions=permissions):
                self.assertFalse(messages.ssp_permits(cert(permissions), messages.SSP_ENROLMENT_REQUEST))


class TestEncryption(unittest.TestCase):

    def test_encrypt_to_both_ecies_curves(self):
        """ECIES with NIST P-256 and brainpoolP256r1 encryption keys (IEEE 1609.2 clause 5.3.5)."""
        pki = TsPki()
        for curve, choice in ((ec.SECP256R1(), "eciesNistP256"), (ec.BrainpoolP256R1(), "eciesBrainpoolP256r1")):
            with self.subTest(choice=choice):
                private = ec.generate_private_key(curve)
                point = private.public_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
                own = _ca(pki.backend, choice, pki.root, 1, encryptionKey={"supportedSymmAlg": "aes128Ccm", "publicKey": (
                    choice, ("compressed-y-0" if point[0] == 2 else "compressed-y-1", point[1:]))})
                data, session_key = messages.encrypt_to(own, b"secret payload")
                self.assertEqual(data["content"][1]["recipients"][0][1]["encKey"][0], choice)
                plaintext, key = Authority(own, private).decrypt(decode("Ieee1609Dot2Data", encode("Ieee1609Dot2Data", data)))
                self.assertEqual((plaintext, key), (b"secret payload", session_key))

    def test_encrypt_to_certificate_without_encryption_key(self):
        pki = TsPki()
        with self.assertRaises(PkiProtocolError) as error:
            messages.encrypt_to(pki.root, b"x")
        self.assertEqual(error.exception.code, "invalidencryptionkey")


class TestResponseChecks(unittest.TestCase):
    """The checks of an EA / AA response (TS 102 941 clauses 6.2.3.2.2, 6.2.3.3.2)."""

    def setUp(self):
        self.pki = TsPki()
        self.canonical = self.pki.backend.create_key()
        self.pki.register(b"id", self.pki.backend.get_public_key(self.canonical))
        self.attributes = {"appPermissions": [{"psid": 623, "ssp": messages.certificate_ssp()}]}

    def request(self):
        return messages.build_enrolment_request(self.pki.backend, self.pki.ea.own, its_id=b"id",
                                                signer_key=self.canonical, current_ec=None,
                                                attributes=self.attributes, now=NOW)

    def test_valid_response(self):
        request = self.request()
        inner = messages.read_enrolment_response(self.pki.enrol(request.message), request, self.pki.ea.own,
                                                 self.pki.backend)
        self.assertEqual(inner["responseCode"], "ok")
        self.assertEqual(inner["requestHash"], request.request_hash)

    def assert_rejected(self, response, request, code, authority=None):
        with self.assertRaises(PkiProtocolError) as error:
            messages.read_enrolment_response(response, request, authority or self.pki.ea.own, self.pki.backend)
        self.assertEqual(error.exception.code, code)

    def test_garbage(self):
        self.assert_rejected(b"\x00\x01", self.request(), "cantparse")

    def test_not_encrypted(self):
        request = self.request()
        signed = encode("Ieee1609Dot2Data", {"protocolVersion": 3, "content": ("unsecuredData", b"x")})
        self.assert_rejected(signed, request, "badcontenttype")

    def test_other_session_key(self):
        """A response for another request (other AES key) is not ours."""
        first, second = self.request(), self.request()
        self.assert_rejected(self.pki.enrol(first.message), second, "imnottherecipient")

    def test_tampered_ciphertext(self):
        request = self.request()
        data = decode("Ieee1609Dot2Data", self.pki.enrol(request.message))
        ciphertext = data["content"][1]["ciphertext"][1]
        ciphertext["ccmCiphertext"] = bytes([ciphertext["ccmCiphertext"][0] ^ 1]) + ciphertext["ccmCiphertext"][1:]
        self.assert_rejected(encode("Ieee1609Dot2Data", data), request, "decryptionfailed")

    def test_signed_by_another_authority(self):
        """A response signed by the AA (not the EA the request was sent to)."""
        request = self.request()
        self.assert_rejected(self.pki.enrol(request.message), request, "invalidsignature", self.pki.aa.own)

    def test_request_hash_mismatch(self):
        request = self.request()
        response = self.pki.enrol(request.message)
        other = messages.PendingRequest(request.message + b"\x00", request.session_key, request.key_id)
        self.assert_rejected(response, other, "badcontenttype")

    def test_ec_for_another_key(self):
        """An EC that does not certify the requested verification key is refused."""
        pki, transport = self.pki, Transport(self.pki)
        original = pki._issue  # pylint: disable=protected-access

        def other_key(issuer, key, permissions, duration=("hours", 1)):
            return original(issuer, pki.backend.get_public_key(pki.backend.create_key()), permissions, duration)
        pki._issue = other_key  # pylint: disable=protected-access
        with self.assertRaises(EnrolmentError) as error:
            asyncio.run(enroll(transport, transport.ea_url, pki.ea.own, pki.backend, its_id=b"id",
                               canonical_key=self.canonical, current_ec=None, attributes=self.attributes, now=NOW))
        self.assertEqual(error.exception.code, "invalidkeys")


if __name__ == "__main__":
    unittest.main()
