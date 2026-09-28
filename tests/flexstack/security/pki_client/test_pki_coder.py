import unittest

from flexstack.security.pki_client.pki_coder import PKI_CODER, PkiCoder
from flexstack.security.security_coder import SecurityCoder


class TestPkiCoder(unittest.TestCase):
    """
    Test suite for PkiCoder and the PKI_CODER singleton.
    """

    def setUp(self) -> None:
        self.coder = PkiCoder()

    def test__init__(self) -> None:
        """
        Tests the initialization of PkiCoder.
        """
        self.assertIsNotNone(self.coder.asn_coder)
        self.assertIsInstance(self.coder, SecurityCoder)

    def test_singleton(self) -> None:
        """
        Tests the PKI_CODER module singleton.
        """
        self.assertIsInstance(PKI_CODER, PkiCoder)
        self.assertIsNotNone(PKI_CODER.asn_coder)

    def test_encode_decode_ieee1609dot2_data(self) -> None:
        """
        Tests encoding and decoding of generic Ieee1609Dot2Data envelopes.
        """
        data = {
            "protocolVersion": 3,
            "content": ("unsecuredData", b"test_payload_123"),
        }
        encoded = self.coder.encode_ieee1609dot2_data(data)
        self.assertIsInstance(encoded, bytes)

        decoded = self.coder.decode_ieee1609dot2_data(encoded)
        self.assertEqual(decoded["protocolVersion"], 3)
        self.assertEqual(decoded["content"], ("unsecuredData", b"test_payload_123"))

    def test_encode_decode_etsi102941_data(self) -> None:
        """
        Tests encoding and decoding of EtsiTs102941Data envelopes.
        """
        inner_ec = {
            "itsId": b"\x01\x02\x03\x04\x05\x06\x07\x08",
            "certificateFormat": 1,
            "publicKeys": {
                "verificationKey": ("ecdsaNistP256", ("compressed-y-0", b"\x00" * 32)),
            },
            "requestedSubjectAttributes": {},
        }
        encoded = self.coder.encode_etsi102941_data("enrolmentRequest", inner_ec)
        self.assertIsInstance(encoded, bytes)

        decoded = self.coder.decode_etsi102941_data(encoded)
        self.assertEqual(decoded["version"], 1)
        self.assertEqual(decoded["content"][0], "enrolmentRequest")
        self.assertEqual(decoded["content"][1]["itsId"], b"\x01\x02\x03\x04\x05\x06\x07\x08")

    def test_encode_decode_inner_ec_request(self) -> None:
        """
        Tests encoding InnerECRequest.
        """
        request = {
            "itsId": b"12345678",
            "certificateFormat": 1,
            "publicKeys": {
                "verificationKey": ("ecdsaNistP256", ("compressed-y-0", b"\x11" * 32)),
                "encryptionKey": {
                    "supportedSymmAlg": "aes128Ccm",
                    "publicKey": ("eciesNistP256", ("compressed-y-1", b"\x22" * 32)),
                },
            },
            "requestedSubjectAttributes": {
                "validityPeriod": {
                    "start": 100,
                    "duration": ("years", 1),
                },
                "appPermissions": [{"psid": 623}],
            },
        }
        encoded = self.coder.encode_inner_ec_request(request)
        self.assertIsInstance(encoded, bytes)

    def test_decode_inner_ec_response(self) -> None:
        """
        Tests decoding InnerECResponse.
        """
        response_dict = {
            "version": 1,
            "responseCode": "ok",
        }
        raw_response = self.coder.asn_coder.encode("InnerECResponse", response_dict)
        decoded = self.coder.decode_inner_ec_response(raw_response)
        self.assertEqual(decoded["version"], 1)
        self.assertEqual(decoded["responseCode"], "ok")

    def test_encode_shared_at_request(self) -> None:
        """
        Tests encoding SharedAtRequest.
        """
        shared_at = {
            "eaId": b"\xaa" * 8,
            "keyTag": b"\xbb" * 16,
            "certificateFormat": 1,
            "requestedSubjectAttributes": {
                "validityPeriod": {
                    "start": 200,
                    "duration": ("hours", 504),
                },
                "appPermissions": [{"psid": 36}, {"psid": 37}],
            },
        }
        encoded = self.coder.encode_shared_at_request(shared_at)
        self.assertIsInstance(encoded, bytes)

    def test_encode_inner_at_request(self) -> None:
        """
        Tests encoding InnerAtRequest.
        """
        shared_at = {
            "eaId": b"\xaa" * 8,
            "keyTag": b"\xbb" * 16,
            "certificateFormat": 1,
            "requestedSubjectAttributes": {},
        }
        inner_at = {
            "publicKeys": {
                "verificationKey": ("ecdsaNistP256", ("compressed-y-0", b"\x11" * 32)),
            },
            "hmacKey": b"\x22" * 32,
            "sharedAtRequest": shared_at,
            "ecSignature": (
                "ecSignature",
                {"protocolVersion": 3, "content": ("unsecuredData", b"dummy")},
            ),
        }
        encoded = self.coder.encode_inner_at_request(inner_at)
        self.assertIsInstance(encoded, bytes)

    def test_decode_inner_at_response(self) -> None:
        """
        Tests decoding InnerAtResponse.
        """
        resp_dict = {
            "requestHash": b"\x33" * 16,
            "responseCode": "ok",
        }
        raw = self.coder.asn_coder.encode("InnerAtResponse", resp_dict)
        decoded = self.coder.decode_inner_at_response(raw)
        self.assertEqual(decoded["requestHash"], b"\x33" * 16)
        self.assertEqual(decoded["responseCode"], "ok")

    def test_encode_public_keys(self) -> None:
        """
        Tests encoding PublicKeys structure for verification and encryption keys.
        """
        keys_only_verify = {
            "verificationKey": ("ecdsaNistP256", ("compressed-y-0", b"\x44" * 32)),
        }
        encoded_verify = self.coder.encode_public_keys(keys_only_verify)
        self.assertIsInstance(encoded_verify, bytes)

        keys_both = {
            "verificationKey": ("ecdsaNistP256", ("compressed-y-0", b"\x44" * 32)),
            "encryptionKey": {
                "supportedSymmAlg": "aes128Ccm",
                "publicKey": ("eciesNistP256", ("compressed-y-1", b"\x55" * 32)),
            },
        }
        encoded_both = self.coder.encode_public_keys(keys_both)
        self.assertIsInstance(encoded_both, bytes)
        self.assertGreater(len(encoded_both), len(encoded_verify))

    def test_encode_decode_certificate(self) -> None:
        """
        Tests encoding and decoding EtsiTs103097Certificate via PkiCoder.
        """
        cert_dict = {
            "version": 3,
            "type": "explicit",
            "issuer": ("self", "sha256"),
            "toBeSigned": {
                "id": ("name", "test.pki"),
                "cracaId": b"\x00\x00\x00",
                "crlSeries": 0,
                "validityPeriod": {
                    "start": 0,
                    "duration": ("seconds", 60),
                },
                "appPermissions": [{"psid": 0}],
                "verifyKeyIndicator": (
                    "verificationKey",
                    ("ecdsaNistP256", ("compressed-y-0", b"\x66" * 32)),
                ),
            },
            "signature": (
                "ecdsaNistP256Signature",
                {
                    "rSig": ("x-only", b"\x77" * 32),
                    "sSig": b"\x88" * 32,
                },
            ),
        }
        encoded = self.coder.encode_certificate(cert_dict)
        self.assertIsInstance(encoded, bytes)

        decoded = self.coder.decode_certificate(encoded)
        self.assertEqual(decoded["version"], 3)
        self.assertEqual(decoded["toBeSigned"]["id"], ("name", "test.pki"))
        self.assertEqual(decoded["signature"][1]["sSig"], b"\x88" * 32)

    def test_inherited_security_coder_methods(self) -> None:
        """
        Tests that parent SecurityCoder methods remain functional on PkiCoder.
        """
        tbs = {
            "payload": {
                "data": {
                    "protocolVersion": 3,
                    "content": ("unsecuredData", b"payload"),
                }
            },
            "headerInfo": {
                "psid": 623,
                "generationTime": 12345678,
            },
        }
        tbs_bytes = self.coder.encode_to_be_signed_data(tbs)
        self.assertIsInstance(tbs_bytes, bytes)

        data_signed = {
            "protocolVersion": 3,
            "content": (
                "signedData",
                {
                    "hashId": "sha256",
                    "tbsData": tbs,
                    "signer": ("digest", b"\x00" * 8),
                    "signature": (
                        "ecdsaNistP256Signature",
                        {"rSig": ("fill", None), "sSig": b"\x01" * 32},
                    ),
                },
            ),
        }
        signed_bytes = self.coder.encode_etsi_ts_103097_data_signed(data_signed)
        self.assertIsInstance(signed_bytes, bytes)
        decoded_signed = self.coder.decode_etsi_ts_103097_data_signed(signed_bytes)
        self.assertEqual(decoded_signed["protocolVersion"], 3)


if __name__ == "__main__":
    unittest.main()
