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

    # Frozen COER encodings of the official ETSI TS 102 941 V2.2.1 types (asn1tools
    # compiled from the forge.etsi.org modules); the Rust stack checks the same bytes.
    VECTORS = {
        "InnerEcRequest": "000831323334353637380180808211111111111111111111111111111111111111111111"
                          "111111111111111111110080832222222222222222222222222222222222222222222222"
                          "222222222222222222240000006486000101018002026f81030201c0",
        "InnerEcResponse": "00abababababababababababababababab0d",
        "SharedAtRequest": "00aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb01040102000124000125",
        "InnerAtResponse": "00cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd0a",
        "crl": "0184000101000000050000000601010101010101010101",
        "rca_ctl": "0186000101000000070003010280830b68747470733a2f2f64632f0101020202020202020281800303030303030303",
        "at_request": "0182000080834444444444444444444444444444444444444444444444444444444444444444555555555555"
                      "555555555555555555555555555555555555555555555555555500aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb"
                      "bbbbbbbbbbbbbbbb01040101000124800382010182666666666666666680827777777777777777777777777777"
                      "777777777777777777777777777777777777888888888888888888888888888888889999999999999999999999"
                      "999999999980121212121212121212121212143434343434343434343434343434343434343434",
    }

    def test_official_encodings(self) -> None:
        """EtsiTs102941Data and inner types encode as the official modules specify:
        extension bits in the preambles, CHOICE indexes (CRL 4, RCA CTL 6), Version
        length-prefixed in CtlFormat / ToBeSignedCrl, one octet in EtsiTs102941Data."""
        values = {
            "InnerEcRequest": {"itsId": b"12345678", "certificateFormat": 1,
                               "publicKeys": {"verificationKey": ("ecdsaNistP256", ("compressed-y-0", b"\x11" * 32)),
                                              "encryptionKey": {"supportedSymmAlg": "aes128Ccm", "publicKey": (
                                                  "eciesNistP256", ("compressed-y-1", b"\x22" * 32))}},
                               "requestedSubjectAttributes": {"validityPeriod": {"start": 100, "duration": ("years", 1)},
                                                              "appPermissions": [{"psid": 623, "ssp": (
                                                                  "bitmapSsp", b"\x01\xc0")}]}},
            "InnerEcResponse": {"requestHash": b"\xab" * 16, "responseCode": "deniedrequest"},
            "SharedAtRequest": {"eaId": b"\xaa" * 8, "keyTag": b"\xbb" * 16, "certificateFormat": 1,
                                "requestedSubjectAttributes": {"appPermissions": [{"psid": 36}, {"psid": 37}]}},
            "InnerAtResponse": {"requestHash": b"\xcd" * 16, "responseCode": "its-aa-unknownea"},
        }
        for type_name, value in values.items():
            with self.subTest(type_name=type_name):
                encoded = self.coder.asn_coder.encode(type_name, value)
                self.assertEqual(encoded.hex(), self.VECTORS[type_name])
                self.assertEqual(self.coder.asn_coder.decode(type_name, encoded), value)
        crl = {"version": 1, "content": ("certificateRevocationList", {
            "version": 1, "thisUpdate": 5, "nextUpdate": 6, "entries": [b"\x01" * 8]})}
        ctl = {"version": 1, "content": ("certificateTrustListRca", {
            "version": 1, "nextUpdate": 7, "isFullCtl": False, "ctlSequence": 3, "ctlCommands": [
                ("add", ("dc", {"url": "https://dc/", "cert": [b"\x02" * 8]})), ("delete", ("cert", b"\x03" * 8))]})}
        at_request = {"version": 1, "content": ("authorizationRequest", {
            "publicKeys": {"verificationKey": ("ecdsaNistP256", ("compressed-y-1", b"\x44" * 32))},
            "hmacKey": b"\x55" * 32,
            "sharedAtRequest": {"eaId": b"\xaa" * 8, "keyTag": b"\xbb" * 16, "certificateFormat": 1,
                                "requestedSubjectAttributes": {"appPermissions": [{"psid": 36}]}},
            "ecSignature": ("encryptedEcSignature", {"protocolVersion": 3, "content": ("encryptedData", {
                "recipients": [("certRecipInfo", {"recipientId": b"\x66" * 8, "encKey": ("eciesNistP256", {
                    "v": ("compressed-y-0", b"\x77" * 32), "c": b"\x88" * 16, "t": b"\x99" * 16})})],
                "ciphertext": ("aes128ccm", {"nonce": b"\x12" * 12, "ccmCiphertext": b"\x34" * 20})})})})}
        for name, value in (("crl", crl), ("rca_ctl", ctl), ("at_request", at_request)):
            with self.subTest(name=name):
                self.assertEqual(self.coder.encode_etsi102941_data(*value["content"]).hex(), self.VECTORS[name])
                self.assertEqual(self.coder.decode_etsi102941_data(bytes.fromhex(self.VECTORS[name])), value)

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
