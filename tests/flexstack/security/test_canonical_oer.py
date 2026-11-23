"""
Canonical OER of certificates (X.696, IEEE Std 1609.2): a PsidGroupPermissions
eeType equal to its DEFAULT {app} is not encoded
(:func:`flexstack.security.security_coder.canonical`), so certificates are
hashed, signed and verified over their canonical encoding, as in RustFlexstack.
"""

import unittest

from flexstack.security.certificate import Certificate, OwnCertificate
from flexstack.security.ecdsa_backend import PythonECDSABackend
from flexstack.security.pki_client.pki_coder import PKI_CODER
from flexstack.security.security_coder import SecurityCoder, canonical

APP = (b"\x80", 8)


def _group(**extra) -> dict:
    return dict({"subjectPermissions": ("all", None), "minChainLength": 2}, **extra)


def _root_tbs(ee_type) -> dict:
    group = _group() if ee_type is None else _group(eeType=ee_type)
    return {
        "id": ("name", "root"), "cracaId": b"\x00\x00\x00", "crlSeries": 0,
        "validityPeriod": {"start": 0, "duration": ("seconds", 30)},
        "appPermissions": [{"psid": 36}],
        "certIssuePermissions": [group],
        "verifyKeyIndicator": ("verificationKey", ("ecdsaNistP256", ("fill", None))),
    }


class TestCanonical(unittest.TestCase):
    """canonical()."""

    def test_default_ee_type_removed_input_untouched(self):
        group = _group(eeType=APP)
        self.assertEqual(canonical(group), _group())
        self.assertEqual(group["eeType"], APP)

    def test_other_values_kept(self):
        for ee_type in ((b"\xc0", 8), (b"\x40", 8), (b"\x80", 1)):
            with self.subTest(ee_type=ee_type):
                self.assertEqual(canonical(_group(eeType=ee_type)), _group(eeType=ee_type))
        self.assertEqual(canonical({"eeType": APP}), {"eeType": APP})   # not a PsidGroupPermissions

    def test_unchanged_values_are_returned_as_is(self):
        value = {"a": [1, (2, _group())], "b": b"x"}
        self.assertIs(canonical(value), value)

    def test_nested_in_lists_and_tuples(self):
        value = {"signer": ("certificate", [{"toBeSigned": _root_tbs(APP)}])}
        self.assertEqual(canonical(value)["signer"][1][0]["toBeSigned"], _root_tbs(None))
        self.assertIsInstance(canonical(value)["signer"], tuple)


class TestCanonicalEncoding(unittest.TestCase):
    """The coders encode canonically."""

    def test_header_info_extension_additions(self):
        """COER of HeaderInfo extension additions (X.696 clause 16.4: presence
        bitmap over the 4 additions of the TS 103 097 V2.2.1 ASN.1, then open
        types). Frozen vectors, also in RustFlexstack
        (header_extensions::tests::header_info_extension_additions_coer)."""
        coder = SecurityCoder().asn_coder
        self.assertEqual(coder.encode("HeaderInfo", {"psid": 36, "pduFunctionalType": 2}).hex(),
                         "8001240204200102")
        self.assertEqual(coder.encode("HeaderInfo", {"psid": 36, "inlineP2pcdRequest": [b"\x01\x02\x03"]}).hex(),
                         "800124020480050101010203")

    def test_security_and_pki_coders(self):
        for coder in (SecurityCoder(), PKI_CODER):
            with self.subTest(coder=type(coder).__name__):
                self.assertEqual(coder.asn_coder.encode("PsidGroupPermissions", _group(eeType=APP)),
                                 coder.asn_coder.encode("PsidGroupPermissions", _group()))
                self.assertEqual(coder.encode_ToBeSignedCertificate(_root_tbs(APP)),
                                 coder.encode_ToBeSignedCertificate(_root_tbs(None)))

    def test_frozen_vector(self):
        """Same vector in RustFlexstack (psid_group_permissions_encoding_is_canonical)."""
        coder = SecurityCoder().asn_coder
        self.assertEqual(coder.encode("PsidGroupPermissions", _group(eeType=APP)).hex(), "80810102")
        self.assertEqual(coder.encode("PsidGroupPermissions", dict(_group(eeType=APP), minChainLength=1)).hex(),
                         "0081")
        self.assertEqual(coder.encode("PsidGroupPermissions", _group(eeType=(b"\xc0", 8))).hex(), "a0810102c0")

    def test_decoded_values_round_trip(self):
        coder = SecurityCoder().asn_coder
        encoded = coder.encode("PsidGroupPermissions", _group(eeType=(b"\xc0", 8)))
        self.assertEqual(coder.encode("PsidGroupPermissions", coder.decode("PsidGroupPermissions", encoded)),
                         encoded)

    def test_signed_with_explicit_default_is_canonical_and_verifies(self):
        backend = PythonECDSABackend()
        explicit = OwnCertificate.initialize_certificate(backend, _root_tbs(APP))
        self.assertTrue(explicit.verify(backend))
        decoded = Certificate().decode(explicit.encode())
        self.assertEqual(decoded.encode(), explicit.encode())
        self.assertTrue(decoded.verify(backend))
        self.assertEqual(decoded.as_hashedid8(), explicit.as_hashedid8())


if __name__ == "__main__":
    unittest.main()


class TestCanonicalEncodingCache(unittest.TestCase):
    """Certificate.canonical_encoding: computed once, same value as to_canonical()."""

    def test_cached_and_equal(self):
        backend = PythonECDSABackend()
        root = OwnCertificate.initialize_certificate(backend=backend, to_be_signed_certificate={
            "id": ("name", "root"), "cracaId": b"\x00\x00\x00", "crlSeries": 0,
            "validityPeriod": {"start": 0, "duration": ("years", 1)},
            "certIssuePermissions": [{"subjectPermissions": ("all", None), "minChainLength": 2}],
            "verifyKeyIndicator": ("verificationKey", ("ecdsaNistP256", ("fill", None)))}, issuer=None)
        first = root.canonical_encoding()
        self.assertEqual(first, root.to_canonical().encode())
        self.assertIs(root.canonical_encoding(), first)
        copy = Certificate(root.certificate, None)
        self.assertEqual(copy.canonical_encoding(), first)
        self.assertEqual(root.as_hashedid8(), copy.as_hashedid8())
