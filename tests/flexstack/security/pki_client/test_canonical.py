"""
Canonical key pair of the ITS-S (ETSI TS 102 941 V2.2.1 clause 6.1.2) kept on
disk by :mod:`flexstack.security.pki_client.canonical`, and the initial
enrolment that depends on its registration with the EA.
"""

import asyncio
import pathlib
import stat
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from flexstack.security.pki_client import PkiClient
from flexstack.security.pki_client.canonical import (
    canonical_id,
    load_or_create_canonical_key,
    public_key_path,
    public_pem,
)
from flexstack.security.pki_client.enrolment import EnrolmentError

from tests.flexstack.security.pki_client.ts_pki import Transport, TsPki

# Frozen vector, also in RustFlexstack (pki_client::canonical): the NIST P-256
# private key of RFC 6979 A.2.5 as PKCS#8 PEM, and its SubjectPublicKeyInfo PEM.
VECTOR_PRIVATE = (
    b"-----BEGIN PRIVATE KEY-----\n"
    b"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgya+p2EW6dRZrXCFX\n"
    b"Z7HWk05Qw9s26JsSe4piKxIPZyGhRANCAARg/tS6JVqdMclh63TGNW1owEm4kjth\n"
    b"+mzmaWIuYPKftnkD/hAIuLyZpBrp6VYovGTy8bIMLX6fUXejwpTURiKZ\n"
    b"-----END PRIVATE KEY-----\n"
)
VECTOR_PUBLIC = (
    b"-----BEGIN PUBLIC KEY-----\n"
    b"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYP7UuiVanTHJYet0xjVtaMBJuJI7\n"
    b"Yfps5mliLmDyn7Z5A/4QCLi8maQa6elWKLxk8vGyDC1+n1F3o8KU1EYimQ==\n"
    b"-----END PUBLIC KEY-----\n"
)
VECTOR_ITS_ID = bytes.fromhex("cbe0f0815a07ecd4")  # SHA-256(DER SPKI), last 8 octets


def _compressed(public: bytes) -> tuple:
    """PublicVerificationKey of a SubjectPublicKeyInfo PEM (as an EA registers it)."""
    key = serialization.load_pem_public_key(public)
    point = key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
    return "ecdsaNistP256", ("compressed-y-0" if point[0] == 2 else "compressed-y-1", point[1:])


class TestCanonicalKeyFiles(unittest.TestCase):
    """The key pair is created once and kept."""

    def setUp(self):
        self.dir = pathlib.Path(tempfile.mkdtemp())
        self.path = self.dir / "pki" / "canonical_key.pem"

    def test_created_once_and_private(self):
        first = load_or_create_canonical_key(self.path)
        self.assertTrue(first.created)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode) & 0o077, 0)
        self.assertEqual(first.public_path, self.dir / "pki" / "canonical_key.pub.pem")
        self.assertEqual(first.public_path.read_bytes(), first.public_pem)
        second = load_or_create_canonical_key(self.path)
        self.assertFalse(second.created)
        self.assertEqual((second.private_pem, second.public_pem), (first.private_pem, first.public_pem))

    def test_public_file_is_rewritten_from_the_private_key(self):
        key = load_or_create_canonical_key(self.path)
        key.public_path.write_bytes(b"stale")
        self.assertEqual(load_or_create_canonical_key(self.path).public_path.read_bytes(), key.public_pem)
        key.public_path.unlink()
        self.assertEqual(load_or_create_canonical_key(self.path).public_path.read_bytes(), key.public_pem)

    def test_frozen_vector(self):
        self.path.parent.mkdir(parents=True)
        self.path.write_bytes(VECTOR_PRIVATE)
        key = load_or_create_canonical_key(self.path)
        self.assertFalse(key.created)
        self.assertEqual(key.public_pem, VECTOR_PUBLIC)
        self.assertEqual(public_pem(VECTOR_PRIVATE), VECTOR_PUBLIC)
        self.assertEqual(key.its_id, VECTOR_ITS_ID)
        self.assertEqual(canonical_id(VECTOR_PUBLIC), VECTOR_ITS_ID)

    def test_sec1_pem_is_read_and_other_curves_refused(self):
        sec1 = ec.generate_private_key(ec.SECP256R1()).private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption())
        self.assertIn(b"BEGIN PUBLIC KEY", public_pem(sec1))
        p384 = ec.generate_private_key(ec.SECP384R1()).private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        with self.assertRaises(ValueError):
            public_pem(p384)

    def test_public_key_path_and_registration_command(self):
        self.assertEqual(public_key_path("/x/key.pem"), pathlib.Path("/x/key.pub.pem"))
        self.assertEqual(public_key_path("/x/key"), pathlib.Path("/x/key.pub.pem"))
        key = load_or_create_canonical_key(self.path)
        self.assertEqual(key.registration_command(bytes.fromhex("0102")),
                         f"ea-tool register --its-id 0102 --public-key {key.public_path}")
        self.assertEqual(key.registration_command(),
                         f"ea-tool register --its-id {key.its_id.hex()} --public-key {key.public_path}")
        self.assertEqual(len(key.its_id), 8)
        self.assertNotEqual(key.its_id, load_or_create_canonical_key(self.dir / "b.pem").its_id)


class TestInitialEnrolment(unittest.TestCase):
    """Generate (ITS-S) → register the public key (EA) → enrol."""

    def setUp(self):
        self.pki = TsPki()
        self.transport = Transport(self.pki)
        self.dir = pathlib.Path(tempfile.mkdtemp())
        self.key = load_or_create_canonical_key(self.dir / "canonical_key.pem")

    def client(self) -> PkiClient:
        """An ITS-S client with the canonical key of the file."""
        return PkiClient(self.transport.ea_url, self.transport.aa_url, self.pki.ea.own, self.pki.aa.own,
                         self.pki.root, canonical_key_pem=self.key.private_pem, certs_dir=str(self.dir),
                         its_id=b"its", transport=self.transport, enrolment_retry=None)

    def test_registered_key_enrols(self):
        client = self.client()
        self.assertEqual(client.canonical_public_key(), _compressed(self.key.public_pem))
        self.pki.register(b"its", _compressed(self.key.public_pem))
        asyncio.run(client.provision())
        self.assertEqual(client.state, "authorized")
        self.assertEqual(self.pki.enrolments[0].outer["content"][1]["signer"][0], "self")

    def test_unregistered_or_other_key_is_refused(self):
        for registered in (None, _compressed(load_or_create_canonical_key(self.dir / "other.pem").public_pem)):
            with self.subTest(registered=registered is not None):
                if registered is not None:
                    self.pki.register(b"its", registered)
                with self.assertRaises(EnrolmentError):
                    asyncio.run(self.client().enroll())
                self.assertFalse(self.pki.enrolments[-1].checks["outer"])

    def test_later_runs_rekey_with_the_saved_ec(self):
        self.pki.register(b"its", _compressed(self.key.public_pem))
        asyncio.run(self.client().enroll())
        later = self.client()
        self.assertIsNotNone(later.load_ec_from_disk())
        asyncio.run(later.enroll())
        self.assertEqual(self.pki.enrolments[-1].outer["content"][1]["signer"][0], "digest")


if __name__ == "__main__":
    unittest.main()
