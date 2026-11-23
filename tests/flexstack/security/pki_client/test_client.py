"""Unit tests of ``PkiClient`` outside the TPs: persistence, provisioning and
preconditions. The protocol behaviour is tested by test_pki_conformance.py."""

import asyncio
import pathlib
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from flexstack.security.pki_client import PkiClient

from tests.flexstack.security.pki_client.ts_pki import Transport, TsPki


class TestPkiClient(unittest.TestCase):

    def setUp(self):
        self.pki = TsPki()
        self.transport = Transport(self.pki)
        self.dir = tempfile.mkdtemp()

    def client(self, **kwargs):
        client = PkiClient(self.transport.ea_url, self.transport.aa_url, self.pki.ea.own, self.pki.aa.own,
                           self.pki.root, certs_dir=self.dir, its_id=b"its", transport=self.transport, **kwargs)
        self.pki.register(b"its", client.canonical_public_key())
        return client

    def test_canonical_key_from_pem(self):
        pem = ec.generate_private_key(ec.SECP256R1()).private_bytes(
            Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption())
        first, second = self.client(canonical_key_pem=pem), self.client(canonical_key_pem=pem)
        self.assertEqual(first.canonical_public_key(), second.canonical_public_key())
        asyncio.run(first.enroll())
        self.assertEqual(first.state, "enrolled")

    def test_provision_enrols_once(self):
        client = self.client()
        asyncio.run(client.provision())
        asyncio.run(client.provision())
        self.assertEqual(client.state, "authorized")
        self.assertEqual((len(self.pki.enrolments), len(self.pki.authorizations)), (1, 2))

    def test_authorize_without_ec(self):
        with self.assertRaises(RuntimeError):
            asyncio.run(self.client().authorize())
        self.assertEqual(self.pki.authorizations, [])

    def test_saved_and_loaded(self):
        client = self.client()
        at = asyncio.run(client.provision(app_permissions=[{"psid": 36}]))
        for name in ("ec.cert", "ec.pem", "at.cert", "at.pem"):
            self.assertTrue((pathlib.Path(self.dir) / name).exists())
        other = self.client()
        self.assertEqual(other.load_ec_from_disk().as_hashedid8(), client.ec.as_hashedid8())
        loaded = other.load_at_from_disk()
        self.assertEqual(loaded.as_hashedid8(), at.as_hashedid8())
        self.assertEqual(other.state, "authorized")
        signature = other.backend.sign(b"data", loaded.key_id)
        self.assertTrue(other.backend.verify_with_pk(b"data", signature, loaded.verification_key()))

    def test_load_missing(self):
        client = self.client()
        self.assertIsNone(client.load_at_from_disk())
        self.assertIsNone(client.load_ec_from_disk())
        (pathlib.Path(self.dir) / "at.cert").write_bytes(b"junk")
        (pathlib.Path(self.dir) / "at.pem").write_bytes(b"junk")
        self.assertIsNone(client.load_at_from_disk())


if __name__ == "__main__":
    unittest.main()
