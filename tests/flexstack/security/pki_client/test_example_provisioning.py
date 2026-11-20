"""
examples/secured_cam_with_pki.py, PKI provisioning: (1) the ITS-S creates its
canonical key pair and stops, (2) the public key is registered with the EA,
(3) the next run enrols and gets an AT; later runs reuse the EC.
"""

import asyncio
import importlib.util
import pathlib
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization

from tests.flexstack.security.pki_client.ts_pki import Transport, TsPki

_EXAMPLE = pathlib.Path(__file__).resolve().parents[4] / "examples" / "secured_cam_with_pki.py"


def _example():
    spec = importlib.util.spec_from_file_location("secured_cam_with_pki", _EXAMPLE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _registered_key(public_pem: bytes) -> tuple:
    point = serialization.load_pem_public_key(public_pem).public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
    return "ecdsaNistP256", ("compressed-y-0" if point[0] == 2 else "compressed-y-1", point[1:])


class TestExampleProvisioning(unittest.TestCase):
    """Generate → register → provision."""

    def setUp(self):
        self.example = _example()
        self.pki = TsPki()
        self.transport = Transport(self.pki)
        self.dir = pathlib.Path(tempfile.mkdtemp())

    def provision(self, **kwargs):
        """Run the provisioning step of the example."""
        return asyncio.run(self.example._provision_at(  # pylint: disable=protected-access
            self.transport.ea_url, self.transport.aa_url, self.pki.root, self.pki.ea.own, self.pki.aa.own,
            str(self.dir), reprovision=True, transport=self.transport, **kwargs))

    def test_three_steps(self):
        with self.assertRaises(SystemExit) as stopped:                      # 1. key created, stop
            self.provision()
        self.assertEqual(stopped.exception.code, 2)
        self.assertEqual(self.pki.enrolments, [])
        key = self.example.load_or_create_canonical_key(self.dir / "canonical_key.pem")
        self.assertFalse(key.created)
        self.pki.register(key.its_id, _registered_key(key.public_pem))    # 2. registration
        at, backend = self.provision()                                      # 3. enrolment + AT
        self.assertIsNotNone(backend)
        self.assertEqual(at.certificate["issuer"][1], self.pki.aa.own.as_hashedid8())
        self.assertEqual(self.pki.enrolments[0].inner["itsId"], key.its_id)
        self.assertEqual(self.pki.enrolments[0].outer["content"][1]["signer"][0], "self")
        self.provision()                                                    # later run: EC reused
        self.assertEqual((len(self.pki.enrolments), len(self.pki.authorizations)), (1, 2))

    def test_unregistered_station_is_refused(self):
        with self.assertRaises(SystemExit):
            self.provision()
        with self.assertRaises(Exception) as refused:
            self.provision()
        self.assertEqual(getattr(refused.exception, "code", None), "invalidsignature")

    def test_assigned_identifier(self):
        with self.assertRaises(SystemExit):
            self.provision(its_id=b"\x01" * 8)
        key = self.example.load_or_create_canonical_key(self.dir / "canonical_key.pem")
        self.pki.register(b"\x01" * 8, _registered_key(key.public_pem))
        self.provision(its_id=b"\x01" * 8)
        self.assertEqual(self.pki.enrolments[0].inner["itsId"], b"\x01" * 8)


if __name__ == "__main__":
    unittest.main()
