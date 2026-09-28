from __future__ import annotations

import pathlib
import shutil
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from flexstack.security.certificate import Certificate, OwnCertificate
from flexstack.security.ecdsa_backend import PythonECDSABackend
from flexstack.security.pki_client.client import PkiClient
from flexstack.security.pki_client.crypto import now_time32
from flexstack.security.pki_client.pki_coder import PKI_CODER


def _create_mock_cert(backend: PythonECDSABackend, name: str) -> Certificate:
    key_id = backend.create_key()
    verify_tuple = backend.get_public_key(key_id)
    cert_dict = {
        "version": 3,
        "type": "explicit",
        "issuer": ("self", "sha256"),
        "toBeSigned": {
            "id": ("name", name),
            "cracaId": b"\x00\x00\x00",
            "crlSeries": 0,
            "validityPeriod": {"start": 0, "duration": ("years", 10)},
            "appPermissions": [{"psid": 0}],
            "verifyKeyIndicator": ("verificationKey", verify_tuple),
        },
        "signature": (
            "ecdsaNistP256Signature",
            {"rSig": ("x-only", b"\x01" * 32), "sSig": b"\x02" * 32},
        ),
    }
    encoded = PKI_CODER.encode_certificate(cert_dict)
    return Certificate().decode(encoded)


def _create_mock_own_cert(backend: PythonECDSABackend, name: str, issuer: Certificate | None = None) -> OwnCertificate:
    key_id = backend.create_key()
    verify_tuple = backend.get_public_key(key_id)
    issuer_tuple = (
        ("sha256AndDigest", issuer.as_hashedid8())
        if issuer is not None
        else ("self", "sha256")
    )
    cert_dict = {
        "version": 3,
        "type": "explicit",
        "issuer": issuer_tuple,
        "toBeSigned": {
            "id": ("name", name),
            "cracaId": b"\x00\x00\x00",
            "crlSeries": 0,
            "validityPeriod": {"start": now_time32() - 100, "duration": ("years", 1)},
            "appPermissions": [{"psid": 623}],
            "verifyKeyIndicator": ("verificationKey", verify_tuple),
        },
        "signature": (
            "ecdsaNistP256Signature",
            {"rSig": ("x-only", b"\x03" * 32), "sSig": b"\x04" * 32},
        ),
    }
    return OwnCertificate(certificate=cert_dict, issuer=issuer, key_id=key_id)


class TestPkiClient(unittest.IsolatedAsyncioTestCase):
    """
    Test suite for PkiClient high-level orchestration and persistence.
    """

    def setUp(self) -> None:
        self.tmp_dir = tempfile.mkdtemp()
        self.backend = PythonECDSABackend()
        self.rca_cert = _create_mock_cert(self.backend, "rca.test")
        self.ea_cert = _create_mock_cert(self.backend, "ea.test")
        self.aa_cert = _create_mock_cert(self.backend, "aa.test")

        self.client = PkiClient(
            ea_url="http://localhost:8080",
            aa_url="http://localhost:8081",
            ea_cert=self.ea_cert,
            aa_cert=self.aa_cert,
            rca_cert=self.rca_cert,
            certs_dir=self.tmp_dir,
            its_id=b"\x00" * 8,
            http_timeout=15.0,
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_init(self) -> None:
        """
        Tests PkiClient initialization and directory setup.
        """
        self.assertEqual(self.client.ea_url, "http://localhost:8080")
        self.assertEqual(self.client.aa_url, "http://localhost:8081")
        self.assertEqual(self.client.ea_cert, self.ea_cert)
        self.assertEqual(self.client.aa_cert, self.aa_cert)
        self.assertEqual(self.client.rca_cert, self.rca_cert)
        self.assertEqual(self.client.certs_dir, pathlib.Path(self.tmp_dir))
        self.assertEqual(self.client.its_id, b"\x00" * 8)
        self.assertEqual(self.client.http_timeout, 15.0)
        self.assertIsInstance(self.client.backend, PythonECDSABackend)
        self.assertIsNone(self.client._ec_own)
        self.assertIsNone(self.client._at_own)

    def test_get_or_create_canonical_cert_generate(self) -> None:
        """
        Tests generating a self-signed canonical certificate on first access.
        """
        canon1 = self.client._get_or_create_canonical_cert()
        self.assertIsInstance(canon1, OwnCertificate)
        self.assertEqual(canon1.certificate["toBeSigned"]["id"], ("name", "its-s-canonical"))

        # Cached in memory
        canon2 = self.client._get_or_create_canonical_cert()
        self.assertIs(canon1, canon2)

    def test_get_or_create_canonical_cert_from_pem(self) -> None:
        """
        Tests creating a canonical certificate using a provided private key PEM.
        """
        key_id = self.backend.create_key()
        pem = self.backend.export_signing_key(key_id)

        custom_client = PkiClient(
            ea_url="http://localhost:8080",
            aa_url="http://localhost:8081",
            ea_cert=self.ea_cert,
            aa_cert=self.aa_cert,
            rca_cert=self.rca_cert,
            canonical_key_pem=pem,
            certs_dir=self.tmp_dir,
        )
        canon = custom_client._get_or_create_canonical_cert()
        self.assertIsInstance(canon, OwnCertificate)
        self.assertEqual(canon.certificate["toBeSigned"]["id"], ("name", "its-s-canonical"))

    def test_save_cert(self) -> None:
        """
        Tests persisting OwnCertificate and private key to disk.
        """
        own_cert = _create_mock_own_cert(self.client.backend, "saved_cert", self.ea_cert)

        self.client._save_cert(own_cert, "saved_cert")
        cert_file = self.client.certs_dir / "saved_cert.cert"
        pem_file = self.client.certs_dir / "saved_cert.pem"

        self.assertTrue(cert_file.exists())
        self.assertTrue(pem_file.exists())
        self.assertEqual(cert_file.read_bytes(), own_cert.encode())
        self.assertEqual(pem_file.read_bytes(), self.client.backend.export_signing_key(own_cert.key_id))

    def test_load_at_from_disk_missing(self) -> None:
        """
        Tests load_at_from_disk returns None when files do not exist.
        """
        self.assertIsNone(self.client.load_at_from_disk("missing_at"))

    def test_load_at_from_disk_success(self) -> None:
        """
        Tests loading an AT from disk when files are present.
        """
        at_own = _create_mock_own_cert(self.client.backend, "at_disk", self.aa_cert)
        self.client._save_cert(at_own, "at")

        loaded = self.client.load_at_from_disk("at")
        self.assertIsNotNone(loaded)
        self.assertIs(loaded, self.client._at_own)
        self.assertEqual(loaded.as_hashedid8(), at_own.as_hashedid8())
        self.assertEqual(loaded.issuer, self.aa_cert)

    def test_load_at_from_disk_corrupt(self) -> None:
        """
        Tests load_at_from_disk gracefully returns None on corrupt data.
        """
        cert_file = self.client.certs_dir / "corrupt.cert"
        pem_file = self.client.certs_dir / "corrupt.pem"
        cert_file.write_bytes(b"invalid data")
        pem_file.write_bytes(b"invalid pem")

        self.assertIsNone(self.client.load_at_from_disk("corrupt"))

    async def test_enroll(self) -> None:
        """
        Tests enroll() orchestrates S3 request and saves result.
        """
        mock_ec = _create_mock_own_cert(self.client.backend, "ec_enrolled", self.ea_cert)

        with patch("flexstack.security.pki_client.client.enroll", AsyncMock(return_value=mock_ec)) as mock_enroll_func:
            res = await self.client.enroll(validity_years=2)
            self.assertEqual(res, mock_ec)
            self.assertIs(self.client._ec_own, mock_ec)
            mock_enroll_func.assert_awaited_once_with(
                ea_url=self.client.ea_url,
                ea_cert=self.client.ea_cert,
                signer_cert=self.client._canonical_cert,
                backend=self.client.backend,
                ecies_backend=None,
                its_id=self.client.its_id,
                requested_app_permissions=None,
                validity_years=2,
                timeout=self.client.http_timeout,
            )

        # Ensure ec.cert and ec.pem were written
        self.assertTrue((self.client.certs_dir / "ec.cert").exists())
        self.assertTrue((self.client.certs_dir / "ec.pem").exists())

    async def test_authorize_success(self) -> None:
        """
        Tests authorize() orchestrates S2 request and saves result.
        """
        mock_ec = _create_mock_own_cert(self.client.backend, "ec_enrolled", self.ea_cert)
        mock_at = _create_mock_own_cert(self.client.backend, "at_authorized", self.aa_cert)
        self.client._ec_own = mock_ec

        with patch("flexstack.security.pki_client.client.authorize", AsyncMock(return_value=mock_at)) as mock_auth_func:
            res = await self.client.authorize(validity_hours=100)
            self.assertEqual(res, mock_at)
            self.assertIs(self.client._at_own, mock_at)
            mock_auth_func.assert_awaited_once_with(
                aa_url=self.client.aa_url,
                aa_cert=self.client.aa_cert,
                ea_cert=self.client.ea_cert,
                ec_own=mock_ec,
                backend=self.client.backend,
                requested_app_permissions=None,
                validity_hours=100,
                timeout=self.client.http_timeout,
            )

        # Ensure at.cert and at.pem were written
        self.assertTrue((self.client.certs_dir / "at.cert").exists())
        self.assertTrue((self.client.certs_dir / "at.pem").exists())

    async def test_authorize_without_ec_raises(self) -> None:
        """
        Tests authorize() raises RuntimeError if called before enroll() and ec_own is None.
        """
        self.client._ec_own = None
        with self.assertRaises(RuntimeError) as ctx:
            await self.client.authorize()
        self.assertIn("No EC available", str(ctx.exception))

    async def test_provision(self) -> None:
        """
        Tests provision() runs enroll() and authorize() in sequence.
        """
        mock_ec = _create_mock_own_cert(self.client.backend, "ec_prov", self.ea_cert)
        mock_at = _create_mock_own_cert(self.client.backend, "at_prov", self.aa_cert)

        with patch.object(self.client, "enroll", AsyncMock(return_value=mock_ec)) as mock_enroll, \
             patch.object(self.client, "authorize", AsyncMock(return_value=mock_at)) as mock_auth:
            perms = [{"psid": 36}]
            res = await self.client.provision(
                app_permissions=perms,
                ec_validity_years=3,
                at_validity_hours=72,
            )
            self.assertEqual(res, mock_at)
            mock_enroll.assert_awaited_once_with(validity_years=3)
            mock_auth.assert_awaited_once_with(
                ec_own=mock_ec,
                app_permissions=perms,
                validity_hours=72,
            )


if __name__ == "__main__":
    unittest.main()
