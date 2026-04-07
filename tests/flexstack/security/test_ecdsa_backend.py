import hashlib
import unittest
from unittest.mock import MagicMock, patch
from flexstack.security.ecdsa_backend import PythonECDSABackend


class TestPythonECDSABackend(unittest.TestCase):
    """
    Testing Case for the Python ECDSA Backend.
    """

    def setUp(self) -> None:
        self.backend = PythonECDSABackend()

    def test__init__(self):
        """
        Tests the init of the Python ECDSA Backend.
        """
        self.assertEqual(self.backend.keys, {})

    def test_create_key(self):
        """
        Tests the create_key of the Python ECDSA Backend.
        """
        self.assertEqual(self.backend.create_key(), 0)
        self.assertEqual(self.backend.create_key(), 1)
        self.assertEqual(self.backend.create_key(), 2)
        self.assertEqual(len(self.backend.keys), 3)

    def test_get_public_key(self):
        """
        Tests the get_public_key of the Python ECDSA Backend.
        """
        self.backend.create_key()
        pk1 = self.backend.get_public_key(0)
        self.assertEqual(pk1[0], "ecdsaNistP256")
        self.assertEqual(len(pk1[1][1]["x"]), 32)
        self.assertEqual(len(pk1[1][1]["y"]), 32)

    def test_sign(self):
        # Given
        self.backend.create_key()
        # When
        signature = self.backend.sign(b"Hello World", 0)
        # Then
        self.assertEqual(signature[0], "ecdsaNistP256Signature")
        self.assertEqual(signature[1]["rSig"][0], "x-only")
        self.assertEqual(len(signature[1]["rSig"][1]), 32)
        self.assertEqual(len(signature[1]["sSig"]), 32)

    def test_verify(self):
        # Given
        self.backend.create_key()
        signature = self.backend.sign(b"Hello World", 0)
        # When
        result = self.backend.verify(b"Hello World", signature, 0)
        # Then
        self.assertTrue(result)

    def test_verify_with_pk(self):
        # Given
        self.backend.create_key()
        signature = self.backend.sign(b"Hello World", 0)
        pk = self.backend.get_public_key(0)
        # When
        result = self.backend.verify_with_pk(b"Hello World", signature, pk)
        # Then
        self.assertTrue(result)
        # Now false
        result = self.backend.verify_with_pk(b"Hello World23", signature, pk)
        self.assertFalse(result)

    @patch("ecdsa.SigningKey.generate")
    @patch("ecdsa.util.sigdecode_string")
    def test_sign_with_sha256_1(self, sigdecode_mock, signingkey_generate_mock):
        # Given
        signing_key = MagicMock()
        signing_key.sign = MagicMock(
            return_value=b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01')
        signingkey_generate_mock.return_value = signing_key
        sigdecode_mock.return_value = (1, 2)

        backend = PythonECDSABackend()
        backend.create_key()

        # When
        backend.sign(b"Hello World", 0)
        # Then
        signingkey_generate_mock.assert_called_once()
        signing_key.sign.assert_called_once_with(
            data=b"Hello World", hashfunc=hashlib.sha256)

    @patch("ecdsa.SigningKey.generate")
    @patch("ecdsa.util.sigencode_string")
    def test_sign_with_sha256_2(self, sigencode_mock, signingkey_generate_mock):
        # Given
        signing_key = MagicMock()
        signing_key.verifying_key = MagicMock()
        signing_key.verifying_key.verify = MagicMock(return_value=True)
        signingkey_generate_mock.return_value = signing_key
        signature = ("ecdsaNistP256Signature", {
            "rSig": ("x-only", (12).to_bytes(32, byteorder='big')),
            "sSig": (2).to_bytes(32, byteorder='big')
        })
        sigencode_mock.return_value = signature
        # When
        backend = PythonECDSABackend()
        backend.create_key()
        backend.verify(b'whatever', signature, 0)
        signingkey_generate_mock.assert_called_once()
        sigencode_mock.assert_called_once()
        signing_key.verifying_key.verify.assert_called_once_with(
            signature=signature,
            data=b'whatever',
            hashfunc=hashlib.sha256
        )

    @patch("ecdsa.ellipticcurve.Point", return_value="something")
    @patch("ecdsa.VerifyingKey.from_public_point")
    @patch("ecdsa.util.sigencode_string")
    def test_sign_with_sha256_3(self, sigencode_mock, from_public_point_mock, point_mock):
        # Given
        verifying_key = MagicMock()
        verifying_key.verify = MagicMock(return_value=True)
        signature = ("ecdsaNistP256Signature", {
            "rSig": ("x-only", (12).to_bytes(32, byteorder='big')),
            "sSig": (2).to_bytes(32, byteorder='big')
        })
        sigencode_mock.return_value = signature
        pk = ("ecdsaNistP256", (
            "uncompressedP256", {
                "x": (123).to_bytes(32, byteorder='big'),
                "y": (321).to_bytes(32, byteorder='big')
            }
        ))
        from_public_point_mock.return_value = verifying_key

        # When
        backend = PythonECDSABackend()
        backend.verify_with_pk(b'whatever', signature, pk)

        # Then
        sigencode_mock.assert_called_once()
        from_public_point_mock.assert_called_once()
        verifying_key.verify.assert_called_once_with(
            signature=signature,
            data=b'whatever',
            hashfunc=hashlib.sha256
        )

    def test_export_signing_key(self):
        """Test that export_signing_key returns a valid PEM-encoded private key."""
        identifier = self.backend.create_key()

        pem = self.backend.export_signing_key(identifier)

        self.assertIsInstance(pem, bytes)
        self.assertIn(b"-----BEGIN EC PRIVATE KEY-----", pem)

    def test_import_signing_key(self):
        """Test that import_signing_key loads a PEM key and returns a usable identifier."""
        # Create a key, export it, then import it under a fresh backend instance
        original_id = self.backend.create_key()
        pem = self.backend.export_signing_key(original_id)

        imported_id = self.backend.import_signing_key(pem)

        # The imported key must be a new distinct identifier
        self.assertNotEqual(imported_id, original_id)
        # Public keys derived from both identifiers must be identical
        self.assertEqual(
            self.backend.get_public_key(original_id),
            self.backend.get_public_key(imported_id),
        )
        # The imported key must be able to produce a valid signature
        signature = self.backend.sign(b"test_data", imported_id)
        self.assertTrue(self.backend.verify(b"test_data", signature, imported_id))
