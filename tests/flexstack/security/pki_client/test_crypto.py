import hashlib
import hmac as _hmac
import os
import time
import unittest

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH,
    SECP256R1,
    generate_private_key,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from flexstack.security.pki_client.crypto import (
    _compress_public_key,
    _public_key_from_tuple,
    aes_ccm_decrypt,
    aes_ccm_encrypt,
    compute_hmac_key_tag,
    ecies_encrypt,
    kdf2,
    now_time32,
    psk_decrypt,
)


class TestCrypto(unittest.TestCase):
    """
    Test suite for cryptographic helpers in pki_client.crypto.
    """

    def test_now_time32(self) -> None:
        """
        Tests now_time32 calculation since ITS epoch (2004-01-01).
        """
        t = now_time32()
        self.assertIsInstance(t, int)
        expected = int(time.time()) - 1_072_915_200
        self.assertAlmostEqual(t, expected, delta=2)

    def test_kdf2(self) -> None:
        """
        Tests IEEE 1609.2 KDF2 key derivation sub-key lengths and determinism.
        """
        shared_x = b"\x11" * 32
        cert_coer = b"\x22" * 100
        k_enc, k_mac = kdf2(shared_x, cert_coer)

        self.assertEqual(len(k_enc), 16)
        self.assertEqual(len(k_mac), 32)

        # Deterministic
        k_enc2, k_mac2 = kdf2(shared_x, cert_coer)
        self.assertEqual(k_enc, k_enc2)
        self.assertEqual(k_mac, k_mac2)

        # Different input yields different keys
        k_enc3, _ = kdf2(b"\x33" * 32, cert_coer)
        self.assertNotEqual(k_enc, k_enc3)

    def test_aes_ccm_encrypt_decrypt(self) -> None:
        """
        Tests AES-128-CCM symmetric encryption and decryption.
        """
        key = os.urandom(16)
        nonce = os.urandom(12)
        plaintext = b"Sensitive ITS message payload 12345"

        ciphertext = aes_ccm_encrypt(key, nonce, plaintext)
        self.assertEqual(len(ciphertext), len(plaintext) + 16)  # 16-byte tag

        recovered = aes_ccm_decrypt(key, nonce, ciphertext)
        self.assertEqual(recovered, plaintext)

    def test_aes_ccm_decrypt_invalid_tag(self) -> None:
        """
        Tests that AES-128-CCM raises InvalidTag if ciphertext is altered.
        """
        key = os.urandom(16)
        nonce = os.urandom(12)
        plaintext = b"Hello World"

        ciphertext = bytearray(aes_ccm_encrypt(key, nonce, plaintext))
        ciphertext[0] ^= 0xFF  # Corrupt ciphertext

        with self.assertRaises(InvalidTag):
            aes_ccm_decrypt(key, nonce, bytes(ciphertext))

    def test_compress_public_key(self) -> None:
        """
        Tests compression of EllipticCurvePublicKey into (choice, x_bytes).
        """
        priv = generate_private_key(SECP256R1(), default_backend())
        pub = priv.public_key()

        choice, x_bytes = _compress_public_key(pub)
        self.assertIn(choice, ("compressed-y-0", "compressed-y-1"))
        self.assertEqual(len(x_bytes), 32)

    def test_public_key_from_tuple(self) -> None:
        """
        Tests reconstructing P-256 public keys from ASN.1 tuples.
        """
        priv = generate_private_key(SECP256R1(), default_backend())
        pub = priv.public_key()

        # Compressed
        raw_comp = pub.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
        choice = "compressed-y-0" if raw_comp[0] == 0x02 else "compressed-y-1"
        x_bytes = raw_comp[1:]

        recovered_pub = _public_key_from_tuple(("eciesNistP256", (choice, x_bytes)))
        self.assertEqual(
            pub.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint),
            recovered_pub.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint),
        )

        # Uncompressed
        raw_uncomp = pub.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        x_uncomp, y_uncomp = raw_uncomp[1:33], raw_uncomp[33:65]
        recovered_uncomp = _public_key_from_tuple(
            ("eciesNistP256", ("uncompressedP256", {"x": x_uncomp, "y": y_uncomp}))
        )
        self.assertEqual(
            pub.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint),
            recovered_uncomp.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint),
        )

        # Unsupported
        with self.assertRaises(ValueError):
            _public_key_from_tuple(("eciesNistP256", ("unsupportedFormat", b"")))

    def test_ecies_encrypt_and_decrypt(self) -> None:
        """
        Tests ECIES encryption by sender and full decryption on recipient side.
        """
        recipient_priv = generate_private_key(SECP256R1(), default_backend())
        recipient_pub = recipient_priv.public_key()
        v_choice, v_x = _compress_public_key(recipient_pub)
        enc_key_tuple = ("eciesNistP256", (v_choice, v_x))
        cert_coer = b"dummy_cert_coer_representation_12345"

        plaintext = b"Payload for PKI recipient (EA/AA)"

        ecies_key, aes_ccm, session_key_a, session_key_hid8 = ecies_encrypt(
            plaintext=plaintext,
            recipient_enc_key_tuple=enc_key_tuple,
            recipient_cert_coer=cert_coer,
        )

        # Check returned structures
        self.assertIn("v", ecies_key)
        self.assertIn("c", ecies_key)
        self.assertIn("t", ecies_key)
        self.assertEqual(len(ecies_key["c"]), 16)
        self.assertEqual(len(ecies_key["t"]), 16)

        self.assertIn("nonce", aes_ccm)
        self.assertIn("ccmCiphertext", aes_ccm)
        self.assertEqual(len(aes_ccm["nonce"]), 12)

        self.assertEqual(len(session_key_a), 16)
        self.assertEqual(len(session_key_hid8), 8)
        self.assertEqual(session_key_hid8, hashlib.sha256(session_key_a).digest()[-8:])

        # Recipient manual decrypt (KEM recovery)
        eph_v_choice, eph_v_x = ecies_key["v"]
        eph_prefix = b"\x02" if eph_v_choice == "compressed-y-0" else b"\x03"
        from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
        eph_pub = EllipticCurvePublicKey.from_encoded_point(SECP256R1(), eph_prefix + eph_v_x)
        shared_x = recipient_priv.exchange(ECDH(), eph_pub)
        k_enc, k_mac = kdf2(shared_x, cert_coer)

        # Check tag
        expected_t = _hmac.new(k_mac, ecies_key["c"], hashlib.sha256).digest()[:16]
        self.assertEqual(expected_t, ecies_key["t"])

        # Recover A
        recovered_a = bytes(x ^ y for x, y in zip(ecies_key["c"], k_enc))
        self.assertEqual(recovered_a, session_key_a)

        # Decrypt ciphertext
        decrypted = aes_ccm_decrypt(recovered_a, aes_ccm["nonce"], aes_ccm["ccmCiphertext"])
        self.assertEqual(decrypted, plaintext)

    def test_psk_decrypt(self) -> None:
        """
        Tests psk_decrypt helper reusing the session key.
        """
        session_key = os.urandom(16)
        nonce = os.urandom(12)
        plaintext = b"Decrypted inner signed ITS data"
        ciphertext = aes_ccm_encrypt(session_key, nonce, plaintext)

        aes_ccm_dict = {
            "nonce": nonce,
            "ccmCiphertext": ciphertext,
        }
        decrypted = psk_decrypt(session_key, aes_ccm_dict)
        self.assertEqual(decrypted, plaintext)

    def test_compute_hmac_key_tag(self) -> None:
        """
        Tests compute_hmac_key_tag produces 16-byte HMAC-SHA256 tag.
        """
        hmac_key = os.urandom(32)
        public_keys_coer = b"coer_encoded_public_keys_data"

        tag = compute_hmac_key_tag(hmac_key, public_keys_coer)
        self.assertEqual(len(tag), 16)

        expected = _hmac.new(hmac_key, public_keys_coer, hashlib.sha256).digest()[:16]
        self.assertEqual(tag, expected)


if __name__ == "__main__":
    unittest.main()
