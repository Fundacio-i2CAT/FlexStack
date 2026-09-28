from __future__ import annotations

import os
import unittest
from unittest.mock import AsyncMock, patch

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1,
    generate_private_key,
)

from flexstack.security.certificate import Certificate, OwnCertificate
from flexstack.security.ecdsa_backend import PythonECDSABackend
from flexstack.security.pki_client.crypto import _compress_public_key, aes_ccm_encrypt
from flexstack.security.pki_client.enrolment import (
    EnrolmentError,
    _decode_enrolment_response,
    _decrypt_psk_response,
    _extract_ea_enc_info,
    enroll,
)
from flexstack.security.pki_client.pki_coder import PKI_CODER


def _create_mock_ea_cert(backend: PythonECDSABackend) -> tuple[OwnCertificate, Certificate]:
    ea_key_id = backend.create_key()
    ea_verify_tuple = backend.get_public_key(ea_key_id)

    enc_priv = generate_private_key(SECP256R1(), default_backend())
    choice, x = _compress_public_key(enc_priv.public_key())
    enc_tuple = ("eciesNistP256", (choice, x))

    ea_cert_dict = {
        "version": 3,
        "type": "explicit",
        "issuer": ("self", "sha256"),
        "toBeSigned": {
            "id": ("name", "ea.test"),
            "cracaId": b"\x00\x00\x00",
            "crlSeries": 0,
            "validityPeriod": {"start": 0, "duration": ("years", 5)},
            "appPermissions": [{"psid": 623}],
            "verifyKeyIndicator": ("verificationKey", ea_verify_tuple),
            "encryptionKey": {
                "supportedSymmAlg": "aes128Ccm",
                "publicKey": enc_tuple,
            },
        },
        "signature": (
            "ecdsaNistP256Signature",
            {"rSig": ("x-only", b"\x01" * 32), "sSig": b"\x02" * 32},
        ),
    }
    ea_own = OwnCertificate(certificate=ea_cert_dict, issuer=None, key_id=ea_key_id)
    ea_cert = Certificate().decode(PKI_CODER.encode_certificate(ea_cert_dict))
    return ea_own, ea_cert


def _build_mock_enrolment_response(
    ea_own: OwnCertificate,
    backend: PythonECDSABackend,
    session_key_a: bytes,
    session_key_hid8: bytes,
    response_code: str = "ok",
    issued_cert_dict: dict | None = None,
) -> bytes:
    inner_resp = {
        "version": 1,
        "responseCode": response_code,
    }
    if issued_cert_dict is not None:
        inner_resp["certificate"] = issued_cert_dict

    etsi_data = PKI_CODER.encode_etsi102941_data("enrolmentResponse", inner_resp)
    tbs_resp = {
        "payload": {
            "data": {
                "protocolVersion": 3,
                "content": ("unsecuredData", etsi_data),
            }
        },
        "headerInfo": {
            "psid": 623,
            "generationTime": 1000000,
        },
    }
    tbs_resp_bytes = PKI_CODER.encode_to_be_signed_data(tbs_resp)
    ea_sig = ea_own.sign_message(backend, tbs_resp_bytes)
    signed_resp = {
        "protocolVersion": 3,
        "content": (
            "signedData",
            {
                "hashId": "sha256",
                "tbsData": tbs_resp,
                "signer": ("certificate", [ea_own.certificate]),
                "signature": ea_sig,
            },
        ),
    }
    signed_resp_bytes = PKI_CODER.encode_ieee1609dot2_data(signed_resp)
    nonce = os.urandom(12)
    ciphertext = aes_ccm_encrypt(session_key_a, nonce, signed_resp_bytes)
    outer_resp = {
        "protocolVersion": 3,
        "content": (
            "encryptedData",
            {
                "recipients": [("pskRecipInfo", session_key_hid8)],
                "ciphertext": (
                    "aes128ccm",
                    {"nonce": nonce, "ccmCiphertext": ciphertext},
                ),
            },
        ),
    }
    return PKI_CODER.encode_ieee1609dot2_data(outer_resp)


class TestEnrolment(unittest.IsolatedAsyncioTestCase):
    """
    Test suite for ETSI TS 102 941 S3 enrolment protocol.
    """

    def setUp(self) -> None:
        self.backend = PythonECDSABackend()
        self.ea_own, self.ea_cert = _create_mock_ea_cert(self.backend)

        # Bootstrap canonical cert
        canon_key_id = self.backend.create_key()
        canon_verify = self.backend.get_public_key(canon_key_id)
        canon_dict = {
            "version": 3,
            "type": "explicit",
            "issuer": ("self", "sha256"),
            "toBeSigned": {
                "id": ("name", "canonical"),
                "cracaId": b"\x00\x00\x00",
                "crlSeries": 0,
                "validityPeriod": {"start": 0, "duration": ("years", 1)},
                "appPermissions": [{"psid": 623}],
                "verifyKeyIndicator": ("verificationKey", canon_verify),
            },
            "signature": (
                "ecdsaNistP256Signature",
                {"rSig": ("x-only", b"\x10" * 32), "sSig": b"\x20" * 32},
            ),
        }
        self.canonical_own = OwnCertificate(
            certificate=canon_dict, issuer=None, key_id=canon_key_id
        )

    def test_enrolment_error(self) -> None:
        """
        Tests EnrolmentError attributes.
        """
        err = EnrolmentError("test_code", "test_message")
        self.assertEqual(err.code, "test_code")
        self.assertEqual(str(err), "test_message")

    def test_extract_ea_enc_info_valid(self) -> None:
        """
        Tests extracting encryption key information from a valid EA certificate.
        """
        enc_tuple, coer = _extract_ea_enc_info(self.ea_cert)
        self.assertEqual(enc_tuple[0], "eciesNistP256")
        self.assertIsInstance(coer, bytes)

    def test_extract_ea_enc_info_missing_encryption_key(self) -> None:
        """
        Tests that _extract_ea_enc_info raises when encryptionKey is absent.
        """
        no_enc_dict = dict(self.ea_cert.certificate)
        no_enc_dict["toBeSigned"] = dict(no_enc_dict["toBeSigned"])
        del no_enc_dict["toBeSigned"]["encryptionKey"]
        cert = Certificate.from_dict(no_enc_dict)

        with self.assertRaises(EnrolmentError) as ctx:
            _extract_ea_enc_info(cert)
        self.assertEqual(ctx.exception.code, "invalidea")

    def test_decrypt_psk_response_invalid_outer(self) -> None:
        """
        Tests that _decrypt_psk_response raises when outer envelope is not encryptedData.
        """
        unsecured = {
            "protocolVersion": 3,
            "content": ("unsecuredData", b"hello"),
        }
        raw = PKI_CODER.encode_ieee1609dot2_data(unsecured)

        with self.assertRaises(EnrolmentError) as ctx:
            _decrypt_psk_response(raw, b"\x00" * 16, b"\x00" * 8)
        self.assertEqual(ctx.exception.code, "badcontenttype")

    def test_decrypt_psk_response_missing_psk_recip(self) -> None:
        """
        Tests that _decrypt_psk_response raises when pskRecipInfo is missing.
        """
        data = {
            "protocolVersion": 3,
            "content": (
                "encryptedData",
                {
                    "recipients": [
                        (
                            "certRecipInfo",
                            {
                                "recipientId": b"\x00" * 8,
                                "encKey": (
                                    "eciesNistP256",
                                    {
                                        "v": ("compressed-y-0", b"\x00" * 32),
                                        "c": b"\x00" * 16,
                                        "t": b"\x00" * 16,
                                    },
                                ),
                            },
                        )
                    ],
                    "ciphertext": (
                        "aes128ccm",
                        {"nonce": b"\x00" * 12, "ccmCiphertext": b"\x00" * 16},
                    ),
                },
            ),
        }
        raw = PKI_CODER.encode_ieee1609dot2_data(data)

        with self.assertRaises(EnrolmentError) as ctx:
            _decrypt_psk_response(raw, b"\x00" * 16, b"\x00" * 8)
        self.assertEqual(ctx.exception.code, "badcontenttype")

    def test_decrypt_psk_response_decryption_failure(self) -> None:
        """
        Tests that _decrypt_psk_response raises decryptionfailed when AES-CCM fails.
        """
        data = {
            "protocolVersion": 3,
            "content": (
                "encryptedData",
                {
                    "recipients": [("pskRecipInfo", b"\x11" * 8)],
                    "ciphertext": (
                        "aes128ccm",
                        {"nonce": b"\x00" * 12, "ccmCiphertext": b"\x00" * 16},
                    ),
                },
            ),
        }
        raw = PKI_CODER.encode_ieee1609dot2_data(data)

        with self.assertRaises(EnrolmentError) as ctx:
            _decrypt_psk_response(raw, b"\x00" * 16, b"\x11" * 8)
        self.assertEqual(ctx.exception.code, "decryptionfailed")

    def test_decode_enrolment_response_invalid_structure(self) -> None:
        """
        Tests that _decode_enrolment_response raises when inner data is not signedData or enrolmentResponse.
        """
        unsecured = {
            "protocolVersion": 3,
            "content": ("unsecuredData", b"hello"),
        }
        raw = PKI_CODER.encode_ieee1609dot2_data(unsecured)

        with self.assertRaises(EnrolmentError) as ctx:
            _decode_enrolment_response(raw)
        self.assertEqual(ctx.exception.code, "badcontenttype")

    async def test_enroll_success(self) -> None:
        """
        Tests successful execution of the enroll() workflow with mocked HTTP response.
        """
        issued_cert_dict = {
            "version": 3,
            "type": "explicit",
            "issuer": ("sha256AndDigest", self.ea_cert.as_hashedid8()),
            "toBeSigned": {
                "id": ("name", "issued.ec"),
                "cracaId": b"\x00\x00\x00",
                "crlSeries": 0,
                "validityPeriod": {"start": 0, "duration": ("years", 1)},
                "appPermissions": [{"psid": 623}],
                "verifyKeyIndicator": (
                    "verificationKey",
                    ("ecdsaNistP256", ("compressed-y-0", b"\x55" * 32)),
                ),
            },
            "signature": (
                "ecdsaNistP256Signature",
                {"rSig": ("x-only", b"\x66" * 32), "sSig": b"\x77" * 32},
            ),
        }

        # Intercept ecies_encrypt to capture the session key for constructing the mock response
        from flexstack.security.pki_client import enrolment

        orig_ecies_encrypt = enrolment.ecies_encrypt

        def mock_ecies_encrypt(plaintext, recipient_enc_key_tuple, recipient_cert_coer):
            res = orig_ecies_encrypt(plaintext, recipient_enc_key_tuple, recipient_cert_coer)
            mock_post.return_value.content = _build_mock_enrolment_response(
                self.ea_own,
                self.backend,
                session_key_a=res[2],
                session_key_hid8=res[3],
                response_code="ok",
                issued_cert_dict=issued_cert_dict,
            )
            return res

        mock_post = AsyncMock()
        mock_post.return_value.status_code = 200

        with patch("httpx.AsyncClient.post", mock_post), \
             patch("flexstack.security.pki_client.enrolment.ecies_encrypt", side_effect=mock_ecies_encrypt):
            ec_own = await enroll(
                ea_url="http://localhost:8080",
                ea_cert=self.ea_cert,
                signer_cert=self.canonical_own,
                backend=self.backend,
                ecies_backend=None,
                its_id=b"\x01" * 8,
            )

        self.assertIsInstance(ec_own, OwnCertificate)
        self.assertEqual(ec_own.issuer, self.ea_cert)
        self.assertIsNotNone(ec_own.key_id)

    async def test_enroll_http_error(self) -> None:
        """
        Tests that enroll() raises EnrolmentError on HTTP non-200 status.
        """
        mock_post = AsyncMock()
        mock_post.return_value.status_code = 503
        mock_post.return_value.text = "Service Unavailable"

        with patch("httpx.AsyncClient.post", mock_post):
            with self.assertRaises(EnrolmentError) as ctx:
                await enroll(
                    ea_url="http://localhost:8080",
                    ea_cert=self.ea_cert,
                    signer_cert=self.canonical_own,
                    backend=self.backend,
                    ecies_backend=None,
                )
            self.assertEqual(ctx.exception.code, "http_error")

    async def test_enroll_rejected_by_ea(self) -> None:
        """
        Tests that enroll() raises EnrolmentError when EA responds with non-ok responseCode.
        """
        from flexstack.security.pki_client import enrolment
        orig_ecies_encrypt = enrolment.ecies_encrypt

        def mock_ecies_encrypt(plaintext, recipient_enc_key_tuple, recipient_cert_coer):
            res = orig_ecies_encrypt(plaintext, recipient_enc_key_tuple, recipient_cert_coer)
            mock_post.return_value.content = _build_mock_enrolment_response(
                self.ea_own,
                self.backend,
                session_key_a=res[2],
                session_key_hid8=res[3],
                response_code="incompatiblelevel",
            )
            return res

        mock_post = AsyncMock()
        mock_post.return_value.status_code = 200

        with patch("httpx.AsyncClient.post", mock_post), \
             patch("flexstack.security.pki_client.enrolment.ecies_encrypt", side_effect=mock_ecies_encrypt):
            with self.assertRaises(EnrolmentError) as ctx:
                await enroll(
                    ea_url="http://localhost:8080",
                    ea_cert=self.ea_cert,
                    signer_cert=self.canonical_own,
                    backend=self.backend,
                    ecies_backend=None,
                )
            self.assertEqual(ctx.exception.code, "incompatiblelevel")


if __name__ == "__main__":
    unittest.main()
