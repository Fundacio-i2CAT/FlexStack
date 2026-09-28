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
from flexstack.security.pki_client.authorization import (
    AuthorizationError,
    _build_ec_signature,
    _decode_authorization_response,
    _decrypt_psk_response,
    _extract_enc_info,
    authorize,
)
from flexstack.security.pki_client.crypto import _compress_public_key, aes_ccm_encrypt
from flexstack.security.pki_client.pki_coder import PKI_CODER


def _create_mock_authority_cert(
    backend: PythonECDSABackend, name: str, psid: int
) -> tuple[OwnCertificate, Certificate]:
    key_id = backend.create_key()
    verify_tuple = backend.get_public_key(key_id)

    enc_priv = generate_private_key(SECP256R1(), default_backend())
    choice, x = _compress_public_key(enc_priv.public_key())
    enc_tuple = ("eciesNistP256", (choice, x))

    cert_dict = {
        "version": 3,
        "type": "explicit",
        "issuer": ("self", "sha256"),
        "toBeSigned": {
            "id": ("name", name),
            "cracaId": b"\x00\x00\x00",
            "crlSeries": 0,
            "validityPeriod": {"start": 0, "duration": ("years", 5)},
            "appPermissions": [{"psid": psid}],
            "verifyKeyIndicator": ("verificationKey", verify_tuple),
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
    own_cert = OwnCertificate(certificate=cert_dict, issuer=None, key_id=key_id)
    cert = Certificate().decode(PKI_CODER.encode_certificate(cert_dict))
    return own_cert, cert


def _build_mock_authorization_response(
    aa_own: OwnCertificate,
    backend: PythonECDSABackend,
    session_key_a: bytes,
    session_key_hid8: bytes,
    response_code: str = "ok",
    issued_cert_dict: dict | None = None,
) -> bytes:
    inner_at_resp = {
        "requestHash": b"\x11" * 16,
        "responseCode": response_code,
    }
    if issued_cert_dict is not None:
        inner_at_resp["certificate"] = issued_cert_dict

    etsi_data = PKI_CODER.encode_etsi102941_data("authorizationResponse", inner_at_resp)
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
    aa_sig = aa_own.sign_message(backend, tbs_resp_bytes)
    signed_resp = {
        "protocolVersion": 3,
        "content": (
            "signedData",
            {
                "hashId": "sha256",
                "tbsData": tbs_resp,
                "signer": ("certificate", [aa_own.certificate]),
                "signature": aa_sig,
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


class TestAuthorization(unittest.IsolatedAsyncioTestCase):
    """
    Test suite for ETSI TS 102 941 S2 authorization protocol.
    """

    def setUp(self) -> None:
        self.backend = PythonECDSABackend()
        self.ea_own, self.ea_cert = _create_mock_authority_cert(self.backend, "ea.test", 623)
        self.aa_own, self.aa_cert = _create_mock_authority_cert(self.backend, "aa.test", 623)

        # Enrolment Credential
        ec_key_id = self.backend.create_key()
        ec_verify = self.backend.get_public_key(ec_key_id)
        ec_dict = {
            "version": 3,
            "type": "explicit",
            "issuer": ("sha256AndDigest", self.ea_cert.as_hashedid8()),
            "toBeSigned": {
                "id": ("name", "ec.test"),
                "cracaId": b"\x00\x00\x00",
                "crlSeries": 0,
                "validityPeriod": {"start": 0, "duration": ("years", 1)},
                "appPermissions": [{"psid": 623}],
                "verifyKeyIndicator": ("verificationKey", ec_verify),
            },
            "signature": (
                "ecdsaNistP256Signature",
                {"rSig": ("x-only", b"\x10" * 32), "sSig": b"\x20" * 32},
            ),
        }
        self.ec_own = OwnCertificate(certificate=ec_dict, issuer=self.ea_cert, key_id=ec_key_id)

    def test_authorization_error(self) -> None:
        """
        Tests AuthorizationError attributes.
        """
        err = AuthorizationError("test_code", "error description")
        self.assertEqual(err.code, "test_code")
        self.assertEqual(str(err), "error description")

    def test_extract_enc_info_valid(self) -> None:
        """
        Tests extracting encryption key information from a valid AA certificate.
        """
        enc_tuple, coer = _extract_enc_info(self.aa_cert, "AA")
        self.assertEqual(enc_tuple[0], "eciesNistP256")
        self.assertIsInstance(coer, bytes)

    def test_extract_enc_info_missing_encryption_key(self) -> None:
        """
        Tests that _extract_enc_info raises when encryptionKey is absent.
        """
        no_enc_dict = dict(self.aa_cert.certificate)
        no_enc_dict["toBeSigned"] = dict(no_enc_dict["toBeSigned"])
        del no_enc_dict["toBeSigned"]["encryptionKey"]
        cert = Certificate.from_dict(no_enc_dict)

        with self.assertRaises(AuthorizationError) as ctx:
            _extract_enc_info(cert, "AA")
        self.assertEqual(ctx.exception.code, "invalidcert")

    def test_build_ec_signature(self) -> None:
        """
        Tests building the privacy-protected ecSignature encrypted for EA.
        """
        shared_at_request = {
            "eaId": self.ea_cert.as_hashedid8(),
            "keyTag": b"\xaa" * 16,
            "certificateFormat": 1,
            "requestedSubjectAttributes": {},
        }
        ec_sig_choice = _build_ec_signature(
            shared_at_request=shared_at_request,
            ec_own=self.ec_own,
            ea_cert=self.ea_cert,
            backend=self.backend,
            gen_time_us=1000000,
        )
        self.assertEqual(ec_sig_choice[0], "encryptedEcSignature")
        self.assertIn("content", ec_sig_choice[1])

    def test_decrypt_psk_response_invalid_outer(self) -> None:
        """
        Tests that _decrypt_psk_response raises when outer envelope is not encryptedData.
        """
        unsecured = {
            "protocolVersion": 3,
            "content": ("unsecuredData", b"hello"),
        }
        raw = PKI_CODER.encode_ieee1609dot2_data(unsecured)

        with self.assertRaises(AuthorizationError) as ctx:
            _decrypt_psk_response(raw, b"\x00" * 16, b"\x00" * 8)
        self.assertEqual(ctx.exception.code, "badcontenttype")

    def test_decode_authorization_response(self) -> None:
        """
        Tests decoding a valid authorization response.
        """
        inner_at_resp = {
            "requestHash": b"\x99" * 16,
            "responseCode": "ok",
        }
        etsi_data = PKI_CODER.encode_etsi102941_data("authorizationResponse", inner_at_resp)
        tbs = {
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
        signed = {
            "protocolVersion": 3,
            "content": (
                "signedData",
                {
                    "hashId": "sha256",
                    "tbsData": tbs,
                    "signer": ("certificate", [self.aa_cert.certificate]),
                    "signature": (
                        "ecdsaNistP256Signature",
                        {"rSig": ("x-only", b"\x01" * 32), "sSig": b"\x02" * 32},
                    ),
                },
            ),
        }
        signed_bytes = PKI_CODER.encode_ieee1609dot2_data(signed)
        decoded = _decode_authorization_response(signed_bytes)
        self.assertEqual(decoded["requestHash"], b"\x99" * 16)
        self.assertEqual(decoded["responseCode"], "ok")

    async def test_authorize_success(self) -> None:
        """
        Tests successful authorize() flow with mocked HTTP communication.
        """
        issued_at_dict = {
            "version": 3,
            "type": "explicit",
            "issuer": ("sha256AndDigest", self.aa_cert.as_hashedid8()),
            "toBeSigned": {
                "id": ("name", "issued.at"),
                "cracaId": b"\x00\x00\x00",
                "crlSeries": 0,
                "validityPeriod": {"start": 0, "duration": ("hours", 504)},
                "appPermissions": [{"psid": 36}, {"psid": 37}],
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

        from flexstack.security.pki_client import authorization
        orig_ecies_encrypt = authorization.ecies_encrypt

        def mock_ecies_encrypt(plaintext, recipient_enc_key_tuple, recipient_cert_coer):
            res = orig_ecies_encrypt(plaintext, recipient_enc_key_tuple, recipient_cert_coer)
            mock_post.return_value.content = _build_mock_authorization_response(
                self.aa_own,
                self.backend,
                session_key_a=res[2],
                session_key_hid8=res[3],
                response_code="ok",
                issued_cert_dict=issued_at_dict,
            )
            return res

        mock_post = AsyncMock()
        mock_post.return_value.status_code = 200

        with patch("httpx.AsyncClient.post", mock_post), \
             patch("flexstack.security.pki_client.authorization.ecies_encrypt", side_effect=mock_ecies_encrypt):
            at_own = await authorize(
                aa_url="http://localhost:8081",
                aa_cert=self.aa_cert,
                ea_cert=self.ea_cert,
                ec_own=self.ec_own,
                backend=self.backend,
            )

        self.assertIsInstance(at_own, OwnCertificate)
        self.assertEqual(at_own.issuer, self.aa_cert)
        self.assertIsNotNone(at_own.key_id)

    async def test_authorize_http_error(self) -> None:
        """
        Tests that authorize() raises AuthorizationError on HTTP error status.
        """
        mock_post = AsyncMock()
        mock_post.return_value.status_code = 500
        mock_post.return_value.text = "Internal Server Error"

        with patch("httpx.AsyncClient.post", mock_post):
            with self.assertRaises(AuthorizationError) as ctx:
                await authorize(
                    aa_url="http://localhost:8081",
                    aa_cert=self.aa_cert,
                    ea_cert=self.ea_cert,
                    ec_own=self.ec_own,
                    backend=self.backend,
                )
            self.assertEqual(ctx.exception.code, "http_error")

    async def test_authorize_rejected_by_aa(self) -> None:
        """
        Tests that authorize() raises AuthorizationError when AA returns non-ok code.
        """
        from flexstack.security.pki_client import authorization
        orig_ecies_encrypt = authorization.ecies_encrypt

        def mock_ecies_encrypt(plaintext, recipient_enc_key_tuple, recipient_cert_coer):
            res = orig_ecies_encrypt(plaintext, recipient_enc_key_tuple, recipient_cert_coer)
            mock_post.return_value.content = _build_mock_authorization_response(
                self.aa_own,
                self.backend,
                session_key_a=res[2],
                session_key_hid8=res[3],
                response_code="deniedpermissions",
            )
            return res

        mock_post = AsyncMock()
        mock_post.return_value.status_code = 200

        with patch("httpx.AsyncClient.post", mock_post), \
             patch("flexstack.security.pki_client.authorization.ecies_encrypt", side_effect=mock_ecies_encrypt):
            with self.assertRaises(AuthorizationError) as ctx:
                await authorize(
                    aa_url="http://localhost:8081",
                    aa_cert=self.aa_cert,
                    ea_cert=self.ea_cert,
                    ec_own=self.ec_own,
                    backend=self.backend,
                )
            self.assertEqual(ctx.exception.code, "deniedpermissions")


if __name__ == "__main__":
    unittest.main()
