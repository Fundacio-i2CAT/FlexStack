import unittest
from unittest.mock import MagicMock, patch

from flexstack.security.verify_service import VerifyService
from flexstack.security.sign_service import SignService
from flexstack.security.sn_sap import SNVERIFYRequest, ReportVerify
from flexstack.security.certificate import Certificate


class TestVerifyService(unittest.TestCase):
    def setUp(self):
        self.backend = MagicMock()
        self.certificate_library = MagicMock()
        self.verify_service = VerifyService(
            backend=self.backend,
            certificate_library=self.certificate_library,
        )

    def test_init(self):
        """Test that VerifyService initializes correctly"""
        self.assertIs(self.verify_service.backend, self.backend)
        self.assertIs(self.verify_service.certificate_library,
                      self.certificate_library)
        self.assertIsNone(self.verify_service.sign_service)

    @patch('flexstack.security.verify_service.SECURITY_CODER')
    def test_verify_with_certificate_signer_success(self, mock_coder):
        """Test successful verification with certificate signer"""
        # Given
        mock_certificate = MagicMock(spec=Certificate)
        mock_certificate.verify.return_value = True
        mock_certificate.as_hashedid8.return_value = b'\x12\x34\x56\x78\x9a\xbc\xde\xf0'
        mock_certificate.certificate = {
            "toBeSigned": {
                "verifyKeyIndicator": ("verificationKey", ("ecdsaNistP256", {"x": b"x", "y": b"y"}))
            }
        }

        inner_payload = b"cam_payload_bytes"
        mock_coder.decode_etsi_ts_103097_data_signed.return_value = {
            "protocolVersion": 3,
            "content": ("signedData", {
                "hashId": "sha256",
                "tbsData": {
                    "payload": {
                        "data": {
                            "protocolVersion": 3,
                            "content": ("unsecuredData", inner_payload)
                        }
                    },
                    "headerInfo": {
                        "psid": 36,
                        "generationTime": 123456789000,
                    },
                },
                "signer": ("certificate", [{"cert": "data"}]),
                "signature": {"rSig": ("x-only", b"r"), "sSig": b"s"}
            })
        }
        mock_coder.encode_to_be_signed_data.return_value = b"encoded_tbs_data"

        self.certificate_library.verify_sequence_of_certificates.return_value = mock_certificate
        self.backend.verify_with_pk.return_value = True

        request = SNVERIFYRequest(
            sec_header_length=10,
            sec_header=b"header",
            message_length=20,
            message=b"signed_message"
        )

        # When
        result = self.verify_service.verify(request)

        # Then
        self.assertEqual(result.report, ReportVerify.SUCCESS)
        self.assertEqual(result.certificate_id,
                         b'\x12\x34\x56\x78\x9a\xbc\xde\xf0')
        self.assertEqual(result.plain_message, inner_payload)
        self.assertEqual(result.its_aid, (36).to_bytes(1, 'big'))
        self.assertEqual(result.its_aid_length, 1)
        self.certificate_library.verify_sequence_of_certificates.assert_called_once()
        self.backend.verify_with_pk.assert_called_once()

    @patch('flexstack.security.verify_service.SECURITY_CODER')
    def test_verify_with_certificate_signer_inconsistent_chain(self, mock_coder):
        """Test verification fails with inconsistent certificate chain"""
        # Given
        mock_coder.decode_etsi_ts_103097_data_signed.return_value = {
            "protocolVersion": 3,
            "content": ("signedData", {
                "hashId": "sha256",
                "tbsData": {"some": "data"},
                "signer": ("certificate", [{"cert": "data"}]),
                "signature": {"rSig": ("x-only", b"r"), "sSig": b"s"}
            })
        }
        mock_coder.encode_to_be_signed_data.return_value = b"encoded_tbs_data"

        self.certificate_library.verify_sequence_of_certificates.return_value = None

        request = SNVERIFYRequest(
            sec_header_length=10,
            sec_header=b"header",
            message_length=20,
            message=b"signed_message"
        )

        # When
        result = self.verify_service.verify(request)

        # Then
        self.assertEqual(result.report, ReportVerify.INCONSISTENT_CHAIN)
        self.assertEqual(result.certificate_id, b'')

    @patch('flexstack.security.verify_service.SECURITY_CODER')
    def test_verify_with_digest_signer_success(self, mock_coder):
        """Test successful verification with digest signer"""
        # Given
        mock_certificate = MagicMock(spec=Certificate)
        mock_certificate.verify.return_value = True
        mock_certificate.as_hashedid8.return_value = b'\x12\x34\x56\x78\x9a\xbc\xde\xf0'
        mock_certificate.certificate = {
            "toBeSigned": {
                "verifyKeyIndicator": ("verificationKey", ("ecdsaNistP256", {"x": b"x", "y": b"y"}))
            }
        }

        inner_payload = b"cam_digest_payload"
        digest = b'\xaa\xbb\xcc\xdd\xee\xff\x00\x11'
        mock_coder.decode_etsi_ts_103097_data_signed.return_value = {
            "protocolVersion": 3,
            "content": ("signedData", {
                "hashId": "sha256",
                "tbsData": {
                    "payload": {
                        "data": {
                            "protocolVersion": 3,
                            "content": ("unsecuredData", inner_payload)
                        }
                    },
                    "headerInfo": {
                        "psid": 36,
                        "generationTime": 123456789000,
                    },
                },
                "signer": ("digest", digest),
                "signature": {"rSig": ("x-only", b"r"), "sSig": b"s"}
            })
        }
        mock_coder.encode_to_be_signed_data.return_value = b"encoded_tbs_data"

        self.certificate_library.get_authorization_ticket_by_hashedid8.return_value = mock_certificate
        self.backend.verify_with_pk.return_value = True

        request = SNVERIFYRequest(
            sec_header_length=10,
            sec_header=b"header",
            message_length=20,
            message=b"signed_message"
        )

        # When
        result = self.verify_service.verify(request)

        # Then
        self.assertEqual(result.report, ReportVerify.SUCCESS)
        self.assertEqual(result.certificate_id,
                         b'\x12\x34\x56\x78\x9a\xbc\xde\xf0')
        self.assertEqual(result.plain_message, inner_payload)
        self.certificate_library.get_authorization_ticket_by_hashedid8.assert_called_once_with(
            digest)

    @patch('flexstack.security.verify_service.SECURITY_CODER')
    def test_verify_with_digest_signer_invalid_certificate(self, mock_coder):
        """Test verification fails when digest signer certificate not found"""
        # Given
        digest = b'\xaa\xbb\xcc\xdd\xee\xff\x00\x11'
        mock_coder.decode_etsi_ts_103097_data_signed.return_value = {
            "protocolVersion": 3,
            "content": ("signedData", {
                "hashId": "sha256",
                "tbsData": {"some": "data"},
                "signer": ("digest", digest),
                "signature": {"rSig": ("x-only", b"r"), "sSig": b"s"}
            })
        }
        mock_coder.encode_to_be_signed_data.return_value = b"encoded_tbs_data"

        self.certificate_library.get_authorization_ticket_by_hashedid8.return_value = None

        request = SNVERIFYRequest(
            sec_header_length=10,
            sec_header=b"header",
            message_length=20,
            message=b"signed_message"
        )

        # When
        result = self.verify_service.verify(request)

        # Then
        self.assertEqual(result.report, ReportVerify.SIGNER_CERTIFICATE_NOT_FOUND)
        self.assertEqual(result.certificate_id, b'')

    @patch('flexstack.security.verify_service.SECURITY_CODER')
    def test_verify_with_unknown_signer_type_raises_exception(self, mock_coder):
        """Test verification raises exception with unknown signer type"""
        # Given
        mock_coder.decode_etsi_ts_103097_data_signed.return_value = {
            "protocolVersion": 3,
            "content": ("signedData", {
                "hashId": "sha256",
                "tbsData": {"some": "data"},
                "signer": ("unknown_type", b"data"),
                "signature": {"rSig": ("x-only", b"r"), "sSig": b"s"}
            })
        }
        mock_coder.encode_to_be_signed_data.return_value = b"encoded_tbs_data"

        request = SNVERIFYRequest(
            sec_header_length=10,
            sec_header=b"header",
            message_length=20,
            message=b"signed_message"
        )

        # When/Then
        with self.assertRaises(Exception) as context:
            self.verify_service.verify(request)
        self.assertEqual(str(context.exception), "Unknown signer type")

    @patch('flexstack.security.verify_service.SECURITY_CODER')
    def test_verify_with_false_signature(self, mock_coder):
        """Test verification returns FALSE_SIGNATURE when signature verification fails"""
        # Given
        mock_certificate = MagicMock(spec=Certificate)
        mock_certificate.verify.return_value = True
        mock_certificate.as_hashedid8.return_value = b'\x12\x34\x56\x78\x9a\xbc\xde\xf0'
        mock_certificate.certificate = {
            "toBeSigned": {
                "verifyKeyIndicator": ("verificationKey", ("ecdsaNistP256", {"x": b"x", "y": b"y"}))
            }
        }

        mock_coder.decode_etsi_ts_103097_data_signed.return_value = {
            "protocolVersion": 3,
            "content": ("signedData", {
                "hashId": "sha256",
                "tbsData": {
                    "headerInfo": {
                        "psid": 36,
                        "generationTime": 123456789000,
                    },
                },
                "signer": ("certificate", [{"cert": "data"}]),
                "signature": {"rSig": ("x-only", b"r"), "sSig": b"s"}
            })
        }
        mock_coder.encode_to_be_signed_data.return_value = b"encoded_tbs_data"

        self.certificate_library.verify_sequence_of_certificates.return_value = mock_certificate
        self.backend.verify_with_pk.return_value = False  # Signature verification fails

        request = SNVERIFYRequest(
            sec_header_length=10,
            sec_header=b"header",
            message_length=20,
            message=b"signed_message"
        )

        # When
        result = self.verify_service.verify(request)

        # Then
        self.assertEqual(result.report, ReportVerify.FALSE_SIGNATURE)
        self.assertEqual(result.certificate_id,
                         b'\x12\x34\x56\x78\x9a\xbc\xde\xf0')

    @patch('flexstack.security.verify_service.SECURITY_CODER')
    def test_verify_with_invalid_certificate_verification(self, mock_coder):
        """Test verification returns INVALID_CERTIFICATE when certificate verification fails"""
        # Given
        mock_certificate = MagicMock(spec=Certificate)
        mock_certificate.verify.return_value = False  # Certificate verification fails
        mock_certificate.certificate = {
            "toBeSigned": {
                "verifyKeyIndicator": ("verificationKey", ("ecdsaNistP256", {"x": b"x", "y": b"y"}))
            }
        }

        mock_coder.decode_etsi_ts_103097_data_signed.return_value = {
            "protocolVersion": 3,
            "content": ("signedData", {
                "hashId": "sha256",
                "tbsData": {"some": "data"},
                "signer": ("certificate", [{"cert": "data"}]),
                "signature": {"rSig": ("x-only", b"r"), "sSig": b"s"}
            })
        }
        mock_coder.encode_to_be_signed_data.return_value = b"encoded_tbs_data"

        self.certificate_library.verify_sequence_of_certificates.return_value = mock_certificate

        request = SNVERIFYRequest(
            sec_header_length=10,
            sec_header=b"header",
            message_length=20,
            message=b"signed_message"
        )

        # When
        result = self.verify_service.verify(request)

        # Then
        self.assertEqual(result.report, ReportVerify.INVALID_CERTIFICATE)

    @patch('flexstack.security.verify_service.SECURITY_CODER')
    def test_verify_with_non_verification_key_indicator(self, mock_coder):
        """Test verification returns INVALID_CERTIFICATE when verifyKeyIndicator is not verificationKey"""
        # Given
        mock_certificate = MagicMock(spec=Certificate)
        mock_certificate.verify.return_value = True
        mock_certificate.certificate = {
            "toBeSigned": {
                # Not verificationKey
                "verifyKeyIndicator": ("reconstructionValue", {"some": "data"})
            }
        }

        mock_coder.decode_etsi_ts_103097_data_signed.return_value = {
            "protocolVersion": 3,
            "content": ("signedData", {
                "hashId": "sha256",
                "tbsData": {"some": "data"},
                "signer": ("certificate", [{"cert": "data"}]),
                "signature": {"rSig": ("x-only", b"r"), "sSig": b"s"}
            })
        }
        mock_coder.encode_to_be_signed_data.return_value = b"encoded_tbs_data"

        self.certificate_library.verify_sequence_of_certificates.return_value = mock_certificate

        request = SNVERIFYRequest(
            sec_header_length=10,
            sec_header=b"header",
            message_length=20,
            message=b"signed_message"
        )

        # When
        result = self.verify_service.verify(request)

        # Then
        self.assertEqual(result.report, ReportVerify.INVALID_CERTIFICATE)

    @patch('flexstack.security.verify_service.SECURITY_CODER')
    def test_verify_missing_generation_time_returns_invalid_timestamp(self, mock_coder):
        """Test §5.2: generationTime MUST be present; absent → INVALID_TIMESTAMP"""
        # Given
        mock_certificate = MagicMock(spec=Certificate)
        mock_certificate.verify.return_value = True
        mock_certificate.as_hashedid8.return_value = b'\x12\x34\x56\x78\x9a\xbc\xde\xf0'
        mock_certificate.certificate = {
            "toBeSigned": {
                "verifyKeyIndicator": ("verificationKey", ("ecdsaNistP256", {"x": b"x", "y": b"y"}))
            }
        }

        mock_coder.decode_etsi_ts_103097_data_signed.return_value = {
            "protocolVersion": 3,
            "content": ("signedData", {
                "hashId": "sha256",
                "tbsData": {
                    "payload": {"data": {"protocolVersion": 3, "content": ("unsecuredData", b"payload")}},
                    "headerInfo": {
                        "psid": 36,
                        # generationTime intentionally absent
                    },
                },
                "signer": ("certificate", [{"cert": "data"}]),
                "signature": {"rSig": ("x-only", b"r"), "sSig": b"s"}
            })
        }
        mock_coder.encode_to_be_signed_data.return_value = b"encoded_tbs_data"

        self.certificate_library.verify_sequence_of_certificates.return_value = mock_certificate

        request = SNVERIFYRequest(
            sec_header_length=10,
            sec_header=b"header",
            message_length=20,
            message=b"signed_message"
        )

        # When
        result = self.verify_service.verify(request)

        # Then
        self.assertEqual(result.report, ReportVerify.INVALID_TIMESTAMP)
        self.backend.verify_with_pk.assert_not_called()

    @patch('flexstack.security.verify_service.SECURITY_CODER')
    def test_verify_forbidden_fields_present_returns_incompatible_protocol(self, mock_coder):
        """Test §5.2: p2pcdLearningRequest and missingCrlIdentifier SHALL be absent"""
        # Given
        mock_certificate = MagicMock(spec=Certificate)
        mock_certificate.verify.return_value = True
        mock_certificate.as_hashedid8.return_value = b'\x12\x34\x56\x78\x9a\xbc\xde\xf0'
        mock_certificate.certificate = {
            "toBeSigned": {
                "verifyKeyIndicator": ("verificationKey", ("ecdsaNistP256", {"x": b"x", "y": b"y"}))
            }
        }

        mock_coder.decode_etsi_ts_103097_data_signed.return_value = {
            "protocolVersion": 3,
            "content": ("signedData", {
                "hashId": "sha256",
                "tbsData": {
                    "payload": {"data": {"protocolVersion": 3, "content": ("unsecuredData", b"payload")}},
                    "headerInfo": {
                        "psid": 36,
                        "generationTime": 123456789000,
                        "p2pcdLearningRequest": b'\x00\x00\x00\x00\x00\x00\x00\x00',
                    },
                },
                "signer": ("certificate", [{"cert": "data"}]),
                "signature": {"rSig": ("x-only", b"r"), "sSig": b"s"}
            })
        }
        mock_coder.encode_to_be_signed_data.return_value = b"encoded_tbs_data"

        self.certificate_library.verify_sequence_of_certificates.return_value = mock_certificate

        request = SNVERIFYRequest(
            sec_header_length=10,
            sec_header=b"header",
            message_length=20,
            message=b"signed_message"
        )

        # When
        result = self.verify_service.verify(request)

        # Then
        self.assertEqual(result.report, ReportVerify.INCOMPATIBLE_PROTOCOL)
        self.backend.verify_with_pk.assert_not_called()

    @patch('flexstack.security.verify_service.SECURITY_CODER')
    def test_verify_with_multiple_certificates_in_signer(self, mock_coder):
        """Test §5.2: signer.certificate SHALL contain exactly one entry; >1 → UNSUPPORTED_SIGNER_IDENTIFIER_TYPE"""
        # Given
        mock_coder.decode_etsi_ts_103097_data_signed.return_value = {
            "protocolVersion": 3,
            "content": ("signedData", {
                "hashId": "sha256",
                "tbsData": {
                    "payload": {"data": {"protocolVersion": 3, "content": ("unsecuredData", b"payload")}},
                    "headerInfo": {"psid": 36, "generationTime": 123456789000},
                },
                "signer": ("certificate", [{"cert": "data1"}, {"cert": "data2"}]),
                "signature": {"rSig": ("x-only", b"r"), "sSig": b"s"}
            })
        }
        mock_coder.encode_to_be_signed_data.return_value = b"encoded_tbs_data"

        request = SNVERIFYRequest(
            sec_header_length=10, sec_header=b"header",
            message_length=20, message=b"signed_message"
        )

        # When
        result = self.verify_service.verify(request)

        # Then
        self.assertEqual(result.report, ReportVerify.UNSUPPORTED_SIGNER_IDENTIFIER_TYPE)
        self.backend.verify_with_pk.assert_not_called()

    @patch('flexstack.security.verify_service.SECURITY_CODER')
    def test_verify_unknown_digest_notifies_sign_service(self, mock_coder):
        """§7.1.1: unknown AT digest triggers sign_service.notify_unknown_at"""
        sign_service = MagicMock(spec=SignService)
        vs = VerifyService(
            backend=self.backend,
            certificate_library=self.certificate_library,
            sign_service=sign_service,
        )
        digest = b'\xaa\xbb\xcc\xdd\xee\xff\x00\x11'
        mock_coder.decode_etsi_ts_103097_data_signed.return_value = {
            "protocolVersion": 3,
            "content": ("signedData", {
                "hashId": "sha256",
                "tbsData": {"some": "data"},
                "signer": ("digest", digest),
                "signature": {}
            })
        }
        mock_coder.encode_to_be_signed_data.return_value = b"encoded_tbs_data"
        self.certificate_library.get_authorization_ticket_by_hashedid8.return_value = None

        result = vs.verify(SNVERIFYRequest(
            sec_header_length=0, sec_header=b"",
            message_length=0, message=b""
        ))

        self.assertEqual(result.report, ReportVerify.SIGNER_CERTIFICATE_NOT_FOUND)
        sign_service.notify_unknown_at.assert_called_once_with(digest)

    @patch('flexstack.security.verify_service.SECURITY_CODER')
    def test_verify_inconsistent_chain_notifies_sign_service(self, mock_coder):
        """§7.1.1: inconsistent chain triggers sign_service.notify_unknown_at for the AA issuer"""
        sign_service = MagicMock(spec=SignService)
        vs = VerifyService(
            backend=self.backend,
            certificate_library=self.certificate_library,
            sign_service=sign_service,
        )
        aa_hashedid8 = b'\x11\x12\x13\x14\x15\x16\x17\x18'
        mock_coder.decode_etsi_ts_103097_data_signed.return_value = {
            "protocolVersion": 3,
            "content": ("signedData", {
                "hashId": "sha256",
                "tbsData": {"some": "data"},
                "signer": ("certificate", [
                    {"issuer": ("sha256AndDigest", aa_hashedid8)}
                ]),
                "signature": {}
            })
        }
        mock_coder.encode_to_be_signed_data.return_value = b"encoded_tbs_data"
        self.certificate_library.verify_sequence_of_certificates.return_value = None

        result = vs.verify(SNVERIFYRequest(
            sec_header_length=0, sec_header=b"",
            message_length=0, message=b""
        ))

        self.assertEqual(result.report, ReportVerify.INCONSISTENT_CHAIN)
        sign_service.notify_unknown_at.assert_called_once_with(aa_hashedid8)

    @patch('flexstack.security.verify_service.SECURITY_CODER')
    def test_verify_success_processes_inline_p2pcd_request(self, mock_coder):
        """§7.1.1: on success, inlineP2pcdRequest in headerInfo is forwarded to sign_service"""
        sign_service = MagicMock(spec=SignService)
        vs = VerifyService(
            backend=self.backend,
            certificate_library=self.certificate_library,
            sign_service=sign_service,
        )
        mock_certificate = MagicMock(spec=Certificate)
        mock_certificate.verify.return_value = True
        mock_certificate.as_hashedid8.return_value = b'\x12\x34\x56\x78\x9a\xbc\xde\xf0'
        mock_certificate.certificate = {
            "toBeSigned": {
                "verifyKeyIndicator": ("verificationKey", ("ecdsaNistP256", {"x": b"x", "y": b"y"}))
            }
        }
        p2pcd_list = [b'\xaa\xbb\xcc']
        mock_coder.decode_etsi_ts_103097_data_signed.return_value = {
            "protocolVersion": 3,
            "content": ("signedData", {
                "hashId": "sha256",
                "tbsData": {
                    "payload": {"data": {"protocolVersion": 3, "content": ("unsecuredData", b"payload")}},
                    "headerInfo": {
                        "psid": 36,
                        "generationTime": 123456789000,
                        "inlineP2pcdRequest": p2pcd_list,
                    },
                },
                "signer": ("certificate", [{"cert": "data"}]),
                "signature": {}
            })
        }
        mock_coder.encode_to_be_signed_data.return_value = b"encoded_tbs_data"
        self.certificate_library.verify_sequence_of_certificates.return_value = mock_certificate
        self.backend.verify_with_pk.return_value = True

        result = vs.verify(SNVERIFYRequest(
            sec_header_length=0, sec_header=b"",
            message_length=0, message=b""
        ))

        self.assertEqual(result.report, ReportVerify.SUCCESS)
        sign_service.notify_inline_p2pcd_request.assert_called_once_with(p2pcd_list)

    @patch('flexstack.security.verify_service.SECURITY_CODER')
    def test_verify_success_processes_requested_certificate(self, mock_coder):
        """§7.1.1: on success, requestedCertificate in headerInfo is forwarded to sign_service"""
        sign_service = MagicMock(spec=SignService)
        vs = VerifyService(
            backend=self.backend,
            certificate_library=self.certificate_library,
            sign_service=sign_service,
        )
        mock_certificate = MagicMock(spec=Certificate)
        mock_certificate.verify.return_value = True
        mock_certificate.as_hashedid8.return_value = b'\x12\x34\x56\x78\x9a\xbc\xde\xf0'
        mock_certificate.certificate = {
            "toBeSigned": {
                "verifyKeyIndicator": ("verificationKey", ("ecdsaNistP256", {"x": b"x", "y": b"y"}))
            }
        }
        requested_cert = {"version": 3, "toBeSigned": {"id": ("name", "aa")}}
        mock_coder.decode_etsi_ts_103097_data_signed.return_value = {
            "protocolVersion": 3,
            "content": ("signedData", {
                "hashId": "sha256",
                "tbsData": {
                    "payload": {"data": {"protocolVersion": 3, "content": ("unsecuredData", b"payload")}},
                    "headerInfo": {
                        "psid": 36,
                        "generationTime": 123456789000,
                        "requestedCertificate": requested_cert,
                    },
                },
                "signer": ("certificate", [{"cert": "data"}]),
                "signature": {}
            })
        }
        mock_coder.encode_to_be_signed_data.return_value = b"encoded_tbs_data"
        self.certificate_library.verify_sequence_of_certificates.return_value = mock_certificate
        self.backend.verify_with_pk.return_value = True

        result = vs.verify(SNVERIFYRequest(
            sec_header_length=0, sec_header=b"",
            message_length=0, message=b""
        ))

        self.assertEqual(result.report, ReportVerify.SUCCESS)
        sign_service.notify_received_ca_certificate.assert_called_once_with(requested_cert)

    @patch('flexstack.security.verify_service.SECURITY_CODER')
    def test_verify_denm_with_digest_signer_returns_unsupported(self, mock_coder):
        """§7.1.2: DENM (psid=37) signed with digest signer → UNSUPPORTED_SIGNER_IDENTIFIER_TYPE."""
        mock_coder.decode_etsi_ts_103097_data_signed.return_value = {
            "protocolVersion": 3,
            "content": ("signedData", {
                "hashId": "sha256",
                "tbsData": {
                    "headerInfo": {"psid": 37, "generationTime": 123456789000},
                    "payload": {},
                },
                "signer": ("digest", b'\xaa\xbb\xcc\xdd\xee\xff\x00\x11'),
                "signature": {}
            })
        }
        mock_coder.encode_to_be_signed_data.return_value = b"tbs"

        result = self.verify_service.verify(SNVERIFYRequest(
            sec_header_length=0, sec_header=b"",
            message_length=0, message=b""
        ))

        self.assertEqual(result.report, ReportVerify.UNSUPPORTED_SIGNER_IDENTIFIER_TYPE)
        self.backend.verify_with_pk.assert_not_called()

    @patch('flexstack.security.verify_service.SECURITY_CODER')
    def test_verify_denm_missing_generation_location_returns_incompatible_protocol(self, mock_coder):
        """§7.1.2: DENM without generationLocation → INCOMPATIBLE_PROTOCOL."""
        mock_certificate = MagicMock(spec=Certificate)
        mock_certificate.verify.return_value = True
        mock_certificate.as_hashedid8.return_value = b'\x12\x34\x56\x78\x9a\xbc\xde\xf0'
        mock_certificate.certificate = {
            "toBeSigned": {
                "verifyKeyIndicator": ("verificationKey", ("ecdsaNistP256", {}))
            }
        }
        mock_coder.decode_etsi_ts_103097_data_signed.return_value = {
            "protocolVersion": 3,
            "content": ("signedData", {
                "hashId": "sha256",
                "tbsData": {
                    "payload": {"data": {"protocolVersion": 3, "content": ("unsecuredData", b"d")}},
                    "headerInfo": {
                        "psid": 37,
                        "generationTime": 123456789000,
                        # generationLocation intentionally absent
                    },
                },
                "signer": ("certificate", [{"cert": "data"}]),
                "signature": {}
            })
        }
        mock_coder.encode_to_be_signed_data.return_value = b"tbs"
        self.certificate_library.verify_sequence_of_certificates.return_value = mock_certificate

        result = self.verify_service.verify(SNVERIFYRequest(
            sec_header_length=0, sec_header=b"",
            message_length=0, message=b""
        ))

        self.assertEqual(result.report, ReportVerify.INCOMPATIBLE_PROTOCOL)
        self.backend.verify_with_pk.assert_not_called()

    @patch('flexstack.security.verify_service.SECURITY_CODER')
    def test_verify_denm_with_forbidden_field_returns_incompatible_protocol(self, mock_coder):
        """§7.1.2: DENM with inlineP2pcdRequest present → INCOMPATIBLE_PROTOCOL."""
        mock_certificate = MagicMock(spec=Certificate)
        mock_certificate.verify.return_value = True
        mock_certificate.as_hashedid8.return_value = b'\x12\x34\x56\x78\x9a\xbc\xde\xf0'
        mock_certificate.certificate = {
            "toBeSigned": {
                "verifyKeyIndicator": ("verificationKey", ("ecdsaNistP256", {}))
            }
        }
        mock_coder.decode_etsi_ts_103097_data_signed.return_value = {
            "protocolVersion": 3,
            "content": ("signedData", {
                "hashId": "sha256",
                "tbsData": {
                    "payload": {"data": {"protocolVersion": 3, "content": ("unsecuredData", b"d")}},
                    "headerInfo": {
                        "psid": 37,
                        "generationTime": 123456789000,
                        "generationLocation": {"latitude": 0, "longitude": 0, "elevation": 0xF000},
                        "inlineP2pcdRequest": [b'\xaa\xbb\xcc'],  # forbidden in DENM
                    },
                },
                "signer": ("certificate", [{"cert": "data"}]),
                "signature": {}
            })
        }
        mock_coder.encode_to_be_signed_data.return_value = b"tbs"
        self.certificate_library.verify_sequence_of_certificates.return_value = mock_certificate

        result = self.verify_service.verify(SNVERIFYRequest(
            sec_header_length=0, sec_header=b"",
            message_length=0, message=b""
        ))

        self.assertEqual(result.report, ReportVerify.INCOMPATIBLE_PROTOCOL)
        self.backend.verify_with_pk.assert_not_called()

    @patch('flexstack.security.verify_service.SECURITY_CODER')
    def test_verify_denm_valid_succeeds(self, mock_coder):
        """§7.1.2: valid DENM with certificate signer and generationLocation → SUCCESS."""
        mock_certificate = MagicMock(spec=Certificate)
        mock_certificate.verify.return_value = True
        mock_certificate.as_hashedid8.return_value = b'\x12\x34\x56\x78\x9a\xbc\xde\xf0'
        mock_certificate.certificate = {
            "toBeSigned": {
                "verifyKeyIndicator": ("verificationKey", ("ecdsaNistP256", {"x": b"x", "y": b"y"}))
            }
        }
        payload = b"denm_payload"
        mock_coder.decode_etsi_ts_103097_data_signed.return_value = {
            "protocolVersion": 3,
            "content": ("signedData", {
                "hashId": "sha256",
                "tbsData": {
                    "payload": {"data": {"protocolVersion": 3, "content": ("unsecuredData", payload)}},
                    "headerInfo": {
                        "psid": 37,
                        "generationTime": 123456789000,
                        "generationLocation": {"latitude": 473400000, "longitude": 85500000, "elevation": 0xF000},
                    },
                },
                "signer": ("certificate", [{"cert": "data"}]),
                "signature": {}
            })
        }
        mock_coder.encode_to_be_signed_data.return_value = b"tbs"
        self.certificate_library.verify_sequence_of_certificates.return_value = mock_certificate
        self.backend.verify_with_pk.return_value = True

        result = self.verify_service.verify(SNVERIFYRequest(
            sec_header_length=0, sec_header=b"",
            message_length=0, message=b""
        ))

        self.assertEqual(result.report, ReportVerify.SUCCESS)
        self.assertEqual(result.plain_message, payload)

    @patch('flexstack.security.verify_service.SECURITY_CODER')
    def test_verify_non_at_profile_returns_invalid_certificate(self, mock_coder):
        """§7.2.1: cert that fails the AT profile check → INVALID_CERTIFICATE."""
        mock_certificate = MagicMock(spec=Certificate)
        mock_certificate.verify.return_value = True
        mock_certificate.is_authorization_ticket.return_value = False
        mock_certificate.as_hashedid8.return_value = b'\x12\x34\x56\x78\x9a\xbc\xde\xf0'
        mock_certificate.certificate = {
            "toBeSigned": {
                "verifyKeyIndicator": ("verificationKey", ("ecdsaNistP256", {"x": b"x", "y": b"y"}))
            }
        }
        mock_coder.decode_etsi_ts_103097_data_signed.return_value = {
            "protocolVersion": 3,
            "content": ("signedData", {
                "hashId": "sha256",
                "tbsData": {
                    "payload": {"data": {"protocolVersion": 3, "content": ("unsecuredData", b"data")}},
                    "headerInfo": {"psid": 36, "generationTime": 123456789000},
                },
                "signer": ("digest", b'\x12\x34\x56\x78\x9a\xbc\xde\xf0'),
                "signature": {}
            })
        }
        mock_coder.encode_to_be_signed_data.return_value = b"tbs"
        self.certificate_library.get_authorization_ticket_by_hashedid8.return_value = mock_certificate

        result = self.verify_service.verify(SNVERIFYRequest(
            sec_header_length=0, sec_header=b"",
            message_length=0, message=b""
        ))

        self.assertEqual(result.report, ReportVerify.INVALID_CERTIFICATE)


if __name__ == '__main__':
    unittest.main()
