import unittest
from unittest.mock import MagicMock, patch

from flexstack.security.verify_service import VerifyService
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

        mock_coder.decode_etsi_ts_103097_data_signed.return_value = {
            "toBeSigned": {"some": "data"},
            "content": ("signedData", {
                "signer": ("certificate", [{"cert": "data"}])
            }),
            "signature": {"rSig": ("x-only", b"r"), "sSig": b"s"}
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
        self.certificate_library.verify_sequence_of_certificates.assert_called_once()
        self.backend.verify_with_pk.assert_called_once()

    @patch('flexstack.security.verify_service.SECURITY_CODER')
    def test_verify_with_certificate_signer_inconsistent_chain(self, mock_coder):
        """Test verification fails with inconsistent certificate chain"""
        # Given
        mock_coder.decode_etsi_ts_103097_data_signed.return_value = {
            "toBeSigned": {"some": "data"},
            "content": ("signedData", {
                "signer": ("certificate", [{"cert": "data"}])
            }),
            "signature": {"rSig": ("x-only", b"r"), "sSig": b"s"}
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

        digest = b'\xaa\xbb\xcc\xdd\xee\xff\x00\x11'
        mock_coder.decode_etsi_ts_103097_data_signed.return_value = {
            "toBeSigned": {"some": "data"},
            "content": ("signedData", {
                "signer": ("digest", digest)
            }),
            "signature": {"rSig": ("x-only", b"r"), "sSig": b"s"}
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
        self.certificate_library.get_authorization_ticket_by_hashedid8.assert_called_once_with(
            digest)

    @patch('flexstack.security.verify_service.SECURITY_CODER')
    def test_verify_with_digest_signer_invalid_certificate(self, mock_coder):
        """Test verification fails when digest signer certificate not found"""
        # Given
        digest = b'\xaa\xbb\xcc\xdd\xee\xff\x00\x11'
        mock_coder.decode_etsi_ts_103097_data_signed.return_value = {
            "toBeSigned": {"some": "data"},
            "content": ("signedData", {
                "signer": ("digest", digest)
            }),
            "signature": {"rSig": ("x-only", b"r"), "sSig": b"s"}
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
        self.assertEqual(result.report, ReportVerify.INVALID_CERTIFICATE)
        self.assertEqual(result.certificate_id, b'')

    @patch('flexstack.security.verify_service.SECURITY_CODER')
    def test_verify_with_unknown_signer_type_raises_exception(self, mock_coder):
        """Test verification raises exception with unknown signer type"""
        # Given
        mock_coder.decode_etsi_ts_103097_data_signed.return_value = {
            "toBeSigned": {"some": "data"},
            "content": ("signedData", {
                "signer": ("unknown_type", b"data")
            }),
            "signature": {"rSig": ("x-only", b"r"), "sSig": b"s"}
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
            "toBeSigned": {"some": "data"},
            "content": ("signedData", {
                "signer": ("certificate", [{"cert": "data"}])
            }),
            "signature": {"rSig": ("x-only", b"r"), "sSig": b"s"}
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
            "toBeSigned": {"some": "data"},
            "content": ("signedData", {
                "signer": ("certificate", [{"cert": "data"}])
            }),
            "signature": {"rSig": ("x-only", b"r"), "sSig": b"s"}
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
            "toBeSigned": {"some": "data"},
            "content": ("signedData", {
                "signer": ("certificate", [{"cert": "data"}])
            }),
            "signature": {"rSig": ("x-only", b"r"), "sSig": b"s"}
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


if __name__ == '__main__':
    unittest.main()
