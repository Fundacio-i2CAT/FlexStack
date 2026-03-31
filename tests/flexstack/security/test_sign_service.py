import unittest
from unittest.mock import Mock, MagicMock, patch
from flexstack.security.sn_sap import SNSIGNRequest, SNSIGNConfirm
from flexstack.security.certificate import OwnCertificate
from flexstack.security.certificate_library import CertificateLibrary
from flexstack.security.ecdsa_backend import ECDSABackend
from flexstack.utils.time_service import TimeService
from flexstack.security.sign_service import (
    CooperativeAwarenessMessageSecurityHandler,
    SignService,
)


class TestCooperativeAwarenessMessageSecurityHandler(unittest.TestCase):

    def setUp(self):
        self.ecdsa_backend = Mock(spec=ECDSABackend)
        self.certificate = Mock(spec=OwnCertificate)
        self.handler = CooperativeAwarenessMessageSecurityHandler(
            self.ecdsa_backend
        )

    @patch('flexstack.security.sign_service.SECURITY_CODER')
    def test_sign(self, mock_coder):
        signed_data = {
            "content": [
                None,
                {"tbsData": "test_data", "signer": [None, None], "signature": None},
            ]
        }
        mock_coder.encode_to_be_signed_data.return_value = b"encoded_tbsData"
        self.certificate.as_hashedid8.return_value = b"hashedid8"
        self.certificate.sign_message.return_value = b"signed_message"

        self.handler.sign(signed_data, self.certificate)

        mock_coder.encode_to_be_signed_data.assert_called_once_with("test_data")
        self.certificate.as_hashedid8.assert_called_once()
        self.certificate.sign_message.assert_called_once_with(self.ecdsa_backend, b"encoded_tbsData")
        self.assertEqual(signed_data["content"][1]["signer"][1], b"hashedid8")
        self.assertEqual(signed_data["content"][1]["signature"], b"signed_message")

    def test_set_up_signer(self):
        self.certificate.as_hashedid8.return_value = b"hashedid8"
        self.certificate.encode.return_value = b"encoded_certificate"
        TimeService.time = MagicMock(return_value=100)

        signer = self.handler.set_up_signer(self.certificate)
        self.assertEqual(signer, ("certificate", b"encoded_certificate"))

        TimeService.time = MagicMock(return_value=101)
        self.handler.last_signer_full_certificate_time = 100

        signer = self.handler.set_up_signer(self.certificate)
        self.assertEqual(signer, ("digest", b"hashedid8"))

        self.handler.requested_own_certificate = True

        signer = self.handler.set_up_signer(self.certificate)
        self.assertEqual(signer, ("certificate", b"encoded_certificate"))


class TestSignService(unittest.TestCase):

    def setUp(self):
        self.backend = Mock(spec=ECDSABackend)
        self.certificate_library = MagicMock(spec=CertificateLibrary)
        self.certificate_library.own_certificates = {}
        self.sign_service = SignService(self.backend, self.certificate_library)

    def test_init(self):
        """Test that SignService initialises correctly with backend and certificate library."""
        self.assertIs(self.sign_service.ecdsa_backend, self.backend)
        self.assertIs(self.sign_service.certificate_library, self.certificate_library)
        self.assertEqual(self.sign_service.unknown_ats, [])
        self.assertEqual(self.sign_service.requested_ats, [])

    def test_sign_request_not_implemented(self):
        """Test that sign_request raises NotImplementedError for all defined ITS-AIDs."""
        for aid in [36, 37, 137, 138, 139, 141, 540, 801, 639, 638]:
            request = Mock(spec=SNSIGNRequest)
            request.its_aid = aid
            with self.assertRaises(NotImplementedError):
                self.sign_service.sign_request(request)

    @patch('flexstack.security.sign_service.SECURITY_CODER')
    def test_sign_cam(self, mock_coder):
        """Test that sign_cam returns a correct SNSIGNConfirm."""
        request = Mock(spec=SNSIGNRequest)
        request.its_aid = 999
        request.tbs_message = b"test_message"
        mock_coder.encode_to_be_signed_data.return_value = b"encoded_tbsData"
        present_at = Mock(spec=OwnCertificate)
        present_at.as_hashedid8.return_value = b"hashedid8"
        present_at.sign_message.return_value = b"signed_message"
        self.sign_service.get_present_at_for_signging = MagicMock(
            return_value=present_at
        )
        mock_coder.encode_etsi_ts_103097_data_signed.return_value = (
            b"encoded_signed_data"
        )

        confirm = self.sign_service.sign_cam(request)

        self.assertIsInstance(confirm, SNSIGNConfirm)
        self.assertEqual(confirm.sec_message, b"encoded_signed_data")
        self.assertEqual(confirm.sec_message_length, len(b"encoded_signed_data"))

    def test_get_present_at_for_signging(self):
        """Test that get_present_at_for_signging returns the correct AT from the library."""
        mock_cert = Mock(spec=OwnCertificate)
        mock_cert.get_list_of_its_aid.return_value = [999]
        self.certificate_library.own_certificates = {b"hashid8": mock_cert}

        cert = self.sign_service.get_present_at_for_signging(999)

        self.assertIsNotNone(cert)
        self.assertEqual(cert, mock_cert)

    def test_get_present_at_for_signging_not_found(self):
        """Test that get_present_at_for_signging returns None when no matching AT exists."""
        mock_cert = Mock(spec=OwnCertificate)
        mock_cert.get_list_of_its_aid.return_value = [36]
        self.certificate_library.own_certificates = {b"hashid8": mock_cert}

        cert = self.sign_service.get_present_at_for_signging(999)

        self.assertIsNone(cert)

    def test_add_own_certificate(self):
        """Test that add_own_certificate delegates to the certificate library."""
        mock_cert = Mock(spec=OwnCertificate)

        self.sign_service.add_own_certificate(mock_cert)

        self.certificate_library.add_own_certificate.assert_called_once_with(mock_cert)

    def test_get_known_at_for_request_not_implemented(self):
        """Test that get_known_at_for_request raises NotImplementedError."""
        with self.assertRaises(NotImplementedError):
            self.sign_service.get_known_at_for_request(b"hashedid3")


if __name__ == "__main__":
    unittest.main()
