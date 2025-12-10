import unittest
from unittest.mock import Mock, MagicMock, patch
from flexstack.security.sn_sap import SNSIGNRequest, SNSIGNConfirm
from flexstack.security.certificate import OwnCertificate
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
        self.sign_service = SignService(self.backend)

    def test_sign_request_not_implemented(self):
        for aid in [36, 37, 137, 138, 139, 141, 540, 801, 639, 638]:
            request = Mock(spec=SNSIGNRequest)
            request.its_aid = aid
            with self.assertRaises(NotImplementedError):
                self.sign_service.sign_request(request)

    @patch('flexstack.security.sign_service.SECURITY_CODER')
    def test_sign_cam(self, mock_coder):
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
        self.sign_service.present_ats = {1: Mock(spec=OwnCertificate)}
        self.sign_service.present_ats[1].get_list_of_its_aid.return_value = [999]

        cert = self.sign_service.get_present_at_for_signging(999)

        self.assertIsNotNone(cert)
        self.assertEqual(cert, self.sign_service.present_ats[1])

    def test_get_known_at_for_request_not_implemented(self):
        with self.assertRaises(NotImplementedError):
            self.sign_service.get_known_at_for_request(b"hashedid3")


if __name__ == "__main__":
    unittest.main()
