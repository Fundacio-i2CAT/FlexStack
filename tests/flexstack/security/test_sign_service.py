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
        cert_dict = {"version": 3}
        self.certificate.certificate = cert_dict
        TimeService.time = MagicMock(return_value=100)

        signer = self.handler.set_up_signer(self.certificate)
        self.assertEqual(signer, ("certificate", [cert_dict]))

        TimeService.time = MagicMock(return_value=101)
        self.handler.last_signer_full_certificate_time = 100

        signer = self.handler.set_up_signer(self.certificate)
        self.assertEqual(signer, ("digest", b"hashedid8"))

        self.handler.requested_own_certificate = True

        signer = self.handler.set_up_signer(self.certificate)
        self.assertEqual(signer, ("certificate", [cert_dict]))
        self.assertFalse(self.handler.requested_own_certificate)


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
        """Only AID 36 (CAM/PKI) remains unimplemented via sign_request(); everything
        else is handled by sign_denm() (§7.1.2) or sign_other() (§7.1.3)."""
        request = Mock(spec=SNSIGNRequest)
        request.its_aid = 36
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
        present_at.certificate = {"version": 3}
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

    def test_get_known_at_for_request_not_found_raises(self):
        """Test that get_known_at_for_request raises RuntimeError when cert not found."""
        self.certificate_library.get_ca_certificate_by_hashedid3.return_value = None
        with self.assertRaises(RuntimeError):
            self.sign_service.get_known_at_for_request(b'\x12\x34\x56')

    def test_get_known_at_for_request_found(self):
        """Test that get_known_at_for_request returns the certificate dict."""
        mock_ca = MagicMock()
        mock_ca.certificate = {"version": 3}
        self.certificate_library.get_ca_certificate_by_hashedid3.return_value = mock_ca
        result = self.sign_service.get_known_at_for_request(b'\x12\x34\x56')
        self.assertEqual(result, {"version": 3})

    def test_notify_unknown_at_adds_hashedid3(self):
        """notify_unknown_at adds the last 3 bytes as HashedId3 to unknown_ats."""
        hashedid8 = b'\xaa\xbb\xcc\xdd\xee\xff\x00\x11'
        self.sign_service.notify_unknown_at(hashedid8)
        self.assertIn(b'\xff\x00\x11', self.sign_service.unknown_ats)

    def test_notify_unknown_at_sets_requested_flag(self):
        """notify_unknown_at sets requested_own_certificate on cam_handler."""
        hashedid8 = b'\xaa\xbb\xcc\xdd\xee\xff\x00\x11'
        self.sign_service.notify_unknown_at(hashedid8)
        self.assertTrue(self.sign_service.cam_handler.requested_own_certificate)

    def test_notify_unknown_at_no_duplicates(self):
        """notify_unknown_at does not add duplicate HashedId3 values."""
        hashedid8 = b'\xaa\xbb\xcc\xdd\xee\xff\x00\x11'
        self.sign_service.notify_unknown_at(hashedid8)
        self.sign_service.notify_unknown_at(hashedid8)
        self.assertEqual(len(self.sign_service.unknown_ats), 1)

    def test_notify_inline_p2pcd_request_own_cert_match(self):
        """notify_inline_p2pcd_request sets requested_own_certificate when own AT listed."""
        mock_cert = MagicMock(spec=OwnCertificate)
        mock_cert.as_hashedid8.return_value = b'\xaa\xbb\xcc\xdd\xee\xff\x00\x11'
        self.certificate_library.own_certificates = {
            b'\xaa\xbb\xcc\xdd\xee\xff\x00\x11': mock_cert
        }
        self.sign_service.notify_inline_p2pcd_request([b'\xff\x00\x11'])
        self.assertTrue(self.sign_service.cam_handler.requested_own_certificate)

    def test_notify_inline_p2pcd_request_ca_cert_match(self):
        """notify_inline_p2pcd_request appends hashedid3 to requested_ats when CA cert found."""
        self.certificate_library.own_certificates = {}
        mock_ca = MagicMock()
        self.certificate_library.get_ca_certificate_by_hashedid3.return_value = mock_ca
        self.sign_service.notify_inline_p2pcd_request([b'\x12\x34\x56'])
        self.assertIn(b'\x12\x34\x56', self.sign_service.requested_ats)

    def test_notify_inline_p2pcd_request_no_match(self):
        """notify_inline_p2pcd_request does nothing when no match found."""
        self.certificate_library.own_certificates = {}
        self.certificate_library.get_ca_certificate_by_hashedid3.return_value = None
        self.sign_service.notify_inline_p2pcd_request([b'\x12\x34\x56'])
        self.assertFalse(self.sign_service.cam_handler.requested_own_certificate)
        self.assertEqual(self.sign_service.requested_ats, [])

    @patch('flexstack.security.sign_service.Certificate')
    def test_notify_received_ca_certificate_removes_pending_requests(self, mock_cert_cls):
        """notify_received_ca_certificate removes cert from requested_ats, unknown_ats and adds to library."""
        mock_cert = MagicMock()
        mock_cert.as_hashedid8.return_value = b'\xaa\xbb\xcc\xdd\xee\xff\x00\x11'
        mock_cert_cls.from_dict.return_value = mock_cert
        self.sign_service.requested_ats = [b'\xff\x00\x11']
        self.sign_service.unknown_ats = [b'\xff\x00\x11']
        self.sign_service.notify_received_ca_certificate({"cert": "data"})
        self.assertEqual(self.sign_service.requested_ats, [])
        self.assertEqual(self.sign_service.unknown_ats, [])
        self.certificate_library.add_authorization_authority.assert_called_once_with(mock_cert)

    @patch('flexstack.security.sign_service.SECURITY_CODER')
    def test_sign_denm_returns_confirm(self, mock_coder):
        """sign_denm returns a valid SNSIGNConfirm when location is provided."""
        request = Mock(spec=SNSIGNRequest)
        request.its_aid = 37
        request.tbs_message = b"denm_bytes"
        request.generation_location = {
            "latitude": 473400000,
            "longitude": 85500000,
            "elevation": 0xF000,
        }
        mock_coder.encode_to_be_signed_data.return_value = b"encoded_tbsData"
        present_at = Mock(spec=OwnCertificate)
        present_at.as_hashedid8.return_value = b"hashedid8"
        present_at.sign_message.return_value = b"sig"
        present_at.certificate = {"version": 3}
        self.sign_service.get_present_at_for_signging = MagicMock(return_value=present_at)
        mock_coder.encode_etsi_ts_103097_data_signed.return_value = b"signed_denm"

        confirm = self.sign_service.sign_denm(request)

        self.assertIsInstance(confirm, SNSIGNConfirm)
        self.assertEqual(confirm.sec_message, b"signed_denm")

    @patch('flexstack.security.sign_service.SECURITY_CODER')
    def test_sign_denm_signer_is_always_certificate(self, mock_coder):
        """§7.1.2: sign_denm always uses 'certificate' signer, never 'digest'."""
        request = Mock(spec=SNSIGNRequest)
        request.its_aid = 37
        request.tbs_message = b"denm_bytes"
        request.generation_location = {"latitude": 0, "longitude": 0, "elevation": 0xF000}
        mock_coder.encode_to_be_signed_data.return_value = b"tbs"

        captured = {}

        def capture_signed(data):
            captured["signer"] = data["content"][1]["signer"]
            return b"out"

        mock_coder.encode_etsi_ts_103097_data_signed.side_effect = capture_signed
        present_at = Mock(spec=OwnCertificate)
        present_at.sign_message.return_value = b"sig"
        present_at.certificate = {"version": 3}
        self.sign_service.get_present_at_for_signging = MagicMock(return_value=present_at)

        self.sign_service.sign_denm(request)

        self.assertEqual(captured["signer"][0], "certificate")

    @patch('flexstack.security.sign_service.SECURITY_CODER')
    def test_sign_denm_includes_generation_location(self, mock_coder):
        """§7.1.2: sign_denm embeds generationLocation in headerInfo."""
        loc = {"latitude": 473400000, "longitude": 85500000, "elevation": 0xF000}
        request = Mock(spec=SNSIGNRequest)
        request.its_aid = 37
        request.tbs_message = b"denm_bytes"
        request.generation_location = loc
        mock_coder.encode_to_be_signed_data.return_value = b"tbs"

        captured = {}

        def capture_signed(data):
            captured["header_info"] = data["content"][1]["tbsData"]["headerInfo"]
            return b"out"

        mock_coder.encode_etsi_ts_103097_data_signed.side_effect = capture_signed
        present_at = Mock(spec=OwnCertificate)
        present_at.sign_message.return_value = b"sig"
        present_at.certificate = {"version": 3}
        self.sign_service.get_present_at_for_signging = MagicMock(return_value=present_at)

        self.sign_service.sign_denm(request)

        self.assertEqual(captured["header_info"]["generationLocation"], loc)

    def test_sign_denm_raises_without_generation_location(self):
        """sign_denm raises ValueError when generation_location is None."""
        request = Mock(spec=SNSIGNRequest)
        request.its_aid = 37
        request.tbs_message = b"denm_bytes"
        request.generation_location = None

        with self.assertRaises(ValueError):
            self.sign_service.sign_denm(request)

    @patch('flexstack.security.sign_service.SECURITY_CODER')
    def test_sign_denm_headerinfo_has_no_extra_fields(self, mock_coder):
        """§7.1.2: headerInfo must not contain inlineP2pcdRequest, expiryTime, etc."""
        loc = {"latitude": 0, "longitude": 0, "elevation": 0xF000}
        request = Mock(spec=SNSIGNRequest)
        request.its_aid = 37
        request.tbs_message = b"d"
        request.generation_location = loc
        mock_coder.encode_to_be_signed_data.return_value = b"tbs"

        captured = {}

        def capture_signed(data):
            captured["header_info"] = data["content"][1]["tbsData"]["headerInfo"]
            return b"out"

        mock_coder.encode_etsi_ts_103097_data_signed.side_effect = capture_signed
        present_at = Mock(spec=OwnCertificate)
        present_at.sign_message.return_value = b"sig"
        present_at.certificate = {"version": 3}
        self.sign_service.get_present_at_for_signging = MagicMock(return_value=present_at)

        self.sign_service.sign_denm(request)

        hi = captured["header_info"]
        for forbidden in ("expiryTime", "encryptionKey", "inlineP2pcdRequest", "requestedCertificate"):
            self.assertNotIn(forbidden, hi, f"{forbidden} must not appear in DENM headerInfo")

    def test_sign_request_delegates_denm_to_sign_denm(self):
        """sign_request(its_aid=37) delegates to sign_denm."""
        request = Mock(spec=SNSIGNRequest)
        request.its_aid = 37
        self.sign_service.sign_denm = MagicMock(return_value=Mock(spec=SNSIGNConfirm))

        result = self.sign_service.sign_request(request)

        self.sign_service.sign_denm.assert_called_once_with(request)
        self.assertIsNotNone(result)

    @patch('flexstack.security.sign_service.SECURITY_CODER')
    def test_sign_other_returns_confirm(self, mock_coder):
        """sign_other returns a valid SNSIGNConfirm for a generic ITS-AID."""
        request = Mock(spec=SNSIGNRequest)
        request.its_aid = 139
        request.tbs_message = b"ivim_bytes"
        mock_coder.encode_to_be_signed_data.return_value = b"tbs"
        mock_coder.encode_etsi_ts_103097_data_signed.return_value = b"signed_other"
        present_at = Mock(spec=OwnCertificate)
        present_at.as_hashedid8.return_value = b"hashedid8"
        present_at.sign_message.return_value = b"sig"
        self.sign_service.get_present_at_for_signging = MagicMock(return_value=present_at)

        confirm = self.sign_service.sign_other(request)

        self.assertIsInstance(confirm, SNSIGNConfirm)
        self.assertEqual(confirm.sec_message, b"signed_other")

    @patch('flexstack.security.sign_service.SECURITY_CODER')
    def test_sign_other_headerinfo_has_psid_and_generation_time(self, mock_coder):
        """§7.1.3 / §5.2: headerInfo SHALL contain psid and generationTime."""
        request = Mock(spec=SNSIGNRequest)
        request.its_aid = 139
        request.tbs_message = b"ivim_bytes"
        mock_coder.encode_to_be_signed_data.return_value = b"tbs"

        captured = {}

        def capture(data):
            captured["hi"] = data["content"][1]["tbsData"]["headerInfo"]
            return b"out"

        mock_coder.encode_etsi_ts_103097_data_signed.side_effect = capture
        present_at = Mock(spec=OwnCertificate)
        present_at.as_hashedid8.return_value = b"hashedid8"
        present_at.sign_message.return_value = b"sig"
        self.sign_service.get_present_at_for_signging = MagicMock(return_value=present_at)

        self.sign_service.sign_other(request)

        hi = captured["hi"]
        self.assertEqual(hi["psid"], 139)
        self.assertIn("generationTime", hi)

    @patch('flexstack.security.sign_service.SECURITY_CODER')
    def test_sign_other_signer_is_digest(self, mock_coder):
        """§7.1.3: sign_other uses 'digest' signer (hashedId8 of the AT)."""
        request = Mock(spec=SNSIGNRequest)
        request.its_aid = 638
        request.tbs_message = b"vru_bytes"
        mock_coder.encode_to_be_signed_data.return_value = b"tbs"

        captured = {}

        def capture(data):
            captured["signer"] = data["content"][1]["signer"]
            return b"out"

        mock_coder.encode_etsi_ts_103097_data_signed.side_effect = capture
        present_at = Mock(spec=OwnCertificate)
        present_at.as_hashedid8.return_value = b"\xaa" * 8
        present_at.sign_message.return_value = b"sig"
        self.sign_service.get_present_at_for_signging = MagicMock(return_value=present_at)

        self.sign_service.sign_other(request)

        self.assertEqual(captured["signer"][0], "digest")
        self.assertEqual(captured["signer"][1], b"\xaa" * 8)

    def test_sign_request_delegates_other_to_sign_other(self):
        """sign_request delegates any AID other than 36/37 to sign_other()."""
        for aid in [137, 138, 139, 141, 540, 801, 639, 638, 9999]:
            request = Mock(spec=SNSIGNRequest)
            request.its_aid = aid
            self.sign_service.sign_other = MagicMock(return_value=Mock(spec=SNSIGNConfirm))

            result = self.sign_service.sign_request(request)

            self.sign_service.sign_other.assert_called_once_with(request)
            self.assertIsNotNone(result)


if __name__ == "__main__":
    unittest.main()
