import unittest
from unittest.mock import MagicMock, patch
from flexstack.facilities.ca_basic_service.cam_coder import CAMCoder


class TestCAMCoder(unittest.TestCase):
    @patch("asn1tools.compile_string")
    def test__init__(self, asn1tools_compile_string_mock):
        asn1tools_compile_string_mock.return_value = "asn_coder"
        cam_coder = CAMCoder()
        asn1tools_compile_string_mock.assert_called_once()
        self.assertEqual(cam_coder.asn_coder, "asn_coder")

    @patch("asn1tools.compile_string")
    def test_encode(self, asn1tools_compile_string_mock):
        asn_coder = MagicMock()
        asn_coder.encode = MagicMock(return_value="encoded_cam")
        asn1tools_compile_string_mock.return_value = asn_coder
        cam_coder = CAMCoder()
        # cam_coder.asn_coder.encode.return_value = "encoded_cam"
        cam = {"camField": "value"}
        encoded_cam = cam_coder.encode(cam)
        cam_coder.asn_coder.encode.assert_called_once_with("CAM", cam)
        self.assertEqual(encoded_cam, "encoded_cam")

    @patch("asn1tools.compile_string")
    def test_decode(self, asn1tools_compile_string_mock):
        asn_coder = MagicMock()
        asn_coder.decode = MagicMock(return_value="decoded_cam")
        asn1tools_compile_string_mock.return_value = asn_coder
        cam_coder = CAMCoder()
        # cam_coder.asn_coder.decode.return_value = "decoded_cam"
        encoded_cam = b'\x30\x0a\x02\x01\x01\x16\x05value'
        decoded_cam = cam_coder.decode(encoded_cam)
        cam_coder.asn_coder.decode.assert_called_once_with("CAM", encoded_cam)
        self.assertEqual(decoded_cam, "decoded_cam")
