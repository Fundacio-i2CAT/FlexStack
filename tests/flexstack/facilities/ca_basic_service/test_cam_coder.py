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
        encoded_cam = b'\x30\x0a\x02\x01\x01\x16\x05value'
        decoded_cam = cam_coder.decode(encoded_cam)
        cam_coder.asn_coder.decode.assert_called_once_with("CAM", encoded_cam)
        self.assertEqual(decoded_cam, "decoded_cam")


class TestCAMCoderExtensionContainers(unittest.TestCase):
    """
    Tests for extension-container encode/decode helpers.

    These tests also verify wire-format interoperability: the bytes
    produced by encode_extension_container must be valid UPER encodings
    of the named container types (i.e. identical to what an unaltered
    ASN.1 encoder would produce), and must round-trip through
    decode_extension_container unchanged.
    """

    @classmethod
    def setUpClass(cls):
        # Use the real coder – these are integration / wire-compat tests.
        cls.coder = CAMCoder()

    # ------------------------------------------------------------------
    # Known container-id / type-name mapping
    # ------------------------------------------------------------------

    def test_encode_extension_container_unknown_id_raises(self):
        with self.assertRaises(ValueError):
            self.coder.encode_extension_container(99, {})

    def test_decode_extension_container_unknown_id_raises(self):
        with self.assertRaises(ValueError):
            self.coder.decode_extension_container(99, b'\x00')

    # ------------------------------------------------------------------
    # VeryLowFrequencyContainer  (containerId = 3)
    # ------------------------------------------------------------------

    def test_encode_decode_vlf_container_empty(self):
        """Empty VLF container round-trips correctly."""
        vlf_in = {}
        data = self.coder.encode_extension_container(3, vlf_in)
        # UPER of empty extensible SEQUENCE with all-optional fields = 0x00
        self.assertEqual(data, b'\x00')
        vlf_out = self.coder.decode_extension_container(3, data)
        self.assertEqual(vlf_out, vlf_in)

    def test_vlf_container_bytes_survive_cam_round_trip(self):
        """
        Encode a CAM with a VLF extensionContainer; after decode the
        containerData bytes must be identical to the standalone-encoded
        VLF bytes, proving wire interoperability.
        """
        vlf_bytes = self.coder.encode_extension_container(3, {})
        cam = _build_minimal_cam(extension_containers=[
            {'containerId': 3, 'containerData': vlf_bytes}
        ])
        encoded = self.coder.encode(cam)
        decoded = self.coder.decode(encoded)
        ext = decoded['cam']['camParameters']['extensionContainers'][0]
        self.assertEqual(ext['containerId'], 3)
        # bytes must survive the CAM UPER encode/decode unchanged
        self.assertEqual(ext['containerData'], vlf_bytes)

    # ------------------------------------------------------------------
    # TwoWheelerContainer  (containerId = 1)
    # ------------------------------------------------------------------

    def test_encode_decode_two_wheeler_container_empty(self):
        """Empty TwoWheelerContainer round-trips correctly."""
        tw_in = {}
        data = self.coder.encode_extension_container(1, tw_in)
        self.assertEqual(data, b'\x00')
        tw_out = self.coder.decode_extension_container(1, data)
        self.assertEqual(tw_out, tw_in)

    def test_two_wheeler_container_bytes_survive_cam_round_trip(self):
        tw_bytes = self.coder.encode_extension_container(1, {})
        cam = _build_minimal_cam(extension_containers=[
            {'containerId': 1, 'containerData': tw_bytes}
        ])
        encoded = self.coder.encode(cam)
        decoded = self.coder.decode(encoded)
        ext = decoded['cam']['camParameters']['extensionContainers'][0]
        self.assertEqual(ext['containerId'], 1)
        self.assertEqual(ext['containerData'], tw_bytes)

    # ------------------------------------------------------------------
    # PathPredictionContainer  (containerId = 4)
    # ------------------------------------------------------------------

    def test_encode_decode_path_prediction_container(self):
        pp_in = {'pathPredictedList': []}
        data = self.coder.encode_extension_container(4, pp_in)
        pp_out = self.coder.decode_extension_container(4, data)
        self.assertEqual(pp_out, pp_in)

    # ------------------------------------------------------------------
    # Multiple extension containers in one CAM
    # ------------------------------------------------------------------

    def test_multiple_extension_containers_in_cam(self):
        vlf_bytes = self.coder.encode_extension_container(3, {})
        tw_bytes = self.coder.encode_extension_container(1, {})
        cam = _build_minimal_cam(extension_containers=[
            {'containerId': 3, 'containerData': vlf_bytes},
            {'containerId': 1, 'containerData': tw_bytes},
        ])
        encoded = self.coder.encode(cam)
        decoded = self.coder.decode(encoded)
        exts = decoded['cam']['camParameters']['extensionContainers']
        self.assertEqual(len(exts), 2)
        self.assertEqual(exts[0]['containerId'], 3)
        self.assertEqual(exts[0]['containerData'], vlf_bytes)
        self.assertEqual(exts[1]['containerId'], 1)
        self.assertEqual(exts[1]['containerData'], tw_bytes)

    # ------------------------------------------------------------------
    # ASN.1 compilation smoke test (WITH SUCCESSORS must not appear)
    # ------------------------------------------------------------------

    def test_asn1_compiles_without_with_successors(self):
        """
        The cam_asn1 module must compile cleanly (i.e. WITH SUCCESSORS
        was removed from the IMPORTS block).
        """
        import asn1tools
        from flexstack.facilities.ca_basic_service.cam_asn1 import (
            CAM_ASN1_DESCRIPTIONS,
        )
        # The problematic syntax:
        #   FROM <module-name> {OID} WITH SUCCESSORS
        # must not appear in the final ASN.1 string.
        import re
        self.assertIsNone(
            re.search(r'FROM\s+\S+\s*\{[^}]*\}\s+WITH\s+SUCCESSORS',
                      CAM_ASN1_DESCRIPTIONS),
            "WITH SUCCESSORS found after a module reference in IMPORTS – "
            "this breaks asn1tools.",
        )
        # Should compile without raising
        coder = asn1tools.compile_string(CAM_ASN1_DESCRIPTIONS, codec="uper")
        self.assertIsNotNone(coder)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_minimal_cam(extension_containers=None):
    cam = {
        'header': {'protocolVersion': 2, 'messageId': 2, 'stationId': 1},
        'cam': {
            'generationDeltaTime': 1000,
            'camParameters': {
                'basicContainer': {
                    'stationType': 5,
                    'referencePosition': {
                        'latitude': 414536062,
                        'longitude': 20737073,
                        'positionConfidenceEllipse': {
                            'semiMajorAxisLength': 875,
                            'semiMinorAxisLength': 1059,
                            'semiMajorAxisOrientation': 0,
                        },
                        'altitude': {
                            'altitudeValue': 16350,
                            'altitudeConfidence': 'unavailable',
                        },
                    },
                },
                'highFrequencyContainer': (
                    'basicVehicleContainerHighFrequency',
                    {
                        'heading': {'headingValue': 3601, 'headingConfidence': 127},
                        'speed': {'speedValue': 16383, 'speedConfidence': 127},
                        'driveDirection': 'unavailable',
                        'vehicleLength': {
                            'vehicleLengthValue': 1023,
                            'vehicleLengthConfidenceIndication': 'unavailable',
                        },
                        'vehicleWidth': 62,
                        'longitudinalAcceleration': {'value': 161, 'confidence': 102},
                        'curvature': {
                            'curvatureValue': 1023,
                            'curvatureConfidence': 'unavailable',
                        },
                        'curvatureCalculationMode': 'unavailable',
                        'yawRate': {
                            'yawRateValue': 32767,
                            'yawRateConfidence': 'unavailable',
                        },
                    },
                ),
            },
        },
    }
    if extension_containers is not None:
        cam['cam']['camParameters']['extensionContainers'] = extension_containers
    return cam
