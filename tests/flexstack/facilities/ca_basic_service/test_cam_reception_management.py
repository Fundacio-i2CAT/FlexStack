import unittest
from unittest.mock import MagicMock
from flexstack.facilities.ca_basic_service.cam_reception_management import (
    CAMReceptionManagement,
)


def _make_crm(with_ldm=False):
    cam_coder = MagicMock()
    btp_router = MagicMock()
    ldm = MagicMock() if with_ldm else None
    crm = CAMReceptionManagement(cam_coder, btp_router, ldm)
    return crm, cam_coder, btp_router, ldm


def _make_indication(data=None):
    ind = MagicMock()
    ind.data = data or MagicMock()
    return ind


class TestCamReceptionManagementInit(unittest.TestCase):

    def test_registers_btp_callback_on_port_2001(self):
        _, _, btp_router, _ = _make_crm()
        btp_router.register_indication_callback_btp.assert_called_once_with(
            port=2001, callback=btp_router.register_indication_callback_btp.call_args[1]["callback"]
        )

    def test_cam_coder_stored(self):
        crm, cam_coder, _, _ = _make_crm()
        self.assertIs(crm.cam_coder, cam_coder)

    def test_ldm_stored(self):
        crm, _, _, ldm = _make_crm(with_ldm=True)
        self.assertIs(crm.ca_basic_service_ldm, ldm)

    def test_no_application_callbacks_initially(self):
        crm, _, _, _ = _make_crm()
        self.assertEqual(crm._application_callbacks, [])


class TestReceptionCallback(unittest.TestCase):

    def test_reception_callback_decodes_cam(self):
        crm, cam_coder, _, _ = _make_crm()
        cam_coder.decode.return_value = {
            "cam": {"generationDeltaTime": 24856},
            "header": {"stationId": 1},
        }
        crm.reception_callback(_make_indication())
        cam_coder.decode.assert_called_once()

    def test_reception_callback_updates_ldm(self):
        crm, cam_coder, _, ldm = _make_crm(with_ldm=True)
        cam_coder.decode.return_value = {
            "cam": {"generationDeltaTime": 24856},
            "header": {"stationId": 1},
        }
        crm.reception_callback(_make_indication())
        ldm.add_provider_data_to_ldm.assert_called_once()

    def test_reception_callback_no_ldm_no_error(self):
        crm, cam_coder, _, _ = _make_crm(with_ldm=False)
        cam_coder.decode.return_value = {
            "cam": {"generationDeltaTime": 24856},
            "header": {"stationId": 1},
        }
        crm.reception_callback(_make_indication())  # Should not raise

    def test_utc_timestamp_added_to_cam(self):
        crm, cam_coder, _, _ = _make_crm()
        cam_dict = {"cam": {"generationDeltaTime": 24856}, "header": {"stationId": 1}}
        cam_coder.decode.return_value = cam_dict
        callbacks_received = []
        crm.add_application_callback(lambda c: callbacks_received.append(c))
        crm.reception_callback(_make_indication())
        self.assertIn("utc_timestamp", callbacks_received[0])


class TestAnnexB331DecodeException(unittest.TestCase):

    def test_decode_exception_does_not_update_ldm(self):
        """Annex B.3.3.1: decoding failure must not update the LDM."""
        crm, cam_coder, _, ldm = _make_crm(with_ldm=True)
        cam_coder.decode.side_effect = ValueError("bad packet")
        crm.reception_callback(_make_indication())
        ldm.add_provider_data_to_ldm.assert_not_called()

    def test_decode_exception_does_not_raise(self):
        """Annex B.3.3.1: decoding failure must not propagate."""
        crm, cam_coder, _, _ = _make_crm()
        cam_coder.decode.side_effect = ValueError("bad packet")
        crm.reception_callback(_make_indication())  # Should not raise

    def test_decode_exception_skips_application_callbacks(self):
        crm, cam_coder, _, _ = _make_crm()
        cam_coder.decode.side_effect = ValueError("bad packet")
        received = []
        crm.add_application_callback(lambda c: received.append(c))
        crm.reception_callback(_make_indication())
        self.assertEqual(received, [])


class TestApplicationCallbacks(unittest.TestCase):

    def test_add_application_callback_called_on_valid_cam(self):
        crm, cam_coder, _, _ = _make_crm()
        cam_coder.decode.return_value = {
            "cam": {"generationDeltaTime": 1000},
            "header": {"stationId": 42},
        }
        received = []
        crm.add_application_callback(lambda c: received.append(c))
        crm.reception_callback(_make_indication())
        self.assertEqual(len(received), 1)
        self.assertEqual(received[0]["header"]["stationId"], 42)

    def test_multiple_callbacks_all_called(self):
        crm, cam_coder, _, _ = _make_crm()
        cam_coder.decode.return_value = {
            "cam": {"generationDeltaTime": 1000},
            "header": {"stationId": 7},
        }
        count = []
        crm.add_application_callback(lambda c: count.append(1))
        crm.add_application_callback(lambda c: count.append(2))
        crm.reception_callback(_make_indication())
        self.assertEqual(count, [1, 2])

    def test_faulty_application_callback_does_not_propagate(self):
        crm, cam_coder, _, _ = _make_crm()
        cam_coder.decode.return_value = {
            "cam": {"generationDeltaTime": 1000},
            "header": {"stationId": 7},
        }
        crm.add_application_callback(lambda c: (_ for _ in ()).throw(RuntimeError("oops")))
        crm.reception_callback(_make_indication())  # Should not raise
