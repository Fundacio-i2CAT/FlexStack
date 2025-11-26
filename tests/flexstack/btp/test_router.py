import unittest
from unittest.mock import MagicMock

from flexstack.btp.router import Router
from flexstack.btp.service_access_point import BTPDataRequest, PacketTransportType, CommunicationProfile, TrafficClass, CommonNH


class TestRouter(unittest.TestCase):

    def test__init__(self):
        gn_router = MagicMock()
        router = Router(gn_router)
        self.assertEqual(router.indication_callbacks, None)
        self.assertEqual(router.gn_router, gn_router)

    def test_register_indication_callback(self):
        gn_router = MagicMock()
        router = Router(gn_router)
        callback = MagicMock()
        router.register_indication_callback_btp(1, callback)
        router.freeze_callbacks()
        self.assertEqual(router.indication_callbacks.get(1),  # type: ignore
                         callback)

    def test_BTPDataRequest(self):
        """
        Test to be improved!
        """
        gn_router = MagicMock()
        gn_router.gn_data_request = MagicMock()
        router = Router(gn_router)
        request = BTPDataRequest(
            btp_type=CommonNH.BTP_B,
            destination_port=2001,
            gn_packet_transport_type=PacketTransportType(),
            communication_profile=CommunicationProfile.UNSPECIFIED,
            traffic_class=TrafficClass(),
            data=b'Hello World',
            length=11,
        )
        router.btp_data_request(request)
        gn_router.gn_data_request.assert_called_once()


if __name__ == '__main__':
    unittest.main()
