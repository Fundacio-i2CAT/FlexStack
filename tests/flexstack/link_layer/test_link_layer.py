import unittest

from flexstack.linklayer.link_layer import LinkLayer


class TestLinkLayer(unittest.TestCase):
    # TODO: Implement tests
    pass


class TestDeliverSender(unittest.TestCase):
    """The link-layer source address reaches callbacks that declare ``sender_ll_address``."""

    def test_sender_passed_when_declared(self):
        received = []

        def callback(packet, sender_ll_address=None):
            received.append((packet, sender_ll_address))

        LinkLayer(callback).deliver(b"pkt", b"\x02\x00\x00\x00\x00\x07")
        self.assertEqual(received, [(b"pkt", b"\x02\x00\x00\x00\x00\x07")])

    def test_single_argument_callback_unchanged(self):
        received = []
        LinkLayer(received.append).deliver(b"pkt", b"\x02\x00\x00\x00\x00\x07")
        self.assertEqual(received, [b"pkt"])
