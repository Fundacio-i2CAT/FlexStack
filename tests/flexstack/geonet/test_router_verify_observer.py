"""
GeoNetworking router verify observer (``Router.set_verify_observer``): it sees
the SN-VERIFY.confirm of every received secured packet, verified or not, and
does not change the processing. Mirrors
``geonet::router::forwarding_tests::verify_observer_sees_every_verification``
in RustFlexstack.
"""

import unittest

from flexstack.security.sn_sap import ReportVerify

from tests.flexstack.security.test_sec_conformance import _Clock, _Pki, _Station


class TestVerifyObserver(unittest.TestCase):

    def test_observer_sees_every_verification(self):
        clock, pki = _Clock(), _Pki()
        sender = _Station(clock, pki, ats=[pki.at()], n=1)
        receiver = _Station(clock, pki, n=2, station_id=0x2002)
        good = sender.certificate_cam(0).raw
        bad = bytearray(good)
        bad[-1] ^= 0x01                         # signature altered
        seen = []
        receiver.gn.set_verify_observer(lambda message, confirm: seen.append((len(message), confirm.report)))

        receiver.deliver(good, at_ms=10)
        receiver.deliver(bytes(bad), at_ms=20)

        self.assertEqual(len(seen), 2)
        self.assertEqual(seen[0], (len(good) - 4, ReportVerify.SUCCESS))
        self.assertEqual(seen[1][0], len(bad) - 4)
        self.assertNotEqual(seen[1][1], ReportVerify.SUCCESS)
        self.assertEqual(len(receiver.cams), 1)  # only the verified CAM reached the CA service

    def test_no_observer_by_default(self):
        clock, pki = _Clock(), _Pki()
        self.assertIsNone(_Station(clock, pki, n=1).gn.verify_observer)


if __name__ == "__main__":
    unittest.main()
