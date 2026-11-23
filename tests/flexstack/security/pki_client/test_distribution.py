"""Unit tests of the P2P CRL / CTL distribution outside the TPs: the header
extension encoding, the reception filters of the service, its triggers and the
retry helper. Mirrors rustflexstack ``security::pki_client::unit_tests``
(distribution section)."""
import asyncio
import time
import unittest
from unittest.mock import MagicMock

from flexstack.btp.router import Router as BTPRouter
from flexstack.security.certificate import SECURITY_CODER
from flexstack.security.header_extensions import (
    CRL_REQUEST_ID, DELTA_CTL_REQUEST_ID, FULL_CTL_REQUEST_ID, decode_requests, encode_requests)
from flexstack.security.pki_client.distribution import CRL_PORT, CTL_PORT, TrustListDistribution
from flexstack.security.pki_client.messages import time32
from flexstack.security.pki_client.transport import PkiTransportError, RetryPolicy, post_with_retry

from tests.flexstack.security.pki_client.test_pki_conformance import _CxlWorld, _frames

ISSUER = b"\x11" * 8


class TestHeaderExtensions(unittest.TestCase):
    """EtsiOriginatingHeaderInfoExtension in contributedExtensions (TS 103 097 clause 4.3.2)."""

    def test_crl_request_encoding(self):
        """COER, derived by hand: Extension = id (01) || open type content (length 0d ||
        EtsiTs102941CrlRequest = preamble 80 (lastKnownUpdate present) || issuerId ||
        Time32 00000005)."""
        blocks = encode_requests([(CRL_REQUEST_ID, {"issuerId": ISSUER, "lastKnownUpdate": 5})])
        self.assertEqual(blocks[0]["contributorId"], 2)
        self.assertEqual(blocks[0]["extns"], [bytes.fromhex("010d80" + "11" * 8 + "00000005")])
        self.assertEqual(decode_requests(blocks), [(CRL_REQUEST_ID, {"issuerId": ISSUER, "lastKnownUpdate": 5})])

    def test_delta_ctl_request_encoding(self):
        """Extension 02, content length 09, preamble 00 (no lastKnownCtlSequence)."""
        blocks = encode_requests([(DELTA_CTL_REQUEST_ID, {"issuerId": ISSUER})])
        self.assertEqual(blocks[0]["extns"], [bytes.fromhex("020900" + "11" * 8)])

    def test_in_a_header_info(self):
        """The block round-trips inside a ToBeSignedData headerInfo."""
        tbs = {"payload": {"data": {"protocolVersion": 3, "content": ("unsecuredData", b"x")}},
               "headerInfo": {"psid": 36, "generationTime": 1,
                              "contributedExtensions": encode_requests([(FULL_CTL_REQUEST_ID, {"issuerId": ISSUER})])}}
        coder = SECURITY_CODER.asn_coder
        decoded = coder.decode("ToBeSignedData", coder.encode("ToBeSignedData", tbs))
        self.assertEqual(decode_requests(decoded["headerInfo"]["contributedExtensions"]),
                         [(FULL_CTL_REQUEST_ID, {"issuerId": ISSUER})])

    def test_foreign_and_unknown_extensions_skipped(self):
        coder = SECURITY_CODER.asn_coder
        unknown = coder.encode("EtsiOriginatingHeaderInfoExtension", {"id": 9, "content": b"\x00"})
        blocks = [{"contributorId": 1, "extns": [b"\x01\x02"]},                  # IEEE contributor
                  {"contributorId": 2, "extns": [unknown, b"\xff", encode_requests(
                      [(CRL_REQUEST_ID, {"issuerId": ISSUER})])[0]["extns"][0]]}]
        self.assertEqual(decode_requests(blocks), [(CRL_REQUEST_ID, {"issuerId": ISSUER})])


class TestDistribution(unittest.TestCase):
    """Behaviour of the CXLDA not covered by a TP."""

    def test_attach_registers_both_ports_open_to_unsecured(self):
        router = BTPRouter(MagicMock())
        TrustListDistribution(MagicMock()).attach(router)
        router.freeze_callbacks()
        self.assertEqual(set(router.indication_callbacks), {CTL_PORT, CRL_PORT})
        self.assertEqual(router.unsecured_ports, {CTL_PORT, CRL_PORT})

    def test_invalid_broadcast_ignored(self):
        """A broadcast list that does not verify neither stops nor starts anything."""
        w = _CxlWorld(self)
        iut = w.iut([w.rca], [w.aa])
        crl = w.crl(w.rca, [])
        iut.cxl.receive(crl, from_dc=True)
        tampered = crl[:-1] + bytes([crl[-1] ^ 1])
        w.neighbour_broadcast(iut, tampered, CRL_PORT)
        self.assertIn(("crl", w.rca.as_hashedid8()), iut.cxl.broadcasts)

    def test_full_ctl_not_broadcast_and_full_ctl_request_ignored(self):
        """Full CTL broadcast (clause 5.5) is not implemented."""
        w = _CxlWorld(self)
        iut = w.iut([w.rca], [w.aa])
        iut.cxl.receive(w.ectl([w.rca]), from_dc=True)
        iut.cxl.on_requests([(FULL_CTL_REQUEST_ID, {"issuerId": w.tlm.as_hashedid8()})])
        w.run(iut, 2000)
        self.assertEqual(_frames(iut), [])

    def test_request_for_a_list_not_held_or_not_newer(self):
        w = _CxlWorld(self)
        iut = w.iut([w.rca], [w.aa], redistribute=False)
        crl = w.crl(w.rca, [])
        iut.cxl.receive(crl, from_dc=True)
        this_update = iut.trust.lists[("crl", w.rca.as_hashedid8())].this_update
        iut.cxl.on_requests([(CRL_REQUEST_ID, {"issuerId": b"\x22" * 8}),
                             (CRL_REQUEST_ID, {"issuerId": w.rca.as_hashedid8(), "lastKnownUpdate": this_update})])
        self.assertEqual(_frames(iut), [])

    def test_crl_next_update_starts_a_request_ended_by_the_crl(self):
        """Clause 5.3.6: the nextUpdate of the CRL reached starts a CRL request, which
        ends when the next CRL is received."""
        w = _CxlWorld(self)
        iut = w.iut([w.rca], [w.aa], redistribute=False)
        iut.cxl.receive(w.crl(w.rca, []), from_dc=True)
        next_update = iut.trust.lists[("crl", w.rca.as_hashedid8())].next_update
        w.clock.ms = (next_update - time32(w.clock.base) + 1) * 1000
        iut.cxl.tick()
        self.assertEqual(iut.cxl.requests, [("crl", w.rca.as_hashedid8())])
        w.neighbour_broadcast(iut, w.crl(w.rca, []), CRL_PORT)
        self.assertEqual(iut.cxl.requests, [])

    def test_ctl_request_ends_at_next_update(self):
        w = _CxlWorld(self)
        iut = w.iut([w.rca], [w.aa])
        iut.cxl.receive(w.rca_ctl(w.rca, [w.aa], next_update_s=60), from_dc=True)
        iut.cxl.request_ctl(w.rca.as_hashedid8())
        w.clock.ms = 61_000
        iut.cxl.tick()
        self.assertEqual(iut.cxl.requests, [])

    def test_requests_in_turn(self):
        """One request per CAM, the pending ones in turn (clause 5.3.2)."""
        w = _CxlWorld(self)
        iut = w.iut([w.rca], [w.aa])
        iut.cxl.request_crl(w.rca.as_hashedid8())
        iut.cxl.request_ctl(w.tlm.as_hashedid8())
        ids = [iut.cxl.next_request()[0] for _ in range(4)]
        self.assertEqual(ids, [CRL_REQUEST_ID, DELTA_CTL_REQUEST_ID] * 2)

    def test_thread(self):
        w = _CxlWorld(self)
        iut = w.iut([w.rca], [w.aa])
        iut.cxl.tick = MagicMock()
        iut.cxl.start(interval=0.01)
        deadline = time.monotonic() + 2.0             # bounded wait: robust on a loaded host
        while iut.cxl.tick.call_count < 2 and time.monotonic() < deadline:
            time.sleep(0.01)
        iut.cxl.stop()
        self.assertGreater(iut.cxl.tick.call_count, 1)


class TestPostWithRetry(unittest.TestCase):

    def test_without_policy_one_transmission(self):
        transport = MagicMock()

        async def post(*_):
            raise PkiTransportError("down")
        transport.post = post
        with self.assertRaises(PkiTransportError):
            asyncio.run(post_with_retry(transport, "u", b"m", "t", None, clock=lambda: 0.0))

    def test_policy_defaults_meet_th2_above_th1_times_n1(self):
        """Clause 5.1.4: TH2 > TH1 x N1."""
        policy = RetryPolicy()
        self.assertGreater(policy.th2, policy.th1 * policy.n1)


if __name__ == "__main__":
    unittest.main()
