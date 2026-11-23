"""Unit tests of the CTL / CRL checks of ``pki_client.trust_lists`` (ETSI TS 102 941
V2.2.1 clauses 6.3.4, 6.3.6, B.2, B.3): every reason a list is rejected.
The accepted cases are tested by test_pki_conformance.py."""

import unittest

from flexstack.security.ecdsa_backend import PythonECDSABackend
from flexstack.security.pki_client.messages import time32
from flexstack.security.pki_client.trust_lists import PSID_CRL, PSID_CTL, ListInfo, TrustListError, TrustStore

from tests.flexstack.security.pki_client.test_pki_conformance import _signed_list, _TrustWorld
from tests.flexstack.security.pki_client.ts_pki import encode
from tests.flexstack.security.test_sec_conformance import _Clock
from tests.flexstack.security.test_security_checks import _ca


class TestTrustListChecks(unittest.TestCase):

    def setUp(self):
        self.w = _TrustWorld(self)
        self.station = self.w.iut([self.w.rca], [self.w.aa])
        self.trust = self.station.trust

    def assert_rejected(self, message, code):
        with self.assertRaises(TrustListError) as error:
            self.trust.process(message)
        self.assertEqual(error.exception.code, code)

    def ctl(self, issuer, psid, choice, commands, full=True, sequence=0):
        content = {"version": 1, "nextUpdate": time32(self.w.clock.unix()) + 3600, "isFullCtl": full,
                   "ctlSequence": sequence, "ctlCommands": commands}
        return _signed_list(issuer, self.w.backend, psid, choice, content, self.w.clock)

    def test_not_signed_data(self):
        self.assert_rejected(encode("Ieee1609Dot2Data", {"protocolVersion": 3, "content": ("unsecuredData", b"x")}),
                             "badcontenttype")

    def test_garbage(self):
        self.assert_rejected(b"\x03\x81", "cantparse")

    def test_ectl_from_untrusted_tlm(self):
        rogue = _ca(self.w.backend, "rogue-tlm", None, 2,
                    appPermissions=[{"psid": PSID_CTL, "ssp": ("bitmapSsp", bytes([1, 0xC8]))}])
        self.assert_rejected(self.ctl(rogue, PSID_CTL, "certificateTrustListTlm", []), "unknownissuer")

    def test_wrong_psid(self):
        self.assert_rejected(self.ctl(self.w.tlm, PSID_CRL, "certificateTrustListTlm", []), "badpsid")

    def test_rca_may_not_sign_root_entries(self):
        """A Root CA CTL (SSP 38h) cannot add Root CAs (bit 40h, Table B.3)."""
        other = self.w.root("other")
        self.assert_rejected(self.ctl(self.w.rca, PSID_CTL, "certificateTrustListRca",
                                      [("add", ("rca", {"selfsignedRootCa": other.certificate}))]),
                             "deniedpermissions")

    def test_full_ctl_without_delete(self):
        self.assert_rejected(self.ctl(self.w.tlm, PSID_CTL, "certificateTrustListTlm",
                                      [("delete", ("cert", b"\x01" * 8))]), "badcontenttype")

    def test_sequence(self):
        """The same ctlSequence twice, or a delta CTL not following the last CTL."""
        self.trust.process(self.ctl(self.w.tlm, PSID_CTL, "certificateTrustListTlm", [], sequence=4))
        self.assert_rejected(self.ctl(self.w.tlm, PSID_CTL, "certificateTrustListTlm", [], sequence=4), "outdated")
        self.assert_rejected(self.ctl(self.w.tlm, PSID_CTL, "certificateTrustListTlm", [], full=False, sequence=6),
                             "outofsequence")
        self.trust.process(self.ctl(self.w.tlm, PSID_CTL, "certificateTrustListTlm", [], full=False, sequence=5))

    def test_tampered_signature(self):
        message = bytearray(self.ctl(self.w.tlm, PSID_CTL, "certificateTrustListTlm", []))
        message[-1] ^= 1
        self.assert_rejected(bytes(message), "invalidsignature")

    def test_crl_issuer_without_crl_permission(self):
        no_crl = _ca(self.w.backend, "no-crl", None, 2,
                     appPermissions=[{"psid": PSID_CTL, "ssp": ("bitmapSsp", bytes([1, 0x38]))}])
        self.station.verify_service.certificate_library.add_root_certificate(no_crl)
        self.assert_rejected(self.w.crl(no_crl, []), "deniedpermissions")

    def test_older_crl(self):
        self.trust.process(self.w.crl(self.w.rca, []))
        self.assert_rejected(self.w.crl(self.w.rca, [], this_update_offset=-10), "outdated")

    def test_revoked_root_cannot_return(self):
        """A revoked certificate is revoked permanently (clause 6.3.3)."""
        self.trust.process(self.w.crl(self.w.rca, [self.w.rca]))
        library = self.station.verify_service.certificate_library
        self.assertNotIn(self.w.rca.as_hashedid8(), library.known_root_certificates)
        self.trust.tlms[self.w.tlm.as_hashedid8()] = self.w.tlm
        self.trust.process(self.w.ectl([self.w.rca]))
        self.assertNotIn(self.w.rca.as_hashedid8(), library.known_root_certificates)

    def test_no_download_without_access_point(self):
        """A list past nextUpdate whose issuer has no CPOC / DC URL is not fetched."""
        clock = _Clock()
        store = TrustStore(self.station.verify_service.certificate_library, PythonECDSABackend(), clock=clock.unix)
        store.lists[("crl", b"\x01" * 8)] = ListInfo(b"\x01" * 8, "crl", time32(clock.unix()) - 1)
        store.lists[("ectl", b"\x02" * 8)] = ListInfo(b"\x02" * 8, "ectl", time32(clock.unix()) - 1)
        self.assertEqual(store.due_downloads(), [])
        store.dc_urls[b"\x01" * 8] = "https://dc.ts"
        self.assertEqual(store.due_downloads(), ["https://dc.ts/getcrl/" + "01" * 8])


if __name__ == "__main__":
    unittest.main()
