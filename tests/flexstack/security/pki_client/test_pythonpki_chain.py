"""
Interoperability with pythonpki: a Root CA -> AA -> AT chain issued by pythonpki
(rca-tool, aa-service) on 2026-11-20, also in RustFlexstack
(pki_client::unit_tests::pythonpki_chain_verifies_and_is_accepted). The Root CA
and AA certificates are canonical OER (no DEFAULT value encoded, X.696), which
RustFlexstack needs since it re-encodes the decoded toBeSigned to verify.
"""

import unittest

from flexstack.security.certificate import Certificate
from flexstack.security.certificate_library import CertificateLibrary
from flexstack.security.ecdsa_backend import PythonECDSABackend

PYTHONPKI_RCA = bytes.fromhex(
    "800300810018810850726f746f52434100000000002b0cb91786000a01028002027081030201388002026e81"
    "0201010101808001058002026f82060201fe02ff01800124818001258180018d818002027e810102808082a6"
    "453124907dae6bc01bead351618c79680c2657af16e0f8fbbd475ebc2c9c0f8080e630d2f11579b3f1aa5f2d"
    "67def9c4ea4e3a8bdb08683549e491d0fe0f7cf1efb25888020946052b4a55306c87fadbf3cc6724fda4626a"
    "480bf7d696da73a16f"
)
PYTHONPKI_AA = bytes.fromhex(
    "8003008077079e43757b7c3419810750726f746f414100000000002b0cb91c86000301018002026f81030201"
    "32010100800104800124818001258180018d818002027e810080822c695f85cc82cd09c08492fc3b78201d55"
    "fc67751dc96613641db65fb293f2058080831d8de66f8d33bde456556062ca5698e2742026d9dff83efb3cb9"
    "bad62c6cda588080c862e19a1e4a5ec6249defe64340c203198ba3f54b4120e86fa848ee3d7a83b8a43abaf2"
    "5f68e9934ea233468b4427abf433d20f31e8351df96633c5bb81041f"
)
PYTHONPKI_AT = bytes.fromhex(
    "800300805690fb8e4949a240108300000000002b0cb95b8400a801040001240001250002027e00018d808082"
    "c2c5913f0d3b921d4c43d629706bccf9189d21591f02fd0c205c4fcadccb5f80808079ee3a46bffff2a25eb2"
    "8171b6bc7009e1ad1ba4b92030fb05994da10759e7c302590958bab26d9a5d0bcc2f88bf98fb0b9fdf95b68d"
    "ba53bf2bdc7d1d589413"
)

# The same chain as issued by pythonpki before it left out eeType {app}: the Root
# CA and AA certificates were signed over a non-canonical encoding (the DEFAULT
# eeType encoded). Also in RustFlexstack (noncanonical_pythonpki_chain_is_refused).
NONCANONICAL_RCA = bytes.fromhex(
    "800300810018810850726f746f52434100000000002b0cb7dd86000a01028002027081030201388002026e81"
    "0201010101a08001058002026f82060201fe02ff01800124818001258180018d818002027e81010280808083"
    "080b512c31f1df29a40e904eb3a5a04ffd8262178534b3e8712a7c9b8d5d02b680807ec831b64bd46e86f065"
    "e8c2fbbca577cbd9c2a3a4086fa6eda7529c87a8066ecaf05acf73227942b175fe627ef59f095c8ef6f9424a"
    "0fff5240a346c02fee2a"
)
NONCANONICAL_AA = bytes.fromhex(
    "80030080dde4bace4bc520c419810750726f746f414100000000002b0cb7e286000301018002026f81030201"
    "32010120800104800124818001258180018d818002027e81800080827542cbc7f4d250187b044b2437188ddc"
    "1e9aaf485746677ac1d0127e43a1602b8080820d0cead14ed8ca0c7360f957808266f22c3eb7e64553c6e40a"
    "ec6d7266f8d9a280801bc855a77a889f47a688f25a731fd4524c1da2b7e15fb5ce4e20d7bdbcab103bbe9716"
    "2c3ab885efcfc3b7e76a7d10fddfcdddade42e0d4a2507e1d3d1eaa715"
)
NONCANONICAL_AT = bytes.fromhex(
    "80030080c47e3d036d7a4746108300000000002b0cb83f8400a801040001240001250002027e00018d808083"
    "6c1232e2d79c4d613d114415772232e8937bc36a8e49cfc2c62ad1a1335e20d580806fb8c8cf9fe8524e15eb"
    "9e6a6b690a57c9968f3107a37a4a8793cc7ddefa6049a5f455633e935777f76b10c39f47c9129b02257b1e8a"
    "baa82cb726380d9f70ed"
)


class TestPythonpkiChain(unittest.TestCase):
    """The chain verifies and is accepted by the certificate library."""

    def test_chain_verifies_and_is_accepted(self):
        backend = PythonECDSABackend()
        rca = Certificate().decode(PYTHONPKI_RCA)
        aa = Certificate().decode(PYTHONPKI_AA, issuer=rca)
        at = Certificate().decode(PYTHONPKI_AT, issuer=aa)
        for name, cert, octets in (("rca", rca, PYTHONPKI_RCA), ("aa", aa, PYTHONPKI_AA), ("at", at, PYTHONPKI_AT)):
            with self.subTest(name):
                self.assertTrue(cert.verify(backend))
                self.assertEqual(cert.encode(), octets)
        library = CertificateLibrary(backend, [rca], [aa], [at])
        self.assertIn(aa.as_hashedid8(), library.known_authorization_authorities)
        self.assertIn(at.as_hashedid8(), library.known_authorization_tickets)

    def test_noncanonical_chain_is_refused(self):
        """Verified over the canonical encoding, as RustFlexstack does: the
        certificates signed over a non-canonical one do not verify."""
        backend = PythonECDSABackend()
        rca = Certificate().decode(NONCANONICAL_RCA)
        aa = Certificate().decode(NONCANONICAL_AA, issuer=rca)
        at = Certificate().decode(NONCANONICAL_AT, issuer=aa)
        self.assertFalse(rca.verify(backend))
        self.assertFalse(aa.verify(backend))
        self.assertNotEqual(rca.encode(), NONCANONICAL_RCA)   # re-encoded canonically
        library = CertificateLibrary(backend, [rca], [aa], [at])
        self.assertEqual((library.known_root_certificates, library.known_authorization_authorities,
                          library.known_authorization_tickets), ({}, {}, {}))


if __name__ == "__main__":
    unittest.main()
