"""
ITS-S PKI conformance tests: one test per Test Purpose of ETSI TS 103 525-2
V2.1.1 clause 5.2 (IUT = ITS-S), against ETSI TS 102 941 V2.2.1.

Each test is named after its TP and quotes the TP identifier. A TP with
variants is one test covering every variant.

Enrolment and authorization (CFG_ENR_ITS-S, CFG_AUTH_ITS-S): the IUT is a
:class:`PkiClient` on an injected clock; the EA and AA are the test system of
``ts_pki`` (written independently of the client), reached through an
in-memory transport. The tests look at what the EA / AA received, decrypted
and decoded with the official ASN.1, and at the IUT state.

CTL and CRL handling (CFG_CXL_P2P): the IUT is a complete station (CA basic
service on BTP on a secured GeoNetworking router) whose trust information is
updated by a :class:`TrustStore`; the test system signs ECTLs, Root CA CTLs,
CRLs and CAMs. CRL handling of the own certificates uses the PkiClient.

Not covered here: the repetition TPs (ETSI TS 103 601), the CTL/CRL
distribution TPs (ETSI TS 103 601), butterfly authorization (optional,
PICS_SECPKI_AUTH_BFK, not implemented) and SECPKI_ITS-S_AUTH_16_BV (ecSignature
not encrypted: the official ASN.1 requires encryptedEcSignature).

Mirrors ``rustflexstack::security::pki_client::conformance``.
"""

import asyncio
import hashlib
import hmac
import tempfile
import unittest
from copy import deepcopy

from flexstack.security.certificate import Certificate, OwnCertificate
from flexstack.security.certificate_library import CertificateLibrary
from flexstack.security.ecdsa_backend import PythonECDSABackend
from flexstack.security.pki_client import PkiClient
from flexstack.security.pki_client.authorization import AuthorizationError
from flexstack.security.pki_client.enrolment import EnrolmentError
from flexstack.security.pki_client.messages import time32
from flexstack.security.pki_client.trust_lists import TrustListError, TrustStore
from flexstack.security.pki_client.distribution import CRL_PORT, CTL_PORT, DistributionConfig, TrustListDistribution
from flexstack.security.pki_client.transport import PkiTransportError, RetryPolicy
from flexstack.security.header_extensions import CRL_REQUEST_ID, DELTA_CTL_REQUEST_ID, decode_requests
from flexstack.security.security_profiles import SecurityProfile
from flexstack.btp.service_access_point import BTPDataRequest
from flexstack.geonet.basic_header import BasicHeader, BasicNH
from flexstack.geonet.common_header import CommonHeader
from flexstack.geonet.service_access_point import CommonNH, HeaderType, PacketTransportType, TopoBroadcastHST

from tests.flexstack.security.pki_client.ts_pki import (
    PSID_CERT_REQUEST, PSID_CRL, PSID_CTL, ROOT_PERMISSIONS, Transport, TsPki, decode, encode, signed_ok,
)
from tests.flexstack.security.test_sec_conformance import (
    APP_PERMISSIONS, TS_ID, _Clock, _header, _resign, _Station,
)
from tests.flexstack.security.test_security_checks import _at_tbs, _ca

ITS_ID = b"\x10\x20\x30\x40\x50\x60\x70\x80"


class _Iut:
    """The IUT (PkiClient) with the test system EA / AA and a clock of its own."""

    def __init__(self, ea_code="ok", aa_code="ok", pop=True):
        self.now = _Clock().base
        self.pki = TsPki(ea_code, aa_code)
        self.transport = Transport(self.pki)
        self.client = PkiClient(self.transport.ea_url, self.transport.aa_url, self.pki.ea.own,
                                self.pki.aa.own, self.pki.root, certs_dir=tempfile.mkdtemp(),
                                its_id=ITS_ID, clock=lambda: self.now, transport=self.transport, pop=pop)
        self.pki.register(ITS_ID, self.client.canonical_public_key())

    def enrol(self):
        return asyncio.run(self.client.enroll())

    def authorize(self):
        return asyncio.run(self.client.authorize())

    @property
    def enrolment(self):
        """The last request received by the EA."""
        return self.pki.enrolments[-1]

    @property
    def authorization(self):
        """The last request received by the AA."""
        return self.pki.authorizations[-1]


def _outer_signer(received):
    return received.outer["content"][1]["signer"]


def _header_of(signed: dict) -> dict:
    return signed["content"][1]["tbsData"]["headerInfo"]


def _app_permission(certificate: dict, psid: int):
    return next((p for p in certificate["toBeSigned"].get("appPermissions", []) if p["psid"] == psid), None)


# ─── Enrolment (TS 103 525-2 clause 5.2.2) ─────────────────────────────────


class TestPkiItssEnrolment(unittest.TestCase):
    """SECPKI_ITS-S_ENR: enrolment request (TS 102 941 clause 6.2.3.2.1)."""

    def test_tp_secpki_its_s_enr_01_bv(self):
        """SECPKI_ITS-S_ENR_01_BV: triggered to request an EC, the IUT sends an
        EnrolmentRequestMessage to the EA."""
        iut = _Iut()
        self.assertEqual(iut.client.state, "initialized")
        iut.enrol()
        url, content, content_type = iut.transport.posts[0]
        self.assertEqual((url, content_type), (iut.transport.ea_url, "application/x-its-request"))
        self.assertEqual(decode("Ieee1609Dot2Data", content)["content"][0], "encryptedData")
        self.assertEqual(iut.enrolment.etsi["content"][0], "enrolmentRequest")

    def test_tp_secpki_its_s_enr_02_bv(self):
        """SECPKI_ITS-S_ENR_02_BV: an initial request has itsId = canonical identifier,
        outer signer self and the outer signature computed with the canonical key."""
        iut = _Iut()
        iut.enrol()
        self.assertEqual(iut.enrolment.inner["itsId"], ITS_ID)
        self.assertEqual(_outer_signer(iut.enrolment), ("self", None))
        self.assertTrue(signed_ok(iut.pki.backend, iut.enrolment.outer, iut.client.canonical_public_key(), b""))

    def test_tp_secpki_its_s_enr_03_bv(self):
        """SECPKI_ITS-S_ENR_03_BV: with a valid EC the request is a re-keying request:
        itsId and signer are the digest of the EC, signed with the EC key."""
        iut = _Iut()
        ec = iut.enrol()
        iut.enrol()
        self.assertEqual(iut.enrolment.inner["itsId"], ec.as_hashedid8())
        self.assertEqual(_outer_signer(iut.enrolment), ("digest", ec.as_hashedid8()))
        self.assertTrue(signed_ok(iut.pki.backend, iut.enrolment.outer, ec.verification_key(),
                                  ec.to_canonical().encode()))

    def test_tp_secpki_its_s_enr_05_bv(self):
        """SECPKI_ITS-S_ENR_05_BV: once the EC expires the IUT is 'initialized' again:
        the next request uses the canonical identifier."""
        iut = _Iut()
        iut.pki.ec_duration = ("hours", 1)
        iut.enrol()
        self.assertEqual(iut.client.state, "enrolled")
        iut.now += 2 * 3600                                       # the EC expires
        self.assertEqual(iut.client.state, "initialized")
        iut.enrol()
        self.assertEqual(iut.enrolment.inner["itsId"], ITS_ID)
        self.assertEqual(_outer_signer(iut.enrolment), ("self", None))

    def test_tp_secpki_its_s_enr_06_bv(self):
        """SECPKI_ITS-S_ENR_06_BV: each request (initial, then re-keying) carries a new
        verification key."""
        iut = _Iut()
        for _ in range(3):
            iut.enrol()
        keys = [r.inner["publicKeys"]["verificationKey"] for r in iut.pki.enrolments]
        self.assertEqual([_outer_signer(r)[0] for r in iut.pki.enrolments], ["self", "digest", "digest"])
        self.assertEqual(len({repr(k) for k in keys}), 3)

    def test_tp_secpki_its_s_enr_07_bv(self):
        """SECPKI_ITS-S_ENR_07_BV: requestedSubjectAttributes contain no certIssuePermissions
        (initialized and enrolled)."""
        iut = _Iut()
        iut.enrol()
        iut.enrol()
        for received in iut.pki.enrolments:
            self.assertNotIn("certIssuePermissions", received.inner["requestedSubjectAttributes"])

    def test_tp_secpki_its_s_enr_08_bv(self):
        """SECPKI_ITS-S_ENR_08_BV: the headerInfo of InnerECRequestSignedForPOP has psid
        AID_CERT_REQ and generationTime only."""
        iut = _Iut()
        iut.enrol()
        iut.enrol()
        for received in iut.pki.enrolments:
            header = _header_of(received.pop)
            self.assertEqual(set(header), {"psid", "generationTime"})
            self.assertEqual(header["psid"], PSID_CERT_REQUEST)

    def test_tp_secpki_its_s_enr_09_bv(self):
        """SECPKI_ITS-S_ENR_09_BV: the headerInfo of the outer EtsiTs103097Data-Signed has
        psid AID_CERT_REQ and generationTime only."""
        iut = _Iut()
        iut.enrol()
        iut.enrol()
        for received in iut.pki.enrolments:
            header = _header_of(received.outer)
            self.assertEqual(set(header), {"psid", "generationTime"})
            self.assertEqual(header["psid"], PSID_CERT_REQUEST)

    def test_tp_secpki_its_s_enr_10_bv(self):
        """SECPKI_ITS-S_ENR_10_BV: exactly one certRecipInfo with the EA's HashedId8; the
        AES key is encrypted (encKey) with the EA's encryption key and decrypts the
        ciphertext (done by the test system EA)."""
        iut = _Iut()
        iut.enrol()
        recipients = iut.enrolment.encrypted["content"][1]["recipients"]
        self.assertEqual(len(recipients), 1)
        choice, recipient = recipients[0]
        self.assertEqual(choice, "certRecipInfo")
        self.assertEqual(recipient["recipientId"], iut.pki.ea.own.as_hashedid8())
        ea_key_choice = iut.pki.ea.own.certificate["toBeSigned"]["encryptionKey"]["publicKey"][0]
        self.assertEqual(recipient["encKey"][0], ea_key_choice)
        self.assertEqual(len(iut.enrolment.session_key), 16)

    def test_tp_secpki_its_s_enr_11_bv(self):
        """SECPKI_ITS-S_ENR_11_BV: the InnerECRequestSignedForPOP signature is computed on
        the InnerECRequest with the private key of its verificationKey."""
        iut = _Iut()
        iut.enrol()
        received = iut.enrolment
        self.assertEqual(received.pop["content"][1]["signer"], ("self", None))
        self.assertTrue(signed_ok(iut.pki.backend, received.pop,
                                  received.inner["publicKeys"]["verificationKey"], b""))
        payload = received.pop["content"][1]["tbsData"]["payload"]["data"]["content"][1]
        self.assertEqual(decode("InnerEcRequest", payload), received.inner)

    def test_tp_secpki_its_s_enr_12_bv(self):
        """SECPKI_ITS-S_ENR_12_BV: enrolled, the request is signed with the EC, whose
        appPermissions grant AID_CERT_REQ with SSP version 1 and the enrolment request
        bit (clause B.4, 80h)."""
        iut = _Iut()
        ec = iut.enrol()
        iut.enrol()
        self.assertEqual(_outer_signer(iut.enrolment), ("digest", ec.as_hashedid8()))
        ssp = _app_permission(ec.certificate, PSID_CERT_REQUEST)["ssp"][1]
        self.assertEqual(ssp[0], 1)
        self.assertTrue(ssp[1] & 0x80)


class TestPkiItssEnrolmentResponse(unittest.TestCase):
    """SECPKI_ITS-S_ENR_RCV: enrolment response handling (TS 102 941 clause 6.2.3.2.2)."""

    def test_tp_secpki_its_s_enr_rcv_01_bv(self):
        """SECPKI_ITS-S_ENR_RCV_01_BV: after a response with responseCode != 0 the IUT
        stays in X_STATE (1 'initialized', 2 'enrolled')."""
        iut = _Iut(ea_code="deniedrequest")
        with self.assertRaises(EnrolmentError) as error:
            iut.enrol()
        self.assertEqual(error.exception.code, "deniedrequest")
        self.assertEqual(iut.client.state, "initialized")                        # variant 1
        iut = _Iut()
        ec = iut.enrol()
        iut.pki.ea_code = "deniedrequest"
        with self.assertRaises(EnrolmentError):
            iut.enrol()
        self.assertEqual(iut.client.state, "enrolled")                           # variant 2
        self.assertEqual(iut.client.ec.as_hashedid8(), ec.as_hashedid8())

    def test_tp_secpki_its_s_enr_rcv_02_bv(self):
        """SECPKI_ITS-S_ENR_RCV_02_BV: a positive EnrolmentResponse (responseCode 0, EC)
        switches the IUT to 'enrolled' with that EC."""
        iut = _Iut()
        ec = iut.enrol()
        self.assertEqual(iut.client.state, "enrolled")
        self.assertEqual(ec.certificate, iut.pki.issued_ecs[-1])
        self.assertEqual(Certificate.from_dict(ec.certificate).verification_key(),
                         iut.enrolment.inner["publicKeys"]["verificationKey"])

    def test_tp_secpki_its_s_enr_rcv_03_be(self):
        """SECPKI_ITS-S_ENR_RCV_03_BE: an EC without AID_CERT_REQ in its appPermissions is
        not used for re-enrolment: the next request is an initial request."""
        iut = _Iut()
        iut.pki.ec_permissions = [{"psid": 36}]
        iut.enrol()
        self.assertEqual(iut.client.state, "enrolled")
        iut.enrol()
        self.assertEqual(_outer_signer(iut.enrolment), ("self", None))
        self.assertEqual(iut.enrolment.inner["itsId"], ITS_ID)

    def test_tp_secpki_its_s_enr_rcv_04_be(self):
        """SECPKI_ITS-S_ENR_RCV_04_BE: an EC whose AID_CERT_REQ SSP has the enrolment
        request bit 0 is not used for re-enrolment: the next request is initial."""
        iut = _Iut()
        iut.pki.ec_permissions = [{"psid": PSID_CERT_REQUEST, "ssp": ("bitmapSsp", bytes([1, 0x40]))}]
        iut.enrol()
        iut.enrol()
        self.assertEqual(_outer_signer(iut.enrolment), ("self", None))
        self.assertEqual(iut.enrolment.inner["itsId"], ITS_ID)


# ─── Authorization (TS 103 525-2 clause 5.2.3) ─────────────────────────────


class TestPkiItssAuthorization(unittest.TestCase):
    """SECPKI_ITS-S_AUTH: authorization request (TS 102 941 clause 6.2.3.3.1)."""

    def enrolled(self, **kwargs):
        iut = _Iut(**kwargs)
        iut.enrol()
        return iut

    def test_tp_secpki_its_s_auth_01_bv(self):
        """SECPKI_ITS-S_AUTH_01_BV: triggered to request an AT, the enrolled IUT sends an
        EtsiTs103097Data-Encrypted to the AA."""
        iut = self.enrolled()
        iut.authorize()
        url, content, content_type = iut.transport.posts[-1]
        self.assertEqual((url, content_type), (iut.transport.aa_url, "application/x-its-request"))
        self.assertEqual(decode("Ieee1609Dot2Data", content)["content"][0], "encryptedData")
        self.assertEqual(iut.client.state, "authorized")

    def test_tp_secpki_its_s_auth_02_bv(self):
        """SECPKI_ITS-S_AUTH_02_BV: encrypted to one AA only: recipients of size 1, a
        certRecipInfo with the HashedId8 of the AA certificate."""
        iut = self.enrolled()
        iut.authorize()
        recipients = iut.authorization.encrypted["content"][1]["recipients"]
        self.assertEqual(len(recipients), 1)
        self.assertEqual(recipients[0][0], "certRecipInfo")
        self.assertEqual(recipients[0][1]["recipientId"], iut.pki.aa.own.as_hashedid8())

    def test_tp_secpki_its_s_auth_03_bv(self):
        """SECPKI_ITS-S_AUTH_03_BV: the data is encrypted with a symmetric key that the AA
        decrypts with the private key of its encryptionKey (AA_ENC_PUB_KEY)."""
        iut = self.enrolled()
        iut.authorize()
        key_choice = iut.pki.aa.own.certificate["toBeSigned"]["encryptionKey"]["publicKey"][0]
        self.assertEqual(iut.authorization.encrypted["content"][1]["recipients"][0][1]["encKey"][0], key_choice)
        self.assertEqual(iut.authorization.etsi["content"][0], "authorizationRequest")

    def test_tp_secpki_its_s_auth_04_bv(self):
        """SECPKI_ITS-S_AUTH_04_BV: a request never reuses the encryption key or the nonce
        of the N previous requests (N = 4)."""
        iut = self.enrolled()
        for _ in range(5):
            iut.authorize()
        nonces = [r.encrypted["content"][1]["ciphertext"][1]["nonce"] for r in iut.pki.authorizations]
        keys = [r.session_key for r in iut.pki.authorizations]
        enc_keys = [r.encrypted["content"][1]["recipients"][0][1]["encKey"][1]["c"] for r in iut.pki.authorizations]
        for values in (nonces, keys, enc_keys):
            self.assertEqual(len(set(values)), 5)

    def test_tp_secpki_its_s_auth_05_bv(self):
        """SECPKI_ITS-S_AUTH_05_BV: EtsiTs102941Data version 1 with an authorizationRequest."""
        iut = self.enrolled()
        iut.authorize()
        self.assertEqual(iut.authorization.etsi["version"], 1)
        self.assertEqual(iut.authorization.etsi["content"][0], "authorizationRequest")

    def test_tp_secpki_its_s_auth_06_bv(self):
        """SECPKI_ITS-S_AUTH_06_BV: each request has a new verificationKey and hmacKey, and
        no encryptionKey (the IUT requests none), differing from the N previous ones."""
        iut = self.enrolled()
        for _ in range(4):
            iut.authorize()
        requests = [r.inner for r in iut.pki.authorizations]
        self.assertEqual(len({repr(r["publicKeys"]["verificationKey"]) for r in requests}), 4)
        self.assertEqual(len({r["hmacKey"] for r in requests}), 4)
        for request in requests:
            self.assertNotIn("encryptionKey", request["publicKeys"])

    def test_tp_secpki_its_s_auth_07_bv(self):
        """SECPKI_ITS-S_AUTH_07_BV: keyTag = HMAC-SHA256(hmacKey, verificationKey ||
        encryptionKey) truncated to 128 bits (clause 6.2.3.3.1)."""
        iut = self.enrolled()
        iut.authorize()
        inner = iut.authorization.inner
        expected = hmac.new(inner["hmacKey"], encode(
            "PublicVerificationKey", inner["publicKeys"]["verificationKey"]), hashlib.sha256).digest()[:16]
        self.assertEqual(inner["sharedAtRequest"]["keyTag"], expected)
        self.assertTrue(iut.authorization.checks["keyTag"])

    def test_tp_secpki_its_s_auth_08_bv(self):
        """SECPKI_ITS-S_AUTH_08_BV: sharedAtRequest.eaId is the HashedId8 of the EA that
        issued the EC."""
        iut = self.enrolled()
        iut.authorize()
        self.assertEqual(iut.authorization.inner["sharedAtRequest"]["eaId"], iut.pki.ea.own.as_hashedid8())
        self.assertEqual(iut.client.ec.get_issuer_hashedid8(), iut.pki.ea.own.as_hashedid8())

    def test_tp_secpki_its_s_auth_09_bv(self):
        """SECPKI_ITS-S_AUTH_09_BV: sharedAtRequest.certificateFormat is 1."""
        iut = self.enrolled()
        iut.authorize()
        self.assertEqual(iut.authorization.inner["sharedAtRequest"]["certificateFormat"], 1)

    def test_tp_secpki_its_s_auth_10_bv(self):
        """SECPKI_ITS-S_AUTH_10_BV: requestedSubjectAttributes contain appPermissions and no
        certIssuePermissions."""
        iut = self.enrolled()
        iut.authorize()
        attributes = iut.authorization.inner["sharedAtRequest"]["requestedSubjectAttributes"]
        self.assertIn("appPermissions", attributes)
        self.assertNotIn("certIssuePermissions", attributes)

    def ec_signature(self, iut):
        return iut.authorization.ec_signature["content"][1]

    def test_tp_secpki_its_s_auth_11_bv(self):
        """SECPKI_ITS-S_AUTH_11_BV: the ecSignature (SignedExternalPayload) payload is
        extDataHash, the SHA-256 hash of the sharedATRequest."""
        iut = self.enrolled()
        iut.authorize()
        expected = hashlib.sha256(encode("SharedAtRequest", iut.authorization.inner["sharedAtRequest"])).digest()
        self.assertEqual(self.ec_signature(iut)["tbsData"]["payload"], {"extDataHash": ("sha256HashedData", expected)})

    def test_tp_secpki_its_s_auth_12_bv(self):
        """SECPKI_ITS-S_AUTH_12_BV: the ecSignature headerInfo has psid AID_PKI_CERT_REQUEST
        and generationTime only."""
        iut = self.enrolled()
        iut.authorize()
        header = self.ec_signature(iut)["tbsData"]["headerInfo"]
        self.assertEqual(set(header), {"psid", "generationTime"})
        self.assertEqual(header["psid"], PSID_CERT_REQUEST)

    def test_tp_secpki_its_s_auth_13_bv(self):
        """SECPKI_ITS-S_AUTH_13_BV: the ecSignature hashId is a supported hash algorithm
        (that of the EC key)."""
        iut = self.enrolled()
        iut.authorize()
        self.assertEqual(self.ec_signature(iut)["hashId"], iut.client.ec.hash_name())

    def test_tp_secpki_its_s_auth_14_bv(self):
        """SECPKI_ITS-S_AUTH_14_BV: the ecSignature signer is the HashedId8 of CERT_EC and
        the signature verifies with the EC verification key."""
        iut = self.enrolled()
        iut.authorize()
        ec = iut.client.ec
        self.assertEqual(self.ec_signature(iut)["signer"], ("digest", ec.as_hashedid8()))
        self.assertTrue(signed_ok(iut.pki.backend, iut.authorization.ec_signature, ec.verification_key(),
                                  ec.to_canonical().encode()))

    def test_tp_secpki_its_s_auth_15_bv(self):
        """SECPKI_ITS-S_AUTH_15_BV: (privacy) encryptedEcSignature with one certRecipInfo for
        CERT_EA (encKey of the EA key type) whose ciphertext is the SignedExternalPayload."""
        iut = self.enrolled()
        iut.authorize()
        choice, encrypted = iut.authorization.inner["ecSignature"]
        self.assertEqual(choice, "encryptedEcSignature")
        recipients = encrypted["content"][1]["recipients"]
        self.assertEqual(len(recipients), 1)
        self.assertEqual(recipients[0][0], "certRecipInfo")
        self.assertEqual(recipients[0][1]["recipientId"], iut.pki.ea.own.as_hashedid8())
        self.assertEqual(recipients[0][1]["encKey"][0],
                         iut.pki.ea.own.certificate["toBeSigned"]["encryptionKey"]["publicKey"][0])
        self.assertIn("extDataHash", self.ec_signature(iut)["tbsData"]["payload"])

    def test_tp_secpki_its_s_auth_17_bv(self):
        """SECPKI_ITS-S_AUTH_17_BV: without proof of possession the encrypted data is an
        unsecured Ieee1609Dot2Data (unsecuredData)."""
        iut = self.enrolled(pop=False)
        iut.authorize()
        self.assertEqual(iut.authorization.outer["content"][0], "unsecuredData")
        self.assertEqual(iut.client.state, "authorized")

    def test_tp_secpki_its_s_auth_18_bv(self):
        """SECPKI_ITS-S_AUTH_18_BV: with proof of possession the request is a self-signed
        EtsiTs103097Data-Signed (valid hashId, headerInfo psid AID_PKI_CERT_REQUEST and
        generationTime only), signed with the key of its verificationKey."""
        iut = self.enrolled(pop=True)
        iut.authorize()
        outer = iut.authorization.outer
        signed = outer["content"][1]
        self.assertEqual(outer["content"][0], "signedData")
        self.assertEqual(signed["hashId"], "sha256")
        self.assertEqual(set(signed["tbsData"]["headerInfo"]), {"psid", "generationTime"})
        self.assertEqual(signed["tbsData"]["headerInfo"]["psid"], PSID_CERT_REQUEST)
        self.assertEqual(signed["signer"], ("self", None))
        self.assertTrue(signed_ok(iut.pki.backend, outer,
                                  iut.authorization.inner["publicKeys"]["verificationKey"], b""))

    def test_tp_secpki_its_s_auth_19_bv(self):
        """SECPKI_ITS-S_AUTH_19_BV: the ecSignature signer (the EC) is permitted to sign it:
        appPermissions with AID_CERT_REQ, SSP version 1 and the authorization request bit
        (clause B.5: 40h, bit 1 of Table B.5); an EC without it is not used."""
        iut = self.enrolled()
        iut.authorize()
        ssp = _app_permission(iut.client.ec.certificate, PSID_CERT_REQUEST)["ssp"][1]
        self.assertEqual(ssp[0], 1)
        self.assertTrue(ssp[1] & 0x40)
        iut = _Iut()
        iut.pki.ec_permissions = [{"psid": PSID_CERT_REQUEST, "ssp": ("bitmapSsp", bytes([1, 0x80]))}]
        iut.enrol()
        with self.assertRaises(AuthorizationError):
            iut.authorize()
        self.assertEqual(iut.pki.authorizations, [])


# ─── CTL and CRL handling (TS 103 525-2 clauses 5.2.4 and 5.2.6) ───────────


class _Trust:
    """Backend and trust anchors for a station (as the PKI of the SEC tests)."""

    def __init__(self, backend, roots, aas):
        self.backend, self.roots, self.aas = backend, list(roots), list(aas)


def _signed_list(issuer: OwnCertificate, backend, psid, choice, content, clock) -> bytes:
    """A CTL / CRL message signed by ``issuer`` (signer certificate, clause 6.3.4)."""
    etsi = encode("EtsiTs102941Data", {"version": 1, "content": (choice, content)})
    tbs = {"payload": {"data": {"protocolVersion": 3, "content": ("unsecuredData", etsi)}},
           "headerInfo": {"psid": psid, "generationTime": clock.its_us()}}
    signature = issuer.sign_message(backend, encode("ToBeSignedData", tbs))
    return encode("Ieee1609Dot2Data", {"protocolVersion": 3, "content": ("signedData", {
        "hashId": "sha256", "tbsData": tbs, "signer": ("certificate", [issuer.certificate]),
        "signature": signature})})


class _TrustWorld:
    """TLM, Root CAs, AAs and ATs of the test system; the IUT station and a tester."""

    CPOC, DC = "https://cpoc.ts/", "https://dc.ts/"

    def __init__(self, test):
        self.test = test
        self.clock = _Clock()
        self.backend = PythonECDSABackend()
        self.tlm = _ca(self.backend, "EU-TLM", None, 2,
                       appPermissions=[{"psid": PSID_CTL, "ssp": ("bitmapSsp", bytes([1, 0xC8]))}])
        self.rca = _ca(self.backend, "rca", None, 2, appPermissions=ROOT_PERMISSIONS)
        self.aa = _ca(self.backend, "aa", self.rca, 1)
        self.sequence = {}

    def root(self, name="rca-new"):
        return _ca(self.backend, name, None, 2, appPermissions=ROOT_PERMISSIONS)

    def at(self, aa):
        return OwnCertificate.initialize_certificate(
            backend=self.backend, to_be_signed_certificate=_at_tbs(appPermissions=APP_PERMISSIONS), issuer=aa)

    def iut(self, roots, aas):
        station = _Station(self.clock, _Trust(self.backend, roots, aas), (self.at(self.aa),))
        library = station.verify_service.certificate_library
        station.trust = TrustStore(library, self.backend, [self.tlm], clock=self.clock.unix)
        return station

    def tester(self, aa, root, n=9):
        return _Station(self.clock, _Trust(self.backend, [root], [aa]), (self.at(aa),), n=n, station_id=TS_ID)

    def _next(self, issuer):
        key = issuer.as_hashedid8()
        self.sequence[key] = self.sequence.get(key, -1) + 1
        return self.sequence[key]

    def ectl(self, roots, full=True, deletes=(), next_update_s=3600):
        commands = [("add", ("rca", {"selfsignedRootCa": r.certificate})) for r in roots]
        commands.append(("add", ("tlm", {"selfSignedTLMCertificate": self.tlm.certificate, "accessPoint": self.CPOC})))
        commands += [("delete", ("cert", d.as_hashedid8())) for d in deletes]
        content = {"version": 1, "nextUpdate": time32(self.clock.unix()) + next_update_s, "isFullCtl": full,
                   "ctlSequence": self._next(self.tlm), "ctlCommands": commands}
        return _signed_list(self.tlm, self.backend, PSID_CTL, "certificateTrustListTlm", content, self.clock)

    def rca_ctl(self, rca, aas, next_update_s=3600, full=True):
        commands = [("add", ("aa", {"aaCertificate": aa.certificate, "accessPoint": "https://aa.ts/"})) for aa in aas]
        commands.append(("add", ("dc", {"url": self.DC, "cert": [rca.as_hashedid8()]})))
        content = {"version": 1, "nextUpdate": time32(self.clock.unix()) + next_update_s, "isFullCtl": full,
                   "ctlSequence": self._next(rca), "ctlCommands": commands}
        return _signed_list(rca, self.backend, PSID_CTL, "certificateTrustListRca", content, self.clock)

    def crl(self, rca, revoked, this_update_offset=0):
        now = time32(self.clock.unix()) + this_update_offset
        content = {"version": 1, "thisUpdate": now, "nextUpdate": now + 3600,
                   "entries": [c.as_hashedid8() for c in revoked]}
        return _signed_list(rca, self.backend, PSID_CRL, "certificateRevocationList", content, self.clock)

    def assert_cam(self, iut, tester, accepted, at_ms, mutate=None):
        """A CAM of ``tester`` (signed with its certificate) is accepted / discarded by the IUT."""
        raw = tester.certificate_cam(at_ms).raw
        if mutate is not None:
            raw = _resign(raw, tester.ats[0], self.backend, mutate)
        before = len(iut.cams)
        iut.deliver(raw, at_ms)
        self.test.assertEqual(len(iut.cams), before + (1 if accepted else 0))


class TestPkiItssCtl(unittest.TestCase):
    """SECPKI_ITS-S_CTL: CTL handling (TS 102 941 clauses 6.3.4 to 6.3.6)."""

    def test_tp_secpki_its_s_ctl_01_bv(self):
        """SECPKI_ITS-S_CTL_01_BV: after a TLM CTL containing CERT_RCA_NEW, a CAM signed with
        an AT of an AA of CERT_RCA_NEW is accepted (the AA delivered as requestedCertificate)."""
        w = _TrustWorld(self)
        rca_new = w.root()
        aa_new = _ca(w.backend, "aa-new", rca_new, 1)
        iut, tester = w.iut([w.rca], [w.aa]), w.tester(aa_new, rca_new)
        with_aa = _header("requestedCertificate", deepcopy(aa_new.certificate))
        w.assert_cam(iut, tester, False, 0, with_aa)                         # RCA_NEW not trusted
        self.assertEqual(iut.trust.process(w.ectl([w.rca, rca_new])), "ectl")
        w.assert_cam(iut, tester, True, 100, with_aa)

    def test_tp_secpki_its_s_ctl_02_bv(self):
        """SECPKI_ITS-S_CTL_02_BV: after a TLM CTL not containing CERT_RCA (trusted from the
        previous ECTL), CAMs chained to CERT_RCA are rejected."""
        w = _TrustWorld(self)
        rca_other = w.root("rca-other")
        iut = w.iut([], [])
        iut.trust.process(w.ectl([w.rca, rca_other]))
        iut.verify_service.certificate_library.learn_ca_certificate(w.aa.certificate)
        tester = w.tester(w.aa, w.rca)
        w.assert_cam(iut, tester, True, 0)
        iut.trust.process(w.ectl([rca_other]))                               # full ECTL without RCA
        self.assertNotIn(w.rca.as_hashedid8(), iut.verify_service.certificate_library.known_root_certificates)
        w.assert_cam(iut, tester, False, 100)
        tester_digest = tester.cam(200).raw                                  # also with the digest
        before = len(iut.cams)
        iut.deliver(tester_digest, 200)
        self.assertEqual(len(iut.cams), before)

    def test_tp_secpki_its_s_ctl_03_bv(self):
        """SECPKI_ITS-S_CTL_03_BV: after the CTL of CERT_RCA containing CERT_AA_NEW, a CAM
        signed with an AT issued by CERT_AA_NEW is accepted."""
        w = _TrustWorld(self)
        aa_new = _ca(w.backend, "aa-new", w.rca, 1)
        iut, tester = w.iut([w.rca], [w.aa]), w.tester(aa_new, w.rca)
        w.assert_cam(iut, tester, False, 0)                                  # AA_NEW unknown
        self.assertEqual(iut.trust.process(w.rca_ctl(w.rca, [w.aa, aa_new])), "rca-ctl")
        w.assert_cam(iut, tester, True, 100)

    def test_tp_secpki_its_s_ctl_04_bv(self):
        """SECPKI_ITS-S_CTL_04_BV: when the TLM CTL (nextUpdate T1, CPOC URL) expires, the IUT
        requests a new CTL from the CPOC (TS 102 941 Annex E.4: getectl)."""
        w = _TrustWorld(self)
        iut = w.iut([], [])
        iut.trust.process(w.ectl([w.rca], next_update_s=60))
        transport = Transport(TsPki())
        self.assertEqual(asyncio.run(iut.trust.refresh(transport)), [])     # T1 not reached
        w.clock.ms = 61_000
        url = f"{w.CPOC}getectl/{w.tlm.as_hashedid8().hex().upper()}"
        transport.files[url] = w.ectl([w.rca])
        self.assertEqual(asyncio.run(iut.trust.refresh(transport)), [url])
        self.assertEqual(transport.gets, [url])
        self.assertEqual(iut.trust.lists[("ectl", w.tlm.as_hashedid8())].sequence, 1)

    def test_tp_secpki_its_s_ctl_05_bv(self):
        """SECPKI_ITS-S_CTL_05_BV: when the RCA CTL (nextUpdate T1, RCA DC URL) expires, the
        IUT requests a new CTL from the RCA DC (TS 102 941 Annex D.1: getctl)."""
        w = _TrustWorld(self)
        iut = w.iut([w.rca], [])
        iut.trust.process(w.rca_ctl(w.rca, [w.aa], next_update_s=60))
        transport = Transport(TsPki())
        self.assertEqual(asyncio.run(iut.trust.refresh(transport)), [])
        w.clock.ms = 61_000
        url = f"{w.DC}getctl/{w.rca.as_hashedid8().hex().upper()}"
        transport.files[url] = w.rca_ctl(w.rca, [w.aa])
        self.assertEqual(asyncio.run(iut.trust.refresh(transport)), [url])
        self.assertEqual(transport.gets, [url])


class TestPkiItssCrl(unittest.TestCase):
    """SECPKI_ITS-S_CRL: CRL handling (TS 102 941 clauses 6.3.3 and 6.3.6)."""

    def test_tp_secpki_its_s_crl_01_bv(self):
        """SECPKI_ITS-S_CRL_01_BV: the IUT accepts the CRL information of its Root CA
        (signed by CERT_IUT_A_RCA); one signed by another key is rejected."""
        w = _TrustWorld(self)
        iut = w.iut([w.rca], [w.aa])
        other = w.root("not-trusted")
        with self.assertRaises(TrustListError):
            iut.trust.process(w.crl(other, []))
        self.assertEqual(iut.trust.process(w.crl(w.rca, [])), "crl")
        self.assertIn(("crl", w.rca.as_hashedid8()), iut.trust.lists)

    def crl_iut(self):
        iut = _Iut()
        iut.enrol()
        iut.authorize()
        library = CertificateLibrary(iut.pki.backend, [iut.pki.root], [iut.pki.aa.own, iut.pki.ea.own], [])
        trust = TrustStore(library, iut.pki.backend, clock=lambda: iut.now, on_revoked=iut.client.revoke)
        self.assertEqual(iut.client.state, "authorized")
        return iut, trust, _Clock()

    def test_tp_secpki_its_s_crl_02_bv(self):
        """SECPKI_ITS-S_CRL_02_BV: a CRL revoking the AA of the IUT's AT switches the IUT
        to 'enrolled'."""
        iut, trust, clock = self.crl_iut()
        trust.process(_signed_list(iut.pki.root, iut.pki.backend, PSID_CRL, "certificateRevocationList", {
            "version": 1, "thisUpdate": time32(iut.now), "nextUpdate": time32(iut.now) + 3600,
            "entries": [iut.pki.aa.own.as_hashedid8()]}, clock))
        self.assertEqual(iut.client.state, "enrolled")

    def test_tp_secpki_its_s_crl_03_bv(self):
        """SECPKI_ITS-S_CRL_03_BV: a CRL revoking the EA of the IUT's EC switches the
        authorized IUT to the initial state."""
        iut, trust, clock = self.crl_iut()
        trust.process(_signed_list(iut.pki.root, iut.pki.backend, PSID_CRL, "certificateRevocationList", {
            "version": 1, "thisUpdate": time32(iut.now), "nextUpdate": time32(iut.now) + 3600,
            "entries": [iut.pki.ea.own.as_hashedid8()]}, clock))
        self.assertEqual(iut.client.state, "initialized")

    def test_tp_secpki_its_s_crl_04_bv(self):
        """SECPKI_ITS-S_CRL_04_BV: a CRL revoking the IUT's Root CA switches the authorized
        IUT to the initial state."""
        iut, trust, clock = self.crl_iut()
        trust.process(_signed_list(iut.pki.root, iut.pki.backend, PSID_CRL, "certificateRevocationList", {
            "version": 1, "thisUpdate": time32(iut.now), "nextUpdate": time32(iut.now) + 3600,
            "entries": [iut.pki.root.as_hashedid8()]}, clock))
        self.assertEqual(iut.client.state, "initialized")

    def test_tp_secpki_its_s_crl_05_bv(self):
        """SECPKI_ITS-S_CRL_05_BV: after a CRL revoking CERT_IUT_A_B_AA, messages signed with
        an AT of that AA (already accepted before) are discarded; another AA still works."""
        w = _TrustWorld(self)
        aa_b = _ca(w.backend, "aa-b", w.rca, 1)
        iut = w.iut([w.rca], [w.aa, aa_b])
        tester_b, tester_a = w.tester(aa_b, w.rca), w.tester(w.aa, w.rca, n=10)
        w.assert_cam(iut, tester_b, True, 0)
        iut.trust.process(w.crl(w.rca, [aa_b]))
        w.assert_cam(iut, tester_b, False, 1000)                              # certificate signer
        digest = tester_b.cam(1100).raw                                       # digest signer
        before = len(iut.cams)
        iut.deliver(digest, 1100)
        self.assertEqual(len(iut.cams), before)
        w.assert_cam(iut, tester_a, True, 1200)


# ─── Request repetition (TS 103 525-2 clauses 5.2.2.3 and 5.2.3.3) ─────────

_TH1, _N1, _TH2 = 10.0, 3, 100.0


class _RetryIut(_Iut):
    """The IUT with the repetition of TS 103 601 clauses 5.1 / 5.2 (PIXIT_*_TIMEOUT_TH1
    = 10 s, PIXIT_*_MAX_N1 = 3, PIXIT_*_TIMEOUT_TH2 = 100 s); waiting advances its clock
    and the transport records the instant of every POST."""

    def __init__(self, th1=_TH1, n1=_N1, th2=_TH2):
        super().__init__()
        policy = RetryPolicy(th1=th1, n1=n1, th2=th2)
        self.client.enrolment_retry = policy
        self.client.authorization_retry = policy
        self.transport.clock = lambda: self.now

        async def sleep(seconds):
            self.now += seconds
        self.client.sleep = sleep

    def posts_to(self, url):
        return [(t, content) for t, (u, content, _) in zip(self.transport.times, self.transport.posts) if u == url]


class TestPkiItssEnrolmentRepetition(unittest.TestCase):
    """SECPKI_ITS-S_ENR_REP: repetition of the enrolment request (TS 103 601 clause 5.1)."""

    def test_tp_secpki_its_s_enr_rep_01_bv(self):
        """SECPKI_ITS-S_ENR_REP_01_BV: the Enrolment Response to the request sent at T1 is
        not received: at T1 + PIXIT_ENR_TIMEOUT_TH1 the IUT sends an EnrolmentRequestMessage
        to the EA."""
        iut = _RetryIut()
        iut.transport.lose = 1
        t1 = iut.now
        iut.enrol()
        self.assertEqual([t for t, _ in iut.posts_to(iut.transport.ea_url)], [t1, t1 + _TH1])

    def test_tp_secpki_its_s_enr_rep_02_bv(self):
        """SECPKI_ITS-S_ENR_REP_02_BV: the re-sent Enrolment Request is the message M sent
        first (same encrypted message, hence the same AES key k, clause 5.1.2)."""
        iut = _RetryIut()
        iut.transport.lose = 1
        ec = iut.enrol()
        (_, first), (_, second) = iut.posts_to(iut.transport.ea_url)
        self.assertEqual(second, first)
        self.assertEqual(len(iut.pki.enrolments), 1)                 # one request M
        self.assertEqual(iut.client.ec.as_hashedid8(), ec.as_hashedid8())

    def test_tp_secpki_its_s_enr_rep_03_bv(self):
        """SECPKI_ITS-S_ENR_REP_03_BV: having sent the Enrolment Request more than once, the
        IUT receives the Enrolment Response and stops sending Enrolment Requests."""
        iut = _RetryIut()
        iut.transport.lose = 2
        iut.enrol()
        self.assertEqual(len(iut.posts_to(iut.transport.ea_url)), 3)
        self.assertEqual(iut.client.state, "enrolled")
        iut.now += 10 * _TH1                                          # no repetition left
        self.assertEqual(len(iut.transport.posts), 3)

    def test_tp_secpki_its_s_enr_rep_04_bv(self):
        """SECPKI_ITS-S_ENR_REP_04_BV: after PIXIT_ENR_MAX_N1 Enrolment Request messages the
        IUT stops sending Enrolment Requests (and gives up the request)."""
        iut = _RetryIut()
        iut.transport.lose = 99
        with self.assertRaises(PkiTransportError):
            iut.enrol()
        posts = iut.posts_to(iut.transport.ea_url)
        self.assertEqual(len(posts), _N1)
        self.assertEqual({content for _, content in posts}, {posts[0][1]})
        self.assertEqual(iut.client.state, "initialized")

    def test_tp_secpki_its_s_enr_rep_05_bv(self):
        """SECPKI_ITS-S_ENR_REP_05_BV (both TPs of this ID): the IUT stops sending the
        Enrolment Request when the local time reaches T1 + PIXIT_ENR_TIMEOUT_TH2 (TH2 =
        25 s, TH1 = 10 s, N1 = 10: transmissions at T1, T1 + 10 and T1 + 20 only)."""
        iut = _RetryIut(th1=10.0, n1=10, th2=25.0)
        iut.transport.lose = 99
        t1 = iut.now
        with self.assertRaises(PkiTransportError):
            iut.enrol()
        self.assertEqual([t for t, _ in iut.posts_to(iut.transport.ea_url)], [t1, t1 + 10, t1 + 20])


class TestPkiItssAuthorizationRepetition(unittest.TestCase):
    """SECPKI_ITS-S_AUTH_REP: repetition of the authorization request (TS 103 601
    clause 5.2; PICS_SECPKI_AUTHORIZATION_RETRY, an ITS-S without privacy requirements)."""

    @staticmethod
    def _enrolled(lose):
        iut = _RetryIut()
        iut.enrol()
        iut.transport.lose = lose
        return iut

    def test_tp_secpki_its_s_auth_rep_01_bv(self):
        """SECPKI_ITS-S_AUTH_REP_01_BV: the Authorization Response to the request sent at T1
        is not received: at T1 + PIXIT_AUTH_TIMEOUT_TH1 the IUT sends an
        AuthorizationRequestMessage (to the AA; the TP text says EA)."""
        iut = self._enrolled(1)
        t1 = iut.now
        iut.authorize()
        self.assertEqual([t for t, _ in iut.posts_to(iut.transport.aa_url)], [t1, t1 + _TH1])

    def test_tp_secpki_its_s_auth_rep_02_bv(self):
        """SECPKI_ITS-S_AUTH_REP_02_BV: the re-sent AuthorizationRequestMessage is the
        message M sent first to the AA."""
        iut = self._enrolled(1)
        iut.authorize()
        (_, first), (_, second) = iut.posts_to(iut.transport.aa_url)
        self.assertEqual(second, first)
        self.assertEqual(len(iut.pki.authorizations), 1)

    def test_tp_secpki_its_s_auth_rep_03_bv(self):
        """SECPKI_ITS-S_AUTH_REP_03_BV: having sent the Authorization Request more than once,
        the IUT receives the Authorization Response and stops sending requests to the AA."""
        iut = self._enrolled(2)
        iut.authorize()
        self.assertEqual(len(iut.posts_to(iut.transport.aa_url)), 3)
        self.assertEqual(iut.client.state, "authorized")

    def test_tp_secpki_its_s_auth_rep_04_bv(self):
        """SECPKI_ITS-S_AUTH_REP_04_BV: after PIXIT_AUTH_MAX_N1 Authorization Request
        messages the IUT stops sending Authorization Requests."""
        iut = self._enrolled(99)
        with self.assertRaises(PkiTransportError):
            iut.authorize()
        self.assertEqual(len(iut.posts_to(iut.transport.aa_url)), _N1)
        self.assertEqual(iut.client.state, "enrolled")

    def test_tp_secpki_its_s_auth_rep_05_bv(self):
        """SECPKI_ITS-S_AUTH_REP_05_BV: the IUT stops sending the Authorization Request when
        the local time reaches T1 + PIXIT_AUTH_TIMEOUT_TH2 (TH2 = 25 s, TH1 = 10 s, N1 = 10)."""
        iut = _RetryIut(th1=10.0, n1=10, th2=25.0)
        iut.enrol()
        iut.transport.lose = 99
        t1 = iut.now
        with self.assertRaises(PkiTransportError):
            iut.authorize()
        self.assertEqual([t for t, _ in iut.posts_to(iut.transport.aa_url)], [t1, t1 + 10, t1 + 20])


# ─── CTL and CRL distribution (TS 103 525-2 clauses 5.2.5 and 5.2.7) ───────

_D1, _D2 = 60.0, 10.0


def _frames(station, since_ms=0):
    """The unsecured SHB of ``station`` sent at or after ``since_ms``: (ms, BTP-B
    destination port, payload). Basic (4) + Common (8) + SHB (28) + BTP-B (4) headers."""
    frames = []
    for ms, raw in station.log:
        if ms < since_ms or BasicHeader.decode_from_bytes(raw[:4]).nh != BasicNH.COMMON_HEADER:
            continue
        common = CommonHeader.decode_from_bytes(raw[4:12])
        if common.ht == HeaderType.TSB and common.hst == TopoBroadcastHST.SINGLE_HOP:
            frames.append((ms, int.from_bytes(raw[40:42], "big"), raw[44:]))
    return frames


class _CxlWorld(_TrustWorld):
    """The trust world with the CRL / CTL distribution service on the IUT (PIXIT D1 =
    60 s, D2 = 10 s, f1 = f2 = 1 Hz) and neighbours broadcasting and requesting lists."""

    def iut(self, roots, aas, redistribute=True):  # pylint: disable=arguments-differ
        def ports(station):
            for port in (CTL_PORT, CRL_PORT):
                station.btp.register_indication_callback_btp(
                    port, lambda indication, st=station: st.cxl.on_btp_indication(indication),
                    accept_unsecured=True)
        station = _Station(self.clock, _Trust(self.backend, roots, aas), (self.at(self.aa),),
                           before_freeze=ports)
        station.trust = TrustStore(station.verify_service.certificate_library, self.backend, [self.tlm],
                                   clock=self.clock.unix)
        station.cxl = TrustListDistribution(
            station.trust, station.btp, sign_service=station.sign_service,
            verify_service=station.verify_service, clock=self.clock.unix,
            config=DistributionConfig(redistribute=redistribute, d1=_D1, d2=_D2))
        return station

    def delta(self, kind, entries=()):
        """A Delta CTL of the TLM (``"ectl"``) or of the Root CA (``"rca-ctl"``)."""
        if kind == "ectl":
            return self.ectl(list(entries), full=False)
        return self.rca_ctl(self.rca, list(entries), full=False)

    def issuer(self, kind):
        return (self.tlm if kind == "ectl" else self.rca).as_hashedid8()

    def run(self, iut, until_ms, step_ms=100):
        """Advance the clock to ``until_ms`` in steps, running the distribution timers."""
        for t in range(self.clock.ms + step_ms, until_ms + 1, step_ms):
            self.clock.ms = t
            iut.cxl.tick()

    def neighbour_broadcast(self, iut, message, port):
        """A neighbour broadcasts ``message`` (unsecured SHB) and the IUT receives it."""
        neighbour = self.tester(self.aa, self.rca)
        neighbour.btp.btp_data_request(BTPDataRequest(
            btp_type=CommonNH.BTP_B, destination_port=port,
            gn_packet_transport_type=PacketTransportType(header_type=HeaderType.TSB,
                                                         header_subtype=TopoBroadcastHST.SINGLE_HOP),
            security_profile=SecurityProfile.UNSECURED, data=message, length=len(message)))
        iut.deliver(neighbour.log[-1][1])

    def neighbour_request(self, iut, ext_id, request, at_ms):
        """A neighbour's CAM carrying the P2P request ``request``, received by the IUT."""
        neighbour = self.tester(self.aa, self.rca)
        neighbour.sign_service.trust_list_request = lambda: (ext_id, request)
        before = len(iut.cams)
        iut.deliver(neighbour.certificate_cam(at_ms).raw, at_ms)
        self.test.assertEqual(len(iut.cams), before + 1)

    def requests_in_cam(self, iut, at_ms):
        """The ETSI originating header extensions of the next CAM of the IUT."""
        cam = iut.cam(at_ms)
        blocks = cam.header.get("contributedExtensions", [])
        self.test.assertEqual([b["contributorId"] for b in blocks], [2] if blocks else [])
        return decode_requests(blocks)


class TestPkiItssCtlDistribution(unittest.TestCase):
    """SECPKI_ITS-S_CTLDIST: Delta CTL distribution (TS 103 601 clauses 5.3, 5.4). Each
    TP is run for the ECTL (TLM) and for the Root CA CTL."""

    KINDS = (("ectl", "certificateTrustListTlm"), ("rca-ctl", "certificateTrustListRca"))

    def test_tp_secpki_its_s_ctldist_01_bv(self):
        """SECPKI_ITS-S_CTLDIST_01_BV: the IUT without CTL information receives a Delta CTL
        (from its DC) and starts broadcasting it."""
        for kind, _ in self.KINDS:
            with self.subTest(kind):
                w = _CxlWorld(self)
                iut = w.iut([w.rca], [w.aa])
                self.assertEqual(iut.trust.lists, {})
                delta = w.delta(kind)
                iut.cxl.receive(delta, from_dc=True)
                self.assertEqual([payload for _, _, payload in _frames(iut)], [delta])

    def test_tp_secpki_its_s_ctldist_02_bv(self):
        """SECPKI_ITS-S_CTLDIST_02_BV: the IUT holding a CTL with ctlSequence SN receives a
        Delta CTL with a greater ctlSequence and starts broadcasting it."""
        for kind, _ in self.KINDS:
            with self.subTest(kind):
                w = _CxlWorld(self)
                iut = w.iut([w.rca], [w.aa])
                full = w.ectl([w.rca]) if kind == "ectl" else w.rca_ctl(w.rca, [w.aa])
                iut.cxl.receive(full, from_dc=True)                  # SN = 0 (full: not broadcast)
                self.assertEqual(_frames(iut), [])
                delta = w.delta(kind)
                iut.cxl.receive(delta, from_dc=True)                 # ctlSequence 1 > SN
                self.assertEqual(iut.trust.lists[(kind, w.issuer(kind))].sequence, 1)
                self.assertEqual([payload for _, _, payload in _frames(iut)], [delta])

    def test_tp_secpki_its_s_ctldist_03_bv(self):
        """SECPKI_ITS-S_CTLDIST_03_BV: the Delta CTL (A: TlmCertificateTrustListMessage, B:
        RcaCertificateTrustListMessage) is broadcast with BTP port 2014 (unsecured SHB)."""
        for kind, content in self.KINDS:
            with self.subTest(kind):
                w = _CxlWorld(self)
                iut = w.iut([w.rca], [w.aa])
                iut.cxl.receive(w.delta(kind), from_dc=True)
                w.run(iut, 3000)
                frames = _frames(iut)
                self.assertGreaterEqual(len(frames), 3)               # f1 = 1 Hz
                for _, port, payload in frames:
                    self.assertEqual(port, 2014)
                    data = decode("Ieee1609Dot2Data", payload)
                    etsi = decode("EtsiTs102941Data", data["content"][1]["tbsData"]["payload"]["data"]["content"][1])
                    self.assertEqual(etsi["content"][0], content)
                    self.assertFalse(etsi["content"][1]["isFullCtl"])

    def test_tp_secpki_its_s_ctldist_04_bv(self):
        """SECPKI_ITS-S_CTLDIST_04_BV: the IUT broadcasting the Delta CTL (SN) signed with
        CERT_TLM / CERT_IUT_A_RCA stops when it receives that Delta CTL with a ctlSequence
        equal to or higher than SN from another ITS-S."""
        for kind, _ in self.KINDS:
            for higher in (False, True):
                with self.subTest(kind=kind, higher=higher):
                    w = _CxlWorld(self)
                    iut = w.iut([w.rca], [w.aa])
                    delta = w.delta(kind)
                    iut.cxl.receive(delta, from_dc=True)
                    w.run(iut, 2000)
                    w.neighbour_broadcast(iut, w.delta(kind) if higher else delta, CTL_PORT)
                    stopped = w.clock.ms
                    w.run(iut, 6000)
                    self.assertEqual(_frames(iut, stopped + 1), [])

    def test_tp_secpki_its_s_ctldist_05_bv(self):
        """SECPKI_ITS-S_CTLDIST_05_BV: the IUT without CTL information for CERT, requested
        to get it, sends secured messages with an ETSI contributed extension (contributorId
        2) EtsiTs102941CtlRequest with issuerId = HashedId8(CERT), without
        lastKnownCtlSequence."""
        for kind, _ in self.KINDS:
            with self.subTest(kind):
                w = _CxlWorld(self)
                iut = w.iut([w.rca], [w.aa])
                iut.cxl.request_ctl(w.issuer(kind))
                self.assertEqual(w.requests_in_cam(iut, 0), [(DELTA_CTL_REQUEST_ID, {"issuerId": w.issuer(kind)})])
                self.assertEqual(w.requests_in_cam(iut, 1000), [(DELTA_CTL_REQUEST_ID, {"issuerId": w.issuer(kind)})])

    def test_tp_secpki_its_s_ctldist_06_bv(self):
        """SECPKI_ITS-S_CTLDIST_06_BV: the IUT holding the CTL of CERT with ctlSequence SN,
        requested to get the CTL information, sends the EtsiTs102941CtlRequest with issuerId
        = HashedId8(CERT) and lastKnownCtlSequence = SN."""
        for kind, _ in self.KINDS:
            with self.subTest(kind):
                w = _CxlWorld(self)
                iut = w.iut([w.rca], [w.aa])
                iut.cxl.receive(w.ectl([w.rca]) if kind == "ectl" else w.rca_ctl(w.rca, [w.aa]), from_dc=True)
                iut.cxl.receive(w.delta(kind), from_dc=True)          # SN = 1
                iut.cxl.request_ctl(w.issuer(kind))
                self.assertEqual(w.requests_in_cam(iut, 0), [
                    (DELTA_CTL_REQUEST_ID, {"issuerId": w.issuer(kind), "lastKnownCtlSequence": 1})])

    def test_tp_secpki_its_s_ctldist_07_bv(self):
        """SECPKI_ITS-S_CTLDIST_07_BV: the IUT holding the CTL of CERT (SN) receives a secured
        message whose EtsiTs102941CtlRequest for CERT has a lastKnownCtlSequence higher than
        SN: it starts sending requests with lastKnownCtlSequence = SN."""
        for kind, _ in self.KINDS:
            with self.subTest(kind):
                w = _CxlWorld(self)
                iut = w.iut([w.rca], [w.aa])
                iut.cxl.receive(w.ectl([w.rca]) if kind == "ectl" else w.rca_ctl(w.rca, [w.aa]), from_dc=True)
                self.assertEqual(w.requests_in_cam(iut, 0), [])
                w.neighbour_request(iut, DELTA_CTL_REQUEST_ID,
                                    {"issuerId": w.issuer(kind), "lastKnownCtlSequence": 3}, 500)
                self.assertEqual(w.requests_in_cam(iut, 1000), [
                    (DELTA_CTL_REQUEST_ID, {"issuerId": w.issuer(kind), "lastKnownCtlSequence": 0})])

    def test_tp_secpki_its_s_ctldist_08_bv(self):
        """SECPKI_ITS-S_CTLDIST_08_BV: the IUT holding a Delta CTL M (SN) signed with CERT
        receives a secured message whose EtsiTs102941CtlRequest for CERT has a
        lastKnownCtlSequence lower than SN: it starts broadcasting M."""
        for kind, _ in self.KINDS:
            with self.subTest(kind):
                w = _CxlWorld(self)
                iut = w.iut([w.rca], [w.aa], redistribute=False)
                iut.cxl.receive(w.ectl([w.rca]) if kind == "ectl" else w.rca_ctl(w.rca, [w.aa]), from_dc=True)
                delta = w.delta(kind)                                 # M, SN = 1
                iut.cxl.receive(delta, from_dc=True)
                self.assertEqual(_frames(iut), [])                   # not redistributed (PIXIT)
                w.neighbour_request(iut, DELTA_CTL_REQUEST_ID,
                                    {"issuerId": w.issuer(kind), "lastKnownCtlSequence": 0}, 500)
                self.assertEqual([(port, payload) for _, port, payload in _frames(iut)], [(CTL_PORT, delta)])

    def test_tp_secpki_its_s_ctldist_09_bv(self):
        """SECPKI_ITS-S_CTLDIST_09_BV: the IUT broadcasting a Delta CTL started at T stops
        broadcasting it at T + D1 (PIXIT D1 = 60 s)."""
        for kind, _ in self.KINDS:
            with self.subTest(kind):
                w = _CxlWorld(self)
                iut = w.iut([w.rca], [w.aa])
                iut.cxl.receive(w.delta(kind), from_dc=True)          # T = 0
                w.run(iut, int(_D1 * 1000) - 100)
                self.assertTrue(_frames(iut, int(_D1 * 1000) - 1500))   # still broadcasting
                w.run(iut, int(_D1 * 1000) + 5000)
                self.assertEqual(_frames(iut, int(_D1 * 1000)), [])
                self.assertEqual(len(_frames(iut)), int(_D1))          # 1 Hz during D1

    def test_tp_secpki_its_s_ctldist_10_bv(self):
        """SECPKI_ITS-S_CTLDIST_10_BV: the IUT broadcasting the requested Delta CTL, started
        at T, stops broadcasting it at T + D2 (PIXIT D2 = 10 s)."""
        for kind, _ in self.KINDS:
            with self.subTest(kind):
                w = _CxlWorld(self)
                iut = w.iut([w.rca], [w.aa], redistribute=False)
                iut.cxl.receive(w.delta(kind), from_dc=True)
                w.neighbour_request(iut, DELTA_CTL_REQUEST_ID, {"issuerId": w.issuer(kind)}, 0)   # T = 0
                w.run(iut, int(_D2 * 1000) + 5000)
                self.assertEqual(_frames(iut, int(_D2 * 1000)), [])
                self.assertEqual(len(_frames(iut)), int(_D2))


class TestPkiItssCrlDistribution(unittest.TestCase):
    """SECPKI_ITS-S_CRLDIST: CRL distribution (TS 103 601 clauses 5.3, 5.4)."""

    def test_tp_secpki_its_s_crldist_01_bv(self):
        """SECPKI_ITS-S_CRLDIST_01_BV: the IUT, with CERT_IUT_A_RCA and no CRL of it yet,
        receives the CRL (thisUpdate T, nextUpdate N) from the DC and starts broadcasting it."""
        w = _CxlWorld(self)
        iut = w.iut([w.rca], [w.aa])
        crl = w.crl(w.rca, [])
        iut.cxl.receive(crl, from_dc=True)
        self.assertEqual([payload for _, _, payload in _frames(iut)], [crl])

    def test_tp_secpki_its_s_crldist_02_bv(self):
        """SECPKI_ITS-S_CRLDIST_02_BV (both TPs of this ID): the CertificateRevocationListMessage
        is broadcast with BTP port 2015; received from the DC at T, its broadcast stops at
        T + D1 (PIXIT D1 = 60 s)."""
        w = _CxlWorld(self)
        iut = w.iut([w.rca], [w.aa])
        crl = w.crl(w.rca, [])
        iut.cxl.receive(crl, from_dc=True)                           # T = 0
        w.run(iut, int(_D1 * 1000) + 5000)
        frames = _frames(iut)
        self.assertEqual({(port, payload) for _, port, payload in frames}, {(CRL_PORT, crl)})
        data = decode("Ieee1609Dot2Data", crl)
        etsi = decode("EtsiTs102941Data", data["content"][1]["tbsData"]["payload"]["data"]["content"][1])
        self.assertEqual(etsi["content"][0], "certificateRevocationList")
        self.assertEqual(_frames(iut, int(_D1 * 1000)), [])
        self.assertEqual(len(frames), int(_D1))

    def test_tp_secpki_its_s_crldist_03_bv(self):
        """SECPKI_ITS-S_CRLDIST_03_BV: the IUT broadcasting the CRL from the DC (nextUpdate N)
        stops when its time reaches N (D1 = 1 week, N = thisUpdate + 1 hour)."""
        w = _CxlWorld(self)
        iut = w.iut([w.rca], [w.aa])
        iut.cxl.config = DistributionConfig()                         # D1 = 1 week
        crl = w.crl(w.rca, [])
        iut.cxl.receive(crl, from_dc=True)
        n_ms = (iut.trust.lists[("crl", w.rca.as_hashedid8())].next_update - time32(w.clock.base)) * 1000
        w.run(iut, n_ms - 2000, step_ms=1000)
        self.assertTrue(_frames(iut, n_ms - 3000))
        w.run(iut, n_ms + 10_000, step_ms=1000)
        self.assertEqual(_frames(iut, n_ms + 1000), [])

    def test_tp_secpki_its_s_crldist_04_bv(self):
        """SECPKI_ITS-S_CRLDIST_04_BV (both TPs of this ID): (1) the IUT broadcasting the CRL
        (thisUpdate T) stops when it receives the CRL of CERT_IUT_A_RCA with thisUpdate equal
        to or greater than T from another station; (2) the IUT that never received a CRL of
        CERT_IUT_A_RCA, requested to get it, sends EtsiTs102941CrlRequest with issuerId =
        HashedId8(CERT_IUT_A_RCA) and without lastKnownUpdate."""
        for greater in (False, True):
            with self.subTest(greater=greater):
                w = _CxlWorld(self)
                iut = w.iut([w.rca], [w.aa])
                crl = w.crl(w.rca, [])
                iut.cxl.receive(crl, from_dc=True)
                w.run(iut, 2000)
                w.neighbour_broadcast(iut, w.crl(w.rca, [], this_update_offset=5) if greater else crl, CRL_PORT)
                stopped = w.clock.ms
                w.run(iut, 6000)
                self.assertEqual(_frames(iut, stopped + 1), [])
        w = _CxlWorld(self)
        iut = w.iut([w.rca], [w.aa])
        iut.cxl.request_crl(w.rca.as_hashedid8())
        self.assertEqual(w.requests_in_cam(iut, 0), [(CRL_REQUEST_ID, {"issuerId": w.rca.as_hashedid8()})])

    def test_tp_secpki_its_s_crldist_05_bv(self):
        """SECPKI_ITS-S_CRLDIST_05_BV: the IUT that received the CRL of CERT_IUT_A_RCA
        (thisUpdate T), requested to get the CRL, sends EtsiTs102941CrlRequest with issuerId =
        HashedId8(CERT_IUT_A_RCA) and lastKnownUpdate = T."""
        w = _CxlWorld(self)
        iut = w.iut([w.rca], [w.aa])
        iut.cxl.receive(w.crl(w.rca, []), from_dc=True)
        t = iut.trust.lists[("crl", w.rca.as_hashedid8())].this_update
        iut.cxl.request_crl(w.rca.as_hashedid8())
        self.assertEqual(w.requests_in_cam(iut, 0), [
            (CRL_REQUEST_ID, {"issuerId": w.rca.as_hashedid8(), "lastKnownUpdate": t})])

    def test_tp_secpki_its_s_crldist_06_bv(self):
        """SECPKI_ITS-S_CRLDIST_06_BV (both TPs of this ID): the IUT holding the CRL, no
        longer broadcasting it, receives a CRL request without lastKnownUpdate (at T): it
        starts broadcasting the CRL and stops at T + D2 (PIXIT D2 = 10 s; the second TP
        text says D1)."""
        w = _CxlWorld(self)
        iut = w.iut([w.rca], [w.aa])
        crl = w.crl(w.rca, [])
        iut.cxl.receive(crl, from_dc=True)
        w.run(iut, int(_D1 * 1000) + 1000)                           # D1 elapsed: stopped
        t_ms = int(_D1 * 1000) + 2000
        self.assertEqual(_frames(iut, int(_D1 * 1000)), [])
        w.neighbour_request(iut, CRL_REQUEST_ID, {"issuerId": w.rca.as_hashedid8()}, t_ms)
        w.run(iut, t_ms + int(_D2 * 1000) + 5000)
        frames = _frames(iut, t_ms)
        self.assertEqual({(port, payload) for _, port, payload in frames}, {(CRL_PORT, crl)})
        self.assertEqual(len(frames), int(_D2))
        self.assertEqual(_frames(iut, t_ms + int(_D2 * 1000)), [])


if __name__ == "__main__":
    unittest.main()
