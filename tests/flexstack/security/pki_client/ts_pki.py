"""
Test system PKI for the ITS-S PKI conformance tests (ETSI TS 103 525-2 V2.1.1
configurations CFG_ENR_ITS-S and CFG_AUTH_ITS-S): a Root CA, an EA and an AA
with encryption keys, written independently of the client code. The EA and AA
decrypt the requests (ECIES recipient side, IEEE 1609.2 clause 5.3.5), check
every layer, record what they received, and answer as TS 102 941 V2.2.1
clauses 6.2.3.2.2 and 6.2.3.3.2 specify (pskRecipInfo with the request key,
signed with the authority key, requestHash).

Mirrors ``rustflexstack::security::pki_conformance::ts_pki``.
"""
from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from flexstack.security.certificate import Certificate, OwnCertificate
from flexstack.security.ecdsa_backend import PythonECDSABackend
from flexstack.security.pki_client.transport import PkiTransportError
from flexstack.security.pki_client.pki_coder import PKI_CODER

from tests.flexstack.security.test_security_checks import _ca, _validity

PSID_CERT_REQUEST = 623
PSID_CRL, PSID_CTL = 622, 624
#: Root CA permissions: sign CRLs (SSP version 1, clause B.3) and Root CA CTLs with
#: EA, AA and DC entries (SSP 0x38, clause B.2).
ROOT_PERMISSIONS = [{"psid": PSID_CRL, "ssp": ("bitmapSsp", b"\x01")},
                    {"psid": PSID_CTL, "ssp": ("bitmapSsp", bytes([1, 0x38]))}]
CODER = PKI_CODER.asn_coder


def encode(type_name, value):
    return CODER.encode(type_name, value)


def decode(type_name, data):
    return CODER.decode(type_name, data)


def _hash(name):
    return hashlib.sha384 if name == "sha384" else hashlib.sha256


def signed_ok(backend, data: dict, key: tuple, signer_bytes: bytes) -> bool:
    """Signature of an Ieee1609Dot2Data signedData over Hash(Hash(tbs) || Hash(signer))."""
    signed = data["content"][1]
    h = _hash(signed["hashId"])
    tbs = encode("ToBeSignedData", signed["tbsData"])
    return backend.verify_with_pk(h(tbs).digest() + h(signer_bytes).digest(), signed["signature"], key)


def _kdf2(shared, p1, length):
    out, counter = b"", 1
    while len(out) < length:
        out += hashlib.sha256(shared + counter.to_bytes(4, "big") + p1).digest()
        counter += 1
    return out[:length]


@dataclass
class Authority:
    """An EA or AA: its certificate (with an encryption key) and the private keys."""
    own: OwnCertificate
    encryption_private: ec.EllipticCurvePrivateKey

    @property
    def certificate(self) -> Certificate:
        return self.own

    def decrypt(self, data: dict) -> tuple[bytes, bytes]:
        """ECIES + AES-CCM decryption of an EtsiTs103097Data-Encrypted for this
        authority (one certRecipInfo with its HashedId8); returns (plaintext, AES key)."""
        choice, encrypted = data["content"]
        assert choice == "encryptedData", choice
        assert len(encrypted["recipients"]) == 1, encrypted["recipients"]
        recipient_choice, recipient = encrypted["recipients"][0]
        assert recipient_choice == "certRecipInfo", recipient_choice
        assert recipient["recipientId"] == self.own.as_hashedid8()
        curve_choice, key = recipient["encKey"]
        curve = ec.SECP256R1() if curve_choice == "eciesNistP256" else ec.BrainpoolP256R1()
        v_kind, v_x = key["v"]
        v = ec.EllipticCurvePublicKey.from_encoded_point(
            curve, (b"\x02" if v_kind == "compressed-y-0" else b"\x03") + v_x)
        shared = self.encryption_private.exchange(ec.ECDH(), v)
        keys = _kdf2(shared, hashlib.sha256(self.own.to_canonical().encode()).digest(), 48)
        assert hmac.compare_digest(hmac.new(keys[16:], key["c"], hashlib.sha256).digest()[:16], key["t"])
        session_key = bytes(a ^ b for a, b in zip(key["c"], keys[:16]))
        ciphertext = encrypted["ciphertext"][1]
        plaintext = AESCCM(session_key, tag_length=16).decrypt(ciphertext["nonce"], ciphertext["ccmCiphertext"], None)
        return plaintext, session_key


@dataclass
class Received:
    """What an authority received, decoded layer by layer."""
    raw: bytes
    encrypted: dict
    session_key: bytes
    outer: dict                       # EtsiTs103097Data-Signed (or unsecured, for AT without POP)
    etsi: dict                        # EtsiTs102941Data
    inner: dict                       # InnerEcRequest / InnerAtRequest
    pop: dict | None = None           # InnerEcRequestSignedForPop
    ec_signature: dict | None = None  # EtsiTs103097Data-SignedExternalPayload (decrypted)
    checks: dict = field(default_factory=dict)


class TsPki:
    """Root CA, EA and AA of the test system; ``enrol`` / ``authorize`` answer requests."""

    def __init__(self, ea_code="ok", aa_code="ok"):
        self.backend = PythonECDSABackend()
        self.root = _ca(self.backend, "ts-root", None, 2, appPermissions=ROOT_PERMISSIONS)
        self.ea = self._authority("ts-ea")
        self.aa = self._authority("ts-aa")
        self.ea_code, self.aa_code = ea_code, aa_code
        self.canonical_keys: dict[bytes, tuple] = {}   # itsId -> canonical public key
        self.ec_permissions = [{"psid": PSID_CERT_REQUEST, "ssp": ("bitmapSsp", bytes([1, 0xC0]))}]
        self.ec_duration = ("years", 1)
        self.enrolments: list[Received] = []
        self.authorizations: list[Received] = []
        self.issued_ecs: list[Certificate] = []

    def _authority(self, name):
        private = ec.generate_private_key(ec.SECP256R1())
        point = private.public_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
        encryption_key = {"supportedSymmAlg": "aes128Ccm", "publicKey": (
            "eciesNistP256", ("compressed-y-0" if point[0] == 2 else "compressed-y-1", point[1:]))}
        own = _ca(self.backend, name, self.root, 1, encryptionKey=encryption_key)
        return Authority(own, private)

    def register(self, its_id: bytes, canonical_key: tuple):
        """Register a canonical identifier and key (manufacturing, out of band)."""
        self.canonical_keys[its_id] = canonical_key

    # -- issuing -------------------------------------------------------------

    def _issue(self, issuer: OwnCertificate, key: tuple, app_permissions, duration=("hours", 1)):
        tbs = {"id": ("none", None), "cracaId": b"\x00\x00\x00", "crlSeries": 0,
               "validityPeriod": _validity(-60, duration), "appPermissions": app_permissions,
               "verifyKeyIndicator": ("verificationKey", key)}
        placeholder = Certificate.from_dict({
            "version": 3, "type": "explicit", "issuer": ("sha256AndDigest", b"\x00" * 8), "toBeSigned": tbs,
            "signature": ("ecdsaNistP256Signature", {"rSig": ("x-only", b"\x00" * 32), "sSig": b"\x00" * 32})})
        return issuer.issue_certificate(self.backend, placeholder).certificate

    def _respond(self, authority: Authority, received: Received, choice: str, code: str, certificate):
        inner = {"requestHash": hashlib.sha256(received.raw).digest()[:16], "responseCode": code}
        if code == "ok":
            inner["certificate"] = certificate
        etsi = encode("EtsiTs102941Data", {"version": 1, "content": (choice, inner)})
        tbs = {"payload": {"data": {"protocolVersion": 3, "content": ("unsecuredData", etsi)}},
               "headerInfo": {"psid": PSID_CERT_REQUEST, "generationTime": _now_time64()}}
        tbs_bytes = encode("ToBeSignedData", tbs)
        signer = authority.own.to_canonical().encode()
        signature = self.backend.sign(hashlib.sha256(tbs_bytes).digest() + hashlib.sha256(signer).digest(),
                                      authority.own.key_id)
        signed = encode("Ieee1609Dot2Data", {"protocolVersion": 3, "content": ("signedData", {
            "hashId": "sha256", "tbsData": tbs, "signer": ("digest", authority.own.as_hashedid8()),
            "signature": signature})})
        nonce = os.urandom(12)
        psk = hashlib.sha256(encode("SymmetricEncryptionKey", ("aes128Ccm", received.session_key))).digest()[-8:]
        return encode("Ieee1609Dot2Data", {"protocolVersion": 3, "content": ("encryptedData", {
            "recipients": [("pskRecipInfo", psk)],
            "ciphertext": ("aes128ccm", {"nonce": nonce, "ccmCiphertext": AESCCM(
                received.session_key, tag_length=16).encrypt(nonce, signed, None)})})})

    # -- EA ------------------------------------------------------------------

    def enrol(self, raw: bytes) -> bytes:
        """EA: read an EnrolmentRequestMessage, check it, answer with an EC (or ea_code)."""
        encrypted = decode("Ieee1609Dot2Data", raw)
        plaintext, session_key = self.ea.decrypt(encrypted)
        outer = decode("Ieee1609Dot2Data", plaintext)
        etsi = decode("EtsiTs102941Data", outer["content"][1]["tbsData"]["payload"]["data"]["content"][1])
        pop = etsi["content"][1]
        inner = decode("InnerEcRequest", pop["content"][1]["tbsData"]["payload"]["data"]["content"][1])
        received = Received(raw, encrypted, session_key, outer, etsi, inner, pop=pop)
        new_key = inner["publicKeys"]["verificationKey"]
        received.checks["pop"] = signed_ok(self.backend, pop, new_key, b"")
        signer = outer["content"][1]["signer"]
        if signer[0] == "self":
            key = self.canonical_keys.get(inner["itsId"])
            received.checks["outer"] = key is not None and signed_ok(self.backend, outer, key, b"")
        else:
            ec_cert = next((c for c in self.issued_ecs if Certificate.from_dict(c).as_hashedid8() == signer[1]), None)
            received.checks["outer"] = ec_cert is not None and signed_ok(
                self.backend, outer, Certificate.from_dict(ec_cert).verification_key(),
                Certificate.from_dict(ec_cert).to_canonical().encode())
        self.enrolments.append(received)
        code = self.ea_code if all(received.checks.values()) else "invalidsignature"
        certificate = self._issue(self.ea.own, new_key, self.ec_permissions, self.ec_duration) if code == "ok" else None
        if certificate is not None:
            self.issued_ecs.append(certificate)
        return self._respond(self.ea, received, "enrolmentResponse", code, certificate)

    # -- AA ------------------------------------------------------------------

    def authorize(self, raw: bytes) -> bytes:
        """AA (validating with the EA's key): read an AuthorizationRequestMessage[WithPop],
        check POP, keyTag and the EC signature, answer with an AT (or aa_code)."""
        encrypted = decode("Ieee1609Dot2Data", raw)
        plaintext, session_key = self.aa.decrypt(encrypted)
        outer = decode("Ieee1609Dot2Data", plaintext)
        if outer["content"][0] == "signedData":
            etsi_bytes = outer["content"][1]["tbsData"]["payload"]["data"]["content"][1]
        else:
            etsi_bytes = outer["content"][1]
        etsi = decode("EtsiTs102941Data", etsi_bytes)
        inner = etsi["content"][1]
        received = Received(raw, encrypted, session_key, outer, etsi, inner)
        keys = inner["publicKeys"]
        if outer["content"][0] == "signedData":
            received.checks["pop"] = signed_ok(self.backend, outer, keys["verificationKey"], b"")
        tag_input = encode("PublicVerificationKey", keys["verificationKey"])
        if "encryptionKey" in keys:
            tag_input += encode("PublicEncryptionKey", keys["encryptionKey"])
        received.checks["keyTag"] = hmac.new(inner["hmacKey"], tag_input, hashlib.sha256).digest()[:16] \
            == inner["sharedAtRequest"]["keyTag"]
        choice, value = inner["ecSignature"]
        if choice == "encryptedEcSignature":
            ec_plain, _ = self.ea.decrypt(value)
            value = decode("Ieee1609Dot2Data", ec_plain)
        received.ec_signature = value
        signed = value["content"][1]
        ec_cert = next((c for c in self.issued_ecs
                        if signed["signer"] == ("digest", Certificate.from_dict(c).as_hashedid8())), None)
        expected = hashlib.sha256(encode("SharedAtRequest", inner["sharedAtRequest"])).digest()
        hash_ok = signed["tbsData"]["payload"].get("extDataHash") == ("sha256HashedData", expected)
        received.checks["ecSignature"] = ec_cert is not None and hash_ok and signed_ok(
            self.backend, value, Certificate.from_dict(ec_cert).verification_key(),
            Certificate.from_dict(ec_cert).to_canonical().encode())
        self.authorizations.append(received)
        code = self.aa_code if all(received.checks.values()) else "invalidsignature"
        app = inner["sharedAtRequest"]["requestedSubjectAttributes"]["appPermissions"]
        certificate = self._issue(self.aa.own, keys["verificationKey"], app) if code == "ok" else None
        return self._respond(self.aa, received, "authorizationResponse", code, certificate)


def _now_time64():
    from flexstack.utils.time_service import TimeService  # pylint: disable=import-outside-toplevel
    return TimeService.timestamp_its() * 1000


class Transport:
    """In-memory transport to the test system: records every POST."""

    def __init__(self, pki: TsPki, ea_url="https://ea.ts/", aa_url="https://aa.ts/", clock=None):
        self.pki, self.ea_url, self.aa_url = pki, ea_url, aa_url
        self.clock = clock
        self.posts: list[tuple[str, bytes, str]] = []
        self.times: list[float] = []      # instant of each POST (with ``clock``)
        self.gets: list[str] = []
        self.files: dict[str, bytes] = {}
        self.lose = 0                     # number of the next responses lost
        self.answered: dict[bytes, bytes] = {}

    async def post(self, url, content, content_type):
        self.posts.append((url, content, content_type))
        if self.clock is not None:
            self.times.append(self.clock())
        # A repeated request gets the response already generated (the EA / AA side
        # of the retry, TS 103 601 clauses 5.1.4 and 5.2.4).
        key = hashlib.sha256(content).digest()
        if key not in self.answered:
            if url == self.ea_url:
                self.answered[key] = self.pki.enrol(content)
            elif url == self.aa_url:
                self.answered[key] = self.pki.authorize(content)
            else:
                raise AssertionError(url)
        if self.lose > 0:
            self.lose -= 1
            raise PkiTransportError(f"POST {url}: response lost")
        return self.answered[key]

    async def get(self, url):
        self.gets.append(url)
        return self.files[url]
