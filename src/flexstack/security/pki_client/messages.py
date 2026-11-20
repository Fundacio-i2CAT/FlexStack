"""
pki_client/messages.py — ITS-S side of the ETSI TS 102 941 V2.2.1 security
management messages: enrolment (clause 6.2.3.2) and authorization (clause
6.2.3.3), with the official ASN.1 modules (clause A.2).

The functions build the request messages and read the responses; they do no
I/O. Times are UTC seconds (``now``) so that callers can inject a clock.

Enrolment request (clause 6.2.3.2.1, Figure 14)::

    EtsiTs103097Data-Encrypted            certRecipInfo(EA), ECIES
      EtsiTs103097Data-Signed             signer self (canonical key) or digest(EC)
        EtsiTs102941Data {v1, enrolmentRequest}
          InnerEcRequestSignedForPop      EtsiTs103097Data-Signed, signer self (new key)
            InnerEcRequest

Authorization request (clause 6.2.3.3.1, Figures 17 and 18)::

    EtsiTs103097Data-Encrypted            certRecipInfo(AA), ECIES
      EtsiTs103097Data-Signed (POP)       signer self (new AT key) — or unsecured
        EtsiTs102941Data {v1, authorizationRequest}
          InnerAtRequest
            publicKeys, hmacKey, sharedAtRequest
            ecSignature = encryptedEcSignature  (certRecipInfo(EA))
              EtsiTs103097Data-SignedExternalPayload   signer digest(EC),
                                                       extDataHash = SHA-256(SharedAtRequest)

Responses (clauses 6.2.3.2.2 and 6.2.3.3.2): EtsiTs103097Data-Encrypted with
pskRecipInfo (the request's AES key), containing an EtsiTs103097Data-Signed by
the EA / AA (signer digest), containing EtsiTs102941Data with the inner
response whose requestHash is the leftmost 16 octets of SHA-256 of the request.
"""
from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from flexstack.security.certificate import Certificate, OwnCertificate, signing_input
from flexstack.security.ecdsa_backend import ECDSABackend, hash_name_for_key
from flexstack.security.pki_client.pki_coder import PKI_CODER
from flexstack.utils.time_service import ELAPSED_SECONDS, ITS_EPOCH

#: ITS-AID "secured certificate request" (ETSI TS 102 965).
PSID_CERT_REQUEST = 623
#: Certificate request SSP (clause B.4): version 1, then the permission bits.
SSP_VERSION = 1
SSP_ENROLMENT_REQUEST = 0x80
SSP_AUTHORIZATION_REQUEST = 0x40
#: certificateFormat ts103097v131 (clauses 6.2.3.2.1 and 6.2.3.3.1).
CERTIFICATE_FORMAT = 1
#: HTTP content types (Annex C).
CT_REQUEST = "application/x-its-request"
CT_RESPONSE = "application/x-its-response"

_ECIES_CURVES = {"eciesNistP256": ec.SECP256R1, "eciesBrainpoolP256r1": ec.BrainpoolP256R1}


class PkiProtocolError(Exception):
    """A response cannot be read or does not match the request (``code`` names the check)."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


# ─── Encoding helpers ───────────────────────────────────────────────────────


def encode(type_name: str, value) -> bytes:
    """COER encoding with the official TS 102 941 / TS 103 097 / IEEE 1609.2 modules."""
    return PKI_CODER.asn_coder.encode(type_name, value)


def decode(type_name: str, data: bytes):
    """COER decoding with the official modules."""
    return PKI_CODER.asn_coder.decode(type_name, data)


def time32(now: float) -> int:
    """Time32 (TAI seconds since the ITS epoch, IEEE 1609.2 clause 6.4.15)."""
    return int(now) - ITS_EPOCH + ELAPSED_SECONDS


def time64(now: float) -> int:
    """Time64 (TAI microseconds since the ITS epoch), as generationTime."""
    return round((now - ITS_EPOCH + ELAPSED_SECONDS) * 1e6)


def request_hash(request: bytes) -> bytes:
    """Leftmost 16 octets of SHA-256 of the request's EtsiTs103097Data-Encrypted."""
    return hashlib.sha256(request).digest()[:16]


def ssp_permits(certificate: Certificate, bit: int) -> bool:
    """The certificate's appPermissions grant ITS-AID 623 with SSP version 1 and ``bit``
    (clause B.4: 0x80 enrolment request, 0x40 authorization request)."""
    for item in certificate.certificate.get("toBeSigned", {}).get("appPermissions", []):
        if item.get("psid") != PSID_CERT_REQUEST:
            continue
        ssp = item.get("ssp")
        if ssp is None or ssp[0] not in ("bitmapSsp", "opaque"):
            return False
        value = ssp[1]
        return len(value) >= 2 and value[0] == SSP_VERSION and bool(value[1] & bit)
    return False


def certificate_ssp() -> tuple:
    """The SSP an EC requests: version 1, enrolment and authorization requests."""
    return ("bitmapSsp", bytes([SSP_VERSION, SSP_ENROLMENT_REQUEST | SSP_AUTHORIZATION_REQUEST]))


# ─── Signing ────────────────────────────────────────────────────────────────


def _hash_name(backend: ECDSABackend, key_id: int) -> str:
    return hash_name_for_key(backend.get_public_key(key_id))


def sign(backend: ECDSABackend, key_id: int, payload: dict, now: float,
         signer: Certificate | None = None) -> dict:
    """An EtsiTs103097Data-Signed with headerInfo {psid 623, generationTime} only.

    ``payload`` is the SignedDataPayload (``{"data": ...}`` or
    ``{"extDataHash": ...}``). The signer is ``self`` when ``signer`` is None
    (signature input with the empty signer, IEEE 1609.2 clause 5.3.1), else the
    digest of ``signer`` (whose key ``key_id`` must be).
    """
    tbs = {"payload": payload,
           "headerInfo": {"psid": PSID_CERT_REQUEST, "generationTime": time64(now)}}
    tbs_bytes = encode("ToBeSignedData", tbs)
    hash_name = _hash_name(backend, key_id)
    hashfunc = hashlib.sha384 if hash_name == "sha384" else hashlib.sha256
    if signer is None:
        signer_id, signer_bytes = ("self", None), b""
    else:
        signer_id, signer_bytes = ("digest", signer.as_hashedid8()), signer.to_canonical().encode()
    signature = backend.sign(signing_input(tbs_bytes, signer_bytes, hashfunc), key_id)
    return {"protocolVersion": 3, "content": ("signedData", {
        "hashId": hash_name, "tbsData": tbs, "signer": signer_id, "signature": signature})}


def data_payload(content: bytes) -> dict:
    """SignedDataPayload ``data`` = unsecured EtsiTs103097Data containing ``content``."""
    return {"data": {"protocolVersion": 3, "content": ("unsecuredData", content)}}


def read_signed(data: dict, signer: Certificate, backend: ECDSABackend) -> bytes:
    """Content of an EtsiTs103097Data-Signed by ``signer`` (signer digest, psid 623,
    generationTime present, no other header, valid signature); raises otherwise."""
    choice, signed = data.get("content", ("", None))
    if choice != "signedData":
        raise PkiProtocolError("badcontenttype", f"expected signedData, got {choice!r}")
    if signed["signer"] != ("digest", signer.as_hashedid8()):
        raise PkiProtocolError("invalidsignature", "response not signed by the expected authority")
    header = signed["tbsData"]["headerInfo"]
    if header.get("psid") != PSID_CERT_REQUEST or set(header) != {"psid", "generationTime"}:
        raise PkiProtocolError("badcontenttype", f"unexpected headerInfo {sorted(header)}")
    key = signer.verification_key()
    if key is None:
        raise PkiProtocolError("invalidsignature", "no verification key for the authority certificate")
    hashfunc = hashlib.sha384 if hash_name_for_key(key) == "sha384" else hashlib.sha256
    tbs_bytes = encode("ToBeSignedData", signed["tbsData"])
    if not backend.verify_with_pk(signing_input(tbs_bytes, signer.to_canonical().encode(), hashfunc),
                                  signed["signature"], key):
        raise PkiProtocolError("invalidsignature", "response signature does not verify")
    content = signed["tbsData"]["payload"].get("data", {}).get("content", ("", b""))
    if content[0] != "unsecuredData":
        raise PkiProtocolError("badcontenttype", "signed payload is not unsecuredData")
    return content[1]


# ─── Encryption (IEEE 1609.2 clauses 5.3.5, 5.3.8; TS 103 097 clause 5.3) ───


def _kdf2(shared: bytes, p1: bytes, length: int) -> bytes:
    out, counter = b"", 1
    while len(out) < length:
        out += hashlib.sha256(shared + counter.to_bytes(4, "big") + p1).digest()
        counter += 1
    return out[:length]


def _point(choice: str, point: tuple) -> ec.EllipticCurvePublicKey:
    curve = _ECIES_CURVES[choice]()
    kind, value = point
    if kind in ("compressed-y-0", "compressed-y-1"):
        data = (b"\x02" if kind == "compressed-y-0" else b"\x03") + value
    else:
        data = b"\x04" + value["x"] + value["y"]
    return ec.EllipticCurvePublicKey.from_encoded_point(curve, data)


def psk_id(session_key: bytes) -> bytes:
    """HashedId8 of the COER SymmetricEncryptionKey {aes128Ccm} holding ``session_key``
    (pskRecipInfo, IEEE 1609.2 clause 6.3.34)."""
    return hashlib.sha256(encode("SymmetricEncryptionKey", ("aes128Ccm", session_key))).digest()[-8:]


def encrypt_to(certificate: Certificate, plaintext: bytes) -> tuple[dict, bytes]:  # pylint: disable=too-many-locals
    """EtsiTs103097Data-Encrypted for the encryption key of ``certificate``: one
    certRecipInfo (its HashedId8), ECIES (fresh ephemeral key, KDF2 with P1 =
    SHA-256 of the canonical certificate, MAC1) on the AES-128-CCM key, which
    encrypts ``plaintext`` with a fresh nonce. Returns the data and the AES key."""
    encryption_key = certificate.certificate["toBeSigned"].get("encryptionKey")
    if encryption_key is None:
        raise PkiProtocolError("invalidencryptionkey", "recipient certificate has no encryptionKey")
    choice, point = encryption_key["publicKey"]
    recipient = _point(choice, point)
    ephemeral = ec.generate_private_key(_ECIES_CURVES[choice]())
    shared = ephemeral.exchange(ec.ECDH(), recipient)
    p1 = hashlib.sha256(certificate.to_canonical().encode()).digest()
    keys = _kdf2(shared, p1, 16 + 32)
    session_key, nonce = os.urandom(16), os.urandom(12)
    c = bytes(a ^ b for a, b in zip(session_key, keys[:16]))
    tag = hmac.new(keys[16:], c, hashlib.sha256).digest()[:16]
    v = ephemeral.public_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
    data = {"protocolVersion": 3, "content": ("encryptedData", {
        "recipients": [("certRecipInfo", {
            "recipientId": certificate.as_hashedid8(),
            "encKey": (choice, {"v": ("compressed-y-0" if v[0] == 2 else "compressed-y-1", v[1:]),
                                "c": c, "t": tag})})],
        "ciphertext": ("aes128ccm", {
            "nonce": nonce, "ccmCiphertext": AESCCM(session_key, tag_length=16).encrypt(nonce, plaintext, None)})})}
    return data, session_key


def decrypt_psk(response: bytes, session_key: bytes) -> dict:
    """Decrypt a response encrypted with the request's AES key (exactly one
    pskRecipInfo with :func:`psk_id`); returns the decoded inner Ieee1609Dot2Data."""
    try:
        data = decode("Ieee1609Dot2Data", response)
    except Exception as exc:  # asn1tools raises several error types
        raise PkiProtocolError("cantparse", f"cannot decode the response: {exc}") from exc
    choice, encrypted = data["content"]
    if choice != "encryptedData":
        raise PkiProtocolError("badcontenttype", f"expected encryptedData, got {choice!r}")
    if encrypted["recipients"] != [("pskRecipInfo", psk_id(session_key))]:
        raise PkiProtocolError("imnottherecipient", "no pskRecipInfo for the request's key")
    ciphertext = encrypted["ciphertext"][1]
    try:
        plaintext = AESCCM(session_key, tag_length=16).decrypt(
            ciphertext["nonce"], ciphertext["ccmCiphertext"], None)
        return decode("Ieee1609Dot2Data", plaintext)
    except Exception as exc:  # InvalidTag or a decoding error
        raise PkiProtocolError("decryptionfailed", f"cannot decrypt the response: {exc}") from exc


# ─── Enrolment (clause 6.2.3.2) ─────────────────────────────────────────────


@dataclass(frozen=True)
class PendingRequest:
    """A request sent: its encoding, AES key and the new key pair to certify."""
    message: bytes
    session_key: bytes
    key_id: int

    @property
    def request_hash(self) -> bytes:
        """requestHash the response shall carry."""
        return request_hash(self.message)


def build_enrolment_request(backend: ECDSABackend, ea: Certificate, *, its_id: bytes,  # pylint: disable=too-many-arguments
                            signer_key: int, current_ec: OwnCertificate | None, attributes: dict, now: float,
                            algorithm: str = "nistP256") -> PendingRequest:
    """EnrolmentRequestMessage (clause 6.2.3.2.1). Initial request (``current_ec``
    None): itsId = canonical identifier ``its_id``, outer signer self with the
    canonical key ``signer_key``. Re-keying: itsId = HashedId8(EC), outer signer
    digest(EC) with the EC key. A new verification key pair is generated."""
    key_id = backend.create_key(algorithm)
    if current_ec is not None:
        its_id = current_ec.as_hashedid8()
        signer_key = current_ec.key_id
    inner = {"itsId": its_id, "certificateFormat": CERTIFICATE_FORMAT,
             "publicKeys": {"verificationKey": backend.get_public_key(key_id)},
             "requestedSubjectAttributes": attributes}
    pop = sign(backend, key_id, data_payload(encode("InnerEcRequest", inner)), now)
    etsi = encode("EtsiTs102941Data", {"version": 1, "content": ("enrolmentRequest", pop)})
    outer = sign(backend, signer_key, data_payload(etsi), now, current_ec)
    encrypted, session_key = encrypt_to(ea, encode("Ieee1609Dot2Data", outer))
    return PendingRequest(encode("Ieee1609Dot2Data", encrypted), session_key, key_id)


def _read_response(response: bytes, request: PendingRequest, authority: Certificate,
                   backend: ECDSABackend, choice: str) -> dict:
    signed = decrypt_psk(response, request.session_key)
    etsi = decode("EtsiTs102941Data", read_signed(signed, authority, backend))
    content_choice, inner = etsi["content"]
    if etsi["version"] != 1 or content_choice != choice:
        raise PkiProtocolError("badcontenttype", f"expected {choice}, got {content_choice!r}")
    if inner["requestHash"] != request.request_hash:
        raise PkiProtocolError("badcontenttype", "requestHash does not match the request")
    return inner


def read_enrolment_response(response: bytes, request: PendingRequest, ea: Certificate,
                            backend: ECDSABackend) -> dict:
    """InnerEcResponse of an EnrolmentResponseMessage (clause 6.2.3.2.2)."""
    return _read_response(response, request, ea, backend, "enrolmentResponse")


# ─── Authorization (clause 6.2.3.3) ─────────────────────────────────────────


def key_tag(hmac_key: bytes, public_keys: dict) -> bytes:
    """keyTag: HMAC-SHA256 with ``hmac_key`` over the serialization of the
    verificationKey and of the encryptionKey (if present), leftmost 128 bits."""
    data = encode("PublicVerificationKey", public_keys["verificationKey"])
    if "encryptionKey" in public_keys:
        data += encode("PublicEncryptionKey", public_keys["encryptionKey"])
    return hmac.new(hmac_key, data, hashlib.sha256).digest()[:16]


def build_authorization_request(  # pylint: disable=too-many-arguments,too-many-locals
        backend: ECDSABackend, aa: Certificate, ea: Certificate, *, ec_own: OwnCertificate, attributes: dict,
        now: float, pop: bool = True, algorithm: str = "nistP256") -> PendingRequest:
    """AuthorizationRequestMessage (``pop`` False) or AuthorizationRequestMessageWithPop
    (clause 6.2.3.3.1), with privacy (encryptedEcSignature to the EA). A new
    verification key pair and hmacKey are generated."""
    key_id = backend.create_key(algorithm)
    public_keys = {"verificationKey": backend.get_public_key(key_id)}
    hmac_key = os.urandom(32)
    shared = {"eaId": ea.as_hashedid8(), "keyTag": key_tag(hmac_key, public_keys),
              "certificateFormat": CERTIFICATE_FORMAT, "requestedSubjectAttributes": attributes}
    external = {"extDataHash": ("sha256HashedData", hashlib.sha256(encode("SharedAtRequest", shared)).digest())}
    ec_signature = sign(backend, ec_own.key_id, external, now, ec_own)
    encrypted_signature, _ = encrypt_to(ea, encode("Ieee1609Dot2Data", ec_signature))
    inner = {"publicKeys": public_keys, "hmacKey": hmac_key, "sharedAtRequest": shared,
             "ecSignature": ("encryptedEcSignature", encrypted_signature)}
    etsi = encode("EtsiTs102941Data", {"version": 1, "content": ("authorizationRequest", inner)})
    if pop:
        plaintext = sign(backend, key_id, data_payload(etsi), now)
    else:
        plaintext = {"protocolVersion": 3, "content": ("unsecuredData", etsi)}
    encrypted, session_key = encrypt_to(aa, encode("Ieee1609Dot2Data", plaintext))
    return PendingRequest(encode("Ieee1609Dot2Data", encrypted), session_key, key_id)


def read_authorization_response(response: bytes, request: PendingRequest, aa: Certificate,
                                backend: ECDSABackend) -> dict:
    """InnerAtResponse of an AuthorizationResponseMessage (clause 6.2.3.3.2)."""
    return _read_response(response, request, aa, backend, "authorizationResponse")
