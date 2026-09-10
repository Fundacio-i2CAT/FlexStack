"""
pki_client/crypto.py — Sender-side cryptographic helpers for the ETSI C-ITS PKI client.

Implements the ITS-S sender side of:
  - IEEE 1609.2 §5.3.5 ECIES (encrypt only — the ITS-S sends, PKI decrypts)
  - KDF2 key derivation (two consecutive SHA-256 calls, NOT HKDF)
  - AES-128-CCM symmetric encryption / decryption
  - pskRecipInfo AES session-key reuse for response decryption
  - HMAC-SHA256 for AT request keyTag computation
  - ITS Time32 helper

All functions are pure (no network, no state). The module only uses the
`cryptography` standard library package; it does NOT import any FlexStack
modules so that it can be unit-tested in isolation.

References
----------
- ETSI TS 102 941 v2.2.1 §6.2.3.2 (enrolment) and §6.2.3.3 (authorisation)
- IEEE 1609.2-2022 §5.3.5 (ECIES)
- ETSI TS 103 097 v2.2.1 Annex B (ECIES wire format)
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import os
import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH,
    EllipticCurvePublicKey,
    SECP256R1,
    generate_private_key,
)
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

# ---------------------------------------------------------------------------
# ITS epoch constant
# ---------------------------------------------------------------------------

#: Unix timestamp of the ITS epoch: 2004-01-01 00:00:00 UTC.
_ITS_EPOCH_UNIX: int = 1_072_915_200


# ---------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------

def now_time32() -> int:
    """Return current UTC time as a Time32 value (seconds since ITS epoch).

    Time32 is used in ``validityPeriod.start`` and ``headerInfo.generationTime``
    (the latter is Time64 in microseconds; multiply by 1_000_000 before placing
    in headerInfo).

    Returns
    -------
    int
        Seconds elapsed since 2004-01-01 00:00:00 UTC.
    """
    return int(time.time()) - _ITS_EPOCH_UNIX


# ---------------------------------------------------------------------------
# KDF2 — IEEE 1609.2 §5.3.5
# ---------------------------------------------------------------------------

def kdf2(shared_x: bytes, recipient_cert_coer: bytes) -> tuple[bytes, bytes]:
    """IEEE 1609.2 §5.3.5 KDF2 key derivation.

    Derives two sub-keys from the ECDH shared x-coordinate and the
    COER-encoded recipient certificate.

    Parameters
    ----------
    shared_x:
        32-byte x-coordinate of the ECDH shared point (P-256).
    recipient_cert_coer:
        COER encoding of the recipient's ``EtsiTs103097Certificate``.
        Used as diversification parameter P1 = SHA-256(cert_coer).

    Returns
    -------
    (k_enc, k_mac):
        k_enc — 16 bytes: XOR-key for the random AES session key A.
        k_mac — 32 bytes: HMAC-SHA256 key authenticating the XOR result.

    Notes
    -----
    ``k_enc`` is **not** the AES content key.  It only encrypts the random
    session key A via XOR: ``c = A XOR k_enc``.  The AES content key used
    for AES-128-CCM is the random A itself.
    """
    p1 = hashlib.sha256(recipient_cert_coer).digest()
    h1 = hashlib.sha256(shared_x + b'\x00\x00\x00\x01' + p1).digest()
    h2 = hashlib.sha256(shared_x + b'\x00\x00\x00\x02' + p1).digest()
    combined = h1 + h2
    return combined[:16], combined[16:48]   # k_enc=16 B, k_mac=32 B


# ---------------------------------------------------------------------------
# AES-128-CCM helpers
# ---------------------------------------------------------------------------

#: Tag length for AES-128-CCM as used in C-ITS (16 bytes = 128 bits).
_CCM_TAG_LEN: int = 16


def aes_ccm_encrypt(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    """Encrypt *plaintext* with AES-128-CCM.

    Parameters
    ----------
    key:
        16-byte AES-128 session key.
    nonce:
        12-byte nonce (randomly generated per message).
    plaintext:
        Data to encrypt.

    Returns
    -------
    bytes
        Ciphertext with the 16-byte CCM authentication tag appended.
    """
    aesccm = AESCCM(key, tag_length=_CCM_TAG_LEN)
    return aesccm.encrypt(nonce, plaintext, associated_data=None)


def aes_ccm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """Decrypt *ciphertext* with AES-128-CCM.

    Parameters
    ----------
    key:
        16-byte AES-128 session key.
    nonce:
        12-byte nonce used during encryption.
    ciphertext:
        Ciphertext with the 16-byte CCM authentication tag appended.

    Returns
    -------
    bytes
        Recovered plaintext.

    Raises
    ------
    cryptography.exceptions.InvalidTag
        If authentication fails.
    """
    aesccm = AESCCM(key, tag_length=_CCM_TAG_LEN)
    return aesccm.decrypt(nonce, ciphertext, associated_data=None)


# ---------------------------------------------------------------------------
# Public-key compression helpers
# ---------------------------------------------------------------------------

def _compress_public_key(pub: EllipticCurvePublicKey) -> tuple[str, bytes]:
    """Return the compressed point encoding as an (asn1_choice, x_bytes) pair.

    Returns
    -------
    (choice_name, x_bytes):
        choice_name — ``"compressed-y-0"`` (y even) or ``"compressed-y-1"`` (y odd).
        x_bytes     — 32-byte big-endian x-coordinate.
    """
    raw = pub.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
    prefix = raw[0]                      # 0x02 → y even, 0x03 → y odd
    x_bytes = raw[1:]                    # 32 bytes
    choice = "compressed-y-0" if prefix == 0x02 else "compressed-y-1"
    return choice, x_bytes


def _public_key_from_tuple(pk_tuple: tuple) -> EllipticCurvePublicKey:
    """Reconstruct a P-256 public key from a FlexStack ASN.1 decoded tuple.

    Accepts the format produced by ``PkiCoder`` / ``SecurityCoder``:
    ``("eciesNistP256", ("compressed-y-0"|"compressed-y-1", x_bytes))``
    or ``("eciesNistP256", ("uncompressedP256", {"x": ..., "y": ...}))``.
    """
    _outer, inner = pk_tuple
    point_type, point_val = inner

    if point_type in ("compressed-y-0", "compressed-y-1"):
        prefix = b'\x02' if point_type == "compressed-y-0" else b'\x03'
        return EllipticCurvePublicKey.from_encoded_point(SECP256R1(), prefix + point_val)

    if point_type == "uncompressedP256":
        x, y = point_val["x"], point_val["y"]
        return EllipticCurvePublicKey.from_encoded_point(SECP256R1(), b'\x04' + x + y)

    raise ValueError(f"Unsupported ECC point type for ECIES: {point_type!r}")


# ---------------------------------------------------------------------------
# ECIES encrypt (sender / ITS-S side)
# ---------------------------------------------------------------------------

def ecies_encrypt(
    plaintext: bytes,
    recipient_enc_key_tuple: tuple,
    recipient_cert_coer: bytes,
) -> tuple[dict, dict, bytes, bytes]:
    """IEEE 1609.2 §5.3.5 ECIES encrypt — ITS-S sender side.

    Performs the two-layer KEM/DEM design:

    KEM layer (key encapsulation):
      1. Ephemeral ECDH → shared x-coordinate S
      2. KDF2(S, SHA-256(recipient_cert_coer)) → k_enc (16 B), k_mac (32 B)
      3. Random session key A (16 B), random nonce n (12 B)
      4. c = A XOR k_enc          — encrypted session key
      5. t = HMAC-SHA256(k_mac, c)[:16]  — MAC over c (NOT over ciphertext)
      → EciesP256EncryptedKey { v=V, c=c, t=t }   (no nonce in this struct)

    DEM layer (data encapsulation):
      6. C = AES-128-CCM(key=A, nonce=n, plaintext)
      → AesCcmCiphertext { nonce=n, ccmCiphertext=C }

    Parameters
    ----------
    plaintext:
        Bytes to encrypt.
    recipient_enc_key_tuple:
        The ``encryptionKey.publicKey`` value from the recipient's certificate
        as decoded by the ASN.1 coder, e.g.:
        ``("eciesNistP256", ("compressed-y-0", x_bytes))``.
    recipient_cert_coer:
        COER encoding of the recipient's certificate (used as KDF2 P1).

    Returns
    -------
    (ecies_key_dict, aes_ccm_dict, session_key_a, session_key_hashedid8):
        ecies_key_dict  — dict for ``EciesP256EncryptedKey`` ASN.1 field.
        aes_ccm_dict    — dict for ``AesCcmCiphertext`` ASN.1 field.
        session_key_a   — 16-byte AES session key (keep in memory for response).
        session_key_hashedid8 — SHA-256(A)[-8:] for ``pskRecipInfo`` identifier.
    """
    # Reconstruct recipient public key
    recipient_pub = _public_key_from_tuple(recipient_enc_key_tuple)

    # Ephemeral key pair
    ephemeral_priv = generate_private_key(SECP256R1(), default_backend())
    ephemeral_pub = ephemeral_priv.public_key()

    # ECDH shared x-coordinate
    shared_x: bytes = ephemeral_priv.exchange(ECDH(), recipient_pub)

    # KDF2
    k_enc, k_mac = kdf2(shared_x, recipient_cert_coer)

    # Random session key A and nonce n
    session_key_a = os.urandom(16)
    nonce_n = os.urandom(12)

    # KEM: c = A XOR k_enc,  t = HMAC-SHA256(k_mac, c)[:16]
    c = bytes(a ^ b for a, b in zip(session_key_a, k_enc))
    t = _hmac.new(k_mac, c, hashlib.sha256).digest()[:16]

    # DEM: AES-128-CCM with session key A
    ciphertext_c = aes_ccm_encrypt(session_key_a, nonce_n, plaintext)

    # Compressed ephemeral public key V
    v_choice, v_x = _compress_public_key(ephemeral_pub)

    ecies_key_dict = {
        "v": (v_choice, v_x),
        "c": c,
        "t": t,
    }
    aes_ccm_dict = {
        "nonce": nonce_n,
        "ccmCiphertext": ciphertext_c,
    }

    # HashedId8(A) = SHA-256(A)[-8:]  — used as pskRecipInfo identifier
    session_key_hashedid8 = hashlib.sha256(session_key_a).digest()[-8:]

    return ecies_key_dict, aes_ccm_dict, session_key_a, session_key_hashedid8


# ---------------------------------------------------------------------------
# pskRecipInfo response decryption
# ---------------------------------------------------------------------------

def psk_decrypt(session_key_a: bytes, aes_ccm_dict: dict) -> bytes:
    """Decrypt a PKI response that uses pskRecipInfo (AES session-key reuse).

    Both EA and AA re-encrypt their responses with the same AES session key
    that the ITS-S used for the request (identified by HashedId8(A) in the
    pskRecipInfo field).  The ITS-S must keep ``session_key_a`` in memory
    between sending the request and receiving the response.

    Parameters
    ----------
    session_key_a:
        The 16-byte AES session key originally generated during :func:`ecies_encrypt`.
    aes_ccm_dict:
        ``AesCcmCiphertext`` dict with keys ``"nonce"`` (12 bytes) and
        ``"ccmCiphertext"`` (ciphertext bytes).

    Returns
    -------
    bytes
        Decrypted plaintext (inner signed Ieee1609Dot2Data bytes).
    """
    nonce = aes_ccm_dict["nonce"]
    ciphertext = aes_ccm_dict["ccmCiphertext"]
    return aes_ccm_decrypt(session_key_a, nonce, ciphertext)


# ---------------------------------------------------------------------------
# HMAC helpers for AT request
# ---------------------------------------------------------------------------

def compute_hmac_key_tag(hmac_key: bytes, public_keys_coer: bytes) -> bytes:
    """Compute the AT request ``keyTag`` field.

    Per TS 102 941 §6.2.3.3:
    ``keyTag = HMAC-SHA256(hmacKey, COER(PublicKeys))[:16]``

    where ``PublicKeys`` is the COER encoding of the ``PublicKeys`` ASN.1
    structure (containing ``verificationKey`` and optionally ``encryptionKey``).

    Parameters
    ----------
    hmac_key:
        32-byte randomly generated HMAC key (unique per AT request).
    public_keys_coer:
        COER encoding of the ``PublicKeys`` structure for the AT key pair.

    Returns
    -------
    bytes
        16-byte keyTag.
    """
    return _hmac.new(hmac_key, public_keys_coer, hashlib.sha256).digest()[:16]
