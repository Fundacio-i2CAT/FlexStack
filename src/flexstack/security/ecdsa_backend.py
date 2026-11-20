from __future__ import annotations
import hashlib
import ecdsa


class ECDSABackend:
    """
    Interface for ECDSA backends.
    """

    def create_key(self, algorithm: str = "nistP256") -> int:
        """
        Creates a new key pair. Returns the identifier of the key.
        """
        raise NotImplementedError("All the ECDSA backends should implement this")

    def get_public_key(self, identifier: int, compressed: bool = True) -> tuple:
        """
        Returns the public key of the key pair with the identifier.
        It returns as a dict to be oer encoded as PublicVerificationKey in oer.
        """
        raise NotImplementedError("All the ECDSA backends should implement this")

    def sign(self, data: bytes, identifier: int) -> tuple:
        """
        Signs the array of bytes. With the Key that corresponds to the identifier of the private key.
        The signature must be received in IEEE 1609.2 format.
        """
        raise NotImplementedError("All the ECDSA backends should implement this")

    def verify(self, data: bytes, signature: dict, key: int) -> bool:
        """
        Verifies the array of bytes. With the Key that corresponds to the identifier.
        """
        raise NotImplementedError("All the ECDSA backends should implement this")

    def verify_with_pk(self, data: bytes, signature: tuple, pk: tuple) -> bool:
        """
        Verifies the array of bytes. With the public key.
        Both key and signature come in IEEE 1609.2 format.

        Parameters
        ----------
        data : bytes
            Data to verify.
        signature : tuple
            Signature to verify. In IEEE 1609.2 format (Signature).
        pk : tuple
            Public key to verify. In IEEE 1609.2 format (PublicVerificationKey).

        Returns
        -------
        bool
            True if the signature is valid, False otherwise.
        """
        raise NotImplementedError("All the ECDSA backends should implement this")


# IEEE 1609.2 algorithm names -> (curve, hash).
_CURVES = {
    "nistP256": (ecdsa.NIST256p, hashlib.sha256),
    "brainpoolP256r1": (ecdsa.BRAINPOOLP256r1, hashlib.sha256),
    "brainpoolP384r1": (ecdsa.BRAINPOOLP384r1, hashlib.sha384),
    "nistP384": (ecdsa.NIST384p, hashlib.sha384),
}
_SIGNATURE_ALGORITHMS = {
    "ecdsaNistP256Signature": "nistP256",
    "ecdsaBrainpoolP256r1Signature": "brainpoolP256r1",
    "ecdsaBrainpoolP384r1Signature": "brainpoolP384r1",
    "ecdsaNistP384Signature": "nistP384",
}
_KEY_ALGORITHMS = {
    "ecdsaNistP256": "nistP256",
    "ecdsaBrainpoolP256r1": "brainpoolP256r1",
    "ecdsaBrainpoolP384r1": "brainpoolP384r1",
    "ecdsaNistP384": "nistP384",
}


_KEY_NAMES = {algorithm: name for name, algorithm in _KEY_ALGORITHMS.items()}
_SIGNATURE_NAMES = {algorithm: name for name, algorithm in _SIGNATURE_ALGORITHMS.items()}


def key_algorithm(pk: tuple) -> str:
    """Algorithm (``nistP256``, ``brainpoolP384r1``, ...) of a PublicVerificationKey."""
    return _KEY_ALGORITHMS.get(pk[0], "nistP256")


def hash_name_for_key(pk: tuple) -> str:
    """``sha256`` or ``sha384`` (the hashes approved by ETSI TS 103 097 V2.2.1
    clause 4.2): SHA-384 for a key on a 384-bit curve, SHA-256 otherwise, as in
    the permutation tables of ETSI TS 103 096-2. Used for HashedId8, hashId and
    the issuer choice."""
    return "sha384" if _CURVES[key_algorithm(pk)][1] is hashlib.sha384 else "sha256"


def hash_for_key(pk: tuple):
    """Hash function of a PublicVerificationKey (SHA-384 for 384-bit curves)."""
    algorithm = _KEY_ALGORITHMS.get(pk[0], "nistP256")
    return _CURVES[algorithm][1]


def _uncompressed(point) -> dict:
    return {"x": point.x().to_bytes(32, "big"), "y": point.y().to_bytes(32, "big")}


def reconstruct_public_key(reconstruction_value: tuple, issuer_key: tuple, e: int) -> tuple | None:
    """
    ECQV public key extraction (SEC 4 v1.0 section 3.5, as profiled by IEEE
    Std 1609.2-2016 clause 5.3.2): Q_U = e * P_U + Q_CA, on the curve of the
    issuer key (NIST P-256 or brainpoolP256r1). ``e`` is the integer hash of
    the implicit certificate (see ``Certificate.implicit_hash_integer``).
    Returns the PublicVerificationKey, or None when it cannot be built.
    """
    algorithm = _KEY_ALGORITHMS.get(issuer_key[0])
    if algorithm not in ("nistP256", "brainpoolP256r1"):
        return None
    curve, _ = _CURVES[algorithm]
    try:
        p_u = _verifying_key(curve, reconstruction_value).pubkey.point
        q_ca = _verifying_key(curve, issuer_key[1]).pubkey.point
    except (ValueError, ecdsa.errors.MalformedPointError, KeyError, TypeError, AssertionError):
        return None
    q_u = p_u * e + q_ca
    if q_u == ecdsa.ellipticcurve.INFINITY:
        return None
    return (issuer_key[0], ("uncompressedP256", _uncompressed(q_u.to_affine())))


def _verifying_key(curve, point: tuple) -> ecdsa.VerifyingKey:
    """VerifyingKey from an EccP256CurvePoint / EccP384CurvePoint."""
    choice, value = point
    if choice.startswith("uncompressed"):
        return ecdsa.VerifyingKey.from_string(b"\x04" + value["x"] + value["y"], curve=curve)
    if choice in ("compressed-y-0", "compressed-y-1"):
        prefix = b"\x02" if choice == "compressed-y-0" else b"\x03"
        return ecdsa.VerifyingKey.from_string(prefix + value, curve=curve)
    raise ValueError(f"Public key choice {choice} not supported")


class PythonECDSABackend(ECDSABackend):
    """
    Python ECDSA backend.

    """

    def __init__(self) -> None:
        """
        Initialize the Python ECDSA backend.
        """
        self.keys: dict[int, ecdsa.keys.SigningKey] = {}
        self.algorithms: dict[int, str] = {}

    def create_key(self, algorithm: str = "nistP256") -> int:
        """
        Creates a new key pair. Returns the identifier of the key.

        Parameters
        ----------
        algorithm : str
            ``nistP256`` (default), ``brainpoolP256r1``, ``brainpoolP384r1``
            or ``nistP384`` (the curves of the IEEE 1609.2
            PublicVerificationKey choices).

        Returns
        -------
        int
            Identifier of the key.
        """
        key: ecdsa.keys.SigningKey = ecdsa.SigningKey.generate(curve=_CURVES[algorithm][0])
        identifier = len(self.keys)
        self.keys[identifier] = key
        self.algorithms[identifier] = algorithm
        return identifier

    def algorithm(self, identifier: int) -> str:
        """Algorithm of a key pair (``nistP256`` for keys of unknown origin)."""
        return self.algorithms.get(identifier, "nistP256")

    def get_public_key(self, identifier: int, compressed: bool = True) -> tuple:
        """
        Returns the public key of the key pair with the identifier.
        Defaults to compressed format (compressed-y-0/1) per IEEE 1609.2 / ETSI TS 103 097.

        Parameters
        ----------
        identifier : int
            Identifier of the key.
        compressed : bool, optional
            Whether to return compressed format (default True).

        Returns
        -------
        tuple
            Public key in IEEE 1609.2 format.
        """
        key = self.keys[identifier]
        algorithm = self.algorithm(identifier)
        size = 48 if algorithm.endswith("384") or algorithm.endswith("384r1") else 32
        x_bytes = key.verifying_key.pubkey.point.x().to_bytes(size, byteorder="big")
        y_int = key.verifying_key.pubkey.point.y()
        name = _KEY_NAMES[algorithm]
        if compressed:
            choice = "compressed-y-0" if (y_int % 2 == 0) else "compressed-y-1"
            return (name, (choice, x_bytes))
        return (name, ("uncompressedP384" if size == 48 else "uncompressedP256",
                       {"x": x_bytes, "y": y_int.to_bytes(size, byteorder="big")}))

    def sign(self, data: bytes, identifier: int) -> tuple:
        """
        Signs the array of bytes. With the Key that corresponds to the identifier of the private key.

        Parameters
        ----------
        data : bytes
            Data to sign.
        identifier : int
            Identifier of the private key.

        Returns
        -------
        dict
            Signature in IEEE 1609.2 format.
        """
        key: ecdsa.keys.SigningKey = self.keys[identifier]
        algorithm = self.algorithm(identifier)
        curve, hashfunc = _CURVES[algorithm]
        size = curve.baselen
        signature = key.sign(data=data, hashfunc=hashfunc)
        r, s = ecdsa.util.sigdecode_string(signature, curve.order)
        return (_SIGNATURE_NAMES[algorithm], {"rSig": ("x-only", r.to_bytes(size, byteorder="big")),
                                              "sSig": s.to_bytes(size, byteorder="big")})

    def verify(self, data: bytes, signature: dict, key: int) -> bool:
        """
        Verifies the array of bytes. With the Key that corresponds to the identifier.

        Parameters
        ----------
        data : bytes
            Data to verify.
        signature : dict
            Signature to verify. In IEEE 1609.2 format (Signature).

        Returns
        -------
        bool
            True if the signature is valid, False otherwise.
        """
        if key not in self.keys:
            return False
        return self.verify_with_pk(data, signature, self.get_public_key(key))

    def verify_with_pk(self, data: bytes, signature: tuple, pk: tuple) -> bool:
        """
        Verifies the array of bytes with a public key; both come in IEEE 1609.2
        format. ``data`` is hashed with the hash of the curve (SHA-256 for the
        256-bit curves, SHA-384 for the 384-bit ones); for messages and
        certificates it is the 1609.2 signing input (see
        :func:`flexstack.security.certificate.signing_input`).

        Supported (ETSI TS 103 097 V2.2.1, clause 5.3.1 of IEEE Std 1609.2):
        NIST P-256, brainpoolP256r1, brainpoolP384r1 and NIST P-384, with the
        r value given as x-only, compressed or uncompressed point. A signature
        whose algorithm does not match the key is not valid.

        Parameters
        ----------
        data : bytes
            Data to verify.
        signature : tuple
            Signature to verify. In IEEE 1609.2 format (Signature).
        pk : tuple
            Public key to verify. In IEEE 1609.2 format (PublicVerificationKey).

        Returns
        -------
        bool
            True if the signature is valid, False otherwise.
        """
        algorithm = _SIGNATURE_ALGORITHMS.get(signature[0])
        if algorithm is None or _KEY_ALGORITHMS.get(pk[0]) != algorithm:
            return False
        curve, hashfunc = _CURVES[algorithm]
        try:
            vk = _verifying_key(curve, pk[1])
            r_choice, r_value = signature[1]["rSig"]
            r_x = r_value["x"] if r_choice.startswith("uncompressed") else r_value
            if r_choice == "fill" or not isinstance(r_x, bytes):
                return False
            r = int.from_bytes(r_x, byteorder="big") % curve.order
            s = int.from_bytes(signature[1]["sSig"], byteorder="big")
            return vk.verify(signature=ecdsa.util.sigencode_string(r, s, curve.order),
                             data=data, hashfunc=hashfunc)
        except (ecdsa.keys.BadSignatureError, ecdsa.errors.MalformedPointError,
                ValueError, KeyError, TypeError, AssertionError):
            return False

    def private_scalar(self, identifier: int) -> int:
        """Private key (scalar) of a key pair, needed by an ECQV issuer."""
        return self.keys[identifier].privkey.secret_multiplier

    def import_private_scalar(self, scalar: int) -> int:
        """Store a NIST P-256 private key given as a scalar (e.g. an ECQV-reconstructed
        key) and return its identifier."""
        identifier = len(self.keys)
        self.keys[identifier] = ecdsa.SigningKey.from_secret_exponent(scalar, curve=ecdsa.NIST256p)
        return identifier

    def export_signing_key(self, identifier: int) -> bytes:
        """
        Export the PEM-encoded signing key for the given identifier.

        Parameters
        ----------
        identifier : int
            Identifier of the key pair to export.

        Returns
        -------
        bytes
            PEM-encoded private signing key.
        """
        return self.keys[identifier].to_pem()

    def import_signing_key(self, key_pem: bytes) -> int:
        """
        Import a PEM-encoded signing key and return its new identifier.

        The imported key is appended to the internal key store. Existing keys
        are not modified.

        Parameters
        ----------
        key_pem : bytes
            PEM-encoded private signing key (NIST P-256/P-384, brainpoolP256r1/P384r1).

        Returns
        -------
        int
            Identifier that can be used with :meth:`sign`, :meth:`get_public_key`,
            and :meth:`export_signing_key`.
        """
        key: ecdsa.keys.SigningKey = ecdsa.SigningKey.from_pem(key_pem)
        identifier = len(self.keys)
        self.keys[identifier] = key
        self.algorithms[identifier] = next(
            (name for name, (curve, _) in _CURVES.items() if curve == key.curve), "nistP256")
        return identifier
