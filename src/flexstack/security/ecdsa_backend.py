from __future__ import annotations
import hashlib
import ecdsa


class ECDSABackend:
    """
    Interface for ECDSA backends.
    """

    def create_key(self) -> int:
        """
        Creates a new key pair. Returns the identifier of the key.
        """
        raise NotImplementedError("All the ECDSA backends should implement this")

    def get_public_key(self, identifier: int) -> tuple:
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

    def verify_with_pk(self, data: bytes, signature: dict, pk: dict) -> bool:
        """
        Verifies the array of bytes. With the public key.
        Both key and signature come in IEEE 1609.2 format.

        Parameters
        ----------
        data : bytes
            Data to verify.
        signature : dict
            Signature to verify. In IEEE 1609.2 format (Signature).
        pk : dict
            Public key to verify. In IEEE 1609.2 format (PublicVerificationKey).

        Returns
        -------
        bool
            True if the signature is valid, False otherwise.
        """
        raise NotImplementedError("All the ECDSA backends should implement this")


class PythonECDSABackend(ECDSABackend):
    """
    Python ECDSA backend.

    """

    def __init__(self) -> None:
        """
        Initialize the Python ECDSA backend.
        """
        self.keys: dict[int, ecdsa.keys.SigningKey] = {}

    def create_key(self) -> int:
        """
        Creates a new key pair. Returns the identifier of the key.

        Returns
        -------
        int
            Identifier of the key.
        """
        key: ecdsa.keys.SigningKey = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p)
        identifier = len(self.keys)
        self.keys[identifier] = key
        return identifier

    def get_public_key(self, identifier: int) -> tuple:
        """
        Returns the public key of the key pair with the identifier.
        It returns as a dict to be oer encoded as PublicVerificationKey in oer.

        Parameters
        ----------
        identifier : int
            Identifier of the key.

        Returns
        -------
        dict
            Public key in IEEE 1609.2 format.
        """
        key = self.keys[identifier]
        return (
            "ecdsaNistP256",
            (
                "uncompressedP256",
                {
                    "x": key.verifying_key.pubkey.point.x().to_bytes(
                        32, byteorder="big"
                    ),
                    "y": key.verifying_key.pubkey.point.y().to_bytes(
                        32, byteorder="big"
                    ),
                },
            ),
        )

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
        signature = key.sign(data=data, hashfunc=hashlib.sha256)
        r, s = ecdsa.util.sigdecode_string(signature, ecdsa.NIST256p.order)
        r = r.to_bytes(32, byteorder="big")
        s = s.to_bytes(32, byteorder="big")
        return ("ecdsaNistP256Signature", {"rSig": ("x-only", r), "sSig": s})

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
        for key_, value in self.keys.items():
            if key_ == key:
                vk: ecdsa.keys.VerifyingKey = value.verifying_key
                r = int.from_bytes(signature[1]["rSig"][1], byteorder="big")
                s = int.from_bytes(signature[1]["sSig"], byteorder="big")
                signature = ecdsa.util.sigencode_string(r, s, ecdsa.NIST256p.order)
                return vk.verify(
                    signature=signature, data=data, hashfunc=hashlib.sha256
                )
        return False

    def verify_with_pk(self, data: bytes, signature: dict, pk: dict) -> bool:
        """
        Verifies the array of bytes. With the public key.
        Both key and signature come in IEEE 1609.2 format.

        Parameters
        ----------
        data : bytes
            Data to verify.
        signature : dict
            Signature to verify. In IEEE 1609.2 format (Signature).
        pk : dict
            Public key to verify. In IEEE 1609.2 format (PublicVerificationKey).

        Returns
        -------
        bool
            True if the signature is valid, False otherwise.
        """
        if (
            signature[0] == "ecdsaNistP256Signature"
            and signature[1]["rSig"][0] == "x-only"
        ):
            r = int.from_bytes(signature[1]["rSig"][1], byteorder="big")
            s = int.from_bytes(signature[1]["sSig"], byteorder="big")
            dec_signature = ecdsa.util.sigencode_string(r, s, ecdsa.NIST256p.order)
        else:
            raise ValueError("Signature format not supported")
        if pk[0] == "ecdsaNistP256" and pk[1][0] == "uncompressedP256":
            x = int.from_bytes(pk[1][1]["x"], byteorder="big")
            y = int.from_bytes(pk[1][1]["y"], byteorder="big")
            point = ecdsa.ellipticcurve.Point(
                ecdsa.NIST256p.curve, x, y, ecdsa.NIST256p.order
            )
            vk: ecdsa.keys.VerifyingKey = ecdsa.VerifyingKey.from_public_point(
                point, curve=ecdsa.NIST256p
            )
            try:
                return vk.verify(
                    signature=dec_signature, data=data, hashfunc=hashlib.sha256
                )
            except ecdsa.keys.BadSignatureError:
                return False
        else:
            raise ValueError("Public key format not supported")
