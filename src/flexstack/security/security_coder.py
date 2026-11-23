"""
Security coder (ETSI TS 103 097 V2.2.1, IEEE Std 1609.2) with canonical OER.

IEEE 1609.2 encodes with the canonical OER of X.696, in which a component
equal to its DEFAULT value is not encoded. The only DEFAULT components of a
certificate are those of PsidGroupPermissions: ``minChainLength`` (1),
``chainLengthRange`` (0) and ``eeType`` ({app}). asn1tools omits the first two
when they equal their DEFAULT, but encodes ``eeType`` {app} when it is given
with its 8 bits (``(b"\\x80", 8)``). :func:`canonical` removes such an
``eeType`` before encoding, so that:

* a certificate is hashed (HashedId8) and verified over its canonical
  encoding, as RustFlexstack (rasn) does: a received certificate that was
  signed over a non-canonical encoding does not verify;
* the certificates FlexStack signs are canonical whatever dict they are given.
"""
import asn1tools
from .security_asn1 import SECURITY_ASN1_DESCRIPTIONS


def _is_app_only(ee_type: tuple) -> bool:
    """The EndEntityType bit string is {app} (bit 0 only)."""
    octets, _ = ee_type
    return bool(octets) and int.from_bytes(octets, "big") == 1 << (8 * len(octets) - 1)


def canonical(value):
    """``value`` with every PsidGroupPermissions ``eeType`` equal to its DEFAULT
    {app} removed (canonical OER). Returns ``value`` itself when nothing changes;
    copies only the containers on the path to a change."""
    if isinstance(value, dict):
        out = None
        for key, item in value.items():
            if isinstance(item, (dict, list, tuple)):
                new = canonical(item)
                if new is not item:
                    if out is None:
                        out = dict(value)
                    out[key] = new
        ee_type = value.get("eeType")
        if isinstance(ee_type, tuple) and "subjectPermissions" in value and ee_type[1] != 1 \
                and _is_app_only(ee_type):   # (b"\x80", 1) is how asn1tools spells the DEFAULT
            if out is None:
                out = dict(value)
            del out["eeType"]
        return value if out is None else out
    if isinstance(value, (list, tuple)):
        items = None
        for index, item in enumerate(value):
            if isinstance(item, (dict, list, tuple)):
                new = canonical(item)
                if new is not item:
                    if items is None:
                        items = list(value)
                    items[index] = new
        return value if items is None else type(value)(items)
    return value


class CanonicalOerCoder:  # pylint: disable=too-few-public-methods
    """An asn1tools OER coder whose ``encode`` applies :func:`canonical`;
    every other attribute is the compiled coder's."""

    def __init__(self, coder) -> None:
        self._coder = coder

    def encode(self, name: str, data, *args, **kwargs) -> bytes:
        """Canonical OER encoding of ``data`` as ``name``."""
        return self._coder.encode(name, canonical(data), *args, **kwargs)

    def __getattr__(self, attribute):
        return getattr(self._coder, attribute)


def compile_canonical(descriptions: str) -> CanonicalOerCoder:
    """Compile ASN.1 ``descriptions`` into a :class:`CanonicalOerCoder`."""
    return CanonicalOerCoder(asn1tools.compile_string(descriptions, codec="oer"))


class SecurityCoder:
    """
    Class for encoding/decoding Security Headers, Certificates and other Security related formats
    Follows the ETSI TS 103 097 V2.2.1 (2026-03) standard.

    Attributes
    ----------
    asn_coder : asn1tools.Coder
        ASN.1 coder.
    """

    def __init__(self) -> None:
        """
        Initialize the Security Coder.
        """
        self.asn_coder = compile_canonical(SECURITY_ASN1_DESCRIPTIONS)

    def encode_etsi_ts_103097_certificate(self, certificate: dict) -> bytes:
        """
        Encode a EtsiTs103097Certificate.

        Parameters
        ----------
        certificate : dict
            The certificate to encode.

        Returns
        -------
        bytes
            The encoded certificate.
        """
        return self.asn_coder.encode("EtsiTs103097Certificate", certificate)

    def decode_etsi_ts_103097_certificate(self, certificate: bytes) -> dict:
        """
        Decode a EtsiTs103097Certificate.

        Parameters
        ----------
        certificate : bytes
            The certificate to decode.

        Returns
        -------
        dict
            The decoded certificate.
        """
        return self.asn_coder.decode("EtsiTs103097Certificate", certificate)

    def encode_etsi_ts_103097_data_signed(self, data: dict) -> bytes:
        """
        Encode a EtsiTs103097Data-Signed.

        Parameters
        ----------
        data : dict
            The data to encode.

        Returns
        -------
        bytes
            The encoded data.
        """
        return self.asn_coder.encode("EtsiTs103097Data", data)

    def decode_etsi_ts_103097_data_signed(self, data: bytes) -> dict:
        """
        Decode a EtsiTs103097Data-Signed.

        Parameters
        ----------
        data : bytes
            The data to decode.

        Returns
        -------
        dict
            The decoded data.
        """
        return self.asn_coder.decode("EtsiTs103097Data", data)

    def encode_to_be_signed_data(self, data: dict) -> bytes:
        """
        Encode a ToBeSignedData.

        Parameters
        ----------
        data : dict
            The data to encode.

        Returns
        -------
        bytes
            The encoded data.
        """
        return self.asn_coder.encode("ToBeSignedData", data)

    def encode_ToBeSignedCertificate(self, data: dict) -> bytes:
        """
        Encode a ToBeSignedCertificate.

        Parameters
        ----------
        data : dict
            The data to encode.

        Returns
        -------
        bytes
            The encoded data.
        """
        return self.asn_coder.encode("ToBeSignedCertificate", data)
