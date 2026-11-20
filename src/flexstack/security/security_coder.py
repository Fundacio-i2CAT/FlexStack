import asn1tools
from .security_asn1 import SECURITY_ASN1_DESCRIPTIONS


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
        self.asn_coder = asn1tools.compile_string(
            SECURITY_ASN1_DESCRIPTIONS, codec="oer"
        )

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
