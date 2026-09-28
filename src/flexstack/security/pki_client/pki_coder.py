"""
pki_client/pki_coder.py — ASN.1 encode/decode for TS 102 941 PKI messages (ITS-S side).

``PkiCoder`` extends FlexStack's ``SecurityCoder`` by compiling the ETSI
TS 102 941 ASN.1 schemas alongside the base IEEE 1609.2 / TS 103 097 schemas.
This gives the ITS-S encoder the same type table as the PKI server,
ensuring interoperable COER encoding on both ends.

Singleton
---------
``PKI_CODER`` is module-level singleton — compile once per process::

    from flexstack.security.pki_client.pki_coder import PKI_CODER
"""
from __future__ import annotations

import asn1tools

from flexstack.security.pki_asn1 import PKI_ASN1_DESCRIPTIONS
from flexstack.security.security_coder import SecurityCoder


# ---------------------------------------------------------------------------
# PkiCoder
# ---------------------------------------------------------------------------

class PkiCoder(SecurityCoder):
    """ASN.1 coder for PKI client messages (ITS-S side).

    Recompiles IEEE 1609.2 + TS 103 097 schemas (from FlexStack) together
    with the TS 102 941 schemas so that all cross-module type references
    resolve correctly.

    Inherits from ``SecurityCoder`` to retain all parent encode/decode methods
    (certificates, ``ToBeSignedData``, etc.).
    """

    def __init__(self) -> None:
        # pylint: disable=super-init-not-called
        self.asn_coder = asn1tools.compile_string(PKI_ASN1_DESCRIPTIONS, codec="oer")

    # ------------------------------------------------------------------
    # Generic Ieee1609Dot2Data  (covers signed + encrypted variants)
    # ------------------------------------------------------------------

    def encode_ieee1609dot2_data(self, data: dict) -> bytes:
        """Encode a generic ``Ieee1609Dot2Data`` (any content choice)."""
        return self.asn_coder.encode("Ieee1609Dot2Data", data)

    def decode_ieee1609dot2_data(self, raw: bytes) -> dict:
        """Decode a generic ``Ieee1609Dot2Data``."""
        return self.asn_coder.decode("Ieee1609Dot2Data", raw)

    # ------------------------------------------------------------------
    # EtsiTs102941Data envelope
    # ------------------------------------------------------------------

    def encode_etsi102941_data(self, content_choice: str, content_value: object) -> bytes:
        """Encode an ``EtsiTs102941Data`` envelope.

        Parameters
        ----------
        content_choice:
            One of ``"enrolmentRequest"``, ``"enrolmentResponse"``,
            ``"authorizationRequest"``, ``"authorizationResponse"``, etc.
        content_value:
            The decoded inner message dict.

        Returns
        -------
        bytes
            COER-encoded ``EtsiTs102941Data``.
        """
        return self.asn_coder.encode(
            "EtsiTs102941Data",
            {"version": 1, "content": (content_choice, content_value)},
        )

    def decode_etsi102941_data(self, raw: bytes) -> dict:
        """Decode an ``EtsiTs102941Data`` envelope → ``{"version": 1, "content": (choice, value)}``."""
        return self.asn_coder.decode("EtsiTs102941Data", raw)

    # ------------------------------------------------------------------
    # Enrolment
    # ------------------------------------------------------------------

    def encode_inner_ec_request(self, data: dict) -> bytes:
        """Encode ``InnerECRequest``."""
        return self.asn_coder.encode("InnerECRequest", data)

    def decode_inner_ec_response(self, raw: bytes) -> dict:
        """Decode ``InnerECResponse`` → ``{"version": 1, "responseCode": ..., "certificate": ...}``."""
        return self.asn_coder.decode("InnerECResponse", raw)

    # ------------------------------------------------------------------
    # Authorization
    # ------------------------------------------------------------------

    def encode_shared_at_request(self, data: dict) -> bytes:
        """Encode ``SharedAtRequest`` (used for HMAC keyTag over-the-wire)."""
        return self.asn_coder.encode("SharedAtRequest", data)

    def encode_inner_at_request(self, data: dict) -> bytes:
        """Encode ``InnerAtRequest``."""
        return self.asn_coder.encode("InnerAtRequest", data)

    def decode_inner_at_response(self, raw: bytes) -> dict:
        """Decode ``InnerAtResponse`` → ``{"requestHash": ..., "responseCode": ..., "certificate": ...}``."""
        return self.asn_coder.decode("InnerAtResponse", raw)

    # ------------------------------------------------------------------
    # PublicKeys (for HMAC keyTag computation)
    # ------------------------------------------------------------------

    def encode_public_keys(self, data: dict) -> bytes:
        """Encode a ``PublicKeys`` structure (COER used as HMAC input for keyTag).

        ``data`` should contain ``"verificationKey"`` and optionally
        ``"encryptionKey"``.
        """
        return self.asn_coder.encode("PublicKeys", data)

    # ------------------------------------------------------------------
    # Certificate encoding (convenience re-export of parent method)
    # ------------------------------------------------------------------

    def encode_certificate(self, cert_dict: dict) -> bytes:
        """Encode an ``EtsiTs103097Certificate``."""
        return self.asn_coder.encode("EtsiTs103097Certificate", cert_dict)

    def decode_certificate(self, raw: bytes) -> dict:
        """Decode an ``EtsiTs103097Certificate``."""
        return self.asn_coder.decode("EtsiTs103097Certificate", raw)


# ---------------------------------------------------------------------------
# Module-level singleton — compiled once per process
# ---------------------------------------------------------------------------

#: Singleton ``PkiCoder`` instance.  Import this directly in protocol modules::
#:
#:     from flexstack.security.pki_client.pki_coder import PKI_CODER
PKI_CODER: PkiCoder = PkiCoder()
