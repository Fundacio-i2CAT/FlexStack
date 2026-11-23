import threading

import asn1tools
from .asn1.denm_asn1 import DENM_ASN1_DESCRIPTIONS

_COMPILED = None
_COMPILE_LOCK = threading.Lock()


def _compiled_specification():
    """Compile DENM-PDU-Descriptions v2.3 + CDD v4.3 once per process (~0.75 s)."""
    global _COMPILED  # pylint: disable=global-statement
    with _COMPILE_LOCK:
        if _COMPILED is None:
            _COMPILED = asn1tools.compile_string(DENM_ASN1_DESCRIPTIONS, codec='uper')
        return _COMPILED


class DENMCoder:
    """
    Class for encoding/decoding Decentralized Environment Notification Messages (DENM)

    Attributes
    ----------
    asn_coder : asn1tools.Coder
        ASN.1 coder.
    """

    def __init__(self) -> None:
        """
        Initialize the DENM Coder.
        """
        self.asn_coder = _compiled_specification()

    def encode(self, denm: dict) -> bytes:
        """
        Encodes a DENM message.

        Parameters
        ----------
        denm : dict
            DENM message.

        Returns
        -------
        bytes
            Encoded DENM message.
        """
        return self.asn_coder.encode('DENM', denm)

    def decode(self, denm: bytes) -> dict:
        """
        Decodes a DENM message.

        Parameters
        ----------
        denm : bytes
            Encoded DENM message.

        Returns
        -------
        dict
            DENM message.
        """
        return self.asn_coder.decode('DENM', denm)

    def validate(self, denm: dict) -> bytes:
        """
        Encode a DENM checking the ASN.1 value constraints (e.g. ranges), which
        ``encode`` does not. Raises an asn1tools error for a DENM that does not
        conform to DENM-PDU-Descriptions (DENM generation exception, ETSI TS
        103 831 V2.3.1 clause 8.2.3.2).
        """
        return self.asn_coder.encode('DENM', denm, check_constraints=True)
