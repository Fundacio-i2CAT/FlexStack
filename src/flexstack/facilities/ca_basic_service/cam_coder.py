from __future__ import annotations

"""
CAM Coder.

This file contains the class for the CAM Coder.

Extension-container (WrappedExtensionContainer) open-type handling
------------------------------------------------------------------
The CAM ASN.1 uses an information-object CLASS to associate each
ExtensionContainerId value with a concrete container type.  asn1tools
treats the open-type field ``containerData`` as raw bytes (the UPER
encoding of the inner container without any additional wrapper).

To *encode* an extension container, call
  ``encode_extension_container(type_name, value)``
which returns the bytes that must be placed in ``containerData``.

To *decode* an extension container, call
  ``decode_extension_container(container_id, data_bytes)``
which dispatches on ``container_id`` and returns the decoded dict.

This pattern is fully wire-interoperable with implementations compiled
from the unaltered ETSI ASN.1 module because the on-wire representation
is identical: UPER length-determinant followed by the inner type's UPER
encoding (X.691 §12, open-type encoding).
"""
import asn1tools
from .cam_asn1 import CAM_ASN1_DESCRIPTIONS

# Maps ExtensionContainerId integer values to ASN.1 type names.
_EXTENSION_CONTAINER_ID_TO_TYPE: dict[int, str] = {
    1: "TwoWheelerContainer",
    2: "EHorizonLocationSharingContainer",
    3: "VeryLowFrequencyContainer",
    4: "PathPredictionContainer",
    5: "GeneralizedLanePositionsContainer",
    6: "VehicleMovementControlContainer",
}


class CAMCoder:
    """
    Class for encoding/decoding Cooperative Awareness Messages (CAM)

    Attributes
    ----------
    asn_coder : asn1tools.Coder
        ASN.1 coder.
    """

    def __init__(self) -> None:
        """
        Initialize the CAM Coder.
        """
        self.asn_coder = asn1tools.compile_string(CAM_ASN1_DESCRIPTIONS, codec="uper")

    def encode(self, cam: dict) -> bytes:
        """
        Encodes a CAM message.

        Parameters
        ----------
        cam : dict
            CAM message.

        Returns
        -------
        bytes
            Encoded CAM message.
        """
        return self.asn_coder.encode("CAM", cam)

    def decode(self, cam: bytes) -> dict:
        """
        Decodes a CAM message.

        Parameters
        ----------
        cam : bytes
            Encoded CAM message.

        Returns
        -------
        dict
            CAM message.
        """
        return self.asn_coder.decode("CAM", cam)

    def encode_extension_container(self, container_id: int, value: dict) -> bytes:
        """
        Encode an extension container value to the raw bytes that go into
        the ``containerData`` open-type field of a WrappedExtensionContainer.

        Parameters
        ----------
        container_id : int
            The ExtensionContainerId (1=TwoWheeler, 2=eHorizon, 3=VLF,
            4=PathPrediction, 5=GenLanePos, 6=VehicleMovementControl).
        value : dict
            The container content as a Python dict.

        Returns
        -------
        bytes
            UPER-encoded inner container bytes suitable for
            ``containerData``.

        Raises
        ------
        ValueError
            If *container_id* is not a known ExtensionContainerId.
        """
        type_name = _EXTENSION_CONTAINER_ID_TO_TYPE.get(container_id)
        if type_name is None:
            raise ValueError(f"Unknown ExtensionContainerId: {container_id}")
        return self.asn_coder.encode(type_name, value)

    def decode_extension_container(self, container_id: int, data: bytes) -> dict:
        """
        Decode the raw ``containerData`` bytes of a WrappedExtensionContainer
        into a Python dict.

        Parameters
        ----------
        container_id : int
            The ExtensionContainerId value from the same
            WrappedExtensionContainer.
        data : bytes
            The raw ``containerData`` bytes as returned by the CAM decoder.

        Returns
        -------
        dict
            Decoded container content.

        Raises
        ------
        ValueError
            If *container_id* is not a known ExtensionContainerId.
        """
        type_name = _EXTENSION_CONTAINER_ID_TO_TYPE.get(container_id)
        if type_name is None:
            raise ValueError(f"Unknown ExtensionContainerId: {container_id}")
        return self.asn_coder.decode(type_name, data)
