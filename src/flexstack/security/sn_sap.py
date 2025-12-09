"""
Security Network - Service Access Point (SN-SAP) module

This module implements the SN-SAP interface for the Security Network.

This module is based in ETSI TS 102 723-8 V1.1.1 (2016-04)
"""

from __future__ import annotations
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum


@dataclass(frozen=True)
class SNSIGNRequest:
    """
    SN-SIGN.request class as specified in ETSI TS 102 723-8 V1.1.1 (2016-04) 5.2.1.2

    ...

    Attributes
    ----------
    tbs_message_length : int
        Length of the message to be signed (16 bits range)
    tbs_message : bytes
        Message to be signed
    its_aid : int
        ITS AID (Determines the security profile to apply)
    permissions_length : int
        Length of the permissions field (16 bits range)
    permissions : bytes
        Specify the sender's permissions for the security entity to decide which key to use. (Max length 31 octets)
    context_information : bytes (optional)
        Context information which could be used in selecting properties of the underlying security protocol for various purposes.
    key_handle : int (optional)
        An indicator for the security entity to decide which key to use
    """
    tbs_message_length: int
    tbs_message: bytes
    its_aid: int
    permissions_length: int
    permissions: bytes
    context_information: bytes | None = None
    key_handle: int | None = None

    def __repr__(self):
        return (
            f"SNSIGNRequest(tbs_message_length={self.tbs_message_length}, "
            f"tbs_message={self.tbs_message}, its_aid={self.its_aid}, "
            f"permissions_length={self.permissions_length}, permissions={self.permissions}, "
            f"context_information={self.context_information}, key_handle={self.key_handle})"
        )

    def __str__(self):
        return (
            f"SNSIGNRequest(tbs_message_length={self.tbs_message_length}, "
            f"tbs_message={self.tbs_message}, its_aid={self.its_aid}, "
            f"permissions_length={self.permissions_length}, permissions={self.permissions}, "
            f"context_information={self.context_information}, key_handle={self.key_handle})"
        )


@dataclass(frozen=True)
class SNSIGNConfirm:
    """
    SN-SIGN.confirm class as specified in ETSI TS 102 723-8 V1.1.1 (2016-04) 5.2.1.3

    ...
    Attributes
    ----------
    sec_message_length : int
        Length of the signed message (16 bits range)
    sec_message : bytes
        Signed message
    """
    sec_message_length: int
    sec_message: bytes

    def __repr__(self):
        return f"SNSIGNConfirm(sec_message_length={self.sec_message_length}, sec_message={self.sec_message})"

    def __str__(self):
        return f"SNSIGNConfirm(sec_message_length={self.sec_message_length}, sec_message={self.sec_message})"


@dataclass(frozen=True)
class SNVERIFYRequest:
    """
    SN-VERIFY.request class as specified in ETSI TS 102 723-8 V1.1.1 (2016-04) 5.2.2.2

    ...
    Attributes
    ----------
    sec_header_length : int
        Length of the security header (16 bits range)
    sec_header : bytes
        Security header
    message_length : int
        Length of the message to be verified (16 bits range)
    message : bytes
        Message to be verified
    """
    sec_header_length: int
    sec_header: bytes
    message_length: int
    message: bytes

    def __repr__(self):
        return (
            f"SNVERIFYRequest(sec_header_length={self.sec_header_length}, "
            f"sec_header={self.sec_header}, message_length={self.message_length}, "
            f"message={self.message})"
        )

    def __str__(self):
        return (
            f"SNVERIFYRequest(sec_header_length={self.sec_header_length}, "
            f"sec_header={self.sec_header}, message_length={self.message_length}, "
            f"message={self.message})"
        )


class ReportVerify(Enum):
    """
    ReportVerify class as specified in ETSI TS 102 723-8 V1.1.1 (2016-04) 5.2.2.3 (Table 5) 2nd Row

    ...
    Attributes
    ----------
    SUCCESS
    FALSE_SIGNATURE
    INVALID_CERTIFICATE
    REVOKED_CERTIFICATE
    INCONSISTENT_CHAIN
    INVALID_TIMESTAMP
    DUPLICATE_MESSAGE
    INVALID_MOBILITY_DATA
    UNSIGNED_MESSAGE
    SIGNER_CERTIFICATE_NOT_FOUND
    UNSUPPORTED_SIGNER_IDENTIFIER_TYPE
    INCOMPATIBLE_PROTOCOL
    """

    SUCCESS = 0
    FALSE_SIGNATURE = 1
    INVALID_CERTIFICATE = 2
    REVOKED_CERTIFICATE = 3
    INCONSISTENT_CHAIN = 4
    INVALID_TIMESTAMP = 5
    DUPLICATE_MESSAGE = 6
    INVALID_MOBILITY_DATA = 7
    UNSIGNED_MESSAGE = 8
    SIGNER_CERTIFICATE_NOT_FOUND = 9
    UNSUPPORTED_SIGNER_IDENTIFIER_TYPE = 10
    INCOMPATIBLE_PROTOCOL = 11


@dataclass(frozen=True)
class SNVERIFYConfirm:
    """
    SN-VERIFY.confirm class as specified in ETSI TS 102 723-8 V1.1.1 (2016-04) 5.2.2.3

    ...
    Attributes
    ----------
    report : ReportVerify
        Verification report
    certificate_id : bytes
        Identification of the source certificate (8 octets)
    its_aid_length : int
        Length of the ITS AID (16 bits range)
    its_aid : bytes
        ITS AID
    permissions : bytes
        Permissions of the signer (Max length 31 octets)
    """
    report: ReportVerify
    certificate_id: bytes
    its_aid_length: int
    its_aid: bytes
    permissions: bytes

    def __repr__(self):
        return (
            f"SNVERIFYConfirm(report={self.report}, certificate_id={self.certificate_id}, "
            f"its_aid_length={self.its_aid_length}, its_aid={self.its_aid}, "
            f"permissions={self.permissions})"
        )

    def __str__(self):
        return (
            f"SNVERIFYConfirm(report={self.report}, certificate_id={self.certificate_id}, "
            f"its_aid_length={self.its_aid_length}, its_aid={self.its_aid}, "
            f"permissions={self.permissions})"
        )


@dataclass(frozen=True)
class SNENCRYPTRequest:
    """
    SN-ENCRYPT.request class as specified in ETSI TS 102 723-8 V1.1.1 (2016-04) 5.2.3.2

    ...
    Attributes
    ----------
    tbe_payload_length : int
        Length of the payload to be encrypted (16 bits range)
    tbe_payload : bytes
        Payload to be encrypted
    target_id_list_length : int
        Length of the list of target identifiers (16 bits range)
    target_id_list : list[bytes]
        List of target identifiers
    context_information : bytes (optional)
        Context information
    """
    tbe_payload_length: int
    tbe_payload: bytes
    target_id_list_length: int
    target_id_list: list[bytes]
    context_information: bytes

    def __repr__(self):
        return (
            f"SNENCRYPTRequest(tbe_payload_length={self.tbe_payload_length}, tbe_payload={self.tbe_payload}, "
            f"target_id_list_length={self.target_id_list_length}, target_id_list={self.target_id_list}, "
            f"context_information={self.context_information})"
        )

    def __str__(self):
        return (
            f"SNENCRYPTRequest(tbe_payload_length={self.tbe_payload_length}, tbe_payload={self.tbe_payload}, "
            f"target_id_list_length={self.target_id_list_length}, target_id_list={self.target_id_list}, "
            f"context_information={self.context_information})"
        )


@dataclass(frozen=True)
class SNENCRYPTConfirm:
    """
    SN-ENCRYPT.confirm class as specified in ETSI TS 102 723-8 V1.1.1 (2016-04) 5.2.3.3

    ...
    Attributes
    ----------
    encrypted_message_length : int
        Length of the encrypted message (16 bits range)
    encrypted_message : bytes
        Encrypted message
    """
    encrypted_message_length: int
    encrypted_message: bytes

    def __repr__(self):
        return (
            f"SNENCRYPTConfirm(encrypted_message_length={self.encrypted_message_length}, "
            f"encrypted_message={self.encrypted_message})"
        )

    def __str__(self):
        return (
            f"SNENCRYPTConfirm(encrypted_message_length={self.encrypted_message_length}, "
            f"encrypted_message={self.encrypted_message})"
        )


@dataclass(frozen=True)
class SNDECRYPTRequest:
    """
    SN-DECRYPT.request class as specified in ETSI TS 102 723-8 V1.1.1 (2016-04) 5.2.4.2

    ...
    Attributes
    ----------
    encrypted_message_length : int
        Length of the encrypted message (16 bits range)
    encrypted_message : bytes
        Encrypted message
    """
    encrypted_message_length: int
    encrypted_message: bytes

    def __repr__(self):
        return (
            f"SNDECRYPTRequest(encrypted_message_length={self.encrypted_message_length}, "
            f"encrypted_message={self.encrypted_message})"
        )

    def __str__(self):
        return (
            f"SNDECRYPTRequest(encrypted_message_length={self.encrypted_message_length}, "
            f"encrypted_message={self.encrypted_message})"
        )


class ReportDecrypt(Enum):
    """
    ReportDecrypt class as specified in ETSI TS 102 723-8 V1.1.1 (2016-04) 5.2.4.3 Table 9 Row 4

    ...
    Attributes
    ----------
    SUCCESS
    UNENCRYPTED_MESSAGE
    DECRYPTION_ERROR
    INCOMPATIBLE_PROTOCOL
    """

    SUCCESS = 0
    UNENCRYPTED_MESSAGE = 1
    DECRYPTION_ERROR = 2
    INCOMPATIBLE_PROTOCOL = 3


@dataclass(frozen=True)
class SNDECRYPTConfirm:
    """
    SN-DECRYPT.confirm class as specified in ETSI TS 102 723-8 V1.1.1 (2016-04) 5.2.4.3

    ...
    Attributes
    ----------
    plaintext_message_length : int
        Length of the plaintext message (16 bits range)
    plaintext_message : bytes
        Plaintext message
    report : ReportDecrypt
        Decryption report
    """
    plaintext_message_length: int
    plaintext_message: bytes
    report: ReportDecrypt

    def __repr__(self):
        return (
            f"SNDECRYPTConfirm(plaintext_message_length={self.plaintext_message_length}, "
            f"plaintext_message={self.plaintext_message}, report={self.report})"
        )

    def __str__(self):
        return (
            f"SNDECRYPTConfirm(plaintext_message_length={self.plaintext_message_length}, "
            f"plaintext_message={self.plaintext_message}, report={self.report})"
        )


class SNIDCHANGEEVENTCommand(Enum):
    """
    SN-ID-CHANGE-EVENT.command class as specified in ETSI TS 102 723-8 V1.1.1 (2016-04) 5.2.6.2 Table 12 Row 2

    ...
    Attributes
    ----------
    PREPARE
    COMMIT
    ABORT
    DEREG
    """

    PREPARE = 0
    COMMIT = 1
    ABORT = 2
    DEREG = 3


@dataclass(frozen=True)
class SNIDCHANGEEVENTIndication:
    """
    SN-ID-CHANGE-EVENT.indication class as specified in ETSI TS 102 723-8 V1.1.1 (2016-04) 5.2.6.2

    ...
    Attributes
    ----------
    command : SNIDCHANGEEVENTCommand
        Command
    identifier : bytes
        ID (8 octets)
    subscriber_data : bytes (optional)
        Subscriber data
    """
    command: SNIDCHANGEEVENTCommand
    identifier: bytes
    subscriber_data: bytes | None = None

    def __repr__(self):
        return (
            f"SNIDCHANGEEVENTIndication(command={self.command}, identifier={self.identifier}, "
            f"subscriber_data={self.subscriber_data})"
        )

    def __str__(self):
        return (
            f"SNIDCHANGEEVENTIndication(command={self.command}, id={self.identifier}, "
            f"subscriber_data={self.subscriber_data})"
        )


@dataclass(frozen=True)
class SNIDCHANGEEVENTResponse:
    """
    SN-ID-CHANGE-EVENT.response class as specified in ETSI TS 102 723-8 V1.1.1 (2016-04) 5.2.6.3

    ...
    Attributes
    ----------
    return_code : bool
        Acknowledgement of the command
    """
    return_code: bool

    def __repr__(self):
        return f"SNIDCHANGEEVENTResponse(return_code={self.return_code})"

    def __str__(self):
        return f"SNIDCHANGEEVENTResponse(return_code={self.return_code})"


@dataclass(frozen=True)
class SNIDCHANGESUBSCRIBERequest:
    """
    SN-ID-CHANGE-SUBSCRIBE.request class as specified in ETSI TS 102 723-8 V1.1.1 (2016-04) 5.2.5.2

    ...
    Attributes
    ----------
    idchange_event_hook : Callable[[SNIDCHANGEEVENTIndication, bytes], None]
        Callback function to be called when the ID-Change event occurs
    subscriber_data : bytes (optional)
        Subscriber data
    """

    idchange_event_hook: Callable[[SNIDCHANGEEVENTIndication, bytes], None]
    subscriber_data: bytes | None = None

    def __repr__(self):
        return (
            f"SNIDCHANGESUBSCRIBERequest(idchange_event_hook={self.idchange_event_hook}, "
            f"subscriber_data={self.subscriber_data})"
        )

    def __str__(self):
        return (
            f"SNIDCHANGESUBSCRIBERequest(idchange_event_hook={self.idchange_event_hook}, "
            f"subscriber_data={self.subscriber_data})"
        )


@dataclass(frozen=True)
class SNIDCHANGESUBSCRIBEConfirm:
    """
    SN-ID-CHANGE-SUBSCRIBE.confirm class as specified in ETSI TS 102 723-8 V1.1.1 (2016-04) 5.2.5.3

    ...
    Attributes
    ----------
    subscription : int
        Subscription handle for unsubscribe (64 bits range)
    """

    subscription: int

    def __repr__(self):
        return f"SNIDCHANGESUBSCRIBEConfirm(subscription={self.subscription})"

    def __str__(self):
        return f"SNIDCHANGESUBSCRIBEConfirm(subscription={self.subscription})"


@dataclass(frozen=True)
class SNIDCHANGEUNSUBSCRIBERequest:
    """
    SN-IDCHANGE-UNSUBSCRIBE.request class as specified in ETSI TS 102 723-8 V1.1.1 (2016-04) 5.2.7.2

    ...
    Attributes
    ----------
    subscription : int
        Subscription handle, given through Mandatory subscribe (64 bits range)
    """
    subscription: int

    def __repr__(self):
        return f"SNIDCHANGEUNSUBSCRIBERequest(subscription={self.subscription})"

    def __str__(self):
        return f"SNIDCHANGEUNSUBSCRIBERequest(subscription={self.subscription})"


@dataclass(frozen=True)
class SNIDCHANGEUNSUBSCRIBEConfirm:
    """
    SN-IDCHANGE-UNSUBSCRIBE.confirm class as specified in ETSI TS 102 723-8 V1.1.1 (2016-04) 5.2.7.3

    ...
    Empty
    """

    def __repr__(self):
        return "SNIDCHANGEUNSUBSCRIBEConfirm()"

    def __str__(self):
        return "SNIDCHANGEUNSUBSCRIBEConfirm()"


@dataclass(frozen=True)
class SNIDCHANGETRIGGERRequest:
    """
    SN-ID-CHANGE-TRIGGER.request class as specified in ETSI TS 102 723-8 V1.1.1 (2016-04) 5.2.8.2

    ...
    Empty
    """

    def __repr__(self):
        return "SNIDCHANGETRIGGERRequest()"

    def __str__(self):
        return "SNIDCHANGETRIGGERRequest()"


@dataclass(frozen=True)
class SNIDCHANGETRIGGERConfirm:
    """
    SN-ID-CHANGE-TRIGGER.confirm class as specified in ETSI TS 102 723-8 V1.1.1 (2016-04) 5.2.8.3

    ...
    Empty
    """

    def __repr__(self):
        return "SNIDCHANGETRIGGERConfirm()"

    def __str__(self):
        return "SNIDCHANGETRIGGERConfirm()"


@dataclass(frozen=True)
class SNIDLOCKRequest:
    """
    SN-ID-LOCK.request class as specified in ETSI TS 102 723-8 V1.1.1 (2016-04) 5.2.9.2

    ...
    Attributes
    ----------
    duration : int
        Number of seconds to lock (1 octet)
    """

    duration: int

    def __repr__(self):
        return f"SNIDLOCKRequest(duration={self.duration})"

    def __str__(self):
        return f"SNIDLOCKRequest(duration={self.duration})"


@dataclass(frozen=True)
class SNIDLOCKConfirm:
    """
    SN-ID-LOCK.confirm class as specified in ETSI TS 102 723-8 V1.1.1 (2016-04) 5.2.9.3

    ...
    Attributes
    ----------
    lock_handle : int
        Handle to unlock manually (64 bits range)
    """

    lock_handle: int

    def __repr__(self):
        return f"SNIDLOCKConfirm(lock_handle={self.lock_handle})"

    def __str__(self):
        return f"SNIDLOCKConfirm(lock_handle={self.lock_handle})"


@dataclass(frozen=True)
class SNIDUNLOCKRequest:
    """
    SN-ID-UNLOCK.request class as specified in ETSI TS 102 723-8 V1.1.1 (2016-04) 5.2.10.2

    ...
    Attributes
    ----------
    lock_handle : int
        Handle to unlock manually (64 bits range)
    """

    lock_handle: int

    def __repr__(self):
        return f"SNIDUNLOCKRequest(lock_handle={self.lock_handle})"

    def __str__(self):
        return f"SNIDUNLOCKRequest(lock_handle={self.lock_handle})"


@dataclass(frozen=True)
class SNIDUNLOCKConfirm:
    """
    SN-ID-UNLOCK.confirm class as specified in ETSI TS 102 723-8 V1.1.1 (2016-04) 5.2.10.3

    ...
    Empty
    """

    def __repr__(self):
        return "SNIDUNLOCKConfirm()"

    def __str__(self):
        return "SNIDUNLOCKConfirm()"


class SNLOGSECURITYEVENTEventType(Enum):
    """
    SN-LOG-SECURITY-EVENT.event-type as specified in ETSI TS 102 723-8 V1.1.1 (2016-04) 5.2.11.2

    ...
    Attributes
    ----------
    TIME_CONSISTENCY_FAILED
    LOCATION_CONSISTENCY_FAILED
    ID_CONSISTENCY_FAILED
    DISALLOWED_MESSAGE_CONTENT
    DISALLOWED_MESSAGE_FREQUENCY
    REPLAY_DETECTION_TIME
    REPLAY_DETECTION_LOCATION
    MOVEMENT_PLAUSIBILITY
    APPEARANCE_PLAUSIBILITY
    LOCATION_PLAUSIBILITY_SENSOR
    LOCATION_PLAUSIBILITY_MAP
    LOCATION_PLAUSIBILITY_CONTRADICTION
    LOCATION_PLAUSIBILITY_CONTRADICTION_VEHICLE_DIMENSION
    LOCATION_PLAUSIBILITY_CONTRADICTION_NEIGHBOR_INFO
    """

    TIME_CONSISTENCY_FAILED = 0x01
    LOCATION_CONSISTENCY_FAILED = 0x02
    ID_CONSISTENCY_FAILED = 0x03
    DISALLOWED_MESSAGE_CONTENT = 0x04
    DISALLOWED_MESSAGE_FREQUENCY = 0x05
    REPLAY_DETECTION_TIME = 0x06
    REPLAY_DETECTION_LOCATION = 0x07
    MOVEMENT_PLAUSIBILITY = 0x08
    APPEARANCE_PLAUSIBILITY = 0x09
    LOCATION_PLAUSIBILITY_SENSOR = 0x0A
    LOCATION_PLAUSIBILITY_MAP = 0x0B
    LOCATION_PLAUSIBILITY_CONTRADICTION = 0x0C
    LOCATION_PLAUSIBILITY_CONTRADICTION_VEHICLE_DIMENSION = 0x0D
    LOCATION_PLAUSIBILITY_CONTRADICTION_NEIGHBOR_INFO = 0x0E


class SNLOGSECURITYEVENTEventEvidenceType(Enum):
    """
    SN-LOG-SECURITY-EVENT.event-evidence-type as specified in ETSI TS 102 723-8 V1.1.1 (2016-04)

    ...
    Attributes
    ----------
    CAM
    DENM
    """

    CAM = 0x01
    DENM = 0x02


@dataclass(frozen=True)
class SNLOGSECURITYEVENTRequest:
    # pylint: disable=too-many-arguments
    """
    SN-LOG-SECURITY-EVENT.request class as specified in ETSI TS 102 723-8 V1.1.1 (2016-04) 5.2.11.2

    ...
    Attributes
    ----------
    event_type : SNLOGSECURITYEVENTEventType
        Type of security event
    neighbour_id_list_length : int
        Length of neighbour ID list (1 octet)
    neighbour_id_list : list[bytes]
        List of affected V2X neighbour nodes, expressed via certificate hash
    event_time : int
        Timestamp of security event (4 octets)
    event_location : dict (optional)
        Location of security event in format {"latitude": float, "longitude": float}
    event_evidence_list_length : int (optional)
        Length of event evidence list (4 octets)
    event_evidence_list : list[dict] (optional)
        List of event evidence in format {"length": int, "data": bytes}
    event_evidence_type : SNLOGSECURITYEVENTEventEvidenceType (optional)
        Type of event evidence
    event_evidence_content_length : int (optional)
        Length of event evidence content (4 octets)
    event_evidence_content : bytes (optional)
        Event evidence content
    """
    event_type: SNLOGSECURITYEVENTEventType
    neighbour_id_list_length: int
    neighbour_id_list: list[bytes]
    event_time: int
    event_location: dict | None = None
    event_evidence_list_length: int | None = None
    event_evidence_list: list[dict] | None = None
    event_evidence_type: SNLOGSECURITYEVENTEventEvidenceType | None = None
    event_evidence_content_length: int | None = None
    event_evidence_content: bytes | None = None

    def __repr__(self):
        return (
            f"SNLOGSECURITYEVENTRequest(event_type={self.event_type}, "
            f"neighbour_id_list_length={self.neighbour_id_list_length}, "
            f"neighbour_id_list={self.neighbour_id_list}, event_time={self.event_time}, "
            f"event_location={self.event_location}, event_evidence_list_length={self.event_evidence_list_length}, "
            f"event_evidence_list={self.event_evidence_list}, event_evidence_type={self.event_evidence_type}, "
            f"event_evidence_content_length={self.event_evidence_content_length}, "
            f"event_evidence_content={self.event_evidence_content})"
        )

    def __str__(self):
        return (
            f"SNLOGSECURITYEVENTRequest(event_type={self.event_type}, "
            f"neighbour_id_list_length={self.neighbour_id_list_length}, "
            f"neighbour_id_list={self.neighbour_id_list}, event_time={self.event_time}, "
            f"event_location={self.event_location}, event_evidence_list_length={self.event_evidence_list_length}, "
            f"event_evidence_list={self.event_evidence_list}, event_evidence_type={self.event_evidence_type}, "
            f"event_evidence_content_length={self.event_evidence_content_length}, "
            f"event_evidence_content={self.event_evidence_content})"
        )


@dataclass(frozen=True)
class SNLOGSECURITYEVENTConfirm:
    """
    SN-LOG-SECURITY-EVENT.confirm class as specified in ETSI TS 102 723-8 V1.1.1 (2016-04) 5.2.11.3

    ...
    Empty
    """

    def __init__(self):
        pass

    def __repr__(self):
        return "SNLOGSECURITYEVENTConfirm()"

    def __str__(self):
        return "SNLOGSECURITYEVENTConfirm()"


@dataclass(frozen=True)
class SNENCAPRequest:
    """
    SN-ENCAP.request class as specified in ETSI TS 102 723-8 V1.1.1 (2016-04) 5.2.12.2

    ...
    Attributes
    ----------
    tbe_packet_length : int
        Length of TBE packet (2 octets)
    tbe_packet : bytes
        TBE packet
    sec_services : int (optional)
        Security services to invoke (2 octets)
    its_aid_length : int (optional)
        Length of ITS AID (2 octets)
    its_aid : int
        ITS AID
    permissions : bytes
        SSP associated with the ITS AID (Max length 31 octets)
    context_information : bytes (optional)
        Context information
    target_id_list_length : int (optional)
        Length of target ID list (2 octets)
    target_id_list : list[bytes] (optional)
        List of target IDs
    """
    tbe_packet_length: int
    tbe_packet: bytes
    sec_services: int | None = None
    its_aid_length: int | None = None
    its_aid: int | None = None
    permissions: bytes | None = None
    context_information: bytes | None = None
    target_id_list_length: int | None = None
    target_id_list: list[bytes] | None = None

    def __repr__(self):
        return (
            f"SNENCAPRequest(tbe_packet_length={self.tbe_packet_length}, tbe_packet={self.tbe_packet}, "
            f"sec_services={self.sec_services}, its_aid_length={self.its_aid_length}, its_aid={self.its_aid}, "
            f"permissions={self.permissions}, context_information={self.context_information}, "
            f"target_id_list_length={self.target_id_list_length}, target_id_list={self.target_id_list})"
        )

    def __str__(self):
        return (
            f"SNENCAPRequest(tbe_packet_length={self.tbe_packet_length}, tbe_packet={self.tbe_packet}, "
            f"sec_services={self.sec_services}, its_aid_length={self.its_aid_length}, its_aid={self.its_aid}, "
            f"permissions={self.permissions}, context_information={self.context_information}, "
            f"target_id_list_length={self.target_id_list_length}, target_id_list={self.target_id_list})"
        )


@dataclass(frozen=True)
class SNENCAPConfirm:
    """
    SN-ENCAP.confirm class as specified in ETSI TS 102 723-8 V1.1.1 (2016-04) 5.2.12.3

    ...
    Attributes
    ----------
    sec_packet_length : int
        Length of security packet (2 octets)
    sec_packet : bytes
        Security packet
    """
    sec_packet_length: int
    sec_packet: bytes

    def __repr__(self):
        return f"SNENCAPConfirm(sec_packet_length={self.sec_packet_length}, sec_packet={self.sec_packet})"

    def __str__(self):
        return f"SNENCAPConfirm(sec_packet_length={self.sec_packet_length}, sec_packet={self.sec_packet})"


@dataclass(frozen=True)
class SNDECAPRequest:
    """
    SN-DECAP.request class as specified in ETSI TS 102 723-8 V1.1.1 (2016-04) 5.2.13.2

    ...
    Attributes
    ----------
    sec_packet_length : int
        Length of security packet (2 octets)
    sec_packet : bytes
        Security packet
    """
    sec_packet_length: int
    sec_packet: bytes

    def __repr__(self):
        return f"SNDECAPRequest(sec_packet_length={self.sec_packet_length}, sec_packet={self.sec_packet})"

    def __str__(self):
        return f"SNDECAPRequest(sec_packet_length={self.sec_packet_length}, sec_packet={self.sec_packet})"


class SNDECAPReport(Enum):
    """
    SN-DECAP.report class as specified in ETSI TS 102 723-8 V1.1.1 (2016-04) 5.2.13.3 Table 27 row 4

    ...
    Attributes
    ----------
    SUCCESS
    FALSE_SIGNATURE
    INVALID_CERTIFICATE
    REVOKED_CERTIFICATE
    INCONSISTENT_CHAIN
    INVALID_TIMESTAMP
    DUPLICATE_MESSAGE
    INVALID_MOBILITY_DATA
    UNSIGNED_MESSAGE
    SIGNER_CERTIFICATE_NOT_FOUND
    UNSUPPORTED_SIGNER_IDENTIFIER_TYPE
    INCOMPATIBLE_PROTOCOL
    UNENCRYPTED_MESSAGE
    DECRYPTION_ERROR
    """

    SUCCESS = 0
    FALSE_SIGNATURE = 1
    INVALID_CERTIFICATE = 2
    REVOKED_CERTIFICATE = 3
    INCONSISTENT_CHAIN = 4
    INVALID_TIMESTAMP = 5
    DUPLICATE_MESSAGE = 6
    INVALID_MOBILITY_DATA = 7
    UNSIGNED_MESSAGE = 8
    SIGNER_CERTIFICATE_NOT_FOUND = 9
    UNSUPPORTED_SIGNER_IDENTIFIER_TYPE = 10
    INCOMPATIBLE_PROTOCOL = 11
    UNENCRYPTED_MESSAGE = 12
    DECRYPTION_ERROR = 13


@dataclass(frozen=True)
class SNDECAPConfirm:
    """
    SN-DECAP.confirm class as specified in ETSI TS 102 723-8 V1.1.1 (2016-04) 5.2.13.3

    ...
    Attributes
    ----------
    plaintext_packet_length : int
        Length of plaintext packet (2 octets)
    plaintext_packet : bytes
        Plaintext packet
    report: SNDECAPReport
        Report
    certificate_id : bytes (optional)
        Certificate ID (8 octets)
    its_aid_length : int
        Length of ITS AID (2 octets)
    its_aid : int
        ITS AID
    permissions : bytes (optional)
        SSP associated with the ITS AID (Max length 31 octets)
    """
    plaintext_packet_length: int
    plaintext_packet: bytes
    report: SNDECAPReport
    certificate_id: bytes | None = None
    its_aid_length: int | None = None
    its_aid: int | None = None
    permissions: bytes | None = None

    def __repr__(self):
        return (
            f"SNDECAPConfirm(plaintext_packet_length={self.plaintext_packet_length}, "
            f"plaintext_packet={self.plaintext_packet}, report={self.report}, "
            f"certificate_id={self.certificate_id}, its_aid_length={self.its_aid_length}, "
            f"its_aid={self.its_aid}, permissions={self.permissions})"
        )

    def __str__(self):
        return (
            f"SNDECAPConfirm(plaintext_packet_length={self.plaintext_packet_length}, "
            f"plaintext_packet={self.plaintext_packet}, report={self.report}, "
            f"certificate_id={self.certificate_id}, its_aid_length={self.its_aid_length}, "
            f"its_aid={self.its_aid}, permissions={self.permissions})"
        )
