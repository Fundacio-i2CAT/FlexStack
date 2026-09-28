# pylint: skip-file
ETSI_TS_102_941_MESSAGES_ITSS_ASN1_DESCRIPTIONS = """
EtsiTs102941MessagesItss
{itu-t(0) identified-organization(4) etsi(0) itsDomain(5) wg5(5) ts(102941) version(2)}

DEFINITIONS AUTOMATIC TAGS ::= BEGIN

IMPORTS

  Uint8
FROM Ieee1609Dot2BaseTypes {iso(1) identified-organization(3) ieee(111)
  standards-association-numbered-series-standards(2) wave-stds(1609)
  dot2(2) base(1) schema(1) major-version-2(2) minor-version-7(7)}

  InnerECRequest, InnerECResponse
FROM EtsiTs102941TypesEnrolment {itu-t(0) identified-organization(4) etsi(0)
  itsDomain(5) wg5(5) ts(102941) version(2)}

  InnerAtRequest, InnerAtResponse
FROM EtsiTs102941TypesAuthorization {itu-t(0) identified-organization(4) etsi(0)
  itsDomain(5) wg5(5) ts(102941) version(2)}

  AuthorizationValidationRequest, AuthorizationValidationResponse
FROM EtsiTs102941TypesAuthorizationValidation {itu-t(0) identified-organization(4) etsi(0)
  itsDomain(5) wg5(5) ts(102941) version(2)}

  ToBeSignedRcaCtl, ToBeSignedCrl
FROM EtsiTs102941TrustLists {itu-t(0) identified-organization(4) etsi(0)
  itsDomain(5) wg5(5) ts(102941) version(2)}
;

-- TS 102 941 v2.2.1 §6.2 — Top-level ETSI TS 102 941 message envelope
-- This wraps all PKI protocol messages with a version field.
-- Conveyed as the payload of an EtsiTs103097Data-Signed or -Encrypted structure.

EtsiTs102941Data ::= SEQUENCE {
  version  Uint8 (1),
  content  EtsiTs102941DataContent
}

EtsiTs102941DataContent ::= CHOICE {
  enrolmentRequest                InnerECRequest,
  enrolmentResponse               InnerECResponse,
  authorizationRequest            InnerAtRequest,
  authorizationResponse           InnerAtResponse,
  authorizationValidationRequest  AuthorizationValidationRequest,
  authorizationValidationResponse AuthorizationValidationResponse,
  certificateTrustListTlm         ToBeSignedRcaCtl,
  certificateTrustListRca         ToBeSignedRcaCtl,
  certificateRevocationList       ToBeSignedCrl
}

END
"""
