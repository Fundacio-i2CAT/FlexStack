# pylint: skip-file
# ASN.1 module EtsiTs102941TypesEnrolment of ETSI TS 102 941 V2.2.1, verbatim (apart from whitespace) from
# https://forge.etsi.org/rep/ITS/asn1/pki_ts102941/-/raw/v2.2.1/EtsiTs102941TypesEnrolment.asn
ETSI_TS_102_941_TYPES_ENROLMENT_ASN1_DESCRIPTIONS = r"""
EtsiTs102941TypesEnrolment
  { itu-t(0) identified-organization(4) etsi(0) itsDomain(5) wg5(5) ts(102941) enrolment(4) major-version-3(3) minor-version-1(1) }

DEFINITIONS AUTOMATIC TAGS ::=
BEGIN

IMPORTS

EtsiTs103097Certificate,
EtsiTs103097Data-Signed
FROM EtsiTs103097Module
{ itu-t(0) identified-organization(4) etsi(0) itsDomain(5) wg5(5) secHeaders(103097) core(1) major-version-3(3) minor-version-1(1) }
WITH SUCCESSORS

CertificateFormat, CertificateSubjectAttributes, EcSignature, HashedId8, PublicKeys, Version
FROM EtsiTs102941BaseTypes
{ itu-t(0) identified-organization(4) etsi(0) itsDomain(5) wg5(5) ts(102941) baseTypes(3) major-version-3(3) minor-version-1(1) }
WITH SUCCESSORS
;

/************
-- EnrolmentRequest/Response
************/

EnrolmentResponseCode ::= ENUMERATED {
  ok(0),
  cantparse, -- valid for any structure
  badcontenttype, -- not encrypted, not signed, not enrolmentrequest
  imnottherecipient, -- the "recipients" doesn't include me
  unknownencryptionalgorithm, -- either kexalg or contentencryptionalgorithm
  decryptionfailed, -- works for ECIES-HMAC and AES-CCM
  unknownits, -- can't retrieve the ITS from the itsId
  invalidsignature, -- signature verification of the request fails
  invalidencryptionkey, -- signature is good, but the responseEncryptionKey is bad
  baditsstatus, -- revoked, not yet active
  incompleterequest, -- some elements are missing
  deniedpermissions, -- requested permissions are not granted
  invalidkeys, -- either the verification_key of the encryption_key is bad
  deniedrequest, -- any other reason?
  ... }

InnerEcRequestSignedForPop::= EtsiTs103097Data-Signed{InnerEcRequest}

InnerEcRequest ::= SEQUENCE {
  itsId                                 OCTET STRING,
  certificateFormat                     CertificateFormat,
  publicKeys                            PublicKeys,
  requestedSubjectAttributes            CertificateSubjectAttributes (WITH COMPONENTS{..., certIssuePermissions ABSENT}),
  ...
 }

InnerEcResponse ::= SEQUENCE {
  requestHash                           OCTET STRING (SIZE(16)),
  responseCode                          EnrolmentResponseCode,
  certificate                           EtsiTs103097Certificate OPTIONAL,
  ...
 }
  (WITH COMPONENTS { responseCode (ok), certificate PRESENT }
     | WITH COMPONENTS { responseCode (ALL EXCEPT ok), certificate ABSENT }
  )

END
"""
