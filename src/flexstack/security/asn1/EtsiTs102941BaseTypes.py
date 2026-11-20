# pylint: skip-file
# ASN.1 module EtsiTs102941BaseTypes of ETSI TS 102 941 V2.2.1, verbatim (apart from whitespace) from
# https://forge.etsi.org/rep/ITS/asn1/pki_ts102941/-/raw/v2.2.1/EtsiTs102941BaseTypes.asn
ETSI_TS_102_941_BASE_TYPES_ASN1_DESCRIPTIONS = r"""
EtsiTs102941BaseTypes
{ itu-t(0) identified-organization(4) etsi(0) itsDomain(5) wg5(5) ts(102941) baseTypes(3) major-version-3(3) minor-version-1(1)}

DEFINITIONS AUTOMATIC TAGS ::=
BEGIN

IMPORTS
  HashedId8, Time32, PublicEncryptionKey, PublicVerificationKey, Signature
FROM
  Ieee1609Dot2BaseTypes {iso(1) identified-organization(3) ieee(111)
  standards-association-numbered-series-standards(2) wave-stds(1609)
  dot2(2) base(1) base-types(2) major-version-2(2) minor-version-3(3)}
  WITH SUCCESSORS

  CertificateId, SubjectAssurance, SequenceOfPsidSsp, SequenceOfPsidGroupPermissions,
  ValidityPeriod, GeographicRegion, HashedData
FROM
  Ieee1609Dot2 {iso(1) identified-organization(3) ieee(111)
  standards-association-numbered-series-standards(2) wave-stds(1609)
  dot2(2) base (1) schema (1) major-version-2(2) minor-version-4(4)}
  WITH SUCCESSORS

  EtsiTs103097Data, EtsiTs103097Data-Encrypted, EtsiTs103097Data-Signed,
  EtsiTs103097Data-SignedExternalPayload,
  EtsiTs103097Data-Unsecured, EtsiTs103097Data-Encrypted-Unicast, EtsiTs103097Data-SignedAndEncrypted-Unicast
FROM
  EtsiTs103097Module {itu-t(0) identified-organization(4) etsi(0) itsDomain(5) wg5(5) secHeaders(103097) core(1) major-version-3(3) minor-version-1(1)}
  WITH SUCCESSORS
;

CertificateFormat::= INTEGER {
  ts103097v131 (1)
  }(1..255)

CertificateSubjectAttributes ::= SEQUENCE {
  id                     CertificateId OPTIONAL,
  validityPeriod        ValidityPeriod OPTIONAL,
  region                GeographicRegion OPTIONAL,
  assuranceLevel        SubjectAssurance OPTIONAL,
  appPermissions        SequenceOfPsidSsp OPTIONAL,
  certIssuePermissions  SequenceOfPsidGroupPermissions OPTIONAL,
  ...
  }(WITH COMPONENTS { ..., appPermissions PRESENT} |
   WITH COMPONENTS { ..., certIssuePermissions PRESENT})

EcSignature::= CHOICE {
  encryptedEcSignature     EtsiTs103097Data-Encrypted{EtsiTs103097Data-SignedExternalPayload},
  ecSignature           EtsiTs103097Data-SignedExternalPayload
  }

PublicKeys ::= SEQUENCE {
  verificationKey       PublicVerificationKey,
  encryptionKey         PublicEncryptionKey OPTIONAL
  }

Version ::= INTEGER {v1(1)}

END
"""
