# pylint: skip-file
ETSI_TS_102_941_BASE_TYPES_ASN1_DESCRIPTIONS = """
EtsiTs102941BaseTypes
{itu-t(0) identified-organization(4) etsi(0) itsDomain(5) wg5(5) ts(102941) version(2)}

DEFINITIONS AUTOMATIC TAGS ::= BEGIN

IMPORTS

  PublicVerificationKey, PublicEncryptionKey,
  SequenceOfPsidSsp, SubjectAssurance, ValidityPeriod, GeographicRegion,
  HashedId8, Time32, Uint8
FROM Ieee1609Dot2BaseTypes {iso(1) identified-organization(3) ieee(111)
  standards-association-numbered-series-standards(2) wave-stds(1609)
  dot2(2) base(1) schema(1) major-version-2(2) minor-version-7(7)}

  Ieee1609Dot2Data, CertificateId, SequenceOfPsidGroupPermissions
FROM Ieee1609Dot2 {iso(1) identified-organization(3) ieee(111)
  standards-association-numbered-series-standards(2) wave-stds(1609)
  dot2(2) base(1) schema(1) major-version-2(2) minor-version-7(7)}

  EtsiTs103097Certificate
FROM EtsiTs103097Module {itu-t(0) identified-organization(4) etsi(0)
  itsDomain(5) wg5(5) secHeaders(103097) core(1) major-version-3(3)
  minor-version-2(2)}
;

-- URL type (up to 2048 UTF-8 characters)
Url ::= UTF8String (SIZE(0..2048))

-- Certificate format version: 1 = ts103097v131
CertificateFormat ::= Uint8

-- Container for the verification + optional encryption public keys
PublicKeys ::= SEQUENCE {
  verificationKey  PublicVerificationKey,
  encryptionKey    PublicEncryptionKey OPTIONAL
}

-- Subject attributes requested in EC/AT certificate
CertificateSubjectAttributes ::= SEQUENCE {
  id                   CertificateId OPTIONAL,
  validityPeriod       ValidityPeriod OPTIONAL,
  region               GeographicRegion OPTIONAL,
  assuranceLevel       SubjectAssurance OPTIONAL,
  appPermissions       SequenceOfPsidSsp OPTIONAL,
  certIssuePermissions SequenceOfPsidGroupPermissions OPTIONAL
}

-- EC signature (over SharedAtRequest), either privacy-protected (encrypted) or plain
-- The privacy case encrypts the signed structure with the EA's encryption key.
-- Both alternatives carry an EtsiTs103097Data structure.
EcSignature ::= CHOICE {
  ecSignature            Ieee1609Dot2Data,
  encryptedEcSignature   Ieee1609Dot2Data
}

-- HashedId10: 10-byte truncated hash used in CRL entries
HashedId10 ::= OCTET STRING (SIZE(10))

-- Sequential number for CTL/CRL
CtlSequenceNumber ::= Uint8

END
"""
