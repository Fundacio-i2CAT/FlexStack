# pylint: skip-file
ETSI_TS_103_097_EXTENSION_MODULE_ASN1_DESCRIPTIONS = """
EtsiTs103097ExtensionModule
{itu-t(0) identified-organization(4) etsi(0) itsDomain(5) wg5(5) secHeaders(103097) extension(2) major-version-1(1) minor-version-2(2)}
DEFINITIONS AUTOMATIC TAGS ::= BEGIN

IMPORTS
  Extension,
  ExtId,
  HashedId8,
  Time32,
  Uint8
FROM Ieee1609Dot2BaseTypes {iso(1) identified-organization(3) ieee(111)
    standards-association-numbered-series-standards(2) wave-stds(1609)
    dot2(2) base(1) base-types(2) major-version-2 (2) minor-version-5 (5)}
;

ExtensionModuleVersion::= INTEGER(2)

EtsiOriginatingHeaderInfoExtension ::= Extension

EtsiTs102941CrlRequest::= SEQUENCE {
    issuerId        HashedId8,
    lastKnownUpdate Time32 OPTIONAL
}

EtsiTs102941CtlRequest::= SEQUENCE {
    issuerId             HashedId8,
    lastKnownCtlSequence Uint8 OPTIONAL
}

EtsiTs102941FullCtlRequest::= SEQUENCE {
    issuerId             HashedId8,
    lastKnownCtlSequence Uint8 OPTIONAL,
    segmentNumber        Uint8 OPTIONAL
}

EtsiTs102941DeltaCtlRequest::= EtsiTs102941CtlRequest

END
"""
