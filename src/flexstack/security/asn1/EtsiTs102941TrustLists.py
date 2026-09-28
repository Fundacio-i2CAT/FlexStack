# pylint: skip-file
ETSI_TS_102_941_TRUST_LISTS_ASN1_DESCRIPTIONS = """
EtsiTs102941TrustLists
{itu-t(0) identified-organization(4) etsi(0) itsDomain(5) wg5(5) ts(102941) version(2)}

DEFINITIONS AUTOMATIC TAGS ::= BEGIN

IMPORTS

  Time32, HashedId8
FROM Ieee1609Dot2BaseTypes {iso(1) identified-organization(3) ieee(111)
  standards-association-numbered-series-standards(2) wave-stds(1609)
  dot2(2) base(1) schema(1) major-version-2(2) minor-version-7(7)}

  EtsiTs103097Certificate
FROM EtsiTs103097Module {itu-t(0) identified-organization(4) etsi(0)
  itsDomain(5) wg5(5) secHeaders(103097) core(1) major-version-3(3)
  minor-version-2(2)}

  Url, CtlSequenceNumber, HashedId10
FROM EtsiTs102941BaseTypes {itu-t(0) identified-organization(4) etsi(0)
  itsDomain(5) wg5(5) ts(102941) version(2)}
;

-- TS 102 941 v2.2.1 §6.3 — Trust List structures

-- Top-level CTL format: full or delta
CtlFormat ::= CHOICE {
  fullCtl   ToBeSignedRcaCtl,
  deltaCtl  ToBeSignedRcaCtl
}

-- Full and delta share the same structure (distinguished by context)
ToBeSignedRcaCtl ::= SEQUENCE {
  version      INTEGER (1),
  nextUpdate   Time32,
  isFullCtl    BOOLEAN,
  ctlSequence  CtlSequenceNumber,
  ctlCommands  SEQUENCE OF CtlCommand
}

CtlCommand ::= CHOICE {
  add     CtlEntry,
  delete  CtlDeleteEntry
}

CtlEntry ::= CHOICE {
  ea  EaEntry,
  aa  AaEntry,
  dc  DcEntry
}

CtlDeleteEntry ::= CHOICE {
  ea  HashedId8,
  aa  HashedId8,
  dc  HashedId8
}

EaEntry ::= SEQUENCE {
  eaCertificate  EtsiTs103097Certificate,
  aaAccessPoint  Url OPTIONAL,
  itsAccessPoint Url OPTIONAL
}

AaEntry ::= SEQUENCE {
  aaCertificate  EtsiTs103097Certificate,
  itsAccessPoint Url OPTIONAL
}

DcEntry ::= SEQUENCE {
  url            Url,
  cert           SEQUENCE OF EtsiTs103097Certificate OPTIONAL
}

-- CRL structures (TS 102 941 v2.2.1 §6.3.5)
ToBeSignedCrl ::= SEQUENCE {
  version     INTEGER (1),
  thisUpdate  Time32,
  nextUpdate  Time32,
  entries     SEQUENCE OF CrlEntry
}

CrlEntry ::= SEQUENCE {
  revokedCertificate HashedId10,
  expiry             Time32
}

END
"""
