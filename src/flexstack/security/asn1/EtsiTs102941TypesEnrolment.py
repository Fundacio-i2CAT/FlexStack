# pylint: skip-file
ETSI_TS_102_941_TYPES_ENROLMENT_ASN1_DESCRIPTIONS = """
EtsiTs102941TypesEnrolment
{itu-t(0) identified-organization(4) etsi(0) itsDomain(5) wg5(5) ts(102941) version(2)}

DEFINITIONS AUTOMATIC TAGS ::= BEGIN

IMPORTS

  Uint8
FROM Ieee1609Dot2BaseTypes {iso(1) identified-organization(3) ieee(111)
  standards-association-numbered-series-standards(2) wave-stds(1609)
  dot2(2) base(1) schema(1) major-version-2(2) minor-version-7(7)}

  EtsiTs103097Certificate
FROM EtsiTs103097Module {itu-t(0) identified-organization(4) etsi(0)
  itsDomain(5) wg5(5) secHeaders(103097) core(1) major-version-3(3)
  minor-version-2(2)}

  CertificateFormat, PublicKeys, CertificateSubjectAttributes
FROM EtsiTs102941BaseTypes {itu-t(0) identified-organization(4) etsi(0)
  itsDomain(5) wg5(5) ts(102941) version(2)}
;

-- TS 102 941 v2.2.1 §6.2.3.2 — Enrolment

InnerECRequest ::= SEQUENCE {
  itsId                      OCTET STRING,
  certificateFormat          CertificateFormat,
  publicKeys                 PublicKeys,
  requestedSubjectAttributes CertificateSubjectAttributes
}

-- InnerECRequestSignedForPOP is an EtsiTs103097Data-Signed wrapping the InnerECRequest.
-- Encoded as Ieee1609Dot2Data at the outer layer; handled in message_builder.py.

InnerECResponse ::= SEQUENCE {
  version                    Uint8,
  responseCode               EnrolmentResponseCode,
  certificate                EtsiTs103097Certificate OPTIONAL
}

EnrolmentResponseCode ::= ENUMERATED {
  ok                      (0),
  cantparse               (1),
  badcontenttype          (2),
  imtoolate               (3),
  imtooearlyorequaltime   (4),
  unauthorizedrequest     (5),
  invalidsig              (6),
  invalidencryptionkey    (7),
  dupkey                  (8),
  invalidrequestformat    (9),
  subjectnotfound        (10),
  incompatiblelevel      (11)
}

END
"""
