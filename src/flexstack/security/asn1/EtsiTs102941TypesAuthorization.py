# pylint: skip-file
ETSI_TS_102_941_TYPES_AUTHORIZATION_ASN1_DESCRIPTIONS = """
EtsiTs102941TypesAuthorization
{itu-t(0) identified-organization(4) etsi(0) itsDomain(5) wg5(5) ts(102941) version(2)}

DEFINITIONS AUTOMATIC TAGS ::= BEGIN

IMPORTS

  HashedId8
FROM Ieee1609Dot2BaseTypes {iso(1) identified-organization(3) ieee(111)
  standards-association-numbered-series-standards(2) wave-stds(1609)
  dot2(2) base(1) schema(1) major-version-2(2) minor-version-7(7)}

  EtsiTs103097Certificate
FROM EtsiTs103097Module {itu-t(0) identified-organization(4) etsi(0)
  itsDomain(5) wg5(5) secHeaders(103097) core(1) major-version-3(3)
  minor-version-2(2)}

  CertificateFormat, PublicKeys, CertificateSubjectAttributes, EcSignature
FROM EtsiTs102941BaseTypes {itu-t(0) identified-organization(4) etsi(0)
  itsDomain(5) wg5(5) ts(102941) version(2)}
;

-- TS 102 941 v2.2.1 §6.2.3.3 — Authorization

-- Shared portion of the AT request (forwarded by AA to EA for validation)
SharedAtRequest ::= SEQUENCE {
  eaId                       HashedId8,
  keyTag                     OCTET STRING (SIZE(16)),
  certificateFormat          CertificateFormat,
  requestedSubjectAttributes CertificateSubjectAttributes
}

-- Inner AT request (encrypted and sent to AA)
InnerAtRequest ::= SEQUENCE {
  publicKeys      PublicKeys,
  hmacKey         OCTET STRING (SIZE(32)),
  sharedAtRequest SharedAtRequest,
  ecSignature     EcSignature
}

-- NOTE: InnerAtResponse has NO version field (unlike InnerECResponse).
-- Per TS 102 941 v2.2.1 EtsiTs102941TypesAuthorization ASN.1 module.
InnerAtResponse ::= SEQUENCE {
  requestHash  OCTET STRING (SIZE(16)),
  responseCode AuthorizationResponseCode,
  certificate  EtsiTs103097Certificate OPTIONAL
}

AuthorizationResponseCode ::= ENUMERATED {
  ok                              (0),
  -- ITS-S → AA failures
  its-aa-cantparse                (1),
  its-aa-badcontenttype           (2),
  its-aa-imnottherecipient        (3),
  its-aa-unknownencryptionalgorithm (4),
  its-aa-decryptionfailed         (5),
  its-aa-keysdontmatch            (6),
  its-aa-incompleterequest        (7),
  its-aa-invalidencryptionkey     (8),
  its-aa-outofsyncrequest         (9),
  its-aa-unknownea               (10),
  its-aa-invalidea               (11),
  its-aa-deniedpermissions       (12),
  -- AA → EA failures
  aa-ea-cantreachea              (13),
  -- EA → AA failures
  ea-aa-cantparse                (14),
  ea-aa-badcontenttype           (15),
  ea-aa-imnottherecipient        (16),
  ea-aa-unknownencryptionalgorithm (17),
  ea-aa-decryptionfailed         (18),
  invalidaa                      (19),
  invalidaasignature             (20),
  wrongea                        (21),
  unknownits                     (22),
  invalidsignature               (23),
  invalidencryptionkey           (24),
  deniedpermissions              (25),
  deniedtoomanycerts             (26)
}

END
"""
