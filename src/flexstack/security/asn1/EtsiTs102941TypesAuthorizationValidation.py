# pylint: skip-file
ETSI_TS_102_941_TYPES_AUTHORIZATION_VALIDATION_ASN1_DESCRIPTIONS = """
EtsiTs102941TypesAuthorizationValidation
{itu-t(0) identified-organization(4) etsi(0) itsDomain(5) wg5(5) ts(102941) version(2)}

DEFINITIONS AUTOMATIC TAGS ::= BEGIN

IMPORTS

  CertificateSubjectAttributes, EcSignature
FROM EtsiTs102941BaseTypes {itu-t(0) identified-organization(4) etsi(0)
  itsDomain(5) wg5(5) ts(102941) version(2)}

  SharedAtRequest
FROM EtsiTs102941TypesAuthorization {itu-t(0) identified-organization(4) etsi(0)
  itsDomain(5) wg5(5) ts(102941) version(2)}
;

-- TS 102 941 v2.2.1 §6.2.3.4 — Authorization Validation (S4: AA → EA)

AuthorizationValidationRequest ::= SEQUENCE {
  sharedAtRequest  SharedAtRequest,
  ecSignature      EcSignature,
  ...
}

AuthorizationValidationResponse ::= SEQUENCE {
  requestHash                OCTET STRING (SIZE(16)),
  responseCode               AuthorizationValidationResponseCode,
  confirmedSubjectAttributes CertificateSubjectAttributes OPTIONAL
}

AuthorizationValidationResponseCode ::= ENUMERATED {
  ok                              (0),
  cantparse                       (1),
  badcontenttype                  (2),
  imnottherecipient               (3),
  unknownencryptionalgorithm      (4),
  decryptionfailed                (5),
  invalidaa                       (6),
  invalidaasignature              (7),
  wrongea                         (8),
  unknownits                      (9),
  invalidsignature               (10),
  invalidencryptionkey           (11),
  deniedpermissions              (12),
  deniedtoomanycerts             (13),
  deniedrequest                  (14)
}

END
"""
