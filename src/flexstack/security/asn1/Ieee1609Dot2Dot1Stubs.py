# pylint: skip-file
# Minimal stand-ins for the IEEE Std 1609.2.1 modules imported by ETSI TS 102 941 V2.2.1.
# Butterfly key expansion is not implemented: these types are used only by extension
# alternatives of EtsiTs102941DataContent and by EtsiTs102941ButterflyAuthorizationRequest-
# X509Signed, so the encoding of every other ETSI TS 102 941 type is unaffected.
IEEE_1609_2_1_STUBS_ASN1_DESCRIPTIONS = r"""
-- Stubs of the IEEE Std 1609.2.1 types imported by ETSI TS 102 941 V2.2.1 for
-- butterfly key expansion only (not implemented). They are referenced only by
-- extension alternatives of EtsiTs102941DataContent, so the encoding of the
-- root alternatives is unaffected.
Ieee1609Dot2Dot1EeRaInterface DEFINITIONS AUTOMATIC TAGS ::= BEGIN
EeRaInterfacePdu ::= CHOICE {
  eeRaCertRequest     EeRaCertRequest,
  ...
}
EeRaCertRequest ::= OCTET STRING
RaEeCertInfo ::= OCTET STRING
EeRaDownloadRequest ::= OCTET STRING
END

Ieee1609Dot2Dot1AcaRaInterface DEFINITIONS AUTOMATIC TAGS ::= BEGIN
RaAcaCertRequest ::= OCTET STRING
AcaRaCertResponse ::= OCTET STRING
END

Ieee1609Dot2Dot1Protocol DEFINITIONS AUTOMATIC TAGS ::= BEGIN
ScmsPdu-Scoped {Pdu} ::= OCTET STRING
Ieee1609Dot2Data-SignedX509AuthenticatedCertRequest {Tbs, Signer} ::= OCTET STRING
SignerSingleX509Cert ::= NULL
END
"""
