# pylint: skip-file
# ASN.1 module EtsiTs102941TypesLinkCertificate of ETSI TS 102 941 V2.2.1, verbatim (apart from whitespace) from
# https://forge.etsi.org/rep/ITS/asn1/pki_ts102941/-/raw/v2.2.1/EtsiTs102941TypesLinkCertificate.asn
ETSI_TS_102_941_TYPES_LINK_CERTIFICATE_ASN1_DESCRIPTIONS = r"""
EtsiTs102941TypesLinkCertificate
{ itu-t(0) identified-organization(4) etsi(0) itsDomain(5) wg5(5) ts(102941) linkCertificate(9) major-version-3(3) minor-version-1(1) }

DEFINITIONS AUTOMATIC TAGS ::=
BEGIN

IMPORTS

Time32, HashedData
FROM EtsiTs102941BaseTypes
{itu-t(0) identified-organization(4) etsi(0) itsDomain(5) wg5(5) ts(102941) baseTypes(3) major-version-3(3) minor-version-1(1)}
WITH SUCCESSORS

;

/************
-- Link certificate messages
************/

ToBeSignedLinkCertificate ::= SEQUENCE {
  expiryTime          Time32,
  certificateHash     HashedData,
  ...
}

ToBeSignedLinkCertificateTlm ::= ToBeSignedLinkCertificate
ToBeSignedLinkCertificateRca ::= ToBeSignedLinkCertificate

END

"""
