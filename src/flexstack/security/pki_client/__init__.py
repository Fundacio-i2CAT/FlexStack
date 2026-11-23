"""
flexstack.security.pki_client — ETSI C-ITS PKI client for FlexStack ITS-S.

Implements the ITS-Station side of ETSI TS 102 941 V2.2.1 (official ASN.1):
  - enrolment with the EA (clause 6.2.3.2): Enrolment Credential (EC)
  - authorization with the AA (clause 6.2.3.3): Authorization Ticket (AT)

Quick start::

    import asyncio
    from flexstack.security.certificate import Certificate
    from flexstack.security.pki_client import PkiClient, load_or_create_canonical_key

    ea_cert = Certificate.from_coer(open("ea.cert", "rb").read())
    aa_cert = Certificate.from_coer(open("aa.cert", "rb").read())
    rca_cert = Certificate.from_coer(open("rca.cert", "rb").read())

    # canonical key pair, created once; its public key is registered with the EA
    # before the first enrolment (TS 102 941 clause 6.1.2)
    canonical = load_or_create_canonical_key("certs/pki/canonical_key.pem")

    client = PkiClient(
        ea_url="https://ea.example/",       # access points (POST, Annex C)
        aa_url="https://aa.example/",
        ea_cert=ea_cert,
        aa_cert=aa_cert,
        rca_cert=rca_cert,
        canonical_key_pem=canonical.private_pem,
        its_id=b"canonical-id",
        certs_dir="certs/pki/",
    )
    at_own = asyncio.run(client.provision(app_permissions=[{"psid": 36}, {"psid": 37}]))
"""
from flexstack.security.pki_client.canonical import CanonicalKey, load_or_create_canonical_key
from flexstack.security.pki_client.client import PkiClient
from flexstack.security.pki_client.enrolment import EnrolmentError, enroll
from flexstack.security.pki_client.authorization import AuthorizationError, authorize
from flexstack.security.pki_client.pki_coder import PKI_CODER, PkiCoder
from flexstack.security.pki_client.messages import PkiProtocolError
from flexstack.security.pki_client.transport import HttpTransport, PkiTransportError, RetryPolicy
from flexstack.security.pki_client.distribution import DistributionConfig, TrustListDistribution

__all__ = [
    "CanonicalKey",
    "load_or_create_canonical_key",
    "RetryPolicy",
    "DistributionConfig",
    "TrustListDistribution",
    "PkiClient",
    "EnrolmentError",
    "AuthorizationError",
    "enroll",
    "authorize",
    "PKI_CODER",
    "PkiCoder",
    "PkiProtocolError",
    "HttpTransport",
    "PkiTransportError",
]
