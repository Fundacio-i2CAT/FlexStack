"""
flexstack.security.pki_client — ETSI C-ITS PKI client for FlexStack ITS-S.

Implements the ITS-Station client side of ETSI TS 102 941:
  - S3 Enrolment (ITS-S → EA): obtain an Enrolment Credential (EC)
  - S2 Authorization (ITS-S → AA): obtain an Authorization Ticket (AT)

Quick start::

    import asyncio
    from flexstack.security.certificate import Certificate
    from flexstack.security.pki_client import PkiClient

    ea_cert = Certificate.from_coer(open("ea.cert", "rb").read())
    aa_cert = Certificate.from_coer(open("aa.cert", "rb").read())
    rca_cert = Certificate.from_coer(open("rca.cert", "rb").read())

    client = PkiClient(
        ea_url="http://localhost:8080",
        aa_url="http://localhost:8081",
        ea_cert=ea_cert,
        aa_cert=aa_cert,
        rca_cert=rca_cert,
        certs_dir="certs/pki/",
    )
    at_own = asyncio.run(client.provision(app_permissions=[{"psid": 36}, {"psid": 37}]))
"""
from flexstack.security.pki_client.client import PkiClient
from flexstack.security.pki_client.enrolment import EnrolmentError, enroll
from flexstack.security.pki_client.authorization import AuthorizationError, authorize
from flexstack.security.pki_client.pki_coder import PKI_CODER, PkiCoder

__all__ = [
    "PkiClient",
    "EnrolmentError",
    "AuthorizationError",
    "enroll",
    "authorize",
    "PKI_CODER",
    "PkiCoder",
]
