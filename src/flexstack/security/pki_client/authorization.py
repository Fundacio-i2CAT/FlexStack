"""
pki_client/authorization.py — authorization of an enrolled ITS-S with an AA
(ETSI TS 102 941 V2.2.1 clause 6.2.3.3): request an Authorization Ticket (AT).

The message construction is in :mod:`.messages`; this module sends the
request and checks the response.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Awaitable, Callable

from flexstack.security.certificate import Certificate, OwnCertificate
from flexstack.security.ecdsa_backend import ECDSABackend

from flexstack.security.pki_client import messages
from flexstack.security.pki_client.enrolment import _same_key
from flexstack.security.pki_client.messages import PkiProtocolError
from flexstack.security.pki_client.transport import RetryPolicy, post_with_retry

log = logging.getLogger(__name__)


class AuthorizationError(Exception):
    """The authorization failed: ``code`` is the AuthorizationResponseCode returned
    by the AA (e.g. ``"its-aa-unknownea"``) or the name of the failed check."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


async def authorize(  # pylint: disable=too-many-arguments,too-many-locals
    transport, aa_url: str, aa_cert: Certificate, ea_cert: Certificate, *, ec_own: OwnCertificate,
    backend: ECDSABackend, attributes: dict, now: float, pop: bool = True,
    retry: RetryPolicy | None = None, clock: Callable[[], float] | None = None,
    sleep: Callable[[float], Awaitable[object]] = asyncio.sleep,
) -> OwnCertificate:
    """Send an AuthorizationRequestMessage (with POP when ``pop``) to ``aa_url`` and
    return the issued AT. Raises :class:`AuthorizationError` for a negative or
    invalid response. With ``retry`` the same message is repeated while no
    response is received (ETSI TS 103 601 V2.1.1 clause 5.2)."""
    request = messages.build_authorization_request(backend, aa_cert, ea_cert, ec_own=ec_own,
                                                   attributes=attributes, now=now, pop=pop)
    log.info("Authorization request to %s, %d bytes", aa_url, len(request.message))
    response = await post_with_retry(transport, aa_url, request.message, messages.CT_REQUEST, retry,
                                     clock=clock or (lambda: now), sleep=sleep)
    try:
        inner = messages.read_authorization_response(response, request, aa_cert, backend)
    except PkiProtocolError as exc:
        raise AuthorizationError(exc.code, str(exc)) from exc
    if inner["responseCode"] != "ok":
        raise AuthorizationError(inner["responseCode"], f"AA rejected the request: {inner['responseCode']}")
    certificate = inner.get("certificate")
    if certificate is None or not _same_key(certificate, backend.get_public_key(request.key_id)):
        raise AuthorizationError("its-aa-keysdontmatch", "the AT does not certify the requested key")
    at_own = OwnCertificate(certificate=certificate, issuer=aa_cert, key_id=request.key_id)
    if not at_own.check_corresponding_issuer(aa_cert):
        raise AuthorizationError("invalidaasignature", "the AT is not issued by the AA")
    log.info("Authorized: AT %s", at_own.as_hashedid8().hex())
    return at_own
