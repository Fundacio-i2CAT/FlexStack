"""
pki_client/enrolment.py — enrolment of an ITS-S with an EA (ETSI TS 102 941
V2.2.1 clause 6.2.3.2): request an Enrolment Credential (EC).

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
from flexstack.security.pki_client.messages import PkiProtocolError
from flexstack.security.pki_client.transport import RetryPolicy, post_with_retry

log = logging.getLogger(__name__)


class EnrolmentError(Exception):
    """The enrolment failed: ``code`` is the EnrolmentResponseCode returned by the
    EA (e.g. ``"deniedrequest"``) or the name of the failed check of the response."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _same_key(certificate: dict, key: tuple) -> bool:
    indicator = certificate.get("toBeSigned", {}).get("verifyKeyIndicator", ("", None))
    issued = Certificate.from_dict({"toBeSigned": {"verifyKeyIndicator": indicator}}).to_canonical()
    ours = Certificate.from_dict({"toBeSigned": {"verifyKeyIndicator": ("verificationKey", key)}}).to_canonical()
    return issued.certificate["toBeSigned"] == ours.certificate["toBeSigned"]


async def enroll(  # pylint: disable=too-many-arguments,too-many-locals
    transport, ea_url: str, ea_cert: Certificate, backend: ECDSABackend, *, its_id: bytes,
    canonical_key: int, current_ec: OwnCertificate | None, attributes: dict, now: float,
    retry: RetryPolicy | None = None, clock: Callable[[], float] | None = None,
    sleep: Callable[[float], Awaitable[object]] = asyncio.sleep,
) -> OwnCertificate:
    """Send an EnrolmentRequestMessage to ``ea_url`` and return the issued EC.

    An initial request (``current_ec`` None) uses the canonical identifier
    ``its_id`` and the canonical key ``canonical_key``; a re-keying request
    uses the EC identifier and key (clause 6.2.3.2.1). Raises
    :class:`EnrolmentError` for a negative response or an invalid response.

    With ``retry`` the same message is repeated while no response is received
    (ETSI TS 103 601 V2.1.1 clause 5.1); :class:`PkiTransportError` when the
    repetition ends without a response (the request and its key are dropped).
    """
    request = messages.build_enrolment_request(
        backend, ea_cert, its_id=its_id, signer_key=canonical_key, current_ec=current_ec,
        attributes=attributes, now=now)
    log.info("Enrolment request (%s) to %s, %d bytes",
             "re-keying" if current_ec is not None else "initial", ea_url, len(request.message))
    response = await post_with_retry(transport, ea_url, request.message, messages.CT_REQUEST, retry,
                                     clock=clock or (lambda: now), sleep=sleep)
    try:
        inner = messages.read_enrolment_response(response, request, ea_cert, backend)
    except PkiProtocolError as exc:
        raise EnrolmentError(exc.code, str(exc)) from exc
    if inner["responseCode"] != "ok":
        raise EnrolmentError(inner["responseCode"], f"EA rejected the request: {inner['responseCode']}")
    certificate = inner.get("certificate")
    if certificate is None or not _same_key(certificate, backend.get_public_key(request.key_id)):
        raise EnrolmentError("invalidkeys", "the EC does not certify the requested verification key")
    ec_own = OwnCertificate(certificate=certificate, issuer=ea_cert, key_id=request.key_id)
    if not ec_own.check_corresponding_issuer(ea_cert):
        raise EnrolmentError("invalidsignature", "the EC is not issued by the EA")
    log.info("Enrolled: EC %s", ec_own.as_hashedid8().hex())
    return ec_own
