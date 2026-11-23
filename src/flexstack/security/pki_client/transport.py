"""
pki_client/transport.py — HTTP transport of the PKI messages.

ETSI TS 102 941 V2.2.1 Annex C: requests are HTTP POSTs to the access point of
the EA / AA (``application/x-its-request``, response
``application/x-its-response``). Annex D / E: CTL, CRL and ECTL are fetched
with HTTP GET from the DC / CPOC.

The transport is injectable so that tests (and other carriers) can replace it.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Awaitable, Callable

import httpx

log = logging.getLogger(__name__)


class PkiTransportError(Exception):
    """The PKI could not be reached or answered with an HTTP error."""


class HttpTransport:
    """``httpx`` transport with a timeout (seconds)."""

    def __init__(self, timeout: float = 30.0) -> None:
        self.timeout = timeout

    async def post(self, url: str, content: bytes, content_type: str) -> bytes:
        """POST ``content`` to ``url``; returns the response body."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(url, content=content, headers={"Content-Type": content_type})
        except httpx.HTTPError as exc:
            raise PkiTransportError(f"POST {url}: {exc}") from exc
        if response.status_code != 200:
            raise PkiTransportError(f"POST {url}: HTTP {response.status_code}")
        return response.content

    async def get(self, url: str) -> bytes:
        """GET ``url``; returns the response body."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(url)
        except httpx.HTTPError as exc:
            raise PkiTransportError(f"GET {url}: {exc}") from exc
        if response.status_code != 200:
            raise PkiTransportError(f"GET {url}: HTTP {response.status_code}")
        return response.content


@dataclass(frozen=True)
class RetryPolicy:
    """Repetition of a request whose response is not received (ETSI TS 103 601
    V2.1.1 clauses 5.1.4 and 5.2.4): the same message is sent again ``th1``
    seconds after the previous transmission (timer T1 / T4), at most ``n1`` times
    in all (N1 / N2), and not after ``th2`` seconds from the first one (T2 / T5,
    TH2 > TH1 x N1; NOTE 1 recommends 60 minutes)."""
    th1: float = 30.0
    n1: int = 3
    th2: float = 3600.0


async def post_with_retry(  # pylint: disable=too-many-arguments
    transport, url: str, content: bytes, content_type: str, policy: RetryPolicy | None, *,
    clock: Callable[[], float], sleep: Callable[[float], Awaitable[object]] = asyncio.sleep,
) -> bytes:
    """POST ``content`` (always the same message) until a response is received,
    following ``policy`` (one transmission when None). Raises
    :class:`PkiTransportError` when no response came: the caller then drops the
    request and its session key (clause 5.1.2, case 2)."""
    if policy is None:
        return await transport.post(url, content, content_type)
    first = clock()
    for attempt in range(1, policy.n1 + 1):
        sent = clock()
        try:
            return await transport.post(url, content, content_type)
        except PkiTransportError as exc:
            log.warning("No response from %s (transmission %d of %d): %s", url, attempt, policy.n1, exc)
        resend = sent + policy.th1
        if attempt == policy.n1 or resend >= first + policy.th2:
            raise PkiTransportError(f"POST {url}: no response after {attempt} transmissions")
        await sleep(max(0.0, resend - clock()))
    raise PkiTransportError(f"POST {url}: no transmission allowed (n1 = {policy.n1})")
