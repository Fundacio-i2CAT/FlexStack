"""
ETSI originating HeaderInfo extensions (ETSI TS 103 097 V2.2.1 clause 4.3.2 and
module EtsiTs103097ExtensionModule): the peer-to-peer CRL / CTL requests of
ETSI TS 103 601 V2.1.1 clause 5.3.4, carried in ``contributedExtensions``.

A ``ContributedExtensionBlock`` of the ETSI contributor (2) holds a sequence of
open types, each the COER encoding of an ``EtsiOriginatingHeaderInfoExtension``
(``id`` and the open type ``content``).
"""
from __future__ import annotations

import logging

from .certificate import SECURITY_CODER

log = logging.getLogger("security")

# IEEE 1609.2 HeaderInfoContributorId of ETSI TC ITS (TS 103 097 clause 4.3.2).
ETSI_HEADER_INFO_CONTRIBUTOR_ID = 2
# EtsiTs103097HeaderInfoExtensionId (EtsiTs103097ExtensionModule).
CRL_REQUEST_ID = 1
DELTA_CTL_REQUEST_ID = 2
FULL_CTL_REQUEST_ID = 3

_TYPES = {
    CRL_REQUEST_ID: "EtsiTs102941CrlRequest",
    DELTA_CTL_REQUEST_ID: "EtsiTs102941DeltaCtlRequest",
    FULL_CTL_REQUEST_ID: "EtsiTs102941FullCtlRequest",
}


def encode_requests(requests: list[tuple[int, dict]]) -> list[dict]:
    """``ContributedExtensionBlocks`` with one ETSI block carrying ``requests``
    (pairs of extension id and the request, e.g. ``(1, {"issuerId": h8})``)."""
    coder = SECURITY_CODER.asn_coder
    extns = [coder.encode("EtsiOriginatingHeaderInfoExtension",
                          {"id": ext_id, "content": coder.encode(_TYPES[ext_id], request)})
             for ext_id, request in requests]
    return [{"contributorId": ETSI_HEADER_INFO_CONTRIBUTOR_ID, "extns": extns}]


def decode_requests(blocks: list[dict]) -> list[tuple[int, dict]]:
    """The CRL / CTL requests in the ``contributedExtensions`` of a received
    headerInfo. Blocks of other contributors, unknown extension ids and
    undecodable extensions are skipped (TS 103 097 clause 4.3.2)."""
    coder = SECURITY_CODER.asn_coder
    requests = []
    for block in blocks:
        if block.get("contributorId") != ETSI_HEADER_INFO_CONTRIBUTOR_ID:
            continue
        for raw in block.get("extns", []):
            try:
                extension = coder.decode("EtsiOriginatingHeaderInfoExtension", raw)
                type_name = _TYPES.get(extension["id"])
                if type_name is not None:
                    requests.append((extension["id"], coder.decode(type_name, extension["content"])))
            except Exception as exc:  # pylint: disable=broad-except
                log.debug("ETSI header extension skipped: %s", exc)
    return requests
