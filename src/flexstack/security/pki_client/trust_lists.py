"""
pki_client/trust_lists.py — CTL and CRL use by an ITS-S (ETSI TS 102 941 V2.2.1
clauses 6.3.1 to 6.3.6, Annexes D and E).

:class:`TrustStore` reads the TLM CTL (ECTL), the Root CA CTLs and the CRLs,
checks that each is signed by its issuer (a trusted TLM, a trusted Root CA)
with the ITS-AID and SSP of the CTL / CRL service (clauses B.2, B.3), and
updates the trust information of a :class:`CertificateLibrary`:

- ECTL: Root CA entries become trust anchors; a full ECTL also withdraws the
  Root CAs it no longer lists; TLM entries add a TLM (re-key); the TLM entry's
  access point is the CPOC;
- Root CA CTL: AA (and EA) entries of that Root CA; DC entries give the DC of
  the listed Root CAs; delete commands withdraw entries;
- CRL: the listed CA certificates are revoked (and the own EC / AT when their
  EA, AA or Root CA is revoked, see :meth:`PkiClient.revoke`).

When a CTL or CRL passes its nextUpdate, :meth:`TrustStore.due_downloads`
gives the URLs to fetch from the CPOC (``getectl``) or the DC (``getctl``,
``getcrl``) and :meth:`TrustStore.refresh` fetches and applies them.
"""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from typing import Callable, Sequence

from flexstack.security.certificate import Certificate, signing_input
from flexstack.security.certificate_library import CertificateLibrary
from flexstack.security.ecdsa_backend import ECDSABackend, hash_name_for_key
from flexstack.utils.time_service import TimeService

from flexstack.security.pki_client.messages import decode, encode, time32

log = logging.getLogger(__name__)

#: ITS-AIDs of the CRL and CTL services (ETSI TS 102 965).
PSID_CRL, PSID_CTL = 622, 624
#: CTL SSP bits (clause B.2, Table B.2).
SSP_TLM_ENTRIES, SSP_RCA_ENTRIES, SSP_EA_ENTRIES, SSP_AA_ENTRIES, SSP_DC_ENTRIES = 0x80, 0x40, 0x20, 0x10, 0x08
_ENTRY_BITS = {"tlm": SSP_TLM_ENTRIES, "rca": SSP_RCA_ENTRIES, "ea": SSP_EA_ENTRIES,
               "aa": SSP_AA_ENTRIES, "dc": SSP_DC_ENTRIES}


class TrustListError(Exception):
    """A CTL or CRL is rejected; ``code`` names the failed check."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass
class ListInfo:
    """The last CTL or CRL applied for an issuer."""
    issuer: bytes                 # HashedId8 of the TLM or Root CA
    kind: str                     # "ectl", "rca-ctl" or "crl"
    next_update: int              # Time32
    sequence: int | None = None   # ctlSequence (CTL) ...
    this_update: int | None = None  # ... or thisUpdate (CRL)
    entries: set[bytes] = field(default_factory=set)   # HashedId8 added by this list


@dataclass(frozen=True)
class ListVersion:
    """Issuer and version of a verified CTL / CRL message (:meth:`TrustStore.inspect`)."""
    kind: str                     # "ectl", "rca-ctl" or "crl"
    issuer: bytes                 # HashedId8 of the TLM or Root CA
    full: bool                    # isFullCtl (False for a CRL)
    sequence: int | None          # ctlSequence (CTL) ...
    this_update: int | None       # ... or thisUpdate (CRL)
    next_update: int              # Time32


def _hex(hashedid8: bytes) -> str:
    return hashedid8.hex().upper()


class TrustStore:  # pylint: disable=too-many-instance-attributes
    """Trust information of an ITS-S built from CTLs and CRLs (module documentation).

    Parameters
    ----------
    library:
        Certificate library of the verify service (trust anchors, AAs, revoked).
    backend:
        ECDSA backend for the signature checks.
    tlm_certificates:
        Trusted TLM certificates (installed out of band).
    clock:
        UTC seconds (defaults to :meth:`TimeService.time`).
    on_revoked:
        Called with the revoked HashedId8 set of each CRL (e.g. ``PkiClient.revoke``).
    """

    def __init__(self, library: CertificateLibrary, backend: ECDSABackend,
                 tlm_certificates: Sequence[Certificate] = (), clock: Callable[[], float] | None = None,
                 on_revoked: Callable[[set[bytes]], None] | None = None) -> None:
        self.library, self.backend = library, backend
        self.tlms = {c.as_hashedid8(): c for c in tlm_certificates}
        self.clock = clock or TimeService.time
        self.on_revoked = on_revoked
        self.lists: dict[tuple[str, bytes], ListInfo] = {}
        self.cpoc_url: str | None = None
        self.dc_urls: dict[bytes, str] = {}        # Root CA HashedId8 -> DC access point
        self.ea_entries: dict[bytes, dict] = {}    # EA HashedId8 -> EaEntry

    # -- reading ---------------------------------------------------------------

    def _signer(self, signed: dict, anchors: dict) -> Certificate:
        signer = signed["signer"]
        if signer[0] == "certificate":
            certificate = Certificate.from_dict(signer[1][0])
            hashedid8 = certificate.as_hashedid8()
        elif signer[0] == "digest":
            hashedid8 = signer[1]
        else:
            raise TrustListError("invalidsigner", f"signer {signer[0]!r}")
        if hashedid8 in self.library.revoked or hashedid8 not in anchors:
            raise TrustListError("unknownissuer", f"issuer {_hex(hashedid8)} is not trusted")
        return anchors[hashedid8]

    def _verify(self, signed: dict, issuer: Certificate, psid: int) -> None:
        header = signed["tbsData"]["headerInfo"]
        if header.get("psid") != psid:
            raise TrustListError("badpsid", f"psid {header.get('psid')}, expected {psid}")
        key = issuer.verification_key()
        if key is None:
            raise TrustListError("invalidsignature", "no verification key for the issuer")
        hashfunc = hashlib.sha384 if hash_name_for_key(key) == "sha384" else hashlib.sha256
        tbs = encode("ToBeSignedData", signed["tbsData"])
        if not self.backend.verify_with_pk(signing_input(tbs, issuer.to_canonical().encode(), hashfunc),
                                           signed["signature"], key):
            raise TrustListError("invalidsignature", "the signature does not verify")

    @staticmethod
    def _permission(issuer: Certificate, psid: int) -> tuple[bool, bytes]:
        """(the issuer's appPermissions contain ``psid``, its SSP octets)."""
        for item in issuer.certificate["toBeSigned"].get("appPermissions", []):
            if item.get("psid") == psid:
                ssp = item.get("ssp")
                return True, ssp[1] if ssp is not None else b""
        return False, b""

    def process(self, message: bytes) -> str:
        """Verify and apply a TlmCertificateTrustListMessage, an
        RcaCertificateTrustListMessage or a CertificateRevocationListMessage;
        returns ``"ectl"``, ``"rca-ctl"`` or ``"crl"``. Raises :class:`TrustListError`."""
        kind, content, issuer = self._open(message)
        if kind == "crl":
            self._apply_crl(issuer, content)
        else:
            self._apply_ctl(issuer, content, kind)
        return kind

    def inspect(self, message: bytes) -> ListVersion:
        """Verify the signature of a CTL / CRL message (as :meth:`process`) without
        applying it; its issuer and version."""
        kind, content, issuer = self._open(message)
        if kind == "crl":
            return ListVersion(kind, issuer.as_hashedid8(), False, None, content["thisUpdate"],
                               content["nextUpdate"])
        return ListVersion(kind, issuer.as_hashedid8(), content["isFullCtl"], content["ctlSequence"],
                           None, content["nextUpdate"])

    def _open(self, message: bytes) -> tuple[str, dict, Certificate]:
        """Decode a CTL / CRL message and verify its signer and signature; its
        kind, content and issuer."""
        try:
            data = decode("Ieee1609Dot2Data", message)
            choice, signed = data["content"]
            if choice != "signedData":
                raise TrustListError("badcontenttype", f"expected signedData, got {choice!r}")
            payload = signed["tbsData"]["payload"]["data"]["content"]
            etsi = decode("EtsiTs102941Data", payload[1])
        except TrustListError:
            raise
        except Exception as exc:  # decoding errors of asn1tools
            raise TrustListError("cantparse", f"cannot decode: {exc}") from exc
        content_choice, content = etsi["content"]
        if content_choice == "certificateTrustListTlm":
            issuer = self._signer(signed, self.tlms)
            self._verify(signed, issuer, PSID_CTL)
            return "ectl", content, issuer
        if content_choice == "certificateTrustListRca":
            issuer = self._signer(signed, self.library.known_root_certificates)
            self._verify(signed, issuer, PSID_CTL)
            return "rca-ctl", content, issuer
        if content_choice == "certificateRevocationList":
            issuer = self._signer(signed, self.library.known_root_certificates)
            self._verify(signed, issuer, PSID_CRL)
            return "crl", content, issuer
        raise TrustListError("badcontenttype", f"unexpected content {content_choice!r}")

    # -- CTL ---------------------------------------------------------------------

    def _apply_ctl(self, issuer: Certificate, ctl: dict, kind: str) -> None:  # pylint: disable=too-many-branches
        issuer_id = issuer.as_hashedid8()
        previous = self.lists.get((kind, issuer_id))
        full = ctl["isFullCtl"]
        if previous is not None and previous.sequence == ctl["ctlSequence"]:
            raise TrustListError("outdated", f"ctlSequence {ctl['ctlSequence']} already applied")
        if not full and previous is not None and ctl["ctlSequence"] != ((previous.sequence or 0) + 1) % 256:
            raise TrustListError("outofsequence", "delta CTL does not follow the last CTL")
        _, allowed = self._permission(issuer, PSID_CTL)
        commands = ctl["ctlCommands"]
        for command, value in commands:
            if command == "add":
                bit = _ENTRY_BITS[value[0]]
                if len(allowed) < 2 or allowed[0] != 1 or not allowed[1] & bit:
                    raise TrustListError("deniedpermissions", f"issuer may not sign {value[0]} entries")
            elif full:
                raise TrustListError("badcontenttype", "a full CTL contains no delete command")
        entries = set() if full or previous is None else set(previous.entries)
        for command, value in commands:
            if command == "add":
                entries |= self._add(issuer_id, value)
            else:
                entries -= self._delete(value)
        if full and previous is not None:
            for hashedid8 in previous.entries - entries:      # withdrawn by the full CTL
                self.library.remove_certificate(hashedid8)
        self.lists[(kind, issuer_id)] = ListInfo(issuer_id, kind, ctl["nextUpdate"], ctl["ctlSequence"],
                                                 entries=entries)
        log.info("%s %d of %s applied (%d entries)", kind, ctl["ctlSequence"], _hex(issuer_id), len(entries))

    def _add(self, issuer_id: bytes, entry: tuple) -> set[bytes]:
        kind, value = entry
        if kind == "rca":
            root = Certificate.from_dict(value["selfsignedRootCa"])
            self.library.add_root_certificate(root)
            return {root.as_hashedid8()} if root.as_hashedid8() in self.library.known_root_certificates else set()
        if kind == "tlm":
            tlm = Certificate.from_dict(value["selfSignedTLMCertificate"])
            if tlm.verify(self.backend):
                self.tlms[tlm.as_hashedid8()] = tlm
            self.cpoc_url = value["accessPoint"]
            return set()
        if kind == "aa":
            root = self.library.known_root_certificates.get(issuer_id)
            aa = Certificate.from_dict(value["aaCertificate"], issuer=root)
            self.library.add_authorization_authority(aa)
            return {aa.as_hashedid8()} if aa.as_hashedid8() in self.library.known_authorization_authorities else set()
        if kind == "ea":
            ea = Certificate.from_dict(value["eaCertificate"])
            self.ea_entries[ea.as_hashedid8()] = value
            return set()
        if kind == "dc":
            for root in value["cert"]:
                self.dc_urls[root] = value["url"]
            return set()
        return set()

    def _delete(self, delete: tuple) -> set[bytes]:
        kind, value = delete
        if kind == "cert":
            self.library.remove_certificate(value)
            self.tlms.pop(value, None)
            self.ea_entries.pop(value, None)
            return {value}
        self.dc_urls = {root: url for root, url in self.dc_urls.items() if url != value}
        return set()

    # -- CRL ---------------------------------------------------------------------

    def _apply_crl(self, issuer: Certificate, crl: dict) -> None:
        issuer_id = issuer.as_hashedid8()
        permitted, ssp = self._permission(issuer, PSID_CRL)
        if not permitted or ssp[:1] != b"\x01":       # clause B.3: SSP = version 1
            raise TrustListError("deniedpermissions", "issuer may not sign CRLs")
        previous = self.lists.get(("crl", issuer_id))
        if previous is not None and crl["thisUpdate"] <= (previous.this_update or 0):
            raise TrustListError("outdated", "not newer than the last CRL")
        revoked = set(crl["entries"])
        self.library.revoke(revoked)
        self.lists[("crl", issuer_id)] = ListInfo(issuer_id, "crl", crl["nextUpdate"],
                                                  this_update=crl["thisUpdate"], entries=revoked)
        if self.on_revoked is not None:
            self.on_revoked(revoked)
        log.info("CRL of %s applied: %d revoked", _hex(issuer_id), len(revoked))

    # -- updates -----------------------------------------------------------------

    def due_downloads(self) -> list[str]:
        """URLs of the lists past their nextUpdate: ECTL from the CPOC (Annex E.4),
        Root CA CTL and CRL from the Root CA's DC (Annex D)."""
        now = time32(self.clock())
        urls = []
        for (kind, issuer), info in self.lists.items():
            if info.next_update > now:
                continue
            if kind == "ectl" and self.cpoc_url:
                urls.append(f"{self.cpoc_url.rstrip('/')}/getectl/{_hex(issuer)}")
            elif kind in ("rca-ctl", "crl") and issuer in self.dc_urls:
                path = "getctl" if kind == "rca-ctl" else "getcrl"
                urls.append(f"{self.dc_urls[issuer].rstrip('/')}/{path}/{_hex(issuer)}")
        return urls

    async def refresh(self, transport, process: Callable[[bytes], object] | None = None) -> list[str]:
        """Fetch and apply the due lists (``transport.get``); returns the URLs fetched.
        ``process`` replaces :meth:`process` (the CRL / CTL distribution service
        applies, then redistributes, what the DC delivers)."""
        urls = self.due_downloads()
        for url in urls:
            try:
                (process or self.process)(await transport.get(url))
            except TrustListError as exc:
                log.warning("List from %s rejected: %s", url, exc)
        return urls
