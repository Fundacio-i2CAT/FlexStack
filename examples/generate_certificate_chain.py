"""
Generate a C-ITS certificate chain: Root CA → Authorization Authority → two Authorization Tickets.

The script creates four certificates that form the chain of trust required to sign and
verify C-ITS (ITS-S) messages between two independent ITS stations:

- **Root Certificate Authority (Root CA)**: self-signed, grants all issue permissions
  with a chain depth of 2 so it can issue AA certificates.
- **Authorization Authority (AA)**: issued by the Root CA, grants issue permissions for
  CAM (psid 36), DENM (psid 37) and VAM (psid 638) with a chain depth of 1 so it can
  issue AT certificates.
- **Authorization Ticket 1 (AT1)**: issued by the AA for the first ITS station.
- **Authorization Ticket 2 (AT2)**: issued by the AA for the second ITS station.

Both ATs share the same Root CA and AA so they trust each other's signed messages.
Each AT is the end-entity certificate used by one ITS station to sign outgoing messages.

Each certificate is saved to a ``certs/`` sub-directory of the directory where this
script lives.  Two files are created for each entity:

- ``<name>.cert`` – OER-encoded certificate (EtsiTs103097Certificate format).
- ``<name>.pem``  – EC private key in PEM format (PKCS #8 / SEC 1 encoding as produced
  by the *ecdsa* library).

These files are consumed by the :mod:`secured_cam_sender_and_receiver` example which
accepts a ``--at {1,2}`` flag to select which AT the station uses for signing.

Usage::

    python examples/generate_certificate_chain.py

References
----------
- ETSI TS 103 097 V2.1.1 – Security header and certificate formats for ITS
- ETSI EN 302 636-4-1 V1.4.1 – GeoNetworking
"""

import os
import sys

# Ensure ../src (relative to this file) is on PYTHONPATH so local modules can be imported
_this_dir = os.path.dirname(os.path.abspath(__file__))
_src_dir = os.path.normpath(os.path.join(_this_dir, "..", "src"))
if _src_dir not in sys.path:
    sys.path.insert(0, _src_dir)

from flexstack.security.certificate import OwnCertificate
from flexstack.security.ecdsa_backend import PythonECDSABackend

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# ITS-AID / PSID values covered by the generated certificates
PSID_CAM = 36
PSID_DENM = 37
PSID_VAM = 638

# Duration choice and value for the certificate validity period.
# Uses the "years" choice of the ETSI TS 103 097 Duration CHOICE type, which accepts
# a Uint16 (0–65535) representing the number of years.
VALIDITY_DURATION = ("years", 10)

# CRACA identifier – arbitrary 3-byte value as per ETSI TS 103 097
CRACA_ID = (0xA49599).to_bytes(3, byteorder="big")

# Directory where certificate and key files are written
CERTS_DIR = os.path.join(_this_dir, "certs")


# ---------------------------------------------------------------------------
# Helper – TBS certificate dictionaries
# ---------------------------------------------------------------------------

def _make_root_ca_tbs() -> dict:
    """
    Return the ToBeSignedCertificate dict for a Root Certificate Authority.

    The Root CA is self-signed and grants *all* subject issue permissions with a
    ``minChainLength`` of 2, which allows it to issue authorization authority
    certificates (chain depth 1) that can in turn issue authorization tickets.
    """
    return {
        "id": ("name", "root-ca.example"),
        "cracaId": CRACA_ID,
        "crlSeries": 0,
        "validityPeriod": {"start": 0, "duration": VALIDITY_DURATION},
        "certIssuePermissions": [
            {
                "subjectPermissions": ("all", None),
                "minChainLength": 2,
                "chainLengthRange": 0,
                "eeType": (b"\x00", 1),
            }
        ],
        "verifyKeyIndicator": (
            "verificationKey",
            ("ecdsaNistP256", ("fill", None)),
        ),
    }


def _make_aa_tbs() -> dict:
    """
    Return the ToBeSignedCertificate dict for an Authorization Authority.

    The AA is issued by the Root CA via :func:`OwnCertificate.initialize_certificate`.
    It carries explicit issue permissions for CAM, DENM and VAM PSIDs so that only
    authorization tickets for those services can be issued from this AA.  The
    ``minChainLength`` of 1 means the AA can issue end-entity (AT) certificates.
    """
    return {
        "id": ("name", "aa.example"),
        "cracaId": CRACA_ID,
        "crlSeries": 0,
        "validityPeriod": {"start": 0, "duration": VALIDITY_DURATION},
        "certIssuePermissions": [
            {
                "subjectPermissions": (
                    "explicit",
                    [
                        {"psid": PSID_CAM},
                        {"psid": PSID_DENM},
                        {"psid": PSID_VAM},
                    ],
                ),
                "minChainLength": 1,
                "chainLengthRange": 0,
                "eeType": (b"\x00", 1),
            }
        ],
        "verifyKeyIndicator": (
            "verificationKey",
            ("ecdsaNistP256", ("fill", None)),
        ),
    }


def _make_at_tbs(index: int) -> dict:
    """
    Return the ToBeSignedCertificate dict for an Authorization Ticket.

    The AT is the end-entity certificate used by an ITS station to sign outgoing
    messages.  It carries *application* permissions (``appPermissions``) listing the
    ITS-AID / PSID values that messages signed with this certificate may carry.

    Parameters
    ----------
    index : int
        Station index (1 or 2) embedded in the certificate id to distinguish
        the two authorization tickets issued from the same AA.
    """
    return {
        "id": ("name", f"at{index}.example"),
        "cracaId": CRACA_ID,
        "crlSeries": 0,
        "validityPeriod": {"start": 0, "duration": VALIDITY_DURATION},
        "appPermissions": [
            {"psid": PSID_CAM},
            {"psid": PSID_DENM},
            {"psid": PSID_VAM},
        ],
        "verifyKeyIndicator": (
            "verificationKey",
            ("ecdsaNistP256", ("fill", None)),
        ),
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Generate the certificate chain and write the resulting files to ``certs/``.

    The four certificates (Root CA, AA, AT1, AT2) are generated in order.  Each
    one is signed either by itself (Root CA) or by the preceding certificate in
    the chain.  After generation the OER-encoded certificate bytes and the
    PEM-encoded private key are written to disk.

    AT1 and AT2 share the same Root CA and AA so either station can verify
    messages sent by the other.
    """
    os.makedirs(CERTS_DIR, exist_ok=True)

    backend = PythonECDSABackend()

    # ------------------------------------------------------------------
    # 1. Root CA – self-signed
    # ------------------------------------------------------------------
    print("Generating Root CA certificate...")
    root_ca_tbs = _make_root_ca_tbs()
    root_ca = OwnCertificate.initialize_certificate(
        backend=backend,
        to_be_signed_certificate=root_ca_tbs,
        issuer=None,  # self-signed
    )
    assert root_ca.verify(backend), "Root CA certificate failed self-verification"

    _write_cert(root_ca, backend, "root_ca")
    print(f"  -> certs/root_ca.cert  ({len(root_ca.encode())} bytes)")
    print(f"  -> certs/root_ca.pem")

    # ------------------------------------------------------------------
    # 2. Authorization Authority – issued by the Root CA
    # ------------------------------------------------------------------
    print("Generating Authorization Authority certificate...")
    aa_tbs = _make_aa_tbs()
    aa = OwnCertificate.initialize_certificate(
        backend=backend,
        to_be_signed_certificate=aa_tbs,
        issuer=root_ca,
    )
    assert aa.verify(backend), "AA certificate failed verification"

    _write_cert(aa, backend, "aa")
    print(f"  -> certs/aa.cert  ({len(aa.encode())} bytes)")
    print(f"  -> certs/aa.pem")

    # ------------------------------------------------------------------
    # 3. Authorization Ticket 1 – issued by the AA (station 1)
    # ------------------------------------------------------------------
    print("Generating Authorization Ticket 1 certificate...")
    at1_tbs = _make_at_tbs(index=1)
    at1_cert = OwnCertificate.initialize_certificate(
        backend=backend,
        to_be_signed_certificate=at1_tbs,
        issuer=aa,
    )
    assert at1_cert.verify(backend), "AT1 certificate failed verification"

    _write_cert(at1_cert, backend, "at1")
    print(f"  -> certs/at1.cert  ({len(at1_cert.encode())} bytes)")
    print(f"  -> certs/at1.pem")

    # ------------------------------------------------------------------
    # 4. Authorization Ticket 2 – issued by the AA (station 2)
    # ------------------------------------------------------------------
    print("Generating Authorization Ticket 2 certificate...")
    at2_tbs = _make_at_tbs(index=2)
    at2_cert = OwnCertificate.initialize_certificate(
        backend=backend,
        to_be_signed_certificate=at2_tbs,
        issuer=aa,
    )
    assert at2_cert.verify(backend), "AT2 certificate failed verification"

    _write_cert(at2_cert, backend, "at2")
    print(f"  -> certs/at2.cert  ({len(at2_cert.encode())} bytes)")
    print(f"  -> certs/at2.pem")

    print("\nCertificate chain generated successfully.")
    print(f"Files are located in: {CERTS_DIR}")
    print()
    print("Run the example with:")
    print("  Terminal 1: python examples/secured_cam_sender_and_receiver.py --at 1")
    print("  Terminal 2: python examples/secured_cam_sender_and_receiver.py --at 2")


def _write_cert(cert: OwnCertificate, backend: PythonECDSABackend, name: str) -> None:
    """
    Persist a certificate and its associated private key to files.

    Parameters
    ----------
    cert : OwnCertificate
        The certificate to persist.
    backend : PythonECDSABackend
        The ECDSA backend that holds the private key referenced by
        ``cert.key_id``.
    name : str
        Base name used for the output files (without extension).  The
        certificate is written to ``<name>.cert`` and the private key to
        ``<name>.pem`` inside :data:`CERTS_DIR`.
    """
    cert_path = os.path.join(CERTS_DIR, f"{name}.cert")
    key_path = os.path.join(CERTS_DIR, f"{name}.pem")
    with open(cert_path, "wb") as f:
        f.write(cert.encode())
    with open(key_path, "wb") as f:
        f.write(backend.export_signing_key(cert.key_id))


if __name__ == "__main__":
    main()
