"""
secured_cam_with_pki.py — C-ITS CAM station that obtains its AT from a live PKI.

This example replaces the static ``generate_certificate_chain.py`` +
``secured_cam_sender_and_receiver.py`` workflow with a fully dynamic, standards-
compliant PKI flow:

  1. Load RCA / EA / AA certificates from disk (or fetch from a CTL endpoint).
  2. Instantiate :class:`~flexstack.security.pki_client.PkiClient` and call
     ``await client.provision(...)`` which performs:

       - **S3 Enrolment** (ITS-S → EA): obtains an Enrolment Credential (EC).
       - **S2 Authorization** (ITS-S → AA): obtains an Authorization Ticket (AT).

  3. Wire the AT into :class:`~flexstack.security.certificate_library.CertificateLibrary`
     exactly as the static example does, then run the full ITS-S stack.

Prerequisites
-------------
- A running **pythonpki** PKI stack (EA + AA).  The quickest way is::

      cd pythonpki
      python -m uvicorn cits_pki.ea.app:app --port 8080 &
      python -m uvicorn cits_pki.aa.app:app --port 8081

- The PKI authority certificates exported to files:
    - ``examples/pki_certs/rca.coer`` — Root CA certificate (COER)
    - ``examples/pki_certs/ea.coer``  — EA certificate (COER)
    - ``examples/pki_certs/aa.coer``  — AA certificate (COER)

  These can be obtained from the PKI bootstrap scripts in ``pythonpki/``.

Usage
-----
::

    # Basic (default EA=:8080, AA=:8081)
    python examples/secured_cam_with_pki.py

    # Custom PKI URLs and cert paths
    python examples/secured_cam_with_pki.py \\
        --ea http://localhost:8080 \\
        --aa http://localhost:8081 \\
        --rca examples/pki_certs/rca.coer \\
        --ea-cert examples/pki_certs/ea.coer \\
        --aa-cert examples/pki_certs/aa.coer \\
        --certs-dir examples/pki_certs/issued/ \\
        --no-reprovision   # reuse a previously issued AT if available

Architecture
------------
::

    PkiClient ──S3──► EA :8080  → issues EC
              ──S2──► AA :8081  → issues AT
                                         │
    AT OwnCertificate ─► CertificateLibrary ─► SignService
                                               VerifyService
                                                     │
    GNRouter (security=ENABLED) ◄────────────────────┘
    BTPRouter → CABasicService → sends signed CAMs @ 10 Hz
    RawLinkLayer (loopback "lo") → sends / receives on network

References
----------
- ETSI TS 102 941 v2.2.1 §6.2 — PKI protocol flows S2 / S3
- ETSI TS 103 097 v2.1.1 — Secured message format
- ETSI EN 302 636-4-1 — GeoNetworking
"""

from __future__ import annotations

import argparse
import asyncio
import datetime
import logging
import math
import os
import random
import sys
import time

# ---------------------------------------------------------------------------
# Add ../src to sys.path so local FlexStack modules are importable
# ---------------------------------------------------------------------------
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_SRC_DIR = os.path.normpath(os.path.join(_THIS_DIR, "..", "src"))
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

# ---------------------------------------------------------------------------
# FlexStack imports
# ---------------------------------------------------------------------------
from flexstack.facilities.ca_basic_service.ca_basic_service import (
    CooperativeAwarenessBasicService,
)
from flexstack.facilities.ca_basic_service.cam_transmission_management import VehicleData
from flexstack.facilities.local_dynamic_map.factory import LDMFactory
from flexstack.facilities.local_dynamic_map.ldm_classes import (
    AccessPermission,
    Circle,
    ComparisonOperators,
    Filter,
    FilterStatement,
    GeometricArea,
    Location,
    OrderingDirection,
    OrderTupleValue,
    RegisterDataConsumerReq,
    RegisterDataConsumerResp,
    RequestDataObjectsResp,
    SubscribeDataobjectsReq,
    SubscribeDataObjectsResp,
    SubscribeDataobjectsResult,
    TimestampIts,
)
from flexstack.facilities.local_dynamic_map.ldm_constants import CAM
from flexstack.btp.router import Router as BTPRouter
from flexstack.geonet.gn_address import GNAddress, M, MID, ST
from flexstack.geonet.mib import GnSecurity, MIB
from flexstack.geonet.router import Router as GNRouter
from flexstack.linklayer.raw_link_layer import RawLinkLayer
from flexstack.security.certificate import Certificate, OwnCertificate
from flexstack.security.certificate_library import CertificateLibrary
from flexstack.security.ecdsa_backend import PythonECDSABackend
from flexstack.security.sign_service import SignService
from flexstack.security.verify_service import VerifyService
from flexstack.security.pki_client import PkiClient

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(name)s — %(message)s",
)
log = logging.getLogger("cam_pki")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

POSITION_COORDINATES = [41.386931, 2.112104]

# Application permissions to request in the AT (CAM + DENM)
AT_APP_PERMISSIONS = [{"psid": 36}, {"psid": 37}]

# Default PKI certificate directory relative to this file
_DEFAULT_PKI_CERTS_DIR = os.path.join(_THIS_DIR, "pki_certs")
_DEFAULT_ISSUED_DIR = os.path.join(_THIS_DIR, "pki_certs", "issued")

MAC_ADDRESS = bytes([random.randint(0, 255) | (0x02 if i == 0 else 0) for i in range(6)])
STATION_ID = random.randint(1, 2_147_483_647)


# ---------------------------------------------------------------------------
# Certificate loading helpers
# ---------------------------------------------------------------------------

def _load_coer_cert(path: str, issuer: Certificate | None = None) -> Certificate:
    """Load a COER-encoded certificate from *path* and decode it.

    Parameters
    ----------
    path:
        File path to a ``.coer`` or ``.cert`` file.
    issuer:
        Issuer certificate (or ``None`` for self-signed / root CA).

    Returns
    -------
    Certificate
        Decoded certificate with issuer chain attached.

    Raises
    ------
    SystemExit
        If the file does not exist.
    """
    if not os.path.isfile(path):
        print(f"Error: certificate file not found: {path}")
        print("Generate PKI authority certificates first (see pythonpki bootstrap scripts).")
        sys.exit(1)
    raw = open(path, "rb").read()
    return Certificate().decode(raw, issuer=issuer)


def _load_pki_authority_certs(
    rca_path: str,
    ea_path: str,
    aa_path: str,
) -> tuple[Certificate, Certificate, Certificate]:
    """Load the PKI authority certificates (RCA → EA, RCA → AA).

    Returns
    -------
    (rca_cert, ea_cert, aa_cert)
    """
    rca_cert = _load_coer_cert(rca_path, issuer=None)
    ea_cert = _load_coer_cert(ea_path, issuer=rca_cert)
    aa_cert = _load_coer_cert(aa_path, issuer=rca_cert)
    log.info("Loaded RCA HashedId8: %s", rca_cert.as_hashedid8().hex())
    log.info("Loaded  EA HashedId8: %s", ea_cert.as_hashedid8().hex())
    log.info("Loaded  AA HashedId8: %s", aa_cert.as_hashedid8().hex())
    return rca_cert, ea_cert, aa_cert


# ---------------------------------------------------------------------------
# PKI provisioning
# ---------------------------------------------------------------------------

async def _provision_at(
    ea_url: str,
    aa_url: str,
    rca_cert: Certificate,
    ea_cert: Certificate,
    aa_cert: Certificate,
    certs_dir: str,
    reprovision: bool,
    station_id: int = STATION_ID,
) -> tuple[OwnCertificate, PythonECDSABackend]:
    """Run PKI provisioning (S3 + S2) and return the AT OwnCertificate.

    If *reprovision* is ``False`` and a previously issued AT exists on disk
    in *certs_dir*, it is loaded directly without contacting the PKI.

    Parameters
    ----------
    ea_url, aa_url:
        PKI service base URLs.
    rca_cert, ea_cert, aa_cert:
        Authority certificates already decoded.
    certs_dir:
        Directory for persisting / loading EC and AT files.
    reprovision:
        If ``True``, always contact the PKI even if cached AT exists.
    station_id:
        ITS Station ID (int).

    Returns
    -------
    (at_own, backend):
        *at_own* — the Authorization Ticket as an ``OwnCertificate``.
        *backend* — the ``PythonECDSABackend`` holding the AT private key.
    """
    client = PkiClient(
        ea_url=ea_url,
        aa_url=aa_url,
        ea_cert=ea_cert,
        aa_cert=aa_cert,
        rca_cert=rca_cert,
        certs_dir=certs_dir,
        its_id=station_id.to_bytes(8, "big"),
    )

    # Attempt to reuse a cached AT (avoids unnecessary PKI round-trips)
    if not reprovision:
        cached = client.load_at_from_disk("at")
        if cached is not None:
            log.info(
                "Reusing cached AT from disk: %s/at.{cert,pem}", certs_dir
            )
            return cached, client.backend

    # Full provision: enrolment + authorization
    log.info("Starting PKI provisioning (this contacts EA at %s and AA at %s)…", ea_url, aa_url)
    at_own = await client.provision(app_permissions=AT_APP_PERMISSIONS)
    log.info(
        "Provisioning complete — AT HashedId8=%s", at_own.as_hashedid8().hex()
    )
    return at_own, client.backend


# ---------------------------------------------------------------------------
# Security stack assembly
# ---------------------------------------------------------------------------

def build_security_stack(
    at_own: OwnCertificate,
    backend: PythonECDSABackend,
    rca_cert: Certificate,
    aa_cert: Certificate,
) -> tuple[SignService, VerifyService]:
    """Assemble SignService + VerifyService from a live-issued AT.

    The certificate library contains:
      - ``root_certificates`` — the Root CA (trust anchor)
      - ``aa_certificates``   — the Authorization Authority
      - ``at_certificates``   — the station's own AT (for signing)

    This mirrors the structure built by the static example, except the AT
    comes from the PKI rather than from a pre-generated file.

    Parameters
    ----------
    at_own:
        The AT ``OwnCertificate`` returned by :func:`_provision_at`.
    backend:
        ECDSA backend holding the AT private key.
    rca_cert, aa_cert:
        Authority certificates for the trust chain.

    Returns
    -------
    (sign_service, verify_service)
    """
    cert_library = CertificateLibrary(
        ecdsa_backend=backend,
        root_certificates=[rca_cert],
        aa_certificates=[aa_cert],
        at_certificates=[at_own],
    )
    cert_library.add_own_certificate(at_own)

    sign_service = SignService(backend=backend, certificate_library=cert_library)
    verify_service = VerifyService(
        backend=backend,
        certificate_library=cert_library,
        sign_service=sign_service,
    )
    log.info("Security stack ready (AT=%s)", at_own.as_hashedid8().hex())
    return sign_service, verify_service


# ---------------------------------------------------------------------------
# Location service — simulated moving vehicle (copied from static example)
# ---------------------------------------------------------------------------

class _RandomTrajectoryLocationService:
    """Thread-based location service that simulates a moving vehicle at ~10 Hz."""

    _PERIOD_S: float = 0.08
    _BASE_SPEED_MPS: float = 10.0
    _EARTH_R: float = 6_371_000.0

    def __init__(self, start_lat: float, start_lon: float) -> None:
        self._callbacks: list = []
        self._lat = start_lat
        self._lon = start_lon
        self._heading = random.uniform(0.0, 360.0)
        self._speed = self._BASE_SPEED_MPS
        import threading
        self.stop_event = threading.Event()
        self.location_service_thread = threading.Thread(
            target=self._run, daemon=True
        )
        self.location_service_thread.start()

    def add_callback(self, callback) -> None:
        self._callbacks.append(callback)

    def _send(self, tpv: dict) -> None:
        for cb in self._callbacks:
            cb(tpv)

    def _step(self) -> None:
        dt = self._PERIOD_S
        delta = random.uniform(5.0, 15.0) * random.choice((-1, 1))
        self._heading = (self._heading + delta) % 360.0
        self._speed = max(5.0, min(20.0, self._speed + random.uniform(-0.5, 0.5)))
        d = self._speed * dt
        heading_r = math.radians(self._heading)
        lat_r = math.radians(self._lat)
        self._lat += math.degrees(d * math.cos(heading_r) / self._EARTH_R)
        self._lon += math.degrees(
            d * math.sin(heading_r) / (self._EARTH_R * math.cos(lat_r))
        )

    def _tpv(self) -> dict:
        ts = datetime.datetime.now(datetime.timezone.utc).isoformat()[:-9] + "Z"
        return {
            "class": "TPV", "device": "/dev/ttyACM0", "mode": 3, "time": ts,
            "ept": 0.005, "lat": self._lat, "lon": self._lon, "alt": 0.0,
            "epx": 1.0, "epy": 1.0, "epv": 5.0, "track": self._heading,
            "speed": self._speed, "climb": 0.0, "eps": 0.01,
        }

    def _run(self) -> None:
        while not self.stop_event.is_set():
            self._step()
            self._send(self._tpv())
            time.sleep(self._PERIOD_S)


# ---------------------------------------------------------------------------
# ITS-S stack
# ---------------------------------------------------------------------------

def run_its_station(
    sign_service: SignService,
    verify_service: VerifyService,
    station_id: int = STATION_ID,
    interface: str = "lo",
) -> None:
    """Wire up GeoNetworking + BTP + LDM + CABasicService and run the CAM loop.

    This function blocks until a ``KeyboardInterrupt`` is received.

    Parameters
    ----------
    sign_service, verify_service:
        Security services built by :func:`build_security_stack`.
    station_id:
        Station ID for this ITS-S instance.
    interface:
        Network interface for the raw link layer (default: "lo").
    """
    location_service = _RandomTrajectoryLocationService(
        start_lat=POSITION_COORDINATES[0],
        start_lon=POSITION_COORDINATES[1],
    )

    mib = MIB(
        itsGnLocalGnAddr=GNAddress(
            m=M.GN_MULTICAST,
            st=ST.CYCLIST,
            mid=MID(MAC_ADDRESS),
        ),
        itsGnSecurity=GnSecurity.ENABLED,
    )
    gn_router = GNRouter(
        mib=mib,
        sign_service=sign_service,
        verify_service=verify_service,
    )
    location_service.add_callback(gn_router.refresh_ego_position_vector)

    btp_router = BTPRouter(gn_router)
    gn_router.register_indication_callback(btp_router.btp_data_indication)

    # LDM
    ldm_location = Location.initializer(
        latitude=int(POSITION_COORDINATES[0] * 10 ** 7),
        longitude=int(POSITION_COORDINATES[1] * 10 ** 7),
    )
    ldm_area = GeometricArea(circle=Circle(radius=5000), rectangle=None, ellipse=None)
    ldm_factory = LDMFactory()
    ldm = ldm_factory.create_ldm(
        ldm_location,
        ldm_maintenance_type="Reactive",
        ldm_service_type="Reactive",
        ldm_database_type="Dictionary",
    )
    location_service.add_callback(ldm_location.location_service_callback)

    # LDM subscription — print received CAMs from other stations
    register_resp: RegisterDataConsumerResp = ldm.if_ldm_4.register_data_consumer(
        RegisterDataConsumerReq(
            application_id=CAM,
            access_permisions=(AccessPermission.CAM,),
            area_of_interest=ldm_area,
        )
    )
    if register_resp.result == 2:
        log.error("LDM registration failed")
        sys.exit(1)

    def _cam_received(data: RequestDataObjectsResp) -> None:
        sender_id = data.data_objects[0]["dataObject"]["header"]["stationId"]
        log.info("Received CAM from stationId=%d", sender_id)

    subscribe_resp: SubscribeDataObjectsResp = ldm.if_ldm_4.subscribe_data_consumer(
        SubscribeDataobjectsReq(
            application_id=CAM,
            data_object_type=(CAM,),
            priority=1,
            filter=Filter(
                filter_statement_1=FilterStatement(
                    "header.stationId",
                    ComparisonOperators.NOT_EQUAL,
                    station_id,
                )
            ),
            notify_time=TimestampIts(0),
            multiplicity=1,
            order=(
                OrderTupleValue(
                    attribute="cam.generationDeltaTime",
                    ordering_direction=OrderingDirection.ASCENDING,
                ),
            ),
        ),
        _cam_received,
    )
    if subscribe_resp.result != SubscribeDataobjectsResult.SUCCESSFUL:
        log.error("LDM subscription failed")
        sys.exit(1)

    # CA Basic Service
    vehicle_data = VehicleData(
        station_id=station_id,
        station_type=5,
        drive_direction="forward",
        vehicle_length={
            "vehicleLengthValue": 1023,
            "vehicleLengthConfidenceIndication": "unavailable",
        },
        vehicle_width=62,
    )
    ca_basic_service = CooperativeAwarenessBasicService(
        btp_router=btp_router,
        vehicle_data=vehicle_data,
        ldm=ldm,
    )
    location_service.add_callback(
        ca_basic_service.cam_transmission_management.location_service_callback
    )

    # Link layer + start
    btp_router.freeze_callbacks()
    link_layer = RawLinkLayer(
        interface, MAC_ADDRESS, receive_callback=gn_router.gn_data_indicate
    )
    gn_router.link_layer = link_layer
    ca_basic_service.start()
    log.info("ITS-S running (stationId=%d) on interface '%s' — press Ctrl+C to stop", station_id, interface)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log.info("Shutting down…")

    ca_basic_service.stop()
    location_service.stop_event.set()
    location_service.location_service_thread.join()
    link_layer.sock.close()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "C-ITS ITS-S that obtains its Authorization Ticket from a live PKI "
            "(ETSI TS 102 941 S3+S2) and then sends/receives signed CAMs."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--station-id",
        type=int,
        default=None,
        metavar="ID",
        help="Custom Station ID integer (default: randomly generated)",
    )
    parser.add_argument(
        "--interface",
        default="lo",
        metavar="IFACE",
        help="Network interface to send/receive raw V2X frames (e.g. lo, veth0)",
    )
    parser.add_argument(
        "--ea",
        default="http://localhost:8080",
        metavar="URL",
        help="Enrolment Authority base URL",
    )
    parser.add_argument(
        "--aa",
        default="http://localhost:8081",
        metavar="URL",
        help="Authorization Authority base URL",
    )
    parser.add_argument(
        "--rca",
        default=os.path.join(_DEFAULT_PKI_CERTS_DIR, "rca.coer"),
        metavar="FILE",
        help="Path to COER-encoded Root CA certificate",
    )
    parser.add_argument(
        "--ea-cert",
        default=os.path.join(_DEFAULT_PKI_CERTS_DIR, "ea.coer"),
        metavar="FILE",
        help="Path to COER-encoded EA certificate",
    )
    parser.add_argument(
        "--aa-cert",
        default=os.path.join(_DEFAULT_PKI_CERTS_DIR, "aa.coer"),
        metavar="FILE",
        help="Path to COER-encoded AA certificate",
    )
    parser.add_argument(
        "--certs-dir",
        default=_DEFAULT_ISSUED_DIR,
        metavar="DIR",
        help="Directory to store/load issued EC + AT certificate files",
    )
    parser.add_argument(
        "--no-reprovision",
        action="store_true",
        help="Reuse a previously issued AT from --certs-dir if available",
    )
    return parser.parse_args()


async def _async_main() -> None:
    """Async entry point: provision AT then hand off to synchronous ITS-S loop."""
    args = _parse_args()

    station_id = args.station_id if args.station_id is not None else STATION_ID

    # 1. Load authority certificates
    rca_cert, ea_cert, aa_cert = _load_pki_authority_certs(
        rca_path=args.rca,
        ea_path=args.ea_cert,
        aa_path=args.aa_cert,
    )

    # 2. Provision AT from PKI (S3 + S2)
    at_own, backend = await _provision_at(
        ea_url=args.ea,
        aa_url=args.aa,
        rca_cert=rca_cert,
        ea_cert=ea_cert,
        aa_cert=aa_cert,
        certs_dir=args.certs_dir,
        reprovision=not args.no_reprovision,
        station_id=station_id,
    )

    # 3. Build security stack
    sign_service, verify_service = build_security_stack(
        at_own=at_own,
        backend=backend,
        rca_cert=rca_cert,
        aa_cert=aa_cert,
    )

    # 4. Run the ITS-S CAM loop (blocks until Ctrl+C)
    run_its_station(
        sign_service=sign_service,
        verify_service=verify_service,
        station_id=station_id,
        interface=args.interface,
    )


def main() -> None:
    """Synchronous entry point (wraps the async provisioning step)."""
    asyncio.run(_async_main())


if __name__ == "__main__":
    main()
