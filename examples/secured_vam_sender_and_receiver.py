"""
Send and receive VAM (VRU Awareness Messages) with C-ITS security.

This example is an extension of :mod:`cam_sender_and_receiver` that enables the
GeoNetworking security layer so that every outgoing VAM is ETSI TS 103 097-signed
and every incoming secured packet is verified before being delivered to the upper
layers.  It simulates two pedestrian VRU ITS-Ss exchanging VAMs over a loopback
interface with VBS clustering support enabled.

Prerequisites
-------------
Run :mod:`generate_certificate_chain` first to create the certificate files::

    python examples/generate_certificate_chain.py

The script expects the following files inside an ``examples/certs/`` directory
(relative to this file):

- ``root_ca.cert`` / ``root_ca.pem`` – Root CA OER certificate and private key.
- ``aa.cert``      / ``aa.pem``      – Authorization Authority OER cert and key.
- ``at1.cert``     / ``at1.pem``     – Authorization Ticket for station 1.
- ``at2.cert``     / ``at2.pem``     – Authorization Ticket for station 2.

If any file is missing the script prints an informative message and exits.

Two-station setup
-----------------
Run two terminals simultaneously to see cross-station VAM verification::

    # Terminal 1
    python examples/secured_vam_sender_and_receiver.py --at 1

    # Terminal 2
    python examples/secured_vam_sender_and_receiver.py --at 2

Each instance signs outgoing VAMs with its own AT while keeping both AT1 and AT2
in its :class:`~flexstack.security.certificate_library.CertificateLibrary` as
*known* authorization tickets.  This allows every station to verify messages from
either peer, regardless of whether the message carries a full certificate or only
a digest signer.

VBS Clustering
--------------
Both stations start with ``cluster_support=True`` and ``own_vru_profile="pedestrian"``.
The VBS clustering state machine (ETSI TS 103 300-3 V2.3.1, clause 5.4) will
automatically negotiate cluster leader/follower roles based on received VAMs.

Architecture
------------
The security objects are wired into the GeoNetworking router as follows::

    CertificateLibrary (trusted root CA + AA, own ATn, known AT1 + AT2) ─┐
                ↓                                                          │
          SignService  ─────────────────────────────────────────────────┤
                           GNRouter (sign_service, verify_service)
          VerifyService ─────────────────────────────────────────────────┘

References
----------
- ETSI TS 103 300-3 V2.3.1 – VRU Awareness Basic Service (VAM specification)
- ETSI TS 103 097 V2.1.1   – Security header and certificate formats for ITS
- ETSI EN 302 636-4-1 V1.4.1 – GeoNetworking (SECURED_PACKET handling)
- ETSI TS 102 723-8 V1.1.1   – ITS-S security services (SN-SAP)
"""

import os
import sys

# Ensure ../src (relative to this file) is on PYTHONPATH so local modules can be imported
_this_dir = os.path.dirname(os.path.abspath(__file__))
_src_dir = os.path.normpath(os.path.join(_this_dir, "..", "src"))
if _src_dir not in sys.path:
    sys.path.insert(0, _src_dir)

import argparse
import datetime
import math
import random
import time
import logging

from flexstack.facilities.local_dynamic_map.ldm_classes import ComparisonOperators
from flexstack.facilities.vru_awareness_service.vam_transmission_management import DeviceDataProvider
from flexstack.facilities.vru_awareness_service.vru_awareness_service import VRUAwarenessService
from flexstack.facilities.local_dynamic_map.ldm_constants import VAM
from flexstack.facilities.local_dynamic_map.ldm_classes import (
    AccessPermission,
    Circle,
    Filter,
    FilterStatement,
    GeometricArea,
    Location,
    OrderTupleValue,
    OrderingDirection,
    SubscribeDataobjectsReq,
    SubscribeDataObjectsResp,
    RegisterDataConsumerReq,
    RegisterDataConsumerResp,
    RequestDataObjectsResp,
    SubscribeDataobjectsResult,
    TimestampIts,
)
from flexstack.facilities.local_dynamic_map.factory import LDMFactory
from flexstack.btp.router import Router as BTPRouter
from flexstack.geonet.gn_address import GNAddress, M, ST, MID
from flexstack.geonet.mib import MIB, GnSecurity
from flexstack.geonet.router import Router as GNRouter
from flexstack.linklayer.raw_link_layer import RawLinkLayer
from flexstack.security.certificate import Certificate, OwnCertificate
from flexstack.security.certificate_library import CertificateLibrary
from flexstack.security.ecdsa_backend import PythonECDSABackend
from flexstack.security.sign_service import SignService
from flexstack.security.verify_service import VerifyService

logging.basicConfig(level=logging.INFO)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

POSITION_COORDINATES = [41.386931, 2.112104]
CERTS_DIR = os.path.join(_this_dir, "certs")


def generate_random_mac_address(locally_administered: bool = True, multicast: bool = False) -> bytes:
    """
    Generate a randomized 6-byte MAC address.

    Parameters
    ----------
    locally_administered:
        Set the locally-administered bit (bit 1 of byte 0).  Default: True.
    multicast:
        Set the multicast/group bit (bit 0 of byte 0).  Default: False.
    """
    addr = [random.randint(0x00, 0xFF) for _ in range(6)]
    if locally_administered:
        addr[0] |= 0x02
    else:
        addr[0] &= ~0x02
    if multicast:
        addr[0] |= 0x01
    else:
        addr[0] &= ~0x01
    return bytes(addr)


MAC_ADDRESS = generate_random_mac_address()
STATION_ID = random.randint(1, 2147483647)


# ---------------------------------------------------------------------------
# Certificate helpers
# ---------------------------------------------------------------------------

def _cert_path(name: str) -> str:
    """Return the absolute path to a certificate file inside CERTS_DIR."""
    return os.path.join(CERTS_DIR, name)


def _check_cert_files() -> None:
    """Exit with a helpful message if any required certificate file is missing."""
    required = [
        "root_ca.cert", "root_ca.pem",
        "aa.cert",      "aa.pem",
        "at1.cert",     "at1.pem",
        "at2.cert",     "at2.pem",
    ]
    missing = [f for f in required if not os.path.isfile(_cert_path(f))]
    if missing:
        print(
            "Missing certificate file(s):\n"
            + "\n".join(f"  {_cert_path(f)}" for f in missing)
            + "\n\nRun:  python examples/generate_certificate_chain.py"
        )
        sys.exit(1)


def _load_at_as_own(
    backend: PythonECDSABackend,
    index: int,
    aa: Certificate,
) -> OwnCertificate:
    """Load AT *index* together with its private key as the *own* certificate."""
    key_pem = open(_cert_path(f"at{index}.pem"), "rb").read()
    key_id = backend.import_signing_key(key_pem)
    cert_bytes = open(_cert_path(f"at{index}.cert"), "rb").read()
    base = Certificate().decode(cert_bytes, issuer=aa)
    return OwnCertificate(certificate=base.certificate, issuer=aa, key_id=key_id)


def _load_at_as_known(index: int, aa: Certificate) -> Certificate:
    """Load AT *index* as a known (peer) certificate."""
    cert_bytes = open(_cert_path(f"at{index}.cert"), "rb").read()
    return Certificate().decode(cert_bytes, issuer=aa)


def build_security_stack(at_index: int) -> tuple[SignService, VerifyService]:
    """
    Build and return a ``(SignService, VerifyService)`` pair for station *at_index*.

    Both AT1 and AT2 are added to the certificate library so that each station
    can verify VAMs from either peer.

    Parameters
    ----------
    at_index:
        Which Authorization Ticket this station owns (1 or 2).
    """
    _check_cert_files()

    backend = PythonECDSABackend()

    # Root CA (self-signed)
    root_ca = Certificate().decode(open(_cert_path("root_ca.cert"), "rb").read(), issuer=None)

    # Authorization Authority (issued by root CA)
    aa = Certificate().decode(open(_cert_path("aa.cert"), "rb").read(), issuer=root_ca)

    # Own AT and peer AT
    peer_index = 2 if at_index == 1 else 1
    own_at = _load_at_as_own(backend, at_index, aa)
    peer_at = _load_at_as_known(peer_index, aa)

    # ------------------------------------------------------------------
    cert_library = CertificateLibrary(
        ecdsa_backend=backend,
        root_certificates=[root_ca],
        aa_certificates=[aa],
        at_certificates=[own_at, peer_at],
    )
    cert_library.add_own_certificate(own_at)

    sign_service = SignService(backend=backend, certificate_library=cert_library)
    verify_service = VerifyService(backend=backend, certificate_library=cert_library, sign_service=sign_service)

    return sign_service, verify_service


# ---------------------------------------------------------------------------
# Randomized moving location service (pedestrian)
# ---------------------------------------------------------------------------

class _RandomTrajectoryLocationService:
    """
    Thread-based location service that simulates a moving pedestrian VRU.

    Updates are emitted every 100 ms (at T_GenVamMin) so the VRU Awareness Basic
    Service timer always has fresh data.  The heading changes by a random ±5–15 °
    on every step, which consistently exceeds the 4 ° heading-change threshold
    (ETSI TS 103 300-3 V2.3.1, clause 6.4.1 condition 1) and sustains regular
    VAM generation.  Speed is randomised in a pedestrian range of 0.5–3.0 m/s.
    """

    _PERIOD_S: float = 0.10       # 100 ms — T_GenVamMin
    _BASE_SPEED_MPS: float = 1.4  # typical walking pace (~5 km/h)
    _EARTH_R: float = 6_371_000.0

    def __init__(self, start_lat: float, start_lon: float) -> None:
        self._callbacks: list = []
        self._lat = start_lat
        self._lon = start_lon
        self._heading = random.uniform(0.0, 360.0)
        self._speed = self._BASE_SPEED_MPS
        self.stop_event = __import__('threading').Event()
        self.location_service_thread = __import__('threading').Thread(
            target=self._run, daemon=True
        )
        self.location_service_thread.start()

    def add_callback(self, callback) -> None:
        self._callbacks.append(callback)

    def _send(self, tpv: dict) -> None:
        for cb in self._callbacks:
            cb(tpv)

    def _step(self) -> None:
        """Advance the simulated position by one time step."""
        dt = self._PERIOD_S

        # Heading: random signed change guaranteed to exceed the 4 ° threshold
        delta = random.uniform(5.0, 15.0) * random.choice((-1, 1))
        self._heading = (self._heading + delta) % 360.0

        # Speed: small random walk in pedestrian range [0.5, 3.0] m/s
        self._speed = max(0.5, min(3.0, self._speed + random.uniform(-0.1, 0.1)))

        # Position update (flat-Earth approximation; step sizes are < 0.3 m)
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
            "class": "TPV",
            "device": "/dev/ttyACM0",
            "mode": 3,
            "time": ts,
            "ept": 0.005,
            "lat": self._lat,
            "lon": self._lon,
            "alt": 0.0,
            "epx": 1.0,
            "epy": 1.0,
            "epv": 5.0,
            "track": self._heading,
            "speed": self._speed,
            "climb": 0.0,
            "eps": 0.01,
        }

    def _run(self) -> None:
        while not self.stop_event.is_set():
            self._step()
            self._send(self._tpv())
            time.sleep(self._PERIOD_S)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Run the secured VAM sender/receiver loop.

    Parses the ``--at {1,2}`` command-line argument to select which Authorization
    Ticket this station uses for signing.  Sets up the full ITS-S stack (location
    service, GN router with security, BTP router, LDM and VRU Awareness Basic
    Service) and then blocks, sending VAMs and printing any received VAMs from the
    peer station until a ``KeyboardInterrupt`` is raised.
    """
    parser = argparse.ArgumentParser(
        description="Secured VAM sender/receiver (select station 1 or 2 via --at)"
    )
    parser.add_argument(
        "--at",
        type=int,
        choices=[1, 2],
        required=True,
        help="Authorization Ticket index for this station (1 or 2)",
    )
    args = parser.parse_args()

    print(f"Starting VRU station with AT{args.at}...")
    sign_service, verify_service = build_security_stack(args.at)

    # Instantiate a moving location service that simulates a pedestrian VRU
    location_service = _RandomTrajectoryLocationService(
        start_lat=POSITION_COORDINATES[0],
        start_lon=POSITION_COORDINATES[1],
    )

    # Instantiate a GN router with security enabled
    mib = MIB(
        itsGnLocalGnAddr=GNAddress(
            m=M.GN_MULTICAST,
            st=ST.PEDESTRIAN,
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

    # Instantiate a BTP router
    btp_router = BTPRouter(gn_router)
    gn_router.register_indication_callback(btp_router.btp_data_indication)

    # Instantiate a Local Dynamic Map (LDM)
    ldm_location = Location.initializer(
        latitude=int(POSITION_COORDINATES[0] * 10 ** 7),
        longitude=int(POSITION_COORDINATES[1] * 10 ** 7),
    )

    ldm_area = GeometricArea(
        circle=Circle(radius=5000),
        rectangle=None,
        ellipse=None,
    )
    ldm_factory = LDMFactory()
    ldm = ldm_factory.create_ldm(
        ldm_location,
        ldm_maintenance_type="Reactive",
        ldm_service_type="Reactive",
        ldm_database_type="Dictionary",
    )
    location_service.add_callback(ldm_location.location_service_callback)

    # Subscribe to LDM to print received VAMs
    register_resp: RegisterDataConsumerResp = ldm.if_ldm_4.register_data_consumer(
        RegisterDataConsumerReq(
            application_id=VAM,
            access_permisions=(AccessPermission.VAM,),
            area_of_interest=ldm_area,
        )
    )
    if register_resp.result == 2:
        sys.exit(1)

    def ldm_subscription_callback(data: RequestDataObjectsResp) -> None:
        print(
            f'Received VAM from: {data.data_objects[0]["dataObject"]["header"]["stationId"]}'
        )

    subscribe_resp: SubscribeDataObjectsResp = ldm.if_ldm_4.subscribe_data_consumer(
        SubscribeDataobjectsReq(
            application_id=VAM,
            data_object_type=(VAM,),
            priority=1,
            filter=Filter(
                filter_statement_1=FilterStatement(
                    "header.stationId",
                    ComparisonOperators.NOT_EQUAL,
                    STATION_ID,
                )
            ),
            notify_time=TimestampIts(0),
            multiplicity=1,
            order=(
                OrderTupleValue(
                    attribute="vam.generationDeltaTime",
                    ordering_direction=OrderingDirection.ASCENDING,
                ),
            ),
        ),
        ldm_subscription_callback,
    )
    if subscribe_resp.result != SubscribeDataobjectsResult.SUCCESSFUL:
        sys.exit(1)

    # Instantiate the VRU Awareness Basic Service
    device_data_provider = DeviceDataProvider(
        station_id=STATION_ID,
        station_type=1,  # pedestrian (ETSI TS 102 894-2, ITSStationType)
    )
    vru_awareness_service = VRUAwarenessService(
        btp_router=btp_router,
        device_data_provider=device_data_provider,
        ldm=ldm,
        cluster_support=True,
        own_vru_profile="pedestrian",
    )
    location_service.add_callback(
        vru_awareness_service.vam_transmission_management.location_service_callback
    )

    # Instantiate a Link Layer and start the main loop
    btp_router.freeze_callbacks()
    link_layer = RawLinkLayer(
        "lo", MAC_ADDRESS, receive_callback=gn_router.gn_data_indicate
    )
    gn_router.link_layer = link_layer

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Exiting...")

    location_service.stop_event.set()
    location_service.location_service_thread.join()
    link_layer.sock.close()


if __name__ == "__main__":
    main()
