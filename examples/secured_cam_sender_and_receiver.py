"""
Send and receive CAM (Cooperative Awareness Messages) with C-ITS security.

This example is an extension of :mod:`cam_sender_and_receiver` that enables the
GeoNetworking security layer so that every outgoing CAM is ETSI TS 103 097-signed
and every incoming secured packet is verified before being delivered to the upper
layers.

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
Run two terminals simultaneously to see cross-station CAM verification::

    # Terminal 1
    python examples/secured_cam_sender_and_receiver.py --at 1

    # Terminal 2
    python examples/secured_cam_sender_and_receiver.py --at 2

Each instance signs outgoing CAMs with its own AT while keeping both AT1 and AT2
in its :class:`~flexstack.security.certificate_library.CertificateLibrary` as
*known* authorization tickets.  This allows every station to verify messages from
either peer, regardless of whether the message carries a full certificate or only
a digest signer.

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
- ETSI TS 103 097 V2.1.1 – Security header and certificate formats for ITS
- ETSI EN 302 636-4-1 V1.4.1 – GeoNetworking (SECURED_PACKET handling)
- ETSI TS 102 723-8 V1.1.1 – ITS-S security services (SN-SAP)
"""

import os
import sys

# Ensure ../src (relative to this file) is on PYTHONPATH so local modules can be imported
_this_dir = os.path.dirname(os.path.abspath(__file__))
_src_dir = os.path.normpath(os.path.join(_this_dir, "..", "src"))
if _src_dir not in sys.path:
    sys.path.insert(0, _src_dir)

import argparse
import random
import time
import logging

from flexstack.facilities.local_dynamic_map.ldm_classes import ComparisonOperators
from flexstack.facilities.ca_basic_service.cam_transmission_management import VehicleData
from flexstack.facilities.ca_basic_service.ca_basic_service import CooperativeAwarenessBasicService
from flexstack.facilities.local_dynamic_map.ldm_constants import CAM
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
from flexstack.utils.static_location_service import ThreadStaticLocationService
from flexstack.btp.router import Router as BTPRouter
from flexstack.geonet.gn_address import GNAddress, M, ST, MID
from flexstack.geonet.mib import MIB
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
    locally_administered : bool
        If *True* (default) the locally-administered bit is set.
    multicast : bool
        If *True* the multicast bit is set; otherwise the address is unicast.

    Returns
    -------
    bytes
        Six-byte MAC address.
    """
    octets = [random.randint(0x00, 0xFF) for _ in range(6)]
    first = octets[0]
    if multicast:
        first |= 0b00000001
    else:
        first &= 0b11111110
    if locally_administered:
        first |= 0b00000010
    else:
        first &= 0b11111101
    octets[0] = first
    return bytes(octets)


MAC_ADDRESS = generate_random_mac_address()
STATION_ID = random.randint(1, 2147483647)


# ---------------------------------------------------------------------------
# Certificate loading
# ---------------------------------------------------------------------------

def _cert_path(name: str) -> str:
    """Return the absolute path to a certificate file inside :data:`CERTS_DIR`."""
    return os.path.join(CERTS_DIR, name)


def _check_cert_files() -> None:
    """
    Check that all required certificate files are present.

    Raises
    ------
    SystemExit
        If any required file is missing, a descriptive message is printed and
        the process exits with code 1.
    """
    required = [
        "root_ca.cert", "root_ca.pem",
        "aa.cert", "aa.pem",
        "at1.cert", "at1.pem",
        "at2.cert", "at2.pem",
    ]
    missing = [f for f in required if not os.path.isfile(_cert_path(f))]
    if missing:
        print("Error: the following certificate files are missing:")
        for f in missing:
            print(f"  {_cert_path(f)}")
        print("\nRun the certificate generation script first:")
        print("  python examples/generate_certificate_chain.py")
        sys.exit(1)


def _load_at_as_own(
    backend: PythonECDSABackend, index: int, aa: Certificate
) -> OwnCertificate:
    """
    Load an Authorization Ticket from disk and return it as an :class:`OwnCertificate`.

    The private key stored in ``at<index>.pem`` is imported into *backend* so
    that the returned certificate can be used for signing.

    Parameters
    ----------
    backend : PythonECDSABackend
        The ECDSA backend that will hold the imported private key.
    index : int
        AT index (1 or 2) that determines which ``at<index>.cert`` /
        ``at<index>.pem`` file pair is read.
    aa : Certificate
        The Authorization Authority certificate that issued this AT, used to
        reconstruct the issuer chain.

    Returns
    -------
    OwnCertificate
        The AT certificate with a valid ``key_id`` pointing to the imported key.
    """
    key_pem = open(_cert_path(f"at{index}.pem"), "rb").read()
    key_id = backend.import_signing_key(key_pem)
    cert_bytes = open(_cert_path(f"at{index}.cert"), "rb").read()
    base = Certificate().decode(cert_bytes, issuer=aa)
    return OwnCertificate(certificate=base.certificate, issuer=aa, key_id=key_id)


def _load_at_as_known(index: int, aa: Certificate) -> Certificate:
    """
    Load an Authorization Ticket from disk as a plain :class:`Certificate`.

    Used to populate the ``known_authorization_tickets`` of the library so that
    incoming messages signed with a *digest* signer referencing this AT can be
    verified.

    Parameters
    ----------
    index : int
        AT index (1 or 2) selecting which ``at<index>.cert`` file is read.
    aa : Certificate
        The Authorization Authority certificate that issued this AT.

    Returns
    -------
    Certificate
        The AT certificate linked to its issuer chain.
    """
    cert_bytes = open(_cert_path(f"at{index}.cert"), "rb").read()
    return Certificate().decode(cert_bytes, issuer=aa)


def build_security_stack(at_index: int) -> tuple:
    """
    Load the certificate chain from disk and construct the security objects.

    Reads the OER certificates (Root CA, AA, AT1, AT2) and the selected AT
    private key from :data:`CERTS_DIR` and assembles a
    :class:`~flexstack.security.certificate_library.CertificateLibrary`,
    a :class:`~flexstack.security.sign_service.SignService` and a
    :class:`~flexstack.security.verify_service.VerifyService`.

    Both AT1 and AT2 are registered as *known* authorization tickets so that
    this station can verify digest-signed messages from either peer without
    waiting for a full-certificate transmission.

    Parameters
    ----------
    at_index : int
        Which AT (1 or 2) this station uses for signing outgoing messages.

    Returns
    -------
    tuple[SignService, VerifyService]
        The configured sign and verify services ready to be passed to the
        :class:`~flexstack.geonet.router.Router`.

    Raises
    ------
    SystemExit
        If any certificate file is missing (see :func:`_check_cert_files`).
    """
    _check_cert_files()

    backend = PythonECDSABackend()

    # ------------------------------------------------------------------
    # Load Root CA (self-signed)
    # ------------------------------------------------------------------
    root_ca_bytes = open(_cert_path("root_ca.cert"), "rb").read()
    root_ca = Certificate().decode(root_ca_bytes, issuer=None)

    # ------------------------------------------------------------------
    # Load Authorization Authority (issued by Root CA)
    # ------------------------------------------------------------------
    aa_bytes = open(_cert_path("aa.cert"), "rb").read()
    aa = Certificate().decode(aa_bytes, issuer=root_ca)

    # ------------------------------------------------------------------
    # Load the signing AT (OwnCertificate with private key) and both ATs
    # as known authorization tickets for peer verification.
    # ------------------------------------------------------------------
    own_at = _load_at_as_own(backend, at_index, aa)
    peer_index = 2 if at_index == 1 else 1
    peer_at = _load_at_as_known(peer_index, aa)

    # ------------------------------------------------------------------
    # Build CertificateLibrary with the full chain of trust.
    # - known_authorization_tickets: both AT1 and AT2 (for digest verification)
    # - own_certificates: the station's own AT (for signing)
    # ------------------------------------------------------------------
    cert_library = CertificateLibrary(
        ecdsa_backend=backend,
        root_certificates=[root_ca],
        aa_certificates=[aa],
        at_certificates=[own_at, peer_at],
    )
    cert_library.add_own_certificate(own_at)

    sign_service = SignService(backend=backend, certificate_library=cert_library)
    verify_service = VerifyService(backend=backend, certificate_library=cert_library)

    return sign_service, verify_service


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Run the secured CAM sender/receiver loop.

    Parses the ``--at {1,2}`` command-line argument to select which Authorization
    Ticket this station uses for signing.  Sets up the full ITS-S stack (location
    service, GN router with security, BTP router, LDM and CA Basic Service) and then
    blocks, sending a CAM every second and printing any received CAMs from the peer
    station until a ``KeyboardInterrupt`` is raised.
    """
    parser = argparse.ArgumentParser(
        description="Secured CAM sender/receiver (select station 1 or 2 via --at)"
    )
    parser.add_argument(
        "--at",
        type=int,
        choices=[1, 2],
        required=True,
        help="Authorization Ticket index for this station (1 or 2)",
    )
    args = parser.parse_args()

    print(f"Starting station with AT{args.at}...")
    sign_service, verify_service = build_security_stack(args.at)

    # Instantiate a Location Service
    location_service = ThreadStaticLocationService(
        period=1000,
        latitude=POSITION_COORDINATES[0],
        longitude=POSITION_COORDINATES[1],
    )

    # Instantiate a GN router with security enabled
    mib = MIB(
        itsGnLocalGnAddr=GNAddress(
            m=M.GN_MULTICAST,
            st=ST.CYCLIST,
            mid=MID(MAC_ADDRESS),
        ),
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

    # Subscribe to LDM to print received CAMs
    register_resp: RegisterDataConsumerResp = ldm.if_ldm_4.register_data_consumer(
        RegisterDataConsumerReq(
            application_id=CAM,
            access_permisions=(AccessPermission.CAM,),
            area_of_interest=ldm_area,
        )
    )
    if register_resp.result == 2:
        sys.exit(1)

    def ldm_subscription_callback(data: RequestDataObjectsResp) -> None:
        print(
            f'Received CAM from: {data.data_objects[0]["dataObject"]["header"]["stationId"]}'
        )

    subscribe_resp: SubscribeDataObjectsResp = ldm.if_ldm_4.subscribe_data_consumer(
        SubscribeDataobjectsReq(
            application_id=CAM,
            data_object_type=(CAM,),
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
                    attribute="cam.generationDeltaTime",
                    ordering_direction=OrderingDirection.ASCENDING,
                ),
            ),
        ),
        ldm_subscription_callback,
    )
    if subscribe_resp.result != SubscribeDataobjectsResult.SUCCESSFUL:
        sys.exit(1)

    # Instantiate a CA Basic Service
    vehicle_data = VehicleData(
        station_id=STATION_ID,
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
