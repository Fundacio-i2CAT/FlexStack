import os
import sys
THIS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(THIS_DIR, os.pardir))
SRC_DIR = os.path.join(PROJECT_ROOT, "src")
if os.path.isdir(SRC_DIR) and SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

# Configure logging
import logging
logging.basicConfig(level=logging.INFO)

# Link Layer Imports
from flexstack.linklayer.raw_link_layer import RawLinkLayer

# GeoNetworking imports
from flexstack.geonet.router import Router as GNRouter
from flexstack.geonet.mib import MIB
from flexstack.geonet.gn_address import GNAddress, M, ST, MID

# BTP Router imports
from flexstack.btp.router import Router as BTPRouter

# Location Service imports
from flexstack.utils.static_location_service import ThreadStaticLocationService

# CA Basic Service imports
from flexstack.facilities.ca_basic_service.ca_basic_service import (
    CooperativeAwarenessBasicService,
)
from flexstack.facilities.ca_basic_service.cam_transmission_management import (
    VehicleData,
)

POSITION_COORDINATES = [41.386931, 2.112104]
MAC_ADDRESS = b"\xaa\xbb\xcc\x11\x21\x11"
STATION_ID = int(MAC_ADDRESS[-1])


def main() -> None:    
    # Instantiate a Location Service
    location_service = ThreadStaticLocationService(
        period=1000, latitude=POSITION_COORDINATES[0], longitude=POSITION_COORDINATES[1]
    )

    # Instantiate a GN router
    mib = MIB(
        itsGnLocalGnAddr=GNAddress(
            m=M.GN_MULTICAST,
            st=ST.CYCLIST,
            mid=MID(MAC_ADDRESS),
            ),
    )
    gn_router = GNRouter(mib=mib, sign_service=None)
    location_service.add_callback(gn_router.refresh_ego_position_vector)

    # Instantiate a Link Layer
    link_layer = RawLinkLayer(
        "lo", MAC_ADDRESS, receive_callback=gn_router.gn_data_indicate
    )

    gn_router.link_layer = link_layer

    # Instantiate a BTP router
    btp_router = BTPRouter(gn_router)
    gn_router.register_indication_callback(btp_router.btp_data_indication)

    # Instantiate a CA Basic Service
    vehicle_data = VehicleData()
    vehicle_data.station_id = STATION_ID  # Station Id of the ITS PDU Header
    vehicle_data.station_type = 5  # Station Type as specified in ETSI TS 102 894-2 V2.3.1 (2024-08)
    vehicle_data.drive_direction = "forward"
    vehicle_data.vehicle_length = {
        "vehicleLengthValue": 1023,  # as specified in ETSI TS 102 894-2 V2.3.1 (2024-08)
        "vehicleLengthConfidenceIndication": "unavailable",
    }
    vehicle_data.vehicle_width = 62

    ca_basic_service = CooperativeAwarenessBasicService(
        btp_router=btp_router,
        vehicle_data=vehicle_data,
    )
    location_service.add_callback(ca_basic_service.cam_transmission_management.location_service_callback)

    print("Press Ctrl+C to stop the program.")
    location_service.location_service_thread.join()

if __name__ == "__main__":
    main()