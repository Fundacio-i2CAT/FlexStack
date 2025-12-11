import logging
import argparse
from time import sleep
from sys import exit
from uuid import getnode as get_mac

from src.flexstack.facilities.vru_awareness_service.vru_awareness_service import VRUAwarenessService
from src.flexstack.facilities.vru_awareness_service.vam_transmission_management import DeviceDataProvider
from src.flexstack.utils.static_location_service import ThreadStaticLocationService as LocationService

from src.flexstack.facilities.local_dynamic_map.factory import LDMFactory
from src.flexstack.facilities.local_dynamic_map.ldm_classes import (
    Location,
    RequestDataObjectsResp,
)

from src.flexstack.btp.router import Router as BTPRouter

from src.flexstack.geonet.router import Router
from src.flexstack.geonet.mib import MIB
from src.flexstack.geonet.gn_address import GNAddress, M, ST, MID

from src.flexstack.linklayer.raw_link_layer import RawLinkLayer


def __configure_logging(log_level: str) -> None:
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid log level: {log_level}")
    logging.basicConfig(level=numeric_level)


def ldm_subscription_callback(response: RequestDataObjectsResp) -> None:
    print(response.data_objects)


def configure_v2x(station_id: int, log_level: str) -> None | Exception:
    # Configure logging level
    __configure_logging(log_level)

    # Geonet
    mac_address = get_mac().to_bytes(6, byteorder='big')
    mac_address = mac_address[:5] + bytes([station_id])
    gn_addr = GNAddress(m=M.GN_MULTICAST, st=ST.CYCLIST, mid=MID(mac_address))
    mib = MIB(itsGnLocalGnAddr=gn_addr,itsGnBeaconServiceRetransmitTimer=3000)
    gn_router = Router(mib=mib, sign_service=None)

    # Link-Layer
    ll = RawLinkLayer(iface="lo", mac_address=mac_address, receive_callback=gn_router.gn_data_indicate)
    gn_router.link_layer = ll

    # BTP
    btp_router = BTPRouter(gn_router)
    gn_router.register_indication_callback(btp_router.btp_data_indication)

    # Facility - Location Service
    location_service = LocationService()

    location_service.add_callback(gn_router.refresh_ego_position_vector)

    # Facility - Local Dynamic Maps
    ldm_location = Location.initializer()
    location_service.add_callback(ldm_location.location_service_callback)
    ldm_factory = LDMFactory()
    local_dynamic_map = ldm_factory.create_ldm(
        ldm_location, ldm_maintenance_type="Reactive", ldm_service_type="Reactive", ldm_database_type="Dictionary"
    )
    ldm_factory.subscribe_to_ldm(
        own_station_id=station_id,
        area_of_interest=ldm_location,
        callback_function=ldm_subscription_callback,
    )

    # Facility - Device Data Provider
    device_data_provider = DeviceDataProvider(station_id=station_id)

    # Facility - VRU Awareness Service
    vru_awareness_service = VRUAwarenessService(
        btp_router=btp_router, device_data_provider=device_data_provider, ldm=local_dynamic_map
    )
    btp_router.freeze_callbacks()
    location_service.add_callback(vru_awareness_service.vam_transmission_management.location_service_callback)


if __name__ == "__main__":
    args = argparse.ArgumentParser(description="FlexStack CAM Sender/Receiver")
    args.add_argument("--station-id", type=int, default=0, help="Station ID")
    args.add_argument("--log-level", type=str, default="INFO", help="Logging level (DEBUG, INFO)")
    args = args.parse_args()

    configure_v2x(args.station_id, args.log_level)
    try:
        while True:
            sleep(1)
    except KeyboardInterrupt:
        print("\nKeyboardInterrupt caught. Cleaning up...")
        exit(0)
