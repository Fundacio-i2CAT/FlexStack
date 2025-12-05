import os
import sys
# Ensure ../src (relative to this file) is on PYTHONPATH so local modules can be imported
_this_dir = os.path.dirname(os.path.abspath(__file__))
_src_dir = os.path.normpath(os.path.join(_this_dir, "..", "src"))
if _src_dir not in sys.path:
    sys.path.insert(0, _src_dir)

# Configure logging
import random
import time
from flexstack.facilities.local_dynamic_map.ldm_classes import ComparisonOperators
from flexstack.facilities.ca_basic_service.cam_transmission_management import (
    VehicleData,
)
from flexstack.facilities.ca_basic_service.ca_basic_service import (
    CooperativeAwarenessBasicService,
)
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
import logging

logging.basicConfig(level=logging.INFO)

def generate_random_mac_address(locally_administered: bool = True, multicast: bool = False) -> bytes:
    """
    Generate a randomized 6-byte MAC address.

    - locally_administered: if True, sets the locally-administered bit.
    - multicast: if True, sets the multicast bit (otherwise unicast).
    Returns the MAC address as a bytes object.
    """
    octets = [random.randint(0x00, 0xFF) for _ in range(6)]
    # Ensure correct unicast/multicast and locally-administered bits in the first octet:
    # bit0 (LSB) = 1 -> multicast, 0 -> unicast
    # bit1 = 1 -> locally administered, 0 -> globally unique
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

POSITION_COORDINATES = [41.386931, 2.112104]
MAC_ADDRESS = generate_random_mac_address()
STATION_ID = random.randint(1, 2147483647)

def main():
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

    # Instantiate a BTP router
    btp_router = BTPRouter(gn_router)
    gn_router.register_indication_callback(btp_router.btp_data_indication)

    # Instantiate a Local Dynamic Map (LDM)
    ldm_location = Location.initializer(
        latitude=int(POSITION_COORDINATES[0]*10**7),
        longitude=int(POSITION_COORDINATES[1]*10**7),
    )
    
    ldm_area = GeometricArea(
        circle=Circle(
            radius=5000,  # 5 km radius
        ),
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

    # Subscribe to LDM
    register_data_consumer_reponse: RegisterDataConsumerResp = (
        ldm.if_ldm_4.register_data_consumer(
            RegisterDataConsumerReq(
                application_id=CAM,
                access_permisions=(AccessPermission.CAM,),
                area_of_interest=ldm_area,
            )
        )
    )
    if register_data_consumer_reponse.result == 2:
        exit(1)

    def ldm_subscription_callback(data: RequestDataObjectsResp) -> None:
        print(
            f'Received CAM from : {data.data_objects[0]["dataObject"]["header"]["stationId"]}')

    subscribe_data_consumer_response: SubscribeDataObjectsResp = (
        ldm.if_ldm_4.subscribe_data_consumer(
            SubscribeDataobjectsReq(
                application_id=CAM,
                data_object_type=(CAM,),
                priority=1,
                filter=Filter(filter_statement_1=FilterStatement("header.stationId",
                                                                ComparisonOperators.NOT_EQUAL,
                                                                STATION_ID)),
                notify_time=TimestampIts(0),
                multiplicity=1,
                order=(OrderTupleValue(attribute="cam.generationDeltaTime",
                                       ordering_direction=OrderingDirection.ASCENDING),),
            ),
            ldm_subscription_callback,
        )
    )
    if subscribe_data_consumer_response.result != SubscribeDataobjectsResult.SUCCESSFUL:
        exit(1)

    # Instantiate a CA Basic Service
    vehicle_data = VehicleData(
        station_id=STATION_ID, # Station Id of the ITS PDU Header
        # Station Type as specified in ETSI TS 102 894-2 V2.3.1 (2024-08)
        station_type=5,
        drive_direction="forward",
        vehicle_length={
            # as specified in ETSI TS 102 894-2 V2.3.1 (2024-08)
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
        ca_basic_service.cam_transmission_management.location_service_callback)


    # Instantiate a Link Layer
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