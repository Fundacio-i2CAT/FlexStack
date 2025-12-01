import logging
from flexstack.linklayer.raw_link_layer import RawLinkLayer
from flexstack.geonet.router import Router as GNRouter
from flexstack.geonet.mib import MIB
from flexstack.geonet.gn_address import GNAddress, M, ST, MID
from flexstack.btp.router import Router as BTPRouter
from flexstack.utils.static_location_service import ThreadStaticLocationService, generate_tpv_dict_with_current_timestamp
from flexstack.facilities.local_dynamic_map.factory import ldm_factory
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
from flexstack.facilities.local_dynamic_map.ldm_constants import CAM, DENM, VAM
from flexstack.facilities.vru_awareness_service.vru_awareness_service import (
    VRUAwarenessService,
)
from flexstack.facilities.vru_awareness_service.vam_transmission_management import (
    DeviceDataProvider,
)
from flexstack.facilities.ca_basic_service.ca_basic_service import (
    CooperativeAwarenessBasicService,
)
from flexstack.facilities.ca_basic_service.cam_transmission_management import (
    VehicleData,
)
from flexstack.facilities.decentralized_environmental_notification_service.den_service import DecentralizedEnvironmentalNotificationService
from flexstack.applications.road_hazard_signalling_service.emergency_vehicle_approaching_service import (
    EmergencyVehicleApproachingService
)
from flexstack.facilities.local_dynamic_map.ldm_classes import ComparisonOperators
import random
import os
import sys
# Ensure ../src (relative to this file) is on PYTHONPATH so local modules can be imported
_this_dir = os.path.dirname(os.path.abspath(__file__))
_src_dir = os.path.normpath(os.path.join(_this_dir, "..", "src"))
if _src_dir not in sys.path:
    sys.path.insert(0, _src_dir)


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
SEND_CAMS = False
SEND_VAMS = False
SEND_DENMS = False


def main():
    # Instantiate a Location Service
    location_service = ThreadStaticLocationService(
        period=1, latitude=POSITION_COORDINATES[0], longitude=POSITION_COORDINATES[1]
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
    ldm = ldm_factory(
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
                access_permisions=(AccessPermission.CAM,
                                   AccessPermission.VAM, AccessPermission.DENM),
                area_of_interest=ldm_area,
            )
        )
    )
    if register_data_consumer_reponse.result == 2:
        exit(1)

    def cam_ldm_subscription_callback(data: RequestDataObjectsResp) -> None:
        print(
            f'Notified CAM from : {data.data_objects[0]["dataObject"]["header"]["stationId"]}')
        print(len(data.data_objects))

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
                                       ordering_direction=OrderingDirection.DESCENDING),),
            ),
            cam_ldm_subscription_callback,
        )
    )
    if subscribe_data_consumer_response.result != SubscribeDataobjectsResult.SUCCESSFUL:
        print("Failed to subscribe to CAM data consumer.")
        exit(1)

    def vam_ldm_subscription_callback(data: RequestDataObjectsResp) -> None:
        print(
            f'Notified VAM from : {data.data_objects[0]["dataObject"]["header"]["stationId"]}')
        print(len(data.data_objects))

    subscribe_data_consumer_response: SubscribeDataObjectsResp = (
        ldm.if_ldm_4.subscribe_data_consumer(
            SubscribeDataobjectsReq(
                application_id=CAM,
                data_object_type=(VAM,),
                priority=1,
                filter=Filter(filter_statement_1=FilterStatement("header.stationId",
                                                                 ComparisonOperators.NOT_EQUAL,
                                                                 STATION_ID)),
                notify_time=TimestampIts(0),
                multiplicity=1,
                order=(OrderTupleValue(attribute="vam.generationDeltaTime",
                                       ordering_direction=OrderingDirection.DESCENDING),),
            ),
            vam_ldm_subscription_callback,
        )
    )
    if subscribe_data_consumer_response.result != SubscribeDataobjectsResult.SUCCESSFUL:
        print("Failed to subscribe to VAM data consumer.")
        print(subscribe_data_consumer_response.result)
        exit(1)

    def denm_ldm_subscription_callback(data: RequestDataObjectsResp) -> None:
        print(
            f'[LDM]Notified DENM from : {data.data_objects[0]["dataObject"]["header"]["stationId"]}')
        print(len(data.data_objects))

    subscribe_data_consumer_response: SubscribeDataObjectsResp = (
        ldm.if_ldm_4.subscribe_data_consumer(
            SubscribeDataobjectsReq(
                application_id=CAM,
                data_object_type=(DENM,),
                priority=1,
                filter=Filter(filter_statement_1=FilterStatement("header.stationId",
                                                                 ComparisonOperators.NOT_EQUAL,
                                                                 STATION_ID)),
                notify_time=TimestampIts(0),
                multiplicity=1,
                order=(OrderTupleValue(attribute="header.stationId",
                                       ordering_direction=OrderingDirection.DESCENDING),),
            ),
            denm_ldm_subscription_callback,
        )
    )
    if subscribe_data_consumer_response.result != SubscribeDataobjectsResult.SUCCESSFUL:
        print("Failed to subscribe to DENM data consumer.")
        exit(1)
    # Instantiate a CA Basic Service
    vehicle_data = VehicleData(
        station_id=STATION_ID,  # Station Id of the ITS PDU Header
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
    vru_awareness_service = VRUAwarenessService(
        btp_router=btp_router,
        device_data_provider=DeviceDataProvider(
            station_id=STATION_ID,
            station_type=5
        ),
        ldm=ldm,
    )
    den_service = DecentralizedEnvironmentalNotificationService(
        btp_router=btp_router, vehicle_data=vehicle_data, ldm=ldm)
    if SEND_DENMS:
        emergency_vehicle_approaching_service = EmergencyVehicleApproachingService(
            den_service=den_service,
            duration=10000,
        )
        emergency_vehicle_approaching_service.trigger_denm_sending(generate_tpv_dict_with_current_timestamp(
            POSITION_COORDINATES[0], POSITION_COORDINATES[1]
        ))

    if SEND_CAMS:
        location_service.add_callback(
            ca_basic_service.cam_transmission_management.location_service_callback)
    if SEND_VAMS:
        location_service.add_callback(
            vru_awareness_service.vam_transmission_management.location_service_callback)

    # Instantiate a Link Layer
    btp_router.freeze_callbacks()
    link_layer = RawLinkLayer(
        "lo", MAC_ADDRESS, receive_callback=gn_router.gn_data_indicate
    )

    gn_router.link_layer = link_layer
    print("Press Ctrl+C to stop the program.")
    location_service.location_service_thread.join()


if __name__ == "__main__":
    main()
