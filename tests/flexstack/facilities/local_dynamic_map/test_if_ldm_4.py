import unittest
from typing import Tuple, cast
from unittest.mock import MagicMock

from flexstack.facilities.local_dynamic_map.if_ldm_4 import InterfaceLDM4
from flexstack.facilities.local_dynamic_map.ldm_classes import (
    ComparisonOperators,
    AccessPermission,
    DeregisterDataConsumerAck,
    DeregisterDataConsumerReq,
    DeregisterDataConsumerResp,
    Filter,
    FilterStatement,
    GeometricArea,
    LogicalOperators,
    OrderingDirection,
    RegisterDataConsumerReq,
    RegisterDataConsumerResp,
    RegisterDataConsumerResult,
    RequestDataObjectsReq,
    RequestedDataObjectsResult,
    OrderTupleValue,
    SubscribeDataobjectsReq,
    SubscribeDataobjectsResult,
    TimestampIts,
    UnsubscribeDataConsumerAck,
    UnsubscribeDataConsumerReq,
    UnsubscribeDataConsumerResp,
)
from flexstack.facilities.local_dynamic_map.ldm_constants import (
    CAM,
    DENM,
    VALID_ITS_AID,
    VAM,
)


WHITE_CAM = {
    "header": {
        "protocolVersion": 2,
        "messageID": 2,
        "stationID": 0,
    },
    "cam": {
        "generationDeltaTime": 0,
        "camParameters": {
            "basicContainer": {
                "stationType": 0,
                "referencePosition": {
                    "latitude": 900000001,
                    "longitude": 1800000001,
                    "positionConfidenceEllipse": {
                        "semiMajorConfidence": 4095,
                        "semiMinorConfidence": 4095,
                        "semiMajorOrientation": 201,
                    },
                    "altitude": {
                        "altitudeValue": 800001,
                        "altitudeConfidence": "unavailable",
                    },
                },
            },
        },
    },
}


class TestInterfaceLDM4(unittest.TestCase):
    def setUp(self) -> None:
        self.ldm_service = MagicMock()
        self.if_ldm_4 = InterfaceLDM4(self.ldm_service)

    def test_check_its_aid_accepts_valid_ids(self) -> None:
        for aid in VALID_ITS_AID:
            self.assertTrue(self.if_ldm_4.check_its_aid(aid))

    def test_check_its_aid_rejects_invalid_values(self) -> None:
        self.assertFalse(self.if_ldm_4.check_its_aid("invalid"))
        self.assertFalse(self.if_ldm_4.check_its_aid(-1))

    def test_check_permissions(self) -> None:
        empty_permissions = cast(Tuple[AccessPermission, ...], tuple())
        vam_permissions = cast(Tuple[AccessPermission, ...], (VAM,))
        cam_permissions = cast(Tuple[AccessPermission, ...], (CAM,))

        self.assertFalse(self.if_ldm_4.check_permissions(empty_permissions, VAM))
        self.assertTrue(self.if_ldm_4.check_permissions(vam_permissions, VAM))
        self.assertTrue(self.if_ldm_4.check_permissions(cam_permissions, DENM))

    def test_register_data_consumer_accepts_valid_request(self) -> None:
        permissions = cast(Tuple[AccessPermission, ...], (CAM,))
        request = RegisterDataConsumerReq(CAM, permissions, GeometricArea(None, None, None))

        response = self.if_ldm_4.register_data_consumer(request)

        self.ldm_service.add_data_consumer_its_aid.assert_called_once_with(CAM)
        self.assertIsInstance(response, RegisterDataConsumerResp)
        self.assertEqual(response.result, RegisterDataConsumerResult.ACCEPTED)

    def test_register_data_consumer_rejects_invalid_request(self) -> None:
        empty_permissions = cast(Tuple[AccessPermission, ...], tuple())
        request = RegisterDataConsumerReq(VAM, empty_permissions, GeometricArea(None, None, None))

        response = self.if_ldm_4.register_data_consumer(request)

        self.assertEqual(response.result, RegisterDataConsumerResult.REJECTED)
        self.ldm_service.add_data_consumer_its_aid.assert_not_called()

    def test_deregister_data_consumer_success(self) -> None:
        self.ldm_service.get_data_consumer_its_aid.return_value = [CAM]
        request = DeregisterDataConsumerReq(CAM)

        response = self.if_ldm_4.deregister_data_consumer(request)

        self.assertEqual(response, DeregisterDataConsumerResp(CAM, DeregisterDataConsumerAck.SUCCEED))
        self.ldm_service.del_data_consumer_its_aid.assert_called_once_with(CAM)

    def test_deregister_data_consumer_not_registered(self) -> None:
        self.ldm_service.get_data_consumer_its_aid.return_value = []
        request = DeregisterDataConsumerReq(CAM)

        response = self.if_ldm_4.deregister_data_consumer(request)

        self.assertEqual(response, DeregisterDataConsumerResp(CAM, DeregisterDataConsumerAck.FAILED))
        self.ldm_service.del_data_consumer_its_aid.assert_not_called()

    def test_request_data_objects_invalid_itsa_id(self) -> None:
        self.ldm_service.get_data_consumer_its_aid.return_value = []
        request = RequestDataObjectsReq(
            CAM,
            (CAM,),
            0,
            cast(tuple, [1]),
            cast(Filter, None),
        )

        response = self.if_ldm_4.request_data_objects(request)

        self.assertEqual(response.result, RequestedDataObjectsResult.INVALID_ITSA_ID)

    def test_request_data_objects_invalid_data_type(self) -> None:
        self.ldm_service.get_data_consumer_its_aid.return_value = [CAM]
        request = RequestDataObjectsReq(
            CAM,
            (999,),
            0,
            cast(tuple, [1]),
            cast(Filter, None),
        )

        response = self.if_ldm_4.request_data_objects(request)

        self.assertEqual(response.result, RequestedDataObjectsResult.INVALID_DATA_OBJECT_TYPE)

    def test_request_data_objects_invalid_priority(self) -> None:
        self.ldm_service.get_data_consumer_its_aid.return_value = [CAM]
        request = RequestDataObjectsReq(
            CAM,
            (CAM,),
            256,
            cast(tuple, [1]),
            cast(Filter, None),
        )

        response = self.if_ldm_4.request_data_objects(request)

        self.assertEqual(response.result, RequestedDataObjectsResult.INVALID_PRIORITY)

    def test_request_data_objects_invalid_filter(self) -> None:
        self.ldm_service.get_data_consumer_its_aid.return_value = [CAM]
        bad_filter = cast(Filter, ["not", "filter"])
        request = RequestDataObjectsReq(
            CAM,
            (CAM,),
            0,
            cast(tuple, [1]),
            bad_filter,
        )

        response = self.if_ldm_4.request_data_objects(request)

        self.assertEqual(response.result, RequestedDataObjectsResult.INVALID_FILTER)

    def test_request_data_objects_invalid_order(self) -> None:
        self.ldm_service.get_data_consumer_its_aid.return_value = [CAM]
        request = RequestDataObjectsReq(
            CAM,
            (CAM,),
            0,
            cast(tuple, (1,)),
            cast(Filter, None),
        )

        response = self.if_ldm_4.request_data_objects(request)

        self.assertEqual(response.result, RequestedDataObjectsResult.INVALID_ORDER)

    def test_request_data_objects_success(self) -> None:
        self.ldm_service.get_data_consumer_its_aid.return_value = [CAM]
        self.ldm_service.query.return_value = (({"dataObject": WHITE_CAM},),)
        data_filter = Filter(
            FilterStatement("cam.camParameters.basicContainer.referencePosition.latitude", ComparisonOperators.EQUAL, 900000001),
            LogicalOperators.AND,
            None,
        )
        request = RequestDataObjectsReq(
            CAM,
            (CAM,),
            0,
            cast(tuple, [1]),
            data_filter,
        )

        response = self.if_ldm_4.request_data_objects(request)

        self.assertEqual(response.result, RequestedDataObjectsResult.SUCCEED)
        self.assertEqual(response.data_objects, ({"dataObject": WHITE_CAM},))

    def test_subscribe_data_consumer_invalid_its_aid(self) -> None:
        self.ldm_service.get_data_consumer_its_aid.return_value = []
        subscribe_req = SubscribeDataobjectsReq(
            CAM,
            (CAM,),
            cast(int, None),
            cast(Filter, None),
            cast(TimestampIts, None),
            cast(int, None),
            (OrderTupleValue(attribute="cam.generationDeltaTime", ordering_direction=OrderingDirection.ASCENDING),),
        )

        response = self.if_ldm_4.subscribe_data_consumer(subscribe_req, MagicMock())

        self.assertEqual(response.result, SubscribeDataobjectsResult.INVALID_ITSA_ID)

    def test_subscribe_data_consumer_invalid_data_object_type(self) -> None:
        self.ldm_service.get_data_consumer_its_aid.return_value = [CAM]
        subscribe_req = SubscribeDataobjectsReq(
            CAM,
            (999,),
            cast(int, None),
            cast(Filter, None),
            cast(TimestampIts, None),
            cast(int, None),
            (OrderTupleValue(attribute="generationDeltaTime", ordering_direction=OrderingDirection.ASCENDING),),
        )

        response = self.if_ldm_4.subscribe_data_consumer(subscribe_req, MagicMock())

        self.assertEqual(response.result, SubscribeDataobjectsResult.INVALID_DATA_OBJECT_TYPE)

    def test_subscribe_data_consumer_invalid_priority(self) -> None:
        self.ldm_service.get_data_consumer_its_aid.return_value = [CAM]
        subscribe_req = SubscribeDataobjectsReq(
            CAM,
            (CAM,),
            256,
            cast(Filter, None),
            cast(TimestampIts, None),
            cast(int, None),
            (OrderTupleValue(attribute="generationDeltaTime", ordering_direction=OrderingDirection.ASCENDING),),
        )

        response = self.if_ldm_4.subscribe_data_consumer(subscribe_req, MagicMock())

        self.assertEqual(response.result, SubscribeDataobjectsResult.INVALID_PRIORITY)

    def test_subscribe_data_consumer_invalid_filter(self) -> None:
        self.ldm_service.get_data_consumer_its_aid.return_value = [CAM]
        bad_filter = cast(Filter, "not a filter")
        subscribe_req = SubscribeDataobjectsReq(
            CAM,
            (CAM,),
            cast(int, None),
            bad_filter,
            cast(TimestampIts, None),
            cast(int, None),
            (OrderTupleValue(attribute="cam.generationDeltaTime", ordering_direction=OrderingDirection.ASCENDING),),
        )

        response = self.if_ldm_4.subscribe_data_consumer(subscribe_req, MagicMock())

        self.assertEqual(response.result, SubscribeDataobjectsResult.INVALID_FILTER)

    def test_subscribe_data_consumer_invalid_notify_time(self) -> None:
        self.ldm_service.get_data_consumer_its_aid.return_value = [CAM]
        subscribe_req = SubscribeDataobjectsReq(
            CAM,
            (CAM,),
            cast(int, None),
            cast(Filter, None),
            TimestampIts(4398046511104),
            cast(int, None),
            (OrderTupleValue(attribute="generationDeltaTime", ordering_direction=OrderingDirection.ASCENDING),),
        )

        response = self.if_ldm_4.subscribe_data_consumer(subscribe_req, MagicMock())

        self.assertEqual(response.result, SubscribeDataobjectsResult.INVALID_NOTIFICATION_INTERVAL)

    def test_subscribe_data_consumer_invalid_multiplicity(self) -> None:
        self.ldm_service.get_data_consumer_its_aid.return_value = [CAM]
        subscribe_req = SubscribeDataobjectsReq(
            CAM,
            (CAM,),
            cast(int, None),
            cast(Filter, None),
            cast(TimestampIts, None),
            256,
            (OrderTupleValue(attribute="generationDeltaTime", ordering_direction=OrderingDirection.ASCENDING),),
        )

        response = self.if_ldm_4.subscribe_data_consumer(subscribe_req, MagicMock())

        self.assertEqual(response.result, SubscribeDataobjectsResult.INVALID_MULTIPLICITY)

    def test_subscribe_data_consumer_success(self) -> None:
        self.ldm_service.get_data_consumer_its_aid.return_value = [CAM]
        self.ldm_service.store_new_subscription_petition.return_value = 42
        data_filter = Filter(FilterStatement("cam.camParameters.basicContainer.referencePosition.latitude", ComparisonOperators.EQUAL, 900000001), None, None)
        subscribe_req = SubscribeDataobjectsReq(
            CAM,
            (CAM,),
            cast(int, None),
            data_filter,
            TimestampIts(1000),
            1,
            (OrderTupleValue(attribute="cam.camParameters.basicContainer.referencePosition.latitude", ordering_direction=OrderingDirection.ASCENDING),),
        )

        response = self.if_ldm_4.subscribe_data_consumer(subscribe_req, MagicMock())

        self.assertEqual(response.result, SubscribeDataobjectsResult.SUCCESSFUL)
        self.assertEqual(response.subscription_id, 42)
        self.ldm_service.store_new_subscription_petition.assert_called_once()

    def test_unsubscribe_data_consumer_invalid_its_aid(self) -> None:
        self.ldm_service.get_data_consumer_its_aid.return_value = []
        request = UnsubscribeDataConsumerReq(CAM, 10)

        response = self.if_ldm_4.unsubscribe_data_consumer(request)

        self.assertEqual(response, UnsubscribeDataConsumerResp(CAM, 0, UnsubscribeDataConsumerAck.FAILED))

    def test_unsubscribe_data_consumer_delete_failure(self) -> None:
        self.ldm_service.get_data_consumer_its_aid.return_value = [CAM]
        self.ldm_service.delete_subscription.return_value = False
        request = UnsubscribeDataConsumerReq(CAM, 99)

        response = self.if_ldm_4.unsubscribe_data_consumer(request)

        self.assertEqual(
            response,
            UnsubscribeDataConsumerResp(CAM, 99, UnsubscribeDataConsumerAck.FAILED),
        )

    def test_unsubscribe_data_consumer_success(self) -> None:
        self.ldm_service.get_data_consumer_its_aid.return_value = [CAM]
        self.ldm_service.delete_subscription.return_value = True
        request = UnsubscribeDataConsumerReq(CAM, 7)

        response = self.if_ldm_4.unsubscribe_data_consumer(request)

        self.assertEqual(
            response,
            UnsubscribeDataConsumerResp(CAM, 7, UnsubscribeDataConsumerAck.ACCEPTED),
        )


if __name__ == "__main__":
    unittest.main()
