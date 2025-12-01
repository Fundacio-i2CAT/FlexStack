import unittest
from typing import Optional, Tuple
from unittest.mock import MagicMock, patch

from flexstack.facilities.local_dynamic_map.ldm_service import (
    LDMService,
)
from flexstack.facilities.local_dynamic_map.ldm_classes import (
    AddDataProviderReq,
    Location,
    LogicalOperators,
    OrderTupleValue,
    OrderingDirection,
    RequestDataObjectsReq,
    Filter,
    ComparisonOperators,
    FilterStatement,
    TimeValidity,
    TimestampIts,
    SubscribeDataobjectsReq,
    SubscriptionInfo,
)
from flexstack.facilities.local_dynamic_map.ldm_constants import (
    CAM,
    DATA_OBJECT_FIELD_NAME,
)


database_example = [
    {
        "applicationId": 36,
        "timeStamp": -452001707.8018279,
        "location": {
            "referencePosition": {
                "latitude": 407143528,
                "longitude": -740059731,
                "positionConfidenceEllipse": {
                    "semiMajorConfidence": 5,
                    "semiMinorConfidence": 5,
                    "semiMajorOrientation": 5,
                },
                "altitude": {"altitudeValue": 1000, "altitudeConfidence": 0},
            },
            "referenceArea": {
                "geometricArea": {
                    "circle": {"radius": 2},
                    "rectangle": None,
                    "ellipse": None,
                },
                "relevanceArea": {
                    "relevanceDistance": 0,
                    "relevaneTrafficDirection": 0,
                },
            },
        },
        "dataObject": {
            "header": {"protocolVersion": 2, "messageID": 2, "stationID": 0},
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
                                "semiMajorOrientation": 3601,
                            },
                            "altitude": {
                                "altitudeValue": 800001,
                                "altitudeConfidence": "unavailable",
                            },
                        },
                    },
                    "highFrequencyContainer": [
                        "basicVehicleContainerHighFrequency",
                        {
                            "heading": {"headingValue": 3601, "headingConfidence": 127},
                            "speed": {"speedValue": 16383, "speedConfidence": 127},
                            "driveDirection": "unavailable",
                            "vehicleLength": {
                                "vehicleLengthValue": 1023,
                                "vehicleLengthConfidenceIndication": "unavailable",
                            },
                            "vehicleWidth": 62,
                            "longitudinalAcceleration": {
                                "longitudinalAccelerationValue": 161,
                                "longitudinalAccelerationConfidence": 102,
                            },
                            "curvature": {
                                "curvatureValue": 1023,
                                "curvatureConfidence": "unavailable",
                            },
                            "curvatureCalculationMode": "unavailable",
                            "yawRate": {
                                "yawRateValue": 32767,
                                "yawRateConfidence": "unavailable",
                            },
                        },
                    ],
                },
            },
        },
        "timeValidity": 1000,
    }
]


white_cam = {
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
                        "semiMajorOrientation": 3601,
                    },
                    "altitude": {
                        "altitudeValue": 800001,
                        "altitudeConfidence": "unavailable",
                    },
                },
            },
            "highFrequencyContainer": [
                "basicVehicleContainerHighFrequency",
                {
                    "heading": {"headingValue": 3601, "headingConfidence": 127},
                    "speed": {"speedValue": 16383, "speedConfidence": 127},
                    "driveDirection": "unavailable",
                    "vehicleLength": {
                        "vehicleLengthValue": 1023,
                        "vehicleLengthConfidenceIndication": "unavailable",
                    },
                    "vehicleWidth": 62,
                    "longitudinalAcceleration": {
                        "longitudinalAccelerationValue": 161,
                        "longitudinalAccelerationConfidence": 102,
                    },
                    "curvature": {
                        "curvatureValue": 1023,
                        "curvatureConfidence": "unavailable",
                    },
                    "curvatureCalculationMode": "unavailable",
                    "yawRate": {
                        "yawRateValue": 32767,
                        "yawRateConfidence": "unavailable",
                    },
                },
            ],
        },
    },
}


class Test_ldm_service(unittest.TestCase):
    def setUp(self) -> None:
        self.ldm_maintenance = MagicMock()
        self.ldm_service = LDMService(self.ldm_maintenance)

        self.search_result = tuple(database_example)
        self.ldm_service.ldm_maintenance.data_containers.search = MagicMock(
            return_value=self.search_result
        )
        self.ldm_service.ldm_maintenance.get_all_data_containers = MagicMock(
            return_value=self.search_result
        )
        self.ldm_service.ldm_maintenance.search_data_containers = MagicMock(
            return_value=self.search_result
        )

        self.ldm_service.data_provider_its_aid = {1, 2, 3}
        self.ldm_service.data_consumer_its_aid = {1, 5, 6}

        self.callback = MagicMock()
        self.filter = Filter(
            FilterStatement(
                "dataObject.cam.generationDeltaTime",
                ComparisonOperators.GREATER_THAN,
                1,
            ),
            None,
            None,
        )
        self.order_tuple = (
            OrderTupleValue("dataObject.cam.generationDeltaTime", OrderingDirection.ASCENDING),
        )

    @staticmethod
    def _timestamp_delta(seconds: int) -> TimestampIts:
        return TimestampIts(seconds * 1000)

    def _make_subscription_request(
        self,
        *,
        application_id: int = 1,
        multiplicity: int = 1,
        notify_seconds: Optional[int] = 0,
        notify_time: Optional[TimestampIts] = None,
        order: Optional[Tuple[OrderTupleValue, ...]] = None,
        filter_obj: Optional[Filter] = None,
    ) -> SubscribeDataobjectsReq:
        return SubscribeDataobjectsReq(
            application_id=application_id,
            data_object_type=(CAM,),
            priority=1,
            filter=filter_obj if filter_obj is not None else self.filter,
            notify_time=notify_time
            if notify_time is not None
            else self._timestamp_delta(notify_seconds or 0),
            multiplicity=multiplicity,
            order=order if order is not None else self.order_tuple,
        )

    def _make_subscription(self, **kwargs) -> SubscriptionInfo:
        request = self._make_subscription_request(**kwargs)
        return SubscriptionInfo(subscription_request=request, callback=self.callback)

    def _set_subscription_state(
        self, subscription: SubscriptionInfo, last_checked: Optional[TimestampIts] = None
    ) -> None:
        self.ldm_service.subscriptions = [subscription]
        self.ldm_service.last_checked_subscriptions_time.clear()
        self.ldm_service.last_checked_subscriptions_time[subscription] = (
            last_checked if last_checked is not None else TimestampIts(0)
        )

    @patch("flexstack.utils.time_service.TimeService.time")
    def test_attend_subscriptions_no_results(self, patch_time):
        patch_time.return_value = 1
        subscription = self._make_subscription(notify_seconds=0)
        self._set_subscription_state(subscription, TimestampIts(0))
        self.callback.reset_mock()
        self.ldm_service.ldm_maintenance.data_containers.search = MagicMock(
            return_value=()
        )
        self.ldm_service.attend_subscriptions()
        self.callback.assert_not_called()

        self.callback.reset_mock()
        subscription = self._make_subscription(multiplicity=2, notify_seconds=0)
        self._set_subscription_state(subscription, TimestampIts(0))
        self.ldm_service.ldm_maintenance.data_containers.search = MagicMock(
            return_value=self.search_result
        )
        self.ldm_service.attend_subscriptions()
        self.callback.assert_not_called()

    @patch("flexstack.utils.time_service.TimeService.time")
    def test_attend_subscriptions_multiplicity(self, patch_time):
        patch_time.return_value = 1
        subscription = self._make_subscription(multiplicity=2)
        self._set_subscription_state(subscription, TimestampIts(0))
        self.callback.reset_mock()
        self.ldm_service.attend_subscriptions()
        self.callback.assert_not_called()

    @patch("flexstack.utils.time_service.TimeService.time")
    def test_attend_subscriptions_order(self, patch_time):
        patch_time.return_value = 3
        subscription = self._make_subscription()
        current_time = TimestampIts.initialize_with_utc_timestamp_seconds()
        past_time = TimestampIts(current_time.timestamp_its - 2000)
        self._set_subscription_state(subscription, past_time)
        ordered_result = (self.search_result,)
        self.ldm_service.order_search_results = MagicMock(return_value=ordered_result)
        self.callback.reset_mock()
        self.ldm_service.attend_subscriptions()
        self.callback.assert_called_once()
        self.ldm_service.order_search_results.assert_called_once_with(
            self.search_result, subscription.subscription_request.order
        )

    @patch("flexstack.utils.time_service.TimeService.time")
    def test_attend_subscriptions_notification_interval_invalid(
        self, patch_time: MagicMock
    ):
        patch_time.return_value = 1
        notify_time = self._timestamp_delta(10)
        subscription = self._make_subscription(notify_time=notify_time)
        current_time = TimestampIts.initialize_with_utc_timestamp_seconds()
        self._set_subscription_state(subscription, current_time)
        self.callback.reset_mock()
        self.ldm_service.attend_subscriptions()
        self.callback.assert_not_called()

    @patch("flexstack.utils.time_service.TimeService.time")
    def test_attend_subscriptions_notification_interval_valid(
        self, patch_time: MagicMock
    ):
        patch_time.return_value = 3
        notify_time = self._timestamp_delta(1)
        subscription = self._make_subscription(notify_time=notify_time)
        current_time = TimestampIts.initialize_with_utc_timestamp_seconds()
        past_time = TimestampIts(current_time.timestamp_its - 2000)
        self._set_subscription_state(subscription, past_time)
        self.callback.reset_mock()
        self.ldm_service.attend_subscriptions()
        self.callback.assert_called_once()

    @patch("flexstack.utils.time_service.TimeService.time")
    def test_attend_subscriptions_subscription(self, patch_time):
        patch_time.return_value = 3
        subscription = self._make_subscription(application_id=123)
        self._set_subscription_state(subscription, TimestampIts(0))
        self.ldm_service.data_consumer_its_aid = {1}
        self.ldm_service.remove_subscription = MagicMock()
        self.ldm_service.attend_subscriptions()
        self.ldm_service.remove_subscription.assert_called_once_with(subscription)

    def test_static_method_find_key_path(self):
        self.assertEqual(
            ["cam.camParameters.basicContainer.referencePosition.latitude"],
            self.ldm_service.find_key_paths_in_list("latitude", [white_cam]),
        )

    @patch("builtins.sorted")
    def test_order_search_results(self, mock_sorted):
        dict_1 = (
            {"applicationId": 1, "location": 1, "doc_id": 1},
            {"applicationId": 1, "location": 0, "doc_id": 2},
            {"applicationId": 3, "location": 3, "doc_id": 3},
        )
        mock_sorted.return_value = [dict_1[1], dict_1[0], dict_1[2]]

        result = self.ldm_service.order_search_results(
            dict_1, (OrderTupleValue("applicationId", OrderingDirection.DESCENDING),)
        )
        self.assertEqual(((dict_1[1], dict_1[0], dict_1[2]),), result)

        mock_sorted.return_value = [dict_1[2], dict_1[0], dict_1[1]]
        result = self.ldm_service.order_search_results(
            dict_1, (OrderTupleValue("applicationId", OrderingDirection.ASCENDING),)
        )
        self.assertEqual(((dict_1[2], dict_1[0], dict_1[1]),), result)

    def test_pop_subscription(self):
        subscription = self._make_subscription()
        self._set_subscription_state(subscription, TimestampIts(0))
        self.ldm_service.remove_subscription(subscription)
        self.assertNotIn(subscription, self.ldm_service.subscriptions)
        self.assertNotIn(
            subscription, self.ldm_service.last_checked_subscriptions_time
        )

        # Removing a non-existing subscription should be a no-op
        self.ldm_service.remove_subscription(subscription)

    def test_add_provider_data(self):
        self.ldm_service.ldm_maintenance.add_provider_data = MagicMock()
        add_data_request = AddDataProviderReq(
            application_id=1,
            timestamp=TimestampIts(5000),
            location=Location.initializer(),
            data_object=white_cam,
            time_validity=TimeValidity(5000),
        )
        self.ldm_service.add_provider_data(add_data_request)
        self.ldm_service.ldm_maintenance.add_provider_data.assert_called_with(
            add_data_request
        )

    def test_add_data_provider_its_aid(self):
        self.ldm_service.data_provider_its_aid = set()
        self.ldm_service.add_data_provider_its_aid(1)
        self.assertIn(1, self.ldm_service.data_provider_its_aid)

    def test_update_provider_data(self):
        self.ldm_service.ldm_maintenance.update_provider_data = MagicMock()
        self.ldm_service.update_provider_data(1, white_cam)
        self.ldm_service.ldm_maintenance.update_provider_data.assert_called_with(
            1, white_cam
        )

    def test_get_data_provider_its_aid(self):
        self.ldm_service.data_provider_its_aid = {1, 2, 3}
        self.assertEqual({1, 2, 3}, self.ldm_service.get_data_provider_its_aid())

    def test_del_provider_data(self):
        self.ldm_service.data_provider_its_aid = {1}
        self.ldm_service.del_provider_data(1)
        self.assertNotIn(1, self.ldm_service.data_provider_its_aid)

    def test_del_data_provider_its_aid(self):
        self.ldm_service.data_provider_its_aid = {1}
        self.ldm_service.del_data_provider_its_aid(1)
        self.assertNotIn(1, self.ldm_service.data_provider_its_aid)

    @patch("builtins.print")
    def test_query(self, mock_print):
        ordered_result = ([database_example[0]],)
        self.ldm_service.ldm_maintenance.get_all_data_containers = MagicMock(
            return_value=self.search_result
        )
        self.ldm_service.ldm_maintenance.search_data_containers = MagicMock(
            return_value=self.search_result
        )
        self.ldm_service.order_search_results = MagicMock(return_value=ordered_result)

        filter_statement_1 = FilterStatement(
            "dataObject.cam.camParameters.basicContainer.referencePosition.latitude",
            ComparisonOperators.LESS_THAN_OR_EQUAL,
            900000001,
        )
        filter_statement_2 = FilterStatement(
            "dataObject.cam.camParameters.basicContainer.referencePosition.longitude",
            ComparisonOperators.LESS_THAN_OR_EQUAL,
            1800000001,
        )
        test_filter = Filter(filter_statement_1, LogicalOperators.AND, filter_statement_2)
        data_request = RequestDataObjectsReq(
            application_id=35,
            data_object_type=(CAM,),
            priority=1,
            order=(
                OrderTupleValue(
                    "dataObject.cam.generationDeltaTime",
                    OrderingDirection.ASCENDING,
                ),
            ),
            filter=test_filter,
        )
        result = self.ldm_service.query(data_request)
        self.assertEqual(white_cam, result[0][0][DATA_OBJECT_FIELD_NAME])

        test_filter_single = Filter(filter_statement_1, None, None)
        data_request_single = RequestDataObjectsReq(
            application_id=35,
            data_object_type=(CAM,),
            priority=1,
            order=(
                OrderTupleValue(
                    "dataObject.cam.generationDeltaTime",
                    OrderingDirection.ASCENDING,
                ),
            ),
            filter=test_filter_single,
        )
        result = self.ldm_service.query(data_request_single)
        self.assertEqual(white_cam, result[0][0][DATA_OBJECT_FIELD_NAME])

        self.ldm_service.ldm_maintenance.search_data_containers = MagicMock(
            side_effect=KeyError
        )
        result = self.ldm_service.query(data_request_single)
        self.assertEqual((), result)
        mock_print.assert_called()

    def test_get_object_type_from_data_object(self):
        self.assertEqual(
            "cam", self.ldm_service.get_object_type_from_data_object(white_cam)
        )
        self.assertEqual(
            "", self.ldm_service.get_object_type_from_data_object({})
        )

    @patch("flexstack.utils.time_service.TimeService.time")
    def test_store_new_subscription_petition(self, patch_time):
        self.ldm_service.subscriptions = []
        patch_time.return_value = 1

        subscription_request = self._make_subscription_request()
        subscription_id = self.ldm_service.store_new_subscription_petition(
            subscription_request=subscription_request,
            callback=self.callback,
        )
        self.assertIsInstance(subscription_id, int)
        self.assertEqual(1, len(self.ldm_service.subscriptions))
        stored_subscription = self.ldm_service.subscriptions[0]
        self.assertEqual(
            subscription_request, stored_subscription.subscription_request
        )
        self.assertEqual(self.callback, stored_subscription.callback)
        self.assertIn(
            stored_subscription, self.ldm_service.last_checked_subscriptions_time
        )

    def test_add_data_consumer_its_aid(self):
        self.ldm_service.data_consumer_its_aid = set()
        self.ldm_service.add_data_consumer_its_aid(1)
        self.assertIn(1, self.ldm_service.data_consumer_its_aid)

    def test_get_data_consumer_its_aid(self):
        self.ldm_service.data_consumer_its_aid = {1, 2, 3}
        self.assertEqual({1, 2, 3}, self.ldm_service.get_data_consumer_its_aid())

    def test_del_data_consumer_its_aid(self):
        self.ldm_service.data_consumer_its_aid = {1}
        self.ldm_service.del_data_consumer_its_aid(1)
        self.assertNotIn(1, self.ldm_service.data_consumer_its_aid)

    def test_get_data_consumer_subscriptions(self):
        subscription = self._make_subscription()
        self.ldm_service.subscriptions = [subscription]
        self.assertEqual([subscription], self.ldm_service.subscriptions)

    def test_delete_subscription(self):
        subscription = self._make_subscription()
        self._set_subscription_state(subscription, TimestampIts(0))
        subscription_id = hash(subscription.subscription_request)
        self.assertTrue(self.ldm_service.delete_subscription(subscription_id))
        self.assertFalse(self.ldm_service.subscriptions)
        self.assertFalse(self.ldm_service.last_checked_subscriptions_time)
        self.assertFalse(self.ldm_service.delete_subscription(subscription_id))
