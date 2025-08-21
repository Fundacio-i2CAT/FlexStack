import unittest
from unittest.mock import MagicMock, patch

from flexstack.facilities.local_dynamic_map.ldm_service import (
    LDMService,
)
from flexstack.facilities.local_dynamic_map.ldm_classes import (
    OrderTuple,
    OrderingDirection,
    RequestDataObjectsReq,
    Filter,
    ComparisonOperators,
    FilterStatement,
)
from flexstack.facilities.local_dynamic_map.ldm_constants import (
    DATA_OBJECT_FIELD_NAME,
)


TEST_DATA_CONTAINER_PATH = (
    r"tests\v2xreferencekit\facilities\local_dynamic_map\test_data_containers.json"
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
    @patch("threading.Thread")
    @patch("asn1tools.compile_string")
    def setUp(self, patch_asn1tools, patch_thread) -> None:
        subscription_service_thread = MagicMock()
        patch_thread.return_value = subscription_service_thread
        patch_asn1tools.return_value.modules = {
            "ETSI-ITS-CDD": [
                "AccelerationChange",
                "AccelerationConfidence",
                "AccelerationControl",
                "AccelerationMagnitudeValue",
                "AccelerationValue",
                "AccessTechnologyClass",
                "AccidentSubCauseCode",
                "location",
                "AdverseWeatherCondition-ExtremeWeatherConditionSubCauseCode",
                "AdverseWeatherCondition-PrecipitationSubCauseCode",
            ]
        }

        subscription_service_thread.start = MagicMock()

        ldm_maintenance = MagicMock()
        self.ldm_service = LDMService(ldm_maintenance)
        self.ldm_service.ldm_maintenance.data_containers = MagicMock(
            return_value=database_example
        )

        self.ldm_service.data_provider_its_aid = [1, 2, 3]
        self.ldm_service.data_consumer_its_aid = [1, 5, 6]

        self.callback = MagicMock()
        self.filter = Filter(None, 0, None)
        self.filter.parse_filter_statement = MagicMock(return_value="")

    @patch("flexstack.utils.time_service.TimeService.time")
    def test_attend_subscriptions_no_results(self, patch_time):
        self.ldm_service.order_search_results = MagicMock(return_value=database_example)
        patch_time.return_value = 1

        # Testing the case when there are no search results
        self.ldm_service.ldm_maintenance.data_containers.search = MagicMock(
            return_value=[]
        )

        self.ldm_service.attend_subscriptions()
        self.callback.assert_not_called()

        # Testing the case when there are search results
        self.ldm_service.ldm_maintenance.data_containers.search = MagicMock(
            return_value=database_example
        )

        self.ldm_service.attend_subscriptions()
        self.callback.assert_not_called()

    @patch("flexstack.utils.time_service.TimeService.time")
    def test_attend_subscriptions_multiplicity(self, patch_time):
        patch_time.return_value = 1
        self.ldm_service.order_search_results = MagicMock(return_value=database_example)

        # Testing the case when multiplicity is higher than the number of search results
        self.ldm_service.ldm_maintenance.search = MagicMock(
            return_value=database_example
        )

        self.ldm_service.subscriptions = [
            {
                "applicationId": 1,
                "data_object_type": [2],
                "priority": 1,
                "filter": self.filter,
                "notification_interval": 1,
                "multiplicity": 2,
                "order": 1,
                "callback": self.callback,
                "last_checked": 1,
                "doc_id": len(self.ldm_service.subscriptions),
            }
        ]
        self.ldm_service.attend_subscriptions()
        self.callback.assert_not_called()

    @patch("flexstack.utils.time_service.TimeService.time")
    def test_attend_subscriptions_order(self, patch_time):
        patch_time.return_value = 3

        # Testing the case when the order is different to empty and the order_search_function has to be called
        self.ldm_service.order_search_results = MagicMock(return_value=database_example)
        self.ldm_service.ldm_maintenance.data_containers.search = MagicMock(
            return_value=database_example
        )
        self.ldm_service.subscriptions = [
            {
                "applicationId": 1,
                "data_object_type": [2],
                "priority": 1,
                "filter": self.filter,
                "notification_interval": 1,
                "multiplicity": 1,
                "order": [1, 2],
                "callback": self.callback,
                "last_checked": 1,
                "doc_id": len(self.ldm_service.subscriptions),
            }
        ]
        self.ldm_service.attend_subscriptions()
        self.callback.assert_called()
        self.ldm_service.order_search_results.assert_called()

    @patch("flexstack.utils.time_service.TimeService.time")
    def test_attend_subscriptions_notification_interval_invalid(
        self, patch_time: MagicMock
    ):
        # Testing the case when the notification interval is still valid and hence the callback is not called
        patch_time.return_value = 1
        self.ldm_service.order_search_results = MagicMock(return_value=database_example)

        self.ldm_service.ldm_maintenance.data_containers.search = MagicMock(
            return_value=database_example
        )

        self.ldm_service.subscriptions = [
            {
                "applicationId": 1,
                "data_object_type": [2],
                "priority": 1,
                "filter": self.filter,
                "notification_interval": 1,
                "multiplicity": 1,
                "order": None,
                "callback": self.callback,
                "last_checked": 1,
                "doc_id": len(self.ldm_service.subscriptions),
            }
        ]
        self.ldm_service.attend_subscriptions()
        self.callback.assert_not_called()
        patch_time.assert_called()

    @patch("flexstack.utils.time_service.TimeService.time")
    def test_attend_subscriptions_notification_interval_valid(
        self, patch_time: MagicMock
    ):
        # Testing the case when the notification interval is not valid and hence the callback is called
        patch_time.return_value = 3
        self.ldm_service.order_search_results = MagicMock(return_value=database_example)

        self.ldm_service.ldm_maintenance.data_containers.search = MagicMock(
            return_value=database_example
        )
        self.ldm_service.subscriptions = [
            {
                "applicationId": 1,
                "data_object_type": [2],
                "priority": 1,
                "filter": self.filter,
                "notification_interval": 1,
                "multiplicity": 1,
                "order": [],
                "callback": self.callback,
                "last_checked": 1,
                "doc_id": len(self.ldm_service.subscriptions),
            }
        ]
        self.ldm_service.attend_subscriptions()
        self.callback.assert_called()
        patch_time.assert_called()

    @patch("flexstack.utils.time_service.TimeService.time")
    def test_attend_subscriptions_subscription(self, patch_time):
        patch_time.return_value = 3
        self.ldm_service.order_search_results = MagicMock(return_value=database_example)

        # Testing the case when applicationId is no longer in self.data_provider_its_aid is is removed from self.subscriptions
        self.ldm_service.ldm_maintenance.data_containers.search = MagicMock(
            return_value=database_example
        )
        self.ldm_service.subscriptions = [
            {
                "applicationId": 123,
                "data_object_type": [2],
                "priority": 1,
                "filter": self.filter,
                "notification_interval": 1,
                "multiplicity": 1,
                "order": [],
                "callback": self.callback,
                "last_checked": 1,
                "doc_id": len(self.ldm_service.subscriptions),
            }
        ]

        self.ldm_service.pop_subscription = MagicMock()

        self.ldm_service.attend_subscriptions()

        self.ldm_service.pop_subscription.assert_called()

    def test_static_method_find_key_path(self):
        self.assertEqual(
            ["cam.camParameters.basicContainer.referencePosition.latitude"],
            self.ldm_service.find_key_paths_in_list("latitude", [white_cam]),
        )

    @patch("builtins.sorted")
    def test_order_search_results(self, mock_sorted):
        class DotDict:
            def __init__(self, dictionary):
                self.__dict__.update(dictionary)

            def __getitem__(self, key):
                return self.__dict__[key]

        dict_1 = [
            {"applicationId": 1, "location": 1, "doc_id": 1},
            {"applicationId": 1, "location": 0, "doc_id": 2},
            {"applicationId": 3, "location": 3, "doc_id": 3},
        ]
        dictionary = [DotDict(dict) for dict in dict_1]
        self.ldm_service.ldm_maintenance.data_containers.search = MagicMock(
            return_value=dictionary
        )
        self.ldm_service.find_key_path = MagicMock(return_value="applicationId")
        create_query_from_filter_statement = MagicMock()
        create_query_from_filter_statement.return_value.exists = MagicMock(
            return_value=True
        )
        self.ldm_service.create_query_from_filter_statement = (
            create_query_from_filter_statement
        )

        sorted_dict = [[dict_1[1], dict_1[0], dict_1[2]]]
        mock_sorted.return_value = [(1, 0), (0, 1), (2, 3)]
        result = self.ldm_service.order_search_results(
            dict_1, [OrderTuple(7, OrderingDirection(1))]
        )
        self.assertEqual(sorted_dict, result)

        sorted_dict = [[dict_1[2], dict_1[0], dict_1[1]]]
        mock_sorted.return_value = [(2, 3), (0, 1), (1, 0)]
        result = self.ldm_service.order_search_results(
            dict_1, [OrderTuple(7, OrderingDirection(0))]
        )
        self.assertEqual(sorted_dict, result)

    @patch("builtins.list")
    def test_pop_subscription(self, mock_builtin_list):
        self.ldm_service.subscriptions = [
            {
                "applicationId": 1,
                "data_object_type": [2],
                "priority": 1,
                "filter": self.filter,
                "notification_interval": 1,
                "multiplicity": 1,
                "order": [],
                "callback": self.callback,
                "last_checked": 1,
                "doc_id": 0,
            },
            {
                "applicationId": 1,
                "data_object_type": [2],
                "priority": 1,
                "filter": self.filter,
                "notification_interval": 1,
                "multiplicity": 1,
                "order": [],
                "callback": self.callback,
                "last_checked": 1,
                "doc_id": 1,
            },
        ]

        self.assertRaises(IndexError, self.ldm_service.pop_subscription, -1)

        mock_builtin_list.pop = MagicMock(
            return_value=self.ldm_service.subscriptions[0]
        )
        self.ldm_service.pop_subscription(1)
        return_value = {
            "applicationId": 1,
            "data_object_type": [2],
            "priority": 1,
            "filter": self.filter,
            "notification_interval": 1,
            "multiplicity": 1,
            "order": [],
            "callback": self.callback,
            "last_checked": 1,
            "doc_id": 0,
        }

        self.assertEqual(return_value, self.ldm_service.subscriptions[0])

    def test_add_provider_data(self):
        self.ldm_service.ldm_maintenance.add_provider_data = MagicMock()
        self.ldm_service.add_provider_data(white_cam)
        assert self.ldm_service.ldm_maintenance.add_provider_data.called

    def test_add_data_provider_its_aid(self):
        self.ldm_service.add_data_provider_its_aid(1)
        self.assertIn(1, self.ldm_service.data_provider_its_aid)

    def test_update_provider_data(self):
        self.ldm_service.ldm_maintenance.update_provider_data = MagicMock()
        self.ldm_service.update_provider_data(1, white_cam)
        assert self.ldm_service.ldm_maintenance.update_provider_data.called

    def test_get_data_provider_its_aid(self):
        self.ldm_service.data_provider_its_aid = [1, 2, 3]
        self.assertEqual([1, 2, 3], self.ldm_service.get_data_provider_its_aid())

    def test_get_provider_data(self):
        self.ldm_service.ldm_maintenance.data_containers = white_cam
        self.assertEqual(white_cam, self.ldm_service.get_provider_data())

    def test_del_provider_data(self):
        self.ldm_service.del_provider_data(1)
        self.assertNotIn(1, self.ldm_service.data_provider_its_aid)

    def test_del_data_provider_its_aid(self):
        self.ldm_service.del_data_provider_its_aid(1)
        self.assertNotIn(1, self.ldm_service.data_provider_its_aid)

    @patch("builtins.print")
    def test_query(self, mock_print):
        self.ldm_service.ldm_maintenance.get_all_data_containers = MagicMock()
        self.ldm_service.ldm_maintenance.get_all_data_containers.return_value = (
            database_example
        )
        self.ldm_service.ldm_maintenance.search_data_containers = MagicMock()
        self.ldm_service.ldm_maintenance.search_data_containers.return_value = (
            database_example
        )
        self.ldm_service.order_search_results = MagicMock()
        self.ldm_service.order_search_results.return_value = database_example
        # Se hace un datarequest
        filter_statement_1 = FilterStatement(
            "dataObject.cam.camParameters.basicContainer.referencePosition.latitude",
            ComparisonOperators(5),
            900000001,
        )
        filter_statement_2 = FilterStatement(
            "dataObject.cam.camParameters.basicContainer.referencePosition.longitude",
            ComparisonOperators(5),
            1800000001,
        )
        # Se hace un query
        test_filter = Filter(filter_statement_1, 0, filter_statement_2)
        data_request = RequestDataObjectsReq(
            application_id=35,
            data_object_type=2,
            priority=1,
            order=None,
            filter=test_filter,
        )

        self.assertEqual(
            white_cam, self.ldm_service.query(data_request)[0][0][DATA_OBJECT_FIELD_NAME]
        )

        test_filter = Filter(filter_statement_1, 0, None)
        data_request_1_filter = RequestDataObjectsReq(
            application_id=35,
            data_object_type=2,
            priority=1,
            order=None,
            filter=test_filter,
        )
        self.assertEqual(
            white_cam,
            self.ldm_service.query(data_request_1_filter)[0][0][DATA_OBJECT_FIELD_NAME],
        )

        data_request_1_filter = RequestDataObjectsReq(
            application_id=35,
            data_object_type=2,
            priority=1,
            order=None,
            filter=None,
        )
        self.assertEqual(
            white_cam,
            self.ldm_service.query(data_request_1_filter)[0][0][DATA_OBJECT_FIELD_NAME],
        )

        test_filter = Filter(filter_statement_1, 0, None)
        data_request_1_filter = RequestDataObjectsReq(
            application_id=35,
            data_object_type=2,
            priority=1,
            order=[OrderTuple(7, OrderingDirection(1))],
            filter=test_filter,
        )
        self.assertEqual(
            database_example,
            self.ldm_service.query(data_request_1_filter),
        )

        self.ldm_service.ldm_maintenance.search_data_containers = MagicMock(
            side_effect=KeyError
        )
        test_filter = Filter(filter_statement_1, 0, None)
        data_request_1_filter = RequestDataObjectsReq(
            application_id=35,
            data_object_type=2,
            priority=1,
            order=None,
            filter=test_filter,
        )
        self.assertEqual(
            [[]],
            self.ldm_service.query(data_request_1_filter),
        )

    def test_get_object_type_from_data_object(self):
        self.assertEqual(
            2, self.ldm_service.get_object_type_from_data_object(white_cam)
        )

        self.assertEqual(None, self.ldm_service.get_object_type_from_data_object({}))

    @patch("flexstack.utils.time_service.TimeService.time")
    def test_store_new_subscription_petition(self, patch_time):
        self.ldm_service.subscriptions = []
        patch_time.return_value = 1

        subscription_petition = {
            "applicationId": 1,
            "data_object_type": [2],
            "priority": 1,
            "filter": self.filter,
            "notification_interval": 1,
            "multiplicity": 1,
            "order": [],
            "callback": self.callback,
            "last_checked": 1,
            "doc_id": len(self.ldm_service.subscriptions),
        }
        self.ldm_service.store_new_subscription_petition(
            application_id=subscription_petition["applicationId"],
            data_object_type=subscription_petition["data_object_type"],
            priority=subscription_petition["priority"],
            filter=subscription_petition["filter"],
            notification_interval=subscription_petition["notification_interval"],
            multiplicity=subscription_petition["multiplicity"],
            order=subscription_petition["order"],
            callback=subscription_petition["callback"],
        )
        self.assertEqual(self.ldm_service.subscriptions, [subscription_petition])

    def test_add_data_consumer_its_aid(self):
        self.ldm_service.data_consumer_its_aid = []
        self.ldm_service.add_data_consumer_its_aid(1)
        self.assertIn(1, self.ldm_service.data_consumer_its_aid)

    def test_get_data_consumer_its_aid(self):
        self.ldm_service.data_consumer_its_aid = [1, 2, 3]
        self.assertEqual([1, 2, 3], self.ldm_service.get_data_consumer_its_aid())

    def test_del_data_consumer_its_aid(self):
        self.ldm_service.data_consumer_its_aid = [1]
        self.ldm_service.del_data_consumer_its_aid(1)
        self.assertNotIn(1, self.ldm_service.data_consumer_its_aid)

    def test_get_data_consumer_subscriptions(self):
        self.ldm_service.subscriptions = [
            {
                "applicationId": 1,
                "data_object_type": [2],
                "priority": 1,
                "filter": self.filter,
                "notification_interval": 1,
                "multiplicity": 1,
                "order": [],
                "callback": self.callback,
                "last_checked": 1,
                "doc_id": len(self.ldm_service.subscriptions),
            }
        ]
        self.assertEqual(
            self.ldm_service.get_data_consumer_subscriptions(),
            self.ldm_service.subscriptions,
        )

    @patch("builtins.list")
    def test_delete_subscription(self, mock_builtin_list):
        self.ldm_service.subscriptions = [
            {
                "applicationId": 1,
                "data_object_type": [2],
                "priority": 1,
                "filter": self.filter,
                "notification_interval": 1,
                "multiplicity": 1,
                "order": [],
                "callback": self.callback,
                "last_checked": 1,
                "doc_id": len(self.ldm_service.subscriptions),
            }
        ]
        mock_builtin_list.pop = MagicMock(return_value=self.ldm_service.subscriptions)
        self.assertTrue(self.ldm_service.delete_subscription(0))

        mock_builtin_list.pop = MagicMock(side_effect=IndexError)
        self.assertFalse(self.ldm_service.delete_subscription(0))
