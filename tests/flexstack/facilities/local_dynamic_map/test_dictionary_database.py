import unittest
from unittest.mock import MagicMock, patch

from flexstack.facilities.local_dynamic_map.dictionary_database import (
    DictionaryDataBase,
)
from flexstack.facilities.local_dynamic_map.ldm_classes import (
    ComparisonOperators,
    Filter,
    FilterStatement,
    LogicalOperators,
)
from flexstack.facilities.local_dynamic_map.ldm_constants import CAM

database_example = {
    0: {
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
}


class TestListDataBase(unittest.TestCase):
    def setUp(self):
        self.database = DictionaryDataBase()
        self.database.database = database_example.copy()

    def test__init__(self):
        self.assertEqual(self.database.database, database_example)

    def test_delete(self):
        self.assertTrue(self.database.delete())
        self.assertDictEqual(self.database.database, {})

    @patch("builtins.print")
    def test_search_equal_operator(self, _):
        self.database.all = MagicMock(return_value=list(database_example.values()))

        filter_statement_1 = FilterStatement(
            "cam.camParameters.basicContainer.referencePosition.latitude",
            ComparisonOperators(5),
            900000001,
        )
        filter_statement_2 = FilterStatement(
            "cam.camParameters.basicContainer.referencePosition.longitude",
            ComparisonOperators(5),
            1800000001,
        )

        # Logical Operator = 0 (AND)
        test_filter = Filter(filter_statement_1, LogicalOperators(0), filter_statement_2)

        request_data_objects_req = MagicMock()
        request_data_objects_req.application_id = None
        request_data_objects_req.data_object_type = [CAM]
        request_data_objects_req.priority = None
        request_data_objects_req.order = None
        request_data_objects_req.filter = test_filter
        result = self.database.search(request_data_objects_req)
        self.assertEqual(result, list(database_example.values()))

        # Locical Operator = 1 (OR)
        test_filter = Filter(filter_statement_1, LogicalOperators(1), filter_statement_2)
        request_data_objects_req.filter = test_filter
        result = self.database.search(request_data_objects_req)
        self.assertEqual(result, list(database_example.values()))

        # Only one filter statement
        test_filter = Filter(filter_statement_1)
        request_data_objects_req.test_filter = test_filter
        result = self.database.search(request_data_objects_req)
        self.assertEqual(result, list(database_example.values()))

        # Wrong path
        filter_statement_1 = FilterStatement(
            "Pam.camParameters.basicContainer.referencePosition.latitude",
            ComparisonOperators(5),
            900000001,
        )

        test_filter = Filter(filter_statement_1)
        request_data_objects_req.filter = test_filter
        result = self.database.search(request_data_objects_req)
        self.assertEqual(result, [])

    def test_insert(self):
        self.database.database = {}
        self.assertEqual(self.database.insert(database_example[0]), 0)
        self.assertEqual(self.database.database, {0: database_example[0]})

    def test_get(self):
        self.database.database = {0: database_example[0]}
        self.assertEqual(self.database.get(0), database_example[0])
        self.assertEqual(self.database.get(1), None)

    def test_update(self):
        self.database.update(database_example.get(0), 0)
        self.assertEqual(self.database.database, database_example)

    def test_remove(self):
        self.database.remove(database_example.get(0))
        self.assertEqual(self.database.database, {})

    def test_all(self):
        self.assertEqual(self.database.all(), [database_example.get(0)])

    def test_exists(self):
        self.assertTrue(self.database.exists("dataObjectID", 0))
        self.assertTrue(self.database.exists("latitude"))
        self.assertFalse(self.database.exists("velocity"))
