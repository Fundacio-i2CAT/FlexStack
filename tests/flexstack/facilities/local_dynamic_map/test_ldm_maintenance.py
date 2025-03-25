import json
import unittest
from unittest.mock import MagicMock, patch
import time

from flexstack.facilities.local_dynamic_map.ldm_maintenance import (
    LDMMaintenance,
)
from flexstack.facilities.local_dynamic_map.ldm_classes import (
    AddDataProviderReq,
    Location,
    Latitude,
    Longitude,
    ReferencePosition,
    ReferenceArea,
    GeometricArea,
    RelevanceArea,
    Circle,
    RelevanceDistance,
    RelevanceTrafficDirection,
    PositionConfidenceEllipse,
    Altitude,
    TimeValidity,
    TimestampIts,
)
from flexstack.facilities.local_dynamic_map.ldm_constants import (
    NEW_DATA_RECIEVED,
    NO_NEW_DATA_RECIEVED,
)

list_database_example = [
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


database_example = {
    "_default": {
        "1": {
            "applicationId": 36,
            "timeStamp": -452001707.8018279,
            "location": {
                "referencePostion": {
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
                                "heading": {
                                    "headingValue": 3601,
                                    "headingConfidence": 127,
                                },
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
}


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


class Test_ldm_maintenance(unittest.TestCase):
    @patch("threading.Lock")
    def setUp(self, patch_threading_lock) -> None:
        self.mock_threading_lock = MagicMock()
        self.mock_threading_lock.acquire = MagicMock(return_value=True)
        self.mock_threading_lock.release = MagicMock(return_value=True)
        self.mock_threading_lock.locked = MagicMock(return_value=False)
        patch_threading_lock.return_value = self.mock_threading_lock

        self.area_of_maintenance = MagicMock()

        self.stop_event = MagicMock()
        self.stop_event.is_set = MagicMock(return_value=False)
        self.database = MagicMock()

        self.ldm_maintenance = LDMMaintenance(self.area_of_maintenance, self.database)

        timestampits = TimestampIts().insert_unix_timestamp(time.time())
        latitude = Latitude.convert_latitude_to_its_latitude(40.7143528)
        longitude = Longitude.convert_longitude_to_its_longitude(-74.0059731)
        reference_position = ReferencePosition(
            latitude,
            longitude,
            PositionConfidenceEllipse(5, 5, 0),
            Altitude(10 * 100, 0),
        )
        referance_area = ReferenceArea(
            GeometricArea(Circle(radius=2), None, None),
            RelevanceArea(
                RelevanceDistance(relevance_distance=0),
                RelevanceTrafficDirection(relevance_traffic_direction=0),
            ),
        )
        location = Location(reference_position, referance_area)

        self.data = AddDataProviderReq(
            36, timestampits, location, white_cam, TimeValidity(1000)
        )

        self.area_of_maintenance = Location(reference_position, referance_area)

    def test_delete_all_database(self):
        self.database.delete = MagicMock()
        self.ldm_maintenance.delete_all_database()
        assert self.database.delete.called

    @patch("builtins.print")
    def test_add_provider_data(self, mock_print):
        self.database.insert = MagicMock()
        self.ldm_maintenance.add_provider_data(self.data)
        self.database.insert.assert_called_once()

        self.database.insert = MagicMock(side_effect=KeyError)
        self.ldm_maintenance.add_provider_data(self.data)
        doc_id = self.database.insert.assert_called_once()
        self.assertIsNone(doc_id)
        mock_print.assert_called_once()

    @patch("builtins.print")
    def test_get_provider_data(self, mock_print):
        self.database.get = MagicMock()
        self.ldm_maintenance.get_provider_data(self.data)
        assert self.database.get.called

        self.database.get = MagicMock(side_effect=KeyError)
        self.ldm_maintenance.get_provider_data(self.data)
        provider_data = self.database.get.assert_called_once()
        self.assertIsNone(provider_data)
        mock_print.assert_called_once()

    @patch("builtins.print")
    def test_update_provider_data(self, mock_print):
        self.database.update = MagicMock()
        data_object_id = 1
        self.ldm_maintenance.update_provider_data(data_object_id, self.data)
        assert self.database.update.called

        self.database.update = MagicMock(side_effect=KeyError)
        self.ldm_maintenance.update_provider_data(data_object_id, self.data)
        self.database.update.assert_called_once()
        mock_print.assert_called_once()

    @patch("builtins.print")
    def test_del_provider_data(self, mock_print):
        self.database.remove = MagicMock()
        doc_id = self.ldm_maintenance.add_provider_data(self.data)
        self.ldm_maintenance.del_provider_data(doc_id)
        assert self.database.remove.called

        self.database.remove = MagicMock(side_effect=KeyError)
        self.ldm_maintenance.del_provider_data(self.data)
        self.database.remove.assert_called_once()
        mock_print.assert_called_once()

    @patch("builtins.print")
    def test_get_all_data_containers(self, mock_print):
        self.database.all = MagicMock(return_value=database_example)
        all_data_containers = self.ldm_maintenance.get_all_data_containers()
        self.assertEqual(all_data_containers, database_example)

        self.database.all = MagicMock(side_effect=KeyError)
        all_data_containers = self.ldm_maintenance.get_all_data_containers()
        self.assertEqual(all_data_containers, [])

    def test_search_data_containers(self):
        self.database.search = MagicMock(return_value=[1])
        filter = MagicMock()
        search_result = self.ldm_maintenance.search_data_containers(filter)
        assert self.database.search.called
        self.assertEqual(search_result, [1])

    @patch(
        "flexstack.facilities.local_dynamic_map.ldm_classes.TimestampIts.insert_unix_timestamp"
    )
    @patch("time.time")
    @patch("builtins.print")
    def test_check_and_delete_time_validity(
        self, mock_print, mock_time, mock_timestampits
    ):
        mock_time.return_value = 1000
        mock_timestampits.return_value = 3000

        self.ldm_maintenance.get_all_data_containers = MagicMock(
            return_value=list_database_example
        )
        self.ldm_maintenance.del_provider_data = MagicMock()
        time_invalidity_data_containers = (
            self.ldm_maintenance.check_and_delete_time_validity()
        )
        self.ldm_maintenance.del_provider_data.assert_called()
        self.assertEqual(time_invalidity_data_containers, list_database_example)

        mock_timestampits.return_value = -452011700.8018279
        self.ldm_maintenance.del_provider_data = MagicMock()
        time_invalidity_data_containers = (
            self.ldm_maintenance.check_and_delete_time_validity()
        )
        self.ldm_maintenance.del_provider_data.assert_not_called()
        self.assertEqual(time_invalidity_data_containers, [])

        mock_timestampits.return_value = 3000
        self.ldm_maintenance.get_all_data_containers = MagicMock(
            return_value=list_database_example
        )
        self.ldm_maintenance.del_provider_data = MagicMock(
            side_effect=json.decoder.JSONDecodeError("test", "test", 1)
        )
        time_invalidity_data_containers = (
            self.ldm_maintenance.check_and_delete_time_validity()
        )
        self.ldm_maintenance.del_provider_data.assert_called()

    @patch("flexstack.facilities.local_dynamic_map.ldm_classes.Utils")
    @patch("builtins.print")
    def test_check_and_delete_area_of_maintenance(self, mock_print, mock_utils):
        mock_utils.euclidian_distance = MagicMock(return_value=1)
        self.ldm_maintenance.get_all_data_containers = MagicMock(
            return_value=list_database_example
        )
        self.ldm_maintenance.del_provider_data = MagicMock()
        self.ldm_maintenance.area_of_maintenance.reference_position.latitude = 407143528
        self.ldm_maintenance.area_of_maintenance.reference_position.longitude = (
            -740059731
        )
        self.ldm_maintenance.area_of_maintenance.reference_position.altitude.altitude_value = (
            1000
        )
        self.ldm_maintenance.area_of_maintenance.reference_area.relevance_area.relevance_distance.compare_with_int = MagicMock(
            return_value=True
        )

        area_of_maintenance_invalidity_data_containers = (
            self.ldm_maintenance.check_and_delete_area_of_maintenance()
        )
        assert self.ldm_maintenance.del_provider_data.called
        self.assertEqual(
            area_of_maintenance_invalidity_data_containers, list_database_example
        )

    @patch(
        "flexstack.facilities.local_dynamic_map.ldm_maintenance.LDMMaintenance.check_and_delete_time_validity"
    )
    @patch(
        "flexstack.facilities.local_dynamic_map.ldm_maintenance.LDMMaintenance.check_and_delete_area_of_maintenance"
    )
    def test_collect_trash(
        self,
        patch_check_area_of_maintenance,
        patch_check_time_validity,
    ):
        self.database.insert = MagicMock()
        self.database.remove = MagicMock()

        patch_check_area_of_maintenance.return_value = [1]
        patch_check_time_validity.return_value = [1]

        self.ldm_maintenance.collect_trash()
        patch_check_area_of_maintenance.assert_called()
        patch_check_time_validity.assert_called()

    def test_update_area_of_maintenance(self):
        self.ldm_maintenance.update_area_of_maintenance(self.area_of_maintenance)
        self.assertEqual(
            self.ldm_maintenance.area_of_maintenance, self.area_of_maintenance
        )

    def test_check_new_data_recieved(self):
        self.ldm_maintenance.new_data_recieved_flag = NEW_DATA_RECIEVED
        return_value = self.ldm_maintenance.check_new_data_recieved()
        self.assertEqual(return_value, NEW_DATA_RECIEVED)

        self.ldm_maintenance.new_data_recieved_flag = NO_NEW_DATA_RECIEVED
        return_value = self.ldm_maintenance.check_new_data_recieved()
        self.assertEqual(return_value, NO_NEW_DATA_RECIEVED)
