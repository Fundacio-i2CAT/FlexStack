import unittest
from unittest.mock import MagicMock

from flexstack.facilities.local_dynamic_map.if_ldm_3 import InterfaceLDM3
from flexstack.facilities.local_dynamic_map.ldm_classes import (
    AddDataProviderReq,
    AddDataProviderResp,
    AccessPermission,
    DeleteDataProviderReq,
    DeleteDataProviderResp,
    DeleteDataProviderResult,
    DeregisterDataProviderAck,
    DeregisterDataProviderReq,
    DeregisterDataProviderResp,
    RegisterDataProviderReq,
    RegisterDataProviderResp,
    RegisterDataProviderResult,
    UpdateDataProviderReq,
    UpdateDataProviderResp,
    TimestampIts,
    TimeValidity,
    Location,
    UpdateDataProviderResult,
)
from flexstack.facilities.local_dynamic_map.ldm_constants import (
    VAM,
    DENM,
    CAM,
)

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
                        "semiMajorOrientation": 201,
                    },
                    "altitude": {
                        "altitudeValue": 800001,
                        "altitudeConfidence": "unavailable",
                    },
                },
            },
            "highFrequencyContainer": (
                "basicVehicleContainerHighFrequency",
                {
                    "heading": {"headingValue": 201, "headingConfidence": 127},
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
            ),
        },
    },
}


class Test_if_ldm_3(unittest.TestCase):
    def setUp(self) -> None:
        self.ldm_service = MagicMock()
        self.if_ldm_3 = InterfaceLDM3(self.ldm_service)

    def test_check_its_aid(self):
        self.assertEqual(self.if_ldm_3.check_its_aid(1), True)
        self.assertEqual(self.if_ldm_3.check_its_aid(2), True)
        self.assertEqual(self.if_ldm_3.check_its_aid(3), True)
        self.assertEqual(self.if_ldm_3.check_its_aid(4), True)
        self.assertEqual(self.if_ldm_3.check_its_aid(5), True)
        self.assertEqual(self.if_ldm_3.check_its_aid(6), True)
        self.assertEqual(self.if_ldm_3.check_its_aid(7), True)
        self.assertEqual(self.if_ldm_3.check_its_aid(8), True)
        self.assertEqual(self.if_ldm_3.check_its_aid(9), True)
        self.assertEqual(self.if_ldm_3.check_its_aid(10), True)
        self.assertEqual(self.if_ldm_3.check_its_aid(11), True)
        self.assertEqual(self.if_ldm_3.check_its_aid(12), True)
        self.assertEqual(self.if_ldm_3.check_its_aid(13), True)
        self.assertEqual(self.if_ldm_3.check_its_aid(14), True)
        self.assertEqual(self.if_ldm_3.check_its_aid(15), True)
        self.assertEqual(self.if_ldm_3.check_its_aid(16), True)
        self.assertEqual(self.if_ldm_3.check_its_aid(17), True)
        self.assertEqual(self.if_ldm_3.check_its_aid(18), True)
        self.assertEqual(self.if_ldm_3.check_its_aid(19), True)
        self.assertEqual(self.if_ldm_3.check_its_aid(20), True)
        self.assertEqual(self.if_ldm_3.check_its_aid(21), True)

    def test_check_permissions(self):
        data_object_id = VAM
        self.assertEqual(self.if_ldm_3.check_permissions(
            (AccessPermission.DENM,), data_object_id), False)
        self.assertEqual(self.if_ldm_3.check_permissions(
            (AccessPermission.CAM,), data_object_id), False)

        data_object_id = VAM
        self.assertEqual(self.if_ldm_3.check_permissions(
            (AccessPermission.VAM,), data_object_id), True)

        access_permisions = (AccessPermission.VAM, AccessPermission.CAM,
                             AccessPermission.DENM, AccessPermission.MAPEM)
        data_object_id = DENM
        self.assertEqual(self.if_ldm_3.check_permissions(
            access_permisions, data_object_id), True)

    def test_register_data_provider(self):
        permission_list = (AccessPermission.CAM,)
        data_provider_correct = RegisterDataProviderReq(
            CAM, permission_list, TimeValidity(5))
        data_provider_incorrect = RegisterDataProviderReq(
            CAM, tuple(), TimeValidity(5))
        self.assertIsInstance(
            self.if_ldm_3.register_data_provider(data_provider_correct),
            RegisterDataProviderResp,
        )

        self.assertEqual(
            self.if_ldm_3.register_data_provider(data_provider_correct).result,
            RegisterDataProviderResult.ACCEPTED,
        )
        self.assertEqual(
            self.if_ldm_3.register_data_provider(
                data_provider_incorrect).result,
            RegisterDataProviderResult.REJECTED,
        )

    def test_deregister_data_provider(self):
        self.ldm_service.del_data_provider_its_aid = MagicMock(
            return_value=None)
        self.ldm_service.get_data_provider_its_aid = MagicMock(
            return_value=[
                2,
            ]
        )
        data_provider_correct = DeregisterDataProviderReq(CAM)
        data_provider_incorrect = DeregisterDataProviderReq(50)

        self.assertIsInstance(
            self.if_ldm_3.deregister_data_provider(data_provider_correct),
            DeregisterDataProviderResp,
        )

        self.assertEqual(
            self.if_ldm_3.deregister_data_provider(
                data_provider_correct).result,
            DeregisterDataProviderAck.ACCEPTED,
        )
        self.assertEqual(
            self.if_ldm_3.deregister_data_provider(
                data_provider_incorrect).result,
            DeregisterDataProviderAck.REJECTED,
        )

    def test_add_provider_data(self):

        data_provider = AddDataProviderReq(
            CAM,
            TimestampIts(5000),
            Location.initializer(latitude=23000000, longitude=41000000),
            white_cam,
            TimeValidity(5),
        )

        self.assertIsInstance(self.if_ldm_3.add_provider_data(
            data_provider), AddDataProviderResp)
        self.assertEqual(self.if_ldm_3.add_provider_data(
            data_provider).data_object_id, -1)

        self.ldm_service.get_data_provider_its_aid = MagicMock(
            return_value=[
                2,
            ]
        )

        self.ldm_service.add_provider_data = MagicMock(return_value=2)

        self.assertIsInstance(self.if_ldm_3.add_provider_data(
            data_provider).data_object_id, int)
        self.ldm_service.add_provider_data.assert_called_once_with(
            data_provider)

    def test_update_provider_data(self):
        self.ldm_service.update_provider_data = MagicMock(return_value=2)
        self.ldm_service.get_object_type_from_data_object = MagicMock()
        self.ldm_service.ldm_maintenance = MagicMock()
        self.ldm_service.ldm_maintenance.data_containers = MagicMock()
        self.ldm_service.ldm_maintenance.data_containers.exists = MagicMock(
            return_value=False)

        data_provider = UpdateDataProviderReq(
            35, AccessPermission.IMZM, TimestampIts(
                5000), Location.initializer(latitude=23000000, longitude=41000000), white_cam, TimeValidity(5))
        self.assertIsInstance(self.if_ldm_3.update_provider_data(
            data_provider), UpdateDataProviderResp)
        self.assertEqual(self.if_ldm_3.update_provider_data(
            data_provider).result, UpdateDataProviderResult.UNKNOWN_DATA_OBJECT_ID)

        self.ldm_service.ldm_maintenance.data_containers.exists = MagicMock(
            return_value=True)
        data_provider = UpdateDataProviderReq(2, AccessPermission(1), TimestampIts(
            5000), Location.initializer(latitude=23000000, longitude=41000000), white_cam, TimeValidity(5))
        self.assertEqual(self.if_ldm_3.update_provider_data(
            data_provider).result, UpdateDataProviderResult.SUCCEED)

    def test_delete_provider_data(self):
        self.ldm_service.del_provider_data = MagicMock(return_value=None)
        self.ldm_service.ldm_maintenance = MagicMock()
        self.ldm_service.ldm_maintenance.data_containers = MagicMock()
        self.ldm_service.ldm_maintenance.data_containers.exists = MagicMock(
            return_value=False)

        data_provider = DeleteDataProviderReq(2, 2, TimestampIts(5000))
        self.assertIsInstance(self.if_ldm_3.delete_provider_data(
            data_provider), DeleteDataProviderResp)
        self.assertEqual(
            self.if_ldm_3.delete_provider_data(data_provider).result,
            DeleteDataProviderResult.FAILED,
        )

        self.ldm_service.ldm_maintenance.data_containers.exists = MagicMock(
            return_value=True)
        self.assertEqual(
            self.if_ldm_3.delete_provider_data(data_provider).result,
            DeleteDataProviderResult.SUCCEED,
        )


if __name__ == "__main__":
    unittest.main()
