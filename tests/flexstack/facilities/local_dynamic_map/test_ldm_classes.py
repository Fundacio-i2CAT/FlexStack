import unittest
from unittest.mock import MagicMock

from flexstack.facilities.local_dynamic_map.ldm_classes import (
    DeleteDataProviderReq,
    DeleteDataProviderResp,
    DeleteDataProviderResult,
    DeregisterDataConsumerAck,
    DeregisterDataConsumerReq,
    DeregisterDataConsumerResp,
    Direction,
    Ellipse,
    Filter,
    FilterStatement,
    GeometricArea,
    Location,
    LogicalOperators,
    OrderTuple,
    OrderingDirection,
    PublishDataobjects,
    Rectangle,
    ReferenceArea,
    ReferenceValue,
    RegisterDataConsumerReq,
    RegisterDataConsumerResp,
    RegisterDataConsumerResult,
    RelevanceDistance,
    RelevanceTrafficDirection,
    RequestDataObjectsReq,
    RequestDataObjectsResp,
    RequestedDataObjectsResult,
    RevokeDataConsumerRegistrationResp,
    StationType,
    Altitude,
    AuthorizeResp,
    DeregisterDataProviderAck,
    DeregisterDataProviderResp,
    Latitude,
    Longitude,
    PositionConfidenceEllipse,
    ReferencePosition,
    RegisterDataProviderReq,
    RegisterDataProviderResult,
    RevocationReason,
    RevocationResult,
    RelevanceArea,
    RevokeAuthorizationReg,
    RevokeDataProviderRegistrationResp,
    SubscribeDataobjectsReq,
    SubscribeDataObjectsResp,
    SubscribeDataobjectsResult,
    TimeValidity,
    TimestampIts,
    DataContainer,
    AuthorizationResult,
    AuthorizeReg,
    Circle,
    UnsubscribeDataConsumerAck,
    UnsubscribeDataConsumerReq,
    UnsubscribeDataConsumerResp,
    UnsubscribeDataobjectsReq,
    UnsubscribeDataobjectsResp,
    UnsubscribeDataobjectsResult,
    UpdateDataProviderResp,
    UpdateDataProviderResult,
    Utils,
)
from flexstack.facilities.local_dynamic_map.ldm_constants import REFERENCE_ITS_TIMESTAMP


white_vam = {
    "header": {"protocolVersion": 3, "messageId": 16, "stationId": 0},
    "vam": {
        "generationDeltaTime": 0,
        "vamParameters": {
            "basicContainer": {
                # roadSideUnit(15), cyclist(2)
                "stationType": 15,
                "referencePosition": {
                    "latitude": 900000001,
                    "longitude": 1800000001,
                    "positionConfidenceEllipse": {
                        "semiMajorAxisLength": 4095,
                        "semiMinorAxisLength": 4095,
                        "semiMajorAxisOrientation": 3601,
                    },
                    "altitude": {
                        "altitudeValue": 800001,
                        "altitudeConfidence": "unavailable",
                    },
                },
            },
            "vruHighFrequencyContainer": {
                "heading": {"value": 3601, "confidence": 127},
                "speed": {"speedValue": 16383, "speedConfidence": 127},
                "longitudinalAcceleration": {
                    "longitudinalAccelerationValue": 161,
                    "longitudinalAccelerationConfidence": 102,
                },
            },
        },
    },
}


class TestTimestampIts(unittest.TestCase):
    def setUp(self) -> None:
        self.timestamp = 3
        self.timestamp_its = TimestampIts(self.timestamp)

    def test__init__(self) -> None:
        self.assertEqual(self.timestamp_its.timestamp, self.timestamp)

    def test_insert_unix_timestamp(self) -> None:
        timestamp = 2000000000
        result = (timestamp - REFERENCE_ITS_TIMESTAMP)
        self.timestamp_its.insert_unix_timestamp(timestamp)
        self.assertEqual(self.timestamp_its.timestamp, result)

    def test_convert_epoch_to_its_timestamp_timestamp_is_none(self) -> None:
        timestamp = None
        result = (self.timestamp - REFERENCE_ITS_TIMESTAMP)
        self.timestamp_its.convert_epoch_to_its_timestamp(timestamp)
        self.assertEqual(self.timestamp_its.timestamp, result)

    def test_convert_epoch_to_its_timestamp_timestamp_not_none(self) -> None:
        timestamp = 2000000000
        result = (timestamp - REFERENCE_ITS_TIMESTAMP)
        self.assertEqual(
            self.timestamp_its.convert_epoch_to_its_timestamp(timestamp), result
        )


class TestDataContainer(unittest.TestCase):
    def test__str__(self) -> None:
        self.assertEqual(
            str(DataContainer({"cam": 1, "test": 2})), "Cooperative Awareness Message"
        )
        self.assertEqual(
            str(DataContainer({"denm": 1, "test": 2})),
            "Decentralized Environmental Notification Message",
        )
        self.assertEqual(
            str(DataContainer({"poi": 1, "test": 2})), "Point of Interest Message"
        )
        self.assertEqual(
            str(DataContainer({"spatem": 1, "test": 2})),
            "Signal and Phase and Timing Extended Message",
        )
        self.assertEqual(
            str(DataContainer({"mapem": 1, "test": 2})), "MAP Extended Message"
        )
        self.assertEqual(
            str(DataContainer({"ivim": 1, "test": 2})), "Vehicle Information Message"
        )
        self.assertEqual(
            str(DataContainer({"ev-rsr": 1, "test": 2})),
            "Electric Vehicle Recharging Spot Reservation Message",
        )
        self.assertEqual(
            str(DataContainer({"tistpgtransaction": 1, "test": 2})),
            "Tyre Information System and Tyre Pressure Gauge Interoperability",
        )
        self.assertEqual(
            str(DataContainer({"srem": 1, "test": 2})),
            "Signal Request Extended Message",
        )
        self.assertEqual(
            str(DataContainer({"ssem": 1, "test": 2})),
            "Signal Request Status Extended Message",
        )
        self.assertEqual(
            str(DataContainer({"evcsn": 1, "test": 2})),
            "Electrical Vehicle Charging Spot Notification Message",
        )
        self.assertEqual(
            str(DataContainer({"saem": 1, "test": 2})),
            "Services Announcement Extended Message",
        )
        self.assertEqual(
            str(DataContainer({"rtcmem": 1, "test": 2})),
            "Radio Technical Commision for Maritime Services Extended Message",
        )
        self.assertEqual(
            str(DataContainer({"cpm": 1, "test": 2})), "Collective Perception Message"
        )
        self.assertEqual(
            str(DataContainer({"imzm": 1, "test": 2})),
            "Interface Management Zone Message",
        )
        self.assertEqual(
            str(DataContainer({"vam": 1, "test": 2})),
            "Vulnerable Road User Awareness Message",
        )
        self.assertEqual(
            str(DataContainer({"dsm": 1, "test": 2})),
            "Diagnosis Logging and Status Message",
        )
        self.assertEqual(
            str(DataContainer({"pcim": 1, "test": 2})),
            "Parking Control Infrastucture Message",
        )
        self.assertEqual(
            str(DataContainer({"pcvm": 1, "test": 2})),
            "Parking Control Vehicle Message",
        )
        self.assertEqual(
            str(DataContainer({"mcm": 1, "test": 2})), "Maneuver Coordination Message"
        )
        self.assertEqual(
            str(DataContainer({"pam": 1, "test": 2})), "Parking Availability Message"
        )
        self.assertEqual(str(DataContainer({"test": 1, "test2": 2})), "unknown")


class TestAuthorizationResult(unittest.TestCase):
    def test__str__(self) -> None:
        self.assertEqual(str(AuthorizationResult(0)), "successful")
        self.assertEqual(str(AuthorizationResult(1)), "invalidITS-AID")
        self.assertEqual(str(AuthorizationResult(2)), "authentiticaionFailure")
        self.assertEqual(str(AuthorizationResult(3)), "applicationNotAuthorized")


class TestAuthorizationReg(unittest.TestCase):
    def test__init__(self) -> None:
        applicationId = 1
        accessPermissions = 2
        self.assertEqual(
            AuthorizeReg(applicationId, accessPermissions).application_id, applicationId
        )
        self.assertEqual(
            AuthorizeReg(applicationId, accessPermissions).access_permissions,
            accessPermissions,
        )


class TestAuthorizationResp(unittest.TestCase):
    def test__init__(self) -> None:
        applicationId = 1
        accessPermissions = 2
        result = 3
        self.assertEqual(
            AuthorizeResp(applicationId, accessPermissions, result).application_id,
            applicationId,
        )
        self.assertEqual(
            AuthorizeResp(applicationId, accessPermissions, result).access_permissions,
            accessPermissions,
        )
        self.assertEqual(
            AuthorizeResp(applicationId, accessPermissions, result).result, result
        )


class TestRevocationReason(unittest.TestCase):
    def test__init__(self) -> None:
        reason = 1
        self.assertEqual(RevocationReason(reason).reason, reason)

    def test__str__(self) -> None:
        self.assertEqual(
            str(RevocationReason(0)), "registratioRevokedByRegistrationAuthority"
        )
        self.assertEqual(str(RevocationReason(1)), "registrationPeriodExpired")


class TestRevocationResult(unittest.TestCase):
    def test__init__(self) -> None:
        result = 1
        self.assertEqual(RevocationResult(result).result, result)

    def test__str__(self) -> None:
        self.assertEqual(str(RevocationResult(0)), "successful")
        self.assertEqual(str(RevocationResult(1)), "invalidITS-AID")
        self.assertEqual(str(RevocationResult(2)), "unknownITS-AID")


class TestRevokeAuthorizationReg(unittest.TestCase):
    def test__init__(self) -> None:
        applicationId = 1
        reason = 2
        self.assertEqual(
            RevokeAuthorizationReg(applicationId, reason).application_id, applicationId
        )
        self.assertEqual(RevokeAuthorizationReg(applicationId, reason).reason, reason)


class TestRegisterDataProviderReq(unittest.TestCase):
    def test__init__(self) -> None:
        applicationId = 1
        accessPermissions = 2
        timeValidity = 3
        self.assertEqual(
            RegisterDataProviderReq(
                applicationId, accessPermissions, timeValidity
            ).application_id,
            applicationId,
        )
        self.assertEqual(
            RegisterDataProviderReq(
                applicationId, accessPermissions, timeValidity
            ).access_permisions,
            accessPermissions,
        )
        self.assertEqual(
            RegisterDataProviderReq(
                applicationId, accessPermissions, timeValidity
            ).time_validity,
            timeValidity,
        )


class TestRegisterDataProviderResp(unittest.TestCase):
    def test__init__(self) -> None:
        result = 1
        self.assertEqual(RegisterDataProviderResult(result).result, result)


class TestDeregisterDataProviderAck(unittest.TestCase):
    def test__init__(self) -> None:
        result = 1
        self.assertEqual(DeregisterDataProviderAck(result).result, result)

    def test__str__(self) -> None:
        self.assertEqual(str(DeregisterDataProviderAck(0)), "accepted")
        self.assertEqual(str(DeregisterDataProviderAck(1)), "rejected")


class TestDeregisterDataProviderReq(unittest.TestCase):
    def test__init__(self) -> None:
        applicationId = 1
        result = 2
        self.assertEqual(
            DeregisterDataProviderResp(applicationId, result).application_id,
            applicationId,
        )
        self.assertEqual(
            DeregisterDataProviderResp(applicationId, result).result, result
        )


class TestRevokeDataProviderRegistrationResp(unittest.TestCase):
    def test__init__(self) -> None:
        applicationId = 1
        self.assertEqual(
            RevokeDataProviderRegistrationResp(applicationId).application_id,
            applicationId,
        )


class TestTimeValidity(unittest.TestCase):
    def test__init__(self) -> None:
        time = 1
        self.assertEqual(TimeValidity(time).time, time)

    def test_to_etsi_its(self) -> None:
        timestamp = 2000000000
        result = ((timestamp - REFERENCE_ITS_TIMESTAMP)) * 1000
        self.assertEqual(TimeValidity(timestamp).to_etsi_its(), result)


class TestPositionConfidenceEllipse(unittest.TestCase):
    def test__init__(self) -> None:
        semiMajorConfidence = 1
        semiMinorConfidence = 2
        semiMajorOrientation = 3
        self.assertEqual(
            PositionConfidenceEllipse(
                semiMajorConfidence, semiMinorConfidence, semiMajorOrientation
            ).semi_major_confidence,
            semiMajorConfidence,
        )
        self.assertEqual(
            PositionConfidenceEllipse(
                semiMajorConfidence, semiMinorConfidence, semiMajorOrientation
            ).semi_minor_confidence,
            semiMinorConfidence,
        )
        self.assertEqual(
            PositionConfidenceEllipse(
                semiMajorConfidence, semiMinorConfidence, semiMajorOrientation
            ).semi_major_orientation,
            semiMajorOrientation,
        )


class TestAltitude(unittest.TestCase):
    def test__init__(self) -> None:
        altitudeValue = 1
        altitudeConfidence = 2
        self.assertEqual(
            Altitude(altitudeValue, altitudeConfidence).altitude_value, altitudeValue
        )
        self.assertEqual(
            Altitude(altitudeValue, altitudeConfidence).altitude_confidence,
            altitudeConfidence,
        )


class TestLatitude(unittest.TestCase):
    def test_convert_latitude_to_its_latitude(self) -> None:
        latitude = 42.1234567
        its_latitude = int(latitude * 10000000)
        self.assertEqual(
            Latitude.convert_latitude_to_its_latitude(latitude), its_latitude
        )

        latitude = 420.1234567
        its_latitude = int(latitude * 10000000)
        self.assertEqual(Latitude.convert_latitude_to_its_latitude(latitude), 900000001)


class TestLongitude(unittest.TestCase):
    def test_convert_longitude_to_its_longitude(self) -> None:
        longitude = 1.234567
        its_longitude = int(longitude * 10000000)
        self.assertEqual(
            Longitude.convert_longitude_to_its_longitude(longitude), its_longitude
        )

        longitude = 181.1234567
        its_longitude = int(longitude * 10000000)
        self.assertEqual(
            Longitude.convert_longitude_to_its_longitude(longitude), 1800000001
        )


class TestReferencePosition(unittest.TestCase):
    def test__init__(self) -> None:
        latitude = 1
        longitude = 2
        positionConfidenceEllipse = MagicMock()
        positionConfidenceEllipse.semiMajorConfidence = 3
        positionConfidenceEllipse.semiMinorConfidence = 4
        positionConfidenceEllipse.semiMajorOrientation = 5
        altitude = MagicMock()
        altitude.altitudeValue = 6
        altitude.altitudeConfidence = 7
        self.assertEqual(
            ReferencePosition(
                latitude, longitude, positionConfidenceEllipse, altitude
            ).latitude,
            latitude,
        )
        self.assertEqual(
            ReferencePosition(
                latitude, longitude, positionConfidenceEllipse, altitude
            ).longitude,
            longitude,
        )
        self.assertEqual(
            ReferencePosition(
                latitude, longitude, positionConfidenceEllipse, altitude
            ).position_confidence_ellipse,
            positionConfidenceEllipse,
        )
        self.assertEqual(
            ReferencePosition(
                latitude, longitude, positionConfidenceEllipse, altitude
            ).altitude,
            altitude,
        )

    def test_to_dict(self) -> None:
        latitude = 1
        longitude = 2
        positionConfidenceEllipse = MagicMock()
        positionConfidenceEllipse.semi_major_confidence = 3
        positionConfidenceEllipse.semi_minor_confidence = 4
        positionConfidenceEllipse.semi_major_orientation = 5
        altitude = MagicMock()
        altitude.altitude_value = 6
        altitude.altitude_confidence = 7
        self.assertEqual(
            ReferencePosition(
                latitude, longitude, positionConfidenceEllipse, altitude
            ).to_dict(),
            {
                "latitude": latitude,
                "longitude": longitude,
                "positionConfidenceEllipse": {
                    "semiMajorConfidence": positionConfidenceEllipse.semi_major_confidence,
                    "semiMinorConfidence": positionConfidenceEllipse.semi_minor_confidence,
                    "semiMajorOrientation": positionConfidenceEllipse.semi_major_orientation,
                },
                "altitude": {
                    "altitudeValue": altitude.altitude_value,
                    "altitudeConfidence": altitude.altitude_confidence,
                },
            },
        )

    def test_update_with_gpsd_tpv(self) -> None:
        latitude = 1
        longitude = 2
        positionConfidenceEllipse = MagicMock()
        positionConfidenceEllipse.semi_major_confidence = 3
        positionConfidenceEllipse.semi_minor_confidence = 4
        positionConfidenceEllipse.semi_major_orientation = 5
        altitude = MagicMock()
        altitude.altitude_value = 6
        altitude.altitude_confidence = 7
        reference_position = ReferencePosition(
            latitude, longitude, positionConfidenceEllipse, altitude
        )
        tpv_data = {
            "class": "TPV",
            "device": "/dev/ttyACM0",
            "mode": 3,
            "time": "2020-03-13T13:01:14.000Z",
            "ept": 0.005,
            "lat": 41.453606167,
            "lon": 2.073707333,
            "alt": 163.500,
            "epx": 8.754,
            "epy": 10.597,
            "epv": 31.970,
            "track": 0.0000,
            "speed": 0.011,
            "climb": 0.000,
            "eps": 0.57,
        }
        reference_position.update_with_gpsd_tpv(tpv_data)
        self.assertEqual(reference_position.latitude, int(tpv_data["lat"] * 10000000))
        self.assertEqual(reference_position.longitude, int(tpv_data["lon"] * 10000000))


class TestStationType(unittest.TestCase):
    def test__init__(self):
        self.assertEqual(StationType(1).station_type, 1)

    def test__str__(self):
        self.assertEqual(str(StationType(0)), "Unknown")
        self.assertEqual(str(StationType(1)), "Pedestrian")
        self.assertEqual(str(StationType(2)), "Cyclist")
        self.assertEqual(str(StationType(3)), "Moped")
        self.assertEqual(str(StationType(4)), "Motorcycle")
        self.assertEqual(str(StationType(5)), "Passenger Car")
        self.assertEqual(str(StationType(6)), "Bus")
        self.assertEqual(str(StationType(7)), "Light Truck")
        self.assertEqual(str(StationType(8)), "Heavy Truck")
        self.assertEqual(str(StationType(9)), "Trailer")
        self.assertEqual(str(StationType(10)), "Special Vehicles")
        self.assertEqual(str(StationType(11)), "Tram")
        self.assertEqual(str(StationType(12)), "Unknown")
        self.assertEqual(str(StationType(15)), "Road-Side-Unit")


class TestDirection(unittest.TestCase):
    def test__init__(self):
        self.assertEqual(Direction(1).direction, 1)

    def test__str__(self):
        self.assertEqual(str(Direction(0)), "north")
        self.assertEqual(str(Direction(7200)), "east")
        self.assertEqual(str(Direction(14400)), "south")
        self.assertEqual(str(Direction(21600)), "west")
        self.assertEqual(str(Direction(2)), "unknown")


class TestCircle(unittest.TestCase):
    def test__init__(self):
        self.assertEqual(Circle(1).radius, 1)


class TestRectangle(unittest.TestCase):
    def test__init__(self):
        self.assertEqual(Rectangle(1, 2, 3).a_semi_axis, 1)
        self.assertEqual(Rectangle(1, 2, 3).b_semi_axis, 2)
        self.assertEqual(Rectangle(1, 2, 3).azimuth_angle, 3)


class TestEllipse(unittest.TestCase):
    def test__init__(self) -> None:
        azimuthAngle = MagicMock()
        self.assertEqual(Ellipse(1, 2, azimuthAngle).a_semi_axis, 1)
        self.assertEqual(Ellipse(1, 2, azimuthAngle).b_semi_axis, 2)
        self.assertEqual(Ellipse(1, 2, azimuthAngle).azimuth_angle, azimuthAngle)


class TestRelevanceTrafficDirection(unittest.TestCase):
    def test__init__(self):
        self.assertEqual(RelevanceTrafficDirection(1).relevance_traffic_direction, 1)

    def test__str__(self) -> None:
        self.assertEqual(str(RelevanceTrafficDirection(0)), "allTrafficDirections")
        self.assertEqual(str(RelevanceTrafficDirection(1)), "upstreamTraffic")
        self.assertEqual(str(RelevanceTrafficDirection(2)), "downstreamTraffic")
        self.assertEqual(str(RelevanceTrafficDirection(3)), "oppositeTraffic")


class TestRelevanceDistance(unittest.TestCase):
    def test__init__(self):
        self.assertEqual(RelevanceDistance(1).relevance_distance, 1)

    def test__str__(self) -> None:
        self.assertEqual(str(RelevanceDistance(0)), "lessThan50m")
        self.assertEqual(str(RelevanceDistance(1)), "lessThan100m")
        self.assertEqual(str(RelevanceDistance(2)), "lessThan200m")
        self.assertEqual(str(RelevanceDistance(3)), "lessThan500m")
        self.assertEqual(str(RelevanceDistance(4)), "lessThan1000m")
        self.assertEqual(str(RelevanceDistance(5)), "lessThan5km")
        self.assertEqual(str(RelevanceDistance(6)), "lessThan10km")
        self.assertEqual(str(RelevanceDistance(7)), "over20km")
        self.assertEqual(str(RelevanceDistance(8)), "unknown")

    def test_compare_with_int(self) -> None:
        self.assertEqual(RelevanceDistance(0).compare_with_int(20), True)
        self.assertEqual(RelevanceDistance(0).compare_with_int(51), False)

        self.assertEqual(RelevanceDistance(1).compare_with_int(20), True)
        self.assertEqual(RelevanceDistance(1).compare_with_int(101), False)

        self.assertEqual(RelevanceDistance(2).compare_with_int(20), True)
        self.assertEqual(RelevanceDistance(2).compare_with_int(201), False)

        self.assertEqual(RelevanceDistance(3).compare_with_int(20), True)
        self.assertEqual(RelevanceDistance(3).compare_with_int(501), False)

        self.assertEqual(RelevanceDistance(4).compare_with_int(20), True)
        self.assertEqual(RelevanceDistance(4).compare_with_int(1001), False)

        self.assertEqual(RelevanceDistance(5).compare_with_int(20), True)
        self.assertEqual(RelevanceDistance(5).compare_with_int(5001), False)

        self.assertEqual(RelevanceDistance(6).compare_with_int(20), True)
        self.assertEqual(RelevanceDistance(6).compare_with_int(10001), False)

        self.assertEqual(RelevanceDistance(7).compare_with_int(20), False)
        self.assertEqual(RelevanceDistance(7).compare_with_int(20001), True)


class TestRelevanceArea(unittest.TestCase):
    def test__init__(self) -> None:
        relevance_distance = MagicMock()
        relevance_traffic_direction = MagicMock()

        self.assertEqual(
            RelevanceArea(
                relevance_distance, relevance_traffic_direction
            ).relevance_distance,
            relevance_distance,
        )
        self.assertEqual(
            RelevanceArea(
                relevance_distance, relevance_traffic_direction
            ).relevance_traffic_direction,
            relevance_traffic_direction,
        )


class TestGeometricArea(unittest.TestCase):
    def test__init__(self) -> None:
        circle = MagicMock()
        rectangle = MagicMock()
        ellipse = MagicMock()
        self.assertEqual(GeometricArea(circle, rectangle, ellipse).circle, circle)
        self.assertEqual(GeometricArea(circle, rectangle, ellipse).rectangle, rectangle)
        self.assertEqual(GeometricArea(circle, rectangle, ellipse).ellipse, ellipse)


class TestReferenceArea(unittest.TestCase):
    def test__init__(self) -> None:
        relevance_area = MagicMock()
        geometric_area = MagicMock()
        self.assertEqual(
            ReferenceArea(geometric_area, relevance_area).relevance_area, relevance_area
        )
        self.assertEqual(
            ReferenceArea(geometric_area, relevance_area).geometric_area, geometric_area
        )


class TestLocation(unittest.TestCase):
    def test__init__(self) -> None:
        referencePosition = MagicMock()
        referenceArea = MagicMock()
        self.assertEqual(
            Location(referencePosition, referenceArea).reference_position,
            referencePosition,
        )
        self.assertEqual(
            Location(referencePosition, referenceArea).reference_area, referenceArea
        )

    def test_location_service_callback(self) -> None:
        referencePosition = MagicMock()
        referencePosition.update_with_gpsd_tpv = MagicMock()
        referenceArea = MagicMock()
        location = Location(referencePosition, referenceArea)
        location.location_service_callback("test")

        referencePosition.update_with_gpsd_tpv.assert_called_once_with("test")

    def test_location_builder_circle(self) -> None:
        latitude = 1
        longitude = 2
        altitude = 3
        radius = 4

        # Check if the values created are the same as the mock values
        reference_position = Location.location_builder_circle(
            latitude, longitude, altitude, radius
        ).reference_position
        reference_area = Location.location_builder_circle(
            latitude, longitude, altitude, radius
        ).reference_area

        self.assertEqual(reference_position.latitude, latitude)
        self.assertEqual(reference_position.longitude, longitude)
        self.assertEqual(reference_position.altitude.altitude_value, altitude)

        self.assertEqual(reference_area.geometric_area.circle.radius, radius)


class TestUpdateDataProviderResult(unittest.TestCase):
    def test__init__(self) -> None:
        result = 1
        self.assertEqual(UpdateDataProviderResult(result).result, result)

    def test__str__(self) -> None:
        self.assertEqual(str(UpdateDataProviderResult(0)), "succeed")
        self.assertEqual(str(UpdateDataProviderResult(1)), "unknownDataObjectID")
        self.assertEqual(str(UpdateDataProviderResult(2)), "inconsistentDataObjectType")


class TestUpdateDataProviderResp(unittest.TestCase):
    def test__init__(self) -> None:
        applicationId = 1
        dataObjectID = 2
        result = MagicMock()
        self.assertEqual(
            UpdateDataProviderResp(applicationId, dataObjectID, result).application_id,
            applicationId,
        )
        self.assertEqual(
            UpdateDataProviderResp(applicationId, dataObjectID, result).data_object_id,
            dataObjectID,
        )
        self.assertEqual(
            UpdateDataProviderResp(applicationId, dataObjectID, result).result, result
        )


class TestDeleteDataProviderReq(unittest.TestCase):
    def test__init__(self) -> None:
        applicationId = 1
        dataObjectID = 2
        timeStamp = 3
        self.assertEqual(
            DeleteDataProviderReq(applicationId, dataObjectID, timeStamp).application_id,
            applicationId,
        )
        self.assertEqual(
            DeleteDataProviderReq(applicationId, dataObjectID, timeStamp).data_object_id,
            dataObjectID,
        )
        self.assertEqual(
            DeleteDataProviderReq(applicationId, dataObjectID, timeStamp).time_stamp,
            timeStamp,
        )


class TestDeleteDataProviderResult(unittest.TestCase):
    def test__init__(self) -> None:
        result = 1
        self.assertEqual(DeleteDataProviderResult(result).result, result)

    def test__str__(self) -> None:
        self.assertEqual(str(DeleteDataProviderResult(0)), "succeed")
        self.assertEqual(str(DeleteDataProviderResult(1)), "failed")


class TestDeleteDataProviderResp(unittest.TestCase):
    def test__init__(self) -> None:
        applicationId = 1
        dataObjectID = 2
        result = MagicMock()
        self.assertEqual(
            DeleteDataProviderResp(applicationId, dataObjectID, result).application_id,
            applicationId,
        )
        self.assertEqual(
            DeleteDataProviderResp(applicationId, dataObjectID, result).data_object_id,
            dataObjectID,
        )
        self.assertEqual(
            DeleteDataProviderResp(applicationId, dataObjectID, result).result, result
        )


class TestRegisterDataProviderResult(unittest.TestCase):
    def test__init__(self) -> None:
        result = 1
        self.assertEqual(RegisterDataProviderResult(result).result, result)

    def test__str__(self) -> None:
        self.assertEqual(str(RegisterDataProviderResult(0)), "accepted")
        self.assertEqual(str(RegisterDataProviderResult(1)), "rejected")


class TestRegisterDataConsumerReq(unittest.TestCase):
    def test__init__(self) -> None:
        applicationId = 1
        accessPermissions = MagicMock()
        areaOfInterest = MagicMock()
        self.assertEqual(
            RegisterDataConsumerReq(
                applicationId, accessPermissions, areaOfInterest
            ).application_id,
            applicationId,
        )
        self.assertEqual(
            RegisterDataConsumerReq(
                applicationId, accessPermissions, areaOfInterest
            ).access_permisions,
            accessPermissions,
        )
        self.assertEqual(
            RegisterDataConsumerReq(
                applicationId, accessPermissions, areaOfInterest
            ).area_of_interest,
            areaOfInterest,
        )


class TestRegisterDataConsumerResult(unittest.TestCase):
    def test__init__(self) -> None:
        result = 1
        self.assertEqual(RegisterDataConsumerResult(result).result, result)

    def test__str__(self) -> None:
        self.assertEqual(str(RegisterDataConsumerResult(0)), "accepted")
        self.assertEqual(str(RegisterDataConsumerResult(1)), "warning")
        self.assertEqual(str(RegisterDataConsumerResult(2)), "rejected")


class TestRegisterDataConsumerResp(unittest.TestCase):
    def test__init__(self) -> None:
        applicationId = 1
        accessPermissions = MagicMock()
        result = MagicMock()
        self.assertEqual(
            RegisterDataConsumerResp(
                applicationId, accessPermissions, result
            ).application_id,
            applicationId,
        )
        self.assertEqual(
            RegisterDataConsumerResp(
                applicationId, accessPermissions, result
            ).access_permisions,
            accessPermissions,
        )
        self.assertEqual(
            RegisterDataConsumerResp(applicationId, accessPermissions, result).result,
            result,
        )


class TestDeregisterDataConsumerReq(unittest.TestCase):
    def test__init__(self) -> None:
        applicationId = 1
        self.assertEqual(
            DeregisterDataConsumerReq(applicationId).application_id, applicationId
        )


class TestDeregisterDataConsumerAck(unittest.TestCase):
    def test__init__(self) -> None:
        result = MagicMock()
        self.assertEqual(DeregisterDataConsumerAck(result).result, result)

    def test__str__(self) -> None:
        self.assertEqual(str(DeregisterDataConsumerAck(0)), "succeed")
        self.assertEqual(str(DeregisterDataConsumerAck(1)), "failed")


class TestDeregisterDataConsumerResp(unittest.TestCase):
    def test__init__(self) -> None:
        applicationId = 1
        ack = MagicMock()
        self.assertEqual(
            DeregisterDataConsumerResp(applicationId, ack).application_id, applicationId
        )
        self.assertEqual(DeregisterDataConsumerResp(applicationId, ack).ack, ack)


class TestUnsubscribeDataConsumerReq(unittest.TestCase):
    def test__init__(self) -> None:
        applicationId = 1
        subscriptionId = 2
        self.assertEqual(
            UnsubscribeDataConsumerReq(applicationId, subscriptionId).application_id,
            applicationId,
        )
        self.assertEqual(
            UnsubscribeDataConsumerReq(applicationId, subscriptionId).subscription_id,
            subscriptionId,
        )


class TestUnsubscribeDataConsumerAck(unittest.TestCase):
    def test__init__(self) -> None:
        result = 1
        self.assertEqual(UnsubscribeDataConsumerAck(result).result, result)

    def test__str__(self) -> None:
        self.assertEqual(str(UnsubscribeDataConsumerAck(0)), "accepted")
        self.assertEqual(str(UnsubscribeDataConsumerAck(1)), "failed")


class TestUnsubscribeDataConsumerResp(unittest.TestCase):
    def test__init__(self) -> None:
        applicationId = 1
        subscriptionId = 2
        result = MagicMock()
        self.assertEqual(
            UnsubscribeDataConsumerResp(applicationId, subscriptionId, result).result,
            result,
        )
        self.assertEqual(
            UnsubscribeDataConsumerResp(
                applicationId, subscriptionId, result
            ).application_id,
            applicationId,
        )
        self.assertEqual(
            UnsubscribeDataConsumerResp(
                applicationId, subscriptionId, result
            ).subscription_id,
            subscriptionId,
        )


class TestRevokeDataConsumerRegistrationResp(unittest.TestCase):
    def test__init__(self) -> None:
        applicationId = 1
        self.assertEqual(
            RevokeDataConsumerRegistrationResp(applicationId).application_id,
            applicationId,
        )


class TestOrderingDirection(unittest.TestCase):
    def test__init__(self) -> None:
        direction = 1
        self.assertEqual(OrderingDirection(direction).direction, direction)

    def test__str__(self) -> None:
        self.assertEqual(str(OrderingDirection(0)), "ascending")
        self.assertEqual(str(OrderingDirection(1)), "descending")


class TestOrderTuple(unittest.TestCase):
    def test__init__(self) -> None:
        attribute = 1
        orderingDirection = MagicMock()
        orderingDirection.direction = 1
        self.assertEqual(OrderTuple(attribute, orderingDirection).attribute, attribute)
        self.assertEqual(
            OrderTuple(attribute, orderingDirection).ordering_direction,
            orderingDirection,
        )


class TestLogicalOperators(unittest.TestCase):
    def test__init__(self) -> None:
        operator = 1
        self.assertEqual(LogicalOperators(operator).operator, operator)

    def test__str__(self) -> None:
        self.assertEqual(str(LogicalOperators(0)), "and")
        self.assertEqual(str(LogicalOperators(1)), "or")


class TestComparisonOperators(unittest.TestCase):
    def test__init__(self) -> None:
        operator = 1
        self.assertEqual(LogicalOperators(operator).operator, operator)

    def test__str__(self) -> None:
        self.assertEqual(str(LogicalOperators(0)), "and")
        self.assertEqual(str(LogicalOperators(1)), "or")


class TestFilterStatement(unittest.TestCase):
    def test__init__(self) -> None:
        attribute = 1
        operator = MagicMock()
        operator.operator = 1
        refValue = 2
        self.assertEqual(
            FilterStatement(attribute, operator, refValue).attribute, attribute
        )
        self.assertEqual(
            FilterStatement(attribute, operator, refValue).operator, operator
        )
        self.assertEqual(
            FilterStatement(attribute, operator, refValue).ref_value, refValue
        )


class TestFilter(unittest.TestCase):
    def test__init__(self) -> None:
        filter_statement_1 = MagicMock()
        filter_statement_2 = MagicMock()
        logicalOperator = MagicMock()

        self.assertEqual(
            Filter(
                filter_statement_1, logicalOperator, filter_statement_2
            ).filter_statement_1,
            filter_statement_1,
        )
        self.assertEqual(
            Filter(
                filter_statement_1, logicalOperator, filter_statement_2
            ).filter_statement_2,
            filter_statement_2,
        )
        self.assertEqual(
            Filter(
                filter_statement_1, logicalOperator, filter_statement_2
            ).logical_operator,
            logicalOperator,
        )


class TestRequestDataObjectsReq(unittest.TestCase):
    def test__init__(self) -> None:
        applicationId = 1
        dataObjectsType = 2
        priority = 3
        order = MagicMock()
        filter = MagicMock()
        self.assertEqual(
            RequestDataObjectsReq(
                applicationId, dataObjectsType, priority, order, filter
            ).application_id,
            applicationId,
        )
        self.assertEqual(
            RequestDataObjectsReq(
                applicationId, dataObjectsType, priority, order, filter
            ).data_object_type,
            dataObjectsType,
        )
        self.assertEqual(
            RequestDataObjectsReq(
                applicationId, dataObjectsType, priority, order, filter
            ).priority,
            priority,
        )
        self.assertEqual(
            RequestDataObjectsReq(
                applicationId, dataObjectsType, priority, order, filter
            ).order,
            order,
        )
        self.assertEqual(
            RequestDataObjectsReq(
                applicationId, dataObjectsType, priority, order, filter
            ).filter,
            filter,
        )


class TestRequestedDataObjectsResult(unittest.TestCase):
    def test__init__(self) -> None:
        result = 1
        self.assertEqual(RequestedDataObjectsResult(result).result, result)

    def test__str__(self) -> None:
        self.assertEqual(str(RequestedDataObjectsResult(0)), "succeed")
        self.assertEqual(str(RequestedDataObjectsResult(1)), "invalidITSAID")
        self.assertEqual(str(RequestedDataObjectsResult(2)), "invalidDataObjectType")
        self.assertEqual(str(RequestedDataObjectsResult(3)), "invalidPriority")
        self.assertEqual(str(RequestedDataObjectsResult(4)), "invalidFilter")
        self.assertEqual(str(RequestedDataObjectsResult(5)), "invalidOrder")


class TestRequestDataObjectsResp(unittest.TestCase):
    def test__init__(self) -> None:
        applicationId = 1
        dataObjects = MagicMock()
        result = MagicMock()
        self.assertEqual(
            RequestDataObjectsResp(applicationId, dataObjects, result).application_id,
            applicationId,
        )
        self.assertEqual(
            RequestDataObjectsResp(applicationId, dataObjects, result).result, result
        )
        self.assertEqual(
            RequestDataObjectsResp(applicationId, dataObjects, result).data_objects,
            dataObjects,
        )

    def test_find_attribute(self) -> None:
        applicationId = 1
        dataObjects = MagicMock()
        result = MagicMock()
        request_data_object_resp = RequestDataObjectsResp(
            applicationId, dataObjects, result
        )

        dict = {"testing": {"test": 1}}
        self.assertEqual(
            request_data_object_resp.find_attribute("test", dict), ["testing", "test"]
        )

        dict = {"testing": {"testing": 1}}
        self.assertEqual(request_data_object_resp.find_attribute("test", dict), [])

    def test_find_attribute_static(self) -> None:
        dict = {"testing": {"test": 1}}
        self.assertEqual(
            RequestDataObjectsResp.find_attribute_static("test", dict),
            ["testing", "test"],
        )

        dict = {"testing": {"testing": 1}}
        self.assertEqual(RequestDataObjectsResp.find_attribute_static("test", dict), [])


class TestSubscribeDataobjectsReq(unittest.TestCase):
    def test__init__(self) -> None:
        applicationId = 1
        dataObjectsType = 2
        priority = 3
        order = MagicMock()
        filter = MagicMock()
        notifyTime = MagicMock()
        multiplicity = 4
        self.assertEqual(
            SubscribeDataobjectsReq(
                applicationId,
                dataObjectsType,
                priority,
                filter,
                notifyTime,
                multiplicity,
                order,
            ).application_id,
            applicationId,
        )
        self.assertEqual(
            SubscribeDataobjectsReq(
                applicationId,
                dataObjectsType,
                priority,
                filter,
                notifyTime,
                multiplicity,
                order,
            ).data_object_type,
            dataObjectsType,
        )
        self.assertEqual(
            SubscribeDataobjectsReq(
                applicationId,
                dataObjectsType,
                priority,
                filter,
                notifyTime,
                multiplicity,
                order,
            ).priority,
            priority,
        )
        self.assertEqual(
            SubscribeDataobjectsReq(
                applicationId,
                dataObjectsType,
                priority,
                filter,
                notifyTime,
                multiplicity,
                order,
            ).filter,
            filter,
        )
        self.assertEqual(
            SubscribeDataobjectsReq(
                applicationId,
                dataObjectsType,
                priority,
                filter,
                notifyTime,
                multiplicity,
                order,
            ).notify_time,
            notifyTime,
        )
        self.assertEqual(
            SubscribeDataobjectsReq(
                applicationId,
                dataObjectsType,
                priority,
                filter,
                notifyTime,
                multiplicity,
                order,
            ).multiplicity,
            multiplicity,
        )
        self.assertEqual(
            SubscribeDataobjectsReq(
                applicationId,
                dataObjectsType,
                priority,
                filter,
                notifyTime,
                multiplicity,
                order,
            ).order,
            order,
        )


class TestSubscribeDataobjectsResult(unittest.TestCase):
    def test__init__(self) -> None:
        result = 1
        self.assertEqual(SubscribeDataobjectsResult(result).result, result)

    def test__str__(self) -> None:
        self.assertEqual(str(SubscribeDataobjectsResult(0)), "successful")
        self.assertEqual(str(SubscribeDataobjectsResult(1)), "invalidITSAID")
        self.assertEqual(str(SubscribeDataobjectsResult(2)), "invalidDataObjectType")
        self.assertEqual(str(SubscribeDataobjectsResult(3)), "invalidPriority")
        self.assertEqual(str(SubscribeDataobjectsResult(4)), "invalidFilter")
        self.assertEqual(
            str(SubscribeDataobjectsResult(5)), "invalidNotificationInterval"
        )
        self.assertEqual(str(SubscribeDataobjectsResult(6)), "invalidMultiplicity")
        self.assertEqual(str(SubscribeDataobjectsResult(7)), "invalidOrder")


class TestSubscribeDataobjectsResp(unittest.TestCase):
    def test__init__(self) -> None:
        applicationId = 1
        subscriptionId = 2
        result = MagicMock()
        errorMessage = "error"
        self.assertEqual(
            SubscribeDataObjectsResp(
                applicationId, subscriptionId, result, errorMessage
            ).application_id,
            applicationId,
        )
        self.assertEqual(
            SubscribeDataObjectsResp(
                applicationId, subscriptionId, result, errorMessage
            ).subscription_id,
            subscriptionId,
        )
        self.assertEqual(
            SubscribeDataObjectsResp(
                applicationId, subscriptionId, result, errorMessage
            ).result,
            result,
        )
        self.assertEqual(
            SubscribeDataObjectsResp(
                applicationId, subscriptionId, result, errorMessage
            ).error_message,
            errorMessage,
        )


class TestPublishDataobjects(unittest.TestCase):
    def test__init__(self) -> None:
        subscriptionId = 1
        requestedData = MagicMock()
        self.assertEqual(
            PublishDataobjects(subscriptionId, requestedData).subscription_id,
            subscriptionId,
        )
        self.assertEqual(
            PublishDataobjects(subscriptionId, requestedData).requested_data,
            requestedData,
        )


class TestUnsubscribeDataobjectsReq(unittest.TestCase):
    def test__init__(self) -> None:
        applicationId = 1
        subscriptionId = 2
        self.assertEqual(
            UnsubscribeDataobjectsReq(applicationId, subscriptionId).application_id,
            applicationId,
        )
        self.assertEqual(
            UnsubscribeDataobjectsReq(applicationId, subscriptionId).subscription_id,
            subscriptionId,
        )


class TestUnsubscribeDataobjectsResult(unittest.TestCase):
    def test__init__(self) -> None:
        result = 1
        self.assertEqual(UnsubscribeDataobjectsResult(result).result, result)

    def test__str__(self) -> None:
        self.assertEqual(str(UnsubscribeDataobjectsResult(0)), "accepted")
        self.assertEqual(str(UnsubscribeDataobjectsResult(1)), "rejected")


class TestUnsubscribeDataobjectsResp(unittest.TestCase):
    def test__init__(self) -> None:
        applicationId = 1
        result = MagicMock()
        self.assertEqual(
            UnsubscribeDataobjectsResp(applicationId, result).application_id,
            applicationId,
        )
        self.assertEqual(
            UnsubscribeDataobjectsResp(applicationId, result).result, result
        )

    def test__str__(self) -> None:
        applicationId = 1
        self.assertEqual(str(UnsubscribeDataobjectsResp(applicationId, 0)), "succeed")
        self.assertEqual(str(UnsubscribeDataobjectsResp(applicationId, 1)), "failed")


class TestReferenceValue(unittest.TestCase):
    def test__init__(self) -> None:
        referenceValue = 1
        self.assertEqual(ReferenceValue(referenceValue).reference_value, referenceValue)

    def test__str__(self) -> None:
        self.assertEqual(str(ReferenceValue(0)), "boolValue")
        self.assertEqual(str(ReferenceValue(1)), "sbyteValue")
        self.assertEqual(str(ReferenceValue(2)), "byteValue")
        self.assertEqual(str(ReferenceValue(3)), "shortValue")
        self.assertEqual(str(ReferenceValue(4)), "intValue")
        self.assertEqual(str(ReferenceValue(5)), "octsValue")
        self.assertEqual(str(ReferenceValue(6)), "bitsValue")
        self.assertEqual(str(ReferenceValue(7)), "strValue")
        self.assertEqual(str(ReferenceValue(8)), "causeCodeValue")
        self.assertEqual(str(ReferenceValue(9)), "speedValue")
        self.assertEqual(str(ReferenceValue(10)), "stationIDValue")


class TestUtils(unittest.TestCase):
    def test_haversine_distance(self) -> None:
        lat1 = 1
        lon1 = 2
        lat2 = 3
        lon2 = 4
        self.assertEqual(
            Utils.haversine_distance([lat1, lon1], [lat2, lon2]), 314402.95102362486
        )

    def test_get_nested(self) -> None:
        dict = {"testing": {"test": 1}}
        self.assertEqual(Utils.get_nested(dict, ["testing", "test"]), 1)

        dict = {"testing": {"testing": 1}}
        self.assertEqual(Utils.get_nested(dict, ["testing", "test"]), None)

    def test_find_attribute(self) -> None:
        dict = {"testing": {"test": 1}}
        self.assertEqual(Utils.find_attribute("test", dict), ["testing", "test"])

        dict = {"testing": {"testing": 1}}
        self.assertEqual(Utils.find_attribute("test", dict), [])

    def test_get_station_id(self) -> None:
        dict = {"stationID": 1}
        self.assertEqual(Utils.get_station_id(dict), 1)

        dict = {"testing": {"testing": 1}}
        self.assertEqual(Utils.get_station_id(dict), None)
