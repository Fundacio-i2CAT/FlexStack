import unittest
from unittest.mock import patch

from flexstack.facilities.local_dynamic_map.ldm_classes import (
    Altitude,
    AuthorizationResult,
    AuthorizeReg,
    AuthorizeResp,
    Circle,
    Rectangle,
    AccessPermission,
    DeleteDataProviderResp,
    DeleteDataProviderResult,
    DeregisterDataConsumerAck,
    DeregisterDataConsumerResp,
    DeregisterDataProviderAck,
    DeregisterDataProviderResp,
    Direction,
    Ellipse,
    Filter,
    FilterStatement,
    GeometricArea,
    Location,
    ComparisonOperators,
    OrderTupleValue,
    OrderingDirection,
    PositionConfidenceEllipse,
    ReferencePosition,
    ReferenceValue,
    RegisterDataConsumerReq,
    RegisterDataConsumerResp,
    RegisterDataConsumerResult,
    RegisterDataProviderReq,
    RegisterDataProviderResp,
    RegisterDataProviderResult,
    RelevanceArea,
    RelevanceDistance,
    RelevanceTrafficDirection,
    RequestDataObjectsReq,
    RequestDataObjectsResp,
    RequestedDataObjectsResult,
    RevokeAuthorizationReg,
    RevokeDataProviderRegistrationResp,
    RevocationReason,
    RevocationResult,
    StationType,
    SubscribeDataObjectsResp,
    SubscribeDataobjectsReq,
    SubscribeDataobjectsResult,
    TimeValidity,
    TimestampIts,
    UnsubscribeDataConsumerAck,
    UnsubscribeDataConsumerReq,
    UnsubscribeDataConsumerResp,
    UnsubscribeDataobjectsReq,
    UnsubscribeDataobjectsResp,
    UnsubscribeDataobjectsResult,
    UpdateDataProviderResp,
    UpdateDataProviderResult,
    Utils,
    Latitude,
    Longitude,
    PublishDataobjects,
)
from flexstack.utils.time_service import ITS_EPOCH, ELAPSED_SECONDS


class TestTimestampIts(unittest.TestCase):
    def test_initialize_with_utc_timestamp_seconds(self) -> None:
        utc_seconds = ITS_EPOCH + 42
        timestamp = TimestampIts.initialize_with_utc_timestamp_seconds(utc_seconds)
        expected = (utc_seconds - ITS_EPOCH + ELAPSED_SECONDS) * 1000
        self.assertEqual(timestamp.timestamp_its, expected)

    def test_initialize_uses_time_service_when_timestamp_missing(self) -> None:
        mocked_time = ITS_EPOCH + 123
        with patch("flexstack.utils.time_service.TimeService.time", return_value=mocked_time):
            timestamp = TimestampIts.initialize_with_utc_timestamp_seconds(0)
        expected = (mocked_time - ITS_EPOCH + ELAPSED_SECONDS) * 1000
        self.assertEqual(timestamp.timestamp_its, expected)

    def test_transform_utc_seconds_to_its(self) -> None:
        utc_seconds = ITS_EPOCH + 10
        transformed = TimestampIts.transform_utc_seconds_timestamp_to_timestamp_its(utc_seconds)
        self.assertEqual(transformed, (utc_seconds - ITS_EPOCH + ELAPSED_SECONDS) * 1000)

    def test_addition_and_subtraction(self) -> None:
        ts1 = TimestampIts(1000)
        ts2 = TimestampIts(2500)
        self.assertEqual((ts1 + ts2).timestamp_its, 3500)
        self.assertEqual((ts2 - ts1).timestamp_its, 1500)

    def test_comparisons(self) -> None:
        ts1 = TimestampIts(1000)
        ts2 = TimestampIts(2000)
        self.assertTrue(ts1 < ts2)
        self.assertTrue(ts2 >= ts1)
        self.assertFalse(ts1 == ts2)
        self.assertFalse(ts1 == "not-a-timestamp")

    def test_invalid_comparison_raises_type_error(self) -> None:
        ts = TimestampIts(1000)
        with self.assertRaises(TypeError):
            ts.__lt__(object())  # type: ignore[arg-type]


class TestTimeValidity(unittest.TestCase):
    def test_to_etsi_its(self) -> None:
        unix_ts = ITS_EPOCH + 100
        validity = TimeValidity(unix_ts)
        expected = (unix_ts - ITS_EPOCH) * 1000
        self.assertEqual(validity.to_etsi_its(), expected)


class TestDataContainer(unittest.TestCase):
    def test_known_message_types(self) -> None:
        self.assertEqual(str(AccessPermission.CAM), "Cooperative Awareness Message")
        self.assertEqual(str(AccessPermission.DENM), "Decentralized Environmental Notification Message")
        self.assertEqual(str(AccessPermission.PAM), "Parking Availability Message")

    def test_invalid_permission_value_raises(self) -> None:
        with self.assertRaises(ValueError):
            AccessPermission(99)


class TestAuthorization(unittest.TestCase):
    def test_authorization_result_str(self) -> None:
        self.assertEqual(str(AuthorizationResult.SUCCESSFUL), "successful")
        self.assertEqual(str(AuthorizationResult.AUTHENTICATION_FAILURE), "authentication_failure")

    def test_authorize_reg_and_resp(self) -> None:
        permissions = (AccessPermission.CAM,)
        request = AuthorizeReg(1, permissions)
        response = AuthorizeResp(1, permissions, AuthorizationResult.INVALID_ITS_AID)
        self.assertEqual(request.application_id, 1)
        self.assertEqual(response.result, AuthorizationResult.INVALID_ITS_AID)


class TestRevocation(unittest.TestCase):
    def test_revocation_reason_and_result_str(self) -> None:
        self.assertEqual(
            str(RevocationReason.REGISTRATION_REVOKED_BY_REGISTRATION_AUTHORITY),
            "registrationRevokedByRegistrationAuthority",
        )
        self.assertEqual(str(RevocationResult.UNKNOWN_ITS_AID), "unknownITS-AID")

    def test_revoke_authorization_reg(self) -> None:
        reg = RevokeAuthorizationReg(7, RevocationReason.REGISTRATION_PERIOD_EXPIRED)
        self.assertEqual(reg.reason, RevocationReason.REGISTRATION_PERIOD_EXPIRED)


class TestRegisterDataProvider(unittest.TestCase):
    def test_to_dict_and_from_dict(self) -> None:
        permissions = (AccessPermission.CAM,)
        validity = TimeValidity(ITS_EPOCH + 10)
        request = RegisterDataProviderReq(5, permissions, validity)

        data = request.to_dict()
        self.assertEqual(data["application_id"], 5)
        self.assertEqual(data["access_permissions"], permissions)
        self.assertEqual(data["time_validity"], validity.time)

        recreated = RegisterDataProviderReq.from_dict(data)
        self.assertEqual(recreated, request)

    def test_from_dict_missing_fields_raises(self) -> None:
        with self.assertRaises(ValueError):
            RegisterDataProviderReq.from_dict({"time_validity": 1})

    def test_result_and_response(self) -> None:
        result = RegisterDataProviderResult.ACCEPTED
        self.assertEqual(str(result), "accepted")
        response = RegisterDataProviderResp(2, (AccessPermission.CAM,), result)
        self.assertEqual(response.result, RegisterDataProviderResult.ACCEPTED)


class TestDeregisterDataProvider(unittest.TestCase):
    def test_ack_and_response(self) -> None:
        self.assertEqual(str(DeregisterDataProviderAck.ACCEPTED), "accepted")
        response = DeregisterDataProviderResp(3, DeregisterDataProviderAck.REJECTED)
        self.assertEqual(response.result, DeregisterDataProviderAck.REJECTED)

    def test_revoke_data_provider_registration_resp(self) -> None:
        resp = RevokeDataProviderRegistrationResp(9)
        self.assertEqual(resp.application_id, 9)


class TestPositioning(unittest.TestCase):
    def test_latitude_and_longitude_conversion(self) -> None:
        self.assertEqual(Latitude.convert_latitude_to_its_latitude(42.1234567), 421234567)
        self.assertEqual(Latitude.convert_latitude_to_its_latitude(420.0), 900000001)
        self.assertEqual(Longitude.convert_longitude_to_its_longitude(1.234567), 12345670)
        self.assertEqual(Longitude.convert_longitude_to_its_longitude(181.5), 1800000001)

    def test_reference_position_to_dict(self) -> None:
        position = ReferencePosition(
            latitude=1,
            longitude=2,
            position_confidence_ellipse=PositionConfidenceEllipse(3, 4, 5),
            altitude=Altitude(6, 7),
        )
        expected = {
            "latitude": 1,
            "longitude": 2,
            "positionConfidenceEllipse": {
                "semiMajorConfidence": 3,
                "semiMinorConfidence": 4,
                "semiMajorOrientation": 5,
            },
            "altitude": {"altitudeValue": 6, "altitudeConfidence": 7},
        }
        self.assertEqual(position.to_dict(), expected)

    def test_update_with_gpsd_tpv(self) -> None:
        tpv = {"lat": 41.0, "lon": 2.0, "epx": 1, "epy": 2, "track": 3, "alt": 4, "epv": 5}
        updated = ReferencePosition.update_with_gpsd_tpv(tpv)
        self.assertEqual(updated.latitude, Latitude.convert_latitude_to_its_latitude(41.0))
        self.assertEqual(updated.longitude, Longitude.convert_longitude_to_its_longitude(2.0))
        self.assertEqual(updated.altitude.altitude_value, 4)


class TestStationAndDirection(unittest.TestCase):
    def test_station_type_str(self) -> None:
        self.assertEqual(str(StationType(0)), "Unknown")
        self.assertEqual(str(StationType(15)), "Road-Side-Unit")

    def test_direction_str(self) -> None:
        self.assertEqual(str(Direction(0)), "north")
        self.assertEqual(str(Direction(7200)), "east")
        self.assertEqual(str(Direction(9999)), "unknown")

    def test_geometric_primitives(self) -> None:
        circle = Circle(10)
        rectangle = Rectangle(2, 3, Direction(0))
        ellipse = Ellipse(4, 5, Direction(7200))
        self.assertEqual(circle.radius, 10)
        self.assertEqual(rectangle.a_semi_axis, 2)
        self.assertEqual(ellipse.azimuth_angle.direction, 7200)


class TestRelevance(unittest.TestCase):
    def test_relevance_distance_str_and_compare(self) -> None:
        rd = RelevanceDistance(0)
        self.assertEqual(str(rd), "lessThan50m")
        self.assertTrue(rd.compare_with_int(25))
        self.assertFalse(rd.compare_with_int(55))
        with self.assertRaises(ValueError):
            RelevanceDistance(99).compare_with_int(10)

    def test_relevance_area(self) -> None:
        area = RelevanceArea(RelevanceDistance(1), RelevanceTrafficDirection.DOWNSTREAM_TRAFFIC)
        self.assertEqual(area.relevance_distance.relevance_distance, 1)


class TestLocation(unittest.TestCase):
    def test_initializer(self) -> None:
        location = Location.initializer(latitude=1, longitude=2, radius=50)
        self.assertEqual(location.reference_position.latitude, 1)
        circle = location.reference_area.geometric_area.circle
        self.assertIsNotNone(circle)
        if circle is not None:
            self.assertEqual(circle.radius, 50)

    def test_location_builder_circle(self) -> None:
        location = Location.location_builder_circle(10, 20, 30, 40)
        self.assertEqual(location.reference_position.latitude, 10)
        circle = location.reference_area.geometric_area.circle
        self.assertIsNotNone(circle)
        if circle is not None:
            self.assertEqual(circle.radius, 40)
        self.assertEqual(location.reference_area.relevance_area.relevance_distance.relevance_distance, 1)


class TestProviderResponses(unittest.TestCase):
    def test_update_data_provider_result_and_resp(self) -> None:
        self.assertEqual(str(UpdateDataProviderResult.SUCCEED), "succeed")
        response = UpdateDataProviderResp(1, 2, UpdateDataProviderResult.INCONSISTENT_DATA_OBJECT_TYPE)
        self.assertEqual(response.result, UpdateDataProviderResult.INCONSISTENT_DATA_OBJECT_TYPE)

    def test_delete_data_provider_result_and_resp(self) -> None:
        self.assertEqual(str(DeleteDataProviderResult.SUCCEED), "succeed")
        response = DeleteDataProviderResp(1, 2, DeleteDataProviderResult.FAILED)
        self.assertEqual(response.result, DeleteDataProviderResult.FAILED)


class TestDataConsumer(unittest.TestCase):
    def test_register_data_consumer(self) -> None:
        result = RegisterDataConsumerResult.WARNING
        self.assertEqual(str(result), "warning")
        req = RegisterDataConsumerReq(1, (AccessPermission.CAM,), GeometricArea(None, None, None))
        resp = RegisterDataConsumerResp(1, req.access_permisions, result)
        self.assertEqual(resp.result, RegisterDataConsumerResult.WARNING)

    def test_deregister_and_unsubscribe(self) -> None:
        self.assertEqual(str(DeregisterDataConsumerAck.SUCCEED), "succeed")
        dereg_resp = DeregisterDataConsumerResp(1, DeregisterDataConsumerAck.FAILED)
        self.assertEqual(dereg_resp.ack, DeregisterDataConsumerAck.FAILED)

        self.assertEqual(str(UnsubscribeDataConsumerAck.ACCEPTED), "accepted")
        unsub_req = UnsubscribeDataConsumerReq(1, 99)
        unsub_resp = UnsubscribeDataConsumerResp(1, 99, UnsubscribeDataConsumerAck.FAILED)
        self.assertEqual(unsub_req.subscription_id, 99)
        self.assertEqual(unsub_resp.result, UnsubscribeDataConsumerAck.FAILED)


class TestRequestDataObjects(unittest.TestCase):
    def test_filter_out_by_data_object_type(self) -> None:
        search_result = (
            {"dataObject": {"cam": {"value": 1}}, "id": 1},
            {"dataObject": {"denm": {"value": 2}}, "id": 2},
        )
        filtered = RequestDataObjectsReq.filter_out_by_data_object_type(search_result, (2,))
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]["id"], 1)

    def test_get_object_type_from_data_object(self) -> None:
        self.assertEqual(RequestDataObjectsReq.get_object_type_from_data_object({"cam": {}}), 2)
        self.assertIsNone(RequestDataObjectsReq.get_object_type_from_data_object({"unknown": {}}))

    def test_find_attribute_helpers(self) -> None:
        response = RequestDataObjectsResp(1, tuple(), RequestedDataObjectsResult.SUCCEED)
        data_object = {"a": {"b": {"c": 5}}}
        self.assertEqual(response.find_attribute("c", data_object), ["a", "b", "c"])
        self.assertEqual(RequestDataObjectsResp.find_attribute_static("c", data_object), ["a", "b", "c"])
        self.assertEqual(RequestDataObjectsResp.find_attribute_static("missing", data_object), [])


class TestSubscribeDataobjects(unittest.TestCase):
    def test_results_and_response(self) -> None:
        self.assertEqual(str(SubscribeDataobjectsResult.SUCCESSFUL), "successful")
        req = SubscribeDataobjectsReq(
            application_id=1,
            data_object_type=(2,),
            priority=1,
            filter=Filter(FilterStatement("cam.generationDeltaTime", ComparisonOperators.EQUAL, 2)),
            notify_time=TimestampIts(1000),
            multiplicity=1,
            order=(OrderTupleValue("cam.generationDeltaTime", OrderingDirection.ASCENDING),),
        )
        self.assertEqual(req.priority, 1)
        resp = SubscribeDataObjectsResp(1, 10, SubscribeDataobjectsResult.INVALID_FILTER, "invalid filter")
        self.assertEqual(resp.error_message, "invalid filter")

    def test_publish_dataobjects(self) -> None:
        publication = PublishDataobjects(7, ("cam", "denm"))
        self.assertEqual(publication.requested_data, ("cam", "denm"))


class TestUnsubscribeDataobjects(unittest.TestCase):
    def test_unsubscribe_result_and_resp(self) -> None:
        self.assertEqual(str(UnsubscribeDataobjectsResult.ACCEPTED), "accepted")
        req = UnsubscribeDataobjectsReq(1, 2)
        resp = UnsubscribeDataobjectsResp(1, 2, UnsubscribeDataobjectsResult.REJECTED)
        self.assertEqual(req.subscription_id, 2)
        self.assertEqual(resp.result, UnsubscribeDataobjectsResult.REJECTED)


class TestReferenceValue(unittest.TestCase):
    def test_reference_value_str(self) -> None:
        self.assertEqual(str(ReferenceValue.BOOL_VALUE), "boolValue")
        self.assertEqual(str(ReferenceValue.STATION_ID_VALUE), "stationIDValue")


class TestUtils(unittest.TestCase):
    def test_haversine_distance_same_point(self) -> None:
        distance = Utils.haversine_distance((41.0, 2.0), (41.0, 2.0))
        self.assertAlmostEqual(distance, 0.0, places=6)

    def test_get_nested_and_find_attribute(self) -> None:
        data = {"a": {"b": {"c": 5}}}
        self.assertEqual(Utils.get_nested(data, ["a", "b", "c"]), 5)
        self.assertIsNone(Utils.get_nested(data, ["missing"]))
        self.assertEqual(Utils.find_attribute("c", data), ["a", "b", "c"])

    def test_get_station_id(self) -> None:
        data = {"header": {"stationID": [123]}}
        self.assertEqual(Utils.get_station_id(data), 123)
        data_lower = {"header": {"stationId": [456]}}
        self.assertEqual(Utils.get_station_id(data_lower), 456)

    def test_check_field(self) -> None:
        data = {"items": [{"name": "entry"}, {"value": 5}]}
        self.assertTrue(Utils.check_field(data, "value"))
        self.assertFalse(Utils.check_field(data, "missing"))

    def test_convert_coordinates_and_distances(self) -> None:
        converted = Utils.convert_etsi_coordinates_to_normal((100000000, 200000000))
        self.assertEqual(converted, (10.0, 20.0))
        self.assertAlmostEqual(Utils.euclidian_distance((0, 0), (3, 4)), 5.0)


if __name__ == "__main__":
    unittest.main()
