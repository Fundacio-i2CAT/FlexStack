"""
Classes as specified in the ETSI ETSI EN 302 895 V1.1.1 (2014-09). Annex B.

A few expeptions:
    - ASN.1 is not used.
    - Permissions and Permissionslist is not used, instead DataContainer and list[DataContainer] is used.
    - DataObject is not used, instead a list of strings is used.
    - Timestamp is not used, instead a int is used.
    - DataContainer modified to custom format.
    - SubscriptionId is not used, instead a int is used. TODO: Check if value is in the 0..65535 range.
    - Multiplicity is not used, instead a int is used. TODO: Check if value is in the 0..255 range.
    - Distance is not used, instead a int is used. TODO: Check if value is in the 0..65535 range.
    - UserPriority is not used, instead a int is used. TODO: Check if value is in the 0..255 range.
    - Attribute is not used, instead a int is used. TODO: Check if is in the 0..65535 range and is OCTET.
    - DataContainer is specified in a custom way, instead of using ASN.1.
    - ReferenceValue does not follow the standard fully, it implements a Python-friendly version.
"""

from __future__ import annotations
from ...utils.time_service import TimeService, ITS_EPOCH, ELAPSED_SECONDS
import math

from .ldm_constants import (
    EATH_RADIUS,
    DATA_OBJECT_TYPE_ID,
    DENM,
    CAM,
    POI,
    SPATEM,
    MAPEM,
    IVIM,
    EV_RSR,
    TISTPGTRANSACTION,
    SREM,
    SSEM,
    EVSCN,
    SAEM,
    RTCMEM,
    CPM,
    IMZM,
    VAM,
    DSM,
    PCIM,
    PCVM,
    MCM,
    PAM,
)


class TimestampIts:
    """
    TimestamptITS class to handle timestamps. Timestamps are expressed in ETSI Timestamp format.
    """

    def __init__(self, utc_timestamp_seconds: int = None) -> None:
        """
        Initializes the TimestampIts class.

        Parameters
        ----------
        utc_timestamp_seconds : int
            The UTC timestamp in seconds since the epoch (UTC).
            If None, it will be set to the current UTC timestamp.
        """
        self.timestamp = 0
        if utc_timestamp_seconds:
            self.timestamp = self.__transform_utc_seconds_timestamp_to_timestamp_its(
                utc_timestamp_seconds)
        else:
            self.timestamp = self.__transform_utc_seconds_timestamp_to_timestamp_its(
                int(TimeService.time()))

    @staticmethod
    def initialize_with_timestamp_its(timestamp_its: int) -> TimestampIts:
        """
        Initializes the TimestampIts class with a given ETSI ITS timestamp.

        Parameters
        ----------
        timestamp_its : int
            The timestamp in ETSI ITS format.

        Returns
        -------
        TimestampIts
            An instance of the TimestampIts class.
        """
        to_return: TimestampIts = TimestampIts(ITS_EPOCH + ELAPSED_SECONDS)
        to_return.timestamp = timestamp_its
        return to_return

    def __transform_utc_seconds_timestamp_to_timestamp_its(self, utc_timestamp_seconds: int) -> int:
        """
        Method to transform a UTC timestamp to a ETSI ITS timestamp.

        Parameters
        ----------
        utc_timestamp_seconds : int
            UTC timestamp in seconds to be converted.

        Returns
        -------
        int
            Converted ITS timestamp.
        """
        return int((utc_timestamp_seconds - ITS_EPOCH + ELAPSED_SECONDS) * 1000)

    def __add__(self, other: TimestampIts) -> TimestampIts:
        """
        Overloads the addition operator for TimestampIts objects.

        Parameters
        ----------
        other : TimestampIts
            Another TimestampIts object.

        Returns
        -------
        TimestampIts
            A new TimestampIts object with the combined timestamp.
        """
        if not isinstance(other, TimestampIts):
            raise TypeError("Operand must be of type TimestampIts")
        return TimestampIts.initialize_with_timestamp_its(self.timestamp + other.timestamp)

    def __sub__(self, other: TimestampIts) -> TimestampIts:
        """
        Overloads the subtraction operator for TimestampIts objects.

        Parameters
        ----------
        other : TimestampIts
            Another TimestampIts object.

        Returns
        -------
        TimestampIts
            A new TimestampIts object with the subtracted timestamp.
        """
        if not isinstance(other, TimestampIts):
            raise TypeError("Operand must be of type TimestampIts")
        return TimestampIts.initialize_with_timestamp_its(self.timestamp - other.timestamp)

    def __eq__(self, other: TimestampIts) -> bool:
        """
        Overloads the equality operator for TimestampIts objects.

        Parameters
        ----------
        other : TimestampIts
            Another TimestampIts object.

        Returns
        -------
        bool
            True if timestamps are equal, False otherwise.
        """
        if not isinstance(other, TimestampIts):
            return False
        return self.timestamp == other.timestamp

    def __lt__(self, other: TimestampIts) -> bool:
        """
        Overloads the less-than operator for TimestampIts objects.

        Parameters
        ----------
        other : TimestampIts
            Another TimestampIts object.

        Returns
        -------
        bool
            True if self.timestamp is less than other.timestamp, False otherwise.
        """
        if not isinstance(other, TimestampIts):
            raise TypeError("Operand must be of type TimestampIts")
        return self.timestamp < other.timestamp

    def __le__(self, other: TimestampIts) -> bool:
        """
        Overloads the less-than-or-equal-to operator for TimestampIts objects.

        Parameters
        ----------
        other : TimestampIts
            Another TimestampIts object.

        Returns
        -------
        bool
            True if self.timestamp is less than or equal to other.timestamp, False otherwise.
        """
        if not isinstance(other, TimestampIts):
            raise TypeError("Operand must be of type TimestampIts")
        return self.timestamp <= other.timestamp

    def __gt__(self, other: TimestampIts) -> bool:
        """
        Overloads the greater-than operator for TimestampIts objects.

        Parameters
        ----------
        other : TimestampIts
            Another TimestampIts object.

        Returns
        -------
        bool
            True if self.timestamp is greater than other.timestamp, False otherwise.
        """
        if not isinstance(other, TimestampIts):
            raise TypeError("Operand must be of type TimestampIts")
        return self.timestamp > other.timestamp

    def __ge__(self, other: TimestampIts) -> bool:
        """
        Overloads the greater-than-or-equal-to operator for TimestampIts objects.

        Parameters
        ----------
        other : TimestampIts
            Another TimestampIts object.

        Returns
        -------
        bool
            True if self.timestamp is greater than or equal to other.timestamp, False otherwise.
        """
        if not isinstance(other, TimestampIts):
            raise TypeError("Operand must be of type TimestampIts")
        return self.timestamp >= other.timestamp


class TimeValidity:
    """
    Class that represents the time validity of a data object. Time is expressed in Normal Unix Format.
    """

    def __init__(self, time: int) -> None:
        self.time = time

    def to_etsi_its(self) -> int:
        """
        Method to convert the time validity from Normal Unix Format to ETSI ITS Timestamp.

        Returns
        -------
        int
            Converted timestamp in ETSI ITS format.
        """
        return int(((self.time - ITS_EPOCH)) * 1000)


class DataContainer:
    """
    Class currently not used, as no real value is added. Currenly a datacontainer is treated as a list of dicts, maybe
    in the future some added funcionalities will be added.
    """

    def __init__(self, data_container: dict) -> None:
        self.data_container = data_container

    def __str__(self) -> str:
        type_mapping = {
            CAM: "Cooperative Awareness Message",
            DENM: "Decentralized Environmental Notification Message",
            POI: "Point of Interest Message",
            SPATEM: "Signal and Phase and Timing Extended Message",
            MAPEM: "MAP Extended Message",
            IVIM: "Vehicle Information Message",
            EV_RSR: "Electric Vehicle Recharging Spot Reservation Message",
            TISTPGTRANSACTION: "Tyre Information System and Tyre Pressure Gauge Interoperability",
            SREM: "Signal Request Extended Message",
            SSEM: "Signal Request Status Extended Message",
            EVSCN: "Electrical Vehicle Charging Spot Notification Message",
            SAEM: "Services Announcement Extended Message",
            RTCMEM: "Radio Technical Commision for Maritime Services Extended Message",
            CPM: "Collective Perception Message",
            IMZM: "Interface Management Zone Message",
            VAM: "Vulnerable Road User Awareness Message",
            DSM: "Diagnosis Logging and Status Message",
            PCIM: "Parking Control Infrastucture Message",
            PCVM: "Parking Control Vehicle Message",
            MCM: "Maneuver Coordination Message",
            PAM: "Parking Availability Message",
        }

        for data_type_id, message in type_mapping.items():
            if DATA_OBJECT_TYPE_ID[data_type_id] in self.data_container.keys():
                return message

        return "unknown"


class AuthorizationResult:
    """
    Class that represents the result of an authorization request as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(self, result: int) -> None:
        self.result = result

    def __str__(self) -> str:
        if self.result == 0:
            return "successful"
        if self.result == 1:
            return "invalidITS-AID"
        if self.result == 2:
            return "authentiticaionFailure"
        if self.result == 3:
            return "applicationNotAuthorized"
        raise ValueError(
            "AuthorizationResult string synonym not found according to ETSI TS 102 894-2 V2.2.1 (2023-10)")


class AuthorizeReg:
    """
    Class that represents an authorization request as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(self, application_id: int, access_permissions: list[DataContainer]) -> None:
        self.application_id = application_id
        self.access_permissions = access_permissions


class AuthorizeResp:
    """
    Class that represents an authorization response as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(
        self,
        application_id: int,
        access_permissions: list[DataContainer],
        result: AuthorizationResult,
    ) -> None:
        self.application_id = application_id
        self.access_permissions = access_permissions
        self.result = result


class RevocationReason:
    """
    Class that represents an Revocation Reason as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(self, reason: int) -> None:
        self.reason = reason

    def __str__(self) -> str:
        if self.reason == 0:
            return "registratioRevokedByRegistrationAuthority"
        if self.reason == 1:
            return "registrationPeriodExpired"
        raise ValueError(
            "RevocationReason string synonym not found according to ETSI TS 102 894-2 V2.2.1 (2023-10)")


class RevocationResult:
    """
    Class that represents a Revocation Result as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(self, result: int) -> None:
        self.result = result

    def __str__(self) -> str:
        if self.result == 0:
            return "successful"
        if self.result == 1:
            return "invalidITS-AID"
        if self.result == 2:
            return "unknownITS-AID"
        raise ValueError(
            "RevocationResult string synonym not found according to ETSI TS 102 894-2 V2.2.1 (2023-10)")


class RevokeAuthorizationReg:
    """
    Class that represents a Revoke Authorization Registration as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(self, application_id: int, reason: RevocationResult) -> None:
        self.application_id = application_id
        self.reason = reason


class RegisterDataProviderReq:
    """
    Class that represents a Register Data Provider Request as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(
        self,
        application_id: int,
        access_permissions: list,
        time_validity: TimeValidity,
    ) -> None:
        self.application_id = application_id
        self.access_permisions = access_permissions
        self.time_validity = time_validity

    def to_dict(self) -> dict:
        """
        Method that creates a dict respresenting the class.

        Parameters
        ----------
        None

        Returns
        --------
        Dict
            A dict containing the information (attributres) of the class
        """

        return {
            "application_id": self.application_id,
            "access_permissions": self.access_permisions,
            "time_validity": self.time_validity.time,
        }

    @staticmethod
    def from_dict(data: dict) -> "RegisterDataProviderReq":
        """
        Method that creates an instance of the class from a dictionary.

        Parameters
        ----------
        data : dict
            Dictionary containing the data to construct the class instance.

        Returns
        -------
        RegisterDataProviderReq
            An instance of the RegisterDataProviderReq class.
        """
        application_id = data.get("application_id")
        access_permissions = data.get("access_permissions")
        time_validity = TimeValidity(data.get("time_validity"))

        return RegisterDataProviderReq(
            application_id=application_id,
            access_permissions=access_permissions,
            time_validity=time_validity,
        )


class RegisterDataProviderResult:
    """
    Class that represents a Register Data Provider Result as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(self, result) -> None:
        self.result = result

    def __str__(self) -> str:
        if self.result == 0:
            return "accepted"
        if self.result == 1:
            return "rejected"
        raise ValueError(
            "RegisterDataProviderResult string synonym not found according to \
                         ETSI TS 102 894-2 V2.2.1 (2023-10)"
        )


class RegisterDataProviderResp:
    """
    Class that represent a Register Data Provder Response as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(
        self,
        application_id: int,
        access_permisions: list,
        result: RegisterDataProviderResult,
    ) -> None:
        self.application_id = application_id
        self.access_permisions = access_permisions
        self.result = result


class DeregisterDataProviderAck:
    """
    Class that represent Deregister Data Provider Ack as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(self, result: int) -> None:
        self.result = result

    def __str__(self) -> str:
        if self.result == 0:
            return "accepted"
        if self.result == 1:
            return "rejected"
        raise ValueError(
            "DeregisterDataProviderAck string synonym not found according \
                         to ETSI TS 102 894-2 V2.2.1 (2023-10)"
        )


class DeregisterDataProviderReq:
    """
    Class that represents Deregister Data Provider Request as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(self, application_id: int) -> None:
        self.application_id = application_id


class DeregisterDataProviderResp:
    """
    Class that represents Deregister Data Provider Response as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(self, application_id: int, result: DeregisterDataProviderAck) -> None:
        self.application_id = application_id
        self.result = result


class RevokeDataProviderRegistrationResp:
    """
    Class that represents Revoke Data Provider Registration Response as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(self, application_id: int) -> None:
        self.application_id = application_id


class PositionConfidenceEllipse:
    """
    Class that represents Position Confidence Ellipse as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(self, semi_major_confidence, semi_minor_confidence, semi_major_orientation) -> None:
        self.semi_major_confidence = semi_major_confidence
        self.semi_minor_confidence = semi_minor_confidence
        self.semi_major_orientation = semi_major_orientation


class Altitude:
    """
    Class that represents Altitude as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(self, altitude_value: int, altitude_confidence: int) -> None:
        """
        Initializes the Altitude class.

        Parameters
        ----------
        altitude_value : int
            The altitude value in ETSI Altitude format (0,01 metre).
        altitude_confidence : int
            The altitude confidence in ETSI Altitude (0,01 metre).

        Returns
        -------
        None
        """
        self.altitude_value = altitude_value
        self.altitude_confidence = altitude_confidence


class Latitude:
    """
    Class that represent Latitude as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    @staticmethod
    def convert_latitude_to_its_latitude(latitude: float) -> int:
        """
        Method to convert latitude into its latitude.

        Parameters
        ----------
        latitude : float
            Latitude to be converted (decimal coordiantes).

        Returns
        -------
        int
            Converted (its) latitude.
        """
        its_latitude = int(latitude * 10000000)
        if its_latitude < -900000000 or its_latitude > 900000000:
            return 900000001
        return its_latitude


class Longitude:
    """
    Class that represent Longitude as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    @staticmethod
    def convert_longitude_to_its_longitude(longitude: float) -> int:
        """
        Static method to convert longitude into its longitude.

        Parameters
        ----------
        longitude : float
            Longitude to be converted (decimal coordiantes).

        Returns
        -------
        int
            Converted (its) longitude.
        """
        its_longitude = int(longitude * 10000000)
        if its_longitude <= -1800000000 or its_longitude > 1800000000:
            return 1800000001
        return its_longitude


class ReferencePosition:
    """
    Class that represent Reference Position as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(
        self,
        latitude: int,
        longitude: int,
        position_confidence_ellipse: PositionConfidenceEllipse,
        altitude: Altitude,
    ) -> None:
        self.latitude = latitude
        self.longitude = longitude
        self.position_confidence_ellipse = position_confidence_ellipse
        self.altitude = altitude

    def to_dict(self) -> dict:
        """
        Method to create dictionary with the reference position.

        Returns
        -------
        dict
            Dictionary with the reference position in the format specified in ETSI TS 102 894-2 V2.2.1 (2023-10).
        """
        return {
            "latitude": self.latitude,
            "longitude": self.longitude,
            "positionConfidenceEllipse": {
                "semiMajorConfidence": self.position_confidence_ellipse.semi_major_confidence,
                "semiMinorConfidence": self.position_confidence_ellipse.semi_minor_confidence,
                "semiMajorOrientation": self.position_confidence_ellipse.semi_major_orientation,
            },
            "altitude": {
                "altitudeValue": self.altitude.altitude_value,
                "altitudeConfidence": self.altitude.altitude_confidence,
            },
        }

    def update_with_gpsd_tpv(self, tpv: dict) -> None:
        """
        Updates the reference position with a TPV from gpsd.

        Parameters
        ----------
        tpv : dict
            Dictionary containing the location data.

        TODO: In the future the altitude and the confidence ellipses should be updated as well.
        """
        self.latitude = Latitude.convert_latitude_to_its_latitude(tpv["lat"])
        self.longitude = Longitude.convert_longitude_to_its_longitude(
            tpv["lon"])


class StationType:
    """
    Class that represent Station Type as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(self, station_type: int) -> None:
        self.station_type = station_type

    def __str__(self):
        type_mapping = {
            0: "Unknown",
            1: "Pedestrian",
            2: "Cyclist",
            3: "Moped",
            4: "Motorcycle",
            5: "Passenger Car",
            6: "Bus",
            7: "Light Truck",
            8: "Heavy Truck",
            9: "Trailer",
            10: "Special Vehicles",
            11: "Tram",
            15: "Road-Side-Unit",
        }

        return type_mapping.get(self.station_type, "Unknown")


class Direction:
    """
    Class that represents Direction as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(self, direction: int) -> None:
        self.direction = direction

    def __str__(self) -> str:
        if self.direction == 0:
            return "north"
        if self.direction == 7200:
            return "east"
        if self.direction == 14400:
            return "south"
        if self.direction == 21600:
            return "west"
        return "unknown"


class Circle:
    """
    Class that represents Circle as speficied in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(self, radius: int) -> None:
        self.radius = radius


class Rectangle:
    """
    Class that represents Rectangle as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(self, a_semi_axis: int, b_semi_axis: int, azimuth_angle: Direction) -> None:
        self.a_semi_axis = a_semi_axis
        self.b_semi_axis = b_semi_axis
        self.azimuth_angle = azimuth_angle


class Ellipse:
    """
    Class that represents Ellipse as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(self, a_semi_axis: int, b_semi_axis: int, azimuth_angle: Direction) -> None:
        self.a_semi_axis = a_semi_axis
        self.b_semi_axis = b_semi_axis
        self.azimuth_angle = azimuth_angle


class RelevanceTrafficDirection:
    """
    Class that represents Relevance Traffic Direction as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(self, relevance_traffic_direction: int) -> None:
        self.relevance_traffic_direction = relevance_traffic_direction

    def __str__(self) -> str:
        if self.relevance_traffic_direction == 0:
            return "allTrafficDirections"
        if self.relevance_traffic_direction == 1:
            return "upstreamTraffic"
        if self.relevance_traffic_direction == 2:
            return "downstreamTraffic"
        if self.relevance_traffic_direction == 3:
            return "oppositeTraffic"
        raise ValueError(
            "RelevanceTrafficDirection string synonym not found according \
                         to ETSI TS 102 894-2 V2.2.1 (2023-10)"
        )


class RelevanceDistance:
    """
    Class that represents Relevance Distance as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(self, relevance_distance: int) -> None:
        self.relevance_distance = relevance_distance

    def __str__(self) -> str:
        distance_mapping = {
            0: "lessThan50m",
            1: "lessThan100m",
            2: "lessThan200m",
            3: "lessThan500m",
            4: "lessThan1000m",
            5: "lessThan5km",
            6: "lessThan10km",
            7: "over20km",
        }

        return distance_mapping.get(self.relevance_distance, "unknown")

    def compare_with_int(self, value: int) -> bool:
        """
        Method to compare a integer (represting a distance between two points) with the
        value for the relevance distance.

        Parameters
        ----------
        value : int
            The value to compare with the relevance distance.
        """
        distance_mapping = {
            0: value < 50,
            1: value < 100,
            2: value < 200,
            3: value < 500,
            4: value < 1000,
            5: value < 5000,
            6: value < 10000,
            7: value > 20000,
        }

        if self.relevance_distance in distance_mapping:
            return distance_mapping[self.relevance_distance]

        raise ValueError(
            f"""RelevanceDistance relevance distance, {self.relevance_distance},
            not valid according to ETSI EN 302 895 V1.1.1 (2014-09). Must be in the range 0..7."""
        )


class RelevanceArea:
    """
    Class that represents Relevance Area as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(
        self,
        relevance_distance: RelevanceDistance,
        relevance_traffic_direction: RelevanceTrafficDirection,
    ) -> None:
        self.relevance_distance = relevance_distance
        self.relevance_traffic_direction = relevance_traffic_direction


class GeometricArea:
    """
    Class that represents Geometric Area as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(self, circle: Circle, rectangle: Rectangle, ellipse: Ellipse) -> None:
        self.circle = circle
        self.rectangle = rectangle
        self.ellipse = ellipse


class ReferenceArea:
    """
    Class that represents Reference Area as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(self, geometric_area: GeometricArea, relevance_area: RelevanceArea) -> None:
        self.geometric_area = geometric_area
        self.relevance_area = relevance_area


class Location:
    """
    Class that represents Location as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(self, reference_position: ReferencePosition, reference_area: ReferenceArea) -> None:
        self.reference_position = reference_position
        self.reference_area = reference_area

    @staticmethod
    def initializer(
        latitude=0,
        longitude=0,
        semi_major_confidence=0,
        semi_major_orientation=0,
        semi_minor_condifence=0,
        altitude_value=0,
        altitude_confidence=0,
        radius=2000,
        rectangle=None,
        ellipse=None,
        relevance_distance=4,
        relevance_traffic_direction=0,
    ) -> "Location":
        """
        Function to intialize a Location object. The location service callback should be used to update all the relevant fields.
        """
        reference_position = ReferencePosition(
            latitude=latitude,
            longitude=longitude,
            position_confidence_ellipse=PositionConfidenceEllipse(
                semi_major_confidence=semi_major_confidence,
                semi_major_orientation=semi_major_orientation,
                semi_minor_confidence=semi_minor_condifence,
            ),
            altitude=Altitude(altitude_value=altitude_value,
                              altitude_confidence=altitude_confidence),
        )
        reference_area = ReferenceArea(
            geometric_area=GeometricArea(circle=Circle(
                radius=radius), rectangle=rectangle, ellipse=ellipse),
            relevance_area=RelevanceArea(
                relevance_distance=RelevanceDistance(
                    relevance_distance=relevance_distance),
                relevance_traffic_direction=RelevanceTrafficDirection(
                    relevance_traffic_direction=relevance_traffic_direction
                ),
            ),
        )

        return Location(reference_position, reference_area)

    def location_service_callback(self, tpv: dict) -> None:
        """
        When the location is tracking the position of the vehicle, this method should be called to update the location
        of the vehicle.

        Parameters
        ----------
        tpv : dict
            Dictionary containing the location data.
        """
        self.reference_position.update_with_gpsd_tpv(tpv)

    @staticmethod
    def location_builder_circle(latitude: int, longitude: int, altitude: int, radius: int) -> "Location":
        """
        Static method to create a location, ETSI class, with a circle as the geometric area as defined
        in ETSI TS 102 894-2 V2.2.1 (2023-10).

        Parameters
        ----------
        latitude : int
            Latitude of the center of the circle in 10^-7 degree as specified in ETSI TS 102 894-2 V2.2.1 (2023-10).
        longitude : int
            Longitude of the center of the circle 10^-7 degree as specified in ETSI TS 102 894-2 V2.2.1 (2023-10).
        altitude : int
            Altitude of the center of the circle in 0,01 metre as specified in ETSI TS 102 894-2 V2.2.1 (2023-10).
        radius : int
            Radius of the circle in 1.0 metre as specified in ETSI EN 302 895 V1.1.1 (2014-09).

        Returns
        -------
        Self
            Location object.
        """
        reference_position = ReferencePosition(
            latitude=latitude,
            longitude=longitude,
            position_confidence_ellipse=PositionConfidenceEllipse(
                semi_major_confidence=0,
                semi_major_orientation=0,
                semi_minor_confidence=0,
            ),
            altitude=Altitude(altitude_value=altitude, altitude_confidence=0),
        )

        reference_area = ReferenceArea(
            geometric_area=GeometricArea(circle=Circle(
                radius=radius), rectangle=None, ellipse=None),
            relevance_area=RelevanceArea(
                relevance_distance=RelevanceDistance(relevance_distance=1),
                relevance_traffic_direction=RelevanceTrafficDirection(
                    relevance_traffic_direction=0),
            ),
        )
        return Location(reference_area=reference_area, reference_position=reference_position)


class AddDataProviderReq:
    """
    Class that represents Add Data Provider Request as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(
        self,
        application_id: int,
        timestamp: TimestampIts,
        location: Location,
        data_object: dict,
        time_validity: TimeValidity,
    ) -> None:
        self.application_id = application_id
        self.timestamp = timestamp
        self.location = location
        self.data_object = data_object
        self.time_validity = time_validity

    def __iter__(self):
        # pylint: disable=line-too-long
        yield "application_id", self.application_id
        yield "timestamp", self.timestamp.timestamp
        yield "location", {
            "referencePosition": {
                "latitude": self.location.reference_position.latitude,
                "longitude": self.location.reference_position.longitude,
                "positionConfidenceEllipse": {
                    "semiMajorConfidence": self.location.reference_position.position_confidence_ellipse.semi_major_confidence,
                    "semiMinorConfidence": self.location.reference_position.position_confidence_ellipse.semi_minor_confidence,
                    "semiMajorOrientation": self.location.reference_position.position_confidence_ellipse.semi_minor_confidence,
                },
                "altitude": {
                    "altitudeValue": self.location.reference_position.altitude.altitude_value,
                    "altitudeConfidence": self.location.reference_position.altitude.altitude_confidence,
                },
            },
            "referenceArea": {
                "geometricArea": {
                    "circle": (
                        {"radius": self.location.reference_area.geometric_area.circle.radius}
                        if self.location.reference_area.geometric_area.circle is not None
                        else None
                    ),
                    "rectangle": (
                        {
                            "aSemiAxis": self.location.reference_area.geometric_area.rectangle.a_semi_axis,
                            "bSemiAxis": self.location.reference_area.geometric_area.rectangle.b_semi_axis,
                            "azimuthAngle": self.location.reference_area.geometric_area.rectangle.azimuth_angle,
                        }
                        if self.location.reference_area.geometric_area.rectangle is not None
                        else None
                    ),
                    "ellipse": (
                        {
                            "aSemiAxis": self.location.reference_area.geometric_area.ellipse.a_semi_axis,
                            "bSemiAxis": self.location.reference_area.geometric_area.ellipse.b_semi_axis,
                            "azimuthAngle": self.location.reference_area.geometric_area.ellipse.azimuth_angle,
                        }
                        if self.location.reference_area.geometric_area.ellipse is not None
                        else None
                    ),
                },
                "relevanceArea": {
                    "relevanceDistance": self.location.reference_area.relevance_area.relevance_distance.relevance_distance,
                    "relevaneTrafficDirection": self.location.reference_area.relevance_area.relevance_traffic_direction.relevance_traffic_direction,
                },
            },
        }
        yield "dataObject", self.data_object
        yield "timeValidity", self.time_validity.time
        # pylint: enable=line-too-long

    def to_dict(self) -> dict:
        """
        Method that returns dict representation of the class

        Parameters
        ----------
        None

        Returns
        ----------
        Dict
            dictionary respresentation of the class
        """
        # pylint: disable=line-too-long
        data = {
            "application_id": self.application_id,
            "timestamp": self.timestamp.timestamp,
            "location": {
                "referencePosition": {
                    "latitude": self.location.reference_position.latitude,
                    "longitude": self.location.reference_position.longitude,
                    "positionConfidenceEllipse": {
                        "semiMajorConfidence": self.location.reference_position.position_confidence_ellipse.semi_major_confidence,
                        "semiMinorConfidence": self.location.reference_position.position_confidence_ellipse.semi_minor_confidence,
                        "semiMajorOrientation": self.location.reference_position.position_confidence_ellipse.semi_minor_confidence,
                    },
                    "altitude": {
                        "altitudeValue": self.location.reference_position.altitude.altitude_value,
                        "altitudeConfidence": self.location.reference_position.altitude.altitude_confidence,
                    },
                },
                "referenceArea": {
                    "geometricArea": {
                        "circle": (
                            {"radius": self.location.reference_area.geometric_area.circle.radius}
                            if self.location.reference_area.geometric_area.circle is not None
                            else None
                        ),
                        "rectangle": (
                            {
                                "aSemiAxis": self.location.reference_area.geometric_area.rectangle.a_semi_axis,
                                "bSemiAxis": self.location.reference_area.geometric_area.rectangle.b_semi_axis,
                                "azimuthAngle": self.location.reference_area.geometric_area.rectangle.azimuth_angle,
                            }
                            if self.location.reference_area.geometric_area.rectangle is not None
                            else None
                        ),
                        "ellipse": (
                            {
                                "aSemiAxis": self.location.reference_area.geometric_area.ellipse.a_semi_axis,
                                "bSemiAxis": self.location.reference_area.geometric_area.ellipse.b_semi_axis,
                                "azimuthAngle": self.location.reference_area.geometric_area.ellipse.azimuth_angle,
                            }
                            if self.location.reference_area.geometric_area.ellipse is not None
                            else None
                        ),
                    },
                    "relevanceArea": {
                        "relevanceDistance": self.location.reference_area.relevance_area.relevance_distance.relevance_distance,
                        "relevaneTrafficDirection": self.location.reference_area.relevance_area.relevance_traffic_direction.relevance_traffic_direction,
                    },
                },
            },
            "dataObject": self.data_object,
            "timeValidity": self.time_validity.time,
        }
        return data
        # pylint: enable=line-too-long

    @staticmethod
    def from_dict(data: dict) -> "AddDataProviderReq":
        """
        Method that creates an instance of the class from a dictionary.

        Parameters
        ----------
        data : dict
            Dictionary containing the data to construct the class instance.

        Returns
        -------
        AddDataProviderReq
            An instance of the AddDataProviderReq class.
        """
        application_id = data.get("application_id")
        time_stamp = TimestampIts.initialize_with_timestamp_its(
            data.get("timestamp"))
        location_data = data.get("location")
        data_object = data.get("dataObject")
        time_validity = TimeValidity(data.get("timeValidity"))

        # Extracting location data
        reference_position_data = location_data.get("referencePosition")
        reference_position = ReferencePosition(
            latitude=reference_position_data.get("latitude"),
            longitude=reference_position_data.get("longitude"),
            position_confidence_ellipse=PositionConfidenceEllipse(
                semi_major_confidence=reference_position_data[
                    "positionConfidenceEllipse"]["semiMajorConfidence"],
                semi_minor_confidence=reference_position_data[
                    "positionConfidenceEllipse"]["semiMinorConfidence"],
                semi_major_orientation=reference_position_data[
                    "positionConfidenceEllipse"]["semiMajorOrientation"],
            ),
            altitude=Altitude(
                altitude_value=reference_position_data["altitude"]["altitudeValue"],
                altitude_confidence=reference_position_data["altitude"]["altitudeConfidence"],
            ),
        )
        reference_area_data = location_data.get("referenceArea")
        reference_area = ReferenceArea(
            geometric_area=GeometricArea(
                circle=(
                    Circle(
                        radius=reference_area_data["geometricArea"]["circle"]["radius"])
                    if reference_area_data["geometricArea"]["circle"]
                    else None
                ),
                rectangle=(
                    Rectangle(
                        a_semi_axis=reference_area_data["geometricArea"]["rectangle"]["aSemiAxis"],
                        b_semi_axis=reference_area_data["geometricArea"]["rectangle"]["bSemiAxis"],
                        azimuth_angle=reference_area_data["geometricArea"]["rectangle"]["azimuthAngle"],
                    )
                    if reference_area_data["geometricArea"]["rectangle"]
                    else None
                ),
                ellipse=(
                    Ellipse(
                        a_semi_axis=reference_area_data["geometricArea"]["ellipse"]["aSemiAxis"],
                        b_semi_axis=reference_area_data["geometricArea"]["ellipse"]["bSemiAxis"],
                        azimuth_angle=reference_area_data["geometricArea"]["ellipse"]["azimuthAngle"],
                    )
                    if reference_area_data["geometricArea"]["ellipse"]
                    else None
                ),
            ),
            relevance_area=RelevanceArea(
                relevance_distance=RelevanceDistance(
                    relevance_distance=reference_area_data["relevanceArea"]["relevanceDistance"]
                ),
                relevance_traffic_direction=RelevanceTrafficDirection(
                    relevance_traffic_direction=reference_area_data[
                        "relevanceArea"]["relevaneTrafficDirection"]
                ),
            ),
        )
        location = Location(
            reference_position=reference_position, reference_area=reference_area)

        return AddDataProviderReq(
            application_id=application_id,
            timestamp=time_stamp,
            location=location,
            data_object=data_object,
            time_validity=time_validity,
        )


class AddDataProviderResp:
    """
    Class that represents Add Data Provider Response as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(self, application_id: int, data_object_id: int) -> None:
        self.application_id = application_id
        self.data_object_id = data_object_id

    def to_dict(self) -> dict:
        """
        Method that returns dict representation of the class

        Parameters
        ----------
        None

        Returns
        ----------
        Dict
            dictionary respresentation of the class
        """
        return {
            "application_id": self.application_id,
            "data_object_id": self.data_object_id,
        }

    @staticmethod
    def from_dict(data: dict) -> "AddDataProviderResp":
        """
        Method that creates an instance of the class from a dictionary.

        Parameters
        ----------
        data : dict
            Dictionary containing the data to construct the class instance.

        Returns
        -------
        AddDataProviderResp
            An instance of the AddDataProviderResp class.
        """
        application_id = data.get("application_id")
        data_object_id = data.get("data_object_id")

        return AddDataProviderResp(application_id=application_id, data_object_id=data_object_id)


class UpdateDataProviderReq:
    """
    Class that represents Update Data Provider Request as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(
        self,
        application_id: int,
        data_object_id: int,
        time_stamp: TimestampIts,
        location: Location,
        data_object: dict,
        time_validity: TimeValidity,
    ) -> None:
        self.application_id = application_id
        self.data_object_id = data_object_id
        self.time_stamp = time_stamp
        self.location = location
        self.data_object = data_object
        self.time_validity = time_validity


class UpdateDataProviderResult:
    """
    Class that represents Update Data Provider Result as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(self, result: int) -> None:
        self.result = result

    def __str__(self) -> str:
        if self.result == 0:
            return "succeed"
        if self.result == 1:
            return "unknownDataObjectID"
        if self.result == 2:
            return "inconsistentDataObjectType"
        raise ValueError(
            "UpdateDataProviderResult string synonym not found according to \
                         ETSI TS 102 894-2 V2.2.1 (2023-10)"
        )


class UpdateDataProviderResp:
    """
    Class that represents Update Data Provider Response as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(self, application_id: int, data_object_id: int, result: UpdateDataProviderResult) -> None:
        self.application_id = application_id
        self.data_object_id = data_object_id
        self.result = result


class DeleteDataProviderReq:
    """
    Class that represents Delete Data Provider Request as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(self, application_id: int, data_object_id: int, time_stamp: TimestampIts) -> None:
        self.application_id = application_id
        self.data_object_id = data_object_id
        self.time_stamp = time_stamp


class DeleteDataProviderResult:
    """
    Class that represents Delete Data Provider Result as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(self, result: int) -> None:
        self.result = result

    def __str__(self) -> str:
        if self.result == 0:
            return "succeed"
        if self.result == 1:
            return "failed"
        raise ValueError(
            "DeleteDataProviderResult string synonym not found according \
                         to ETSI TS 102 894-2 V2.2.1 (2023-10)"
        )


class DeleteDataProviderResp:
    """
    Class that represents Delete Data Provider Response as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(self, application_id: int, data_object_id: int, result: DeleteDataProviderResult) -> None:
        self.application_id = application_id
        self.data_object_id = data_object_id
        self.result = result


class RegisterDataConsumerReq:
    """
    Class that represents Register Data Consumer Request as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(
        self,
        application_id: int,
        access_permisions: list[DataContainer],
        area_of_interest: GeometricArea,
    ) -> None:
        self.application_id = application_id
        self.access_permisions = access_permisions
        self.area_of_interest = area_of_interest


class RegisterDataConsumerResult:
    """
    Class that represents Register Data Consumer Result as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(self, result: int) -> None:
        self.result = result

    def __str__(self) -> str:
        if self.result == 0:
            return "accepted"
        if self.result == 1:
            return "warning"
        if self.result == 2:
            return "rejected"
        raise ValueError(
            "RegisterDataConsumerResult string synonym not found according to \
                         ETSI TS 102 894-2 V2.2.1 (2023-10)"
        )


class RegisterDataConsumerResp:
    """
    Class that represents Register Data Consumer Response as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(
        self,
        application_id: int,
        access_permisions: list[DataContainer],
        result: RegisterDataConsumerResult,
    ) -> None:
        self.application_id = application_id
        self.access_permisions = access_permisions
        self.result = result


class DeregisterDataConsumerReq:
    """
    Class that represents Deregister Data Consumer Request as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(self, application_id: int) -> None:
        self.application_id = application_id


class DeregisterDataConsumerAck:
    """
    Class that represents Deegister Data Consumer Ack as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(self, result: int) -> None:
        self.result = result

    def __str__(self) -> str:
        if self.result == 0:
            return "succeed"
        if self.result == 1:
            return "failed"
        raise ValueError(
            "DeregisterDataConsumerAck string synonym not found according \
                         to ETSI TS 102 894-2 V2.2.1 (2023-10)"
        )


class DeregisterDataConsumerResp:
    """
    Class that represents Deregister Data Consumer Response as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(self, application_id: int, ack: DeregisterDataConsumerAck) -> None:
        self.application_id = application_id
        self.ack = ack


class UnsubscribeDataConsumerReq:
    """
    Class that represents Unsubscribe Data Consumer Request as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(self, application_id: int, subscription_id: int) -> None:
        self.application_id = application_id
        self.subscription_id = subscription_id


class UnsubscribeDataConsumerAck:
    """
    Class that represents Unsubscribe Data Consumer Ack as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(self, result: int) -> None:
        self.result = result

    def __str__(self) -> str:
        if self.result == 0:
            return "accepted"
        if self.result == 1:
            return "failed"
        raise ValueError(
            "UnsubscribeDataConsumerAck string synonym not found according \
                         to ETSI TS 102 894-2 V2.2.1 (2023-10)"
        )


class UnsubscribeDataConsumerResp:
    """
    Class that represents Unsubscribe Data Consumer Response as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(
        self,
        application_id: int,
        subscription_id: int,
        result: UnsubscribeDataConsumerAck,
    ) -> None:
        self.application_id = application_id
        self.subscription_id = subscription_id
        self.result = result


class RevokeDataConsumerRegistrationResp:
    """
    Class that represents Revoke Data Consumer Registration Response as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(self, application_id: int) -> None:
        self.application_id = application_id


class OrderingDirection:
    """
    Class that represents Ordering Direction as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(self, direction: int) -> None:
        self.direction = direction

    def __str__(self) -> str:
        if self.direction == 0:
            return "ascending"
        if self.direction == 1:
            return "descending"
        raise ValueError(
            "OrderingDirection string synonym not found according to ETSI TS 102 894-2 V2.2.1 (2023-10)")


class OrderTuple:
    """
    Class that represents Order Tuple as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    TODO: The current implementation doesn't follow the ETSI standard. The standard says the attribute should be an int
    that represent the CDD value of the attribute. I think this is not optimial and have changed it. Verify if it
    makes any sense...

    Attributes
    ----------
    attribute: string
        Attribute to be ordered. For example "generationDeltaTime" or "latitude". It should match the ASN.1 format.
    ordering_direction: OrderingDirection
        OrderingDirection class that represents what direction to be ordered.
    """

    def __init__(self, attribute: str, ordering_direction: OrderingDirection) -> None:
        self.attribute = attribute
        self.ordering_direction = ordering_direction


class LogicalOperators:
    """
    Class that represents Logical Operators as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(self, operator: int) -> None:
        self.operator = operator

    def __str__(self) -> str:
        if self.operator == 0:
            return "and"
        if self.operator == 1:
            return "or"
        raise ValueError(
            "LogicalOperators string synonym not found according to ETSI TS 102 894-2 V2.2.1 (2023-10)")


class ComparisonOperators:
    """
    Class that represents Comparison Operators as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(self, operator: int) -> None:
        self.operator = operator

    def __str__(self) -> str:
        operator_mapping = {
            0: "==",
            1: "!=",
            2: ">",
            3: "<",
            4: ">=",
            5: "<=",
            6: "like",
            7: "notlike",
        }

        if self.operator in operator_mapping:
            return operator_mapping[self.operator]

        raise ValueError(
            "ComparisonOperators string synonym not found according to ETSI TS 102 894-2 V2.2.1 (2023-10)")


class FilterStatement:
    """
    Class that represents Filter Statement as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(self, attribute: int, operator: ComparisonOperators, ref_value: int):
        self.attribute = attribute
        self.operator = operator
        self.ref_value = ref_value


class Filter:
    """
    Class that represents Filter as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(
        self,
        filter_statement_1: FilterStatement,
        logical_operator: LogicalOperators = None,
        filter_statement_2: FilterStatement = None,
    ) -> None:
        self.filter_statement_1 = filter_statement_1
        self.logical_operator = logical_operator
        self.filter_statement_2 = filter_statement_2


class RequestDataObjectsReq:
    """
    Class that represents Request Data Objects Request as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(
        self,
        application_id: int,
        data_object_type: list[int],
        priority: int,
        order: list[OrderTuple],
        filter: Filter,
    ) -> None:
        self.application_id = application_id
        self.data_object_type = data_object_type
        self.priority = priority
        self.order = order
        self.filter = filter

    @staticmethod
    def filter_out_by_data_object_type(search_result: list[dict], data_object_types: list[int]) -> list[dict]:
        """
        Function that filters out all packets that are not part of the specified data object type list given
        in the RequestDataObjectReq

        Parameters
        ----------
        search_result: list[dict]
            The current search result with all data object types (CAM, DENM, VAM, etc)
        data_object_types: list[int]
            The data objects that want to be returned (field from RequestDataObjectReq)
        Returns
        ---------
        filtered_search_result: list[dict]
            Only the packets that have the type specified in the data object type of the RequestDataObjectReq
        """
        filtered_search_result = []
        for result in search_result:
            if RequestDataObjectsReq.get_object_type_from_data_object(result["dataObject"]) in data_object_types:
                filtered_search_result.append(result)
        return filtered_search_result

    @staticmethod
    def get_object_type_from_data_object(data_object: dict) -> str:
        """
        Method to get object type from data object.

        Parameters
        ----------
        data_object : dict
        """
        for data_object_type_str in data_object.keys():
            if data_object_type_str in DATA_OBJECT_TYPE_ID.values():
                return list(DATA_OBJECT_TYPE_ID.keys())[list(DATA_OBJECT_TYPE_ID.values()).index(data_object_type_str)]
        return None


class RequestedDataObjectsResult:
    """
    Class that represents Requested Data Objects Result as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(self, result: int) -> None:
        self.result = result

    def __str__(self) -> str:
        if self.result == 0:
            return "succeed"
        if self.result == 1:
            return "invalidITSAID"
        if self.result == 2:
            return "invalidDataObjectType"
        if self.result == 3:
            return "invalidPriority"
        if self.result == 4:
            return "invalidFilter"
        if self.result == 5:
            return "invalidOrder"
        raise ValueError(
            "RequestedDataObjectsResult string synonym not found according\
                          to ETSI TS 102 894-2 V2.2.1 (2023-10)"
        )


class RequestDataObjectsResp:
    """
    Class that represents Request Data Objects Response as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(
        self,
        application_id: int,
        data_objects: list[dict],
        result: RequestedDataObjectsResult,
    ) -> None:
        self.application_id = application_id
        self.data_objects = data_objects
        self.result = result

    def find_attribute(self, attribute: str, data_object: dict) -> list:
        """
        Method to find an nested (or not) atrribute in a dictionary.

        If a dict looks like this:
        dictionary = {
            "a": {
                "b": {
                    "c": "value"
                }
            }
        }

        You can get the value of c by calling this function like this:
        attribute_path = get_nested("c", dictionary)
        attribute_path = ["a", "b", "c"]

        Parameters
        ----------
        attribute : str
            The attribute to be found in string format.
        data_object : dict
            The dictionary to be searched.


        Returns
        -------
        list
            list with the path to the attribute.
        """
        for key, value in data_object.items():
            if key == attribute:
                return [key]
            if isinstance(value, dict):
                path = self.find_attribute(attribute, value)
                if path:
                    return [key] + path
        return []

    @staticmethod
    def find_attribute_static(attribute: str, data_object: dict) -> list:
        """
        (Static) Method to find attribute in a dictionary.

        Parameters
        ----------
        attribute : str
            The attribute to be found in string format.
        data_object : dict
            The dictionary to be searched.

        Returns
        -------
        list
            list with the path to the attribute.
        """
        for key, value in data_object.items():
            if key == attribute:
                return [key]
            if isinstance(value, dict):
                path = RequestDataObjectsResp.find_attribute_static(
                    attribute, value)
                if path:
                    return [key] + path
        return []


class SubscribeDataobjectsReq:
    """
    As specified in src.facilities.local_dynamic_map.if_ldm_4.py this class has been modified to fit implementation.
    The parameter "callback : function" has been added (not in the standard)
    """

    def __init__(
        self,
        application_id: int,
        data_object_type: list[int],
        priority: int,
        filter: Filter,
        notify_time: TimestampIts,
        multiplicity: int,
        order: list[OrderTuple],
    ) -> None:
        """
        Constructor for SubscribeDataobjectsReq class.

        Parameters
        ----------
        application_id : int
            The application id.
        data_object_type : list[int]
            The data object type.
        priority : int
            The priority.
        filter : Filter
            The filter.
        notify_time : TimestampIts
            The notify time.
        multiplicity : int
            The multiplicity.
        order : list[OrderTuple]
            The order.
        """
        self.application_id = application_id
        self.data_object_type = data_object_type
        self.priority = priority
        self.filter = filter
        self.notify_time = notify_time
        self.multiplicity = multiplicity
        self.order = order


class SubscribeDataobjectsResult:
    """
    Class that represents Subscribe Data Objects Result as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(self, result: int) -> None:
        self.result = result

    def __str__(self) -> str:
        result_mapping = {
            0: "successful",
            1: "invalidITSAID",
            2: "invalidDataObjectType",
            3: "invalidPriority",
            4: "invalidFilter",
            5: "invalidNotificationInterval",
            6: "invalidMultiplicity",
            7: "invalidOrder",
        }

        result_str = result_mapping.get(self.result)
        if result_str is not None:
            return result_str

        raise ValueError("SubscribeDataobjectsResult string synonym not found")


class SubscribeDataObjectsResp:
    """
    Class that represents Subscribe Data Objects Response as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(
        self,
        application_id: int,
        subscription_id: int,
        result: SubscribeDataobjectsResult,
        error_message: str,
    ) -> None:
        self.application_id = application_id
        self.subscription_id = subscription_id
        self.result = result
        self.error_message = error_message


class PublishDataobjects:
    """
    Class that represents Publish Data Objects as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(self, subscription_id: int, request_data: list[str]) -> None:
        self.subscription_id = subscription_id
        self.requested_data = request_data


class UnsubscribeDataobjectsReq:
    """
    Class that represents Unsubscribe Data Objects Request as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(self, application_id: int, subscription_id: int) -> None:
        self.application_id = application_id
        self.subscription_id = subscription_id


class UnsubscribeDataobjectsResult:
    """
    Class that represents Unsubscribe Data Objects Result as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(self, result: int) -> None:
        self.result = result

    def __str__(self) -> str:
        if self.result == 0:
            return "accepted"
        if self.result == 1:
            return "rejected"
        raise ValueError(
            "UnsubscribeDataobjectsResult string synonym not found\
                          according to ETSI TS 102 894-2 V2.2.1 (2023-10)"
        )


class UnsubscribeDataobjectsResp:
    """
    Class that represents Unsubscribe Data Objects Response as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(self, application_id: int, result: UnsubscribeDataobjectsResult) -> None:
        self.application_id = application_id
        self.result = result

    def __str__(self) -> str:
        if self.result == 0:
            return "succeed"
        if self.result == 1:
            return "failed"
        return None


class ReferenceValue:
    """
    Class that represents Reference Value as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    def __init__(self, reference_value: int) -> None:
        self.reference_value = reference_value

    def __str__(self) -> str:
        value_mapping = {
            0: "boolValue",
            1: "sbyteValue",
            2: "byteValue",
            3: "shortValue",
            4: "intValue",
            5: "octsValue",
            6: "bitsValue",
            7: "strValue",
            8: "causeCodeValue",
            9: "speedValue",
            10: "stationIDValue",
        }

        result = value_mapping.get(self.reference_value)

        if result is None:
            raise ValueError(
                "ReferenceValue string synonym not found according to ETSI TS 102 894-2 V2.2.1 (2023-10)")

        return result


class Utils:
    """
    Utils class contains generic methods that are usefull throughout the project.
    TODO: Currenlty it resides in the local_dynamic_map folder, but it should be moved to a more generic location.
    """

    @staticmethod
    def haversine_a(dlat: float, lat1: float, lat2: float, dlon: float) -> float:
        """
        Method to calculate the haversine A varible from the difference in latitude and longitude and the latitude_1 and latitude_2.

        Parameters
        ----------
        dlat : float
            Difference in latitude.
        lat1 : float
            Latitude 1.
        lat2 : float
            Latitude 2.
        dlon : float
            Difference in longitude.

        Returns
        -------
        float
            Haversine value.
        """
        return math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2

    @staticmethod
    def haversine_c(a: float) -> float:
        """
        Method to calculate the haversine C variable from the haversine A variable.

        Parameters
        ----------
        dlat : float
            Difference in latitude.
        lat1 : float
            Latitude 1.
        lat2 : float
            Latitude 2.
        dlon : float
            Difference in longitude.

        Returns
        -------
        float
            Haversine value.
        """
        return 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

    @staticmethod
    def haversine_distance(coord1: tuple, coord2: tuple) -> int:
        """
        Function that returns the distance between two coordinates in meters.

        Parameters
        ----------
        coord1 : tuple(int, int)
        coord2 : tuple(int, int)
        """
        lat1, lon1 = math.radians(coord1[0]), math.radians(coord1[1])
        lat2, lon2 = math.radians(coord2[0]), math.radians(coord2[1])

        dlat, dlon = lat2 - lat1, lon2 - lon1

        a = Utils.haversine_a(dlat, lat1, lat2, dlon)
        c = Utils.haversine_c(a)

        distance = EATH_RADIUS * c

        return distance

    @staticmethod
    def get_nested(data: dict, path: list) -> list:
        """
        Returns the value nested in a dict. If the path is not found, returns None.
        If a dict looks like this:
        dictionary = {
            "a": {
                "b": {
                    "c": "value"
                }
            }
        }
        You can get the value of c by calling this function like this:
        get_nested(dictionary, ["a", "b", "c"])

        Parameters
        ----------
        data : dict
            Dict containing the data.
        path : list
            list containing the path to the value.

        Returns
        -------
        list
            list with the path to the attribute.
        """
        if path and data:
            element = path[0]
            if element in data:
                value = data[element]
                return value if len(path) == 1 else Utils.get_nested(value, path[1:])
        return None

    @staticmethod
    def find_attribute(attribute: str, data_object: dict) -> list:
        """
        Method to find attribute in a dictionary.

        Parameters
        ----------
        attribute : str
            The attribute to be found in string format.
        data_object : dict
            The dictionary to be searched.

        Returns
        -------
        list
            list with the path to the attribute.
        """
        for key, value in data_object.items():
            if key == attribute:
                return [key]
            if isinstance(value, dict):
                path = Utils.find_attribute(attribute, value)
                if path:
                    return [key] + path
        return []

    @staticmethod
    def get_station_id(data_object: dict) -> int:
        """
        Method to get the station id from a data object. This method was created because some older (ETSI) standards
        use stationId instead of stationID.

        Parameters
        ----------
        data_object : dict
            The data object to get the station id from.

        Returns
        -------
        int
            The station id.
        """
        station_id = Utils.get_nested(
            data_object, Utils.find_attribute("stationID", data_object))
        if station_id is None:
            station_id = Utils.get_nested(
                data_object, Utils.find_attribute("stationId", data_object))
        return station_id

    @staticmethod
    def check_field(data: dict, field_name: str = None) -> bool:
        """
        Method that checks if field name exists in dictionary. It checks all levels of the dictionary.

        Parameters
        ----------
        data : dict
            Dictionary to check.
        field_name : str
            Field name to check for.

        Returns
        -------
        bool
            True if field name exists in dictionary, False otherwise.
        """
        if isinstance(data, dict):
            if field_name in data:
                return True
            for value in data.values():
                if Utils.check_field(value, field_name):
                    return True
        elif isinstance(data, list):
            for item in data:
                if Utils.check_field(item, field_name):
                    return True
        return False

    @staticmethod
    def convert_etsi_coordinates_to_normal(point: tuple) -> tuple:
        """
        Function to convert ETSI Coordiantes into normal coordinates

        Parameters
        ----------
        point: tuple
            Coordinates to convert

        Returns
        --------
        tuple
            Coordinates in normal format
        """
        return point / 10000000

    @staticmethod
    def euclidian_distance(point1, point2):
        """
        Generated the euclidian distance between two points.

        Attributes
        ----------
        point1 : tuple
            First point.
        point2 : tuple
            Second point.
        """
        return ((point1[0] - point2[0]) ** 2 + (point1[1] - point2[1]) ** 2) ** (1 / 2)
