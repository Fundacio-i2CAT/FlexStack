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
from dataclasses import dataclass
from functools import total_ordering
from enum import IntEnum
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


@total_ordering
@dataclass(frozen=True)
class TimestampIts:
    """
    TimestampITS class to handle timestamps. Timestamps are expressed in ETSI Timestamp format.

    Attributes
    ----------
    timestamp : int
        The timestamp in ETSI Timestamp format (milliseconds since 1st January 2004).
    """
    timestamp_its: int

    @staticmethod
    def initialize_with_utc_timestamp_seconds(utc_timestamp_seconds: int) -> TimestampIts:
        """
        Initializes the TimestampIts class with a given UTC timestamp in seconds.

        Parameters
        ----------
        utc_timestamp_seconds : int
            The UTC timestamp in seconds since the epoch (UTC).

        Returns
        -------
        TimestampIts
            An instance of the TimestampIts class.
        """
        if utc_timestamp_seconds:
            return TimestampIts(TimestampIts.transform_utc_seconds_timestamp_to_timestamp_its(
                utc_timestamp_seconds))
        else:
            return TimestampIts(TimestampIts.transform_utc_seconds_timestamp_to_timestamp_its(
                int(TimeService.time())))

    @staticmethod
    def transform_utc_seconds_timestamp_to_timestamp_its(utc_timestamp_seconds: int) -> int:
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
        return TimestampIts(timestamp_its=self.timestamp_its + other.timestamp_its)

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
        return TimestampIts(timestamp_its=self.timestamp_its - other.timestamp_its)

    def __eq__(self, other: object) -> bool:
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
        return self.timestamp_its == other.timestamp_its

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
        return self.timestamp_its < other.timestamp_its


@dataclass(frozen=True)
class TimeValidity:
    """
    Class that represents the time validity of a data object. Time is expressed in Normal Unix Format.

    Attributes
    ----------
    time : int
        The time validity in Normal Unix Format.
    """
    time: int

    def to_etsi_its(self) -> int:
        """
        Method to convert the time validity from Normal Unix Format to ETSI ITS Timestamp.

        Returns
        -------
        int
            Converted timestamp in ETSI ITS format.
        """
        return int(((self.time - ITS_EPOCH)) * 1000)


@dataclass(frozen=True)
class DataContainer:
    """
    Class currently not used, as no real value is added. Currenly a datacontainer is treated as a list of dicts, maybe
    in the future some added funcionalities will be added.
    """
    data_container: dict

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


class AuthorizationResult(IntEnum):
    SUCCESSFUL = 0
    INVALID_ITS_AID = 1
    AUTHENTICATION_FAILURE = 2
    APPLICATION_NOT_AUTHORIZED = 3

    def __str__(self):
        return self.name.lower()


@dataclass(frozen=True)
class AuthorizeReg:
    """
    Class that represents an authorization request as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """
    application_id: int
    access_permissions: tuple[DataContainer, ...]


@dataclass(frozen=True)
class AuthorizeResp:
    """
    Class that represents an authorization response as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """
    application_id: int
    access_permissions: tuple[DataContainer, ...]
    result: AuthorizationResult


class RevocationReason(IntEnum):
    REGISTRATION_REVOKED_BY_REGISTRATION_AUTHORITY = 0
    REGISTRATION_PERIOD_EXPIRED = 1

    def __str__(self) -> str:
        return {
            RevocationReason.REGISTRATION_REVOKED_BY_REGISTRATION_AUTHORITY:
                "registrationRevokedByRegistrationAuthority",
            RevocationReason.REGISTRATION_PERIOD_EXPIRED:
                "registrationPeriodExpired",
        }[self]


class RevocationResult(IntEnum):
    SUCCESSFUL = 0
    INVALID_ITS_AID = 1
    UNKNOWN_ITS_AID = 2

    def __str__(self) -> str:
        return {
            RevocationResult.SUCCESSFUL: "successful",
            RevocationResult.INVALID_ITS_AID: "invalidITS-AID",
            RevocationResult.UNKNOWN_ITS_AID: "unknownITS-AID",
        }[self]


@dataclass(frozen=True)
class RevokeAuthorizationReg:
    """
    Class that represents a Revoke Authorization Registration as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """
    application_id: int
    reason: RevocationReason


@dataclass(frozen=True)
class RegisterDataProviderReq:
    """
    Class that represents a Register Data Provider Request as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """
    application_id: int
    access_permissions: tuple[DataContainer, ...]
    time_validity: TimeValidity

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
            "access_permissions": self.access_permissions,
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
        time_validity = TimeValidity(data.get("time_validity", 0))

        if application_id is None or access_permissions is None:
            raise ValueError("Missing required fields in data dictionary")

        return RegisterDataProviderReq(
            application_id=application_id,
            access_permissions=access_permissions,
            time_validity=time_validity,
        )


class RegisterDataProviderResult(IntEnum):
    """
    Class that represents a Register Data Provider Result as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """
    ACCEPTED = 0
    REJECTED = 1

    def __str__(self) -> str:
        return {
            RegisterDataProviderResult.ACCEPTED: "accepted",
            RegisterDataProviderResult.REJECTED: "rejected",
        }[self]


@dataclass(frozen=True)
class RegisterDataProviderResp:
    """
    Class that represent a Register Data Provder Response as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """
    application_id: int
    access_permisions: tuple[DataContainer, ...]
    result: RegisterDataProviderResult


class DeregisterDataProviderAck(IntEnum):
    """
    Class that represent Deregister Data Provider Ack as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """
    ACCEPTED = 0
    REJECTED = 1

    def __str__(self) -> str:
        return {
            DeregisterDataProviderAck.ACCEPTED: "accepted",
            DeregisterDataProviderAck.REJECTED: "rejected",
        }[self]


@dataclass(frozen=True)
class DeregisterDataProviderReq:
    """
    Class that represents Deregister Data Provider Request as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """
    application_id: int


@dataclass(frozen=True)
class DeregisterDataProviderResp:
    """
    Class that represents Deregister Data Provider Response as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """
    application_id: int
    result: DeregisterDataProviderAck


@dataclass(frozen=True)
class RevokeDataProviderRegistrationResp:
    """
    Class that represents Revoke Data Provider Registration Response as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """
    application_id: int


@dataclass(frozen=True)
class PositionConfidenceEllipse:
    """
    Class that represents Position Confidence Ellipse as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """
    semi_major_confidence: int
    semi_minor_confidence: int
    semi_major_orientation: int


@dataclass(frozen=True)
class Altitude:
    """
    Class that represents Altitude as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """
    altitude_value: int
    altitude_confidence: int


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


@dataclass(frozen=True)
class ReferencePosition:
    """
    Class that represent Reference Position as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """
    latitude: int
    longitude: int
    position_confidence_ellipse: PositionConfidenceEllipse
    altitude: Altitude

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

    @classmethod
    def update_with_gpsd_tpv(cls, tpv: dict) -> "ReferencePosition":
        """
        Updates the reference position with a TPV from gpsd.

        Parameters
        ----------
        tpv : dict
            Dictionary containing the location data.

        Returns
        -------
        ReferencePosition
            Updated ReferencePosition instance.

        TODO: In the future the altitude and the confidence ellipses should be updated as well.
        """
        return cls(
            latitude=Latitude.convert_latitude_to_its_latitude(tpv["lat"]),
            longitude=Longitude.convert_longitude_to_its_longitude(tpv["lon"]),
            position_confidence_ellipse=PositionConfidenceEllipse(
                semi_major_confidence=tpv["epx"],
                semi_minor_confidence=tpv["epy"],
                semi_major_orientation=tpv["track"],
            ),
            altitude=Altitude(
                altitude_value=tpv["alt"],
                altitude_confidence=tpv["epv"],
            ),
        )


@dataclass(frozen=True)
class StationType:
    """
    Class that represent Station Type as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """
    station_type: int

    def __str__(self) -> str:
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


@dataclass(frozen=True)
class Direction:
    """
    Class that represents Direction as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """
    direction: int

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


@dataclass(frozen=True)
class Circle:
    """
    Class that represents Circle as speficied in ETSI EN 302 895 V1.1.1 (2014-09).
    """
    radius: int


@dataclass(frozen=True)
class Rectangle:
    """
    Class that represents Rectangle as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """
    a_semi_axis: int
    b_semi_axis: int
    azimuth_angle: Direction


@dataclass(frozen=True)
class Ellipse:
    """
    Class that represents Ellipse as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """
    a_semi_axis: int
    b_semi_axis: int
    azimuth_angle: Direction


class RelevanceTrafficDirection(IntEnum):
    ALL_TRAFFIC_DIRECTIONS = 0
    UPSTREAM_TRAFFIC = 1
    DOWNSTREAM_TRAFFIC = 2
    OPPOSITE_TRAFFIC = 3

    def __str__(self) -> str:
        return {
            RelevanceTrafficDirection.ALL_TRAFFIC_DIRECTIONS: "allTrafficDirections",
            RelevanceTrafficDirection.UPSTREAM_TRAFFIC: "upstreamTraffic",
            RelevanceTrafficDirection.DOWNSTREAM_TRAFFIC: "downstreamTraffic",
            RelevanceTrafficDirection.OPPOSITE_TRAFFIC: "oppositeTraffic",
        }[self]


@dataclass(frozen=True)
class RelevanceDistance:
    """
    Class that represents Relevance Distance as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """
    relevance_distance: int

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


@dataclass(frozen=True)
class RelevanceArea:
    """
    Class that represents Relevance Area as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """
    relevance_distance: RelevanceDistance
    relevance_traffic_direction: RelevanceTrafficDirection


@dataclass(frozen=True)
class GeometricArea:
    """
    Class that represents Geometric Area as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """
    circle: Circle | None
    rectangle: Rectangle | None
    ellipse: Ellipse | None


@dataclass(frozen=True)
class ReferenceArea:
    """
    Class that represents Reference Area as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """
    geometric_area: GeometricArea
    relevance_area: RelevanceArea


@dataclass(frozen=True)
class Location:
    """
    Class that represents Location as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """

    reference_position: ReferencePosition
    reference_area: ReferenceArea

    @staticmethod
    def initializer(
        latitude=0,
        longitude=0,
        semi_major_confidence=0,
        semi_major_orientation=0,
        semi_minor_confidence=0,
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
                semi_minor_confidence=semi_minor_confidence,
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
                    relevance_traffic_direction
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
                relevance_traffic_direction=RelevanceTrafficDirection(0),
            ),
        )
        return Location(reference_area=reference_area, reference_position=reference_position)


@dataclass(frozen=True)
class AddDataProviderReq:
    """
    Class that represents Add Data Provider Request as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """
    application_id: int
    timestamp: TimestampIts
    location: Location
    data_object: dict
    time_validity: TimeValidity

    def __iter__(self):
        # pylint: disable=line-too-long
        yield "application_id", self.application_id
        yield "timestamp", self.timestamp.timestamp_its
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
                    "relevanceTrafficDirection": self.location.reference_area.relevance_area.relevance_traffic_direction.value,
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
            "timestamp": self.timestamp.timestamp_its,
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
                        "relevanceTrafficDirection": self.location.reference_area.relevance_area.relevance_traffic_direction.value,
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
        time_stamp = TimestampIts(timestamp_its=data.get("timestamp", 0))
        location_data = data.get("location")
        data_object = data.get("dataObject")
        time_validity = TimeValidity(data.get("timeValidity", 0))
        if application_id is None or location_data is None or data_object is None:
            raise ValueError("Missing required fields in data dictionary")
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
                    else Circle(radius=0)
                ),
                rectangle=(
                    Rectangle(
                        a_semi_axis=reference_area_data["geometricArea"]["rectangle"]["aSemiAxis"],
                        b_semi_axis=reference_area_data["geometricArea"]["rectangle"]["bSemiAxis"],
                        azimuth_angle=reference_area_data["geometricArea"]["rectangle"]["azimuthAngle"],
                    )
                    if reference_area_data["geometricArea"]["rectangle"]
                    else Rectangle(a_semi_axis=0, b_semi_axis=0, azimuth_angle=Direction(0))
                ),
                ellipse=(
                    Ellipse(
                        a_semi_axis=reference_area_data["geometricArea"]["ellipse"]["aSemiAxis"],
                        b_semi_axis=reference_area_data["geometricArea"]["ellipse"]["bSemiAxis"],
                        azimuth_angle=reference_area_data["geometricArea"]["ellipse"]["azimuthAngle"],
                    )
                    if reference_area_data["geometricArea"]["ellipse"]
                    else Ellipse(a_semi_axis=0, b_semi_axis=0, azimuth_angle=Direction(0))
                ),
            ),
            relevance_area=RelevanceArea(
                relevance_distance=RelevanceDistance(
                    relevance_distance=reference_area_data["relevanceArea"]["relevanceDistance"]
                ),
                relevance_traffic_direction=RelevanceTrafficDirection(reference_area_data[
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


@dataclass(frozen=True)
class AddDataProviderResp:
    """
    Class that represents Add Data Provider Response as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """
    application_id: int
    data_object_id: int

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
        application_id = data.get("application_id", 0)
        data_object_id = data.get("data_object_id", 0)

        return AddDataProviderResp(application_id=application_id, data_object_id=data_object_id)


@dataclass(frozen=True)
class UpdateDataProviderReq:
    """
    Class that represents Update Data Provider Request as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """
    application_id: int
    data_object_id: int
    time_stamp: TimestampIts
    location: Location
    data_object: dict
    time_validity: TimeValidity


class UpdateDataProviderResult(IntEnum):
    """
    Class that represents Update Data Provider Result as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """
    SUCCEED = 0
    UNKNOWN_DATA_OBJECT_ID = 1
    INCONSISTENT_DATA_OBJECT_TYPE = 2

    def __str__(self) -> str:
        return {
            UpdateDataProviderResult.SUCCEED: "succeed",
            UpdateDataProviderResult.UNKNOWN_DATA_OBJECT_ID: "unknownDataObjectID",
            UpdateDataProviderResult.INCONSISTENT_DATA_OBJECT_TYPE: "inconsistentDataObjectType"
        }[self]


@dataclass(frozen=True)
class UpdateDataProviderResp:
    """
    Class that represents Update Data Provider Response as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """
    application_id: int
    data_object_id: int
    result: UpdateDataProviderResult


@dataclass(frozen=True)
class DeleteDataProviderReq:
    """
    Class that represents Delete Data Provider Request as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """
    application_id: int
    data_object_id: int
    time_stamp: TimestampIts


class DeleteDataProviderResult(IntEnum):
    """
    Class that represents Delete Data Provider Result as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """
    SUCCEED = 0
    FAILED = 1

    def __str__(self) -> str:
        return {
            DeleteDataProviderResult.SUCCEED: "succeed",
            DeleteDataProviderResult.FAILED: "failed",
        }[self]


@dataclass(frozen=True)
class DeleteDataProviderResp:
    """
    Class that represents Delete Data Provider Response as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """
    application_id: int
    data_object_id: int
    result: DeleteDataProviderResult


@dataclass(frozen=True)
class RegisterDataConsumerReq:
    """
    Class that represents Register Data Consumer Request as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """
    application_id: int
    access_permisions: tuple[DataContainer, ...]
    area_of_interest: GeometricArea


class RegisterDataConsumerResult(IntEnum):
    """
    Class that represents Register Data Consumer Result as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """
    ACCEPTED = 0
    WARNING = 1
    REJECTED = 2

    def __str__(self) -> str:
        return {
            RegisterDataConsumerResult.ACCEPTED: "accepted",
            RegisterDataConsumerResult.WARNING: "warning",
            RegisterDataConsumerResult.REJECTED: "rejected",
        }[self]


@dataclass(frozen=True)
class RegisterDataConsumerResp:
    """
    Class that represents Register Data Consumer Response as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """
    application_id: int
    access_permisions: tuple[DataContainer, ...]
    result: RegisterDataConsumerResult


@dataclass(frozen=True)
class DeregisterDataConsumerReq:
    """
    Class that represents Deregister Data Consumer Request as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """
    application_id: int


class DeregisterDataConsumerAck(IntEnum):
    """
    Class that represents Deegister Data Consumer Ack as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """
    SUCCEED = 0
    FAILED = 1

    def __str__(self) -> str:
        return {
            DeregisterDataConsumerAck.SUCCEED: "succeed",
            DeregisterDataConsumerAck.FAILED: "failed",
        }[self]


@dataclass(frozen=True)
class DeregisterDataConsumerResp:
    """
    Class that represents Deregister Data Consumer Response as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """
    application_id: int
    ack: DeregisterDataConsumerAck


@dataclass(frozen=True)
class UnsubscribeDataConsumerReq:
    """
    Class that represents Unsubscribe Data Consumer Request as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """
    application_id: int
    subscription_id: int


class UnsubscribeDataConsumerAck(IntEnum):
    """
    Class that represents Unsubscribe Data Consumer Ack as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """
    ACCEPTED = 0
    FAILED = 1

    def __str__(self) -> str:
        return {
            UnsubscribeDataConsumerAck.ACCEPTED: "accepted",
            UnsubscribeDataConsumerAck.FAILED: "failed",
        }[self]


@dataclass(frozen=True)
class UnsubscribeDataConsumerResp:
    """
    Class that represents Unsubscribe Data Consumer Response as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """
    application_id: int
    subscription_id: int
    result: UnsubscribeDataConsumerAck


@dataclass(frozen=True)
class RevokeDataConsumerRegistrationResp:
    """
    Class that represents Revoke Data Consumer Registration Response as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """
    application_id: int


class OrderingDirection(IntEnum):
    """
    Class that represents Ordering Direction as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """
    ASCENDING = 0
    DESCENDING = 1

    def __str__(self) -> str:
        return {
            OrderingDirection.ASCENDING: "ascending",
            OrderingDirection.DESCENDING: "descending",
        }[self]


@dataclass(frozen=True)
class OrderTuple:
    """
    Class that represents Order Tuple as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    TODO: The current implementation doesn't follow the ETSI standard. The standard says the attribute should be an int
    that represent the CDD value of the attribute. I think this is not optimial and have changed it. Verify if it
    makes any sense...

    Attributes
    ----------
    attribute: stringvalues
        Attribute to be ordered. For example "generationDeltaTime" or "latitude". It should match the ASN.1 format.
    ordering_direction: OrderingDirection
        OrderingDirection class that represents what direction to be ordered.
    """
    attribute: str
    ordering_direction: OrderingDirection


class LogicalOperators(IntEnum):
    """
    Class that represents Logical Operators as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """
    AND = 0
    OR = 1

    def __str__(self) -> str:
        return {
            LogicalOperators.AND: "and",
            LogicalOperators.OR: "or",
        }[self]


class ComparisonOperators(IntEnum):
    """
    Class that represents Comparison Operators as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """
    EQUAL = 0  # ==
    NOT_EQUAL = 1  # !=
    GREATER_THAN = 2  # >
    LESS_THAN = 3  # <
    GREATER_THAN_OR_EQUAL = 4  # >=
    LESS_THAN_OR_EQUAL = 5  # <=
    LIKE = 6  # like
    NOT_LIKE = 7  # not like

    def __str__(self) -> str:
        return {
            ComparisonOperators.EQUAL: "==",
            ComparisonOperators.NOT_EQUAL: "!=",
            ComparisonOperators.GREATER_THAN: ">",
            ComparisonOperators.LESS_THAN: "<",
            ComparisonOperators.GREATER_THAN_OR_EQUAL: ">=",
            ComparisonOperators.LESS_THAN_OR_EQUAL: "<=",
            ComparisonOperators.LIKE: "like",
            ComparisonOperators.NOT_LIKE: "notlike",
        }[self]


@dataclass(frozen=True)
class FilterStatement:
    """
    Class that represents Filter Statement as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """
    attribute: int
    operator: ComparisonOperators
    ref_value: int


@dataclass(frozen=True)
class Filter:
    """
    Class that represents Filter as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """
    filter_statement_1: FilterStatement
    logical_operator: LogicalOperators | None = None
    filter_statement_2: FilterStatement | None = None


@dataclass(frozen=True)
class RequestDataObjectsReq:
    """
    Class that represents Request Data Objects Request as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """
    application_id: int
    data_object_type: tuple[int, ...]
    priority: int
    order: tuple[OrderTuple, ...]
    filter: Filter

    @staticmethod
    def filter_out_by_data_object_type(search_result: tuple[dict, ...], data_object_types: tuple[int, ...]) -> list[dict]:
        """
        Function that filters out all packets that are not part of the specified data object type list given
        in the RequestDataObjectReq

        Parameters
        ----------
        search_result: tuple[dict, ...]
            The current search result with all data object types (CAM, DENM, VAM, etc)
        data_object_types: tuple[int, ...]
            The data objects that want to be returned (field from RequestDataObjectReq)
        
        Returns
        -------
        filtered_search_result: list[dict]
            Only the packets that have the type specified in the data object type of the RequestDataObjectReq
        """
        filtered_search_result = []
        for result in search_result:
            if RequestDataObjectsReq.get_object_type_from_data_object(result["dataObject"]) in data_object_types:
                filtered_search_result.append(result)
        return filtered_search_result

    @staticmethod
    def get_object_type_from_data_object(data_object: dict) -> str | None:
        """
        Method to get object type from data object.

        Parameters
        ----------
        data_object : dict
        """
        for data_object_type_str in data_object.keys():
            if data_object_type_str in DATA_OBJECT_TYPE_ID.values():
                return list(DATA_OBJECT_TYPE_ID.keys())[list(DATA_OBJECT_TYPE_ID.values()).index(data_object_type_str)]  # type: ignore
        return None


class RequestedDataObjectsResult(IntEnum):
    """
    Class that represents Requested Data Objects Result as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """
    SUCCEED = 0
    INVALID_ITSA_ID = 1
    INVALID_DATA_OBJECT_TYPE = 2
    INVALID_PRIORITY = 3
    INVALID_FILTER = 4
    INVALID_ORDER = 5

    def __str__(self) -> str:

        return {
            RequestedDataObjectsResult.SUCCEED: "succeed",
            RequestedDataObjectsResult.INVALID_ITSA_ID: "invalidITSAID",
            RequestedDataObjectsResult.INVALID_DATA_OBJECT_TYPE: "invalidDataObjectType",
            RequestedDataObjectsResult.INVALID_PRIORITY: "invalidPriority",
            RequestedDataObjectsResult.INVALID_FILTER: "invalidFilter",
            RequestedDataObjectsResult.INVALID_ORDER: "invalidOrder",
        }[self]


@dataclass(frozen=True)
class RequestDataObjectsResp:
    """
    Class that represents Request Data Objects Response as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """
    application_id: int
    data_objects: tuple[dict, ...]
    result: RequestedDataObjectsResult

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


@dataclass(frozen=True)
class SubscribeDataobjectsReq:
    """
    As specified in src.facilities.local_dynamic_map.if_ldm_4.py this class has been modified to fit implementation.
    The parameter "callback : function" has been added (not in the standard)
    """
    application_id: int
    data_object_type: tuple[int, ...]
    priority: int
    filter: Filter
    notify_time: TimestampIts
    multiplicity: int
    order: tuple[OrderTuple, ...]


class SubscribeDataobjectsResult(IntEnum):
    """
    Class that represents Subscribe Data Objects Result as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """
    SUCCESSFUL = 0
    INVALID_ITSA_ID = 1
    INVALID_DATA_OBJECT_TYPE = 2
    INVALID_PRIORITY = 3
    INVALID_FILTER = 4
    INVALID_NOTIFICATION_INTERVAL = 5
    INVALID_MULTIPLICITY = 6
    INVALID_ORDER = 7

    def __str__(self) -> str:
        return {
            SubscribeDataobjectsResult.SUCCESSFUL: "successful",
            SubscribeDataobjectsResult.INVALID_ITSA_ID: "invalidITSAID",
            SubscribeDataobjectsResult.INVALID_DATA_OBJECT_TYPE: "invalidDataObjectType",
            SubscribeDataobjectsResult.INVALID_PRIORITY: "invalidPriority",
            SubscribeDataobjectsResult.INVALID_FILTER: "invalidFilter",
            SubscribeDataobjectsResult.INVALID_NOTIFICATION_INTERVAL: "invalidNotificationInterval",
            SubscribeDataobjectsResult.INVALID_MULTIPLICITY: "invalidMultiplicity",
            SubscribeDataobjectsResult.INVALID_ORDER: "invalidOrder",
        }[self]


@dataclass(frozen=True)
class SubscribeDataObjectsResp:
    """
    Class that represents Subscribe Data Objects Response as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """
    application_id: int
    subscription_id: int
    result: SubscribeDataobjectsResult
    error_message: str


@dataclass(frozen=True)
class PublishDataobjects:
    """
    Class that represents Publish Data Objects as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """
    subscription_id: int
    requested_data: tuple[str, ...]


@dataclass(frozen=True)
class UnsubscribeDataobjectsReq:
    """
    Class that represents Unsubscribe Data Objects Request as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """
    application_id: int
    subscription_id: int


class UnsubscribeDataobjectsResult(IntEnum):
    """
    Class that represents Unsubscribe Data Objects Result as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """
    ACCEPTED = 0
    REJECTED = 1

    def __str__(self) -> str:
        return {
            UnsubscribeDataobjectsResult.ACCEPTED: "accepted",
            UnsubscribeDataobjectsResult.REJECTED: "rejected",
        }[self]


@dataclass(frozen=True)
class UnsubscribeDataobjectsResp:
    """
    Class that represents Unsubscribe Data Objects Response as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """
    application_id: int
    subscription_id: int
    result: UnsubscribeDataobjectsResult


class ReferenceValue(IntEnum):
    """
    Class that represents Reference Value as specified in ETSI EN 302 895 V1.1.1 (2014-09).
    """
    BOOL_VALUE = 0
    SBYTE_VALUE = 1
    BYTE_VALUE = 2
    SHORT_VALUE = 3
    INT_VALUE = 4
    OCTS_VALUE = 5
    BITS_VALUE = 6
    STR_VALUE = 7
    CAUSE_CODE_VALUE = 8
    SPEED_VALUE = 9
    STATION_ID_VALUE = 10

    def __str__(self) -> str:
        return {
            ReferenceValue.BOOL_VALUE: "boolValue",
            ReferenceValue.SBYTE_VALUE: "sbyteValue",
            ReferenceValue.BYTE_VALUE: "byteValue",
            ReferenceValue.SHORT_VALUE: "shortValue",
            ReferenceValue.INT_VALUE: "intValue",
            ReferenceValue.OCTS_VALUE: "octsValue",
            ReferenceValue.BITS_VALUE: "bitsValue",
            ReferenceValue.STR_VALUE: "strValue",
            ReferenceValue.CAUSE_CODE_VALUE: "causeCodeValue",
            ReferenceValue.SPEED_VALUE: "speedValue",
            ReferenceValue.STATION_ID_VALUE: "stationIDValue",
        }[self]


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
    def haversine_distance(coord1: tuple[float, float], coord2: tuple[float, float]) -> float:
        """
        Function that returns the distance between two coordinates in meters.

        Parameters
        ----------
        coord1 : tuple[float, float]
        coord2 : tuple[float, float]

        Returns
        -------
        float
            Distance in meters between the two coordinates.
        """
        lat1, lon1 = math.radians(coord1[0]), math.radians(coord1[1])
        lat2, lon2 = math.radians(coord2[0]), math.radians(coord2[1])

        dlat, dlon = lat2 - lat1, lon2 - lon1

        a = Utils.haversine_a(dlat, lat1, lat2, dlon)
        c = Utils.haversine_c(a)

        distance = EATH_RADIUS * c

        return distance

    @staticmethod
    def get_nested(data: dict, path: list) -> list | None:
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
    def get_station_id(data_object: dict) -> int | None:
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
        if station_id is None:
            return None
        station_id = int(station_id[0]) if station_id[0] is not None else None
        return station_id

    @staticmethod
    def check_field(data: dict, field_name: str | None = None) -> bool:
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
        return tuple(coord / 10**7 for coord in point)

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
