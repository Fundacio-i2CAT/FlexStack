import threading
import time
import asyncio
import datetime
from .location_service import LocationService


def generate_tpv_dict(current_utc_timestamp: float, latitude: float, longitude: float) -> dict:
    """
    Generate a TPV dictionary with the given UTC timestamp, latitude, and longitude.

    Parameters
    ----------
    current_utc_timestamp : float
        The current UTC timestamp.
    latitude : float
        The latitude of the location.
    longitude : float
        The longitude of the location.

    Returns
    -------
    dict
        A dictionary containing the TPV data.
    """
    tt_dt = datetime.datetime.fromtimestamp(
        current_utc_timestamp, datetime.timezone.utc)
    tt = tt_dt.isoformat()
    tt = tt[:-9] + "Z"
    return {'class': 'TPV',
            'device': '/dev/ttyACM0',
            'mode': 3,
            'time': tt,
            'ept': 0.005,
            'lat': latitude,
            'lon': longitude,
            'alt': 163.8,
            'epx': 10.0,
            'epy': 10.0,
            'epv': 10.0,
            'track': 0.0,
            'speed': 0.0,
            'climb': 0.0,
            'eps': 0.0}


def generate_tpv_dict_with_current_timestamp(latitude: float, longitude: float) -> dict:
    """
    Generate a TPV dictionary with the current UTC timestamp, latitude, and longitude.

    Parameters
    ----------
    latitude : float
        The latitude of the location.
    longitude : float
        The longitude of the location.

    Returns
    -------
    dict
        A dictionary containing the TPV data.
    """
    current_utc_timestamp = datetime.datetime.now(
        datetime.timezone.utc).timestamp()
    return generate_tpv_dict(current_utc_timestamp, latitude, longitude)


class AsyncStaticLocationService(LocationService):
    """
    Location Servie that just provides an static position.

    Attributes
    ----------
    period : int
        Periodicity of the location update in ms.
    latitude : float
        Latitude of the static location.
    longitude : float
        Longitude of the static location.
    """

    def __init__(
        self,
        period: int = 1000,
        latitude: float = 41.387304,
        longitude: float = 2.112485,
    ) -> None:
        """
        Initialize the Static Location Service.
        period : int
            Periodicity of the location update in ms.
        static_location : dict
            The static location to provide. (In TPV format)
        """
        super().__init__()
        self.period = period
        self.latitude = latitude
        self.longitude = longitude

    async def start_async(self) -> None:
        # pylint: disable=duplicate-code
        """
        Start the Static Location Service.
        """
        while True:
            json_tpv = generate_tpv_dict_with_current_timestamp(
                self.latitude, self.longitude)
            self.send_to_callbacks(json_tpv)
            await asyncio.sleep(self.period / 1000)


class ThreadStaticLocationService(LocationService):
    """
    Location Servie that just provides an static position.

    Attributes
    ----------
    period : int
        Periodicity of the location update in ms.
    latitude : float
        Latitude of the static location.
    longitude : float
        Longitude of the static location.
    location_service_thread : threading.Thread
        The thread of the location service.
    """

    def __init__(
        self,
        period: int = 1000,
        latitude: float = 41.387304,
        longitude: float = 2.112485,
    ) -> None:
        """
        Initialize the Static Location Service.
        period : int
            Periodicity of the location update in ms.
        latitude : float
            Latitude of the static location.
        longitude : float
            Longitude of the static location.
        """
        super().__init__()
        self.period = period
        self.latitude = latitude
        self.longitude = longitude
        self.location_service_thread = threading.Thread(
            target=self.start, daemon=True)
        self.stop_event = threading.Event()
        self.location_service_thread.start()

    def start(self) -> None:
        # pylint: disable=duplicate-code
        """
        Start the Static Location Service.
        """
        while not self.stop_event.is_set():
            json_tpv = generate_tpv_dict_with_current_timestamp(
                self.latitude, self.longitude)
            self.send_to_callbacks(json_tpv)
            time.sleep(self.period / 1000)
