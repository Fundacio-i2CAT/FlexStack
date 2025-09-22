"""
Location Service Module

This module contains the LocationService class, which is used to get the current
location from a GPSD server.

Usage:
    from location_service import LocationService

    # Initialize a new LocationService instance
    location_service = LocationService(gpsd_host='localhost', gpsd_port=2947)

    # Add a callback function to be called when a new location is received
    def my_callback(location):
        print(f'New location received: {location}')

    location_service.add_callback(my_callback)

Attributes
----------
gpsd_host : str
    The hostname or IP address of the GPSD server.
gpsd_port : int
    The port number of the GPSD server.
socket : socket.socket
    The socket object used to communicate with the GPSD server.
callbacks : List[Callable[[dict], None]]
    A list of callback functions to be called when a new location is received.

Classes
-------
LocationService
    A class that connects to a GPSD server and provides current location data.
"""
from __future__ import annotations
import logging
import threading
import socket
import json
from .location_service import LocationService


class GPSDLocationService(LocationService):
    """
    Location Service

    This class is used to get the location.

    Attributes
    ----------
    gpsd_host : str
        The host of the gpsd server.
    gpsd_port : int
        The port of the gpsd server.
    socket : socket.socket
        The socket to the gpsd server.
    callbacks : List[Callable[[dict], None]]
        The callbacks to call when a new location is received.
    """

    def __init__(self, gpsd_host: str = "localhost", gpsd_port: int = 2947) -> None:
        """
        Initialize the Location Service.

        Parameters
        ----------
        gpsd_host : str
            The host of the gpsd server.
        gpsd_port : int
            The port of the gpsd server.
        """
        super().__init__()
        self.logger = logging.getLogger("GPSDLocationService")
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.gpsd_host = gpsd_host
        self.gpsd_port = gpsd_port
        self.stop_event = threading.Event()
        self.location_service_thread = threading.Thread(
            target=self.start, daemon=True)
        self.location_service_thread.start()

    def __del__(self) -> None:
        """
        Destroy the Location Service.
        """
        self.socket.close()

    def reconnect(self) -> None:
        """
        Reconnect the Location Service.
        """
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(10)
        connected = False
        while not connected:
            try:
                self.socket.connect((self.gpsd_host, self.gpsd_port))
                connected = True
            except TimeoutError:
                pass
            except InterruptedError:
                pass
            except ConnectionRefusedError:
                self.logger.warning(
                    "ConnectionRefusedError: [Errno 111] Connection refused, trying again...")
        try:
            self.socket.send(b'?WATCH={"enable":true,"json":true};')
        except BrokenPipeError:
            self.reconnect()

    def start(self) -> None:
        """
        Starts the Location Service Thread.
        """
        self.reconnect()
        while not self.stop_event.is_set():
            try:
                data = self.socket.recv(1024)
                if data:
                    json_data = {}
                    try:
                        json_data = json.loads(data)
                    except ValueError:
                        self.logger.debug("Could not decode data")
                        self.logger.debug(data)
                    if "class" in json_data and json_data["class"] == "TPV":
                        self.send_to_callbacks(json_data)
            except BrokenPipeError:
                self.reconnect()
            except ConnectionResetError:
                self.reconnect()
            except TimeoutError:
                self.reconnect()
