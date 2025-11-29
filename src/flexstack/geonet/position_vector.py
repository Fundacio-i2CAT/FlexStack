from dateutil import parser
from dataclasses import dataclass
from ..utils.time_service import ITS_EPOCH, ITS_EPOCH_MS, ELAPSED_SECONDS, ELAPSED_MILLISECONDS
from .exceptions import DecodeError
from .gn_address import GNAddress


@dataclass(frozen=True)
class TST:
    """
    Timestamp class.  ETSI EN 302 636-4-1 V1.4.1 (2020-01). Section 9.5.2

    Expresses the time in milliseconds at which
    the latitude and longitude of the ITS-S were
    acquired by the GeoAdhoc router. The time is
    encoded as:
    TST = TST(TAI)mod 2^32
    where TST(TAI) is the number of elapsed TAI
    milliseconds since 2004-01-01 00:00:00.000
    UTC

    Attributes
    ----------
    msec : int
        Milliseconds.
    """

    msec: int = 0

    @classmethod
    def set_in_normal_timestamp_seconds(cls, utc_timestamp_seconds: float) -> "TST":
        """
        Set the timestamp in normal timestamp format.

        Parameters
        ----------
        utc_timestamp_seconds : float
            Timestamp in normal UTC timestamp format.
        """
        msec = ((utc_timestamp_seconds - ITS_EPOCH
                + ELAPSED_SECONDS) * 1000) % 2 ** 32
        return cls(msec=int(msec))

    @classmethod
    def set_in_normal_timestamp_milliseconds(cls, utc_timestamp_milliseconds: int) -> "TST":
        """
        Set the timestamp in normal timestamp format.

        Parameters
        ----------
        utc_timestamp_milliseconds : int
            Timestamp in normal UTC timestamp format.
        """
        msec = (utc_timestamp_milliseconds - ITS_EPOCH_MS
                + ELAPSED_MILLISECONDS) % 2 ** 32
        return cls(msec=int(msec))

    def encode(self) -> int:
        """
        Encode the timestamp.

        Returns
        -------
        int
            Encoded timestamp.
        """
        return self.msec % 2**32

    @classmethod
    def decode(cls, data: int) -> "TST":
        """
        Decode the timestamp.

        Parameters
        ----------
        data : int
            Encoded timestamp.
        """
        return cls(msec=int(data % 2 ** 32))

    def __eq__(self, __o: object) -> bool:
        """
        Equal operator.

        Parameters
        ----------
        __o : object
            Object to compare.

        Returns
        -------
        bool
            True if equal, False otherwise.
        """
        if isinstance(__o, TST):
            return self.msec == __o.msec
        return False

    def __ne__(self, __o: object) -> bool:
        """
        Not equal operator.

        Parameters
        ----------
        __o : object
            Object to compare.

        Returns
        -------
        bool
            True if not equal, False otherwise.
        """
        return not self.__eq__(__o)

    def __gt__(self, __o: object) -> bool:
        """
        Greater than operator.
        Uses the ETSI EN 302 636-4-1 V1.4.1 (2020-01). Annex C.2

        Parameters
        ----------
        __o : object
            Object to compare.

        Returns
        -------
        bool
            True if greater than, False otherwise.
        """
        if isinstance(__o, TST):
            return (self.msec > __o.msec) and ((self.msec - __o.msec) <= (2**32)/2) or (
                (__o.msec > self.msec) and ((__o.msec - self.msec) > (2**32)/2))
        return False

    def __ge__(self, __o: object) -> bool:
        """
        Greater than or equal operator.

        Parameters
        ----------
        __o : object
            Object to compare.

        Returns
        -------
        bool
            True if greater than or equal, False otherwise.
        """
        if isinstance(__o, TST):
            return self.__eq__(__o) or self.__gt__(__o)
            # return (self==__o) or (self>__o)
        return False

    def __lt__(self, __o: object) -> bool:
        """
        Less than operator.

        Parameters
        ----------
        __o : object
            Object to compare.

        Returns
        -------
        bool
            True if less than, False otherwise.
        """
        if isinstance(__o, TST):
            # return not (self>=__o)
            return not self.__ge__(__o)
        return False

    def __le__(self, __o: object) -> bool:
        """
        Less than or equal operator.

        Parameters
        ----------
        __o : object
            Object to compare.

        Returns
        -------
        bool
            True if less than or equal, False otherwise.
        """
        if isinstance(__o, TST):
            # return not (self>__o)
            return not self.__gt__(__o)
        return False

    def __add__(self, __o: object) -> int:
        """
        Add operator.

        Parameters
        ----------
        __o : object
            Object to add.

        Returns
        -------
        int
            Sum.
        """
        if isinstance(__o, TST):
            return (self.msec + __o.msec) % 2**32
        return self.msec

    def __sub__(self, __o: object) -> int:
        """
        Subtract operator.

        Parameters
        ----------
        __o : object
            Object to subtract.

        Returns
        -------
        int
            Difference.
        """
        if isinstance(__o, TST):
            result = self.msec - __o.msec
            if result < 0:
                result += 2**32
            return result
        return self.msec

    def __str__(self) -> str:
        """
        String representation.

        Returns
        -------
        str
            String representation.
        """
        return str(self.msec)+" msec"


@dataclass(frozen=True)
class LongPositionVector:
    """
    Long Position Vector class.  ETSI EN 302 636-4-1 V1.4.1 (2020-01). Section 9.5.2

    Attributes
    ----------
    gn_addr : GNAddress
        GeoNetworking address GN_ADDR.
    tst : TST
        Timestamp TST indicating when the geographical position POS was generated.
    Latitude : int
        Latitude of the ITS-S. WGS 84 1/10 micro degree.
    Longitude : int
        Longitude of the ITS-S. WGS 84 1/10 micro degree.
    pai : bool
        Accuracy of the geographical position PAI. Set to 1 (i.e. True) if the semiMajorConfidence
        of the PosConfidenceEllipse as specified in ETSI TS 102 894-2 [11] is smaller than the GN
        protocol constant itsGnPaiInterval / 2 Set to 0 (i.e. False) otherwise
    s : int
        Speed S. 0.01 m/s.
    h : int
        Heading H. 0.1 degree from north.
    """

    gn_addr: GNAddress = GNAddress()
    tst: TST = TST()
    latitude: int = 0
    longitude: int = 0
    pai: bool = False
    s: int = 0
    h: int = 0

    def set_gn_addr(self, gn_addr: GNAddress) -> "LongPositionVector":
        """
        Set the GN address.

        Parameters
        ----------
        gn_addr : GNAddress
            GN address.
        """
        return LongPositionVector(gn_addr=gn_addr, tst=self.tst, latitude=self.latitude, longitude=self.longitude, pai=self.pai, s=self.s, h=self.h)

    def set_tst_in_normal_timestamp_seconds(self, timestamp: float) -> "LongPositionVector":
        """
        Set the timestamp in normal timestamp format.

        Parameters
        ----------
        timestamp : float
            Timestamp in normal timestamp format.
        """
        tst = self.tst.set_in_normal_timestamp_seconds(timestamp)
        return LongPositionVector(gn_addr=self.gn_addr, tst=tst, latitude=self.latitude, longitude=self.longitude, pai=self.pai, s=self.s, h=self.h)

    def set_tst_in_normal_timestamp_milliseconds(self, timestamp: int) -> "LongPositionVector":
        """
        Set the timestamp in normal timestamp format.

        Parameters
        ----------
        timestamp : int
            Timestamp in normal timestamp format.
        """
        tst = self.tst.set_in_normal_timestamp_milliseconds(timestamp)
        return LongPositionVector(gn_addr=self.gn_addr, tst=tst, latitude=self.latitude, longitude=self.longitude, pai=self.pai, s=self.s, h=self.h)

    def set_latitude(self, latitude: float) -> "LongPositionVector":
        """
        Set the latitude.

        Parameters
        ----------
        latitude : float
            Latitude in WGS 84 1/10 micro degree.
        """
        return LongPositionVector(gn_addr=self.gn_addr, tst=self.tst, latitude=int(latitude * 10000000), longitude=self.longitude, pai=self.pai, s=self.s, h=self.h)

    def set_longitude(self, longitude: float) -> "LongPositionVector":
        """
        Set the longitude.

        Parameters
        ----------
        longitude : float
            Longitude in WGS 84 1/10 micro degree.
        """
        return LongPositionVector(gn_addr=self.gn_addr, tst=self.tst, latitude=self.latitude, longitude=int(longitude * 10000000), pai=self.pai, s=self.s, h=self.h)

    def set_pai(self, pai: bool) -> "LongPositionVector":
        """
        Set the PAI.

        Parameters
        ----------
        pai : bool
            PAI.
        """
        return LongPositionVector(gn_addr=self.gn_addr, tst=self.tst, latitude=self.latitude, longitude=self.longitude, pai=pai, s=self.s, h=self.h)

    def set_speed(self, speed: float) -> "LongPositionVector":
        """
        Set the speed.

        Parameters
        ----------
        speed : float
            Speed in m/s.
        """
        return LongPositionVector(gn_addr=self.gn_addr, tst=self.tst, latitude=self.latitude, longitude=self.longitude, pai=self.pai, s=int(speed * 100), h=self.h)

    def set_heading(self, heading: float) -> "LongPositionVector":
        """
        Set the heading.

        Parameters
        ----------
        heading : float
            Heading in degree from north.
        """
        return LongPositionVector(gn_addr=self.gn_addr, tst=self.tst, latitude=self.latitude, longitude=self.longitude, pai=self.pai, s=self.s, h=int(heading * 10))

    def refresh_with_tpv_data(self, tpv_data: dict) -> "LongPositionVector":
        """
        Refresh the LongPositionVector with a dict containing the data from a GPSD TPV message.

        Parameters
        ----------
        tpv_data : dict
            Dict containing the data from a GPSD TPV message.
        """
        lpv = LongPositionVector(
            gn_addr=self.gn_addr,
            tst=self.tst,
            pai=self.pai,
            latitude=int(tpv_data["lat"] * 10**7),
            longitude=int(tpv_data["lon"] * 10**7),
            s=int(tpv_data["speed"] * 100),
            h=int(tpv_data["track"] * 10)
        )
        lpv = lpv.set_tst_in_normal_timestamp_seconds(
            int(parser.parse(tpv_data["time"]).timestamp()))
        return lpv

    def encode(self) -> bytes:
        """
        Encode the LongPositionVector.

        Returns
        -------
        bytes
            Encoded LongPositionVector.
        """
        return ((self.gn_addr.encode_to_int() << 32*4) | (self.tst.encode() << 32*3) | (
            self.latitude << 32*2) | (self.longitude << 32) | (
                self.pai << 31) | (self.s << 16) | self.h).to_bytes(24, byteorder='big')

    def encode_to_int(self) -> int:
        """
        Encode the LongPositionVector.

        Returns
        -------
        int
            Encoded LongPositionVector.
        """
        return (self.gn_addr.encode_to_int() << 32*4) | (self.tst.encode() << 32*3) | (
            self.latitude << 32*2) | (self.longitude << 32) | (int(self.pai) << 31) | (self.s << 16) | self.h

    @classmethod
    def decode(cls, data: bytes) -> "LongPositionVector":
        """
        Decode the LongPositionVector.

        Parameters
        ----------
        data : bytes
            Encoded LongPositionVector.
        """
        if len(data) < 24:
            raise DecodeError("LongPositionVector must be 24 bytes long")
        data_as_int = int.from_bytes(data[0:24], byteorder='big')
        gn_addr = GNAddress.decode(
            (data_as_int >> 32 * 4).to_bytes(8, byteorder='big'))
        tst = TST.decode(data_as_int >> 32 * 3)
        latitude = (data_as_int >> 32 * 2) & 0xFFFFFFFF
        longitude = (data_as_int >> 32) & 0xFFFFFFFF
        pai = bool((data_as_int >> 31) & 0x1)
        s = (data_as_int >> 16) & 0x7FFF
        h = data_as_int & 0xFFFF
        return cls(gn_addr=gn_addr, tst=tst, latitude=latitude, longitude=longitude, pai=pai, s=s, h=h)

    def __eq__(self, __o: object) -> bool:
        if isinstance(__o, LongPositionVector):
            return (
                self.gn_addr == __o.gn_addr
                and self.tst == __o.tst
                and self.latitude == __o.latitude
                and self.longitude == __o.longitude
                and self.pai == __o.pai
                and self.s == __o.s
                and self.h == __o.h
            )
        return False

    def __str__(self):
        return "LongPositionVector: \n" + \
            "    GN Address: " + str(self.gn_addr) + "\n" + \
            "    Timestamp: " + str(self.tst) + "\n" + \
            "    Latitude: " + str(self.latitude) + "\n" + \
            "    Longitude: " + str(self.longitude) + "\n" + \
            "    PAI: " + str(self.pai) + "\n" + \
            "    Speed: " + str(self.s) + "\n" + \
            "    Heading: " + str(self.h) + "\n"


@dataclass(frozen=True)
class ShortPositionVector:
    """
    Short Position Vector class.  ETSI EN 302 636-4-1 V1.4.1 (2020-01). Section 9.5.2

    Attributes
    ----------
    gn_addr : GNAddress
        GeoNetworking address GN_ADDR.
    tst : TST
        Timestamp TST indicating when the geographical position POS was generated.
    latitude : int
        Latitude of the ITS-S. WGS 84 1/10 micro degree.
    longitude : int
        Longitude of the ITS-S. WGS 84 1/10 micro degree.
    """

    gn_addr: GNAddress = GNAddress()
    tst: TST = TST()
    latitude: int = 0
    longitude: int = 0

    def set_gn_addr(self, gn_addr: GNAddress) -> "ShortPositionVector":
        """
        Set the GN address.

        Parameters
        ----------
        gn_addr : GNAddress
            GN address.
        """
        return ShortPositionVector(gn_addr=gn_addr, tst=self.tst, latitude=self.latitude, longitude=self.longitude)

    def set_tst_in_normal_timestamp_seconds(self, timestamp: int) -> "ShortPositionVector":
        """
        Set the timestamp in normal timestamp format.

        Parameters
        ----------
        timestamp : int
            Timestamp in normal timestamp format.
        """
        tst = self.tst.set_in_normal_timestamp_seconds(timestamp)
        return ShortPositionVector(gn_addr=self.gn_addr, tst=tst, latitude=self.latitude, longitude=self.longitude)

    def set_tst_in_normal_timestamp_milliseconds(self, timestamp: int) -> "ShortPositionVector":
        """
        Set the timestamp in normal timestamp format.

        Parameters
        ----------
        timestamp : int
            Timestamp in normal timestamp format.
        """
        tst = self.tst.set_in_normal_timestamp_milliseconds(timestamp)
        return ShortPositionVector(gn_addr=self.gn_addr, tst=tst, latitude=self.latitude, longitude=self.longitude)

    def set_latitude(self, latitude: float) -> "ShortPositionVector":
        """
        Set the latitude.

        Parameters
        ----------
        latitude : float
            Latitude in WGS 84 1/10 micro degree.
        """
        return ShortPositionVector(gn_addr=self.gn_addr, tst=self.tst, latitude=int(latitude * 10000000), longitude=self.longitude)

    def get_latitude(self) -> float:
        """
        Get the latitude.

        Returns
        -------
        float
            Latitude in WGS 84 1/10 micro degree.
        """
        return self.latitude/10000000

    def set_longitude(self, longitude: float) -> "ShortPositionVector":
        """
        Set the longitude.

        Parameters
        ----------
        longitude : float
            Longitude in WGS 84 1/10 micro degree.
        """
        return ShortPositionVector(gn_addr=self.gn_addr, tst=self.tst, latitude=self.latitude, longitude=int(longitude * 10000000))

    def get_longitude(self) -> float:
        """
        Get the longitude.

        Returns
        -------
        float
            Longitude in WGS 84 1/10 micro degree.
        """
        return self.longitude/10000000

    def encode(self) -> bytes:
        """
        Encode the ShortPositionVector.

        Returns
        -------
        bytes
            Encoded ShortPositionVector.
        """
        return ((self.gn_addr.encode_to_int() << 32*3) | (self.tst.encode() << 32*2) | (
            self.latitude << 32*1) | self.longitude).to_bytes(20, byteorder='big')

    def encode_to_int(self) -> int:
        """
        Encode the ShortPositionVector.

        Returns
        -------
        int
            Encoded ShortPositionVector.
        """
        return (self.gn_addr.encode_to_int() << 32*3) | (self.tst.encode() << 32*2) | (
            self.latitude << 32*1) | self.longitude

    @classmethod
    def decode(cls, data: bytes) -> "ShortPositionVector":
        """
        Decode the ShortPositionVector.

        Parameters
        ----------
        data : bytes
            Encoded ShortPositionVector.
        """
        data_int = int.from_bytes(data, byteorder='big')
        gn_addr = GNAddress.decode(
            (data_int >> 32 * 3).to_bytes(8, byteorder='big'))
        tst = TST.decode(data_int >> 32 * 2)
        latitude = (data_int >> 32 * 1) & 0xFFFFFFFF
        longitude = data_int & 0xFFFFFFFF
        return cls(gn_addr=gn_addr, tst=tst, latitude=latitude, longitude=longitude)

    def __eq__(self, __o: object) -> bool:
        if isinstance(__o, ShortPositionVector):
            return (
                self.gn_addr == __o.gn_addr
                and self.tst == __o.tst
                and self.latitude == __o.latitude
                and self.longitude == __o.longitude
            )
        return False
