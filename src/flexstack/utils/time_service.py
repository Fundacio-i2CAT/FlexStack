import datetime

ITS_EPOCH = 1072915200
ITS_EPOCH_MS = ITS_EPOCH * 1000
ELAPSED_SECONDS = 5
ELAPSED_MILLISECONDS = ELAPSED_SECONDS * 1000


class TimeService:
    """
    Time Service that provides the current time.

    This class serves as a blueprint in implementations where the time comes
    from other devices or services different from the system time.
    """

    @staticmethod
    def time() -> float:
        """
        Get the current UTC Timestamp in Seconds.

        Returns
        -------
        float
            UTC Timestamp in Seconds.
        """
        return datetime.datetime.now(datetime.timezone.utc).timestamp()

    @staticmethod
    def timestamp_its() -> int:
        """
        Get the current ITS Timestamp in Milliseconds.

        Returns
        -------
        int
            ITS Timestamp in Milliseconds(with leap seconds added).
        """
        return int((TimeService.time() - ITS_EPOCH + ELAPSED_SECONDS) * 1000)
