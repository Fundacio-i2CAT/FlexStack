import datetime


class TimeService:
    """
    Time Service that provides the current time.

    This class serves as a blueprint in implementations where the time comes
    from other devices or services different from the system time.
    """

    @staticmethod
    def time() -> float:
        """
        Get the current time.

        Returns
        -------
        float
            The current time.
        """
        return datetime.datetime.now(datetime.timezone.utc).timestamp()
