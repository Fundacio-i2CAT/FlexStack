from .ldm_constants import (
    RESULT_INVALID_ITS_AID,
    RESULT_NOT_AUTHORIZED,
    RESULT_UNABLE_APPLICATION_AUTHENTICATION,
)


class InterfaceLDM2:
    """
    Class specified is described in ETSI EN 302 895 V1.1.1 (2014-09). Section 5.4.2.
    The IF.LDM.2 interface is responsible for the exchange of information with the ITS Security Layer, as described
    in EN 302 665.
    The ITS security layer will exchange information with the LDM across interface IF.LDM.2 in order to revoke the
    authorization of previously authorized iTS LDM Data Provider/Consumer.
    TODO: Finish once Security Layer is implemented

    Attributes
    ----------
    None
    """

    def __init__(self) -> None:
        pass


class Authorization:
    """
    Class to handle Authorization requests.

    """

    def __init__(self, its_application_identifider: str, permissions_granted: int):
        self.its_application_identifider = its_application_identifider
        self.permissions_granted = permissions_granted
        self.result = 0

    def check_its_aid(self) -> bool:
        """
        Check if the ITS AID is valid.

        Returns
        -------
        bool
            True if ITS AID is valid, False otherwise.
        """
        raise NotImplementedError("TODO: Finish once Security Layer is implemented")

    def check_permissions(self) -> bool:
        """
        Check permissions granted.

        Returns
        -------
        bool
            True if permissions granted, False otherwise.
        """
        raise NotImplementedError("TODO: Finish once Security Layer is implemented")

    def check_application_authentication(self) -> bool:
        """
        Check application authentication.

        Returns
        -------
        bool
            True if application authenticated, False otherwise.
        """
        raise NotImplementedError("TODO: Finish once Security Layer is implemented")

    def generate_result(self) -> str:
        """
        Check if the ITS AID is valid, permissions granted and application authenticated.
        If all checks are passed, return RESULT_OK.

        Returns
        -------
        str
            RESULT_OK if all checks are passed, otherwise return the corresponding error.
        """
        if not self.check_its_aid():
            return RESULT_INVALID_ITS_AID
        if not self.check_permissions():
            return RESULT_NOT_AUTHORIZED
        if not self.check_application_authentication():
            return RESULT_UNABLE_APPLICATION_AUTHENTICATION

        raise NotImplementedError("TODO: Finish once Security Layer is implemented")

    def __str__(self) -> str:
        return f"Its_application_identifider: {self.its_application_identifider}, \
            Permissions_granted: {self.permissions_granted}, Result: {self.result}"
