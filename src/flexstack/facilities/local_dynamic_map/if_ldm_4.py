from __future__ import annotations
from collections.abc import Callable
import logging
from .ldm_constants import (
    DENM,
    DATA_OBJECT_TYPE_ID,
    MAPEM,
    SPATEM,
    VALID_ITS_AID,
)
from .ldm_classes import (
    AccessPermission,
    Filter,
    OrderTupleValue,
    OrderingDirection,
    RegisterDataConsumerReq,
    RequestDataObjectsReq,
    RequestDataObjectsResp,
    SubscribeDataobjectsReq,
    SubscribeDataObjectsResp,
    DeregisterDataConsumerAck,
    DeregisterDataConsumerReq,
    SubscribeDataobjectsResult,
    RegisterDataConsumerResp,
    RequestedDataObjectsResult,
    DeregisterDataConsumerResp,
    RegisterDataConsumerResult,
    TimestampIts,
    UnsubscribeDataConsumerReq,
    UnsubscribeDataConsumerResp,
    UnsubscribeDataConsumerAck,
)
from .ldm_service import LDMService


class InterfaceLDM4:
    """
    Class specified is described in ETSI EN 302 895 V1.1.1 (2014-09). Section 5.4.4.
    The LDM shall provide an interface IF.LDM.4 to enable an application or facility to register as a LDM Data Consumer

    Data consumers, in our implementation, ask for data in the form of dataframes,
    as specified in ETSI TS 102 894-2 V1.3.1 (2018-08) and updated in https://forge.etsi.org/rep/ITS/asn1.

    Attributes
    ----------
    TODO: Add attributes
    TODO: There is replicated code (IF_LDM_3 and IF_LDM_4). Check if it can be removed.

    """

    def __init__(self, ldm_service: LDMService) -> None:
        self.logging = logging.getLogger("local_dynamic_map")

        self.ldm_service = ldm_service

    def check_its_aid(self, its_application_identifier) -> bool:
        """
        Method specified in ETSI EN 302 895 V1.1.1 (2014-09). Section 6.2.1
        It checks the ITS-AID of the application that wants to register as a data provider.

        Parameters
        ----------
        its_application_identifier : int
            ITS-AID of the application that wants to register as a data provider
        """
        return (
            isinstance(its_application_identifier, int)
            and its_application_identifier in VALID_ITS_AID
        )

    def check_permissions(self, permissions_granted: tuple[AccessPermission, ...], data_object_id: int) -> bool:
        """
        Method that checks permissions to grant access to the data provider
        as specified in ETSI EN 302 895 V1.1.1 (2014-09). Section 6.2.1.
        TODO: Implement better security. Currenlty very basic security is implemented.

        Parameters
        ----------
        permissions_granted : list
            List of permissions granted to the data provider
        dataObjectID : int
        """
        if len(permissions_granted) == 0:
            return False
        for permission in permissions_granted:
            if permission == data_object_id:
                return True
            # TODO: Change SPATEM and MAPEM!!! DENMs have access to all data objects.
            if data_object_id in (DENM, SPATEM, MAPEM):
                return True
        return False

    def register_data_consumer(
        self, data_consumer: RegisterDataConsumerReq
    ) -> RegisterDataConsumerResp:
        """
        Method specified in ETSI EN 302 895 V1.1.1 (2014-09). Section 6.3.1.1
        TODO: Apply Security. Currenly gives access to anyone sending valid information.
        TODO: Validate check permissions and its_aid.

        Parameters
        ----------
        data_consumer : RegisterDataConsumerReq
            RegisterDataConsumerReq as specified in ETSI EN 302 895 V1.1.1 (2014-09). Section Annex B.
        """
        if (
            data_consumer is None
            or self.check_its_aid(data_consumer.application_id) is False
            or self.check_permissions(
                data_consumer.access_permisions, data_consumer.application_id
            )
            is False
        ):
            return RegisterDataConsumerResp(
                data_consumer.application_id, tuple(), RegisterDataConsumerResult(2)
            )
        self.ldm_service.add_data_consumer_its_aid(
            data_consumer.application_id)
        self.logging.debug(
            "Registered new LDM Data Consumer with application_id %d",
            data_consumer.application_id,
        )
        return RegisterDataConsumerResp(
            data_consumer.application_id,
            data_consumer.access_permisions,
            RegisterDataConsumerResult(0),
        )

    def deregister_data_consumer(
        self, data_consumer: DeregisterDataConsumerReq
    ) -> DeregisterDataConsumerResp:
        """
        Method specified in ETSI EN 302 895 V1.1.1 (2014-09). Section 6.3.2.1
        Returning ACK 0 if the application is registered (and now will be unregistered) and
        ACK 1 if it is not (and will not be unregistered).
        """
        self.logging.debug(
            "Deregistring LDM Data Consumer wtih application_id: %d",
            data_consumer.application_id,
        )

        if data_consumer.application_id in self.ldm_service.get_data_consumer_its_aid():
            self.ldm_service.del_data_consumer_its_aid(
                data_consumer.application_id)
            return DeregisterDataConsumerResp(
                data_consumer.application_id, DeregisterDataConsumerAck(0)
            )
        return DeregisterDataConsumerResp(
            data_consumer.application_id, DeregisterDataConsumerAck(1)
        )

    def request_data_objects(
        self, data_request: RequestDataObjectsReq
    ) -> RequestDataObjectsResp:
        """
        Method specified in ETSI EN 302 895 V1.1.1 (2014-09). Section 6.3.3
        TODO: Add error message in response if result is not successful.
        TODO: Raise errors! Create an expection file!
        Parameters
        ----------
        data_request : RequestDataObjectsReq
            RequestDataObjectsReq as specified in ETSI EN 302 895 V1.1.1 (2014-09). Section Annex B.
        """
        self.logging.debug(
            "LDM Data Consumer with application id %s, asking for the following data types; %s",
            data_request.application_id,
            data_request.data_object_type,
        )
        if (
            data_request.application_id
            not in self.ldm_service.get_data_consumer_its_aid()
        ):
            return RequestDataObjectsResp(
                data_request.application_id, (), RequestedDataObjectsResult.INVALID_ITSA_ID
            )
        for data_object_type in data_request.data_object_type:
            if data_object_type not in DATA_OBJECT_TYPE_ID:
                return RequestDataObjectsResp(
                    data_request.application_id, (), RequestedDataObjectsResult.INVALID_DATA_OBJECT_TYPE
                )

        if data_request.priority is not None:
            if data_request.priority < 0 or data_request.priority > 255:
                return RequestDataObjectsResp(
                    data_request.application_id, (), RequestedDataObjectsResult.INVALID_PRIORITY
                )
        if data_request.order is not None:
            if not isinstance(data_request.order, list):
                return RequestDataObjectsResp(
                    data_request.application_id,
                    (),
                    RequestedDataObjectsResult.INVALID_ORDER,
                )
        if data_request.filter is not None:
            if not isinstance(data_request.filter, Filter):
                return RequestDataObjectsResp(
                    data_request.application_id, (), RequestedDataObjectsResult.INVALID_FILTER
                )
        data_objects: tuple[tuple[dict, ...], ...] = self.ldm_service.query(
            data_request
        )  # Find data objects in LDM Maintance DataBases
        self.logging.debug(
            "LDM Data Consumer with application id %s, has recieved %s.",
            data_request.application_id,
            len(data_objects),
        )
        return RequestDataObjectsResp(
            data_request.application_id, data_objects[0], RequestedDataObjectsResult.SUCCEED
        )

    def subscribe_data_consumer(
        self,
        subscribe_data_consumer: SubscribeDataobjectsReq,
        callback: Callable[[RequestDataObjectsResp], None],
    ) -> SubscribeDataObjectsResp:
        """
        Method specified in ETSI EN 302 895 V1.1.1 (2014-09). Section 6.3.4.1
        Method parameters have been modified in order to implement standard.
        Currently, the "callback" parameter is used to "PublishDataObject".
        New Version -> SubscribeDataobjectsReq(applicationId,
                                                dataObjects,
                                                callback,
                                                priority,
                                                order,
                                                filter,
                                                notifyTime,
                                                multiplicity,
                                                order)
        Standard Version -> SubscribeDataobjectsReq(applicationId,
                                                    dataObjects,
                                                    priority,
                                                    order,
                                                    filter,
                                                    notifyTime,
                                                    multiplicity,
                                                    order)

        Parameters
        ----------
        subscribe_data_consumer : SubscribeDataobjectsReq
            SubscribeDataobjectsReq as specified in ETSI EN 302 895 V1.1.1 (2014-09). Section Annex B.
        callback : Callable[[None], None]
            Callback function that will be called when data is available for the data consumer.
        """
        self.logging.debug(
            "LDM Data Consumer subscribed with application id %s",
            str(subscribe_data_consumer),
        )
        result = self.validate_subscribe_data_consumer(subscribe_data_consumer)

        if result is not None:
            return result

        subscription_id = self.store_subscription_info(
            subscribe_data_consumer, callback
        )

        return SubscribeDataObjectsResp(
            subscribe_data_consumer.application_id,
            subscription_id,
            SubscribeDataobjectsResult.SUCCESSFUL,
            "",
        )

    def validate_subscribe_data_consumer(
        self,
        subscribe_data_consumer: SubscribeDataobjectsReq,
    ) -> SubscribeDataObjectsResp | None:
        """
        Method that groups all the validation methods for the SubscribeDataobjectsReq

        Parameters
        ----------
        subscribe_data_consumer : SubscribeDataobjectsReq
            SubscribeDataobjectsReq as specified in ETSI EN 302 895 V1.1.1 (2014-09). Section Annex B.

        Returns
        -------
        SubscribeDataObjectsResp | None
            SubscribeDataObjectsResp with error message if there is an error, None otherwise.
        """
        if not self.is_valid_its_aid(subscribe_data_consumer.application_id):
            return SubscribeDataObjectsResp(
                subscribe_data_consumer.application_id,
                0,
                SubscribeDataobjectsResult.INVALID_ITSA_ID,
                "Invalid ITS-AID",
            )

        if not self.is_valid_data_object_type(subscribe_data_consumer.data_object_type):
            return SubscribeDataObjectsResp(
                subscribe_data_consumer.application_id,
                0,
                SubscribeDataobjectsResult.INVALID_DATA_OBJECT_TYPE,
                "Invalid data object type",
            )

        if subscribe_data_consumer.priority is not None and not self.is_valid_priority(subscribe_data_consumer.priority):
            return SubscribeDataObjectsResp(
                subscribe_data_consumer.application_id,
                0,
                SubscribeDataobjectsResult.INVALID_PRIORITY,
                "Invalid priority",
            )

        if subscribe_data_consumer.order is not None and not self.is_valid_order(subscribe_data_consumer.order):
            return SubscribeDataObjectsResp(
                subscribe_data_consumer.application_id,
                0,
                SubscribeDataobjectsResult.INVALID_ORDER,
                "Invalid order",
            )

        if subscribe_data_consumer.filter is not None and not self.is_valid_filter(subscribe_data_consumer.filter):
            return SubscribeDataObjectsResp(
                subscribe_data_consumer.application_id,
                0,
                SubscribeDataobjectsResult.INVALID_FILTER,
                "Invalid filter",
            )

        if not self.is_valid_notify_time(subscribe_data_consumer.notify_time):
            return SubscribeDataObjectsResp(
                subscribe_data_consumer.application_id,
                0,
                SubscribeDataobjectsResult.INVALID_NOTIFICATION_INTERVAL,
                "Invalid notifyTime",
            )

        if not self.is_valid_multiplicity(subscribe_data_consumer.multiplicity):
            return SubscribeDataObjectsResp(
                subscribe_data_consumer.application_id,
                0,
                SubscribeDataobjectsResult.INVALID_MULTIPLICITY,
                "Invalid multiplicity",
            )

        return None

    def is_valid_its_aid(self, application_id: int) -> bool:
        """
        Method to check if application_id (its aid) is valid as specified
        in ETSI EN 302 895 V1.1.1 (2014-09). Section 6.3.4

        Parameters
        ----------
        application_id : int
            Application ID to be checked

        Returns
        -------
        bool
            True if application_id is valid, False otherwise.
        """
        return application_id in self.ldm_service.get_data_consumer_its_aid()

    def is_valid_data_object_type(self, data_object_type: tuple[int, ...]) -> bool:
        """
        Method to check if data_object_types are valid as specified in CDD TS 102 894-2.

        Parameters
        ----------
        data_object_types : list
            List of data object types to be checked

        Returns
        -------
        bool
            True if data_object_types are valid, False otherwise.
        """
        return all(
            data_object_type in DATA_OBJECT_TYPE_ID
            for data_object_type in data_object_type
        )

    def is_valid_priority(self, priority: int) -> bool:
        """
        Method to check if priority is valid as specified in ETSI EN 302 895 V1.1.1 (2014-09). Section 6.3.4

        Parameters
        ----------
        priority : int
            Priority to be checked

        Returns
        -------
        bool
            True if priority is valid, False otherwise.
        """
        return priority is None or (0 <= priority <= 255)

    def is_valid_order(self, order: tuple[OrderTupleValue, ...]) -> bool:
        """
        Method to check if order is valid as specified in ETSI EN 302 895 V1.1.1 (2014-09). Section 6.3.4

        Parameters
        ----------
        order : tuple[OrderTuple, ...]
            Order to be checked

        Returns
        -------
        bool
            True if order is valid, False otherwise.
        """
        return all(o.ordering_direction in [OrderingDirection.ASCENDING, OrderingDirection.DESCENDING] for o in order)

    def is_valid_filter(self, data_filter: Filter) -> bool:
        """
        Method to check if filter is valid as specified in ETSI EN 302 895 V1.1.1 (2014-09). Section 6.3.4

        Parameters
        ----------
        data_filter : Filter
            Filter to be checked

        Returns
        -------
        bool
            True if filter is valid, False otherwise.
        """
        return data_filter is None or isinstance(data_filter, Filter)

    def is_valid_notify_time(self, notify_time: TimestampIts) -> bool:
        """
        Method to check if notifyTime is valid as specified in ETSI EN 302 895 V1.1.1 (2014-09). Section 6.3.4

        Parameters
        ----------
        notify_time : int
            NotifyTime to be checked

        Returns
        -------
        bool
            True if notifyTime is valid, False otherwise.
        """
        return notify_time is None or (0 <= notify_time.timestamp_its <= 4398046511103)

    def is_valid_multiplicity(self, multiplicity: int) -> bool:
        """
        Method to check if the multiplicity value is valid as specified
        in ETSI EN 302 895 V1.1.1 (2014-09). Section 6.3.4

        Parameters
        ----------
        multiplicity : int
            Multiplicity to be checked

        Returns
        -------
        bool
            True if multiplicity is valid, False otherwise.
        """
        return multiplicity is None or (0 <= multiplicity <= 255)

    def store_subscription_info(
        self, subscribe_data_consumer: SubscribeDataobjectsReq, callback: Callable
    ) -> int:
        """
        Method to store subscription information as specified in ETSI EN 302 895 V1.1.1 (2014-09). Section 6.3.4

        Parameters
        ----------
        subscribe_data_consumer : SubscribeDataobjectsReq
            SubscribeDataobjectsReq as specified in ETSI EN 302 895 V1.1.1 (2014-09). Section Annex B.
        callback : Callable[[None], None]
            Callback function that will be called when data is available for the data consumer.

        Returns
        -------
        int
            Subscription ID (index of the subscription in the database)
        """
        return self.ldm_service.store_new_subscription_petition(
            subscription_request=subscribe_data_consumer,
            callback=callback,
        )

    def unsubscribe_data_consumer(
        self, unsubscribe_data_consumer: UnsubscribeDataConsumerReq
    ):
        """
        Method specified in ETSI EN 302 895 V1.1.1 (2014-09). Section 6.3.5.1
        Current standard doesn't have ASN.1 implementation for UnsubscribeDataConsumerReq
        or UnsubscribeDataConsumerResp so it has been implemented in-house.
        Will have to be updated once standard is updated.

        Parameters
        ----------
        unsubscribe_data_consumer : UnsubscribeDataConsumerReq
            UnsubscribeDataConsumerReq as specified in ETSI EN 302 895 V1.1.1 (2014-09). Section Annex B.
        """
        self.logging.debug(
            "LDM Data Consumer Subscriber with application_id %s has unsubscribed.",
            unsubscribe_data_consumer.application_id,
        )
        if (
            unsubscribe_data_consumer.application_id
            not in self.ldm_service.get_data_consumer_its_aid()
        ):
            return UnsubscribeDataConsumerResp(
                unsubscribe_data_consumer.application_id,
                0,
                UnsubscribeDataConsumerAck.FAILED,
            )

        if not isinstance(unsubscribe_data_consumer.subscription_id, int):
            return UnsubscribeDataConsumerResp(
                unsubscribe_data_consumer.application_id,
                unsubscribe_data_consumer.subscription_id,
                UnsubscribeDataConsumerAck.FAILED,
            )

        if not self.ldm_service.delete_subscription(
            unsubscribe_data_consumer.subscription_id
        ):
            return UnsubscribeDataConsumerResp(
                unsubscribe_data_consumer.application_id,
                unsubscribe_data_consumer.subscription_id,
                UnsubscribeDataConsumerAck(1),
            )

        return UnsubscribeDataConsumerResp(
            unsubscribe_data_consumer.application_id,
            unsubscribe_data_consumer.subscription_id,
            UnsubscribeDataConsumerAck(0),
        )
