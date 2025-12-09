from __future__ import annotations
from collections.abc import Callable
import json
import threading

from .ldm_classes import (
    AddDataProviderReq,
    OrderingDirection,
    RequestDataObjectsResp,
    RequestedDataObjectsResult,
    RequestDataObjectsReq,
    OrderTupleValue,
    SubscribeDataobjectsReq,
    TimestampIts,
    Utils,
    SubscriptionInfo
)
from .ldm_constants import (
    DATA_OBJECT_TYPE_ID,
)
from .ldm_maintenance import (
    LDMMaintenance,
)


class LDMService:
    """
    Class specified in the ETSI ETSI EN 302 895 V1.1.1 (2014-09). Section 5.3.
    The Local Dynamic Map (LDM) Service component is responsible for providing functionalities to authorized LDM data
    Providers and Consumers for LDM data manipulation
    (such as adding new data, modifying existing data, delete existing data), direct access to data (query data)
    and a publish/subscribe mechanism for data access by LDM Data Consumers

    Attributes
    ----------
    ldm_maintenance : LDMMaintenance
        Backend component that stores, updates and retrieves data containers.
    data_provider_its_aid : set[int]
        Thread-safe set with the ITS-AID values of registered data providers.
    data_consumer_its_aid : set[int]
        Thread-safe set with the ITS-AID values of registered data consumers.
    subscriptions : list[SubscriptionInfo]
        Active subscription records registered by data consumers.
    last_checked_subscriptions_time : dict[SubscriptionInfo, TimestampIts]
        Tracks the last notification timestamp per subscription.
    _lock : threading.RLock
        Reentrant lock guarding shared mutable state in the service.

    """

    def __init__(self, ldm_maintenance: LDMMaintenance) -> None:
        self.ldm_maintenance = ldm_maintenance
        self.data_provider_its_aid: set[int] = set()
        self.data_consumer_its_aid: set[int] = set()
        self.subscriptions: list[SubscriptionInfo] = []
        self.last_checked_subscriptions_time: dict[SubscriptionInfo, TimestampIts] = {
        }
        self._lock = threading.RLock()

    def attend_subscriptions(self) -> None:
        """
        Method to attend subscriptions as specified in the ETSI EN 302 895 V1.1.1 (2014-09). Section 6.3.4.
        """
        with self._lock:
            subscriptions = self.subscriptions.copy()
        subscriptions_to_remove = set()
        for subscription in subscriptions:
            search_result = self.search_data(subscription)
            if not search_result:
                continue
            if subscription.subscription_request.multiplicity is not None and subscription.subscription_request.multiplicity > len(search_result):
                continue

            ordered_search_result = search_result
            if subscription.subscription_request.order is not None:
                ordered_sequences = self.order_search_results(
                    search_result, subscription.subscription_request.order
                )
                if ordered_sequences:
                    ordered_search_result = ordered_sequences[0]
            self.process_notifications(subscription, ordered_search_result)
            data_consumer_its_aid = self.get_data_consumer_its_aid()
            if subscription.subscription_request.application_id not in data_consumer_its_aid:
                subscriptions_to_remove.add(subscription)
        for subscription in subscriptions_to_remove:
            self.remove_subscription(subscription)

    def search_data(self, subscription: SubscriptionInfo) -> tuple[dict, ...]:
        """
        Method to search data by using the filter in the subscription.

        Parameters
        ----------
        subscription : dict
            Subscription information (in dictionary format).
        Returns
        -------
        tuple[dict, ...]
            tuple of data objects that match the filter.
        """
        if subscription.subscription_request.filter is not None and subscription.subscription_request.order is not None and subscription.subscription_request.priority is not None:
            data_request = RequestDataObjectsReq(
                subscription.subscription_request.application_id,
                subscription.subscription_request.data_object_type,
                subscription.subscription_request.priority,
                subscription.subscription_request.order,
                subscription.subscription_request.filter,
            )
            return self.ldm_maintenance.data_containers.search(data_request)
        return ()

    def filter_data_object_type(
        self, search_result: tuple[dict, ...], allowed_types: tuple[str, ...]
    ) -> tuple[dict, ...]:
        """
        Method to filter data objects by type.

        Parameters
        ----------
        search_result : tuple[dict, ...]
            tuple of data objects that match the filter.
        allowed_types : list[str]
            list of allowed data object types
            (as specified in the ETSI TS 102 894-2 V2.2.1 (2023-10), i.e. CAM, DENM,...).

        Returns
        -------
        tuple[dict, ...]
            tuple of data objects that match the filter and are of the allowed types.
        """
        return tuple(
            result
            for result in search_result
            if self.get_object_type_from_data_object(result["dataObject"])
            in allowed_types
        )

    def process_notifications(
        self, subscription: SubscriptionInfo, valid_search_result: tuple[dict, ...]
    ) -> None:
        """
        Method to process notifications for a subscription. It checks the notification interval and the last time
        it had been checked. If the notification interval has passed since the last check, it will send a notification
        to the callback function (listed in the subscription information dictionary database).

        Parameters
        ----------
        subscription : dict
            Subscription information (in dictionary format).
        valid_search_result : tuple[dict]
            tuple of data objects that match the filter and are of the allowed types.

        Returns
        -------
        None
        """
        current_time = TimestampIts.initialize_with_utc_timestamp_seconds()
        notify_time = subscription.subscription_request.notify_time
        with self._lock:
            last_checked = self.last_checked_subscriptions_time.get(
                subscription)
            if last_checked is None:
                self.last_checked_subscriptions_time[subscription] = current_time
                last_checked = current_time
            if notify_time is not None and last_checked + notify_time > current_time:
                return
            self.last_checked_subscriptions_time[subscription] = current_time

        subscription.callback(
            RequestDataObjectsResp(
                application_id=subscription.subscription_request.application_id,
                data_objects=valid_search_result,
                result=RequestedDataObjectsResult.SUCCEED,
            )
        )

    def remove_subscription(self, subscription: SubscriptionInfo) -> None:
        """
        Method that removes (pops) a subscription from the subscriptions list.

        Parameters
        ----------
        subscription: SubscriptionInfo
        """
        with self._lock:
            if subscription in self.subscriptions:
                self.subscriptions.remove(subscription)
            self.last_checked_subscriptions_time.pop(subscription, None)

    def find_key_paths_in_list(self, target_key: str, search_result: list) -> list[str]:
        """
        Static method to find the path of a key in a list

        Parameters
        ----------
        target_key : str
        search_result : list
        """
        key_paths = []
        for result in search_result:
            key_paths.append(self.find_key_path(target_key, result))
        return key_paths

    def find_key_path(self, target_key: str, dictionary: dict, path: list | None = None) -> str:
        """
        Static method to find the path of a key in a dictionary.

        Parameters
        ----------
        target_key : str
        dictionary : dict
        path : list
        """
        if path is None:
            path = []
        for key, value in dictionary.items():
            if key == target_key:
                path.append(key)
                return ".".join(path)  # Return the formatted path
            if isinstance(value, dict):
                sub_path = self.find_key_path(target_key, value, path + [key])
                if sub_path:
                    return sub_path
        return ""

    def order_search_results(
        self, search_results: tuple[dict, ...], orders: tuple[OrderTupleValue, ...]
    ) -> tuple[tuple[dict, ...], ...]:
        """
        Method to order search results.

        Parameters
        ----------
        search_results : tuple[dict, ...]
            tuple of data objects that match the filter.
        orders : tuple[OrderTuple, ...]
            tuple of OrderTuple objects specifying the ordering.

        Returns
        -------
        tuple[tuple[dict, ...], ...]
            tuple of ordered tuples of data objects.
        """
        def build_key(item):
            return tuple(
                Utils.get_nested(
                    item, Utils.find_attribute(order.attribute, item))
                for order in orders
            )

        reverse = any(order.ordering_direction == OrderingDirection.DESCENDING
                      for order in orders)
        return (tuple(sorted(search_results, key=build_key, reverse=reverse)),)

    def add_provider_data(self, data: AddDataProviderReq) -> int | None:
        """
        Method created in order to add provider data into the data containers.

        Parameters
        ----------
        data : AddDataProviderReq
        """
        return self.ldm_maintenance.add_provider_data(data)

    def add_data_provider_its_aid(self, its_aid: int) -> None:
        """
        Method created in order to add the providers ITS_AID into the list of data consumers.

        Parameters
        ----------
        its_aid : int
        """
        with self._lock:
            self.data_provider_its_aid.add(its_aid)

    def update_provider_data(self, data_object_id: int, data_object: dict) -> None:
        """
        Method used to update provider data.

        Parameters
        ----------
        data_object_id : int
        data_object : dict
        """
        self.ldm_maintenance.update_provider_data(data_object_id, data_object)

    def get_data_provider_its_aid(self) -> set[int]:
        """
        Method to get all providers ITS_AID values.

        Parameters
        ----------
        None
        """
        with self._lock:
            data_provider_its_aid_copy = self.data_provider_its_aid.copy()
        return data_provider_its_aid_copy

    def del_provider_data(self, provider_data_id: int) -> None:
        """
        Method to delete all provider data with doc_id.

        Parameters
        ----------
        provider_data_id : int
        """
        with self._lock:
            self.data_provider_its_aid.discard(provider_data_id)

    def del_data_provider_its_aid(self, its_aid: int) -> None:
        """
        Method to delete provider ITS_AID from the list of data providers.

        Parameters
        ----------
        its_aid : int
        """
        with self._lock:
            self.data_provider_its_aid.discard(its_aid)

    def query(self, data_request: RequestDataObjectsReq) -> tuple[tuple[dict, ...], ...]:
        """
        Method to query the data containers using the RequestDataObjectsReq object.

        Parameters
        ----------
        data_request : RequestDataObjectsReq

        Returns
        -------
        list[list[dict]]
            list of list of data objects. Each list of data objects is ordered according to the order specified in the data_request object.
        """
        try:
            if data_request.filter is None:
                search_result = self.ldm_maintenance.get_all_data_containers()
            else:
                search_result = self.ldm_maintenance.search_data_containers(
                    data_request
                )
        except (KeyError, json.decoder.JSONDecodeError) as e:
            print(f"Error querying data container: {str(e)}")
            return (())

        # If it does then see if it needs ordering and order it
        if data_request.order is not None:
            search_result = self.order_search_results(
                search_result, data_request.order)
        else:
            search_result = (search_result,)
        return search_result

    def get_object_type_from_data_object(self, data_object: dict) -> str:
        """
        Method to get object type from data object.

        Parameters
        ----------
        data_object : dict

        Returns
        -------
        str
            data object type.
        """
        for data_object_type_str in data_object.keys():
            if data_object_type_str in DATA_OBJECT_TYPE_ID.values():
                return data_object_type_str
        return ""

    def store_new_subscription_petition(
        self,
        subscription_request: SubscribeDataobjectsReq,
        callback: Callable[[RequestDataObjectsResp], None],
    ) -> int:
        # pylint: disable=too-many-arguments
        """
        Method as standarized in ETSI EN 302 895 V1.1.1 (2014-09). Section 6.3.4.
        Method is used to store a new subscription petition.

        Parameters
        ----------
        subscription_request : SubscribeDataobjectsReq
            Subscription request object containing subscription details.
        callback: Callable[[RequestDataObjectsResp], None]
            callback function to be called when a notification is to be sent.
        """
        new_subscription = SubscriptionInfo(
            subscription_request=subscription_request,
            callback=callback,
        )
        with self._lock:
            self.subscriptions.append(
                new_subscription
            )
            self.last_checked_subscriptions_time[new_subscription] = TimestampIts.initialize_with_utc_timestamp_seconds(
            )
        return hash(new_subscription.subscription_request)

    def add_data_consumer_its_aid(self, its_aid: int) -> None:
        """
        Method to add data consumer ITS_AID to the list of data consumers.

        Parameters
        ----------
        its_aid : int
        """
        with self._lock:
            self.data_consumer_its_aid.add(its_aid)

    def get_data_consumer_its_aid(self) -> set[int]:
        """
        Method to get list of data consumer ITS_AID.

        Parameters
        ----------
        None
        """
        with self._lock:
            data_consumer_its_aid_copy = self.data_consumer_its_aid.copy()
        return data_consumer_its_aid_copy

    def del_data_consumer_its_aid(self, its_aid: int) -> None:
        """
        Method to delete data consumer ITS_AID from the list of data consumers.

        Parameters
        ----------
        its_aid : int
        """
        with self._lock:
            self.data_consumer_its_aid.discard(its_aid)

    def delete_subscription(self, subscription_id: int) -> bool:
        """
        Method to delete subscriptions from the subscriptions storage.

        Parameters
        ----------
        subscription_id : int
        """
        with self._lock:
            subscriptions = self.subscriptions.copy()
        to_remove = set()
        for subscription in subscriptions:
            if hash(subscription.subscription_request) == subscription_id:
                to_remove.add(subscription)
        for subscription in to_remove:
            self.remove_subscription(subscription)
        return bool(to_remove)
