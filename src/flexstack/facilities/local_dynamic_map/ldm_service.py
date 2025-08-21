from __future__ import annotations
from collections.abc import Callable
import json

from ...utils.time_service import TimeService
from .ldm_classes import (
    Filter,
    AddDataProviderReq,
    RequestDataObjectsResp,
    RequestedDataObjectsResult,
    RequestDataObjectsReq,
    OrderTuple,
    TimestampIts,
    Utils,
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
    TODO: Add attributes

    """

    def __init__(self, ldm_maintenance: LDMMaintenance) -> None:
        self.ldm_maintenance = ldm_maintenance

        self.data_provider_its_aid: list[int] = []
        self.data_consumer_its_aid: list[int] = []

        self.subscriptions: list[dict] = []

    def subscriptions_service(self) -> None:
        """
        Method that attends subscriptions.

        The method is meant to be run in a seperate thread.
        """
        while True:
            self.attend_subscriptions()

    def attend_subscriptions(self) -> None:
        """
        Method to attend subscriptions as specified in the ETSI EN 302 895 V1.1.1 (2014-09). Section 6.3.4.
        """
        for subscription in self.subscriptions:
            search_result = self.search_data(subscription)
            if not search_result:
                continue

            valid_search_result = self.filter_data_object_type(
                search_result, subscription["data_object_type"]
            )
            if subscription["multiplicity"] is not None and subscription[
                "multiplicity"
            ] > len(valid_search_result):
                continue

            if subscription["order"] is not None:
                valid_search_result = self.order_search_results(
                    valid_search_result, subscription["order"]
                )

            self.process_notifications(subscription, valid_search_result)

            if subscription["applicationId"] not in self.data_consumer_its_aid:
                self.pop_subscription(subscription["doc_id"])

    def search_data(self, subscription: dict) -> list[dict]:
        """
        Method to search data by using the filter in the subscription.

        Parameters
        ----------
        subscription : dict
            Subscription information (in dictionary format).
        Returns
        -------
        list[dict]
            list of data objects that match the filter.
        """
        data_request = RequestDataObjectsReq(
            subscription["applicationId"],
            subscription["data_object_type"],
            subscription["priority"],
            subscription["order"],
            subscription["filter"],
        )
        return self.ldm_maintenance.data_containers.search(data_request)

    def filter_data_object_type(
        self, search_result: list[dict], allowed_types: list[str]
    ) -> list[dict]:
        """
        Method to filter data objects by type.

        Parameters
        ----------
        search_result : list[dict]
            list of data objects that match the filter.
        allowed_types : list[str]
            list of allowed data object types
            (as specified in the ETSI TS 102 894-2 V2.2.1 (2023-10), i.e. CAM, DENM,...).

        Returns
        -------
        list[dict]
            list of data objects that match the filter and are of the allowed types.
        """
        return [
            result
            for result in search_result
            if self.get_object_type_from_data_object(result["dataObject"])
            in allowed_types
        ]

    def process_notifications(
        self, subscription: dict, valid_search_result: list[dict]
    ) -> None:
        """
        Method to process notifications for a subscription. It checks the notification interval and the last time
        it had been checked. If the notification interval has passed since the last check, it will send a notification
        to the callback function (listed in the subscription information dictionary database).

        Parameters
        ----------
        subscription : dict
            Subscription information (in dictionary format).
        valid_search_result : list[dict]
            list of data objects that match the filter and are of the allowed types.

        Returns
        -------
        None
        """
        current_time = TimeService.time()
        if (
            subscription["last_checked"] + subscription["notification_interval"]
            > current_time
        ):
            return

        subscription["last_checked"] = current_time
        subscription["callback"](
            RequestDataObjectsResp(
                application_id=subscription["applicationId"],
                data_objects=valid_search_result,
                result=RequestedDataObjectsResult(result=0),
            )
        )

    def pop_subscription(self, index: int) -> None:
        """
        Method that removes (pops) a subscription from the subscriptions list and updates the new index values
        in the "doc_id" field.

        Parameters
        ----------
        index : int
        """
        if index < 0 or index >= len(self.subscriptions):
            raise IndexError("Index out of range")

        self.subscriptions.pop(index)

        for i, _ in enumerate(self.subscriptions):
            self.subscriptions[i]["doc_id"] = i

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

    def find_key_path(self, target_key: str, dictionary: dict, path: str = None) -> str:
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
        return None

    def order_search_results(
        self, search_results: list[dict], orders: list[OrderTuple]
    ) -> list[list[dict]]:
        """
        Method to order search results.

        Parameters
        ----------
        search_results : list[dict]
        orders : list[OrderTuple]
        """
        results = []
        for order in orders:
            tuple_list = [
                (
                    index,
                    Utils.get_nested(
                        search_result,
                        Utils.find_attribute(order.attribute, search_result),
                    ),
                )
                for index, search_result in enumerate(search_results)
            ]
            if str(order.ordering_direction) == "ascending":
                sorted_tuple_list = sorted(
                    tuple_list, key=lambda x: x[1], reverse=False
                )
            else:
                sorted_tuple_list = sorted(tuple_list, key=lambda x: x[1], reverse=True)

            result = [search_results[tuple[0]] for tuple in sorted_tuple_list]
            results.append(result)
        return results

    def add_provider_data(self, data: AddDataProviderReq) -> int:
        """
        Method created in order to add provider data into the data containers.

        Parameters
        ----------
        data : dict
        """
        return self.ldm_maintenance.add_provider_data(data)

    def add_data_provider_its_aid(self, its_aid: int) -> None:
        """
        Method created in order to add the providers ITS_AID into the list of data consumers.

        Parameters
        ----------
        its_aid : int
        """
        self.data_provider_its_aid.append(its_aid)

    def update_provider_data(self, data_object_id: int, data_object: dict) -> None:
        """
        Method used to update provider data.

        Parameters
        ----------
        data_object_id : int
        data_object : dict
        """
        self.ldm_maintenance.update_provider_data(data_object_id, data_object)

    def get_provider_data(self) -> list:
        """
        Method to get provider data from the data containers.

        Parameters
        ----------
        None
        """
        return self.ldm_maintenance.data_containers

    def get_data_provider_its_aid(self) -> list[int]:
        """
        Method to get all providers ITS_AID values.

        Parameters
        ----------
        None
        """
        return self.data_provider_its_aid

    def del_provider_data(self, provider_data_id: int) -> None:
        """
        Method to delete all provider data with doc_id.

        Parameters
        ----------
        provider_data_id : int
        """
        self.data_provider_its_aid.remove(provider_data_id)

    def del_data_provider_its_aid(self, its_aid: int) -> None:
        """
        Method to delete provider ITS_AID from the list of data providers.

        Parameters
        ----------
        its_aid : int
        """
        self.data_provider_its_aid.remove(its_aid)

    def query(self, data_request: RequestDataObjectsReq) -> list[list[dict]]:
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
            return [[]]

        # If it does then see if it needs ordering and order it
        if data_request.order is not None:
            search_result = self.order_search_results(search_result, data_request.order)
        else:
            search_result = [search_result]
        return search_result

    def get_object_type_from_data_object(self, data_object: dict) -> str:
        """
        Method to get object type from data object.

        Parameters
        ----------
        data_object : dict
        """
        for data_object_type_str in data_object.keys():
            if data_object_type_str in DATA_OBJECT_TYPE_ID.values():
                return list(DATA_OBJECT_TYPE_ID.keys())[
                    list(DATA_OBJECT_TYPE_ID.values()).index(data_object_type_str)
                ]
        return None

    def store_new_subscription_petition(
        self,
        application_id: int,
        data_object_type: list[int],
        priority: int,
        filter: Filter,
        notification_interval: TimestampIts,
        multiplicity: int,
        order: list[OrderTuple],
        callback: Callable[[RequestDataObjectsResp], None],
    ) -> int:
        # pylint: disable=too-many-arguments
        """
        Method as standarized in ETSI EN 302 895 V1.1.1 (2014-09). Section 6.3.4.
        Method is used to store a new subscription petition.

        Parameters
        ----------
        application_id : int
        data_object_type : int
        priority : int
        filter : Filter
        notification_interval : int
        multiplicity : int
        order : int
        callback : function
        """
        return self.subscriptions.append(
            {
                "applicationId": application_id,
                "data_object_type": data_object_type,
                "priority": priority,
                "filter": filter,
                "notification_interval": notification_interval,
                "multiplicity": multiplicity,
                "order": order,
                "callback": callback,
                "last_checked": TimeService.time(),
                "doc_id": len(self.subscriptions),
            }
        )

    def add_data_consumer_its_aid(self, its_aid: int) -> None:
        """
        Method to add data consumer ITS_AID to the list of data consumers.

        Parameters
        ----------
        its_aid : int
        """
        self.data_consumer_its_aid.append(its_aid)

    def get_data_consumer_its_aid(self) -> list[int]:
        """
        Method to get list of data consumer ITS_AID.

        Parameters
        ----------
        None
        """
        return self.data_consumer_its_aid

    def del_data_consumer_its_aid(self, its_aid: int) -> None:
        """
        Method to delete data consumer ITS_AID from the list of data consumers.

        Parameters
        ----------
        its_aid : int
        """
        self.data_consumer_its_aid.remove(its_aid)

    def get_data_consumer_subscriptions(self) -> list[dict]:
        """
        Method to get data consumer subscriptions from the subscriptions storage.

        Parameters
        ----------
        None
        """
        return self.subscriptions

    def delete_subscription(self, subscription_id: int) -> bool:
        """
        Method to delete subscriptions from the subscriptions storage.

        Parameters
        ----------
        subscription_id : int
        """
        try:
            self.subscriptions.pop(subscription_id)
            return True
        except IndexError:
            return False
