"""
General Constant for LDM
"""
import os
library_folder = os.path.dirname(os.path.abspath(__file__))
file_path = os.path.join(library_folder, "data_containers.json")
LDM_STORAGE_PATH = file_path
MAINTENANCE_AREA_MAX_ALTITUDE_DIFFERENCE = 15
EATH_RADIUS = 6371000.0


"""
Consatants for Interface LDM Service. As mentioned in ETSI EN 302 895 V1.1.1 (2014-09).
"""
DATA_OBJECT_FIELD_NAME = "dataObject"

"""
Constants for Interface LDM Maintenance. As mentioned in ETSI EN 302 895 V1.1.1 (2014-09).
"""
NEW_DATA_RECIEVED = 0
NO_NEW_DATA_RECIEVED = 1
MAINTENANCE_AREA_MAX_ALTITUDE_DIFFERENCE = 15

"""
Constants for Interface IF.LDM.2. As mentioned in ETSI EN 302 895 V1.1.1 (2014-09). Section 6.1.1.1
"""

RESULT_SUCCESS = "Successful"
RESULT_INVALID_ITS_AID = "Fail: Invalid ITS-AID"
RESULT_UNABLE_APPLICATION_AUTHENTICATION = "Fail: Unable to authenticate application"
RESULT_NOT_AUTHORIZED = "Fail: Application not authorized for requested permissions"

"""
Constants for Interface IF.LDM.3, As mentioned in ETSI EN 302 895 V1.1.1 (2014-09). Section 6.2
"""
REGISTER_DATA_PROVIDER_RESULT_ACCEPTED = "accepted"
REGISTER_DATA_PROVIDER_RESULT_REJECTED = "rejected"

ADD_DATA_PROVIDER_RESULT_ACCEPTED = "Accepted"
ADD_DATA_PROVIDER_RESULT_REJECTED = "unsuccessful"

UPDATE_DATA_PROVIDER_RESULT_ACCEPTED = "UpdateSuccessful"
UPDATE_DATA_PROVIDER_RESULT_REJECTED_DOES_NOT_EXIST = "UpdateRejectedDoesNotExist"
UPDATE_DATA_PROVIDER_RESULT_REJECTED_INCONSISTENT_TYPE = (
    "UpdateRejectedInconsistentType"
)

DELETE_DATA_PROVIDER_RESULT_ACCEPTED = "DeleteSuccessful"
DELETE_DATA_PROVIDER_RESULT_REJECTED = "DeleteRejected"

"""
Constants for the Interface IF.LDM.4. As mentioned in ETSI EN 302 895 V1.1.1 (2014-09). Section 6.3
"""

REGISTER_DATA_CONSUMER_RESULT_ACCEPTED = "Accepted"
REGISTER_DATA_CONSUMER_RESULT_REJECTED = "Rejected"

REQUEST_DATA_OBJECT_ACCEPTED = "Accepted"
REQUEST_DATA_OBJECT_INVALID_ITS_AID = "Fail: Invalid ITS-AID"
REQUEST_DATA_OBJECT_INVALID_DATA_OBJECT_TYPE = "Fail: Invalid Data Object Type"
REQUEST_DATA_OBJECT_INVALID_PRIORITY = "Fail: Invalid Priority"
REQUEST_DATA_OBJECT_INVALID_FILTER = "Fail: Invalid Filter"
REQUEST_DATA_OBJECT_INVALID_ORDER = "Fail: Invalid Order"

"""
ITS-AID defined in standard ETSI TS 102 965 V2.1.1 (2021-11).
TODO: This might be wrong! ITS-AID is standarized in ETSI TS 102 965 V2.1.1 (2021-11);
CA_BASIC_SERVICE = 36
DEN_BASIC_SERVICE = 37
TLM_BASIC_SERVICE = 137
RLT_SERVICE = 138
IVI_SERVICE = 139
GN_MGMT = 141
SA_SERVICE = 540801
CRL_SERVICE = 622
SECURED_CERTIFICATE_REQUEST_SERVICE = 623
CTL_SERVICE = 624
GPS_SERVICE = 625
GPC_SERVICE = 540802
CP_SERVICE = 639
VRU_SERVICE = 638
TLC_REQUEST_SERVICE = 140
IMZ_SERVICE = 640

"""

DENM = 1
CAM = 2
POI = 3
SPATEM = 4
MAPEM = 5
IVIM = 6
EV_RSR = 7
TISTPGTRANSACTION = 8
SREM = 9
SSEM = 10
EVSCN = 11
SAEM = 12
RTCMEM = 13
CPM = 14
IMZM = 15
VAM = 16
DSM = 17
PCIM = 18
PCVM = 19
MCM = 20
PAM = 21

DATA_OBJECT_TYPE_ID = {
    1: "denm",
    2: "cam",
    3: "poi",
    4: "spatem",
    5: "mapem",
    6: "ivim",
    7: "ev-rsr",
    8: "tistpgtransaction",
    9: "srem",
    10: "ssem",
    11: "evcsn",
    12: "saem",
    13: "rtcmem",
    14: "cpm",
    15: "imzm",
    16: "vam",
    17: "dsm",
    18: "pcim",
    19: "pcvm",
    20: "mcm",
    21: "pam",
}

VALID_ITS_AID = {
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
    PAM
}


UNKNOWN = 0
PEDESTRIAN = 1
CYCLIST = 2
MOPED = 3
MOTORCYCLE = 4
PASSENGER_CAR = 5
BUS = 6
LIGHT_TRUCK = 7
HEAVY_TRUCK = 8
TRAILER = 9
SPCIAL_VEHICLES = 10
TRAM = 11
ROAD_SIDE_UNIT = 15

"""
Operator contant
"""
OPERATOR_MAPPING = {
    "==": lambda x, y: x == y,
    "!=": lambda x, y: x != y,
    ">": lambda x, y: x > y,
    "<": lambda x, y: x < y,
    ">=": lambda x, y: x >= y,
    "<=": lambda x, y: x <= y,
    "like": lambda x, y: x in y,
    "notlike": lambda x, y: x not in y
}
