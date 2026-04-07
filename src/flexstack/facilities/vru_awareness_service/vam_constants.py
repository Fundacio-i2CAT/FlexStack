"""
Constants extracted from: ETSI TS 103 300-3 V2.3.1 (2025-12)

Table 16: Parameters for VAM generation in case of using direct communications (clause 6.2)
Table 17: Parameters for VAM generation triggering (clause 6.4)
Table 14: Parameters for VRU clustering decisions (clause 5.4.2)
Table 15: Cluster membership parameters (clause 5.4.2)

Note: minimumSafeLateralDistance and minimumSafeLongitudinalDistance are
      not static constants — they depend on the VRU speed and are therefore
      not defined here (see ETSI TS 103 300-2 clause 6.5.10.5).
"""

# ---------------------------------------------------------------------------
# Table 16 – VAM generation parameters (clause 6.2)
# ---------------------------------------------------------------------------

#: Minimum time between consecutive VAM generation events [ms].
T_GENVAMMIN = 100

#: Maximum time between consecutive VAM generation events [ms].
T_GENVAMMAX = 5000

#: Minimum time between consecutive LF-container inclusions [ms].
#: The LF container is also included in the first VAM and whenever a cluster
#: operation container is present (spec clause 6.2).
T_GENVAM_LFMIN = 2000

#: VAM generation-check period; shall be ≤ T_GenVamMin [ms].
T_CHECKVAMGEN = T_GENVAMMIN

#: DCC-provided inter-VAM gap; T_GenVamMin ≤ T_GenVam_DCC ≤ T_GenVamMax [ms].
T_GENVAM_DCC = T_GENVAMMIN

#: Maximum time allowed for assembling a VAM packet in the facilities layer [ms].
T_ASSEMBLEVAM = 50

# ---------------------------------------------------------------------------
# Table 17 – VAM generation triggering thresholds (clause 6.4)
# ---------------------------------------------------------------------------

#: Minimum Euclidean position change to trigger a new VAM [m].
MINREFERENCEPOINTPOSITIONCHANGETHRESHOLD = 4

#: Minimum ground-speed change to trigger a new VAM [m/s].
MINGROUNDSPEEDCHANGETHRESHOLD = 0.5

#: Minimum heading-vector orientation change to trigger a new VAM [degrees].
MINGROUNDVELOCITYORIENTATIONCHANGETHRESHOLD = 4

#: Minimum trajectory-interception probability change to trigger a new VAM [%].
MINTRAJECTORYINTERCEPTIONPROBCHANGETHRESHOLD = 10

#: Maximum number of consecutive VAMs that may be skipped for redundancy
#: mitigation (range 2-10 per spec Table 17).
NUMSKIPVAMSFORREDUNDANCYMITIGATION = 2

#: Minimum cluster bounding-box distance change to trigger a new cluster VAM [m].
MINCLUSTERDISTANCECHANGETHRESHOLD = 2

#: Minimum safe vertical distance between ego-VRU and another participant [m].
MINIMUMSAFEVERTICALDISTANCE = 5

# ---------------------------------------------------------------------------
# Table 14 – VRU clustering decision parameters (clause 5.4.2)
# ---------------------------------------------------------------------------

#: Minimum number of nearby VRU devices needed before a potential cluster
#: leader will create a cluster (recommended range: 3–5).
NUM_CREATE_CLUSTER = 3

#: Maximum distance between a VRU and the cluster edge for joining/creation [m]
#: (recommended range: 3–5 m).
MAX_CLUSTER_DISTANCE = 5

#: Maximum relative speed difference within a cluster expressed as a fraction
#: (5 % per spec).
MAX_CLUSTER_VELOCITY_DIFFERENCE = 0.05

#: Maximum distance for a *combined* VRU cluster (recommended range: 1–2 m).
MAX_COMBINED_CLUSTER_DISTANCE = 2

#: Initial cluster cardinality size set immediately after cluster creation.
MIN_CLUSTER_SIZE = 1

#: Maximum cluster cardinality (number of active ITS-S).
MAX_CLUSTER_SIZE = 20

#: Number of VAMs with former identifiers to transmit after a cancelled- or
#: failed-join before resuming pseudonymisation.
NUM_CLUSTER_VAM_REPEAT = 3

# ---------------------------------------------------------------------------
# Table 15 – Cluster membership timing parameters (clause 5.4.2) [seconds]
# ---------------------------------------------------------------------------

#: Cluster IDs received within this window must not be reused by a new leader.
TIME_CLUSTER_UNIQUENESS_THRESHOLD = 30.0

#: Duration for which the breakup indication is broadcast before disbanding.
TIME_CLUSTER_BREAKUP_WARNING = 3.0

#: Duration for which the join intention is advertised in individual VAMs.
TIME_CLUSTER_JOIN_NOTIFICATION = 3.0

#: Time the joining VRU waits for the leader to acknowledge membership.
TIME_CLUSTER_JOIN_SUCCESS = 0.5

#: Duration for which the cluster-ID change intent is advertised.
TIME_CLUSTER_ID_CHANGE_NOTIFICATION = 3.0

#: After a cluster-ID change, the old ID is valid in leave indications for
#: this long.
TIME_CLUSTER_ID_PERSIST = 3.0

#: If no cluster VAM arrives within this window, the leader is assumed lost.
TIME_CLUSTER_CONTINUITY = 2.0

#: Duration for which the leave indication is included in individual VAMs
#: after leaving a cluster.
TIME_CLUSTER_LEAVE_NOTIFICATION = 1.0

#: Window during which a combined-VRU cluster opportunity is advertised.
TIME_COMBINED_VRU_CLUSTER_OPPORTUNITY = 15.0

# ---------------------------------------------------------------------------
# VRU role (clause 4.2, Table 1)
# ---------------------------------------------------------------------------

#: The device user is considered a VRU.
VRU_ROLE_ON = "VRU_ROLE_ON"

#: The device user is NOT considered a VRU (zero-risk area, e.g. inside a bus).
VRU_ROLE_OFF = "VRU_ROLE_OFF"

# ---------------------------------------------------------------------------
# Default VRU profile (informative placeholder; real value from VRU profile
# management entity per ETSI TS 103 300-2).
# ---------------------------------------------------------------------------

VRU_PROFILE = {
    "Type": "Cyclist",
    "Speed": 20,
    "TransmissionRange": 70,
    "Environment": "Urban",
    "WeightClass": "High",
    "TrajectoryAmbiguity": "Medium",
    "ClusterSize": 1,
}
