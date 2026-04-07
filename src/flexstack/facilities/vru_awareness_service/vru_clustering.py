"""
VRU Basic Service (VBS) Clustering State Machine.

Implements the VRU cluster management function specified in
ETSI TS 103 300-3 V2.3.1 (2025-12), clause 5.4.

The clustering function is optional for all VRU profiles (clause 5.4.1)
and is recommended for VRU Profile 1 (pedestrian) when conditions are met.

Architecture overview
---------------------
``VBSClusteringManager`` is the single entry-point.  It is created by
``VRUAwarenessService``, injected into ``VAMTransmissionManagement`` and
``VAMReceptionManagement``, and orchestrates:

* **State machine** – four VBS states (Table 5):
  ``VRU_IDLE``, ``VRU_ACTIVE_STANDALONE``,
  ``VRU_ACTIVE_CLUSTER_LEADER``, ``VRU_PASSIVE``.

* **Cluster creation** – triggered when enough nearby VRUs are visible and
  no joinable cluster exists (clause 5.4.2.4).

* **Cluster joining** – three-phase handshake:
  notification → passive → confirmation (or failure) (clause 5.4.2.2).

* **Cluster leaving** – with leave-reason notification period
  (clause 5.4.2.2).

* **Cluster breakup** – by the cluster leader, with a warning period and
  reason code (clause 5.4.2.2).

* **Leader-lost detection** – timeout on ``timeClusterContinuity``
  (clause 5.4.2.2).

* **Container generation** – ``VruClusterInformationContainer`` (leader)
  and ``VruClusterOperationContainer`` (joining/leaving/breaking-up).

Thread safety
-------------
All public methods acquire ``_lock`` so the class is safe to call from
a GPS-callback thread and a BTP-reception thread simultaneously.
"""

from __future__ import annotations

import logging
import random
import threading
import time
from dataclasses import dataclass, field
from enum import Enum, unique
from typing import Callable, Dict, Optional

from . import vam_constants

__all__ = [
    "VBSState",
    "ClusterLeaveReason",
    "ClusterBreakupReason",
    "VBSClusteringManager",
]

logger = logging.getLogger("vru_basic_service")


# ---------------------------------------------------------------------------
# Public enums
# ---------------------------------------------------------------------------


@unique
class VBSState(Enum):
    """VBS clustering states as defined in ETSI TS 103 300-3 V2.3.1, Table 5.

    VRU_IDLE
        The device user is not considered a VRU (role is ``VRU_ROLE_OFF``).
        The VBS remains operational to monitor role changes.

    VRU_ACTIVE_STANDALONE
        VAMs are sent with information about this individual VRU only.
        The VRU may indicate cluster-join or cluster-leave intentions in
        the ``VruClusterOperationContainer``.

    VRU_ACTIVE_CLUSTER_LEADER
        The VRU leads a cluster and transmits *cluster* VAMs that describe
        the entire cluster.  Only VRU Profile 1 and Profile 2 may be in
        this state.

    VRU_PASSIVE
        The VRU is a cluster member.  It does **not** transmit VAMs except
        when it is in the process of leaving a cluster (leave-notification
        period) or when it is located in a low-risk geographical area.
    """

    VRU_IDLE = "VRU-IDLE"
    VRU_ACTIVE_STANDALONE = "VRU-ACTIVE-STANDALONE"
    VRU_ACTIVE_CLUSTER_LEADER = "VRU-ACTIVE-CLUSTER-LEADER"
    VRU_PASSIVE = "VRU-PASSIVE"


@unique
class ClusterLeaveReason(Enum):
    """Reasons for leaving a cluster.

    Values match the ASN.1 ``ClusterLeaveReason`` enumeration in the VAM
    module (ETSI TS 103 300-3 V2.3.1, clause 7.3.5 and Table 12).
    """

    NOT_PROVIDED = "notProvided"
    CLUSTER_LEADER_LOST = "clusterLeaderLost"
    CLUSTER_DISBANDED_BY_LEADER = "clusterDisbandedByLeader"
    OUT_OF_CLUSTER_BOUNDING_BOX = "outOfClusterBoundingBox"
    OUT_OF_CLUSTER_SPEED_RANGE = "outOfClusterSpeedRange"
    JOINING_ANOTHER_CLUSTER = "joiningAnotherCluster"
    CANCELLED_JOIN = "cancelledJoin"
    FAILED_JOIN = "failedJoin"
    SAFETY_CONDITION = "safetyCondition"


@unique
class ClusterBreakupReason(Enum):
    """Reasons for breaking up a cluster.

    Values match the ASN.1 ``ClusterBreakupReason`` enumeration in the VAM
    module (ETSI TS 103 300-3 V2.3.1, clause 7.3.5 and Table 13).
    """

    NOT_PROVIDED = "notProvided"
    CLUSTERING_PURPOSE_COMPLETED = "clusteringPurposeCompleted"
    LEADER_MOVED_OUT_OF_BOUNDING_BOX = "leaderMovedOutOfClusterBoundingBox"
    JOINING_ANOTHER_CLUSTER = "joiningAnotherCluster"
    ENTERING_LOW_RISK_AREA = "enteringLowRiskAreaBasedOnMaps"
    RECEPTION_OF_CPM_CONTAINING_CLUSTER = "receptionOfCpmContainingCluster"


# ---------------------------------------------------------------------------
# Internal join/leave sub-states
# ---------------------------------------------------------------------------


@unique
class _JoinSubstate(Enum):
    """Internal substates of the cluster-joining procedure."""

    NONE = "none"
    """Not joining any cluster."""

    NOTIFY = "notify"
    """Sending join-intent notification in individual VAMs for
    ``timeClusterJoinNotification`` seconds (clause 5.4.2.2)."""

    WAITING = "waiting"
    """Individual VAMs have stopped; waiting up to ``timeClusterJoinSuccess``
    for the cluster leader to acknowledge membership."""

    JOINED = "joined"
    """In VRU_PASSIVE state; fully admitted cluster member."""

    CANCELLED = "cancelled"
    """Join cancelled; sending leave notification for
    ``timeClusterLeaveNotification`` seconds (clause 5.4.2.2)."""

    FAILED = "failed"
    """Join failed; sending leave notification and returning to STANDALONE."""


@unique
class _LeaveSubstate(Enum):
    """Internal substates of the cluster-leaving procedure."""

    NONE = "none"
    """Not leaving any cluster."""

    NOTIFY = "notify"
    """Sending leave indication for ``timeClusterLeaveNotification`` seconds
    (clause 5.4.2.2)."""


# ---------------------------------------------------------------------------
# Internal data structures
# ---------------------------------------------------------------------------


@dataclass
class _NearbyVRU:
    """Position and kinematic snapshot of a recently observed VRU ITS-S."""

    station_id: int
    lat: float
    lon: float
    speed: float
    heading: float
    last_seen: float


@dataclass
class _NearbyCluster:
    """Information about a recently observed VRU cluster."""

    cluster_id: int
    leader_station_id: int
    cardinality: int
    lat: float
    lon: float
    speed: float
    heading: float
    bounding_box_radius: Optional[float]
    last_seen: float


@dataclass
class _ClusterState:
    """Own cluster state when this device is acting as cluster leader."""

    cluster_id: int
    cardinality: int = vam_constants.MIN_CLUSTER_SIZE
    #: Set of VRU profile strings currently observed in the cluster,
    #: e.g. {"pedestrian"}.
    profiles: "set[str]" = field(default_factory=set)
    #: Bounding-box radius in metres; grows as members join.
    radius: float = float(vam_constants.MAX_CLUSTER_DISTANCE)
    #: Timestamp when the breakup warning was started (None = not breaking up).
    breakup_started: Optional[float] = None
    #: Reason for the pending breakup.
    breakup_reason: Optional[ClusterBreakupReason] = None
    #: Station IDs of devices currently executing the join notification phase.
    pending_members: "set[int]" = field(default_factory=set)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _heading_diff(h1: float, h2: float) -> float:
    """Return the absolute angular difference in degrees, handling wrap-around.

    Parameters
    ----------
    h1, h2:
        Heading values in degrees in the range [0, 360).

    Returns
    -------
    float
        Absolute angular difference in [0, 180].
    """
    diff = abs(h1 - h2) % 360.0
    return diff if diff <= 180.0 else 360.0 - diff


def _haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Approximate great-circle distance between two WGS-84 points [m].

    Uses the Haversine formula.  Accuracy is sufficient for the short
    inter-VRU distances (< 100 m) encountered in clustering decisions.

    Parameters
    ----------
    lat1, lon1, lat2, lon2:
        Coordinates in decimal degrees.

    Returns
    -------
    float
        Distance in metres.
    """
    import math

    r = 6_371_000.0  # Earth radius in metres
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlam = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlam / 2) ** 2
    return r * 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------


class VBSClusteringManager:
    """VRU Basic Service clustering state machine.

    Implements the cluster management function described in
    ETSI TS 103 300-3 V2.3.1, clause 5.4.

    Parameters
    ----------
    own_station_id:
        The station ID of the local ITS-S (used to generate cluster IDs and
        build cluster containers).
    own_vru_profile:
        The VRU profile string as it appears in the ASN.1 enumeration, e.g.
        ``"pedestrian"``, ``"bicyclistAndLightVruVehicle"``,
        ``"motorcyclist"``, ``"animal"``.  Used to populate
        ``clusterProfiles`` in the cluster information container.
    time_fn:
        Callable returning the current POSIX timestamp in seconds.
        Defaults to :func:`time.time`.  Override in unit tests to inject a
        fake clock.
    """

    def __init__(
        self,
        own_station_id: int,
        own_vru_profile: str = "pedestrian",
        time_fn: Callable[[], float] = time.time,
    ) -> None:
        self._own_station_id = own_station_id
        self._own_vru_profile = own_vru_profile
        self._time_fn = time_fn

        # --- VBS state ---
        self._state: VBSState = VBSState.VRU_ACTIVE_STANDALONE

        # --- Own cluster data (valid in VRU_ACTIVE_CLUSTER_LEADER) ---
        self._cluster: Optional[_ClusterState] = None

        # --- Joined cluster data (valid in VRU_PASSIVE) ---
        self._joined_cluster_id: Optional[int] = None
        self._leader_station_id: Optional[int] = None
        self._last_leader_vam_time: Optional[float] = None

        # --- Join and leave sub-state machine (VRU_ACTIVE_STANDALONE) ---
        self._join_substate: _JoinSubstate = _JoinSubstate.NONE
        self._join_target_cluster_id: Optional[int] = None
        self._join_started: Optional[float] = None
        self._join_leave_reason: Optional[ClusterLeaveReason] = None
        self._join_leave_started: Optional[float] = None

        # --- Leave notification state (VRU_PASSIVE leaving) ---
        self._leave_substate: _LeaveSubstate = _LeaveSubstate.NONE
        self._leave_reason: Optional[ClusterLeaveReason] = None
        self._leave_cluster_id: Optional[int] = None
        self._leave_started: Optional[float] = None

        # --- Nearby VRU and cluster tables ---
        self._nearby_vrus: Dict[int, _NearbyVRU] = {}
        self._nearby_clusters: Dict[int, _NearbyCluster] = {}

        # --- Recently seen cluster IDs (for uniqueness threshold) ---
        self._seen_cluster_ids: Dict[int, float] = {}  # id → first-seen time

        self._lock = threading.RLock()  # Reentrant: public methods may call other public methods
        logger.debug("VBSClusteringManager initialised (station_id=%d)", own_station_id)

    # ------------------------------------------------------------------
    # Public properties
    # ------------------------------------------------------------------

    @property
    def state(self) -> VBSState:
        """Current VBS clustering state (thread-safe)."""
        with self._lock:
            return self._state

    # ------------------------------------------------------------------
    # VRU role management (clause 4.2, Table 1)
    # ------------------------------------------------------------------

    def set_vru_role_on(self) -> None:
        """Transition from VRU_IDLE to VRU_ACTIVE_STANDALONE.

        Called when the VRU profile management entity notifies that the
        device user is now considered a VRU (VRU_ROLE_ON, clause 5.4.2.2).
        """
        with self._lock:
            if self._state is VBSState.VRU_IDLE:
                self._state = VBSState.VRU_ACTIVE_STANDALONE
                logger.info(
                    "VBS state: VRU_IDLE → VRU_ACTIVE_STANDALONE (VRU_ROLE_ON)"
                )

    def set_vru_role_off(self) -> None:
        """Transition to VRU_IDLE (VRU_ROLE_OFF).

        Called when the VRU profile management entity notifies that the
        device user is no longer considered a VRU (clause 5.4.2.2).
        Any active cluster relationships are abandoned without notification.
        """
        with self._lock:
            self._state = VBSState.VRU_IDLE
            self._cluster = None
            self._joined_cluster_id = None
            self._leader_station_id = None
            self._last_leader_vam_time = None
            self._join_substate = _JoinSubstate.NONE
            self._leave_substate = _LeaveSubstate.NONE
            logger.info("VBS state → VRU_IDLE (VRU_ROLE_OFF)")

    # ------------------------------------------------------------------
    # Clustering creation (clause 5.4.2.2)
    # ------------------------------------------------------------------

    def try_create_cluster(
        self,
        own_lat: float,
        own_lon: float,
    ) -> bool:
        """Attempt to create a new VRU cluster.

        A cluster is created when all conditions from clause 5.4.2.4 are met:

        * The device is in VRU_ACTIVE_STANDALONE.
        * Enough nearby devices (``NUM_CREATE_CLUSTER``) are visible within
          ``MAX_CLUSTER_DISTANCE`` metres.
        * No joinable cluster has been found (caller responsibility).

        On success the state transitions to VRU_ACTIVE_CLUSTER_LEADER.

        Parameters
        ----------
        own_lat, own_lon:
            Current estimated position of this ITS-S in decimal degrees.

        Returns
        -------
        bool
            ``True`` if a cluster was successfully created.
        """
        with self._lock:
            if self._state is not VBSState.VRU_ACTIVE_STANDALONE:
                return False

            # Count nearby VRUs within MAX_CLUSTER_DISTANCE
            now = self._time_fn()
            nearby_count = sum(
                1
                for vru in self._nearby_vrus.values()
                if (
                    now - vru.last_seen < vam_constants.T_GENVAMMAX / 1000.0
                    and _haversine_distance(own_lat, own_lon, vru.lat, vru.lon)
                    <= vam_constants.MAX_CLUSTER_DISTANCE
                )
            )
            if nearby_count < vam_constants.NUM_CREATE_CLUSTER:
                return False

            # Generate a locally unique non-zero cluster ID
            cluster_id = self._generate_unique_cluster_id(now)
            if cluster_id is None:
                logger.warning(
                    "Could not generate a unique cluster ID; cluster creation aborted."
                )
                return False

            self._cluster = _ClusterState(
                cluster_id=cluster_id,
                cardinality=vam_constants.MIN_CLUSTER_SIZE,
                profiles={self._own_vru_profile},
                radius=float(vam_constants.MAX_CLUSTER_DISTANCE),
            )
            self._state = VBSState.VRU_ACTIVE_CLUSTER_LEADER
            logger.info(
                "VBS state: VRU_ACTIVE_STANDALONE → VRU_ACTIVE_CLUSTER_LEADER "
                "(cluster_id=%d, cardinality=%d)",
                cluster_id,
                self._cluster.cardinality,
            )
            return True

    # ------------------------------------------------------------------
    # Cluster joining (clause 5.4.2.2)
    # ------------------------------------------------------------------

    def initiate_join(self, cluster_id: int) -> bool:
        """Begin the cluster-join notification phase.

        The VRU will include ``clusterJoinInfo`` in its individual VAMs for
        ``timeClusterJoinNotification`` seconds, then enter VRU_PASSIVE if
        the join is successful (clause 5.4.2.2).

        Parameters
        ----------
        cluster_id:
            Identifier of the cluster to join.  Use ``0`` if the cluster was
            indicated by a non-VAM message and has no identifier.

        Returns
        -------
        bool
            ``True`` if the join initiation was accepted (device is in
            VRU_ACTIVE_STANDALONE and not already joining).
        """
        with self._lock:
            if self._state is not VBSState.VRU_ACTIVE_STANDALONE:
                return False
            if self._join_substate is not _JoinSubstate.NONE:
                return False  # already in a join procedure

            self._join_substate = _JoinSubstate.NOTIFY
            self._join_target_cluster_id = cluster_id
            self._join_started = self._time_fn()
            logger.info(
                "Cluster join initiated: cluster_id=%d (notification phase starts)",
                cluster_id,
            )
            return True

    def cancel_join(self) -> None:
        """Cancel an in-progress join and start leave-notification phase.

        Called when joining conditions are no longer met while in
        ``_JoinSubstate.NOTIFY`` (clause 5.4.2.2 — "Cancelled-join
        handling").
        """
        with self._lock:
            if self._join_substate not in (_JoinSubstate.NOTIFY, _JoinSubstate.WAITING):
                return
            self._join_leave_reason = ClusterLeaveReason.CANCELLED_JOIN
            self._join_leave_started = self._time_fn()
            self._join_substate = _JoinSubstate.CANCELLED
            logger.info(
                "Cluster join cancelled (cluster_id=%d); leave-notification phase started.",
                self._join_target_cluster_id,
            )

    def confirm_join_failed(self) -> None:
        """Mark the join as failed and start leave-notification phase.

        Called when ``timeClusterJoinSuccess`` expires without the cluster
        leader acknowledging membership (clause 5.4.2.2 — "Failed-join
        handling").
        """
        with self._lock:
            if self._join_substate is not _JoinSubstate.WAITING:
                return
            self._join_leave_reason = ClusterLeaveReason.FAILED_JOIN
            self._join_leave_started = self._time_fn()
            self._join_substate = _JoinSubstate.FAILED
            logger.warning(
                "Cluster join failed (cluster_id=%d); reverting to STANDALONE.",
                self._join_target_cluster_id,
            )

    # ------------------------------------------------------------------
    # Cluster leaving (clause 5.4.2.2)
    # ------------------------------------------------------------------

    def trigger_leave_cluster(
        self, reason: ClusterLeaveReason = ClusterLeaveReason.NOT_PROVIDED
    ) -> None:
        """Begin the cluster-leave notification phase.

        Valid from both VRU_PASSIVE and VRU_ACTIVE_STANDALONE (during the
        join notification phase).

        Parameters
        ----------
        reason:
            The reason for leaving the cluster (Table 12).
        """
        with self._lock:
            if self._state is VBSState.VRU_PASSIVE:
                self._do_leave_to_standalone(reason)
                logger.info(
                    "Cluster leave initiated (reason: %s).",
                    reason.value,
                )
            elif (
                self._state is VBSState.VRU_ACTIVE_STANDALONE
                and self._join_substate is _JoinSubstate.NOTIFY
            ):
                self.cancel_join()

    # ------------------------------------------------------------------
    # Cluster breakup (clause 5.4.2.2)
    # ------------------------------------------------------------------

    def trigger_breakup_cluster(
        self, reason: ClusterBreakupReason = ClusterBreakupReason.NOT_PROVIDED
    ) -> bool:
        """Initiate the cluster breakup warning phase.

        The leader will include ``clusterBreakupInfo`` in cluster VAMs for
        ``timeClusterBreakupWarning`` seconds before disbanding and
        transitioning to VRU_ACTIVE_STANDALONE (clause 5.4.2.2).

        Parameters
        ----------
        reason:
            The reason for breaking up the cluster (Table 13).

        Returns
        -------
        bool
            ``True`` if the breakup was successfully initiated.
        """
        with self._lock:
            if self._state is not VBSState.VRU_ACTIVE_CLUSTER_LEADER:
                return False
            if self._cluster is None:
                return False
            if self._cluster.breakup_started is not None:
                return False  # already in breakup warning phase

            self._cluster.breakup_started = self._time_fn()
            self._cluster.breakup_reason = reason
            logger.info(
                "Cluster breakup initiated (cluster_id=%d, reason=%s); "
                "warning phase started.",
                self._cluster.cluster_id,
                reason.value,
            )
            return True

    # ------------------------------------------------------------------
    # Periodic maintenance – call on every VAM generation event
    # ------------------------------------------------------------------

    def update(
        self,
        own_lat: float,
        own_lon: float,
        own_speed: float,
        own_heading: float,
    ) -> None:
        """Advance all time-based state transitions.

        Must be called once per VAM generation check cycle
        (i.e. at least every ``T_CheckVamGen`` ms) so that:

        * The join notification phase concludes and the device enters passive.
        * Failed-join detection fires after ``timeClusterJoinSuccess``.
        * The leave notification phase concludes.
        * Breakup warning timeout results in the STANDALONE transition.
        * Cluster-leader-lost timeout triggers a leave.

        Parameters
        ----------
        own_lat, own_lon:
            Current estimated position in decimal degrees.
        own_speed:
            Current speed in m/s.
        own_heading:
            Current heading in degrees (0–360).
        """
        with self._lock:
            now = self._time_fn()
            self._expire_nearby_tables(now)

            if self._state is VBSState.VRU_ACTIVE_STANDALONE:
                self._update_standalone(now, own_lat, own_lon, own_speed, own_heading)

            elif self._state is VBSState.VRU_ACTIVE_CLUSTER_LEADER:
                self._update_leader(now, own_lat, own_lon, own_speed)

            elif self._state is VBSState.VRU_PASSIVE:
                self._update_passive(now, own_lat, own_lon, own_speed)

    # ------------------------------------------------------------------
    # VAM reception (called from VAMReceptionManagement)
    # ------------------------------------------------------------------

    def on_received_vam(self, vam: dict) -> None:
        """Process a received VAM for cluster management purposes.

        Updates the internal tables of nearby VRUs and clusters, advances
        the join-/leave-confirmation sub-states, and handles cluster-leader-
        lost recovery.

        Parameters
        ----------
        vam:
            Decoded VAM as a Python dict (the full VAM structure produced by
            :class:`~flexstack.facilities.vru_awareness_service.vam_coder.VAMCoder`).
        """
        with self._lock:
            try:
                self._process_received_vam(vam)
            except (KeyError, TypeError) as exc:
                logger.debug("on_received_vam: skipping malformed VAM – %s", exc)

    # ------------------------------------------------------------------
    # Container generation (called by VAMTransmissionManagement)
    # ------------------------------------------------------------------

    def get_cluster_information_container(self) -> Optional[dict]:
        """Return a ``VruClusterInformationContainer`` dict or ``None``.

        Only non-``None`` when the device is in VRU_ACTIVE_CLUSTER_LEADER
        and a valid cluster state exists.  The returned dict is suitable for
        direct inclusion in the ``vamParameters`` dict passed to the
        :class:`~flexstack.facilities.vru_awareness_service.vam_coder.VAMCoder`.
        """
        with self._lock:
            if (
                self._state is not VBSState.VRU_ACTIVE_CLUSTER_LEADER
                or self._cluster is None
            ):
                return None

            cluster_info: dict = {
                "clusterId": self._cluster.cluster_id,
                "clusterBoundingBoxShape": {
                    "circular": {
                        "radius": max(1, int(self._cluster.radius))
                    }
                },
                "clusterCardinalitySize": self._cluster.cardinality,
            }
            if self._cluster.profiles:
                cluster_info["clusterProfiles"] = self._encode_cluster_profiles(
                    self._cluster.profiles
                )

            return {"vruClusterInformation": cluster_info}

    def get_cluster_operation_container(self) -> Optional[dict]:
        """Return a ``VruClusterOperationContainer`` dict or ``None``.

        Returns an appropriate container during:

        * *Join-notification* phase – ``clusterJoinInfo``.
        * *Leave-notification* phase – ``clusterLeaveInfo``.
        * *Cancelled/failed-join* phase – ``clusterLeaveInfo``.
        * *Breakup-warning* phase – ``clusterBreakupInfo``.

        Returns ``None`` when no cluster operation is in progress.
        """
        with self._lock:
            now = self._time_fn()

            if self._state is VBSState.VRU_ACTIVE_STANDALONE:
                return self._standalone_operation_container(now)

            if self._state is VBSState.VRU_PASSIVE:
                return self._passive_operation_container(now)

            if self._state is VBSState.VRU_ACTIVE_CLUSTER_LEADER:
                return self._leader_operation_container(now)

            return None

    def should_transmit_vam(self) -> bool:
        """Return ``True`` when the VBS should transmit a VAM.

        A VRU in VRU_PASSIVE must NOT transmit individual VAMs unless it is
        in the leave-notification phase (clause 6.3).  A device in VRU_IDLE
        must NOT transmit VAMs (Table 1).
        """
        with self._lock:
            if self._state is VBSState.VRU_IDLE:
                return False
            if self._state is VBSState.VRU_PASSIVE:
                # Only allowed while sending leave notifications
                return self._leave_substate is _LeaveSubstate.NOTIFY
            return True  # STANDALONE or CLUSTER_LEADER

    # ------------------------------------------------------------------
    # Member-tracking helpers (called from on_received_vam)
    # ------------------------------------------------------------------

    def _process_received_vam(self, vam: dict) -> None:
        """Internal VAM processing (must be called with ``_lock`` held)."""
        header = vam["header"]
        sender_id: int = header["stationId"]
        params = vam["vam"]["vamParameters"]
        basic = params["basicContainer"]

        lat = basic["referencePosition"]["latitude"] / 1e7
        lon = basic["referencePosition"]["longitude"] / 1e7
        hf = params.get("vruHighFrequencyContainer", {})
        speed = hf.get("speed", {}).get("speedValue", 0) / 100.0
        heading = hf.get("heading", {}).get("value", 0) / 10.0
        now = self._time_fn()

        # Update nearby VRU table
        self._nearby_vrus[sender_id] = _NearbyVRU(
            station_id=sender_id,
            lat=lat,
            lon=lon,
            speed=speed,
            heading=heading,
            last_seen=now,
        )

        # --- Cluster information container ---
        cluster_info_ctr = params.get("vruClusterInformationContainer")
        if cluster_info_ctr:
            vci = cluster_info_ctr["vruClusterInformation"]
            c_id: int = vci.get("clusterId", 0)
            cardinality: int = vci.get("clusterCardinalitySize", 1)
            # Extract radius from circular bounding box if present
            bbox = vci.get("clusterBoundingBoxShape")
            radius: Optional[float] = None
            if bbox and "circular" in bbox:
                radius = float(bbox["circular"].get("radius", vam_constants.MAX_CLUSTER_DISTANCE))

            self._nearby_clusters[c_id] = _NearbyCluster(
                cluster_id=c_id,
                leader_station_id=sender_id,
                cardinality=cardinality,
                lat=lat,
                lon=lon,
                speed=speed,
                heading=heading,
                bounding_box_radius=radius,
                last_seen=now,
            )
            # Track cluster IDs for uniqueness threshold
            if c_id not in self._seen_cluster_ids:
                self._seen_cluster_ids[c_id] = now

            # If we are the leader of this cluster, update cardinality/profiles
            if (
                self._state is VBSState.VRU_ACTIVE_CLUSTER_LEADER
                and self._cluster is not None
                and self._cluster.cluster_id == c_id
                and sender_id != self._own_station_id
            ):
                # Another leader claiming the same ID → trigger ID change
                logger.warning(
                    "Duplicate cluster ID %d detected from station %d; "
                    "cluster ID change required.",
                    c_id,
                    sender_id,
                )

            # Join-waiting phase confirmation: a VAM from the leader that still
            # advertises the same cluster ID means we are accepted (clause 5.4.2.2).
            if (
                self._state is VBSState.VRU_ACTIVE_STANDALONE
                and self._join_substate is _JoinSubstate.WAITING
                and self._join_target_cluster_id is not None
                and c_id == self._join_target_cluster_id
            ):
                self._complete_join(sender_id)

        # --- Cluster operation container ---
        cluster_op_ctr = params.get("vruClusterOperationContainer")
        if cluster_op_ctr:
            join_info = cluster_op_ctr.get("clusterJoinInfo")
            leave_info = cluster_op_ctr.get("clusterLeaveInfo")
            breakup_info = cluster_op_ctr.get("clusterBreakupInfo")

            # Leader tracks join/leave notifications to update cardinality
            if (
                self._state is VBSState.VRU_ACTIVE_CLUSTER_LEADER
                and self._cluster is not None
            ):
                if join_info and join_info.get("clusterId") == self._cluster.cluster_id:
                    self._cluster.pending_members.add(sender_id)
                    self._cluster.cardinality = max(
                        vam_constants.MIN_CLUSTER_SIZE,
                        len(self._cluster.pending_members) + 1,
                    )
                    logger.debug(
                        "Station %d joining cluster %d; cardinality now %d.",
                        sender_id,
                        self._cluster.cluster_id,
                        self._cluster.cardinality,
                    )
                if leave_info and leave_info.get("clusterId") == self._cluster.cluster_id:
                    self._cluster.pending_members.discard(sender_id)
                    self._cluster.cardinality = max(
                        vam_constants.MIN_CLUSTER_SIZE,
                        len(self._cluster.pending_members) + 1,
                    )
                    logger.debug(
                        "Station %d leaving cluster %d; cardinality now %d.",
                        sender_id,
                        self._cluster.cluster_id,
                        self._cluster.cardinality,
                    )

            # Breakup from leader
            if breakup_info:
                if self._state is VBSState.VRU_PASSIVE and (
                    self._leader_station_id == sender_id
                    or self._joined_cluster_id
                    == self._nearby_clusters.get(0, _NearbyCluster(0, 0, 0, 0, 0, 0, 0, None, 0)).cluster_id
                ):
                    reason_str = breakup_info.get(
                        "clusterBreakupReason", "clusterDisbandedByLeader"
                    )
                    if reason_str == ClusterBreakupReason.RECEPTION_OF_CPM_CONTAINING_CLUSTER.value:
                        # May stay PASSIVE per clause 5.4.2.2
                        logger.info(
                            "Cluster %d broken up by leader (CPM reason); "
                            "remaining in VRU_PASSIVE.",
                            self._joined_cluster_id,
                        )
                    else:
                        self._do_leave_to_standalone(ClusterLeaveReason.CLUSTER_DISBANDED_BY_LEADER)

        # Refresh leader heartbeat when we are passive
        if (
            self._state is VBSState.VRU_PASSIVE
            and self._leader_station_id == sender_id
        ):
            self._last_leader_vam_time = now

    def _complete_join(self, leader_station_id: int) -> None:
        """Finalize a join: transition to VRU_PASSIVE (must be called with lock)."""
        self._join_substate = _JoinSubstate.JOINED
        self._joined_cluster_id = self._join_target_cluster_id
        self._leader_station_id = leader_station_id
        self._last_leader_vam_time = self._time_fn()
        self._state = VBSState.VRU_PASSIVE
        logger.info(
            "VBS state: VRU_ACTIVE_STANDALONE → VRU_PASSIVE (joined cluster %d, "
            "leader station %d).",
            self._joined_cluster_id,
            leader_station_id,
        )

    def _do_leave_to_standalone(self, reason: ClusterLeaveReason) -> None:
        """Immediately transition back to STANDALONE (must be called with lock)."""
        self._leave_substate = _LeaveSubstate.NOTIFY
        self._leave_reason = reason
        self._leave_cluster_id = self._joined_cluster_id
        self._leave_started = self._time_fn()
        self._joined_cluster_id = None
        self._leader_station_id = None
        self._last_leader_vam_time = None
        self._join_substate = _JoinSubstate.NONE
        self._join_target_cluster_id = None
        self._state = VBSState.VRU_ACTIVE_STANDALONE
        logger.info(
            "VBS state: VRU_PASSIVE → VRU_ACTIVE_STANDALONE (reason: %s).",
            reason.value,
        )

    # ------------------------------------------------------------------
    # Periodic state update helpers (called from update())
    # ------------------------------------------------------------------

    def _update_standalone(
        self,
        now: float,
        own_lat: float,
        own_lon: float,
        own_speed: float,
        own_heading: float,
    ) -> None:
        """Handle STANDALONE state time-based transitions (lock held)."""
        # --- Join notification phase ---
        if self._join_substate is _JoinSubstate.NOTIFY:
            assert self._join_started is not None
            if now - self._join_started >= vam_constants.TIME_CLUSTER_JOIN_NOTIFICATION:
                # Stop sending individual VAMs; wait for confirmation
                self._join_substate = _JoinSubstate.WAITING
                self._join_started = now  # reuse as "waiting started"
                self._state = VBSState.VRU_ACTIVE_STANDALONE  # stays standalone while waiting
                logger.info(
                    "Join notification complete (cluster_id=%d); "
                    "waiting for leader acknowledgement.",
                    self._join_target_cluster_id,
                )

        # --- Join waiting phase ---
        elif self._join_substate is _JoinSubstate.WAITING:
            assert self._join_started is not None
            if now - self._join_started >= vam_constants.TIME_CLUSTER_JOIN_SUCCESS:
                self.confirm_join_failed()

        # --- Cancelled / failed join leave-notification phase ---
        elif self._join_substate in (_JoinSubstate.CANCELLED, _JoinSubstate.FAILED):
            assert self._join_leave_started is not None
            if now - self._join_leave_started >= vam_constants.TIME_CLUSTER_LEAVE_NOTIFICATION:
                self._join_substate = _JoinSubstate.NONE
                self._join_target_cluster_id = None
                self._join_leave_reason = None
                self._join_leave_started = None
                logger.debug("Leave-notification after failed/cancelled join complete.")

        # --- Leave-notification phase (after leaving from PASSIVE) ---
        if self._leave_substate is _LeaveSubstate.NOTIFY:
            assert self._leave_started is not None
            if now - self._leave_started >= vam_constants.TIME_CLUSTER_LEAVE_NOTIFICATION:
                self._leave_substate = _LeaveSubstate.NONE
                self._leave_reason = None
                self._leave_cluster_id = None
                self._leave_started = None
                logger.debug("Leave-notification period complete.")

    def _update_leader(
        self,
        now: float,
        own_lat: float,
        own_lon: float,
        own_speed: float,
    ) -> None:
        """Handle CLUSTER_LEADER state time-based transitions (lock held)."""
        if self._cluster is None:
            return

        # --- Breakup warning timeout → transition to STANDALONE ---
        if (
            self._cluster.breakup_started is not None
            and now - self._cluster.breakup_started >= vam_constants.TIME_CLUSTER_BREAKUP_WARNING
        ):
            logger.info(
                "Breakup warning period complete (cluster_id=%d); "
                "transitioning to VRU_ACTIVE_STANDALONE.",
                self._cluster.cluster_id,
            )
            self._cluster = None
            self._state = VBSState.VRU_ACTIVE_STANDALONE

    def _update_passive(
        self,
        now: float,
        own_lat: float,
        own_lon: float,
        own_speed: float,
    ) -> None:
        """Handle PASSIVE state time-based transitions (lock held)."""
        # --- Leader-lost detection ---
        if (
            self._last_leader_vam_time is not None
            and now - self._last_leader_vam_time >= vam_constants.TIME_CLUSTER_CONTINUITY
        ):
            logger.warning(
                "Cluster leader (station %d) lost after %.1f s silence; "
                "leaving cluster.",
                self._leader_station_id,
                vam_constants.TIME_CLUSTER_CONTINUITY,
            )
            self._do_leave_to_standalone(ClusterLeaveReason.CLUSTER_LEADER_LOST)
            return

        # --- Leave notification timeout ---
        if self._leave_substate is _LeaveSubstate.NOTIFY:
            assert self._leave_started is not None
            if now - self._leave_started >= vam_constants.TIME_CLUSTER_LEAVE_NOTIFICATION:
                self._leave_substate = _LeaveSubstate.NONE
                self._leave_reason = None
                self._leave_cluster_id = None
                self._leave_started = None
                logger.debug("Leave-notification period complete (passive).")

    # ------------------------------------------------------------------
    # Container-building helpers
    # ------------------------------------------------------------------

    def _standalone_operation_container(self, now: float) -> Optional[dict]:
        """Build operation container for STANDALONE state (lock held)."""
        if self._join_substate is _JoinSubstate.NOTIFY:
            # Include clusterJoinInfo
            elapsed = now - (self._join_started or now)
            remaining_s = max(
                0.0,
                vam_constants.TIME_CLUSTER_JOIN_NOTIFICATION - elapsed,
            )
            # joinTime is DeltaTimeQuarterSecond (0..127, units 0.25 s)
            join_time = min(127, int(remaining_s / 0.25))
            return {
                "clusterJoinInfo": {
                    "clusterId": self._join_target_cluster_id or 0,
                    "joinTime": join_time,
                }
            }

        if self._join_substate in (_JoinSubstate.CANCELLED, _JoinSubstate.FAILED):
            return {
                "clusterLeaveInfo": {
                    "clusterId": self._join_target_cluster_id or 0,
                    "clusterLeaveReason": (
                        self._join_leave_reason or ClusterLeaveReason.NOT_PROVIDED
                    ).value,
                }
            }

        # Leave notification from prior cluster membership
        if self._leave_substate is _LeaveSubstate.NOTIFY:
            return {
                "clusterLeaveInfo": {
                    "clusterId": self._leave_cluster_id or 0,
                    "clusterLeaveReason": (
                        self._leave_reason or ClusterLeaveReason.NOT_PROVIDED
                    ).value,
                }
            }

        return None

    def _passive_operation_container(self, now: float) -> Optional[dict]:
        """Build operation container for PASSIVE state (lock held)."""
        if self._leave_substate is _LeaveSubstate.NOTIFY:
            return {
                "clusterLeaveInfo": {
                    "clusterId": self._leave_cluster_id or 0,
                    "clusterLeaveReason": (
                        self._leave_reason or ClusterLeaveReason.NOT_PROVIDED
                    ).value,
                }
            }
        return None

    def _leader_operation_container(self, now: float) -> Optional[dict]:
        """Build operation container for CLUSTER_LEADER state (lock held)."""
        if self._cluster is None:
            return None
        if self._cluster.breakup_started is not None:
            elapsed = now - self._cluster.breakup_started
            remaining_s = max(
                0.0,
                vam_constants.TIME_CLUSTER_BREAKUP_WARNING - elapsed,
            )
            breakup_time = min(127, int(remaining_s / 0.25))
            return {
                "clusterBreakupInfo": {
                    "clusterBreakupReason": (
                        self._cluster.breakup_reason or ClusterBreakupReason.NOT_PROVIDED
                    ).value,
                    "breakupTime": breakup_time,
                }
            }
        return None

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------

    def _generate_unique_cluster_id(self, now: float) -> Optional[int]:
        """Return a non-zero cluster ID that is locally unique.

        Per clause 5.4.2.2 the ID must differ from any cluster ID received
        within ``timeClusterUniquenessThreshold`` seconds.

        Returns ``None`` if no unique ID can be found within 100 attempts.
        """
        # Prune stale entries
        self._seen_cluster_ids = {
            k: v
            for k, v in self._seen_cluster_ids.items()
            if now - v < vam_constants.TIME_CLUSTER_UNIQUENESS_THRESHOLD
        }
        recent_ids = set(self._seen_cluster_ids.keys())

        for _ in range(100):
            candidate = random.randint(1, 255)
            if candidate not in recent_ids:
                return candidate
        return None  # pragma: no cover – extremely unlikely

    @staticmethod
    def _encode_cluster_profiles(profiles: "set[str]") -> bytes:
        """Encode a set of VRU profile names as a 4-bit BIT STRING byte.

        The ASN.1 definition of ``VruClusterProfiles`` (SIZE(4)) is::

            VruClusterProfiles ::= BIT STRING {
                pedestrian                   (0),
                bicyclistAndLightVRUvehicle  (1),
                motorcyclist                 (2),
                animal                       (3)
            } (SIZE (4))

        The returned single byte has the four named bits packed into the most-
        significant nibble, as expected by the UPER codec.

        Parameters
        ----------
        profiles:
            Set of ASN.1 profile-name strings, e.g.
            ``{"pedestrian", "bicyclistAndLightVruVehicle"}``.

        Returns
        -------
        bytes
            A single byte carrying the 4-bit BIT STRING.
        """
        bit = 0
        profile_bits = {
            "pedestrian": 0x80,
            "bicyclistAndLightVruVehicle": 0x40,
            "motorcyclist": 0x20,
            "animal": 0x10,
        }
        for name, mask in profile_bits.items():
            if name in profiles:
                bit |= mask
        return bytes([bit])

    def _expire_nearby_tables(self, now: float) -> None:
        """Remove VRU / cluster entries older than T_GenVamMax (lock held)."""
        max_age = vam_constants.T_GENVAMMAX / 1000.0
        self._nearby_vrus = {
            k: v for k, v in self._nearby_vrus.items() if now - v.last_seen < max_age
        }
        self._nearby_clusters = {
            k: v for k, v in self._nearby_clusters.items() if now - v.last_seen < max_age
        }

    # ------------------------------------------------------------------
    # Convenience / introspection
    # ------------------------------------------------------------------

    def get_nearby_vru_count(self) -> int:
        """Return the number of recently observed nearby VRUs."""
        with self._lock:
            return len(self._nearby_vrus)

    def get_nearby_cluster_count(self) -> int:
        """Return the number of recently observed nearby clusters."""
        with self._lock:
            return len(self._nearby_clusters)

    def get_cluster_id(self) -> Optional[int]:
        """Return the current cluster ID.

        Returns the *led* cluster ID when acting as leader,
        the *joined* cluster ID when passive, or ``None`` otherwise.
        """
        with self._lock:
            if self._state is VBSState.VRU_ACTIVE_CLUSTER_LEADER and self._cluster:
                return self._cluster.cluster_id
            if self._state is VBSState.VRU_PASSIVE:
                return self._joined_cluster_id
            return None
