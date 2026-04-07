"""Unit tests for the VBS clustering state machine.

Tests cover:
* All VBSState transitions (clause 5.4.2.2 of ETSI TS 103 300-3 V2.3.1).
* Cluster creation / destruction lifecycle.
* Join-notification, waiting, confirmation, cancellation, and failure flows.
* Leave-notification flow (from VRU_PASSIVE).
* Cluster-breakup warning flow (from VRU_ACTIVE_CLUSTER_LEADER).
* Leader-lost detection (timeClusterContinuity timeout).
* Container generation: VruClusterInformationContainer and
  VruClusterOperationContainer.
* should_transmit_vam() and get_cluster_id() helpers.
* on_received_vam() nearby-VRU / cluster table updates.
* VRU role on/off transitions.
* Thread-safety (basic: running state machine from two threads).
"""
from __future__ import annotations

import threading
import unittest

from flexstack.facilities.vru_awareness_service import vam_constants
from flexstack.facilities.vru_awareness_service.vru_clustering import (
    ClusterBreakupReason,
    ClusterLeaveReason,
    VBSClusteringManager,
    VBSState,
)


# ---------------------------------------------------------------------------
# Fake clock helpers
# ---------------------------------------------------------------------------


class _FakeClock:
    """Mutable fake clock for deterministic time-based tests."""

    def __init__(self, start: float = 1000.0) -> None:
        self._t = start

    def __call__(self) -> float:  # callable interface matching time.time
        return self._t

    def advance(self, seconds: float) -> None:
        """Advance the fake clock by *seconds*."""
        self._t += seconds


# ---------------------------------------------------------------------------
# Minimal VAM dict factory
# ---------------------------------------------------------------------------


def _make_vam(
    station_id: int = 42,
    lat: float = 48.0,
    lon: float = 11.0,
    speed: float = 1.5,
    heading: float = 90.0,
    cluster_id: int | None = None,
    join_cluster_id: int | None = None,
    leave_cluster_id: int | None = None,
    leave_reason: str = "notProvided",
    breakup_reason: str | None = None,
    breakup_time: int = 12,
) -> dict:
    """Return a minimal decoded VAM dict suitable for ``on_received_vam``."""
    params: dict = {
        "basicContainer": {
            "referencePosition": {
                "latitude": int(lat * 1e7),
                "longitude": int(lon * 1e7),
            },
        },
        "vruHighFrequencyContainer": {
            "speed": {"speedValue": int(speed * 100)},
            "heading": {"value": int(heading * 10)},
        },
    }

    if cluster_id is not None:
        params["vruClusterInformationContainer"] = {
            "vruClusterInformation": {
                "clusterId": cluster_id,
                "clusterCardinalitySize": 3,
                "clusterBoundingBoxShape": {
                    "circular": {"radius": vam_constants.MAX_CLUSTER_DISTANCE}
                },
            }
        }

    op: dict = {}
    if join_cluster_id is not None:
        op["clusterJoinInfo"] = {"clusterId": join_cluster_id, "joinTime": 12}
    if leave_cluster_id is not None:
        op["clusterLeaveInfo"] = {
            "clusterId": leave_cluster_id,
            "clusterLeaveReason": leave_reason,
        }
    if breakup_reason is not None:
        op["clusterBreakupInfo"] = {
            "clusterBreakupReason": breakup_reason,
            "breakupTime": breakup_time,
        }
    if op:
        params["vruClusterOperationContainer"] = op

    return {
        "header": {"stationId": station_id},
        "vam": {"vamParameters": params},
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestInitialState(unittest.TestCase):
    """VBSClusteringManager is created in VRU_ACTIVE_STANDALONE by default."""

    def setUp(self) -> None:
        self.clock = _FakeClock()
        self.mgr = VBSClusteringManager(
            own_station_id=1, own_vru_profile="pedestrian", time_fn=self.clock
        )

    def test_initial_state(self) -> None:
        self.assertEqual(self.mgr.state, VBSState.VRU_ACTIVE_STANDALONE)

    def test_should_transmit_initially(self) -> None:
        self.assertTrue(self.mgr.should_transmit_vam())

    def test_no_cluster_info_initially(self) -> None:
        self.assertIsNone(self.mgr.get_cluster_information_container())

    def test_no_cluster_op_initially(self) -> None:
        self.assertIsNone(self.mgr.get_cluster_operation_container())

    def test_cluster_id_none_initially(self) -> None:
        self.assertIsNone(self.mgr.get_cluster_id())


class TestVruRoleTransitions(unittest.TestCase):
    """VRU role-on / role-off state transitions (clause 5.4.2.2, Table 5)."""

    def setUp(self) -> None:
        self.clock = _FakeClock()
        self.mgr = VBSClusteringManager(own_station_id=1, time_fn=self.clock)

    def test_role_off_from_standalone(self) -> None:
        self.mgr.set_vru_role_off()
        self.assertEqual(self.mgr.state, VBSState.VRU_IDLE)

    def test_role_on_from_idle(self) -> None:
        self.mgr.set_vru_role_off()
        self.mgr.set_vru_role_on()
        self.assertEqual(self.mgr.state, VBSState.VRU_ACTIVE_STANDALONE)

    def test_role_on_ignored_when_already_standalone(self) -> None:
        """set_vru_role_on() from STANDALONE is a no-op."""
        self.mgr.set_vru_role_on()
        self.assertEqual(self.mgr.state, VBSState.VRU_ACTIVE_STANDALONE)

    def test_idle_suppresses_transmit(self) -> None:
        self.mgr.set_vru_role_off()
        self.assertFalse(self.mgr.should_transmit_vam())

    def test_role_off_clears_cluster_state(self) -> None:
        """Role-off from LEADER tears down cluster data."""
        self._populate_nearby(count=vam_constants.NUM_CREATE_CLUSTER)
        self.mgr.try_create_cluster(0.0, 0.0)
        self.assertEqual(self.mgr.state, VBSState.VRU_ACTIVE_CLUSTER_LEADER)
        self.mgr.set_vru_role_off()
        self.assertIsNone(self.mgr.get_cluster_information_container())

    def _populate_nearby(self, count: int) -> None:
        """Inject *count* nearby VRU entries directly into the manager."""
        now = self.clock()
        for i in range(count):
            from flexstack.facilities.vru_awareness_service.vru_clustering import _NearbyVRU
            # pylint: disable=protected-access
            self.mgr._nearby_vrus[100 + i] = _NearbyVRU(
                station_id=100 + i,
                lat=0.0,
                lon=0.0,
                speed=1.0,
                heading=0.0,
                last_seen=now,
            )


class TestClusterCreation(unittest.TestCase):
    """VRU_ACTIVE_STANDALONE → VRU_ACTIVE_CLUSTER_LEADER via try_create_cluster."""

    def setUp(self) -> None:
        self.clock = _FakeClock()
        self.mgr = VBSClusteringManager(own_station_id=5, time_fn=self.clock)

    def _add_nearby(self, count: int) -> None:
        from flexstack.facilities.vru_awareness_service.vru_clustering import _NearbyVRU
        now = self.clock()
        for i in range(count):
            # pylint: disable=protected-access
            self.mgr._nearby_vrus[200 + i] = _NearbyVRU(
                station_id=200 + i,
                lat=0.0,
                lon=0.0,
                speed=1.0,
                heading=0.0,
                last_seen=now,
            )

    def test_cluster_not_created_without_enough_vrus(self) -> None:
        """Cluster requires at least NUM_CREATE_CLUSTER nearby VRUs."""
        self._add_nearby(vam_constants.NUM_CREATE_CLUSTER - 1)
        result = self.mgr.try_create_cluster(0.0, 0.0)
        self.assertFalse(result)
        self.assertEqual(self.mgr.state, VBSState.VRU_ACTIVE_STANDALONE)

    def test_cluster_created_with_enough_vrus(self) -> None:
        self._add_nearby(vam_constants.NUM_CREATE_CLUSTER)
        result = self.mgr.try_create_cluster(0.0, 0.0)
        self.assertTrue(result)
        self.assertEqual(self.mgr.state, VBSState.VRU_ACTIVE_CLUSTER_LEADER)

    def test_cluster_info_container_present_after_creation(self) -> None:
        self._add_nearby(vam_constants.NUM_CREATE_CLUSTER)
        self.mgr.try_create_cluster(0.0, 0.0)
        ctr = self.mgr.get_cluster_information_container()
        self.assertIsNotNone(ctr)
        assert ctr is not None
        info = ctr["vruClusterInformation"]
        self.assertIn("clusterId", info)
        self.assertGreater(info["clusterId"], 0)
        self.assertIn("clusterBoundingBoxShape", info)
        self.assertIn("clusterCardinalitySize", info)

    def test_cluster_id_accessible_after_creation(self) -> None:
        self._add_nearby(vam_constants.NUM_CREATE_CLUSTER)
        self.mgr.try_create_cluster(0.0, 0.0)
        self.assertIsNotNone(self.mgr.get_cluster_id())

    def test_create_fails_when_not_standalone(self) -> None:
        self.mgr.set_vru_role_off()
        self._add_nearby(vam_constants.NUM_CREATE_CLUSTER)
        result = self.mgr.try_create_cluster(0.0, 0.0)
        self.assertFalse(result)

    def test_cluster_not_created_for_vrus_out_of_range(self) -> None:
        """VRUs further than MAX_CLUSTER_DISTANCE are not counted."""
        from flexstack.facilities.vru_awareness_service.vru_clustering import _NearbyVRU
        now = self.clock()
        # Place 5 VRUs 1 km away — well outside MAX_CLUSTER_DISTANCE
        for i in range(5):
            # pylint: disable=protected-access
            self.mgr._nearby_vrus[300 + i] = _NearbyVRU(
                station_id=300 + i,
                lat=10.0,  # far from 0.0
                lon=10.0,
                speed=1.0,
                heading=0.0,
                last_seen=now,
            )
        result = self.mgr.try_create_cluster(0.0, 0.0)
        self.assertFalse(result)


class TestClusterBreakup(unittest.TestCase):
    """Cluster breakup warning flow (clause 5.4.2.2)."""

    def setUp(self) -> None:
        self.clock = _FakeClock()
        self.mgr = VBSClusteringManager(own_station_id=5, time_fn=self.clock)
        # Force into LEADER state
        from flexstack.facilities.vru_awareness_service.vru_clustering import _NearbyVRU
        now = self.clock()
        for i in range(vam_constants.NUM_CREATE_CLUSTER):
            # pylint: disable=protected-access
            self.mgr._nearby_vrus[400 + i] = _NearbyVRU(
                station_id=400 + i,
                lat=0.0,
                lon=0.0,
                speed=1.0,
                heading=0.0,
                last_seen=now,
            )
        self.mgr.try_create_cluster(0.0, 0.0)
        self.assertEqual(self.mgr.state, VBSState.VRU_ACTIVE_CLUSTER_LEADER)

    def test_breakup_initiation(self) -> None:
        result = self.mgr.trigger_breakup_cluster(ClusterBreakupReason.CLUSTERING_PURPOSE_COMPLETED)
        self.assertTrue(result)

    def test_breakup_container_present(self) -> None:
        self.mgr.trigger_breakup_cluster(ClusterBreakupReason.NOT_PROVIDED)
        op = self.mgr.get_cluster_operation_container()
        self.assertIsNotNone(op)
        assert op is not None
        self.assertIn("clusterBreakupInfo", op)
        info = op["clusterBreakupInfo"]
        self.assertIn("clusterBreakupReason", info)
        self.assertIn("breakupTime", info)
        self.assertGreaterEqual(info["breakupTime"], 0)
        self.assertLessEqual(info["breakupTime"], 127)

    def test_breakup_transitions_to_standalone_after_warning(self) -> None:
        self.mgr.trigger_breakup_cluster(ClusterBreakupReason.NOT_PROVIDED)
        self.clock.advance(vam_constants.TIME_CLUSTER_BREAKUP_WARNING)
        self.mgr.update(0.0, 0.0, 1.0, 0.0)
        self.assertEqual(self.mgr.state, VBSState.VRU_ACTIVE_STANDALONE)

    def test_breakup_not_before_warning_expires(self) -> None:
        self.mgr.trigger_breakup_cluster(ClusterBreakupReason.NOT_PROVIDED)
        self.clock.advance(vam_constants.TIME_CLUSTER_BREAKUP_WARNING - 0.1)
        self.mgr.update(0.0, 0.0, 1.0, 0.0)
        self.assertEqual(self.mgr.state, VBSState.VRU_ACTIVE_CLUSTER_LEADER)

    def test_double_breakup_ignored(self) -> None:
        self.mgr.trigger_breakup_cluster(ClusterBreakupReason.NOT_PROVIDED)
        result = self.mgr.trigger_breakup_cluster(ClusterBreakupReason.CLUSTERING_PURPOSE_COMPLETED)
        self.assertFalse(result)

    def test_breakup_fails_when_not_leader(self) -> None:
        mgr = VBSClusteringManager(own_station_id=99, time_fn=self.clock)
        result = mgr.trigger_breakup_cluster()
        self.assertFalse(result)


class TestClusterJoiningFlow(unittest.TestCase):
    """Join notification → passive → confirmation / failure / cancellation flows."""

    def setUp(self) -> None:
        self.clock = _FakeClock()
        self.mgr = VBSClusteringManager(own_station_id=10, time_fn=self.clock)

    def test_initiate_join(self) -> None:
        result = self.mgr.initiate_join(cluster_id=7)
        self.assertTrue(result)

    def test_join_operation_container_present(self) -> None:
        self.mgr.initiate_join(cluster_id=7)
        op = self.mgr.get_cluster_operation_container()
        self.assertIsNotNone(op)
        assert op is not None
        self.assertIn("clusterJoinInfo", op)
        self.assertEqual(op["clusterJoinInfo"]["clusterId"], 7)

    def test_join_time_decreases(self) -> None:
        self.mgr.initiate_join(cluster_id=7)
        op1 = self.mgr.get_cluster_operation_container()
        self.clock.advance(1.0)
        op2 = self.mgr.get_cluster_operation_container()
        assert op1 is not None and op2 is not None
        self.assertGreaterEqual(
            op1["clusterJoinInfo"]["joinTime"],
            op2["clusterJoinInfo"]["joinTime"],
        )

    def test_double_initiate_join_rejected(self) -> None:
        self.mgr.initiate_join(cluster_id=7)
        result2 = self.mgr.initiate_join(cluster_id=8)
        self.assertFalse(result2)

    def test_join_notification_phase_ends_and_enters_waiting(self) -> None:
        self.mgr.initiate_join(cluster_id=7)
        self.clock.advance(vam_constants.TIME_CLUSTER_JOIN_NOTIFICATION)
        self.mgr.update(0.0, 0.0, 1.0, 0.0)
        # Still standalone during waiting phase
        self.assertEqual(self.mgr.state, VBSState.VRU_ACTIVE_STANDALONE)

    def test_failed_join_after_join_success_timeout(self) -> None:
        self.mgr.initiate_join(cluster_id=7)
        # Skip through notification phase
        self.clock.advance(vam_constants.TIME_CLUSTER_JOIN_NOTIFICATION)
        self.mgr.update(0.0, 0.0, 1.0, 0.0)
        # Skip through waiting phase
        self.clock.advance(vam_constants.TIME_CLUSTER_JOIN_SUCCESS)
        self.mgr.update(0.0, 0.0, 1.0, 0.0)
        # Should now have failed-join leave-notice in op container
        op = self.mgr.get_cluster_operation_container()
        self.assertIsNotNone(op)
        assert op is not None
        self.assertIn("clusterLeaveInfo", op)
        self.assertEqual(
            op["clusterLeaveInfo"]["clusterLeaveReason"],
            ClusterLeaveReason.FAILED_JOIN.value,
        )

    def test_failed_join_leave_notice_expires(self) -> None:
        self.mgr.initiate_join(cluster_id=7)
        self.clock.advance(vam_constants.TIME_CLUSTER_JOIN_NOTIFICATION)
        self.mgr.update(0.0, 0.0, 1.0, 0.0)
        self.clock.advance(vam_constants.TIME_CLUSTER_JOIN_SUCCESS)
        self.mgr.update(0.0, 0.0, 1.0, 0.0)
        # Advance through leave notification period
        self.clock.advance(vam_constants.TIME_CLUSTER_LEAVE_NOTIFICATION)
        self.mgr.update(0.0, 0.0, 1.0, 0.0)
        self.assertIsNone(self.mgr.get_cluster_operation_container())

    def test_cancelled_join(self) -> None:
        self.mgr.initiate_join(cluster_id=7)
        self.mgr.cancel_join()
        op = self.mgr.get_cluster_operation_container()
        self.assertIsNotNone(op)
        assert op is not None
        self.assertIn("clusterLeaveInfo", op)
        self.assertEqual(
            op["clusterLeaveInfo"]["clusterLeaveReason"],
            ClusterLeaveReason.CANCELLED_JOIN.value,
        )

    def test_successful_join_via_received_vam(self) -> None:
        """Leader VAM with matching cluster ID during waiting phase confirms join."""
        self.mgr.initiate_join(cluster_id=99)
        # Advance past notification phase
        self.clock.advance(vam_constants.TIME_CLUSTER_JOIN_NOTIFICATION)
        self.mgr.update(0.0, 0.0, 1.0, 0.0)
        # Simulate leader's cluster VAM
        vam = _make_vam(station_id=50, cluster_id=99)
        self.mgr.on_received_vam(vam)
        self.assertEqual(self.mgr.state, VBSState.VRU_PASSIVE)
        self.assertEqual(self.mgr.get_cluster_id(), 99)

    def test_join_initiate_rejected_from_idle(self) -> None:
        self.mgr.set_vru_role_off()
        result = self.mgr.initiate_join(cluster_id=7)
        self.assertFalse(result)


class TestClusterLeaving(unittest.TestCase):
    """Leave notification flow from VRU_PASSIVE (clause 5.4.2.2)."""

    def _make_passive_manager(self) -> VBSClusteringManager:
        """Return a manager that has been placed into VRU_PASSIVE."""
        mgr = VBSClusteringManager(own_station_id=20, time_fn=self.clock)
        mgr.initiate_join(cluster_id=3)
        self.clock.advance(vam_constants.TIME_CLUSTER_JOIN_NOTIFICATION)
        mgr.update(0.0, 0.0, 1.0, 0.0)
        # Confirm join via leader VAM
        mgr.on_received_vam(_make_vam(station_id=15, cluster_id=3))
        self.assertEqual(mgr.state, VBSState.VRU_PASSIVE)
        return mgr

    def setUp(self) -> None:
        self.clock = _FakeClock()
        self.mgr = self._make_passive_manager()

    def test_passive_suppresses_transmit(self) -> None:
        self.assertFalse(self.mgr.should_transmit_vam())

    def test_leave_starts_notification_phase(self) -> None:
        self.mgr.trigger_leave_cluster(ClusterLeaveReason.SAFETY_CONDITION)
        # During leave-notification the device moves back to STANDALONE and
        # transmits leave VAMs
        self.assertEqual(self.mgr.state, VBSState.VRU_ACTIVE_STANDALONE)
        self.assertTrue(self.mgr.should_transmit_vam())
        op = self.mgr.get_cluster_operation_container()
        self.assertIsNotNone(op)
        assert op is not None
        self.assertIn("clusterLeaveInfo", op)
        self.assertEqual(
            op["clusterLeaveInfo"]["clusterLeaveReason"],
            ClusterLeaveReason.SAFETY_CONDITION.value,
        )

    def test_leave_notification_expires(self) -> None:
        self.mgr.trigger_leave_cluster()
        self.clock.advance(vam_constants.TIME_CLUSTER_LEAVE_NOTIFICATION)
        self.mgr.update(0.0, 0.0, 1.0, 0.0)
        self.assertIsNone(self.mgr.get_cluster_operation_container())


class TestLeaderLostDetection(unittest.TestCase):
    """Leader-lost detection via timeClusterContinuity timeout (clause 5.4.2.2)."""

    def setUp(self) -> None:
        self.clock = _FakeClock()
        self.mgr = VBSClusteringManager(own_station_id=30, time_fn=self.clock)
        # Enter VRU_PASSIVE
        self.mgr.initiate_join(cluster_id=11)
        self.clock.advance(vam_constants.TIME_CLUSTER_JOIN_NOTIFICATION)
        self.mgr.update(0.0, 0.0, 1.0, 0.0)
        self.mgr.on_received_vam(_make_vam(station_id=77, cluster_id=11))
        self.assertEqual(self.mgr.state, VBSState.VRU_PASSIVE)

    def test_leader_lost_after_continuity_timeout(self) -> None:
        self.clock.advance(vam_constants.TIME_CLUSTER_CONTINUITY)
        self.mgr.update(0.0, 0.0, 1.0, 0.0)
        self.assertEqual(self.mgr.state, VBSState.VRU_ACTIVE_STANDALONE)

    def test_leader_not_lost_before_continuity_timeout(self) -> None:
        self.clock.advance(vam_constants.TIME_CLUSTER_CONTINUITY - 0.1)
        self.mgr.update(0.0, 0.0, 1.0, 0.0)
        self.assertEqual(self.mgr.state, VBSState.VRU_PASSIVE)

    def test_receiving_leader_vam_resets_timeout(self) -> None:
        # Advance close to timeout
        self.clock.advance(vam_constants.TIME_CLUSTER_CONTINUITY - 0.1)
        # Receive a fresh leader VAM — resets the timer
        self.mgr.on_received_vam(_make_vam(station_id=77, cluster_id=11))
        # Advance a bit more — should not yet trigger leader-lost
        self.clock.advance(vam_constants.TIME_CLUSTER_CONTINUITY - 0.1)
        self.mgr.update(0.0, 0.0, 1.0, 0.0)
        self.assertEqual(self.mgr.state, VBSState.VRU_PASSIVE)

    def test_leader_lost_sends_leave_notice(self) -> None:
        self.clock.advance(vam_constants.TIME_CLUSTER_CONTINUITY)
        self.mgr.update(0.0, 0.0, 1.0, 0.0)
        op = self.mgr.get_cluster_operation_container()
        self.assertIsNotNone(op)
        assert op is not None
        self.assertIn("clusterLeaveInfo", op)
        self.assertEqual(
            op["clusterLeaveInfo"]["clusterLeaveReason"],
            ClusterLeaveReason.CLUSTER_LEADER_LOST.value,
        )


class TestLeaderDisbandByLeader(unittest.TestCase):
    """Passive VRU receives breakup VAM from leader and leaves cluster."""

    def setUp(self) -> None:
        self.clock = _FakeClock()
        self.mgr = VBSClusteringManager(own_station_id=40, time_fn=self.clock)
        self.mgr.initiate_join(cluster_id=22)
        self.clock.advance(vam_constants.TIME_CLUSTER_JOIN_NOTIFICATION)
        self.mgr.update(0.0, 0.0, 1.0, 0.0)
        self.mgr.on_received_vam(_make_vam(station_id=88, cluster_id=22))

    def test_leader_breakup_triggers_standalone(self) -> None:
        breakup_vam = _make_vam(
            station_id=88,
            breakup_reason=ClusterBreakupReason.CLUSTERING_PURPOSE_COMPLETED.value,
        )
        self.mgr.on_received_vam(breakup_vam)
        self.assertEqual(self.mgr.state, VBSState.VRU_ACTIVE_STANDALONE)


class TestNearbyTableMaintenance(unittest.TestCase):
    """Nearby VRU and cluster tables track received VAMs and expire stale entries."""

    def setUp(self) -> None:
        self.clock = _FakeClock()
        self.mgr = VBSClusteringManager(own_station_id=50, time_fn=self.clock)

    def test_nearby_vru_added_on_reception(self) -> None:
        self.mgr.on_received_vam(_make_vam(station_id=60))
        self.assertEqual(self.mgr.get_nearby_vru_count(), 1)

    def test_nearby_vru_updated_on_second_reception(self) -> None:
        self.mgr.on_received_vam(_make_vam(station_id=60, speed=1.0))
        self.mgr.on_received_vam(_make_vam(station_id=60, speed=2.0))
        # Same station should not add a duplicate entry
        self.assertEqual(self.mgr.get_nearby_vru_count(), 1)

    def test_nearby_cluster_added_on_reception(self) -> None:
        self.mgr.on_received_vam(_make_vam(station_id=70, cluster_id=5))
        self.assertEqual(self.mgr.get_nearby_cluster_count(), 1)

    def test_stale_entries_expire_on_update(self) -> None:
        self.mgr.on_received_vam(_make_vam(station_id=60))
        self.clock.advance(vam_constants.T_GENVAMMAX / 1000.0)
        self.mgr.update(0.0, 0.0, 1.0, 0.0)
        self.assertEqual(self.mgr.get_nearby_vru_count(), 0)

    def test_malformed_vam_does_not_crash(self) -> None:
        """on_received_vam tolerates incomplete VAM dicts."""
        self.mgr.on_received_vam({})  # should not raise
        self.mgr.on_received_vam({"header": {}, "vam": {}})


class TestClusterProfileEncoding(unittest.TestCase):
    """_encode_cluster_profiles produces valid BIT STRING bytes."""

    def test_pedestrian_bit_set(self) -> None:
        # pylint: disable=protected-access
        result = VBSClusteringManager._encode_cluster_profiles({"pedestrian"})
        self.assertEqual(len(result), 1)
        self.assertTrue(result[0] & 0x80)  # bit 0 (MSB)

    def test_bicyclist_bit_set(self) -> None:
        # pylint: disable=protected-access
        result = VBSClusteringManager._encode_cluster_profiles({"bicyclistAndLightVruVehicle"})
        self.assertTrue(result[0] & 0x40)

    def test_multiple_profiles(self) -> None:
        # pylint: disable=protected-access
        result = VBSClusteringManager._encode_cluster_profiles(
            {"pedestrian", "motorcyclist"}
        )
        self.assertTrue(result[0] & 0x80)  # pedestrian
        self.assertTrue(result[0] & 0x20)  # motorcyclist

    def test_empty_profiles(self) -> None:
        # pylint: disable=protected-access
        result = VBSClusteringManager._encode_cluster_profiles(set())
        self.assertEqual(result, bytes([0]))


class TestContainerFormats(unittest.TestCase):
    """Cluster information and operation containers have the expected dict structure."""

    def setUp(self) -> None:
        self.clock = _FakeClock()
        self.mgr = VBSClusteringManager(own_station_id=1, time_fn=self.clock)

    def _create_cluster(self) -> None:
        from flexstack.facilities.vru_awareness_service.vru_clustering import _NearbyVRU
        now = self.clock()
        for i in range(vam_constants.NUM_CREATE_CLUSTER):
            # pylint: disable=protected-access
            self.mgr._nearby_vrus[500 + i] = _NearbyVRU(
                station_id=500 + i,
                lat=0.0,
                lon=0.0,
                speed=1.0,
                heading=0.0,
                last_seen=now,
            )
        self.mgr.try_create_cluster(0.0, 0.0)

    def test_info_container_keys(self) -> None:
        self._create_cluster()
        ctr = self.mgr.get_cluster_information_container()
        assert ctr is not None
        info = ctr["vruClusterInformation"]
        self.assertIn("clusterId", info)
        self.assertIn("clusterBoundingBoxShape", info)
        self.assertIn("clusterCardinalitySize", info)
        self.assertIn("circular", info["clusterBoundingBoxShape"])
        self.assertIn("radius", info["clusterBoundingBoxShape"]["circular"])

    def test_info_container_none_when_not_leader(self) -> None:
        self.assertIsNone(self.mgr.get_cluster_information_container())

    def test_breakup_container_fields(self) -> None:
        self._create_cluster()
        self.mgr.trigger_breakup_cluster(ClusterBreakupReason.CLUSTERING_PURPOSE_COMPLETED)
        op = self.mgr.get_cluster_operation_container()
        assert op is not None
        breakup = op["clusterBreakupInfo"]
        self.assertEqual(
            breakup["clusterBreakupReason"],
            ClusterBreakupReason.CLUSTERING_PURPOSE_COMPLETED.value,
        )
        self.assertIsInstance(breakup["breakupTime"], int)
        self.assertGreaterEqual(breakup["breakupTime"], 0)
        self.assertLessEqual(breakup["breakupTime"], 127)


class TestThreadSafety(unittest.TestCase):
    """Basic concurrent access test: no crashes or deadlocks under parallel calls."""

    def test_concurrent_update_and_received_vam(self) -> None:
        clock = _FakeClock()
        mgr = VBSClusteringManager(own_station_id=99, time_fn=clock)
        errors: list[Exception] = []

        def update_thread() -> None:
            try:
                for _ in range(50):
                    mgr.update(0.0, 0.0, 1.0, 90.0)
            except Exception as exc:  # pylint: disable=broad-except
                errors.append(exc)

        def receive_thread() -> None:
            try:
                for i in range(50):
                    mgr.on_received_vam(_make_vam(station_id=i + 1))
            except Exception as exc:  # pylint: disable=broad-except
                errors.append(exc)

        t1 = threading.Thread(target=update_thread)
        t2 = threading.Thread(target=receive_thread)
        t1.start()
        t2.start()
        t1.join(timeout=5.0)
        t2.join(timeout=5.0)
        self.assertFalse(errors, f"Exceptions raised in threads: {errors}")


if __name__ == "__main__":
    unittest.main()
