"""
Unit tests of the DEN protocol engine (ETSI TS 103 831 V2.3.1, clause 8). The
test purposes of ETSI TS 102 869-2 V1.6.1 are checked one by one, through the
whole stack, in ``test_den_conformance.py``. Time is injected explicitly
(TimestampIts, ms); DENMs go through the real UPER coder where the wire format
matters.

Mirrors the tests of
``rustflexstack::facilities::decentralized_environmental_notification_service::den_protocol``.
"""

import random
import unittest

from flexstack.facilities.decentralized_environmental_notification_service.den_protocol import (
    DEFAULT_VALIDITY_DURATION_S,
    ActionId,
    DenFailure,
    DenmState,
    DENMRequest,
    DENProtocol,
    DiscardReason,
    inside_area,
)
from flexstack.facilities.decentralized_environmental_notification_service.denm_coder import (
    DENMCoder,
)
from flexstack.facilities.decentralized_environmental_notification_service.denm_ssp import (
    cause_code_value,
    ssp_consistent,
    ssp_permits_cause_code,
)
from flexstack.geonet.service_access_point import Area, GeoBroadcastHST

CODER = DENMCoder()
T0 = 600_000_000_000  # an arbitrary TimestampIts (ms)
POSITION = {
    "latitude": 415520000,
    "longitude": 21340000,
    "positionConfidenceEllipse": {"semiMajorConfidence": 4095, "semiMinorConfidence": 4095,
                                  "semiMajorOrientation": 3601},
    "altitude": {"altitudeValue": 800001, "altitudeConfidence": "unavailable"},
}
SITUATION = {"informationQuality": 3, "eventType": {"ccAndScc": ("accident2", 0)}}
LOCATION = {"detectionZonesToEventPosition": [[{"pathPosition": {
    "deltaLatitude": 131072, "deltaLongitude": 131072, "deltaAltitude": 12800}}]]}


def new_request(**kwargs) -> DENMRequest:
    fields = {"event_position": POSITION, "situation": SITUATION, "location": LOCATION}
    fields.update(kwargs)
    return DENMRequest(**fields)


def station(station_id=7, **kwargs) -> DENProtocol:
    return DENProtocol(station_id, 5, validate=CODER.validate, rng=random.Random(1), **kwargs)


def over_the_air(outgoing):
    """Encode and decode, as a receiving ITS-S would see the DENM."""
    return CODER.decode(CODER.encode(outgoing.denm))


def management(outgoing):
    return outgoing.denm["denm"]["management"]


class TestEventGeneration(unittest.TestCase):
    """AppDENM_trigger (clauses 6.1.1, 6.1.2.1, 8.2.2)."""

    def test_trigger_generates_new_denm(self):
        """New event (TS 103 831 clauses 6.1.1, 8.2.2)."""
        result, out = station().trigger(new_request(), T0)
        self.assertTrue(result.ok)
        self.assertEqual(len(out), 1)
        decoded = over_the_air(out[0])
        self.assertNotIn("termination", decoded["denm"]["management"])
        self.assertIn("situation", decoded["denm"])
        self.assertIn("location", decoded["denm"])
        self.assertEqual(out[0].area_type, GeoBroadcastHST.GEOBROADCAST_CIRCLE)

    def test_each_new_denm_gets_new_action_id(self):
        """New event (TS 103 831 clauses 6.1.1, 8.2.2)."""
        its = station()
        ids = {its.trigger(new_request(), T0 + i)[0].action_id for i in range(5)}
        self.assertEqual(len(ids), 5)

    def test_action_id_contains_station_id(self):
        """New event (TS 103 831 clauses 6.1.1, 8.2.2)."""
        result, out = station(4242).trigger(new_request(), T0)
        self.assertEqual(result.action_id.station_id, 4242)
        self.assertEqual(management(out[0])["actionId"]["originatingStationId"], 4242)

    def test_cause_code_as_provided_by_application(self):
        """New event (TS 103 831 clauses 6.1.1, 8.2.2)."""
        situation = {"informationQuality": 5,
                     "eventType": {"ccAndScc": ("emergencyVehicleApproaching95", 1)}}
        _, out = station().trigger(new_request(situation=situation), T0)
        self.assertEqual(over_the_air(out[0])["denm"]["situation"]["eventType"]["ccAndScc"],
                         ("emergencyVehicleApproaching95", 1))

    def test_reference_time_is_current_time(self):
        """New event (TS 103 831 clauses 6.1.1, 8.2.2)."""
        _, out = station().trigger(new_request(detection_time=T0 - 500), T0)
        self.assertEqual(management(out[0])["referenceTime"], T0)
        self.assertEqual(management(out[0])["detectionTime"], T0 - 500)

    def test_sequence_number_is_next_unused_value(self):
        """New event (TS 103 831 clauses 6.1.1, 8.2.2)."""
        its = station()
        first = its.trigger(new_request(), T0)[0].action_id
        second = its.trigger(new_request(), T0 + 1)[0].action_id
        self.assertEqual(second.sequence_number, first.sequence_number + 1)

    def test_sequence_number_wraps_around(self):
        """New event (TS 103 831 clauses 6.1.1, 8.2.2): 65535 is followed by 0."""
        its = station()
        its._next_sequence_number = 65535  # pylint: disable=protected-access
        self.assertEqual(its.trigger(new_request(), T0)[0].action_id.sequence_number, 65535)
        self.assertEqual(its.trigger(new_request(), T0 + 1)[0].action_id.sequence_number, 0)

    def test_sequence_numbers_in_use_are_skipped(self):
        """Clause 6.1.1.1: a sequence number of a stored event is not reassigned."""
        its = station()
        its.trigger(new_request(), T0)                       # uses 0
        its._next_sequence_number = 0  # pylint: disable=protected-access
        self.assertEqual(its.trigger(new_request(), T0 + 1)[0].action_id.sequence_number, 1)

    def test_pseudonym_change_updates_action_ids(self):
        """Pseudonym change (TS 103 831 clause 6.1.1.2): stored actionIds follow the new stationId."""
        its = station(7)
        result, _ = its.trigger(new_request(repetition_interval=100, repetition_duration=1000), T0)
        its.update_station_id(8)
        moved = ActionId(8, result.action_id.sequence_number)
        self.assertIn(moved, its.originating)
        self.assertNotIn(result.action_id, its.originating)
        out, _ = its.tick(T0 + 100)
        self.assertEqual(management(out[0])["actionId"]["originatingStationId"], 8)
        self.assertEqual(out[0].denm["header"]["stationId"], 8)
        new = its.trigger(new_request(), T0 + 200)[0].action_id
        self.assertEqual(new.station_id, 8)

    def test_action_id_from_central_entity_is_used(self):
        """Table 2 note 10: actionId provided by the application."""
        result, _ = station().trigger(new_request(action_id=ActionId(99, 12)), T0)
        self.assertEqual(result.action_id, ActionId(99, 12))

    def test_validity_in_the_past_is_a_failure(self):
        """Clause 8.2.3.4: T_O_Validity expiration time in the past."""
        result, out = station().trigger(new_request(detection_time=T0 - 20_000,
                                                    validity_duration=10), T0)
        self.assertEqual(result.failure, DenFailure.VALIDITY_EXPIRED)
        self.assertEqual(out, [])

    def test_missing_situation_is_a_generation_failure(self):
        """Clause 8.2.3.2: a new DENM needs the Situation and Location containers."""
        result, out = station().trigger(new_request(situation=None), T0)
        self.assertEqual(result.failure, DenFailure.GENERATION_FAILED)
        self.assertEqual(out, [])

    def test_unencodable_denm_is_a_generation_failure(self):
        """Clause 8.2.3.2: data out of the ASN.1 range."""
        bad = {"informationQuality": 99, "eventType": {"ccAndScc": ("accident2", 0)}}
        result, out = station().trigger(new_request(situation=bad), T0)
        self.assertEqual(result.failure, DenFailure.GENERATION_FAILED)
        self.assertEqual(out, [])

    def test_default_validity_and_optional_fields(self):
        """Clauses 7.1.3, 8.2.1.5: default validityDuration; optional components."""
        _, out = station().trigger(new_request(awareness_distance="lessThan200m",
                                               traffic_direction="allTrafficDirections",
                                               transmission_interval=500), T0)
        decoded = over_the_air(out[0])["denm"]["management"]
        self.assertEqual(decoded["validityDuration"], DEFAULT_VALIDITY_DURATION_S)
        self.assertEqual(decoded["awarenessDistance"], "lessThan200m")
        self.assertEqual(decoded["transmissionInterval"], 500)


class TestEventUpdate(unittest.TestCase):
    """AppDENM_update (clauses 6.1.2.2, 8.2.2)."""

    def setUp(self):
        self.its = station()
        self.result, _ = self.its.trigger(new_request(), T0)

    def test_update_generates_update_denm(self):
        """Event update (TS 103 831 clause 8.2.2)."""
        new_situation = {"informationQuality": 6, "eventType": {"ccAndScc": ("accident2", 1)}}
        result, out = self.its.update(self.result.action_id,
                                      new_request(situation=new_situation), T0 + 1000)
        self.assertTrue(result.ok)
        self.assertEqual(over_the_air(out[0])["denm"]["situation"], new_situation)

    def test_update_keeps_action_id(self):
        """Event update (TS 103 831 clause 8.2.2)."""
        result, out = self.its.update(self.result.action_id, new_request(), T0 + 1000)
        self.assertEqual(result.action_id, self.result.action_id)
        self.assertEqual(management(out[0])["actionId"], self.result.action_id.to_dict())

    def test_update_reference_time_is_current_time(self):
        """Event update (TS 103 831 clause 8.2.2)."""
        _, out = self.its.update(self.result.action_id, new_request(), T0 + 1000)
        self.assertEqual(management(out[0])["referenceTime"], T0 + 1000)

    def test_update_reference_time_strictly_increases(self):
        """Clause 6.1.2.2: greater than the previous referenceTime, even at the same ms."""
        _, out = self.its.update(self.result.action_id, new_request(), T0)
        self.assertGreater(management(out[0])["referenceTime"], T0)

    def test_update_of_unknown_action_id_fails(self):
        """Event update (TS 103 831 clause 8.2.2)."""
        result, out = self.its.update(ActionId(7, 999), new_request(), T0 + 1000)
        self.assertEqual(result.failure, DenFailure.UNKNOWN_ACTION_ID)
        self.assertEqual(out, [])

    def test_update_keeps_containers_not_provided(self):
        """Table 3 note 2: unchanged data keeps its previous value."""
        _, out = self.its.update(self.result.action_id,
                                 new_request(situation=None, location=None), T0 + 1000)
        self.assertEqual(out[0].denm["denm"]["situation"], SITUATION)
        self.assertEqual(out[0].denm["denm"]["location"], LOCATION)


class TestEventTermination(unittest.TestCase):
    """AppDENM_termination (clauses 6.1.2.4, 8.2.2)."""

    def setUp(self):
        self.originator = station(7)
        self.receiver = station(9)
        self.result, out = self.originator.trigger(new_request(), T0)
        self.receiver.receive(over_the_air(out[0]), T0 + 10)

    def test_cancellation_by_originating_its(self):
        """Event termination (TS 103 831 clauses 6.1.2.4, 8.2.2)."""
        result, out = self.originator.terminate(self.result.action_id, new_request(), T0 + 500)
        self.assertTrue(result.ok)
        self.assertEqual(over_the_air(out[0])["denm"]["management"]["termination"],
                         "isCancellation")
        self.assertEqual(self.originator.originating[self.result.action_id].state,
                         DenmState.CANCELLED)

    def test_negation_by_other_its(self):
        """Event termination (TS 103 831 clauses 6.1.2.4, 8.2.2)."""
        result, out = self.receiver.terminate(self.result.action_id, new_request(), T0 + 500)
        self.assertTrue(result.ok)
        decoded = over_the_air(out[0])
        self.assertEqual(decoded["denm"]["management"]["termination"], "isNegation")
        self.assertEqual(decoded["denm"]["management"]["actionId"],
                         self.result.action_id.to_dict())
        self.assertEqual(decoded["header"]["stationId"], 9)
        self.assertEqual(self.receiver.originating[self.result.action_id].state,
                         DenmState.NEGATED)

    def test_negation_reference_time_is_latest_received(self):
        """Event termination (TS 103 831 clauses 6.1.2.4, 8.2.2)."""
        _, out = self.receiver.terminate(self.result.action_id, new_request(), T0 + 500)
        self.assertEqual(management(out[0])["referenceTime"], T0)

    def test_cancellation_has_management_container_only(self):
        """Event termination (TS 103 831 clauses 6.1.2.4, 8.2.2)."""
        _, out = self.originator.terminate(self.result.action_id, new_request(), T0 + 500)
        self.assertEqual(set(over_the_air(out[0])["denm"].keys()), {"management"})

    def test_negation_has_management_container_only(self):
        """Event termination (TS 103 831 clauses 6.1.2.4, 8.2.2)."""
        _, out = self.receiver.terminate(self.result.action_id, new_request(), T0 + 500)
        self.assertEqual(set(over_the_air(out[0])["denm"].keys()), {"management"})

    def test_termination_of_unknown_action_id_fails(self):
        """Event termination (TS 103 831 clause 8.2.2): unknown actionId, own or other stationId."""
        result, out = self.receiver.terminate(ActionId(1, 1), new_request(), T0 + 500)
        self.assertEqual(result.failure, DenFailure.UNKNOWN_ACTION_ID)
        self.assertEqual(out, [])

    def test_cancellation_reference_time_is_current_time(self):
        """Event termination (TS 103 831 clauses 6.1.2.4, 8.2.2)."""
        _, out = self.originator.terminate(self.result.action_id, new_request(), T0 + 500)
        self.assertEqual(management(out[0])["referenceTime"], T0 + 500)

    def test_detection_time_is_termination_detection_time(self):
        """Clause 6.1.2.4: detectionTime of a termination is when it was detected."""
        _, out = self.originator.terminate(self.result.action_id,
                                           new_request(detection_time=T0 + 400), T0 + 500)
        self.assertEqual(management(out[0])["detectionTime"], T0 + 400)

    def test_cancelled_event_cannot_be_cancelled_again(self):
        """Clause 8.2.2 termination step 2: entry state must be ACTIVE."""
        self.originator.terminate(self.result.action_id, new_request(), T0 + 500)
        result, _ = self.originator.terminate(self.result.action_id, new_request(), T0 + 600)
        self.assertEqual(result.failure, DenFailure.UNKNOWN_ACTION_ID)


class TestRepetition(unittest.TestCase):
    """DENM repetition (clauses 6.1.2.3, 8.2.1.5)."""

    def test_repetition_at_repetition_interval(self):
        """DENM repetition (TS 103 831 clauses 6.1.2.3, 8.2.2)."""
        its = station()
        its.trigger(new_request(repetition_interval=100, repetition_duration=1000), T0)
        sent = [t for t in range(T0 + 1, T0 + 501) if its.tick(t)[0]]
        self.assertEqual(sent, [T0 + 100, T0 + 200, T0 + 300, T0 + 400, T0 + 500])

    def test_repetition_sends_latest_update(self):
        """DENM repetition (TS 103 831 clauses 6.1.2.3, 8.2.2)."""
        its = station()
        result, _ = its.trigger(new_request(repetition_interval=100, repetition_duration=1000), T0)
        new_situation = {"informationQuality": 7, "eventType": {"ccAndScc": ("accident2", 2)}}
        its.update(result.action_id, new_request(situation=new_situation), T0 + 150)
        out, _ = its.tick(T0 + 250)
        self.assertEqual(out[0].denm["denm"]["situation"], new_situation)

    def test_repetition_stops_at_validity_expiry(self):
        """DENM repetition (TS 103 831 clauses 6.1.2.3, 8.2.2)."""
        its = station()
        result, _ = its.trigger(new_request(validity_duration=1, repetition_interval=100,
                                            repetition_duration=5000), T0)
        self.assertEqual(len(its.tick(T0 + 900)[0]), 1)
        self.assertEqual(its.tick(T0 + 1000)[0], [])
        self.assertNotIn(result.action_id, its.originating)
        self.assertEqual(its.tick(T0 + 1100)[0], [])

    def test_repetition_stops_at_repetition_duration(self):
        """DENM repetition (TS 103 831 clauses 6.1.2.3, 8.2.2)."""
        its = station()
        its.trigger(new_request(repetition_interval=100, repetition_duration=250), T0)
        sent = [t for t in range(T0 + 1, T0 + 1001) if its.tick(t)[0]]
        self.assertEqual(sent, [T0 + 100, T0 + 200])

    def test_no_repetition_without_interval(self):
        """DENM repetition (TS 103 831 clauses 6.1.2.3, 8.2.2)."""
        its = station()
        its.trigger(new_request(repetition_duration=1000), T0)
        self.assertFalse(any(its.tick(t)[0] for t in range(T0 + 1, T0 + 2000, 10)))

    def test_no_repetition_without_duration(self):
        """DENM repetition (TS 103 831 clauses 6.1.2.3, 8.2.2)."""
        its = station()
        its.trigger(new_request(repetition_interval=100), T0)
        self.assertFalse(any(its.tick(t)[0] for t in range(T0 + 1, T0 + 2000, 10)))

    def test_repetition_keeps_action_id(self):
        """DENM repetition (TS 103 831 clauses 6.1.2.3, 8.2.2)."""
        its = station()
        result, _ = its.trigger(new_request(repetition_interval=100, repetition_duration=1000), T0)
        for t in (T0 + 100, T0 + 200):
            out, _ = its.tick(t)
            self.assertEqual(management(out[0])["actionId"], result.action_id.to_dict())

    def test_repetition_keeps_reference_time(self):
        """DENM repetition (TS 103 831 clauses 6.1.2.3, 8.2.2)."""
        its = station()
        _, first = its.trigger(new_request(repetition_interval=100, repetition_duration=1000), T0)
        out, _ = its.tick(T0 + 100)
        self.assertEqual(management(out[0])["referenceTime"], management(first[0])["referenceTime"])
        self.assertEqual(management(out[0])["detectionTime"], management(first[0])["detectionTime"])

    def test_repetition_stops_at_default_validity(self):
        """DENM repetition (TS 103 831 clauses 6.1.2.3, 8.2.2): 600 s default validityDuration."""
        its = station()
        result, _ = its.trigger(new_request(repetition_interval=100_000,
                                            repetition_duration=10_000_000), T0)
        its.tick(T0 + 599_999)
        self.assertIn(result.action_id, its.originating)
        its.tick(T0 + 600_000)
        self.assertNotIn(result.action_id, its.originating)

    def test_cancellation_stops_repetition_of_new_denm(self):
        """Clause 8.2.2 termination step 4: repetition timers are stopped."""
        its = station()
        result, _ = its.trigger(new_request(repetition_interval=100, repetition_duration=1000), T0)
        its.terminate(result.action_id, new_request(), T0 + 150)
        self.assertEqual(its.tick(T0 + 200)[0], [])

    def test_next_deadline(self):
        its = station()
        self.assertIsNone(its.next_deadline())
        its.trigger(new_request(repetition_interval=100, repetition_duration=1000), T0)
        self.assertEqual(its.next_deadline(), T0 + 100)


class TestReception(unittest.TestCase):
    """Receiving ITS-S operation (clause 8.4.2)."""

    def setUp(self):
        self.originator = station(7)
        self.receiver = station(9)
        self.result, out = self.originator.trigger(new_request(), T0)
        self.first = over_the_air(out[0])

    def update(self, at):
        _, out = self.originator.update(self.result.action_id, new_request(), at)
        return over_the_air(out[0])

    def test_new_action_id_is_passed_to_application(self):
        """Receiving ITS-S (TS 103 831 clause 8.4.2)."""
        outcome = self.receiver.receive(self.first, T0 + 1)
        self.assertTrue(outcome.accepted)
        self.assertEqual(outcome.state, DenmState.ACTIVE)

    def test_newer_reference_time_is_passed_to_application(self):
        """Receiving ITS-S (TS 103 831 clause 8.4.2)."""
        self.receiver.receive(self.first, T0 + 1)
        self.assertTrue(self.receiver.receive(self.update(T0 + 1000), T0 + 1001).accepted)

    def test_termination_for_unknown_action_id_is_discarded(self):
        """Receiving ITS-S (TS 103 831 clause 8.4.2): termination of an unknown actionId, IUT or other stationId."""
        _, out = self.originator.terminate(self.result.action_id, new_request(), T0 + 10)
        outcome = self.receiver.receive(over_the_air(out[0]), T0 + 11)
        self.assertFalse(outcome.accepted)
        self.assertEqual(outcome.reason, DiscardReason.UNKNOWN_TERMINATION)

    def test_older_reference_time_is_discarded(self):
        """Receiving ITS-S (TS 103 831 clause 8.4.2)."""
        self.receiver.receive(self.update(T0 + 1000), T0 + 1001)
        outcome = self.receiver.receive(self.first, T0 + 1002)
        self.assertEqual(outcome.reason, DiscardReason.OUTDATED)

    def test_older_detection_time_is_discarded(self):
        """Receiving ITS-S (TS 103 831 clause 8.4.2)."""
        _, out = self.originator.update(self.result.action_id,
                                        new_request(detection_time=T0 + 900), T0 + 1000)
        self.receiver.receive(over_the_air(out[0]), T0 + 1001)
        older = over_the_air(out[0])
        older["denm"]["management"]["detectionTime"] = T0 + 800
        older["denm"]["management"]["referenceTime"] = T0 + 2000
        outcome = self.receiver.receive(older, T0 + 2001)
        self.assertEqual(outcome.reason, DiscardReason.OUTDATED)

    def test_equal_reference_time_with_state_change_is_passed(self):
        """Receiving ITS-S (TS 103 831 clause 8.4.2): e.g. a negation keeps the latest referenceTime."""
        self.receiver.receive(self.first, T0 + 1)
        negator = station(11)
        negator.receive(self.first, T0 + 2)
        _, out = negator.terminate(self.result.action_id, new_request(detection_time=T0), T0 + 3)
        outcome = self.receiver.receive(over_the_air(out[0]), T0 + 4)
        self.assertTrue(outcome.accepted)
        self.assertEqual(outcome.state, DenmState.NEGATED)

    def test_repeated_denm_is_not_passed_again(self):
        """Clause 8.4.2 step 2.b.ii: a repetition of the stored DENM is discarded."""
        self.receiver.receive(self.first, T0 + 1)
        outcome = self.receiver.receive(self.first, T0 + 100)
        self.assertEqual(outcome.reason, DiscardReason.REPEATED)

    def test_cancellation_of_known_event_sets_state(self):
        """Clause 8.4.2: state follows the termination of the received DENM."""
        self.receiver.receive(self.first, T0 + 1)
        _, out = self.originator.terminate(self.result.action_id, new_request(), T0 + 10)
        outcome = self.receiver.receive(over_the_air(out[0]), T0 + 11)
        self.assertEqual(outcome.state, DenmState.CANCELLED)

    def test_expired_denm_is_discarded(self):
        """Clause 8.4.2 step 1: T_R_Validity in the past."""
        outcome = self.receiver.receive(self.first, T0 + 601_000)
        self.assertEqual(outcome.reason, DiscardReason.EXPIRED)

    def test_entry_removed_at_t_r_validity(self):
        """Clause 8.4.1.5: entries expire at detectionTime + validityDuration."""
        self.receiver.receive(self.first, T0 + 1)
        _, expired = self.receiver.tick(T0 + 600_000)
        self.assertEqual(expired, [self.result.action_id])
        self.assertNotIn(self.result.action_id, self.receiver.receiving)

    def test_ssp_inconsistent_new_event_is_discarded(self):
        """Receiving ITS-S (TS 103 831 clause 8.4.2)."""
        outcome = self.receiver.receive(self.first, T0 + 1, ssp_consistent=False)
        self.assertEqual(outcome.reason, DiscardReason.SSP_INCONSISTENT)
        self.assertNotIn(self.result.action_id, self.receiver.receiving)

    def test_ssp_inconsistent_update_is_discarded(self):
        """Receiving ITS-S (TS 103 831 clause 8.4.2)."""
        self.receiver.receive(self.first, T0 + 1)
        outcome = self.receiver.receive(self.update(T0 + 1000), T0 + 1001, ssp_consistent=False)
        self.assertEqual(outcome.reason, DiscardReason.SSP_INCONSISTENT)


class TestKeepAliveForwarding(unittest.TestCase):
    """Keep-Alive Forwarding (clauses 6.1.4.2, 8.3)."""

    AREA = Area(latitude=415520000, longitude=21340000, a=1000, b=0, angle=0)

    def setUp(self):
        self.originator = station(7)
        self.forwarder = station(9, kaf_enabled=True)
        self.forwarder.set_ego_position(415520000, 21340000)

    def received(self, transmission_interval=100, validity=10, **kwargs):
        result, out = self.originator.trigger(new_request(
            transmission_interval=transmission_interval, validity_duration=validity, **kwargs), T0)
        denm = over_the_air(out[0])
        self.forwarder.receive(denm, T0, area=self.AREA,
                               area_type=GeoBroadcastHST.GEOBROADCAST_CIRCLE)
        return result.action_id, denm

    def forwards(self, until):
        return [(t, out) for t in range(T0 + 1, until) for out in self.forwarder.tick(t)[0]]

    def test_forwards_when_no_denm_received_during_delay(self):
        """Keep-Alive Forwarding (TS 103 831 clause 8.3)."""
        action_id, _ = self.received()
        entry = self.forwarder.forwarding[action_id]
        sent = self.forwards(T0 + entry.forwarding_timeout + 1)
        self.assertEqual(len(sent), 1)

    def test_same_reference_time_restarts_forwarding_timer(self):
        """Keep-Alive Forwarding (TS 103 831 clause 8.3): no forward while the DENM keeps being received."""
        action_id, denm = self.received()
        timeout = self.forwarder.forwarding[action_id].forwarding_timeout
        for t in range(T0 + 100, T0 + 2000, 100):
            self.forwarder.receive(denm, t, area=self.AREA,
                                   area_type=GeoBroadcastHST.GEOBROADCAST_CIRCLE)
            self.assertEqual(self.forwarder.tick(t)[0], [])
        self.assertEqual(self.forwarder.forwarding[action_id].next_forwarding, T0 + 1900 + timeout)

    def test_forwarding_delay(self):
        """Keep-Alive Forwarding (TS 103 831 clause 8.3): 2 x transmissionInterval + [0, 150] ms, at most validityDuration."""
        action_id, _ = self.received(transmission_interval=100)
        timeout = self.forwarder.forwarding[action_id].forwarding_timeout
        self.assertGreaterEqual(timeout, 200)
        self.assertLessEqual(timeout, 350)
        capped, _ = self.received(transmission_interval=10_000, validity=5)
        self.assertEqual(self.forwarder.forwarding[capped].forwarding_timeout, 5000)

    def test_forwarded_denm_has_own_pdu_header(self):
        """Keep-Alive Forwarding (TS 103 831 clause 8.3)."""
        self.received()
        _, out = self.forwards(T0 + 400)[0]
        self.assertEqual(out.denm["header"]["stationId"], 9)

    def test_forwarded_denm_keeps_action_id_reference_time_and_containers(self):
        """Keep-Alive Forwarding (TS 103 831 clause 8.3.2): actionId, referenceTime and containers unchanged."""
        _, denm = self.received()
        _, out = self.forwards(T0 + 400)[0]
        forwarded = over_the_air(out)
        self.assertEqual(forwarded["denm"], denm["denm"])

    def test_forwarded_negation_keeps_termination(self):
        """Keep-Alive Forwarding (TS 103 831 clause 8.3)."""
        action_id, denm = self.received()
        negator = station(11)
        negator.receive(denm, T0 + 1)
        _, out = negator.terminate(action_id, new_request(transmission_interval=100,
                                                          detection_time=T0), T0 + 2)
        self.forwarder.receive(over_the_air(out[0]), T0 + 2, area=self.AREA,
                               area_type=GeoBroadcastHST.GEOBROADCAST_CIRCLE)
        _, forwarded = self.forwards(T0 + 500)[0]
        self.assertEqual(forwarded.denm["denm"]["management"]["termination"], "isNegation")

    def test_forwarding_stops_after_validity(self):
        """Keep-Alive Forwarding (TS 103 831 clause 8.3)."""
        action_id, _ = self.received(validity=1)
        sent = self.forwards(T0 + 3000)
        self.assertTrue(all(t < T0 + 1000 for t, _ in sent))
        self.assertNotIn(action_id, self.forwarder.forwarding)

    def test_forwarding_stops_outside_destination_area(self):
        """Keep-Alive Forwarding (TS 103 831 clause 8.3)."""
        self.forwarder.set_ego_position(425520000, 21340000)    # ~111 km north
        self.received()
        self.assertEqual(self.forwards(T0 + 2000), [])

    def test_no_forwarding_without_transmission_interval(self):
        """Keep-Alive Forwarding (TS 103 831 clause 8.3)."""
        action_id, _ = self.received(transmission_interval=None)
        self.assertNotIn(action_id, self.forwarder.forwarding)

    def test_older_reference_time_is_not_stored(self):
        """Clause 8.3.3 step 2.b."""
        action_id, denm = self.received()
        _, out = self.originator.update(action_id, new_request(transmission_interval=100,
                                                               validity_duration=10), T0 + 50)
        self.forwarder.receive(over_the_air(out[0]), T0 + 50, area=self.AREA,
                               area_type=GeoBroadcastHST.GEOBROADCAST_CIRCLE)
        latest = self.forwarder.forwarding[action_id].reference_time
        self.forwarder.receive(denm, T0 + 60, area=self.AREA,
                               area_type=GeoBroadcastHST.GEOBROADCAST_CIRCLE)
        self.assertEqual(self.forwarder.forwarding[action_id].reference_time, latest)

    def test_kaf_disabled_by_default(self):
        """Clause 6.1.4.2: KAF is optional."""
        receiver = station(12)
        _, out = self.originator.trigger(new_request(transmission_interval=100), T0)
        receiver.receive(over_the_air(out[0]), T0)
        self.assertEqual(receiver.forwarding, {})


class TestDestinationArea(unittest.TestCase):

    def test_circle(self):
        area = Area(latitude=415520000, longitude=21340000, a=100, b=0, angle=0)
        self.assertTrue(inside_area(area, GeoBroadcastHST.GEOBROADCAST_CIRCLE, 415520000, 21340000))
        self.assertTrue(inside_area(area, GeoBroadcastHST.GEOBROADCAST_CIRCLE, 415528000, 21340000))
        self.assertFalse(inside_area(area, GeoBroadcastHST.GEOBROADCAST_CIRCLE, 415530000, 21340000))

    def test_rotated_rectangle(self):
        # 1000 m x 10 m rectangle along the east-west axis (angle 90 degrees).
        area = Area(latitude=415520000, longitude=21340000, a=1000, b=10, angle=90)
        east_500m = 21340000 + int(500 / (111320 * 0.7485) * 1e7)
        north_500m = 415520000 + int(500 / 111195 * 1e7)
        self.assertTrue(inside_area(area, GeoBroadcastHST.GEOBROADCAST_RECT, 415520000, east_500m))
        self.assertFalse(inside_area(area, GeoBroadcastHST.GEOBROADCAST_RECT, north_500m, 21340000))


class TestDenmSsp(unittest.TestCase):
    """DENM SSP (clause 6.2.2.2, Table 10)."""

    def test_bits_of_table_10(self):
        ssp = bytes([2, 0x40, 0x00, 0x10, 0x00])      # accident(2), emergencyVehicleApproaching(95)
        self.assertTrue(ssp_permits_cause_code(ssp, 2))
        self.assertTrue(ssp_permits_cause_code(ssp, 95))
        self.assertFalse(ssp_permits_cause_code(ssp, 1))
        self.assertFalse(ssp_permits_cause_code(ssp, 99))

    def test_release_2_code_needs_version_2_ssp(self):
        version_1 = bytes([1, 0xFF, 0xFF, 0xFF])
        self.assertTrue(ssp_permits_cause_code(version_1, 99))
        self.assertFalse(ssp_permits_cause_code(version_1, 5))   # octet 4
        self.assertTrue(ssp_permits_cause_code(version_1 + bytes([0x80]), 5))

    def test_consistency_of_received_denm(self):
        denm = {"denm": {"management": {}, "situation": SITUATION}}
        self.assertEqual(cause_code_value(denm), 2)
        self.assertTrue(ssp_consistent(None, denm))
        self.assertTrue(ssp_consistent(bytes([2, 0x40, 0, 0, 0]), denm))
        self.assertFalse(ssp_consistent(bytes([2, 0x80, 0, 0, 0]), denm))
        self.assertTrue(ssp_consistent(bytes([2, 0, 0, 0, 0]), {"denm": {"management": {}}}))


if __name__ == "__main__":
    unittest.main()
