"""Offline finite-world counterexamples, never literary acceptance fixtures."""
from copy import deepcopy
import unittest

from decision_lab.planning import (
    DecisionModelError, decision_action_inputs, replay_decision_case, solve_decision_case,
)


WORLDS = ["faithful", "defect"]


def refs(name):
    return [{"path": "fixture/" + name + ".json", "sha256": "A" * 64}]


def evidence(name, worlds=None, candidate="a", kind="report", group=None):
    entry = {"id": name, "kind": kind, "source_group": group or name, "claim_id": name,
             "scope": "paragraph-1", "source_version": "source-1", "condition_version": "conditions-1",
             "candidate_id": candidate, "possible_worlds": WORLDS[:] if worlds is None else worlds,
             "evidence_refs": refs(name)}
    if kind == "approval":
        entry.update(record_status="accepted", task_id="/root/fixture_adjudicator")
    return entry


def action(name, kind="read", candidate="a", requires=(), outcomes=None, seconds=1):
    return {"id": name, "kind": kind, "candidate_id": candidate, "requires": list(requires),
            "outcomes": outcomes or [{"id": "done", "possible_worlds": WORLDS[:]}],
            "cost": 1, "duration": {"kind": "scenario", "seconds": seconds}, "evidence_refs": refs("action-" + name)}


def case_fixture():
    return {"schema_version": 1, "case_id": "offline-only",
            "candidates": [{"id": name, "scope": "paragraph-1", "source_version": "source-1",
                            "condition_version": "conditions-1", "features": {"agency": feature},
                            "evidence_refs": refs("candidate-" + name)}
                           for name, feature in (("a", "disputed"), ("b", "corrected"))],
            "worlds": [{"id": "faithful", "defects": {"a": [], "b": []}},
                       {"id": "defect", "defects": {"a": ["wrong-agency"], "b": []}}],
            "defects": [{"id": "wrong-agency", "loss": 1, "evidence_refs": refs("defect-definition")}],
            "evidence": [evidence("source", candidate=None, kind="source"),
                         evidence("good", ["faithful"], group="review"),
                         evidence("bad", ["defect"], group="review"),
                         evidence("old-A", kind="approval"), evidence("new-A", candidate="b", kind="approval")],
            "initial": {"candidate_id": "a", "evidence_ids": [], "consumer_versions": {"pilot": "a"}},
            "actions": [
                action("read-source", outcomes=[{"id": "read", "possible_worlds": WORLDS[:], "add_evidence": ["source"]}]),
                action("review", "check", requires=("source",), outcomes=[
                    {"id": "supported", "possible_worlds": ["faithful"], "add_evidence": ["good"]},
                    {"id": "counterexample", "possible_worlds": ["defect"], "add_evidence": ["bad"]},
                    {"id": "miss-or-fail", "possible_worlds": WORLDS[:], "no_information": True}]),
                action("correct", "correct", requires=("bad",), outcomes=[
                    {"id": "revised", "possible_worlds": WORLDS[:], "candidate_id": "b"}]),
                action("read-new-A", candidate="b", outcomes=[
                    {"id": "record", "possible_worlds": WORLDS[:], "add_evidence": ["new-A"]}]),
                action("sync", "propagate", candidate="b", requires=("new-A",), outcomes=[
                    {"id": "copied", "possible_worlds": WORLDS[:], "propagate_to": ["pilot"]}]),
            ],
            "targets": {"max_loss": 0, "require_approval": False, "require_current_consumers": False},
            "limits": {"max_depth": 8, "max_states": 5000, "max_policies": 10000}}


class DecisionModelTests(unittest.TestCase):
    def test_counterexample_increases_lower_risk_without_votes_or_probability(self):
        case = case_fixture()
        report = replay_decision_case(case, [{"action": "read-source", "outcome": "read"},
                                             {"action_id": "review", "outcome_id": "counterexample"}])
        self.assertEqual(report["initial_state"]["risk"]["lower_loss"], 0)
        self.assertEqual(report["final_state"]["risk"]["lower_loss"], 1)
        self.assertEqual(report["final_state"]["risk"]["certain_defects"], ["wrong-agency"])
        self.assertEqual(report["trace"][1]["world_count_reduction"], 1)
        self.assertFalse(report["final_state"]["stop_allowed"])
        self.assertEqual(report["final_state"]["risk"]["overall_literary_error_rate"], "unknown")

    def test_same_source_copy_does_not_add_confidence_or_a_new_group(self):
        case = case_fixture()
        duplicate = deepcopy(case["evidence"][1])
        duplicate.update(id="copy", evidence_refs=refs("copy"))
        case["evidence"].append(duplicate)
        case["initial"]["evidence_ids"] = ["good"]
        case["actions"].append(action("read-copy", outcomes=[
            {"id": "copy", "possible_worlds": ["faithful"], "add_evidence": ["copy"]},
            {"id": "unavailable", "possible_worlds": WORLDS[:], "no_information": True}]))
        result = replay_decision_case(case, [{"action": "read-copy", "outcome": "copy"}])
        self.assertEqual(result["trace"][0]["world_count_reduction"], 0)
        self.assertEqual(result["trace"][0]["new_distinct_source_groups"], [])
        self.assertEqual(result["final_state"]["risk"], result["initial_state"]["risk"])
        duplicate["possible_worlds"] = WORLDS[:]
        with self.assertRaisesRegex(DecisionModelError, "same-source copies disagree"):
            solve_decision_case(case)

    def test_revocation_reopens_worlds_and_retracts_the_actual_observation_support(self):
        case = case_fixture()
        case["actions"].append(action("withdraw", requires=("good",), outcomes=[
            {"id": "withdrawn", "possible_worlds": WORLDS[:], "revoke_evidence": ["good"]}]))
        report = replay_decision_case(case, [
            {"action": "read-source", "outcome": "read"}, {"action": "review", "outcome": "supported"},
            {"action": "withdraw", "outcome": "withdrawn"}])
        self.assertEqual(report["trace"][1]["state"]["possible_world_count"], 1)
        self.assertEqual(report["final_state"]["possible_world_count"], 2)
        self.assertEqual(report["final_state"]["risk"]["upper_loss"], 1)
        self.assertIn("good", report["final_state"]["received_evidence_ids"])
        self.assertNotIn("good", report["final_state"]["active_evidence_ids"])
        self.assertEqual(len(report["final_state"]["observation_history"]), 3)

    def test_counterevidence_can_revoke_a_false_support_before_applicability_test(self):
        case = case_fixture()
        case["initial"]["evidence_ids"] = ["good"]
        case["actions"].append(action("counter", outcomes=[
            {"id": "found", "possible_worlds": ["defect"], "add_evidence": ["bad"], "revoke_evidence": ["good"]},
            {"id": "no-information", "possible_worlds": WORLDS[:], "no_information": True}]))
        report = replay_decision_case(case, [{"action": "counter", "outcome": "found"}])
        self.assertEqual(report["initial_state"]["risk"]["upper_loss"], 0)
        self.assertEqual(report["final_state"]["risk"]["lower_loss"], 1)

    def test_rereading_revoked_approval_cannot_restore_stopping_authority(self):
        case = case_fixture()
        case["initial"].update(candidate_id="b", evidence_ids=["new-A"], consumer_versions={"pilot": "b"})
        case["targets"].update(require_approval=True, require_current_consumers=True)
        case["actions"].append(action("revoke-A", candidate="b", outcomes=[
            {"id": "withdrawn", "possible_worlds": WORLDS[:], "revoke_evidence": ["new-A"]}]))
        report = replay_decision_case(case, [{"action": "revoke-A", "outcome": "withdrawn"},
                                             {"action": "read-new-A", "outcome": "record"}])
        self.assertTrue(report["initial_state"]["stop_allowed"])
        self.assertFalse(report["trace"][0]["state"]["stop_allowed"])
        self.assertFalse(report["final_state"]["stop_allowed"])
        self.assertEqual(report["final_state"]["matched_approval_ids"], [])
        self.assertEqual(report["final_state"]["revoked_evidence_ids"], ["new-A"])

    def test_revocation_covers_same_claim_copies_and_their_later_reads(self):
        case = case_fixture()
        duplicate = deepcopy(case["evidence"][1])
        duplicate.update(id="copy", evidence_refs=refs("copy"))
        case["evidence"].append(duplicate)
        case["targets"]["require_approval"] = True
        case["actions"].extend([
            action("withdraw", outcomes=[
                {"id": "withdrawn", "possible_worlds": WORLDS[:], "revoke_evidence": ["good"]}]),
            action("read-copy", outcomes=[
                {"id": "copy", "possible_worlds": ["faithful"], "add_evidence": ["copy"]},
                {"id": "unavailable", "possible_worlds": WORLDS[:], "no_information": True}]),
            action("counter", outcomes=[
                {"id": "found", "possible_worlds": ["defect"], "add_evidence": ["bad"], "revoke_evidence": ["good"]},
                {"id": "unavailable", "possible_worlds": WORLDS[:], "no_information": True}]),
        ])
        for received in (["good", "copy", "old-A"], ["good", "old-A"]):
            with self.subTest(received=received):
                case["initial"]["evidence_ids"] = received
                report = replay_decision_case(case, [{"action": "withdraw", "outcome": "withdrawn"},
                                                     {"action": "read-copy", "outcome": "copy"}])
                self.assertTrue(report["initial_state"]["stop_allowed"])
                self.assertEqual(report["final_state"]["possible_world_count"], 2)
                self.assertEqual(report["final_state"]["active_evidence_ids"], ["old-A"])
                self.assertEqual(report["final_state"]["revoked_evidence_ids"], ["copy", "good"])
                self.assertFalse(report["final_state"]["stop_allowed"])
        case["initial"]["evidence_ids"] = ["good", "copy", "old-A"]
        counter = replay_decision_case(case, [{"action": "counter", "outcome": "found"}])
        self.assertEqual(counter["final_state"]["possible_worlds"], ["defect"])
        self.assertEqual(counter["final_state"]["active_evidence_ids"], ["bad", "old-A"])

    def test_empty_intersection_is_conflict_not_zero_risk(self):
        case = case_fixture()
        case["initial"]["evidence_ids"] = ["good", "bad"]
        state = replay_decision_case(case, [])["final_state"]
        self.assertTrue(state["risk"]["inconsistent_evidence"])
        self.assertIsNone(state["risk"]["upper_loss"])
        self.assertIsNone(state["risk"]["lower_loss"])
        self.assertFalse(state["stop_allowed"])

    def test_approval_is_authority_not_a_semantic_risk_reduction(self):
        case = case_fixture()
        case["initial"]["evidence_ids"] = ["old-A"]
        state = replay_decision_case(case, [])["final_state"]
        self.assertEqual(state["matched_approval_ids"], ["old-A"])
        self.assertEqual(state["risk"]["upper_loss"], 1)
        case["evidence"][3]["possible_worlds"] = ["faithful"]
        with self.assertRaisesRegex(DecisionModelError, "approval is responsibility"):
            solve_decision_case(case)
        case = case_fixture()
        case["actions"].append(action("A", outcomes=[
            {"id": "approved", "possible_worlds": ["faithful"], "add_evidence": ["old-A"]},
            {"id": "missing", "possible_worlds": WORLDS[:]}]))
        with self.assertRaisesRegex(DecisionModelError, "approval response cannot"):
            solve_decision_case(case)

    def test_revision_changes_features_and_requires_new_approval_and_propagation(self):
        case = case_fixture()
        case["initial"]["evidence_ids"] = ["old-A"]
        case["targets"].update(require_approval=True, require_current_consumers=True)
        history = [{"action": "read-source", "outcome": "read"},
                   {"action": "review", "outcome": "counterexample"},
                   {"action": "correct", "outcome": "revised"}]
        corrected = replay_decision_case(case, history)
        state = corrected["final_state"]
        self.assertEqual(state["features"], {"agency": "corrected"})
        self.assertEqual(corrected["trace"][-1]["feature_updates"]["agency"]["before"], "disputed")
        self.assertEqual(state["matched_approval_ids"], [])
        self.assertIn("no-exact-current-approval", state["stop_blockers"])
        self.assertIn("consumers-not-current", state["stop_blockers"])
        history += [{"action": "read-new-A", "outcome": "record"}, {"action": "sync", "outcome": "copied"}]
        final = replay_decision_case(case, history)["final_state"]
        self.assertTrue(final["stop_allowed"])
        self.assertEqual(final["consumer_versions"], {"pilot": "b"})
        self.assertFalse(final["formal_acceptance"])

    def test_wrong_scope_or_condition_evidence_cannot_clear_risk(self):
        for field in ("scope", "source_version", "condition_version", "candidate_id"):
            with self.subTest(field=field):
                case = case_fixture()
                case["evidence"][1][field] = "b" if field == "candidate_id" else "other"
                case["initial"]["evidence_ids"] = ["good"]
                # Remove informative actions whose assertions no longer match.
                case["actions"] = []
                state = replay_decision_case(case, [])["final_state"]
                self.assertEqual(state["active_evidence_ids"], [])
                self.assertEqual(state["risk"]["upper_loss"], 1)

    def test_threshold_or_loss_unknown_prevents_a_claimed_stop(self):
        case = case_fixture()
        case["targets"]["max_loss"] = None
        case["initial"]["evidence_ids"] = ["good"]
        self.assertIn("threshold-unspecified", replay_decision_case(case, [])["final_state"]["stop_blockers"])
        case["targets"]["max_loss"] = 0
        case["initial"]["evidence_ids"] = []
        case["defects"][0]["loss"] = None
        state = replay_decision_case(case, [])["final_state"]
        self.assertIsNone(state["risk"]["upper_loss"])
        self.assertFalse(state["stop_allowed"])

    def test_exact_and_or_search_finds_a_useful_two_action_combination(self):
        case = case_fixture()
        case["actions"] = case["actions"][:2]
        before = deepcopy(case)
        result = solve_decision_case(case)
        self.assertEqual(case, before)
        self.assertTrue(result["search"]["complete"])
        useful = [p for p in result["policy_frontier"] if p["can_stop_in_some_outcome"]]
        self.assertTrue(useful)
        policy = useful[0]["policy"]
        self.assertEqual(policy["action_id"], "read-source")
        next_step = policy["outcomes"]["read"]
        self.assertEqual(next_step["action_id"], "review")
        self.assertEqual(next_step["outcomes"]["supported"]["terminal"], "stop")
        self.assertEqual(next_step["outcomes"]["counterexample"]["terminal"], "defer")
        self.assertEqual(next_step["outcomes"]["miss-or-fail"]["terminal"], "defer")
        self.assertFalse(useful[0]["guaranteed_stop"])
        self.assertTrue(any(p["policy"].get("terminal") == "defer" for p in result["policy_frontier"]))

    def test_future_model_response_needs_a_noninformative_failure_branch(self):
        case = case_fixture()
        case["actions"][1]["outcomes"].pop()
        with self.assertRaisesRegex(DecisionModelError, "no-information/failure branch"):
            solve_decision_case(case)
        case = case_fixture()
        case["actions"][1]["outcomes"][-1]["candidate_id"] = "b"
        with self.assertRaises(DecisionModelError):
            solve_decision_case(case)

    def test_unknown_duration_is_not_zero_and_cutoff_is_not_optimality(self):
        case = case_fixture()
        case["actions"] = case["actions"][:2]
        case["actions"][1]["duration"] = {"kind": "unknown"}
        result = solve_decision_case(case)
        plan = next(p for p in result["policy_frontier"] if p["can_stop_in_some_outcome"])
        self.assertIsNone(plan["duration"]["seconds"])
        self.assertTrue(any("review" in p["unknown_actions"] for p in plan["duration"]["max_of_paths"]))
        case["limits"]["max_depth"] = 1
        limited = solve_decision_case(case)
        self.assertFalse(limited["search"]["complete"])
        self.assertEqual(limited["frontier_kind"], "partial-search")

    def test_inputs_do_not_read_future_evidence_and_replay_state_is_reusable(self):
        case = case_fixture()
        state = replay_decision_case(case, [{"action": "read-source", "outcome": "read"}])["final_state"]
        inputs = decision_action_inputs(case, state, "review")
        self.assertEqual(inputs["evidence_ids"], ["source"])
        self.assertIn(refs("source")[0], inputs["required_evidence_refs"])
        self.assertEqual(inputs["action_refs"], refs("action-review"))
        self.assertNotIn(refs("bad")[0], inputs["refs"])
        self.assertNotIn(refs("new-A")[0], inputs["refs"])
        result = replay_decision_case(case, [{"action": "read-source", "outcome": "read"},
                                            {"action": "review", "outcome": "counterexample"}])
        self.assertEqual(result["trace"][-1]["consumed_evidence_ids"], ["source"])
        self.assertIn(refs("bad")[0], decision_action_inputs(case, result["final_state"], "correct")["refs"])

    def test_future_check_cannot_smuggle_its_unreceived_report_as_action_input(self):
        case = case_fixture()
        case["initial"]["evidence_ids"] = ["source"]
        case["actions"][1]["evidence_refs"] = refs("bad")
        state = replay_decision_case(case, [])["final_state"]
        with self.assertRaisesRegex(DecisionModelError, "unreceived outcome"):
            decision_action_inputs(case, state, "review")
        with self.assertRaisesRegex(DecisionModelError, "unreceived outcome"):
            replay_decision_case(case, [{"action": "review", "outcome": "counterexample"}])
        # An archive read is allowed to name the document it is about to read.
        case["actions"][1]["kind"] = "read"
        self.assertIn(refs("bad")[0], decision_action_inputs(case, state, "review")["action_refs"])
        # A later check may consume exactly that already received support.
        case["actions"][1]["kind"] = "check"
        case["initial"]["evidence_ids"] = ["source", "bad"]
        state = replay_decision_case(case, [])["final_state"]
        self.assertIn(refs("bad")[0], decision_action_inputs(case, state, "review")["context_refs"])

    def test_input_bytes_is_a_separate_frontier_objective_not_work_or_delay(self):
        case = case_fixture()
        case["initial"]["evidence_ids"] = ["source"]
        heavy, lean = deepcopy(case["actions"][1]), deepcopy(case["actions"][1])
        heavy.update(id="heavy", cost=1, evidence_refs=[dict(refs("heavy")[0], bytes=100)])
        lean.update(id="lean", cost=2, evidence_refs=[dict(refs("lean")[0], bytes=10)])
        case["actions"] = [heavy, lean]
        for rows in (case["candidates"], case["evidence"], case["defects"]):
            for row in rows:
                for ref in row["evidence_refs"]:
                    ref["bytes"] = 5
        result = solve_decision_case(case)
        plans = {p["policy"].get("action_id"): p for p in result["policy_frontier"]}
        self.assertEqual(plans["heavy"]["input_bytes"]["bytes"], 110)
        self.assertEqual(plans["lean"]["input_bytes"]["bytes"], 20)
        self.assertEqual(plans["heavy"]["worst_action_cost"], 1)
        self.assertEqual(plans["lean"]["worst_action_cost"], 2)
        self.assertEqual(plans["heavy"]["duration"], plans["lean"]["duration"])

    def test_unknown_reference_bytes_count_each_receiver_not_just_unique_files(self):
        case = case_fixture()
        case["actions"] = case["actions"][:2]
        for candidate in case["candidates"]:
            candidate["evidence_refs"][0]["bytes"] = 0
        shared = refs("shared-unknown")
        case["evidence"][0]["evidence_refs"] = deepcopy(shared)
        case["actions"][0]["evidence_refs"] = deepcopy(shared)
        case["actions"][1]["evidence_refs"] = deepcopy(shared)
        result = solve_decision_case(case)
        plan = next(p for p in result["policy_frontier"] if p["can_stop_in_some_outcome"])
        self.assertIsNone(plan["input_bytes"]["bytes"])
        terms = plan["input_bytes"]["max_of_paths"]
        self.assertEqual(len(terms), 1)
        self.assertEqual(terms[0]["unknown_refs"], [dict(shared[0], reads=2)])
        report = replay_decision_case(case, [{"action": "read-source", "outcome": "read"},
                                             {"action": "review", "outcome": "supported"}])
        self.assertEqual([row["input_bytes"]["max_of_paths"][0]["unknown_refs"][0]["reads"]
                          for row in report["trace"]], [1, 1])

    def test_future_oracle_is_not_an_input_to_planning(self):
        for field in ("actual_world", "expected_final", "observations", "first_discoverer"):
            case = case_fixture()
            case["validation"] = {field: "hidden"}
            with self.assertRaisesRegex(DecisionModelError, "oracle/outcomes"):
                solve_decision_case(case)

    def test_zero_risk_stop_prunes_remaining_work_but_not_positive_tolerated_risk(self):
        case = case_fixture()
        case["initial"]["evidence_ids"] = ["good"]
        case["actions"] = [action("unneeded", kind="wait")]
        case["actions"][0]["duration"] = {"kind": "unknown"}
        result = solve_decision_case(case)
        self.assertTrue(result["search"]["complete"])
        self.assertEqual(result["search"]["states"], 1)
        self.assertEqual(len(result["policy_frontier"]), 1)
        self.assertEqual(result["policy_frontier"][0]["policy"]["terminal"], "stop")

        # Stopping is allowed at loss 1, but a declared correction can still
        # lower that risk, so positive-risk stop must not prune the choice.
        case["initial"]["evidence_ids"] = []
        case["targets"]["max_loss"] = 1
        case["actions"] = [action("correct-now", kind="correct", outcomes=[
            {"id": "revised", "possible_worlds": WORLDS[:], "candidate_id": "b"}])]
        result = solve_decision_case(case)
        corrected = next(p for p in result["policy_frontier"]
                         if p["policy"].get("action_id") == "correct-now")
        self.assertEqual(corrected["worst_modeled_loss"], 0)
        self.assertEqual(corrected["worst_action_cost"], 1)
        self.assertEqual(corrected["duration"]["seconds"], 1)


if __name__ == "__main__":
    unittest.main()
