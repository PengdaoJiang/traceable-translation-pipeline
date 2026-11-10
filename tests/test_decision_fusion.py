"""Contract and failure-path tests; fixture claims are not literary judgments."""
from copy import deepcopy
import json
import unittest

from decision_lab.fusion import (
    COMPACT_RESULT_SCHEMA, DEFAULT_DIMENSIONS, FusionInputError, RESULT_SCHEMA,
    check_observation_continuity, fuse_results, parse_compact_result, parse_result,
)


def packet():
    return {"request": "Assess this proposed revision.", "scope": "local fixture only",
            "documents": [{"id": "source", "kind": "source", "text": "The two sensors recorded separate samples."},
                          {"id": "candidate", "kind": "candidate", "text": "One sensor recorded twice."}]}


def assessment(dimension="source_meaning", disposition="supported", evidence=None):
    return {"dimension": dimension, "disposition": disposition,
            "reason": "A fixture assertion; semantic truth is separately evaluated.",
            "evidence": evidence if evidence is not None else [{"document_id": "source", "quote": "two sensors"}],
            "affected_document_ids": ["candidate"], "next_action": "No additional action proposed."}


def result(disposition="supported", stop="ready", dimensions=DEFAULT_DIMENSIONS):
    return {"assessments": [assessment(d, disposition) for d in dimensions], "stop_recommendation": stop}


def compact_result(expanded=None):
    expanded = result() if expanded is None else expanded
    compact = {"evidence": [], "assessments": [], "stop_recommendation": expanded["stop_recommendation"]}
    identities = {}
    for item in expanded["assessments"]:
        entry = {key: deepcopy(value) for key, value in item.items() if key != "evidence"}
        entry["evidence_ids"] = []
        for citation in item["evidence"]:
            identity = (citation["document_id"], citation["quote"])
            if identity not in identities:
                evidence_id = "e" + str(len(identities) + 1)
                identities[identity] = evidence_id
                compact["evidence"].append(dict(citation, id=evidence_id))
            entry["evidence_ids"].append(identities[identity])
        compact["assessments"].append(entry)
    return compact


class SubspaceFusionTests(unittest.TestCase):
    def test_same_contract_and_fusion_for_full_and_partitioned_views(self):
        full = fuse_results(packet(), {"full": result()})
        parts = fuse_results(packet(), {d: result(dimensions=(d,)) for d in DEFAULT_DIMENSIONS})
        self.assertEqual(full["fused_stop_recommendation"], "ready")
        self.assertEqual(parts["fused_stop_recommendation"], "ready")
        self.assertFalse(full["formal_acceptance"])
        self.assertEqual(len(full["unique_evidence"]), 1)
        self.assertEqual(len(parts["unique_evidence"]), 1)
        self.assertEqual(RESULT_SCHEMA["properties"]["stop_recommendation"]["enum"],
                         ["ready", "revise", "need_evidence"])

    def test_parse_json_and_exact_fence_without_silent_prose_recovery(self):
        raw = json.dumps(result())
        self.assertEqual(parse_result(raw), result())
        self.assertEqual(parse_result("```json\n" + raw + "\n```"), result())
        with self.assertRaises(FusionInputError):
            parse_result("Here is JSON: " + raw)
        with self.assertRaises(FusionInputError):
            parse_result('{"assessments":[],"stop_recommendation":"ready","stop_recommendation":"revise"}')
        invalid = result()
        invalid["confidence"] = 0.99
        with self.assertRaises(FusionInputError):
            parse_result(invalid)

    def test_bad_quote_never_constrains_and_blocks_ready(self):
        raw = result()
        raw["assessments"][0]["evidence"][0]["quote"] = "sensors flew"
        fused = fuse_results(packet(), {"full": raw})
        dim = fused["dimensions"]["source_meaning"]
        self.assertEqual(dim["asserted_candidate_state_intersection"], ["acceptable", "needs_revision"])
        self.assertIn("invalid-citation", dim["unresolved"])
        self.assertEqual(fused["fused_stop_recommendation"], "need_evidence")
        self.assertTrue(fused["view_stop_checks"]["full"]["local_disagreement"])

    def test_unknown_document_and_affected_document_are_visible(self):
        raw = result()
        raw["assessments"][0]["evidence"][0]["document_id"] = "future-answer"
        raw["assessments"][1]["affected_document_ids"] = ["not-in-packet"]
        fused = fuse_results(packet(), {"full": raw})
        self.assertEqual(fused["fused_stop_recommendation"], "need_evidence")
        self.assertIn("unknown-affected-document", fused["dimensions"]["rendering"]["unresolved"])

    def test_missing_dimension_and_empty_results_block_ready(self):
        fused = fuse_results(packet(), {"source_meaning": result(dimensions=("source_meaning",))})
        self.assertEqual(fused["missing_dimensions"], ["rendering", "applicability"])
        self.assertEqual(fused["fused_stop_recommendation"], "need_evidence")
        self.assertEqual(fuse_results(packet(), {})["fused_stop_recommendation"], "need_evidence")

    def test_same_source_copies_do_not_become_independent_votes(self):
        source_packet = packet()
        source_packet["documents"].append({"id": "copy", "kind": "copied-source", "text": source_packet["documents"][0]["text"]})
        outputs = {d: result(dimensions=(d,)) for d in DEFAULT_DIMENSIONS}
        outputs["rendering"]["assessments"][0]["evidence"][0]["document_id"] = "copy"
        outputs["applicability"]["assessments"][0]["evidence"] *= 4
        fused = fuse_results(source_packet, outputs)
        self.assertEqual(len(fused["unique_source_contents"]), 1)
        self.assertEqual(len(fused["unique_evidence"]), 1)
        self.assertEqual(fused["unique_evidence"][0]["document_ids"], ["copy", "source"])
        self.assertNotIn("confidence", fused)

    def test_many_supported_votes_cannot_outvote_one_conflicting_problem(self):
        raw = result()
        raw["assessments"] += [assessment() for _ in range(20)]
        raw["assessments"].append(assessment(disposition="problem"))
        fused = fuse_results(packet(), {"full": raw})
        dim = fused["dimensions"]["source_meaning"]
        self.assertTrue(dim["conflict"])
        self.assertEqual(dim["asserted_candidate_state_intersection"], [])
        self.assertEqual(fused["fused_stop_recommendation"], "need_evidence")
        self.assertTrue(fused["requires_revision_or_review"])

    def test_unknown_or_uncited_claim_does_not_turn_into_support(self):
        for disposition, evidence in (("unknown", []), ("supported", []), ("problem", [])):
            raw = result()
            raw["assessments"][0] = assessment(disposition=disposition, evidence=evidence)
            fused = fuse_results(packet(), {"full": raw})
            self.assertEqual(fused["fused_stop_recommendation"], "need_evidence")
            self.assertEqual(fused["dimensions"]["source_meaning"]["asserted_candidate_state_intersection"],
                             ["acceptable", "needs_revision"])

    def test_problem_requires_revision_without_claiming_semantic_proof(self):
        raw = result()
        raw["assessments"][0]["disposition"] = "problem"
        fused = fuse_results(packet(), {"full": raw})
        self.assertEqual(fused["fused_stop_recommendation"], "revise")
        self.assertFalse(fused["formal_acceptance"])
        self.assertEqual(fused["dimensions"]["source_meaning"]["semantic_truth"], "unverified")

    def test_false_positive_with_exact_quote_remains_for_external_evaluation(self):
        raw = result()
        raw["assessments"][0].update(disposition="problem", reason="Unsupported claim: the sensors measure gravity.")
        fused = fuse_results(packet(), {"full": raw})
        claim = fused["dimensions"]["source_meaning"]["assessments"][0]
        self.assertEqual(claim["citation_status"], "matched")
        self.assertEqual(claim["semantic_support"], "not-established-by-citation-matching")
        self.assertEqual(claim["reason"], raw["assessments"][0]["reason"])
        self.assertNotIn("hallucination_rate", fused)

    def test_view_cannot_silently_assess_another_dimension(self):
        fused = fuse_results(packet(), {"source_meaning": result()})
        self.assertIn("outside-assigned-view", fused["dimensions"]["rendering"]["unresolved"])
        self.assertEqual(fused["fused_stop_recommendation"], "need_evidence")

    def test_explicit_caution_is_not_discarded(self):
        fused = fuse_results(packet(), {"full": result(stop="need_evidence")})
        self.assertEqual(fused["assessment_derived_stop"], "ready")
        self.assertEqual(fused["fused_stop_recommendation"], "need_evidence")
        self.assertTrue(fused["view_stop_checks"]["full"]["local_disagreement"])

    def test_packet_and_inputs_are_not_mutated(self):
        data, outputs = packet(), {"full": result()}
        before = deepcopy((data, outputs))
        fuse_results(data, outputs)
        self.assertEqual((data, outputs), before)

    def test_packet_identity_and_expected_dimensions_are_checked(self):
        data = packet()
        data["documents"].append(deepcopy(data["documents"][0]))
        with self.assertRaises(FusionInputError):
            fuse_results(data, {"full": result()})
        with self.assertRaises(FusionInputError):
            fuse_results(packet(), {"full": result()}, expected_dimensions=())

    def test_compact_schema_does_not_mutate_original_schema(self):
        original_fields = RESULT_SCHEMA["properties"]["assessments"]["items"]["properties"]
        compact_fields = COMPACT_RESULT_SCHEMA["properties"]["assessments"]["items"]["properties"]
        self.assertIn("evidence", original_fields)
        self.assertNotIn("evidence_ids", original_fields)
        self.assertIn("evidence_ids", compact_fields)
        self.assertNotIn("evidence", compact_fields)
        self.assertEqual(RESULT_SCHEMA["required"], ["assessments", "stop_recommendation"])

    def test_compact_expansion_and_fusion_are_exactly_equivalent(self):
        scenarios = [result(), result("problem", "revise"), result("unknown", "need_evidence")]
        contradictory = result()
        contradictory["assessments"].append(assessment(disposition="problem"))
        scenarios.append(contradictory)
        bad_quote = result()
        bad_quote["assessments"][0]["evidence"][0]["quote"] = "incorrect quotation"
        scenarios.append(bad_quote)
        for expanded in scenarios:
            with self.subTest(dispositions=[a["disposition"] for a in expanded["assessments"]]):
                compact = compact_result(expanded)
                normalized = parse_compact_result(compact)
                self.assertEqual(normalized, expanded)
                self.assertEqual(fuse_results(packet(), {"full": normalized}),
                                 fuse_results(packet(), {"full": expanded}))

    def test_compact_subspaces_share_schema_without_changing_verdicts(self):
        views = {d: result(dimensions=(d,)) for d in DEFAULT_DIMENSIONS}
        normalized = {view: parse_compact_result(compact_result(raw)) for view, raw in views.items()}
        self.assertEqual(fuse_results(packet(), normalized), fuse_results(packet(), views))

    def test_compact_rejects_duplicate_ids_even_when_identical(self):
        compact = compact_result()
        compact["evidence"].append(deepcopy(compact["evidence"][0]))
        with self.assertRaisesRegex(FusionInputError, "duplicate evidence id"):
            parse_compact_result(compact)

    def test_compact_rejects_dangling_ids_without_silent_removal(self):
        compact = compact_result()
        compact["assessments"][0]["evidence_ids"].append("missing")
        with self.assertRaisesRegex(FusionInputError, "unknown evidence id"):
            parse_compact_result(compact)

    def test_compact_unused_evidence_does_not_confer_support(self):
        expanded = result()
        expanded["assessments"][0]["evidence"] = []
        compact = compact_result(expanded)
        compact["evidence"].append({"id": "unused", "document_id": "future-answer", "quote": "Not consulted."})
        normalized = parse_compact_result(compact)
        self.assertEqual(normalized, expanded)
        fused = fuse_results(packet(), {"full": normalized})
        self.assertEqual(fused["fused_stop_recommendation"], "need_evidence")
        self.assertIn("no-cited-evidence", fused["dimensions"]["source_meaning"]["unresolved"])
        self.assertEqual(len(fused["unique_evidence"]), 1)

    def test_compact_preserves_conditions_and_duplicate_reference_occurrences(self):
        expanded = result()
        expanded["assessments"][0]["reason"] = "Only in this speaker's conjecture; not an objective fact or a general rule."
        expanded["assessments"][0]["evidence"] *= 2
        compact = compact_result(expanded)
        before = deepcopy(compact)
        self.assertEqual(parse_compact_result(compact), expanded)
        self.assertEqual(compact, before)

    def test_compact_rejects_unknown_fields_and_does_not_relax_v1(self):
        for path in ("top", "assessment", "evidence"):
            compact = compact_result()
            target = compact if path == "top" else compact["assessments" if path == "assessment" else "evidence"][0]
            target["extra"] = True
            with self.subTest(path=path), self.assertRaises(FusionInputError):
                parse_compact_result(compact)
        compact = compact_result()
        compact["assessments"][0]["disposition"] = "approved"
        with self.assertRaises(FusionInputError):
            parse_compact_result(compact)

    def test_compact_json_fences_and_duplicate_json_keys(self):
        compact = compact_result()
        raw = json.dumps(compact)
        self.assertEqual(parse_compact_result(raw), result())
        self.assertEqual(parse_compact_result("```json\n" + raw + "\n```"), result())
        with self.assertRaises(FusionInputError):
            parse_compact_result("Here is JSON: " + raw)
        with self.assertRaises(FusionInputError):
            parse_compact_result('{"evidence":[],"assessments":[],"stop_recommendation":"ready","stop_recommendation":"revise"}')

    def test_continuity_ready_does_not_clear_same_packet_objection(self):
        previous = result()
        previous["assessments"][0].update(disposition="problem", reason="The local quantifier is unsupported.")
        first = check_observation_continuity(packet(), fuse_results(packet(), {"full": previous}))
        current = fuse_results(packet(), {"full": result()})
        before = deepcopy((first, current))
        next_state = check_observation_continuity(packet(), current, first["observations"])
        self.assertEqual(next_state["input_fused_stop_recommendation"], "ready")
        self.assertEqual(next_state["continuity_stop_recommendation"], "need_evidence")
        self.assertFalse(next_state["research_auto_stop_allowed"])
        self.assertEqual(next_state["observations"][0]["claim"]["reason"], "The local quantifier is unsupported.")
        self.assertEqual(next_state["observations"][0]["semantic_truth"], "unverified-observation-not-a-proven-defect")
        self.assertEqual((first, current), before)

    def test_continuity_preserves_unknown_and_deduplicates_exact_copies(self):
        previous = result()
        previous["assessments"][0].update(disposition="unknown", evidence=[])
        previous["assessments"].append(deepcopy(previous["assessments"][0]))
        state = check_observation_continuity(packet(), fuse_results(packet(), {"full": previous}))
        self.assertEqual(len(state["observations"]), 1)
        ready = check_observation_continuity(packet(), fuse_results(packet(), {"full": result()}), state["observations"])
        self.assertEqual(len(ready["pending"]), 1)
        self.assertFalse(ready["research_auto_stop_allowed"])

    def test_continuity_changed_candidate_or_scope_requires_local_applicability(self):
        previous = result()
        previous["assessments"][0]["disposition"] = "problem"
        old = check_observation_continuity(packet(), fuse_results(packet(), {"full": previous}))
        for change in ("candidate", "scope", "source"):
            data = packet()
            if change == "scope":
                data["scope"] = "different local scope"
            else:
                data["documents"][1 if change == "candidate" else 0]["text"] += " New content."
            current = check_observation_continuity(data, fuse_results(data, {"full": result()}), old["observations"])
            self.assertEqual(current["observations"][0]["applicability"], "requires-local-applicability-judgment")
            self.assertEqual(current["observations"][0]["binding"], old["current_binding"])
            self.assertEqual(current["pending"][0]["reason"], "changed-packet-applicability-unresolved")
            self.assertFalse(current["research_auto_stop_allowed"])

    def test_continuity_explicit_targeted_disposition_not_ordinary_ready(self):
        previous = result()
        previous["assessments"][0]["disposition"] = "problem"
        old = check_observation_continuity(packet(), fuse_results(packet(), {"full": previous}))
        # A new reason about a different scope is not an explicit disposition.
        new = result()
        new["assessments"][0]["reason"] = "This is not a whole-book rule."
        current = fuse_results(packet(), {"full": new})
        unchanged = check_observation_continuity(packet(), current, old["observations"])
        self.assertFalse(unchanged["research_auto_stop_allowed"])
        disposition = {"observation_id": old["observations"][0]["id"],
                       "packet_sha256": old["current_binding"]["packet_sha256"],
                       "outcome": "resolved", "reason": "An explicit supplied judgment addressing this exact observation.",
                       "evidence": [{"document_id": "source", "quote": "two sensors"}]}
        resolved = check_observation_continuity(packet(), current, old["observations"], [disposition])
        self.assertTrue(resolved["research_auto_stop_allowed"])
        self.assertFalse(resolved["formal_acceptance"])
        self.assertEqual(resolved["observations"][0]["resolution"], disposition)
        self.assertIn("semantic adequacy", " ".join(resolved["limitations"]))
        data = packet()
        data["scope"] = "later changed scope"
        recheck = check_observation_continuity(data, fuse_results(data, {"full": result()}), resolved["observations"])
        self.assertFalse(recheck["research_auto_stop_allowed"])

    def test_continuity_rejects_wrong_target_binding_or_citation(self):
        previous = result()
        previous["assessments"][0]["disposition"] = "problem"
        old = check_observation_continuity(packet(), fuse_results(packet(), {"full": previous}))
        current = fuse_results(packet(), {"full": result()})
        valid = {"observation_id": old["observations"][0]["id"],
                 "packet_sha256": old["current_binding"]["packet_sha256"], "outcome": "resolved",
                 "reason": "Explicit addressed judgment.", "evidence": [{"document_id": "source", "quote": "two sensors"}]}
        for key, value in (("observation_id", "wrong"), ("packet_sha256", "wrong"), ("evidence", []),
                           ("evidence", [{"document_id": "source", "quote": "not in text"}])):
            disposition = deepcopy(valid)
            disposition[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(FusionInputError):
                check_observation_continuity(packet(), current, old["observations"], [disposition])

    def test_continuity_never_overrides_a_current_adverse_recommendation(self):
        current = fuse_results(packet(), {"full": result("problem", "revise")})
        state = check_observation_continuity(packet(), current)
        dispositions = [{"observation_id": item["id"], "packet_sha256": state["current_binding"]["packet_sha256"],
                         "outcome": "not_applicable", "reason": "A supplied explicit judgment, not asserted true by code.",
                         "evidence": [{"document_id": "source", "quote": "two sensors"}]} for item in state["observations"]]
        disposed = check_observation_continuity(packet(), current, state["observations"], dispositions)
        self.assertEqual(disposed["continuity_stop_recommendation"], "revise")
        self.assertFalse(disposed["research_auto_stop_allowed"])

    def test_continuity_rejects_tampered_inherited_resolution(self):
        previous = result()
        previous["assessments"][0]["disposition"] = "problem"
        old = check_observation_continuity(packet(), fuse_results(packet(), {"full": previous}))
        ready = fuse_results(packet(), {"full": result()})
        for malformed in (
            {"observation_id": old["observations"][0]["id"], "packet_sha256": old["current_binding"]["packet_sha256"],
             "outcome": "resolved"},
            {"observation_id": old["observations"][0]["id"], "packet_sha256": old["current_binding"]["packet_sha256"],
             "outcome": "resolved", "reason": "Claimed closure", "evidence": []},
            {"observation_id": old["observations"][0]["id"], "packet_sha256": old["current_binding"]["packet_sha256"],
             "outcome": "resolved", "reason": "Claimed closure",
             "evidence": [{"document_id": "source", "quote": "fabricated quote"}]},
        ):
            inherited = deepcopy(old["observations"])
            inherited[0]["resolution"] = malformed
            with self.subTest(resolution=malformed), self.assertRaises(FusionInputError):
                check_observation_continuity(packet(), ready, inherited)

    def test_continuity_inherits_valid_unchanged_explicit_disposition(self):
        previous = result()
        previous["assessments"][0]["disposition"] = "problem"
        old = check_observation_continuity(packet(), fuse_results(packet(), {"full": previous}))
        ready = fuse_results(packet(), {"full": result()})
        disposition = {"observation_id": old["observations"][0]["id"],
                       "packet_sha256": old["current_binding"]["packet_sha256"], "outcome": "resolved",
                       "reason": "Explicit supplied disposition of this observation.",
                       "evidence": [{"document_id": "source", "quote": "two sensors"}]}
        closed = check_observation_continuity(packet(), ready, old["observations"], [disposition])
        inherited = check_observation_continuity(packet(), ready, closed["observations"])
        self.assertTrue(inherited["research_auto_stop_allowed"])
        self.assertEqual(inherited["observations"][0]["resolution"], disposition)
        self.assertEqual(inherited["observations"], closed["observations"])
        self.assertFalse(inherited["formal_acceptance"])


if __name__ == "__main__":
    unittest.main()
