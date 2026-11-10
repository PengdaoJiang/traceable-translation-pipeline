"""Original synthetic cases for the extracted decision kernels; no model calls."""
from copy import deepcopy
import hashlib
import json

from .planning import replay_decision_case, solve_decision_case
from .fusion import DEFAULT_DIMENSIONS, check_observation_continuity, fuse_results


def planning_case():
    worlds = ["accurate", "count-error"]

    def refs(name):
        return [{"path": "synthetic/" + name, "sha256": hashlib.sha256(name.encode()).hexdigest()}]

    def evidence(name, possible=None, candidate="draft", kind="report"):
        entry = dict(id=name, kind=kind, source_group=name, claim_id=name,
                     scope="sensor-summary", source_version="source-v1", condition_version="conditions-v1",
                     candidate_id=candidate, possible_worlds=worlds[:] if possible is None else possible,
                     evidence_refs=refs(name))
        if kind == "approval":
            entry.update(record_status="accepted", task_id="/root/synthetic_reviewer")
        return entry

    def action(name, kind, outcomes, candidate="draft", requires=()):
        return dict(id=name, kind=kind, candidate_id=candidate, requires=list(requires),
                    cost=1, duration={"kind": "scenario", "seconds": 1},
                    evidence_refs=refs(name), outcomes=outcomes)

    return dict(
        schema_version=1, case_id="synthetic-sensor-summary",
        candidates=[dict(id=name, scope="sensor-summary", source_version="source-v1",
                         condition_version="conditions-v1", features={"sensor_count": value},
                         evidence_refs=refs(name)) for name, value in (("draft", "disputed"), ("revision", "corrected"))],
        worlds=[{"id": "accurate", "defects": {"draft": [], "revision": []}},
                {"id": "count-error", "defects": {"draft": ["count-mismatch"], "revision": []}}],
        defects=[{"id": "count-mismatch", "loss": 1, "evidence_refs": refs("defect")}],
        evidence=[evidence("source", candidate=None, kind="source"),
                  evidence("supported", ["accurate"]), evidence("counterexample", ["count-error"]),
                  evidence("revision-approval", candidate="revision", kind="approval")],
        initial={"candidate_id": "draft", "evidence_ids": [], "consumer_versions": {"report": "draft"}},
        actions=[
            action("read", "read", [{"id": "loaded", "possible_worlds": worlds, "add_evidence": ["source"]}]),
            action("check", "check", [
                {"id": "supported", "possible_worlds": ["accurate"], "add_evidence": ["supported"]},
                {"id": "counterexample", "possible_worlds": ["count-error"], "add_evidence": ["counterexample"]},
                {"id": "inconclusive", "possible_worlds": worlds, "no_information": True}], requires=("source",)),
            action("correct", "correct", [{"id": "revised", "possible_worlds": worlds,
                                             "candidate_id": "revision"}], requires=("counterexample",)),
            action("approval", "read", [{"id": "recorded", "possible_worlds": worlds,
                                           "add_evidence": ["revision-approval"]}], candidate="revision"),
            action("propagate", "propagate", [{"id": "copied", "possible_worlds": worlds,
                                                "propagate_to": ["report"]}], candidate="revision", requires=("revision-approval",)),
        ],
        targets={"max_loss": 0, "require_approval": True, "require_current_consumers": True},
        limits={"max_depth": 8, "max_states": 5000, "max_policies": 10000})


def run_demo():
    case = planning_case()
    observations = [{"action": action, "outcome": outcome} for action, outcome in
                    [("read", "loaded"), ("check", "counterexample"), ("correct", "revised"),
                     ("approval", "recorded"), ("propagate", "copied")]]
    replay = replay_decision_case(case, observations)
    search_case = deepcopy(case)
    search_case["actions"] = search_case["actions"][:2]
    search_case["targets"].update(require_approval=False, require_current_consumers=False)
    search = solve_decision_case(search_case)

    packet = {"request": "Review the sensor summary.", "scope": "synthetic example",
              "documents": [{"id": "source", "kind": "source", "text": "Two sensors recorded separate samples."},
                            {"id": "candidate", "kind": "candidate", "text": "One sensor recorded twice."}]}
    ready = {"assessments": [{"dimension": d, "disposition": "supported",
                              "reason": "A synthetic later response omits the prior objection.",
                              "evidence": [{"document_id": "source", "quote": "Two sensors"}],
                              "affected_document_ids": ["candidate"], "next_action": "None proposed."}
                             for d in DEFAULT_DIMENSIONS], "stop_recommendation": "ready"}
    prior = deepcopy(ready)
    prior["assessments"][0].update(disposition="problem", reason="The candidate changes the number of sensors.",
                                   next_action="Check the count against the source and revise.")
    prior["stop_recommendation"] = "revise"
    first = check_observation_continuity(packet, fuse_results(packet, {"full": prior}))
    current = fuse_results(packet, {"full": ready})
    continuity = check_observation_continuity(packet, current, first["observations"])
    assert replay["final_state"]["stop_allowed"]
    assert not replay["trace"][2]["state"]["stop_allowed"]
    assert search["search"]["complete"]
    assert not continuity["research_auto_stop_allowed"]
    return {"fixture": "original synthetic data; no model calls or historical approvals",
            "planning": {"search": search["search"], "policy_frontier": search["policy_frontier"]},
            "replay": replay, "continuity": continuity}


if __name__ == "__main__":
    print(json.dumps(run_demo(), ensure_ascii=False, indent=2))
