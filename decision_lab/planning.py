"""Finite, set-valued editorial decision research; no models, files or acceptance.

Worlds are explicitly declared hypotheses, not a distribution or an exhaustive
account of literary error. Evidence references and response envelopes must be
verified by the adapter. Same-source copies are not independent observations.
Planning never receives the actual historical outcome sequence; replay does.
"""
from __future__ import annotations

from copy import deepcopy
from fractions import Fraction
from functools import lru_cache
from itertools import product
import json
import math
import re


class DecisionModelError(ValueError):
    pass


def _need(value, message):
    if not value:
        raise DecisionModelError(message)


def _rows(value, label):
    _need(isinstance(value, list), label + " must be a list")
    result = {}
    for row in value:
        _need(isinstance(row, dict) and isinstance(row.get("id"), str) and row["id"]
              and row["id"] not in result, "invalid/duplicate " + label)
        result[row["id"]] = row
    return result


def _names(value, known, label):
    _need(isinstance(value, list) and all(isinstance(x, str) for x in value)
          and len(value) == len(set(value)) and set(value) <= set(known), "invalid " + label)
    return set(value)


def _number(value, label):
    _need(type(value) in (int, float) and math.isfinite(value) and value >= 0,
          label + " must be a finite nonnegative number")
    return Fraction(str(value))


def _refs(value, label):
    _need(isinstance(value, list) and value and all(isinstance(r, dict)
          and isinstance(r.get("path"), str) and r["path"]
          and isinstance(r.get("sha256"), str) and re.fullmatch(r"[a-fA-F0-9]{64}", r["sha256"])
          for r in value), label + " needs exact record references")
    _need(all("bytes" not in r or (type(r["bytes"]) is int and r["bytes"] >= 0) for r in value),
          label + " reference bytes must be a nonnegative integer when known")


def _ref_key(ref):
    return ref["path"], ref["sha256"].upper()


def _unique_refs(refs):
    result = {}
    for ref in refs:
        key = _ref_key(ref)
        if key not in result:
            result[key] = deepcopy(ref)
        elif "bytes" in ref:
            _need("bytes" not in result[key] or result[key]["bytes"] == ref["bytes"],
                  "same exact reference has inconsistent byte sizes")
            result[key]["bytes"] = ref["bytes"]
    return list(result.values())


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _no_oracle(value):
    if isinstance(value, dict):
        _need(not {"actual_world", "oracle_world", "reference_answer", "expected_final", "observations", "first_discoverer"} & value.keys(),
              "historical oracle/outcomes must be supplied to replay, not planning")
        for child in value.values():
            _no_oracle(child)
    elif isinstance(value, list):
        for child in value:
            _no_oracle(child)


def _max_time(expressions):
    result = {}
    for expression in expressions:
        for variables, constant in expression.items():
            result[variables] = max(constant, result.get(variables, constant))
    return result or {frozenset(): Fraction(0)}


def _time_json(expression):
    return {"seconds": None if any(expression) else float(max(expression.values())),
            "known_lower_bound_seconds": float(max(expression.values())),
            "max_of_paths": [{"known_seconds": float(v), "unknown_actions": sorted(k)}
                             for k, v in sorted(expression.items(), key=lambda x: (sorted(x[0]), x[1]))]}


def _time_leq(left, right):
    return all(any(a <= b and x <= y for b, y in right.items()) for a, x in left.items())


def _add_input_bytes(expression, refs):
    known = sum(ref.get("bytes", 0) for ref in refs)
    missing = [_ref_key(ref) for ref in refs if "bytes" not in ref]
    result = {}
    for coefficients, constant in expression.items():
        counts = {(path, sha): n for path, sha, n in coefficients}
        for key in missing:
            counts[key] = counts.get(key, 0) + 1
        key = tuple(sorted((path, sha, n) for (path, sha), n in counts.items()))
        result[key] = constant + known
    return result


def _bytes_leq(left, right):
    return all(any(x <= y and all(n <= {(p, h): m for p, h, m in b}.get((path, sha), 0)
                                 for path, sha, n in a) for b, y in right.items())
               for a, x in left.items())


def _bytes_json(expression):
    return {"bytes": None if any(expression) else max(expression.values()),
            "known_lower_bound_bytes": max(expression.values()),
            "max_of_paths": [{"known_bytes": value,
                              "unknown_refs": [{"path": path, "sha256": sha, "reads": n} for path, sha, n in key]}
                             for key, value in sorted(expression.items())]}


class _Model:
    def __init__(self, case):
        _need(isinstance(case, dict) and case.get("schema_version") == 1, "unsupported decision schema")
        _no_oracle(case)
        self.case = case
        self.candidates = _rows(case.get("candidates"), "candidates")
        self.worlds = _rows(case.get("worlds"), "worlds")
        self.defects = _rows(case.get("defects", []), "defects")
        self.evidence = _rows(case.get("evidence", []), "evidence")
        self.actions = _rows(case.get("actions", []), "actions")
        _need(self.candidates and self.worlds, "finite candidates and worlds required")
        for candidate in self.candidates.values():
            _need(all(isinstance(candidate.get(k), str) and candidate[k]
                      for k in ("scope", "source_version", "condition_version"))
                  and isinstance(candidate.get("features"), dict), "candidate needs exact context and features")
            if "evidence_refs" in candidate:
                _refs(candidate["evidence_refs"], "candidate")
        for defect in self.defects.values():
            if defect.get("loss") is not None:
                _number(defect["loss"], "declared defect loss")
            _refs(defect.get("evidence_refs"), "defect")
        for world in self.worlds.values():
            _need(isinstance(world.get("defects"), dict) and set(world["defects"]) == set(self.candidates),
                  "every world must explicitly cover every candidate")
            for items in world["defects"].values():
                _names(items, self.defects, "world defect set")
        groups, self.claim_keys = {}, {}
        for entry in self.evidence.values():
            _need(entry.get("kind") in {"source", "report", "approval"}
                  and all(isinstance(entry.get(k), str) and entry[k]
                          for k in ("source_group", "scope", "source_version", "condition_version")),
                  "evidence needs kind, source group and exact scope/version")
            _need(entry.get("candidate_id") is None or entry["candidate_id"] in self.candidates,
                  "evidence has unknown candidate")
            _need(_names(entry.get("possible_worlds"), self.worlds, "evidence worlds"), "evidence world set cannot be empty")
            _refs(entry.get("evidence_refs"), "evidence")
            if entry["kind"] == "approval":
                _need(entry.get("candidate_id") is not None and entry.get("record_status") == "accepted"
                      and isinstance(entry.get("task_id"), str)
                      and (re.fullmatch(r"[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}", entry["task_id"])
                           or re.fullmatch(r"/root(?:/[A-Za-z0-9_-]+)*", entry["task_id"])),
                      "approval needs an exact accepted record and actual adjudicator identity")
                _need(set(entry["possible_worlds"]) == set(self.worlds), "approval is responsibility, not evidence reducing semantic risk")
            key = tuple(entry.get(k) for k in ("source_group", "claim_id", "kind", "scope", "source_version", "condition_version", "candidate_id"))
            worlds = frozenset(entry["possible_worlds"])
            _need(key not in groups or groups[key] == worlds, "same-source copies disagree; declare distinct claims, not independent votes")
            groups[key] = worlds
            self.claim_keys[entry["id"]] = key
        self.outcomes = {}
        for name, action in self.actions.items():
            _need(action.get("kind") in {"read", "check", "correct", "propagate", "wait"}
                  and action.get("candidate_id") in self.candidates, "invalid action or exact prestate candidate")
            _names(action.get("requires", []), self.evidence, "required evidence")
            _number(action.get("cost"), "action cost")
            _refs(action.get("evidence_refs"), "action")
            duration = action.get("duration")
            _need(isinstance(duration, dict) and duration.get("kind") in {"observed", "scenario", "unknown"}, "action needs duration classification")
            if duration["kind"] == "unknown":
                _need("seconds" not in duration, "unknown duration is not zero")
            else:
                _number(duration.get("seconds"), "action duration")
            outcomes = _rows(action.get("outcomes"), "outcomes")
            _need(outcomes, "action needs explicit response branches")
            coverage = set()
            for outcome in outcomes.values():
                worlds = _names(outcome.get("possible_worlds"), self.worlds, "outcome worlds")
                _need(worlds, "outcome world set cannot be empty")
                coverage.update(worlds)
                additions = _names(outcome.get("add_evidence", []), self.evidence, "added evidence")
                _names(outcome.get("revoke_evidence", []), self.evidence, "revoked evidence")
                after = outcome.get("candidate_id", action["candidate_id"])
                _need(after in self.candidates and (after == action["candidate_id"] or action["kind"] == "correct"),
                      "only correct can change the exact candidate")
                if outcome.get("propagate_to"):
                    _need(action["kind"] == "propagate", "only propagate changes consumer versions")
                for evidence_id in additions:
                    entry = self.evidence[evidence_id]
                    if self.matches(entry, after):
                        _need(worlds <= set(entry["possible_worlds"]), "response envelope contradicts its own added evidence")
                if any(self.evidence[e]["kind"] == "approval" for e in additions):
                    _need(worlds == set(self.worlds), "approval response cannot secretly narrow semantic risk")
                if worlds != set(self.worlds):
                    supports = [set(self.evidence[e]["possible_worlds"]) for e in additions
                                if self.matches(self.evidence[e], after) and self.evidence[e]["kind"] != "approval"]
                    _need(supports and set.intersection(*supports) == worlds,
                          "informative response needs scoped evidence for its complete world constraint")
                if outcome.get("no_information"):
                    _need(worlds == set(self.worlds) and after == action["candidate_id"]
                          and not outcome.get("revoke_evidence") and not outcome.get("propagate_to")
                          and all(set(self.evidence[e]["possible_worlds"]) == set(self.worlds)
                                  and self.evidence[e]["kind"] != "approval" for e in additions),
                          "no-information branch must not secretly resolve uncertainty or approve")
            _need(coverage == set(self.worlds), "response model omits possible worlds")
            if action["kind"] == "check":
                _need(any(o.get("no_information") is True for o in outcomes.values()),
                      "unobserved model check needs a no-information/failure branch")
            self.outcomes[name] = outcomes
        targets = case.get("targets", {})
        _need(isinstance(targets, dict) and "max_loss" in targets
              and type(targets.get("require_approval")) is bool
              and type(targets.get("require_current_consumers")) is bool, "explicit research stopping targets required")
        if targets["max_loss"] is not None:
            _number(targets["max_loss"], "loss threshold")
        self.targets = targets
        self.limits = {"max_depth": 8, "max_states": 5000, "max_policies": 10000}
        supplied = case.get("limits", {})
        _need(isinstance(supplied, dict) and set(supplied) <= self.limits.keys(), "unknown finite-search limit")
        self.limits.update(supplied)
        _need(all(type(v) is int and v > 0 for v in self.limits.values()) and self.limits["max_depth"] <= 12,
              "invalid finite-search limit")
        initial = case.get("initial", {})
        _need(initial.get("candidate_id") in self.candidates, "unknown initial candidate")
        ids = _names(initial.get("evidence_ids", []), self.evidence, "initial evidence")
        consumers = initial.get("consumer_versions", {})
        _need(isinstance(consumers, dict) and all(isinstance(k, str) and k and v in self.candidates for k, v in consumers.items()), "invalid initial consumer versions")
        for outcomes in self.outcomes.values():
            for outcome in outcomes.values():
                _names(outcome.get("propagate_to", []), consumers, "consumer destinations")
        _unique_refs([ref for rows in (self.candidates, self.defects, self.evidence, self.actions)
                      for row in rows.values() for ref in row.get("evidence_refs", [])])
        self.initial = (initial["candidate_id"], frozenset(ids), frozenset(), tuple(sorted(consumers.items())), frozenset(), ())

    def matches(self, evidence, candidate_id):
        candidate = self.candidates[candidate_id]
        return (evidence.get("candidate_id") in (None, candidate_id)
                and all(evidence[k] == candidate[k] for k in ("scope", "source_version", "condition_version")))

    def revoked_equivalents(self, ids):
        """Withdrawal follows the declared claim, including unread copies."""
        keys = {self.claim_keys[e] for e in ids}
        return {e for e, key in self.claim_keys.items() if key in keys}

    def details(self, state):
        candidate, received, revoked, consumers, used, observations = state
        revoked = self.revoked_equivalents(revoked)
        active = {e for e in received if e not in revoked and self.matches(self.evidence[e], candidate)}
        worlds = set(self.worlds)
        for evidence_id in active:
            worlds.intersection_update(self.evidence[evidence_id]["possible_worlds"])
        # Observations remain in history. Their semantic constraints are carried
        # by explicitly scoped evidence, so withdrawal really retracts support
        # and an old approval cannot constrain a corrected candidate.
        inconsistent = not worlds
        sets = [set(self.worlds[w]["defects"][candidate]) for w in worlds]
        possible = set.union(*sets) if sets else set()
        certain = set.intersection(*sets) if sets else set()
        unknown = {d for d in possible if self.defects[d].get("loss") is None}
        values = [sum((_number(self.defects[d]["loss"], "loss") for d in defects
                       if self.defects[d].get("loss") is not None), Fraction(0)) for defects in sets]
        lower = min(values) if values else None
        upper = None if inconsistent or unknown else max(values)
        approvals = sorted(e for e in active if self.evidence[e]["kind"] == "approval")
        reasons = []
        if inconsistent:
            reasons.append("conflicting-evidence")
        if self.targets["max_loss"] is None:
            reasons.append("threshold-unspecified")
        elif upper is None:
            reasons.append("modeled-loss-unknown")
        elif upper > _number(self.targets["max_loss"], "threshold"):
            reasons.append("possible-required-defect")
        if self.targets["require_approval"] and not approvals:
            reasons.append("no-exact-current-approval")
        if self.targets["require_current_consumers"] and any(v != candidate for _, v in consumers):
            reasons.append("consumers-not-current")
        inactive = [{"id": e, "reason": "revoked-support" if e in revoked else "scope-version-or-candidate-mismatch"}
                    for e in sorted(received - active)]
        return {"candidate_id": candidate, "features": deepcopy(self.candidates[candidate]["features"]),
                "possible_worlds": sorted(worlds), "possible_world_count": len(worlds),
                "risk": {"certain_defects": sorted(certain), "possible_defects": sorted(possible),
                         "lower_loss": None if lower is None else float(lower),
                         "upper_loss": None if upper is None else float(upper), "unknown_loss_defects": sorted(unknown),
                         "inconsistent_evidence": inconsistent, "scope": "declared-specific-defects-only",
                         "overall_literary_error_rate": "unknown"},
                "active_evidence_ids": sorted(active), "inactive_evidence": inactive,
                "received_evidence_ids": sorted(received), "revoked_evidence_ids": sorted(revoked & received),
                "effective_source_groups": sorted({self.evidence[e]["source_group"] for e in active}),
                "matched_approval_ids": approvals, "consumer_versions": dict(consumers),
                "used_action_ids": sorted(used), "observation_history": [list(row) for row in observations],
                "stop_allowed": not reasons, "stop_blockers": reasons,
                "formal_acceptance": False, "publication": False}

    def available(self, state, action_id):
        info = self.details(state)
        action = self.actions[action_id]
        return (action_id not in state[4] and action["candidate_id"] == state[0]
                and set(action.get("requires", [])) <= set(info["active_evidence_ids"]))

    def branches(self, state, action_id):
        result = []
        for outcome in self.outcomes[action_id].values():
            # A counter-observation may explicitly withdraw an earlier derived
            # assertion. Do not use that very assertion to make the counter-
            # observation impossible before checking it.
            candidate, received, revoked, consumers, used, history = state
            relaxed = (candidate, received, revoked | set(outcome.get("revoke_evidence", [])), consumers, used, history)
            info = self.details(relaxed)
            possible = set(info["possible_worlds"]) or set(self.worlds)
            if possible & set(outcome["possible_worlds"]):
                result.append(outcome)
        return result

    def inputs(self, state, action_id):
        _need(action_id in self.actions and self.available(state, action_id), "action is not available at this exact state")
        info = self.details(state)
        ids = sorted(set(info["active_evidence_ids"]) | set(self.actions[action_id].get("requires", [])))
        context_refs, required_refs = [], []
        for entry in [self.candidates[state[0]], *(self.evidence[e] for e in ids)]:
            for ref in entry.get("evidence_refs", []):
                if ref not in context_refs:
                    context_refs.append(deepcopy(ref))
        for evidence_id in self.actions[action_id].get("requires", []):
            for ref in self.evidence[evidence_id]["evidence_refs"]:
                if ref not in required_refs:
                    required_refs.append(deepcopy(ref))
        context_refs, required_refs = _unique_refs(context_refs), _unique_refs(required_refs)
        action_refs = _unique_refs(self.actions[action_id]["evidence_refs"])
        if self.actions[action_id]["kind"] == "check":
            future_refs = {_ref_key(ref) for outcomes in self.outcomes.values() for outcome in outcomes.values()
                           for e in outcome.get("add_evidence", []) for ref in self.evidence[e]["evidence_refs"]}
            _need(not ({_ref_key(ref) for ref in action_refs} & future_refs
                       - {_ref_key(ref) for ref in context_refs}),
                  "model check cannot read an unreceived outcome evidence reference")
        refs = _unique_refs(context_refs + action_refs)
        return {"consumed_evidence_ids": ids, "evidence_ids": ids, "refs": refs, "evidence_refs": refs,
                "required_evidence_refs": required_refs, "context_refs": context_refs, "action_refs": action_refs,
                "source_groups": sorted({self.evidence[e]["source_group"] for e in ids})}

    def step(self, state, action_id, outcome_id):
        _need(action_id in self.actions and self.available(state, action_id), "action is not available at this exact state")
        _need(outcome_id in self.outcomes[action_id], "unknown observed outcome")
        outcome = self.outcomes[action_id][outcome_id]
        _need(outcome in self.branches(state, action_id), "observed outcome is outside the declared response envelope")
        before = self.details(state)
        candidate, received, revoked, consumers, used, observations = state
        after = outcome.get("candidate_id", candidate)
        additions = set(outcome.get("add_evidence", []))
        revocations = set(outcome.get("revoke_evidence", []))
        _need(revocations <= received | additions, "cannot revoke evidence never observed")
        versions = dict(consumers)
        for destination in outcome.get("propagate_to", []):
            versions[destination] = after
        # Reading the same record again is not a new restoration authority.
        # Retain withdrawal seeds; details also withdraws their claim copies.
        next_state = (after, received | additions, revoked | revocations,
                      tuple(sorted(versions.items())), used | {action_id}, observations + ((action_id, outcome_id, after),))
        info = self.details(next_state)
        new_ids = additions - received
        trace = {"action_id": action_id, "outcome_id": outcome_id, **self.inputs(state, action_id),
                 "added_evidence_ids": sorted(additions),
                 "revoked_evidence_ids": sorted(self.revoked_equivalents(revocations) & (received | additions)),
                 "new_evidence_source_groups": sorted({self.evidence[e]["source_group"] for e in new_ids}),
                 "new_distinct_source_groups": sorted({self.evidence[e]["source_group"] for e in new_ids}
                                                       - set(before["effective_source_groups"])),
                 "world_count_before": before["possible_world_count"], "world_count_after": info["possible_world_count"],
                 "world_count_reduction": None if info["risk"]["inconsistent_evidence"] else before["possible_world_count"] - info["possible_world_count"],
                 "feature_updates": {k: {"before": before["features"].get(k), "after": info["features"].get(k)}
                                     for k in before["features"].keys() | info["features"].keys()
                                     if before["features"].get(k) != info["features"].get(k)},
                 "cost": self.actions[action_id]["cost"], "duration": deepcopy(self.actions[action_id]["duration"]),
                 "input_bytes": _bytes_json(_add_input_bytes({(): 0}, self.inputs(state, action_id)["refs"])),
                 "state": info}
        return next_state, trace


def _state_from_public(model, info):
    _need(isinstance(info, dict) and info.get("candidate_id") in model.candidates, "invalid public state")
    received = _names(info.get("received_evidence_ids", []), model.evidence, "received evidence")
    revoked = _names(info.get("revoked_evidence_ids", []), received, "revoked evidence")
    used = _names(info.get("used_action_ids", []), model.actions, "used actions")
    consumers = info.get("consumer_versions", {})
    _need(set(consumers) == set(dict(model.initial[3])) and all(v in model.candidates for v in consumers.values()), "invalid consumer state")
    observations = tuple(tuple(row) for row in info.get("observation_history", []))
    _need(all(len(row) == 3 and row[0] in model.actions and row[1] in model.outcomes[row[0]]
              and row[2] in model.candidates for row in observations), "invalid observation history")
    return (info["candidate_id"], frozenset(received), frozenset(revoked), tuple(sorted(consumers.items())), frozenset(used), observations)


def decision_action_inputs(case, state, action_id):
    """Exact declared scope inputs for an available action; not a trust oracle."""
    model = _Model(case)
    return model.inputs(_state_from_public(model, state), action_id)


def replay_decision_case(case, observations):
    """Replay a separately supplied historical sequence without replanning it."""
    model = _Model(case)
    _need(isinstance(observations, list), "observations must be a list")
    state, trace = model.initial, []
    for observation in observations:
        _need(isinstance(observation, dict), "observation must be an object")
        action = observation.get("action_id", observation.get("action"))
        outcome = observation.get("outcome_id", observation.get("outcome"))
        state, row = model.step(state, action, outcome)
        trace.append(row)
    return {"initial_state": model.details(model.initial), "trace": trace, "final_state": model.details(state),
            "formal_acceptance": False, "publication": False,
            "note": "Historical response replay is not an estimate of future response reliability."}


def _dominates(left, right):
    if left["duration_kind"] != right["duration_kind"]:
        return False
    if left["upper_loss"] is None or right["upper_loss"] is None:
        risk_leq = left["unknown_risk"] == right["unknown_risk"] and left["upper_loss"] == right["upper_loss"]
    else:
        risk_leq = left["upper_loss"] <= right["upper_loss"]
    return (left["can_stop"] >= right["can_stop"] and left["guaranteed_stop"] >= right["guaranteed_stop"]
            and risk_leq and left["cost"] <= right["cost"] and _time_leq(left["time"], right["time"])
            and _bytes_leq(left["input_bytes"], right["input_bytes"]))


def solve_decision_case(case):
    """Enumerate bounded AND/OR contingent policies, not clairvoyant schedules.

    Every possible response of a selected action has a continuation. Finite
    depth and one execution per action make the graph acyclic. All continuation
    combinations are enumerated; frontier pruning uses monotone worst-path
    objectives and can/guaranteed-stop flags. A cutoff reports partial search.
    No probability, expected value, confidence score or preferred weight is used.
    """
    model = _Model(case)
    stats = {"states": 0, "policy_combinations": 0, "complete": True}
    state_log = []

    def terminal(state, stop=False):
        info = model.details(state)
        return {"tree": {"terminal": "stop" if stop else "defer", "state": info},
                "can_stop": stop, "guaranteed_stop": stop, "upper_loss": info["risk"]["upper_loss"],
                "unknown_risk": tuple(info["risk"]["unknown_loss_defects"]) + (("inconsistent",) if info["risk"]["inconsistent_evidence"] else ()),
                "cost": Fraction(0), "time": {frozenset(): Fraction(0)}, "duration_kind": "observed", "input_bytes": {(): 0}}

    def frontier_add(frontier, plan):
        if any(_dominates(old, plan) for old in frontier):
            return
        frontier[:] = [old for old in frontier if not _dominates(plan, old)]
        frontier.append(plan)

    @lru_cache(None)
    def search(state, depth):
        info = model.details(state)
        best = [terminal(state, stop=info["stop_allowed"])]
        if stats["states"] >= model.limits["max_states"]:
            stats["complete"] = False
            return tuple(best)
        stats["states"] += 1
        state_log.append(info)
        # This is zero *remaining* work, not zero request time. With every
        # stopping condition satisfied and zero declared loss, nonnegative
        # future cost/time cannot improve any objective, even when its duration
        # classification differs. Positive tolerated loss is not this case.
        if info["stop_allowed"] and info["risk"]["upper_loss"] == 0:
            return tuple(best)
        available = [a for a in model.actions if model.available(state, a)]
        if depth >= model.limits["max_depth"]:
            if available:
                stats["complete"] = False
            return tuple(best)
        for action_id in available:
            if stats["policy_combinations"] >= model.limits["max_policies"]:
                stats["complete"] = False
                break
            outcomes = model.branches(state, action_id)
            children = [search(model.step(state, action_id, o["id"])[0], depth + 1) for o in outcomes]
            for combination in product(*children):
                if stats["policy_combinations"] >= model.limits["max_policies"]:
                    stats["complete"] = False
                    break
                stats["policy_combinations"] += 1
                action = model.actions[action_id]
                duration = action["duration"]
                kind = duration["kind"]
                seconds = Fraction(0) if kind == "unknown" else _number(duration["seconds"], "duration")
                child_time = _max_time(p["time"] for p in combination)
                time = {variables | ({action_id} if kind == "unknown" else set()): constant + seconds
                        for variables, constant in child_time.items()}
                duration_kind = "unknown" if kind == "unknown" or any(p["duration_kind"] == "unknown" for p in combination) else (
                    "scenario" if kind == "scenario" or any(p["duration_kind"] == "scenario" for p in combination) else "observed")
                unknown = set().union(*(set(p["unknown_risk"]) for p in combination))
                inputs = model.inputs(state, action_id)
                input_bytes = _add_input_bytes(_max_time(p["input_bytes"] for p in combination), inputs["refs"])
                plan = {"tree": {"action_id": action_id, **inputs,
                                  "outcomes": {o["id"]: p["tree"] for o, p in zip(outcomes, combination)}},
                        "can_stop": any(p["can_stop"] for p in combination),
                        "guaranteed_stop": all(p["guaranteed_stop"] for p in combination),
                        "upper_loss": None if any(p["upper_loss"] is None for p in combination) else max(p["upper_loss"] for p in combination),
                        "unknown_risk": tuple(sorted(unknown)),
                        "cost": _number(action["cost"], "cost") + max(p["cost"] for p in combination),
                        "time": time, "duration_kind": duration_kind, "input_bytes": input_bytes}
                frontier_add(best, plan)
        return tuple(best)

    plans = search(model.initial, 0)
    return {"schema_version": 1, "case_id": case.get("case_id", case.get("id")),
            "initial_state": model.details(model.initial), "states": state_log, "search": stats,
            "policy_frontier": [{"policy": p["tree"], "can_stop_in_some_outcome": p["can_stop"],
                                 "guaranteed_stop": p["guaranteed_stop"], "worst_modeled_loss": p["upper_loss"],
                                 "worst_action_cost": float(p["cost"]), "duration": _time_json(p["time"]),
                                 "duration_kind": p["duration_kind"], "input_bytes": _bytes_json(p["input_bytes"])} for p in plans],
            "frontier_kind": "bounded-contingent-pareto" if stats["complete"] else "partial-search",
            "formal_acceptance": False, "publication": False, "overall_literary_error_rate": "unknown",
            "limits": ["Finite worlds and response envelopes are explicit research assumptions, not calibrated probabilities.",
                       "Loss counts only declared specific defects, not the rate or completeness of literary error detection.",
                       "A possible stopping branch is not a guarantee or an expected benefit; no action is selected by invented weights.",
                       "Historical measured times do not predict new model responses. Unknown times remain symbolic.",
                       "Exact evidence bytes, judgments and canonical identities must be verified by the read-only adapter."]}
