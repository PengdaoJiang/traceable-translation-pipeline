"""Small, offline output contract and conservative subspace fusion.

This module checks *citation occurrence*, not whether a quotation supports a
literary claim.  Neither an exact quotation nor unanimous model output is proof
of semantic correctness.  The result is an experimental recommendation, never
literary acceptance, a calibrated error probability, or a publication action.
"""
from copy import deepcopy
import hashlib
import json


DEFAULT_DIMENSIONS = ("source_meaning", "rendering", "applicability")
DISPOSITIONS = ("supported", "problem", "unknown")
STOP_RECOMMENDATIONS = ("ready", "revise", "need_evidence")

RESULT_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "properties": {
        "assessments": {
            "type": "array", "items": {
                "type": "object", "additionalProperties": False,
                "properties": {
                    "dimension": {"type": "string", "enum": list(DEFAULT_DIMENSIONS)},
                    "disposition": {"type": "string", "enum": list(DISPOSITIONS)},
                    "reason": {"type": "string", "minLength": 1},
                    "evidence": {"type": "array", "items": {
                        "type": "object", "additionalProperties": False,
                        "properties": {"document_id": {"type": "string", "minLength": 1},
                                       "quote": {"type": "string", "minLength": 1}},
                        "required": ["document_id", "quote"],
                    }},
                    "affected_document_ids": {"type": "array", "items": {"type": "string", "minLength": 1}},
                    "next_action": {"type": "string", "minLength": 1},
                },
                "required": ["dimension", "disposition", "reason", "evidence",
                             "affected_document_ids", "next_action"],
            },
        },
        "stop_recommendation": {"type": "string", "enum": list(STOP_RECOMMENDATIONS)},
    },
    "required": ["assessments", "stop_recommendation"],
}

# V2 is only a wire representation.  It expands to RESULT_SCHEMA before any
# existing fusion logic runs; dimensions, verdicts and stop rules are unchanged.
COMPACT_RESULT_SCHEMA = deepcopy(RESULT_SCHEMA)
_compact_assessment = COMPACT_RESULT_SCHEMA["properties"]["assessments"]["items"]
del _compact_assessment["properties"]["evidence"]
_compact_assessment["properties"]["evidence_ids"] = {
    "type": "array", "items": {"type": "string", "minLength": 1},
}
_compact_assessment["required"] = [
    "evidence_ids" if field == "evidence" else field
    for field in _compact_assessment["required"]
]
COMPACT_RESULT_SCHEMA["properties"]["evidence"] = {
    "type": "array", "items": {
        "type": "object", "additionalProperties": False,
        "properties": {field: {"type": "string", "minLength": 1}
                       for field in ("id", "document_id", "quote")},
        "required": ["id", "document_id", "quote"],
    },
}
COMPACT_RESULT_SCHEMA["required"] = ["evidence", "assessments", "stop_recommendation"]
del _compact_assessment


class FusionInputError(ValueError):
    """Invalid research packet or model output; no silent repair is performed."""


def _object_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise FusionInputError("duplicate JSON field: " + key)
        result[key] = value
    return result


def _keys(value, required, location):
    if not isinstance(value, dict) or set(value) != set(required):
        raise FusionInputError(location + ": expected exactly " + ", ".join(required))


def _text(value, location):
    if not isinstance(value, str) or not value.strip():
        raise FusionInputError(location + ": expected a nonempty string")


def parse_result(raw):
    """Parse one exact contract; fenced JSON is accepted, surrounding prose is not.

    Multiple assessments of one dimension are retained so contradictory claims
    cannot be hidden by last-write-wins parsing.  Their verdicts address the
    overall supplied dimension; the prose carries conditions and limitations.
    """
    if isinstance(raw, str):
        source = raw.strip()
        if source.startswith("```json\n") and source.endswith("\n```"):
            source = source[8:-4]
        elif source.startswith("```\n") and source.endswith("\n```"):
            source = source[4:-4]
        try:
            result = json.loads(source, object_pairs_hook=_object_pairs)
        except (json.JSONDecodeError, TypeError) as exc:
            raise FusionInputError("not a single valid JSON object") from exc
    elif isinstance(raw, dict):
        result = deepcopy(raw)
    else:
        raise FusionInputError("result must be JSON text or an object")
    _keys(result, ("assessments", "stop_recommendation"), "result")
    if result["stop_recommendation"] not in STOP_RECOMMENDATIONS:
        raise FusionInputError("invalid stop_recommendation")
    if not isinstance(result["assessments"], list):
        raise FusionInputError("assessments must be an array")
    for index, assessment in enumerate(result["assessments"]):
        where = "assessment " + str(index)
        _keys(assessment, ("dimension", "disposition", "reason", "evidence",
                           "affected_document_ids", "next_action"), where)
        if assessment["dimension"] not in DEFAULT_DIMENSIONS:
            raise FusionInputError(where + ": invalid dimension")
        if assessment["disposition"] not in DISPOSITIONS:
            raise FusionInputError(where + ": invalid disposition")
        _text(assessment["reason"], where + " reason")
        _text(assessment["next_action"], where + " next_action")
        if not isinstance(assessment["evidence"], list):
            raise FusionInputError(where + ": evidence must be an array")
        for evidence in assessment["evidence"]:
            _keys(evidence, ("document_id", "quote"), where + " evidence")
            _text(evidence["document_id"], where + " document_id")
            _text(evidence["quote"], where + " quote")
        if not isinstance(assessment["affected_document_ids"], list):
            raise FusionInputError(where + ": affected_document_ids must be an array")
        for document_id in assessment["affected_document_ids"]:
            _text(document_id, where + " affected document id")
    return result


def parse_compact_result(raw):
    """Strictly expand V2 shared citations into the unchanged V1 contract.

    Unused table entries are structurally validated but confer no support and
    are not attached to any claim.  The caller should retain the raw response
    for audit.  Duplicate IDs and dangling references fail the entire contract;
    neither is silently removed to make an otherwise-ready output pass.
    """
    if isinstance(raw, str):
        source = raw.strip()
        if source.startswith("```json\n") and source.endswith("\n```"):
            source = source[8:-4]
        elif source.startswith("```\n") and source.endswith("\n```"):
            source = source[4:-4]
        try:
            compact = json.loads(source, object_pairs_hook=_object_pairs)
        except (json.JSONDecodeError, TypeError) as exc:
            raise FusionInputError("not a single valid compact JSON object") from exc
    elif isinstance(raw, dict):
        compact = deepcopy(raw)
    else:
        raise FusionInputError("compact result must be JSON text or an object")
    _keys(compact, ("evidence", "assessments", "stop_recommendation"), "compact result")
    if not isinstance(compact["evidence"], list):
        raise FusionInputError("compact evidence must be an array")
    table = {}
    for item in compact["evidence"]:
        _keys(item, ("id", "document_id", "quote"), "compact evidence")
        for field in ("id", "document_id", "quote"):
            _text(item[field], "compact evidence " + field)
        if item["id"] in table:
            raise FusionInputError("duplicate evidence id: " + item["id"])
        table[item["id"]] = {"document_id": item["document_id"], "quote": item["quote"]}
    if not isinstance(compact["assessments"], list):
        raise FusionInputError("compact assessments must be an array")
    expanded = {"assessments": [], "stop_recommendation": compact["stop_recommendation"]}
    for index, assessment in enumerate(compact["assessments"]):
        where = "compact assessment " + str(index)
        _keys(assessment, ("dimension", "disposition", "reason", "evidence_ids",
                           "affected_document_ids", "next_action"), where)
        if not isinstance(assessment["evidence_ids"], list):
            raise FusionInputError(where + ": evidence_ids must be an array")
        citations = []
        for evidence_id in assessment["evidence_ids"]:
            _text(evidence_id, where + " evidence id")
            if evidence_id not in table:
                raise FusionInputError(where + ": unknown evidence id: " + evidence_id)
            citations.append(deepcopy(table[evidence_id]))
        entry = {field: deepcopy(value) for field, value in assessment.items() if field != "evidence_ids"}
        entry["evidence"] = citations
        expanded["assessments"].append(entry)
    return parse_result(expanded)


def _packet_documents(packet):
    if not isinstance(packet, dict) or not all(key in packet for key in ("documents", "request", "scope")):
        raise FusionInputError("packet requires documents, request, scope")
    _text(packet["request"], "packet request")
    if not isinstance(packet["scope"], (str, dict, list)) or not packet["scope"]:
        raise FusionInputError("packet scope must be nonempty")
    if not isinstance(packet["documents"], list):
        raise FusionInputError("packet documents must be an array")
    documents = {}
    for document in packet["documents"]:
        if not isinstance(document, dict) or not all(key in document for key in ("id", "kind", "text")):
            raise FusionInputError("document requires id, kind, text")
        _text(document["id"], "document id")
        _text(document["kind"], "document kind")
        if not isinstance(document["text"], str):
            raise FusionInputError("document text must be a string")
        if document["id"] in documents:
            raise FusionInputError("duplicate document id: " + document["id"])
        documents[document["id"]] = document
    return documents


def _derived_stop(claims, missing=False):
    """A conservative research recommendation, not a semantic correctness test."""
    if missing or not claims or any(claim["unresolved"] for claim in claims):
        return "need_evidence"
    by_dimension = {}
    for claim in claims:
        by_dimension.setdefault(claim["dimension"], set()).add(claim["disposition"])
    if any(len(verdicts) > 1 for verdicts in by_dimension.values()):
        return "need_evidence"
    if any(claim["disposition"] == "problem" for claim in claims):
        return "revise"
    return "ready"


def fuse_results(packet, outputs, expected_dimensions=DEFAULT_DIMENSIONS):
    """Use the same computation for one full response or several subspace views.

    A view named after a dimension is scoped to that dimension.  Other names
    (e.g. ``full``) may contain all expected dimensions.  Exact citations and
    identical document bodies are deduplicated, but never counted as votes.
    Unsupported or invalid claims remain visible for external evaluation.
    """
    documents = _packet_documents(packet)
    dimensions = tuple(expected_dimensions)
    if not dimensions or len(set(dimensions)) != len(dimensions) or any(d not in DEFAULT_DIMENSIONS for d in dimensions):
        raise FusionInputError("expected_dimensions must be unique known dimensions")
    if not isinstance(outputs, dict):
        raise FusionInputError("outputs must map view names to results")
    claims = []
    citation_index = {}
    source_index = {}
    view_stops = {}
    for view, raw in outputs.items():
        _text(view, "view name")
        parsed = parse_result(raw)
        view_stops[view] = parsed["stop_recommendation"]
        for index, assessment in enumerate(parsed["assessments"]):
            claim = deepcopy(assessment)
            claim.update(view=view, assessment_index=index, citation_checks=[], unresolved=[])
            if claim["dimension"] not in dimensions:
                claim["unresolved"].append("outside-expected-dimensions")
            if view in DEFAULT_DIMENSIONS and claim["dimension"] != view:
                claim["unresolved"].append("outside-assigned-view")
            for citation in claim["evidence"]:
                document = documents.get(citation["document_id"])
                valid = document is not None and citation["quote"] in document["text"]
                checked = dict(citation, exact_match=valid)
                if not valid:
                    checked["error"] = "unknown-document" if document is None else "quote-not-found"
                    claim["unresolved"].append("invalid-citation")
                else:
                    source_id = hashlib.sha256(document["text"].encode("utf-8")).hexdigest()
                    evidence_key = (source_id, citation["quote"])
                    source_index.setdefault(source_id, set()).add(document["id"])
                    citation_index.setdefault(evidence_key, {"source_content_sha256": source_id,
                        "quote": citation["quote"], "document_ids": set(), "uses": []})
                    citation_index[evidence_key]["document_ids"].add(document["id"])
                    citation_index[evidence_key]["uses"].append({"view": view, "assessment_index": index})
                    checked["source_content_sha256"] = source_id
                claim["citation_checks"].append(checked)
            if not claim["evidence"] and claim["disposition"] != "unknown":
                claim["unresolved"].append("no-cited-evidence")
            if claim["disposition"] == "unknown":
                claim["unresolved"].append("model-unknown")
            unknown_affected = sorted(set(claim["affected_document_ids"]) - set(documents))
            if unknown_affected:
                claim["unresolved"].append("unknown-affected-document")
            claim["unknown_affected_document_ids"] = unknown_affected
            claim["unresolved"] = sorted(set(claim["unresolved"]))
            claim["citation_status"] = ("invalid" if any(not c["exact_match"] for c in claim["citation_checks"])
                                        else "matched" if claim["citation_checks"] else "absent")
            claim["semantic_support"] = "not-established-by-citation-matching"
            claims.append(claim)

    dimension_reports = {}
    missing_dimensions = []
    unresolved = []
    for dimension in dimensions:
        selected = [c for c in claims if c["dimension"] == dimension]
        if not selected:
            missing_dimensions.append(dimension)
        # These are intersections of asserted candidate states, not proof that
        # either assertion is true.  Invalid claims impose no constraint.
        states = {"acceptable", "needs_revision"}
        effective = [c for c in selected if not c["unresolved"]]
        for claim in effective:
            states &= {"acceptable"} if claim["disposition"] == "supported" else {"needs_revision"}
        conflict = bool(effective) and not states
        issues = sorted({issue for c in selected for issue in c["unresolved"]})
        if not selected:
            issues.append("missing-dimension")
        if conflict:
            issues.append("conflicting-dispositions")
        dimension_reports[dimension] = {
            "assessments": selected, "asserted_candidate_state_intersection": sorted(states),
            "conflict": conflict, "unresolved": sorted(set(issues)),
            "requires_revision_or_review": any(c["disposition"] == "problem" for c in effective),
            "semantic_truth": "unverified",
        }
        unresolved.extend({"dimension": dimension, "reason": issue} for issue in issues)
    for claim in claims:
        if claim["dimension"] not in dimensions:
            unresolved.append({"dimension": claim["dimension"], "reason": "outside-expected-dimensions"})
    assessment_stop = _derived_stop(claims, missing=bool(missing_dimensions))
    # Preserve an explicitly cautious recommendation even if a model forgot to
    # express its reason as a dimension-level unknown.  No extra model call.
    stop = assessment_stop
    if "need_evidence" in view_stops.values():
        stop = "need_evidence"
    elif stop == "ready" and "revise" in view_stops.values():
        stop = "revise"
    view_checks = {}
    for view, declared in view_stops.items():
        selected = [c for c in claims if c["view"] == view]
        view_expected = (view,) if view in DEFAULT_DIMENSIONS else dimensions
        observed = {c["dimension"] for c in selected}
        local = _derived_stop(selected, missing=any(d not in observed for d in view_expected))
        view_checks[view] = {"declared_stop": declared, "derived_local_stop": local,
                             "local_disagreement": declared != local,
                             "agrees_with_fused_stop": declared == stop,
                             "comparison_scope": "assigned-view-not-whole-project"}
    evidence = []
    for key in sorted(citation_index):
        item = citation_index[key]
        evidence.append(dict(item, document_ids=sorted(item["document_ids"])))
    return {
        "schema_version": 1, "research_only": True, "formal_acceptance": False,
        "publication": False, "expected_dimensions": list(dimensions),
        "missing_dimensions": missing_dimensions, "dimensions": dimension_reports,
        "unresolved": unresolved, "assessment_derived_stop": assessment_stop,
        "fused_stop_recommendation": stop, "view_stop_checks": view_checks,
        "unique_evidence": evidence,
        "unique_source_contents": [{"sha256": key, "document_ids": sorted(ids)}
                                   for key, ids in sorted(source_index.items())],
        "requires_revision_or_review": any(d["requires_revision_or_review"] for d in dimension_reports.values()),
        "limitations": [
            "Exact quotation occurrence does not establish semantic support or correctness.",
            "Matching source bodies and repeated citations are deduplicated, never independent votes.",
            "Different source bodies may share an unknown origin; no independence is assumed.",
            "Ready means a research recommendation under the supplied packet, not literary acceptance.",
            "Hallucination, missed defects and false stops require separate answer-hidden evaluation.",
        ],
    }


def _content_identity(value):
    body = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def check_observation_continuity(packet, current_fusion, prior_observations=(), dispositions=()):
    """Keep prior objections visible without declaring them true or accepted.

    This optional, pure overlay does not change parse/fuse or saved experiments.
    Pass its ``observations`` into the next call.  Mere silence or a new ``ready``
    cannot dispose of an old observation.  A changed packet requires a local
    applicability decision, not automatic transfer or deletion of the objection.

    Explicit disposition records must contain exactly observation_id,
    packet_sha256, outcome (resolved/not_applicable/still_open), reason, evidence.
    Their semantic adequacy is NOT established here: exact references and exact
    target binding only make them auditable, not proven correct adjudications.
    This function is not an authenticated acceptance entry point; the caller
    binds current_fusion to the experimental packet and retains the raw records.
    """
    documents = _packet_documents(packet)
    if not isinstance(current_fusion, dict) or current_fusion.get("fused_stop_recommendation") not in STOP_RECOMMENDATIONS:
        raise FusionInputError("continuity requires an existing fusion report")
    document_bindings = [{"id": doc["id"], "kind": doc["kind"],
                          "sha256": hashlib.sha256(doc["text"].encode("utf-8")).hexdigest()}
                         for _, doc in sorted(documents.items())]
    binding = {
        "packet_sha256": _content_identity({"request": packet["request"], "scope": packet["scope"],
                                            "documents": document_bindings}),
        "scope_sha256": _content_identity(packet["scope"]),
        "candidate_documents": [doc for doc in document_bindings if doc["kind"].startswith("candidate")],
        "document_contents": document_bindings,
    }

    def validate_current_disposition(disposition, expected_identity):
        _keys(disposition, ("observation_id", "packet_sha256", "outcome", "reason", "evidence"), "observation disposition")
        if disposition["observation_id"] != expected_identity:
            raise FusionInputError("disposition observation identity mismatch")
        if disposition["packet_sha256"] != binding["packet_sha256"]:
            raise FusionInputError("disposition is not bound to the current packet")
        if disposition["outcome"] not in ("resolved", "not_applicable", "still_open"):
            raise FusionInputError("invalid observation disposition outcome")
        _text(disposition["reason"], "disposition reason")
        if not isinstance(disposition["evidence"], list):
            raise FusionInputError("disposition evidence must be an array")
        if disposition["outcome"] != "still_open" and not disposition["evidence"]:
            raise FusionInputError("closing disposition requires explicit current evidence")
        for citation in disposition["evidence"]:
            _keys(citation, ("document_id", "quote"), "disposition citation")
            _text(citation["document_id"], "disposition document_id")
            _text(citation["quote"], "disposition quote")
            doc = documents.get(citation["document_id"])
            if doc is None or citation["quote"] not in doc["text"]:
                raise FusionInputError("disposition citation is not in the current packet")

    observations = {}
    for previous in prior_observations:
        if not isinstance(previous, dict) or not all(key in previous for key in ("id", "binding", "claim", "resolution")):
            raise FusionInputError("malformed prior observation")
        claim = parse_result({"assessments": [previous["claim"]], "stop_recommendation": "need_evidence"})["assessments"][0]
        if claim["disposition"] not in ("problem", "unknown"):
            raise FusionInputError("prior observation must be problem or unknown")
        expected_id = _content_identity({"binding": previous["binding"], "claim": claim})
        if previous["id"] != expected_id or previous["id"] in observations:
            raise FusionInputError("prior observation identity mismatch or duplicate")
        resolution = previous["resolution"]
        # An inherited record capable of closing this packet must pass exactly
        # the same checks as a newly supplied record.  Older-packet records are
        # retained as history but cannot authorize a current automatic stop.
        if resolution is not None and (not isinstance(resolution, dict)
                                       or resolution.get("packet_sha256") == binding["packet_sha256"]):
            validate_current_disposition(resolution, previous["id"])
        observations[previous["id"]] = deepcopy(previous)
    claim_fields = RESULT_SCHEMA["properties"]["assessments"]["items"]["required"]
    for dimension in current_fusion.get("dimensions", {}).values():
        for assessment in dimension.get("assessments", []):
            if assessment.get("disposition") not in ("problem", "unknown"):
                continue
            claim = {key: deepcopy(assessment[key]) for key in claim_fields}
            # Identical copies create one observation, not independent evidence
            # or a vote.  Distinct prose is not guessed to be semantically equal.
            identity = _content_identity({"binding": binding, "claim": claim})
            observations.setdefault(identity, {"id": identity, "binding": deepcopy(binding),
                                               "claim": claim, "resolution": None})
    seen_dispositions = set()
    for disposition in dispositions:
        _keys(disposition, ("observation_id", "packet_sha256", "outcome", "reason", "evidence"), "observation disposition")
        identity = disposition["observation_id"]
        _text(identity, "disposition observation_id")
        if identity not in observations or identity in seen_dispositions:
            raise FusionInputError("unknown or multiply disposed observation id")
        seen_dispositions.add(identity)
        validate_current_disposition(disposition, identity)
        observations[identity]["resolution"] = deepcopy(disposition)
    pending = []
    for identity, observation in observations.items():
        same_packet = observation["binding"]["packet_sha256"] == binding["packet_sha256"]
        resolution = observation["resolution"]
        current_resolution = (isinstance(resolution, dict) and resolution.get("observation_id") == identity
                              and resolution.get("packet_sha256") == binding["packet_sha256"])
        closed = current_resolution and resolution.get("outcome") in ("resolved", "not_applicable")
        observation["status"] = "explicitly-disposed-research-only" if closed else "pending"
        observation["applicability"] = "same-packet" if same_packet else "requires-local-applicability-judgment"
        observation["semantic_truth"] = "unverified-observation-not-a-proven-defect"
        if not closed:
            pending.append({"observation_id": identity, "reason": "unresolved-same-packet-observation" if same_packet
                            else "changed-packet-applicability-unresolved"})
    suggested_stop = current_fusion["fused_stop_recommendation"]
    return {
        "research_only": True, "formal_acceptance": False, "publication": False,
        "current_binding": binding, "observations": list(observations.values()), "pending": pending,
        "input_fused_stop_recommendation": suggested_stop,
        "continuity_stop_recommendation": "need_evidence" if pending else suggested_stop,
        "research_auto_stop_allowed": suggested_stop == "ready" and not pending,
        "limitations": [
            "A retained observation is not a fact, a vote, or a proof of a defect.",
            "Changed inputs require local applicability judgment; an old assertion is not automatically transferred.",
            "Explicit targeted dispositions are supplied judgments; citation matching does not prove their semantic adequacy.",
            "This overlay restricts experimental automatic stopping only and confers no literary acceptance.",
        ],
    }
