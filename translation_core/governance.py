"""Mechanical Codex receipt and artifact-link governance.

This module validates machine-verifiable facts only: canonical task identity,
receipt syntax, file hashes, chain linkage, lifecycle status, chronology, and
artifact references.  It deliberately does not judge literary reasoning or
require protocol phrases, receipt IDs, dispositions, or minimum word counts in
free-form dossiers.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]

TASK_RECEIPT_HEADER = (
    "receipt_id",
    "task_id",
    "role",
    "stage",
    "scope_id",
    "input_sha256",
    "output_path",
    "output_sha256",
    "review_of_receipt_id",
    "context_policy",
    "status",
    "created_at",
    "notes",
)
TASK_RECEIPT_ROLES = {"producer", "counter-reviewer", "adjudicator"}
CANONICAL_CODEX_TASK_ID_PATTERN = re.compile(r"/root(?:/[a-z0-9_]+)*")


def is_canonical_codex_task_id(value: str) -> bool:
    """Return whether *value* has the repository's canonical Codex task-path form."""

    return bool(CANONICAL_CODEX_TASK_ID_PATTERN.fullmatch(value))
TASK_RECEIPT_CONTEXT_POLICIES = {
    "full-context",
    "isolated-context",
    "blind-review",
}
TASK_RECEIPT_STATUSES = {
    "completed",
    "accepted",
    "rework-required",
    "unresolved",
    "superseded",
    "stale",
}


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def _parse_timezone_aware_iso8601(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed


def read_dossier_subject_sha256(path: Path) -> str | None:
    """Read the governed subject digest declared by a producer dossier."""
    try:
        raw = path.read_text(encoding="utf-8")
    except (FileNotFoundError, UnicodeDecodeError, OSError):
        return None
    value: Any = None
    if path.suffix.lower() == ".json":
        try:
            document = json.loads(raw)
        except json.JSONDecodeError:
            return None
        if isinstance(document, dict):
            value = document.get("subject_sha256")
    else:
        matches = re.findall(
            r"(?m)^subject_sha256:\s*`?([A-F0-9]{64})`?\s*$", raw
        )
        if len(matches) == 1:
            value = matches[0]
    return (
        value
        if isinstance(value, str) and re.fullmatch(r"[A-F0-9]{64}", value)
        else None
    )


def receipt_output_path_is_staging(
    output_path: str, *, workspace_root: Path | None = None
) -> bool:
    """Reject staging paths after case-folded, junction-aware normalization."""
    root = workspace_root or ROOT
    try:
        candidate = (root / Path(output_path)).resolve()
    except (OSError, RuntimeError, ValueError):
        return True
    candidate_key = os.path.normcase(str(candidate))
    for staging_root in (
        root / "data" / "nomenclature" / "staging",
        root / "data" / "editorial" / "staging",
        root / "build" / "staging",
    ):
        staging_key = os.path.normcase(str(staging_root.resolve()))
        if candidate_key == staging_key or candidate_key.startswith(
            staging_key + os.sep
        ):
            return True
    return False


def validate_task_receipts(
    receipt_path: Path | None = None,
    *,
    workspace_root: Path | None = None,
) -> dict[str, Any]:
    """Validate Codex production -> counter-review -> adjudication receipts."""
    root = workspace_root or ROOT
    path = receipt_path or (root / "data" / "governance" / "task-receipts.tsv")
    errors: list[str] = []
    try:
        with path.open("r", encoding="utf-8", newline="") as handle:
            raw_rows = list(csv.reader(handle, delimiter="\t"))
    except FileNotFoundError:
        return {
            "valid": False,
            "receipt_count": 0,
            "accepted_chains": 0,
            "by_id": {},
            "errors": [f"required Codex task receipt registry is missing: {path}"],
        }
    if not raw_rows or tuple(raw_rows[0]) != TASK_RECEIPT_HEADER:
        return {
            "valid": False,
            "receipt_count": 0,
            "accepted_chains": 0,
            "by_id": {},
            "errors": [f"{path.name}: header must be {list(TASK_RECEIPT_HEADER)}"],
        }
    by_id: dict[str, dict[str, Any]] = {}
    output_owners: dict[str, str] = {}
    validation_now = datetime.now(timezone.utc)
    maximum_clock_skew = timedelta(minutes=5)
    for row_number, values in enumerate(raw_rows[1:], start=2):
        prefix = f"{path.name}:{row_number}"
        if len(values) != len(TASK_RECEIPT_HEADER):
            errors.append(f"{prefix}: expected {len(TASK_RECEIPT_HEADER)} fields")
            continue
        row: dict[str, Any] = dict(
            zip(TASK_RECEIPT_HEADER, values, strict=True)
        )
        receipt_id = row["receipt_id"]
        if not re.fullmatch(r"RCP-[0-9]{8}-[0-9]{4}", receipt_id):
            errors.append(f"{prefix}: invalid receipt_id {receipt_id!r}")
        elif receipt_id in by_id:
            errors.append(f"{prefix}: duplicate receipt_id {receipt_id}")
        by_id[receipt_id] = row
        if not is_canonical_codex_task_id(row["task_id"]):
            errors.append(
                f"{prefix}: task_id must be a canonical /root Codex task path"
            )
        if row["role"] not in TASK_RECEIPT_ROLES:
            errors.append(f"{prefix}: invalid role {row['role']!r}")
        if not re.fullmatch(r"M[0-7]", row["stage"]):
            errors.append(f"{prefix}: stage must be a canonical milestone ID M0-M7")
        if not row["scope_id"].strip():
            errors.append(f"{prefix}: scope_id is required")
        for field_name in ("input_sha256", "output_sha256"):
            if not re.fullmatch(r"[A-F0-9]{64}", row[field_name]):
                errors.append(f"{prefix}: invalid {field_name}")
        output_value = row["output_path"]
        if (
            not output_value
            or "\\" in output_value
            or Path(output_value).is_absolute()
        ):
            errors.append(f"{prefix}: output_path must be workspace-relative")
        else:
            output_path = (root / output_value).resolve()
            try:
                output_path.relative_to(root.resolve())
            except ValueError:
                errors.append(f"{prefix}: output_path escapes the workspace")
            else:
                if output_path.suffix.lower() not in {".md", ".json"}:
                    errors.append(f"{prefix}: output_path must be a readable dossier")
                relative_output = output_path.relative_to(root.resolve()).as_posix()
                if not relative_output.startswith(("data/", "docs/")):
                    errors.append(
                        f"{prefix}: output dossier must be under data/ or docs/"
                    )
                if output_path == path.resolve():
                    errors.append(f"{prefix}: receipt registry cannot be its own output")
                prior_owner = output_owners.get(relative_output)
                if prior_owner is not None and prior_owner != receipt_id:
                    errors.append(
                        f"{prefix}: output_path is already owned by receipt {prior_owner}"
                    )
                output_owners[relative_output] = receipt_id
                actual_hash = (
                    _sha256_bytes(output_path.read_bytes())
                    if output_path.exists()
                    else None
                )
                if actual_hash != row["output_sha256"]:
                    errors.append(f"{prefix}: output dossier is missing or has drifted")
                if output_path.exists():
                    try:
                        readable_text = output_path.read_text(encoding="utf-8")
                    except (UnicodeDecodeError, OSError):
                        errors.append(
                            f"{prefix}: output dossier must be readable UTF-8"
                        )
                    else:
                        if not readable_text.strip():
                            errors.append(f"{prefix}: output dossier must not be empty")
        if row["context_policy"] not in TASK_RECEIPT_CONTEXT_POLICIES:
            errors.append(
                f"{prefix}: invalid context_policy {row['context_policy']!r}"
            )
        if row["status"] not in TASK_RECEIPT_STATUSES:
            errors.append(f"{prefix}: invalid status {row['status']!r}")
        if not re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
            row["created_at"],
        ):
            errors.append(f"{prefix}: created_at must be UTC RFC-3339 with seconds")
        else:
            created_at = _parse_timezone_aware_iso8601(row["created_at"])
            if created_at is None:
                errors.append(f"{prefix}: created_at is not a real UTC timestamp")
            else:
                row["_created_at_datetime"] = created_at
                if created_at > validation_now + maximum_clock_skew:
                    errors.append(f"{prefix}: created_at is implausibly in the future")
        role = row["role"]
        if role == "producer":
            subject_path = (
                (root / output_value).resolve()
                if output_value and not Path(output_value).is_absolute()
                else None
            )
            subject_digest = (
                read_dossier_subject_sha256(subject_path)
                if subject_path is not None
                else None
            )
            if subject_digest is None:
                errors.append(
                    f"{prefix}: producer dossier must declare exactly one subject_sha256"
                )
            row["_subject_sha256"] = subject_digest or ""
        if role == "producer":
            if row["review_of_receipt_id"]:
                errors.append(f"{prefix}: producer cannot review another receipt")
            if row["context_policy"] != "full-context":
                errors.append(f"{prefix}: producer must use full-context")
            if row["status"] not in {"completed", "superseded", "stale"}:
                errors.append(f"{prefix}: invalid producer status")
        elif role == "counter-reviewer":
            if not row["review_of_receipt_id"]:
                errors.append(
                    f"{prefix}: counter-reviewer must name the producer receipt"
                )
            # Independence is proven by task identity and the hash-locked edge.
            # The declared context policy records actual context, not a prose test.
            if row["context_policy"] not in TASK_RECEIPT_CONTEXT_POLICIES:
                errors.append(f"{prefix}: counter-review has invalid context policy")
            if row["status"] not in {"completed", "superseded", "stale"}:
                errors.append(f"{prefix}: invalid counter-reviewer status")
        elif role == "adjudicator":
            if not row["review_of_receipt_id"]:
                errors.append(
                    f"{prefix}: adjudicator must name the counter-review receipt"
                )
            if row["context_policy"] != "full-context":
                errors.append(f"{prefix}: adjudicator must reconcile with full-context")
            if row["status"] not in {
                "accepted",
                "rework-required",
                "unresolved",
                "superseded",
                "stale",
            }:
                errors.append(f"{prefix}: invalid adjudicator status")
    children_by_parent: defaultdict[str, list[str]] = defaultdict(list)
    for receipt_id, row in by_id.items():
        parent_id = row["review_of_receipt_id"]
        if not parent_id:
            continue
        children_by_parent[parent_id].append(receipt_id)
        parent = by_id.get(parent_id)
        if parent is None:
            errors.append(f"{path.name}: {receipt_id} reviews unknown {parent_id}")
            continue
        expected_parent_role = (
            "producer" if row["role"] == "counter-reviewer" else "counter-reviewer"
        )
        if parent["role"] != expected_parent_role:
            errors.append(f"{path.name}: {receipt_id} reviews the wrong role")
        if (row["stage"], row["scope_id"]) != (
            parent["stage"],
            parent["scope_id"],
        ):
            errors.append(f"{path.name}: {receipt_id} changes stage or scope")
        if row["input_sha256"] != parent["output_sha256"]:
            errors.append(f"{path.name}: {receipt_id} input hash breaks the chain")
        child_created_at = row.get("_created_at_datetime")
        parent_created_at = parent.get("_created_at_datetime")
        if (
            isinstance(child_created_at, datetime)
            and isinstance(parent_created_at, datetime)
            and child_created_at < parent_created_at
        ):
            errors.append(
                f"{path.name}: {receipt_id} predates upstream receipt {parent_id}"
            )
        lifecycle_statuses = {"stale", "superseded"}
        if (
            row["status"] in lifecycle_statuses
            or parent["status"] in lifecycle_statuses
        ) and row["status"] != parent["status"]:
            errors.append(
                f"{path.name}: lifecycle status must agree across receipt edge "
                f"{parent_id} -> {receipt_id}"
            )
        # Registry edge + input hash bind the exact upstream bytes; free prose is
        # not parsed for receipt IDs, lifecycle words, or adjudication language.
    for parent_id, child_ids in sorted(children_by_parent.items()):
        if len(child_ids) > 1:
            errors.append(
                f"{path.name}: {parent_id} has multiple downstream review children "
                f"{child_ids}; rework requires a new producer and a new chain"
            )
    accepted_chains = sum(
        row["role"] == "adjudicator" and row["status"] == "accepted"
        for row in by_id.values()
    )
    return {
        "valid": not errors,
        "receipt_count": len(by_id),
        "accepted_chains": accepted_chains,
        "by_id": by_id,
        "errors": errors,
    }


def validate_receipt_chain(
    receipts: dict[str, Any],
    *,
    producer_receipt_id: str,
    review_receipt_id: str,
    adjudication_receipt_id: str,
    stage: str,
    scope_id: str,
    dossier_path: str,
    adjudication_status: str = "accepted",
    subject_sha256: str | None = None,
) -> list[str]:
    """Return chain errors without pretending to evaluate literary judgment."""
    errors: list[str] = []
    if not receipts.get("valid"):
        return ["task receipt registry is invalid"]
    by_id = receipts.get("by_id", {})
    ids = (producer_receipt_id, review_receipt_id, adjudication_receipt_id)
    if not all(isinstance(value, str) and value for value in ids):
        return ["producer, counter-review, and adjudication receipts are required"]
    rows = [by_id.get(value) for value in ids]
    if any(row is None for row in rows):
        return ["one or more task receipt IDs are unknown"]
    producer, reviewer, adjudicator = rows
    assert producer is not None and reviewer is not None and adjudicator is not None
    if [producer["role"], reviewer["role"], adjudicator["role"]] != [
        "producer",
        "counter-reviewer",
        "adjudicator",
    ]:
        errors.append("receipt roles must be producer -> counter-reviewer -> adjudicator")
    if len({producer["task_id"], reviewer["task_id"], adjudicator["task_id"]}) != 3:
        errors.append(
            "production, counter-review, and adjudication require distinct Codex tasks"
        )
    if any(row["stage"] != stage or row["scope_id"] != scope_id for row in rows):
        errors.append("receipt chain stage or scope does not match the governed artifact")
    if reviewer["review_of_receipt_id"] != producer_receipt_id:
        errors.append("counter-review receipt does not review the producer receipt")
    if adjudicator["review_of_receipt_id"] != review_receipt_id:
        errors.append("adjudication receipt does not review the counter-review receipt")
    if producer["status"] != "completed" or reviewer["status"] != "completed":
        errors.append("producer and counter-review receipts must be completed")
    if adjudicator["status"] != adjudication_status:
        errors.append(
            f"adjudicator disposition must be {adjudication_status}, "
            f"not {adjudicator['status']}"
        )
    if len(
        {producer["output_path"], reviewer["output_path"], adjudicator["output_path"]}
    ) != 3:
        errors.append("production, counter-review, and adjudication outputs must be distinct")
    if producer["output_path"] != dossier_path:
        errors.append("dossier_path must identify the producer's literary dossier")
    if subject_sha256 is not None and producer.get("_subject_sha256") != subject_sha256:
        errors.append("producer dossier subject_sha256 does not match the governed payload")
    return errors


def validate_producer_receipt(
    receipts: dict[str, Any],
    *,
    producer_receipt_id: str,
    stage: str,
    scope_id: str,
    dossier_path: str,
    subject_sha256: str | None = None,
) -> list[str]:
    row = receipts.get("by_id", {}).get(producer_receipt_id)
    if row is None:
        return ["producer receipt is missing or unknown"]
    errors: list[str] = []
    if row["role"] != "producer" or row["status"] != "completed":
        errors.append("producer receipt is not a completed production task")
    if row["stage"] != stage or row["scope_id"] != scope_id:
        errors.append("producer receipt stage or scope does not match")
    if row["output_path"] != dossier_path:
        errors.append("dossier_path must identify the producer's output")
    if subject_sha256 is not None and row.get("_subject_sha256") != subject_sha256:
        errors.append("producer dossier subject_sha256 does not match the governed payload")
    return errors


def validate_task_receipt_role(
    receipts: dict[str, Any],
    *,
    receipt_id: str,
    role: str,
    stage: str,
    scope_id: str,
    allowed_statuses: set[str],
) -> list[str]:
    """Validate a single receipt reference without treating it as acceptance."""
    row = receipts.get("by_id", {}).get(receipt_id)
    if row is None:
        return ["task receipt is missing or unknown"]
    errors: list[str] = []
    if row["role"] != role:
        errors.append(f"task receipt must have role {role}")
    if row["status"] not in allowed_statuses:
        errors.append(
            "task receipt status must be one of " + ", ".join(sorted(allowed_statuses))
        )
    if row["stage"] != stage or row["scope_id"] != scope_id:
        errors.append("task receipt stage or scope does not match")
    return errors


def validate_adjudication_receipt(
    receipts: dict[str, Any],
    *,
    adjudication_receipt_id: str,
    stage: str,
    scope_id: str,
    subject_sha256: str | None = None,
) -> list[str]:
    """Resolve and validate the full chain behind one accepted adjudication ID."""
    by_id = receipts.get("by_id", {})
    adjudicator = by_id.get(adjudication_receipt_id)
    if adjudicator is None:
        return ["adjudication receipt is missing or unknown"]
    review_receipt_id = adjudicator.get("review_of_receipt_id", "")
    reviewer = by_id.get(review_receipt_id)
    if reviewer is None:
        return ["adjudication receipt does not resolve to a counter-review receipt"]
    producer_receipt_id = reviewer.get("review_of_receipt_id", "")
    producer = by_id.get(producer_receipt_id)
    if producer is None:
        return ["counter-review receipt does not resolve to a producer receipt"]
    return validate_receipt_chain(
        receipts,
        producer_receipt_id=producer_receipt_id,
        review_receipt_id=review_receipt_id,
        adjudication_receipt_id=adjudication_receipt_id,
        stage=stage,
        scope_id=scope_id,
        dossier_path=producer.get("output_path", ""),
        subject_sha256=subject_sha256,
    )


def resolve_accepted_receipt_scope(
    receipts: dict[str, Any],
    *,
    stage: str,
    scope_id: str,
    subject_sha256: str | None = None,
) -> dict[str, Any]:
    """Resolve the one current accepted chain for a milestone scope."""
    candidates = [
        receipt_id
        for receipt_id, row in receipts.get("by_id", {}).items()
        if row.get("role") == "adjudicator"
        and row.get("status") == "accepted"
        and row.get("stage") == stage
        and row.get("scope_id") == scope_id
    ]
    errors: list[str] = []
    if len(candidates) != 1:
        errors.append(
            f"expected exactly one accepted adjudication for {stage}/{scope_id}, "
            f"found {len(candidates)}"
        )
    elif receipts.get("valid"):
        errors.extend(
            validate_adjudication_receipt(
                receipts,
                adjudication_receipt_id=candidates[0],
                stage=stage,
                scope_id=scope_id,
                subject_sha256=subject_sha256,
            )
        )
    else:
        errors.append("task receipt registry is invalid")
    return {
        "valid": not errors,
        "adjudication_receipt_id": candidates[0] if len(candidates) == 1 else None,
        "errors": errors,
    }


def validate_codex_artifact_receipts(
    document: dict[str, Any],
    receipts: dict[str, Any],
    *,
    stage: str,
    scope_id: str,
    producer_required: bool = False,
    review_required: bool = False,
    acceptance_required: bool = False,
    validate_references: bool = True,
    subject_sha256: str | None = None,
) -> dict[str, Any]:
    """Validate receipt references without evaluating the literary artifact."""
    errors: list[str] = []
    receipt_ids: dict[str, str] = {}
    roles = {
        "producer_receipt_id": "producer",
        "review_receipt_id": "counter-reviewer",
        "adjudication_receipt_id": "adjudicator",
    }
    for field_name in roles:
        value = document.get(field_name)
        if value is None:
            receipt_ids[field_name] = ""
        elif not isinstance(value, str):
            errors.append(f"{field_name} must be null or a Codex receipt ID")
            receipt_ids[field_name] = ""
        else:
            normalized = value.strip()
            receipt_ids[field_name] = normalized
            if value != normalized:
                errors.append(f"{field_name} must not contain surrounding whitespace")
            if not re.fullmatch(r"RCP-[0-9]{8}-[0-9]{4}", normalized):
                errors.append(f"{field_name} must match RCP-YYYYMMDD-NNNN")

    dossier_value = document.get("dossier_path")
    if dossier_value is None:
        dossier_path = ""
    elif not isinstance(dossier_value, str):
        errors.append("dossier_path must be null or a repository-relative path")
        dossier_path = ""
    else:
        dossier_path = dossier_value.strip()
        if dossier_value != dossier_path:
            errors.append("dossier_path must not contain surrounding whitespace")
        if not re.fullmatch(r"(?:data|docs)/.+", dossier_path):
            errors.append("dossier_path must be a non-empty data/ or docs/ path")

    producer_id = receipt_ids["producer_receipt_id"]
    review_id = receipt_ids["review_receipt_id"]
    adjudication_id = receipt_ids["adjudication_receipt_id"]
    if (review_id or adjudication_id) and not producer_id:
        errors.append("downstream receipts require producer_receipt_id")
    if adjudication_id and not review_id:
        errors.append("adjudication_receipt_id requires review_receipt_id")
    if (producer_id or review_id or adjudication_id) and not dossier_path:
        errors.append("receipt references require dossier_path")
    if dossier_path and not producer_id:
        errors.append("dossier_path requires producer_receipt_id")

    if producer_required and not producer_id:
        errors.append("producer_receipt_id is required at this workflow stage")
    if review_required and not review_id:
        errors.append("review_receipt_id is required at this workflow stage")
    if acceptance_required and not adjudication_id:
        errors.append("adjudication_receipt_id is required for acceptance")

    if validate_references and not acceptance_required and producer_id and dossier_path:
        errors.extend(
            validate_producer_receipt(
                receipts,
                producer_receipt_id=producer_id,
                stage=stage,
                scope_id=scope_id,
                dossier_path=dossier_path,
                subject_sha256=subject_sha256,
            )
        )
    if validate_references and not acceptance_required and review_id:
        errors.extend(
            validate_task_receipt_role(
                receipts,
                receipt_id=review_id,
                role="counter-reviewer",
                stage=stage,
                scope_id=scope_id,
                allowed_statuses={"completed"},
            )
        )
        review_row = receipts.get("by_id", {}).get(review_id)
        if review_row is not None and review_row.get("review_of_receipt_id") != producer_id:
            errors.append("review_receipt_id does not review producer_receipt_id")
    if validate_references and adjudication_id and not acceptance_required:
        errors.extend(
            validate_task_receipt_role(
                receipts,
                receipt_id=adjudication_id,
                role="adjudicator",
                stage=stage,
                scope_id=scope_id,
                allowed_statuses={"accepted", "rework-required", "unresolved"},
            )
        )
        adjudication_row = receipts.get("by_id", {}).get(adjudication_id)
        if (
            adjudication_row is not None
            and adjudication_row.get("review_of_receipt_id") != review_id
        ):
            errors.append("adjudication_receipt_id does not review review_receipt_id")

    chain_errors: list[str] = []
    if acceptance_required:
        chain_errors = validate_receipt_chain(
            receipts,
            producer_receipt_id=producer_id,
            review_receipt_id=review_id,
            adjudication_receipt_id=adjudication_id,
            stage=stage,
            scope_id=scope_id,
            dossier_path=dossier_path,
            subject_sha256=subject_sha256,
        )
        errors.extend(chain_errors)
    return {
        "valid": not errors,
        "producer_receipt_present": bool(producer_id),
        "review_receipt_present": bool(review_id),
        "adjudication_receipt_present": bool(adjudication_id),
        "receipt_chain_accepted": bool(
            acceptance_required
            and receipts.get("valid")
            and not chain_errors
            and not errors
        ),
        "errors": errors,
    }
