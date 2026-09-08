"""Source-derived corpus preparation core. See docs/source-provenance.md."""
from __future__ import annotations
import csv
import hashlib
import json
import os
import re
import sqlite3
import statistics
import tempfile
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "project.json"

ISSUE_HEADER = (
    "issue_id",
    "severity",
    "category",
    "status",
    "source_location",
    "observed",
    "proposal",
    "confidence",
    "evidence_or_next_action",
    "notes",
)

CN_DIGITS = {
    "零": 0,
    "〇": 0,
    "一": 1,
    "二": 2,
    "两": 2,
    "三": 3,
    "四": 4,
    "五": 5,
    "六": 6,
    "七": 7,
    "八": 8,
    "九": 9,
}

CN_UNITS = {"十": 10, "百": 100, "千": 1000, "万": 10000}

NUMERAL_CHARS = "0-9零〇一二两三四五六七八九十百千万"

VOLUME_RE = re.compile(
    rf"^第(?P<number>[{NUMERAL_CHARS}]+)卷(?:\s+(?P<title>.*))?$"
)

CHAPTER_RE = re.compile(
    rf"^第(?P<start>[{NUMERAL_CHARS}]+)章"
    rf"(?:(?:\s*[-—–－~～至]\s*)第?(?P<end>[{NUMERAL_CHARS}]+)章)?"
    rf"(?:\s*(?P<title>.*))?$"
)

HAN_RE = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff]")

class PipelineError(RuntimeError):
    """A validation failure that must stop the pipeline."""

@dataclass
class LineRecord:
    source_line: int
    raw: str
    text: str
    patch_ids: list[str] = field(default_factory=list)
    split_part: int = 0

@dataclass
class Volume:
    volume_id: str
    ordinal: int
    declared_number: int
    title_zh: str
    heading_critical: str
    heading_diplomatic: str
    source_line: int
    record_index: int
    unit_count: int = 0
    patch_ids: list[str] = field(default_factory=list)

@dataclass
class SourceUnit:
    source_unit_id: str
    ordinal: int
    volume_id: str
    volume_number: int
    volume_title_zh: str
    declared_start: int
    declared_end: int
    declared_occurrence: int
    heading_kind: str
    title_zh: str
    heading_critical: str
    heading_diplomatic: str
    source_line_start: int
    source_line_end: int
    paragraph_count: int
    character_count: int
    source_anchor_sha256: str
    critical_sha256: str
    flags: list[str]
    patch_ids: list[str] = field(default_factory=list)

@dataclass
class Paragraph:
    paragraph_id: str
    source_unit_id: str
    ordinal: int
    source_line: int
    zh_diplomatic: str
    zh_critical: str
    diplomatic_sha256: str
    critical_sha256: str
    patch_ids: list[str]

@dataclass
class Corpus:
    volumes: list[Volume]
    units: list[SourceUnit]
    paragraphs: list[Paragraph]
    paratext_paragraphs: list[Paragraph]
    coverage: dict[str, Any]

def structure_signature(volumes: Sequence[Volume], units: Sequence[SourceUnit]) -> str:
    """Lock the ordered structural identity, not merely aggregate counts."""
    payload = {
        "volumes": [
            {
                "ordinal": volume.ordinal,
                "volume_id": volume.volume_id,
                "declared_number": volume.declared_number,
                "title_zh": volume.title_zh,
                "heading_critical": volume.heading_critical,
                "source_line": volume.source_line,
            }
            for volume in volumes
        ],
        "units": [
            {
                "ordinal": unit.ordinal,
                "source_unit_id": unit.source_unit_id,
                "volume_id": unit.volume_id,
                "declared_start": unit.declared_start,
                "declared_end": unit.declared_end,
                "declared_occurrence": unit.declared_occurrence,
                "heading_kind": unit.heading_kind,
                "title_zh": unit.title_zh,
                "heading_critical": unit.heading_critical,
                "source_line_start": unit.source_line_start,
                "source_anchor_sha256": unit.source_anchor_sha256,
            }
            for unit in units
        ],
    }
    serialized = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    return sha256_text(serialized)

def structure_topology_signature(
    volumes: Sequence[Volume], units: Sequence[SourceUnit]
) -> str:
    """Lock ordered structural facts while deliberately excluding wording."""
    payload = {
        "volumes": [
            {
                "ordinal": volume.ordinal,
                "volume_id": volume.volume_id,
                "declared_number": volume.declared_number,
                "source_line": volume.source_line,
            }
            for volume in volumes
        ],
        "units": [
            {
                "ordinal": unit.ordinal,
                "source_unit_id": unit.source_unit_id,
                "volume_id": unit.volume_id,
                "declared_start": unit.declared_start,
                "declared_end": unit.declared_end,
                "declared_occurrence": unit.declared_occurrence,
                "heading_kind": unit.heading_kind,
                "source_line_start": unit.source_line_start,
            }
            for unit in units
        ],
    }
    serialized = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    return sha256_text(serialized)

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()

def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))

def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise PipelineError(f"JSON root must be an object: {path}")
        return value
    except FileNotFoundError as exc:
        raise PipelineError(f"Required file is missing: {path}") from exc
    except json.JSONDecodeError as exc:
        raise PipelineError(f"Invalid JSON in {path}: {exc}") from exc

def atomic_write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    except Exception:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
        raise

def atomic_write_text(path: Path, text: str, *, newline: str = "\n") -> None:
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    if newline != "\n":
        normalized = normalized.replace("\n", newline)
    atomic_write_bytes(path, normalized.encode("utf-8"))

def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    text = "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows)
    atomic_write_text(path, text)

def parse_numeral(value: str) -> int:
    if value.isdigit():
        return int(value)
    total = 0
    section = 0
    number = 0
    for char in value:
        if char in CN_DIGITS:
            number = CN_DIGITS[char]
        elif char in CN_UNITS:
            unit = CN_UNITS[char]
            if unit == 10000:
                total += (section + number) * unit
                section = 0
                number = 0
            else:
                if number == 0:
                    number = 1
                section += number * unit
                number = 0
        else:
            raise PipelineError(f"Unsupported Chinese numeral: {value!r}")
    return total + section + number

def parse_volume_heading(text: str) -> tuple[int, str] | None:
    match = VOLUME_RE.fullmatch(text)
    if not match:
        return None
    return parse_numeral(match.group("number")), (match.group("title") or "").strip()

def parse_chapter_heading(text: str) -> tuple[int, int, str] | None:
    match = CHAPTER_RE.fullmatch(text)
    if not match:
        return None
    start = parse_numeral(match.group("start"))
    end = parse_numeral(match.group("end")) if match.group("end") else start
    if end < start:
        raise PipelineError(f"Descending chapter range: {text}")
    return start, end, (match.group("title") or "").strip()

def load_config() -> dict[str, Any]:
    return load_json(CONFIG_PATH)

def read_and_validate_baseline(
    config: dict[str, Any],
) -> tuple[bytes, str, list[str], dict[str, Any]]:
    source_path = ROOT / config["source_path"]
    raw = source_path.read_bytes()
    expected = config["expected_source"]
    actual_hash = sha256_bytes(raw)
    if actual_hash != expected["sha256"].upper():
        raise PipelineError(
            f"Source hash mismatch: expected {expected['sha256']}, got {actual_hash}"
        )
    if len(raw) != expected["bytes"]:
        raise PipelineError(
            f"Source size mismatch: expected {expected['bytes']}, got {len(raw)}"
        )
    if raw.startswith(b"\xef\xbb\xbf"):
        raise PipelineError("Source unexpectedly contains a UTF-8 BOM")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise PipelineError(f"Source is not strict UTF-8: {exc}") from exc
    crlf_count = text.count("\r\n")
    if crlf_count != expected["crlf_count"]:
        raise PipelineError(
            f"CRLF count mismatch: expected {expected['crlf_count']}, got {crlf_count}"
        )
    without_crlf = text.replace("\r\n", "")
    if "\r" in without_crlf or "\n" in without_crlf:
        raise PipelineError("Source contains a lone CR or LF")
    if not text.endswith("\r\n"):
        raise PipelineError("Source must end with CRLF")
    lines = text[:-2].split("\r\n")
    if len(lines) != crlf_count:
        raise PipelineError("Physical-line reconstruction failed")
    stats = {
        "path": config["source_path"],
        "sha256": actual_hash,
        "bytes": len(raw),
        "physical_lines": len(lines),
        "crlf_count": crlf_count,
        "characters_including_newlines": len(text),
        "characters_excluding_newlines": len(without_crlf),
        "blank_lines": sum(1 for line in lines if line == ""),
        "nonblank_lines": sum(1 for line in lines if line != ""),
        "han_characters": len(HAN_RE.findall(text)),
        "ends_with_crlf": True,
        "utf8_bom": False,
    }
    return raw, text, lines, stats

def validate_patch_ledger(
    patch_doc: dict[str, Any], config: dict[str, Any]
) -> list[dict[str, Any]]:
    if patch_doc.get("schema_version") != 1:
        raise PipelineError("Patch ledger schema_version must be 1")
    if patch_doc.get("application_model") != "line-anchored-first-then-ordered-global":
        raise PipelineError("Patch ledger application_model is missing or unsupported")
    if patch_doc.get("baseline_sha256", "").upper() != config["expected_source"][
        "sha256"
    ].upper():
        raise PipelineError("Patch ledger targets a different baseline hash")
    patches = patch_doc.get("patches")
    if not isinstance(patches, list):
        raise PipelineError("Patch ledger patches must be an array")
    allowed_statuses = {"approved", "proposed", "rejected", "withdrawn"}
    common_keys = {
        "patch_id",
        "issue_id",
        "status",
        "kind",
        "expected",
        "replacement",
        "reason",
        "depends_on",
    }
    issues_path = ROOT / "data" / "editorial" / "issues.tsv"
    try:
        with issues_path.open("r", encoding="utf-8", newline="") as handle:
            raw_issue_rows = list(csv.reader(handle, delimiter="\t"))
    except FileNotFoundError as exc:
        raise PipelineError(f"Issue ledger is missing: {issues_path}") from exc
    if not raw_issue_rows or tuple(raw_issue_rows[0]) != ISSUE_HEADER:
        raise PipelineError("Issue ledger header does not match the required schema")
    known_issue_ids: set[str] = set()
    for line_number, values in enumerate(raw_issue_rows[1:], start=2):
        if len(values) != len(ISSUE_HEADER):
            raise PipelineError(
                f"Issue ledger line {line_number} has {len(values)} fields, expected {len(ISSUE_HEADER)}"
            )
        issue_id = values[0]
        if not re.fullmatch(r"ISSUE-[A-Z0-9-]+", issue_id):
            raise PipelineError(
                f"Issue ledger line {line_number} has invalid issue_id {issue_id!r}"
            )
        if issue_id in known_issue_ids:
            raise PipelineError(f"Duplicate issue ID: {issue_id}")
        known_issue_ids.add(issue_id)
    seen_ids: set[str] = set()
    approved_ids_in_order: list[str] = []
    approved: list[dict[str, Any]] = []
    anchored_lines: set[int] = set()
    for index, patch in enumerate(patches, start=1):
        prefix = f"patch record {index}"
        if not isinstance(patch, dict):
            raise PipelineError(f"{prefix} must be an object")
        patch_id = patch.get("patch_id")
        if not isinstance(patch_id, str) or not patch_id:
            raise PipelineError(f"{prefix}: patch_id must be a non-empty string")
        if patch_id in seen_ids:
            raise PipelineError(f"Duplicate patch ID: {patch_id}")
        seen_ids.add(patch_id)
        if not isinstance(patch.get("issue_id"), str) or not patch["issue_id"]:
            raise PipelineError(f"{patch_id}: issue_id must be a non-empty string")
        if patch["issue_id"] not in known_issue_ids:
            raise PipelineError(
                f"{patch_id}: unknown issue_id {patch['issue_id']!r}"
            )
        status = patch.get("status")
        if status not in allowed_statuses:
            raise PipelineError(f"{patch_id}: unsupported status {status!r}")
        kind = patch.get("kind")
        if kind not in {"replace_line", "replace_text", "replace_global"}:
            raise PipelineError(f"{patch_id}: unsupported patch kind {kind!r}")
        allowed_keys = set(common_keys)
        if kind in {"replace_line", "replace_text"}:
            allowed_keys.add("source_line")
        if kind in {"replace_text", "replace_global"}:
            allowed_keys.add("expected_occurrences")
        extra_keys = sorted(set(patch) - allowed_keys)
        if extra_keys:
            raise PipelineError(f"{patch_id}: unexpected fields {extra_keys}")
        if not isinstance(patch.get("expected"), str) or not patch["expected"]:
            raise PipelineError(f"{patch_id}: expected must be a non-empty string")
        if not isinstance(patch.get("reason"), str) or not patch["reason"].strip():
            raise PipelineError(f"{patch_id}: reason must be a non-empty string")
        dependencies = patch.get("depends_on", [])
        if not isinstance(dependencies, list) or not all(
            isinstance(value, str) and value for value in dependencies
        ):
            raise PipelineError(f"{patch_id}: depends_on must be an array of patch IDs")
        if len(dependencies) != len(set(dependencies)):
            raise PipelineError(f"{patch_id}: duplicate depends_on entries")
        if kind != "replace_global" and dependencies:
            raise PipelineError(
                f"{patch_id}: depends_on is only supported for ordered global patches"
            )
        unknown_or_forward = [
            dependency
            for dependency in dependencies
            if dependency not in approved_ids_in_order
        ]
        if status == "approved" and unknown_or_forward:
            raise PipelineError(
                f"{patch_id}: dependencies must name earlier approved patches: "
                f"{unknown_or_forward}"
            )
        if kind == "replace_line":
            replacements = patch.get("replacement")
            if not isinstance(replacements, list) or not all(
                isinstance(value, str) for value in replacements
            ):
                raise PipelineError(
                    f"{patch_id}: replace_line replacement must be an array of strings"
                )
        else:
            if not isinstance(patch.get("replacement"), str) or not patch["replacement"]:
                raise PipelineError(
                    f"{patch_id}: text replacement must be a non-empty string"
                )
            if patch["replacement"] == patch["expected"]:
                raise PipelineError(f"{patch_id}: replacement is identical to expected")
            occurrences = patch.get("expected_occurrences")
            if not isinstance(occurrences, int) or isinstance(occurrences, bool) or occurrences < 1:
                raise PipelineError(
                    f"{patch_id}: expected_occurrences must be a positive integer"
                )
        if kind in {"replace_line", "replace_text"}:
            source_line = patch.get("source_line")
            if (
                not isinstance(source_line, int)
                or isinstance(source_line, bool)
                or not 1 <= source_line <= config["expected_source"]["crlf_count"]
            ):
                raise PipelineError(f"{patch_id}: invalid source_line {source_line!r}")
            if status == "approved" and source_line in anchored_lines:
                raise PipelineError(
                    f"{patch_id}: source line {source_line} already has an anchored patch; "
                    "combine the edits so the immutable baseline has one anchor"
                )
            if status == "approved":
                anchored_lines.add(source_line)
        if status == "approved":
            approved.append(patch)
            approved_ids_in_order.append(patch_id)
    return approved

def apply_patches(
    original_lines: list[str], config: dict[str, Any]
) -> tuple[list[LineRecord], list[dict[str, Any]]]:
    patch_doc = load_json(ROOT / config["patches_path"])
    approved = validate_patch_ledger(patch_doc, config)
    records = [
        LineRecord(source_line=index, raw=line, text=line)
        for index, line in enumerate(original_lines, start=1)
    ]
    patch_log: list[dict[str, Any]] = []

    # Line-anchored changes are evaluated before corpus-wide exact phrases.
    for patch in (p for p in approved if p["kind"] != "replace_global"):
        patch_id = patch["patch_id"]
        source_line = int(patch["source_line"])
        indexes = [i for i, record in enumerate(records) if record.source_line == source_line]
        if len(indexes) != 1:
            raise PipelineError(
                f"{patch_id}: expected one record for source line {source_line}, got {len(indexes)}"
            )
        index = indexes[0]
        record = records[index]
        kind = patch["kind"]
        if kind == "replace_line":
            if record.raw != patch["expected"] or record.text != patch["expected"]:
                raise PipelineError(
                    f"{patch_id}: line {source_line} anchor mismatch: {record.text!r}"
                )
            replacements = patch["replacement"]
            new_records = [
                LineRecord(
                    source_line=source_line,
                    raw=record.raw,
                    text=value,
                    patch_ids=record.patch_ids + [patch_id],
                    split_part=part,
                )
                for part, value in enumerate(replacements)
            ]
            records[index : index + 1] = new_records
            applied_occurrences = 1
            output_records = len(new_records)
        elif kind == "replace_text":
            expected_count = int(patch.get("expected_occurrences", 1))
            actual_count = record.text.count(patch["expected"])
            if actual_count != expected_count:
                raise PipelineError(
                    f"{patch_id}: line {source_line} expected {expected_count} occurrences, got {actual_count}"
                )
            record.text = record.text.replace(patch["expected"], patch["replacement"])
            record.patch_ids.append(patch_id)
            applied_occurrences = actual_count
            output_records = 1
        else:
            raise PipelineError(f"{patch_id}: unsupported patch kind {kind}")
        patch_log.append(
            {
                "patch_id": patch_id,
                "issue_id": patch.get("issue_id", ""),
                "kind": kind,
                "source_line": source_line,
                "applied_occurrences": applied_occurrences,
                "output_records": output_records,
                "reason": patch.get("reason", ""),
            }
        )

    initial_global_counts = {
        patch["patch_id"]: sum(
            record.text.count(patch["expected"]) for record in records
        )
        for patch in approved
        if patch["kind"] == "replace_global"
    }
    applied_patch_ids = {entry["patch_id"] for entry in patch_log}
    for patch in (p for p in approved if p["kind"] == "replace_global"):
        patch_id = patch["patch_id"]
        expected_count = int(patch["expected_occurrences"])
        dependencies = patch.get("depends_on", [])
        unapplied_dependencies = [
            dependency for dependency in dependencies if dependency not in applied_patch_ids
        ]
        if unapplied_dependencies:
            raise PipelineError(
                f"{patch_id}: dependencies were not applied: {unapplied_dependencies}"
            )
        if not dependencies and initial_global_counts[patch_id] != expected_count:
            raise PipelineError(
                f"{patch_id}: expected count differs from the initial global layer; "
                "declare the earlier patch dependency explicitly"
            )
        actual_count = sum(record.text.count(patch["expected"]) for record in records)
        if actual_count != expected_count:
            raise PipelineError(
                f"{patch_id}: expected {expected_count} global occurrences of "
                f"{patch['expected']!r}, got {actual_count}"
            )
        touched_lines = 0
        for record in records:
            if patch["expected"] in record.text:
                record.text = record.text.replace(patch["expected"], patch["replacement"])
                record.patch_ids.append(patch_id)
                touched_lines += 1
        patch_log.append(
            {
                "patch_id": patch_id,
                "issue_id": patch.get("issue_id", ""),
                "kind": "replace_global",
                "source_line": None,
                "applied_occurrences": actual_count,
                "touched_lines": touched_lines,
                "reason": patch.get("reason", ""),
            }
        )
        applied_patch_ids.add(patch_id)

    return records, patch_log

def segment_corpus(
    records: list[LineRecord], original_lines: list[str], config: dict[str, Any]
) -> Corpus:
    volume_markers: list[tuple[int, LineRecord, int, str]] = []
    chapter_markers: list[tuple[int, LineRecord, int, int, str]] = []
    structural_indexes: list[int] = []
    current_volume_number: int | None = None

    for index, record in enumerate(records):
        volume = parse_volume_heading(record.text)
        if volume:
            current_volume_number = volume[0]
            volume_markers.append((index, record, volume[0], volume[1]))
            structural_indexes.append(index)
            continue
        chapter = parse_chapter_heading(record.text)
        if chapter:
            if current_volume_number is None:
                raise PipelineError(
                    f"Chapter before first volume at source line {record.source_line}"
                )
            chapter_markers.append((index, record, chapter[0], chapter[1], chapter[2]))
            structural_indexes.append(index)

    volumes: list[Volume] = []
    for ordinal, (index, record, number, title) in enumerate(volume_markers, start=1):
        volumes.append(
            Volume(
                volume_id=f"V{number:02d}",
                ordinal=ordinal,
                declared_number=number,
                title_zh=title,
                heading_critical=record.text,
                heading_diplomatic=original_lines[record.source_line - 1],
                source_line=record.source_line,
                record_index=index,
                patch_ids=list(record.patch_ids),
            )
        )
    volume_by_index = sorted(volumes, key=lambda item: item.record_index)

    expected_structure = config["expected_structure"]
    if len(volumes) != expected_structure["volumes"]:
        raise PipelineError(
            f"Expected {expected_structure['volumes']} volumes, parsed {len(volumes)}"
        )
    if [v.declared_number for v in volumes] != list(
        range(1, expected_structure["volumes"] + 1)
    ):
        raise PipelineError("Volume numbers are not continuous from 1")
    if len(chapter_markers) != expected_structure["source_units"]:
        raise PipelineError(
            f"Expected {expected_structure['source_units']} source units, parsed {len(chapter_markers)}"
        )

    all_structural = sorted(set(structural_indexes))
    next_structural: dict[int, int] = {}
    for left, right in zip(all_structural, all_structural[1:]):
        next_structural[left] = right
    next_structural[all_structural[-1]] = len(records)

    number_frequency = Counter(marker[2] for marker in chapter_markers)
    number_seen: Counter[int] = Counter()
    units: list[SourceUnit] = []
    paragraphs: list[Paragraph] = []
    paratext_paragraphs: list[Paragraph] = []
    paratext_indexes = {
        index
        for index in range(all_structural[0])
        if records[index].text != ""
    }
    for ordinal, record_index in enumerate(sorted(paratext_indexes), start=1):
        record = records[record_index]
        diplomatic = original_lines[record.source_line - 1]
        paratext_paragraphs.append(
            Paragraph(
                paragraph_id=f"PT-000001-P{ordinal:04d}",
                source_unit_id="PT-000001",
                ordinal=ordinal,
                source_line=record.source_line,
                zh_diplomatic=diplomatic,
                zh_critical=record.text,
                diplomatic_sha256=sha256_text(diplomatic),
                critical_sha256=sha256_text(record.text),
                patch_ids=record.patch_ids,
            )
        )
    assigned_body_indexes: set[int] = set()
    volume_lookup: dict[str, Volume] = {volume.volume_id: volume for volume in volumes}

    for ordinal, (index, heading_record, start, end, title) in enumerate(
        chapter_markers, start=1
    ):
        applicable = [volume for volume in volume_by_index if volume.record_index < index]
        if not applicable:
            raise PipelineError(
                f"Cannot assign volume to source line {heading_record.source_line}"
            )
        volume = applicable[-1]
        number_seen[start] += 1
        occurrence = number_seen[start]
        body_record_indexes = range(index + 1, next_structural[index])
        assigned_body_indexes.update(
            record_index
            for record_index in body_record_indexes
            if records[record_index].text != ""
        )
        body_records = records[index + 1 : next_structural[index]]
        while body_records and body_records[0].text == "":
            body_records = body_records[1:]
        while body_records and body_records[-1].text == "":
            body_records = body_records[:-1]
        nonblank_body = [record for record in body_records if record.text != ""]
        source_line_end = (
            max(record.source_line for record in nonblank_body)
            if nonblank_body
            else heading_record.source_line
        )
        unit_id = f"SU-{ordinal:06d}"
        unit_paragraphs: list[Paragraph] = []
        for paragraph_ordinal, record in enumerate(nonblank_body, start=1):
            diplomatic = original_lines[record.source_line - 1]
            paragraph = Paragraph(
                paragraph_id=f"{unit_id}-P{paragraph_ordinal:04d}",
                source_unit_id=unit_id,
                ordinal=paragraph_ordinal,
                source_line=record.source_line,
                zh_diplomatic=diplomatic,
                zh_critical=record.text,
                diplomatic_sha256=sha256_text(diplomatic),
                critical_sha256=sha256_text(record.text),
                patch_ids=record.patch_ids,
            )
            unit_paragraphs.append(paragraph)
            paragraphs.append(paragraph)
        flags: list[str] = []
        if end > start:
            heading_kind = "range"
            flags.append("composite-range")
        elif number_frequency[start] > 1:
            heading_kind = "repeated-number"
            flags.append("repeated-declared-number")
        else:
            heading_kind = "normal"
        if not title and end == start:
            flags.append("missing-title")
        critical_block = "\n".join(
            [heading_record.text] + [record.text for record in body_records]
        )
        source_anchor = original_lines[heading_record.source_line - 1]
        units.append(
            SourceUnit(
                source_unit_id=unit_id,
                ordinal=ordinal,
                volume_id=volume.volume_id,
                volume_number=volume.declared_number,
                volume_title_zh=volume.title_zh,
                declared_start=start,
                declared_end=end,
                declared_occurrence=occurrence,
                heading_kind=heading_kind,
                title_zh=title,
                heading_critical=heading_record.text,
                heading_diplomatic=source_anchor,
                source_line_start=heading_record.source_line,
                source_line_end=source_line_end,
                paragraph_count=len(unit_paragraphs),
                character_count=sum(len(p.zh_critical.strip()) for p in unit_paragraphs),
                source_anchor_sha256=sha256_text(source_anchor),
                critical_sha256=sha256_text(critical_block),
                flags=flags,
                patch_ids=list(heading_record.patch_ids),
            )
        )
        volume_lookup[volume.volume_id].unit_count += 1

    last_declared = expected_structure["last_declared_chapter"]
    coverage_counter: Counter[int] = Counter()
    for unit in units:
        coverage_counter.update(range(unit.declared_start, unit.declared_end + 1))
    missing = [number for number in range(1, last_declared + 1) if not coverage_counter[number]]
    repeated = [
        number for number in range(1, last_declared + 1) if coverage_counter[number] > 1
    ]
    out_of_range = sorted(
        number for number in coverage_counter if number < 1 or number > last_declared
    )
    coverage = {
        "first_declared_chapter": min(coverage_counter),
        "last_declared_chapter": max(coverage_counter),
        "missing_declared_numbers_after_range_expansion": missing,
        "repeated_declared_numbers_after_range_expansion": repeated,
        "out_of_range_declared_numbers": out_of_range,
        "logical_number_slots_counting_ranges_and_repeats": sum(coverage_counter.values()),
        "unique_declared_numbers": len(coverage_counter),
    }
    expected_repeated = expected_structure["repeated_declared_numbers"]
    if missing:
        raise PipelineError(f"Critical structure still has missing chapter numbers: {missing}")
    if repeated != expected_repeated:
        raise PipelineError(
            f"Repeated critical chapter numbers differ: expected {expected_repeated}, got {repeated}"
        )
    if out_of_range:
        raise PipelineError(f"Out-of-range chapter numbers: {out_of_range}")
    if units[-1].declared_end != last_declared:
        raise PipelineError(
            f"Last source unit is {units[-1].declared_end}, expected {last_declared}"
        )
    actual_ranges = [
        [unit.declared_start, unit.declared_end]
        for unit in units
        if unit.declared_end > unit.declared_start
    ]
    if actual_ranges != expected_structure["composite_ranges"]:
        raise PipelineError(
            f"Composite ranges differ: expected {expected_structure['composite_ranges']}, "
            f"got {actual_ranges}"
        )
    for previous, current in zip(units, units[1:]):
        advances = current.declared_start == previous.declared_end + 1
        explicit_repeat = (
            previous.declared_start == previous.declared_end
            and current.declared_start == current.declared_end
            and current.declared_start == previous.declared_start
        )
        if not advances and not explicit_repeat:
            raise PipelineError(
                "Chapter sequence is not monotonic at "
                f"{previous.source_unit_id}/{current.source_unit_id}: "
                f"{previous.declared_start}-{previous.declared_end} -> "
                f"{current.declared_start}-{current.declared_end}"
            )
    actual_volume_counts = [volume.unit_count for volume in volumes]
    if actual_volume_counts != expected_structure["volume_unit_counts"]:
        raise PipelineError(
            f"Volume unit counts differ: expected {expected_structure['volume_unit_counts']}, "
            f"got {actual_volume_counts}"
        )
    signature = structure_signature(volumes, units)
    coverage["structure_signature_sha256"] = signature
    coverage["topology_signature_sha256"] = structure_topology_signature(
        volumes, units
    )
    expected_signature = expected_structure.get("structure_signature_sha256")
    if not isinstance(expected_signature, str) or not re.fullmatch(
        r"[A-F0-9]{64}", expected_signature
    ):
        raise PipelineError(
            "project.json expected_structure.structure_signature_sha256 "
            "must be a required uppercase SHA-256"
        )
    if signature != expected_signature:
        raise PipelineError(
            f"Ordered structure signature mismatch: expected {expected_signature}, got {signature}"
        )
    classified_nonblank = set(structural_indexes) | paratext_indexes | assigned_body_indexes
    unassigned_nonblank = [
        (index, record)
        for index, record in enumerate(records)
        if record.text != "" and index not in classified_nonblank
    ]
    if unassigned_nonblank:
        sample = [
            {"source_line": record.source_line, "text": record.text[:80]}
            for _, record in unassigned_nonblank[:5]
        ]
        raise PipelineError(f"Nonblank records escaped classification: {sample}")
    coverage["classified_nonblank_records"] = len(classified_nonblank)
    coverage["unassigned_nonblank_records"] = 0
    return Corpus(
        volumes=volumes,
        units=units,
        paragraphs=paragraphs,
        paratext_paragraphs=paratext_paragraphs,
        coverage=coverage,
    )

def create_sqlite_index(
    path: Path,
    corpus: Corpus,
    audit: dict[str, Any],
    critical_sha256: str,
    input_fingerprint: str,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    os.close(fd)
    temp_path = Path(temp_name)
    connection: sqlite3.Connection | None = None
    expected_search_documents = (
        len(corpus.paratext_paragraphs)
        + len(corpus.volumes)
        + len(corpus.units)
        + len(corpus.paragraphs)
    )
    try:
        connection = sqlite3.connect(temp_path)
        connection.executescript(
            """
            PRAGMA journal_mode=OFF;
            PRAGMA synchronous=OFF;
            CREATE TABLE metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE volumes (
                volume_id TEXT PRIMARY KEY,
                ordinal INTEGER NOT NULL,
                declared_number INTEGER NOT NULL,
                title_zh TEXT NOT NULL,
                heading_critical TEXT NOT NULL,
                source_line INTEGER NOT NULL,
                unit_count INTEGER NOT NULL
            );
            CREATE TABLE source_units (
                source_unit_id TEXT PRIMARY KEY,
                ordinal INTEGER NOT NULL,
                volume_id TEXT NOT NULL,
                declared_start INTEGER NOT NULL,
                declared_end INTEGER NOT NULL,
                declared_occurrence INTEGER NOT NULL,
                heading_kind TEXT NOT NULL,
                title_zh TEXT NOT NULL,
                heading_critical TEXT NOT NULL,
                source_line_start INTEGER NOT NULL,
                source_line_end INTEGER NOT NULL,
                paragraph_count INTEGER NOT NULL,
                character_count INTEGER NOT NULL,
                critical_sha256 TEXT NOT NULL,
                flags_json TEXT NOT NULL,
                FOREIGN KEY(volume_id) REFERENCES volumes(volume_id)
            );
            CREATE TABLE paragraphs (
                paragraph_id TEXT PRIMARY KEY,
                source_unit_id TEXT NOT NULL,
                ordinal INTEGER NOT NULL,
                source_line INTEGER NOT NULL,
                zh_diplomatic TEXT NOT NULL,
                zh_critical TEXT NOT NULL,
                diplomatic_sha256 TEXT NOT NULL,
                critical_sha256 TEXT NOT NULL,
                patch_ids_json TEXT NOT NULL,
                FOREIGN KEY(source_unit_id) REFERENCES source_units(source_unit_id)
            );
            CREATE INDEX paragraphs_source_line_idx ON paragraphs(source_line);
            CREATE INDEX paragraphs_unit_idx ON paragraphs(source_unit_id, ordinal);
            CREATE INDEX units_declared_idx ON source_units(declared_start, declared_occurrence);
            CREATE TABLE search_documents (
                document_id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                stable_id TEXT NOT NULL,
                source_unit_id TEXT,
                volume_id TEXT,
                source_line INTEGER NOT NULL,
                text_critical TEXT NOT NULL
            );
            CREATE INDEX search_documents_kind_idx ON search_documents(kind);
            CREATE INDEX search_documents_line_idx ON search_documents(source_line);
            CREATE VIRTUAL TABLE search_fts USING fts5(
                document_id UNINDEXED,
                text_critical,
                tokenize='trigram'
            );
            """
        )
        connection.executemany(
            "INSERT INTO metadata(key, value) VALUES (?, ?)",
            [
                ("source_sha256", audit["source"]["sha256"]),
                ("critical_sha256", critical_sha256),
                ("input_fingerprint", input_fingerprint),
                ("source_units", str(len(corpus.units))),
                ("paragraphs", str(len(corpus.paragraphs))),
                ("paratext_paragraphs", str(len(corpus.paratext_paragraphs))),
                ("search_documents", str(expected_search_documents)),
                ("generated_at", audit["generated_at"]),
            ],
        )
        connection.executemany(
            """
            INSERT INTO volumes(
                volume_id, ordinal, declared_number, title_zh,
                heading_critical, source_line, unit_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    volume.volume_id,
                    volume.ordinal,
                    volume.declared_number,
                    volume.title_zh,
                    volume.heading_critical,
                    volume.source_line,
                    volume.unit_count,
                )
                for volume in corpus.volumes
            ],
        )
        connection.executemany(
            """
            INSERT INTO source_units(
                source_unit_id, ordinal, volume_id, declared_start, declared_end,
                declared_occurrence, heading_kind, title_zh, heading_critical,
                source_line_start, source_line_end, paragraph_count,
                character_count, critical_sha256, flags_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    unit.source_unit_id,
                    unit.ordinal,
                    unit.volume_id,
                    unit.declared_start,
                    unit.declared_end,
                    unit.declared_occurrence,
                    unit.heading_kind,
                    unit.title_zh,
                    unit.heading_critical,
                    unit.source_line_start,
                    unit.source_line_end,
                    unit.paragraph_count,
                    unit.character_count,
                    unit.critical_sha256,
                    json.dumps(unit.flags, ensure_ascii=False),
                )
                for unit in corpus.units
            ],
        )
        paragraph_rows = [
            (
                paragraph.paragraph_id,
                paragraph.source_unit_id,
                paragraph.ordinal,
                paragraph.source_line,
                paragraph.zh_diplomatic,
                paragraph.zh_critical,
                paragraph.diplomatic_sha256,
                paragraph.critical_sha256,
                json.dumps(paragraph.patch_ids, ensure_ascii=False),
            )
            for paragraph in corpus.paragraphs
        ]
        connection.executemany(
            """
            INSERT INTO paragraphs(
                paragraph_id, source_unit_id, ordinal, source_line,
                zh_diplomatic, zh_critical, diplomatic_sha256,
                critical_sha256, patch_ids_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            paragraph_rows,
        )
        unit_by_id = {unit.source_unit_id: unit for unit in corpus.units}
        search_rows: list[tuple[str, str, str, str | None, str | None, int, str]] = []
        search_rows.extend(
            (
                paragraph.paragraph_id,
                "paratext",
                paragraph.paragraph_id,
                None,
                None,
                paragraph.source_line,
                paragraph.zh_critical,
            )
            for paragraph in corpus.paratext_paragraphs
        )
        search_rows.extend(
            (
                f"{volume.volume_id}-H",
                "volume-heading",
                volume.volume_id,
                None,
                volume.volume_id,
                volume.source_line,
                volume.heading_critical,
            )
            for volume in corpus.volumes
        )
        search_rows.extend(
            (
                f"{unit.source_unit_id}-H",
                "chapter-heading",
                unit.source_unit_id,
                unit.source_unit_id,
                unit.volume_id,
                unit.source_line_start,
                unit.heading_critical,
            )
            for unit in corpus.units
        )
        search_rows.extend(
            (
                paragraph.paragraph_id,
                "paragraph",
                paragraph.paragraph_id,
                paragraph.source_unit_id,
                unit_by_id[paragraph.source_unit_id].volume_id,
                paragraph.source_line,
                paragraph.zh_critical,
            )
            for paragraph in corpus.paragraphs
        )
        connection.executemany(
            """
            INSERT INTO search_documents(
                document_id, kind, stable_id, source_unit_id, volume_id,
                source_line, text_critical
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            search_rows,
        )
        connection.executemany(
            "INSERT INTO search_fts(document_id, text_critical) VALUES (?, ?)",
            [(row[0], row[6]) for row in search_rows],
        )
        if len(search_rows) != expected_search_documents:
            raise PipelineError(
                "Internal search-document count differs from the declared metadata"
            )
        connection.commit()
        connection.execute("PRAGMA optimize")
        connection.close()
        connection = None
        os.replace(temp_path, path)
    except Exception:
        if connection is not None:
            try:
                connection.rollback()
            finally:
                connection.close()
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass
        raise

def inspect_search_index(
    path: Path,
    *,
    expected_input_fingerprint: str | None,
    expected_critical_sha256: str | None,
    expected_source_units: int | None,
    expected_paragraphs: int | None,
    expected_search_documents: int | None,
) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    connection: sqlite3.Connection | None = None
    metadata: dict[str, str] = {}
    counts: dict[str, int] = {}
    try:
        connection = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
        quick_check = connection.execute("PRAGMA quick_check").fetchone()[0]
        if quick_check != "ok":
            errors.append(f"SQLite quick_check returned {quick_check!r}")
        foreign_key_errors = connection.execute("PRAGMA foreign_key_check").fetchall()
        if foreign_key_errors:
            errors.append(f"SQLite foreign_key_check returned {len(foreign_key_errors)} rows")
        metadata = dict(connection.execute("SELECT key, value FROM metadata").fetchall())
        counts = {
            "source_units": connection.execute(
                "SELECT count(*) FROM source_units"
            ).fetchone()[0],
            "paragraphs": connection.execute(
                "SELECT count(*) FROM paragraphs"
            ).fetchone()[0],
            "search_documents": connection.execute(
                "SELECT count(*) FROM search_documents"
            ).fetchone()[0],
            "search_fts": connection.execute(
                "SELECT count(*) FROM search_fts"
            ).fetchone()[0],
        }
    except (OSError, sqlite3.Error) as exc:
        errors.append(f"Search index cannot be validated: {exc}")
    finally:
        if connection is not None:
            connection.close()

    expected_pairs = {
        "input_fingerprint": expected_input_fingerprint,
        "critical_sha256": expected_critical_sha256,
        "source_units": expected_source_units,
        "paragraphs": expected_paragraphs,
        "search_documents": expected_search_documents,
    }
    for key, expected in expected_pairs.items():
        if expected is None:
            errors.append(f"Expected search-index value is missing: {key}")
            continue
        if metadata.get(key) != str(expected):
            errors.append(
                f"Search-index metadata mismatch for {key}: "
                f"expected {expected!r}, got {metadata.get(key)!r}"
            )
    for key in ("source_units", "paragraphs", "search_documents"):
        if key in counts and metadata.get(key) != str(counts[key]):
            errors.append(
                f"Search-index row count mismatch for {key}: "
                f"metadata={metadata.get(key)!r}, rows={counts[key]}"
            )
    if counts.get("search_documents") != counts.get("search_fts"):
        errors.append(
            "Search FTS row count differs from the searchable-document row count"
        )
    return {
        "valid": not errors,
        "path": str(path),
        "metadata": metadata,
        "counts": counts,
        "errors": errors,
    }

def chinese_alignment_scopes(corpus: Corpus) -> list[dict[str, str]]:
    """Return the complete, ordered Chinese review surface.

    Review is deliberately tracked at physical-source-unit granularity.  This
    avoids pretending that display chapter numbers are unique identifiers and
    keeps the front matter inside the completeness calculation.
    """
    paratext_payload = [
        {
            "paragraph_id": paragraph.paragraph_id,
            "zh_critical": paragraph.zh_critical,
        }
        for paragraph in corpus.paratext_paragraphs
    ]
    scopes = [
        {
            "scope_id": "PT-000001",
            "kind": "paratext",
            "volume_id": "",
            "declared_chapter": "",
            "declared_occurrence": "",
            "source_critical_sha256": sha256_text(
                json.dumps(
                    paratext_payload,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
            ),
        }
    ]
    units_by_volume: defaultdict[str, list[SourceUnit]] = defaultdict(list)
    for unit in corpus.units:
        units_by_volume[unit.volume_id].append(unit)
    for volume in corpus.volumes:
        scopes.append(
            {
                "scope_id": volume.volume_id,
                "kind": "volume-heading",
                "volume_id": volume.volume_id,
                "declared_chapter": "",
                "declared_occurrence": "",
                "source_critical_sha256": sha256_text(volume.heading_critical),
            }
        )
        scopes.extend(
            {
                "scope_id": unit.source_unit_id,
                "kind": "source-unit",
                "volume_id": unit.volume_id,
                "declared_chapter": (
                    str(unit.declared_start)
                    if unit.declared_start == unit.declared_end
                    else f"{unit.declared_start}-{unit.declared_end}"
                ),
                "declared_occurrence": str(unit.declared_occurrence),
                "source_critical_sha256": unit.critical_sha256,
            }
            for unit in units_by_volume[volume.volume_id]
        )
    return scopes

