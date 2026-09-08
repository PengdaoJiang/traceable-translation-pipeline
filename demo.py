"""Public fixture for the unchanged source-derived corpus and receipt functions."""
from __future__ import annotations

import argparse
import csv
import importlib.util
import json
import shutil
import sys
from dataclasses import asdict
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load_core(root: Path):
    name = "public_translation_core"
    spec = importlib.util.spec_from_file_location(name, root / "translation_core/corpus.py")
    core = importlib.util.module_from_spec(spec)
    sys.modules[name] = core
    spec.loader.exec_module(core)
    return core


def make_fixture(root: Path):
    root.mkdir(parents=True, exist_ok=False)
    (root / "translation_core").mkdir()
    shutil.copyfile(HERE / "translation_core/corpus.py", root / "translation_core/corpus.py")
    core = load_core(root)
    lines = ["白塔札记：原创测试文本。", "第一卷 河岸", "第一章 灯火", "灯火映者河面。",
             "第一章 来客", "旅人把铜铃放在窗前。", "第二章-第三章 夜航", "船在晨雾中离岸。"]
    raw = ("\r\n".join(lines) + "\r\n").encode("utf-8")
    (root / "source").mkdir()
    (root / "source/demo.txt").write_bytes(raw)
    # Independent, authored structural manifest. Never accepted from the parser's
    # own output or automatically refreshed on a failed comparison.
    manifest = {"volumes": [{"ordinal": 1, "volume_id": "V01", "declared_number": 1,
        "title_zh": "河岸", "heading_critical": lines[1], "source_line": 2}], "units": []}
    for ordinal, (line_number, start, end, occurrence, kind, title) in enumerate(
        [(3, 1, 1, 1, "repeated-number", "灯火"), (5, 1, 1, 2, "repeated-number", "来客"),
         (7, 2, 3, 1, "range", "夜航")], 1):
        heading = lines[line_number - 1]
        manifest["units"].append({"ordinal": ordinal, "source_unit_id": f"SU-{ordinal:06d}", "volume_id": "V01",
            "declared_start": start, "declared_end": end, "declared_occurrence": occurrence, "heading_kind": kind,
            "title_zh": title, "heading_critical": heading, "source_line_start": line_number,
            "source_anchor_sha256": core.sha256_text(heading)})
    config = {"source_path": "source/demo.txt", "patches_path": "data/editorial/patches.json",
        "expected_source": {"sha256": core.sha256_bytes(raw), "bytes": len(raw), "crlf_count": len(lines)},
        "expected_structure": {"volumes": 1, "source_units": 3, "last_declared_chapter": 3,
            "repeated_declared_numbers": [1], "composite_ranges": [[2, 3]], "volume_unit_counts": [3],
            "structure_signature_sha256": core.sha256_text(json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")))}}
    (root / "project.json").write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")
    editorial = root / "data/editorial"
    editorial.mkdir(parents=True)
    with (editorial / "issues.tsv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, delimiter="\t")
        writer.writerow(core.ISSUE_HEADER)
        writer.writerow(["ISSUE-DEMO-001", "minor", "typo", "synthetic_fixture", "line 4",
            "映者", "映着", "fixture", "Original test sentence", "Not a historical editorial decision"])
    patch = {"patch_id": "PATCH-DEMO-001", "issue_id": "ISSUE-DEMO-001", "status": "approved",
        "kind": "replace_text", "source_line": 4, "expected": "映者", "replacement": "映着",
        "expected_occurrences": 1, "reason": "Synthetic approved-patch fixture on original test prose", "depends_on": []}
    (editorial / "patches.json").write_text(json.dumps({"schema_version": 1,
        "application_model": "line-anchored-first-then-ordered-global",
        "baseline_sha256": config["expected_source"]["sha256"], "patches": [patch]}, ensure_ascii=False, indent=2), encoding="utf-8")
    return core, config


def make_receipts(root: Path, subject: str):
    from translation_core import governance
    folder = root / "data/governance"
    folder.mkdir(parents=True, exist_ok=True)
    rows, prior_id, prior_hash = [], "", subject
    for index, role in enumerate(("producer", "counter-reviewer", "adjudicator"), 1):
        path = f"data/governance/fixture-{index}.md"
        body = f"# Synthetic {role} fixture\n\nThis is test data, not a real editorial review.\n"
        if index == 1:
            body += f"\nsubject_sha256: {subject}\n"
        (root / path).write_text(body, encoding="utf-8", newline="\n")
        output_hash = governance._sha256_bytes((root / path).read_bytes())
        receipt_id = f"RCP-20000101-{index:04d}"
        rows.append([receipt_id, f"/root/fixture_{index}", role, "M1", "demo-scope", prior_hash,
            path, output_hash, prior_id, "full-context", "accepted" if index == 3 else "completed",
            f"2000-01-01T00:00:0{index}Z", "Synthetic record; no actual task attestation"])
        prior_id, prior_hash = receipt_id, output_hash
    receipt_path = folder / "task-receipts.tsv"
    with receipt_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, delimiter="\t")
        writer.writerow(governance.TASK_RECEIPT_HEADER)
        writer.writerows(rows)
    registry = governance.validate_task_receipts(receipt_path, workspace_root=root)
    chain = governance.resolve_accepted_receipt_scope(registry, stage="M1", scope_id="demo-scope", subject_sha256=subject)
    return registry, chain


def run(root: Path):
    core, config = make_fixture(root)
    raw, _, lines, source = core.read_and_validate_baseline(config)
    records, patch_log = core.apply_patches(lines, config)
    corpus = core.segment_corpus(records, lines, config)
    critical = "\r\n".join(record.text for record in records) + "\r\n"
    critical_hash = core.sha256_text(critical)
    fingerprint = core.sha256_bytes((root / "project.json").read_bytes() + (root / config["patches_path"]).read_bytes())
    build = root / "build"
    build.mkdir()
    (build / "zh-critical.txt").write_bytes(critical.encode())
    core.write_jsonl(build / "paragraphs.jsonl", [asdict(paragraph) for paragraph in corpus.paragraphs])
    core.create_sqlite_index(build / "corpus.sqlite3", corpus,
        {"source": source, "generated_at": "synthetic-fixture"}, critical_hash, fingerprint)
    docs = len(corpus.paratext_paragraphs) + len(corpus.volumes) + len(corpus.units) + len(corpus.paragraphs)
    validation = core.inspect_search_index(build / "corpus.sqlite3", expected_input_fingerprint=fingerprint,
        expected_critical_sha256=critical_hash, expected_source_units=len(corpus.units),
        expected_paragraphs=len(corpus.paragraphs), expected_search_documents=docs)
    registry, chain = make_receipts(root, critical_hash)
    if not validation["valid"] or not registry["valid"] or not chain["valid"]:
        raise RuntimeError({"index": validation["errors"], "registry": registry["errors"], "chain": chain["errors"]})
    result = {"data_kind": "original_test_text_and_synthetic_editorial_records", "immutable_baseline": (root / config["source_path"]).read_bytes() == raw,
        "source_unit_ids": [unit.source_unit_id for unit in corpus.units], "heading_kinds": [unit.heading_kind for unit in corpus.units],
        "paragraph_ids": [paragraph.paragraph_id for paragraph in corpus.paragraphs], "patches": patch_log,
        "index_valid": validation["valid"], "receipt_contract_valid": chain["valid"], "critical_sha256": critical_hash,
        "fingerprint": fingerprint, "search_documents": docs}
    (build / "case.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("demo-output"))
    print(json.dumps(run(parser.parse_args().out), ensure_ascii=False, indent=2))
