from __future__ import annotations
import json
from pathlib import Path
import tempfile
import unittest

from demo import make_fixture, make_receipts, run
from translation_core import governance


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "workspace"

    def tearDown(self):
        self.temp.cleanup()

    def test_complete_replay(self):
        result = run(self.root)
        self.assertTrue(result["immutable_baseline"])
        self.assertTrue(result["index_valid"])
        self.assertEqual(result["heading_kinds"], ["repeated-number", "repeated-number", "range"])
        self.assertEqual(len(set(result["source_unit_ids"])), 3)

    def test_baseline_edit_is_rejected(self):
        core, config = make_fixture(self.root)
        (self.root / config["source_path"]).write_bytes(b"changed")
        with self.assertRaisesRegex(core.PipelineError, "Source hash mismatch"):
            core.read_and_validate_baseline(config)

    def test_wrong_patch_anchor_is_rejected(self):
        core, config = make_fixture(self.root)
        _, _, lines, _ = core.read_and_validate_baseline(config)
        file = self.root / config["patches_path"]
        document = json.loads(file.read_text(encoding="utf-8"))
        document["patches"][0]["expected"] = "not present"
        file.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")
        with self.assertRaises(core.PipelineError):
            core.apply_patches(lines, config)

    def test_same_task_cannot_supply_three_roles(self):
        self.root.mkdir()
        registry, _ = make_receipts(self.root, "A" * 64)
        for row in registry["by_id"].values():
            row["task_id"] = "/root/same_fixture"
        result = governance.resolve_accepted_receipt_scope(registry, stage="M1", scope_id="demo-scope", subject_sha256="A" * 64)
        self.assertFalse(result["valid"])
        self.assertTrue(any("distinct" in error for error in result["errors"]))

    def test_changed_subject_invalidates_downstream_chain(self):
        self.root.mkdir()
        registry, _ = make_receipts(self.root, "A" * 64)
        result = governance.resolve_accepted_receipt_scope(registry, stage="M1", scope_id="demo-scope", subject_sha256="B" * 64)
        self.assertFalse(result["valid"])

    def test_changed_dossier_invalidates_registry(self):
        self.root.mkdir()
        make_receipts(self.root, "A" * 64)
        (self.root / "data/governance/fixture-1.md").write_text("changed", encoding="utf-8")
        result = governance.validate_task_receipts(workspace_root=self.root)
        self.assertFalse(result["valid"])


if __name__ == "__main__":
    unittest.main()
