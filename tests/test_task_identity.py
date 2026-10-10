"""Synthetic identity-format cases for the synchronized receipt validator."""
import unittest
from translation_core.governance import is_canonical_codex_task_id


class TaskIdentityTests(unittest.TestCase):
    def test_supported_identifiers(self):
        for value in ['/root/reviewer', '00000000-0000-4000-8000-000000000001']:
            self.assertTrue(is_canonical_codex_task_id(value))

    def test_labels_and_noncanonical_formats_are_rejected(self):
        for value in ['reviewer', ' /root/reviewer', 'FFFFFFFF-0000-4000-8000-000000000001', '/root/not-a-task', '']:
            self.assertFalse(is_canonical_codex_task_id(value))


if __name__ == '__main__':
    unittest.main()
