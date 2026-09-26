"""Runs first (modules load in name order): records the evidence folders."""
import unittest

import evidence_guard
import isolation  # noqa: F401 -- redirects audit/users/queue before any other test


class EvidenceBaseline(unittest.TestCase):
    def test_record_the_evidence_folders_before_any_other_test(self):
        evidence_guard.BASELINE = evidence_guard.snapshot()
        self.assertIsNotNone(evidence_guard.BASELINE)


if __name__ == '__main__':
    unittest.main()
