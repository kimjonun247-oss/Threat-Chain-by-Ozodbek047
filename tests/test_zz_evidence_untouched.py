"""Runs last (modules load in name order): no test may have written evidence."""
import unittest

import evidence_guard


class EvidenceUntouched(unittest.TestCase):
    def test_the_suite_wrote_no_report_into_the_evidence_folders(self):
        if evidence_guard.BASELINE is None:
            self.skipTest('Faqat to‘liq to‘plam bilan ma’noli: `python3 -m unittest discover -s tests`')
        added = sorted(evidence_guard.snapshot() - evidence_guard.BASELINE)
        self.assertEqual(added, [], 'Test haqiqiy dalil papkasiga yozdi: ' + ', '.join(added[:5]))


if __name__ == '__main__':
    unittest.main()
