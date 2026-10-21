"""First-scan time is written as a breakdown, not one number (PLAN.md 2.1).

The code scan records where its wall time went -- reading the files, loading the
rules, running the scanners, and everything else -- so a slow first scan on a
large project can be explained instead of guessed at. Runs the real scan path
(scanners.start) with the stand-in scanner, so the phases are ThreatChain's own.
"""
import unittest
from unittest.mock import patch

from zanjir import scanners, triage
from test_architecture import FakeScanner, Workspace


class ScanProfileTests(Workspace):
    def setUp(self):
        super().setUp()
        self.tool = FakeScanner()
        for patcher in (patch.object(scanners, 'RUNS', self.tmp / 'runs'),
                        patch.object(scanners, 'target_root', return_value=self.source),
                        patch.object(scanners, 'version', return_value='1.2.3'),
                        patch.object(scanners, 'run_tool', self.tool),
                        patch.object(triage, 'record_scan', return_value=False)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_a_timing_breaks_the_scan_into_named_phases(self):
        self.put('a.py', 'eval(x)\n')
        self.put('b.py', 'eval(y)\n')
        report = scanners.start('demo', background=False)
        self.assertEqual(report['state'], 'completed', report)
        timing = report['timing']
        for key in ('files_s', 'rules_s', 'scan_s', 'other_s', 'total_s'):
            self.assertIn(key, timing, timing)
            self.assertGreaterEqual(timing[key], 0.0)

    def test_b_the_phases_never_exceed_the_total(self):
        self.put('a.py', 'eval(x)\n')
        report = scanners.start('demo', background=False)
        timing = report['timing']
        parts = timing['files_s'] + timing['rules_s'] + timing['scan_s']
        self.assertLessEqual(parts, timing['total_s'] + 0.5)          # rounding slack
        self.assertGreaterEqual(timing['other_s'], 0.0)


if __name__ == '__main__':
    unittest.main()
