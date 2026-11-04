"""Every report says which scanner and which rules produced it (PLAN.md 4.3).

A result nobody can reproduce is a result nobody can trust: each stage records
its scanner version and, where a rule pack or binary is involved, its hash.

Two stages run without an external binary and are checked here end to end: the
code stage (Semgrep/Gitleaks version + rules_sha256, via the stand-in scanner)
and the repository stage (ThreatChain's own engine_version). The images, IaC
and web stages record the Trivy/Nuclei version and binary_sha256 in the same
shape (zanjir/images.py, iac.py, webscan.py); those need the real binary and are
exercised by the real-tool CI, not here. See BETA_READINESS.md ("4.3").
"""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from zanjir import repository, scanners, triage
from test_architecture import FakeScanner, Workspace


class CodeStageProvenanceTests(Workspace):
    def setUp(self):
        super().setUp()
        self.tool = FakeScanner()
        for patcher in (patch.object(scanners, 'RUNS', self.tmp / 'runs'),
                        patch.object(scanners, 'target_root', return_value=self.source),
                        patch.object(scanners, 'version', return_value='9.9.9'),
                        patch.object(scanners, 'run_tool', self.tool),
                        patch.object(triage, 'record_scan', return_value=False)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_every_tool_records_its_version_and_rules_hash(self):
        self.put('a.py', 'eval(x)\n')
        report = scanners.start('demo', background=False)
        self.assertEqual(report['state'], 'completed', report)
        self.assertTrue(report['tools'], report)
        for tool, record in report['tools'].items():
            self.assertTrue(record.get('version'), (tool, record))
            self.assertRegex(record.get('rules_sha256', ''), r'^[0-9a-f]{64}$', (tool, record))


class RepositoryStageProvenanceTests(unittest.TestCase):
    def test_the_report_names_the_engine_version(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / 'compose.yml').write_text('services:\n  web:\n    image: nginx\n    ports: ["127.0.0.1:8080:80"]\n',
                                              encoding='utf-8')
            report = repository.scan_repository(root, 'compose.yml')
        self.assertTrue(report.get('engine_version'), report)
        self.assertEqual(report['engine_version'], repository.VERSION)


if __name__ == '__main__':
    unittest.main()
