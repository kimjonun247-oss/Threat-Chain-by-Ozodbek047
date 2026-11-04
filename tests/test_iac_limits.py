"""IaC stage limits on a large project (shortcomings review 2026-11-02, LP#10).

  - Trivy gets an explicit --timeout. Without it Trivy stopped at its own 5-minute
    default and a large project failed long before this module's limit.
  - The time budget grows with the snapshot size, like the code stage's.
  - What the snapshot left out (files over 1 MB) is recorded in the report.
  - A Trivy JSON larger than 64 MB fails clearly instead of being read into memory.
"""
import contextlib
import json
import shutil
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from zanjir import iac, images, repo_store, scanners, triage

RID = '20261102T000000-0123abcd'


class CommandTests(unittest.TestCase):
    def test_a_trivy_is_given_its_own_timeout(self):
        command = iac.command(Path('src'), Path('out.json'), 600)
        self.assertEqual(command[command.index('--timeout') + 1], '570s')

    def test_b_the_timeout_never_drops_below_a_minute(self):
        command = iac.command(Path('src'), Path('out.json'), 10)
        self.assertEqual(command[command.index('--timeout') + 1], '60s')


class FakeTrivy:
    """Writes the --output file the command names, then exits 0."""

    def __init__(self, payload):
        self.payload = payload
        self.commands = []

    def __call__(self, command, **kwargs):
        self.commands.append(command)
        Path(command[command.index('--output') + 1]).write_bytes(self.payload)
        process = mock.Mock()
        process.poll.return_value = 0
        process.returncode = 0
        return process


class ExecuteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.source = self.tmp / 'src'
        (self.source / 'k8s').mkdir(parents=True)
        (self.source / 'Dockerfile').write_text('FROM alpine\n', encoding='utf-8')
        (self.source / 'k8s' / 'crds.yaml').write_text('# big\n' + 'x: 1\n' * 300_000, encoding='utf-8')  # > 1 MB
        binary = self.tmp / 'trivy'
        binary.write_bytes(b'fake trivy')

        @contextlib.contextmanager
        def source_for(target):
            yield self.source, {'mode': 'local'}
        for patcher in (mock.patch.object(iac, 'RUNS', self.tmp / 'runs'),
                        mock.patch.object(images, 'BINARY', binary),
                        mock.patch.object(scanners, 'source_for', source_for),
                        mock.patch.object(iac, 'trivy_version', return_value='0.74.0'),
                        mock.patch.object(triage, 'record_scan', return_value=False)):
            patcher.start()
            self.addCleanup(patcher.stop)
        repo_store.write_json(self.tmp / 'runs' / RID / 'report.json',
                              {'id': RID, 'target': 'demo', 'state': 'queued', 'findings': []})

    def run_with(self, payload):
        fake = FakeTrivy(payload)
        self.assertTrue(iac.LOCK.acquire(blocking=False))     # start() holds it; execute() releases it
        with mock.patch.object(iac.subprocess, 'Popen', fake):
            iac.execute(RID, 'demo', threading.Event())
        return iac.read_raw(RID), fake

    def test_a_the_skipped_large_file_is_recorded(self):
        report, fake = self.run_with(json.dumps({'Results': []}).encode())
        self.assertEqual(report['state'], 'completed', report)
        self.assertEqual(report['skipped'].get('large'), 1, report.get('skipped'))
        self.assertIn('--timeout', fake.commands[0])

    def test_b_an_oversized_trivy_answer_fails_clearly(self):
        with mock.patch.object(iac, 'MAX_OUTPUT', 10):
            report, _ = self.run_with(json.dumps({'Results': []}).encode())
        self.assertEqual(report['state'], 'failed', report)


if __name__ == '__main__':
    unittest.main()
