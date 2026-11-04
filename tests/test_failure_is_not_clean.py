"""The most dangerous wrong answer a security gate can give: "scanner did not
work" read as "no risk found" (PLAN.md 4.1).

Every failure mode below runs through the real code-scan entry point
(scanners.start) and then through the real CI gate CLI (ci_gate.main). For
each one the report must not say `completed` and the CLI must exit 2 -- never
0 ("clean") and never 1 ("findings"). A working scan of the same project is
the control: it exits 0 or 1 by its findings.
"""
import io
import json
import subprocess
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from zanjir import pipeline, scanners, triage
from test_architecture import FakeScanner, Workspace

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import ci_gate as gate_cli  # noqa: E402


class FailureIsNotCleanTests(Workspace):
    def setUp(self):
        super().setUp()
        self.put('app.py', 'x = 1\n')
        self.put('lib/util.py', 'y = 2\n')
        self.tool = FakeScanner()
        for patcher in (patch.object(scanners, 'RUNS', self.tmp / 'runs'),
                        patch.object(scanners, 'target_root', return_value=self.source),
                        patch.object(scanners, 'history_secrets', return_value=({'state': 'not_applicable'}, [])),
                        patch.object(triage, 'record_scan', return_value=False)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def code_scan(self, run_tool=None, version=lambda *a, **k: '1.2.3'):
        with patch.object(scanners, 'run_tool', run_tool or self.tool), patch.object(scanners, 'version', version):
            return scanners.start('demo', background=False)

    def gate(self, report):
        """Exit code of the real CLI for an assessment holding this code report."""
        stage = {'kind': 'code', 'target': 'demo', 'state': report['state'], 'report': report}
        assessment = {'id': 'a1', 'state': 'completed' if report['state'] == 'completed' else 'partial',
                      'stages': [stage], 'findings': [], 'chains': []}
        out = io.StringIO()
        argv = ['ci_gate.py', '--target', 'demo', '--sarif-out', str(self.tmp / 'out.sarif')]
        with patch.object(sys, 'argv', argv), patch.object(pipeline, 'start', return_value=assessment), \
                patch.object(pipeline, 'sarif', return_value={}), patch.object(pipeline, 'attach_triage', lambda r: r), \
                redirect_stdout(out), redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as stop:
                gate_cli.main()
        return stop.exception.code, json.loads(out.getvalue())

    def assert_not_clean(self, report, label):
        self.assertNotEqual(report['state'], 'completed', label)
        code, shown = self.gate(report)
        self.assertEqual(code, 2, f'{label}: gate exit {code}, report {report["state"]}, {shown}')

    # -- control -------------------------------------------------------------------
    def test_a_a_working_scan_passes_or_fails_by_its_findings(self):
        clean = self.code_scan()
        self.assertEqual((clean['state'], self.gate(clean)[0]), ('completed', 0))

    # -- failure modes ---------------------------------------------------------------
    def test_b_scanner_not_installed(self):
        def missing(*args, **kwargs):
            raise FileNotFoundError('semgrep.exe')
        self.assert_not_clean(self.code_scan(version=missing), 'tool missing')

    def test_c_every_part_times_out(self):
        def slow(command, cwd, env, timeout, cancel=None, **low):
            if 'dir' in command:
                return self.tool(command, cwd, env, timeout, cancel, **low)
            raise subprocess.TimeoutExpired(command, timeout)
        self.assert_not_clean(self.code_scan(slow), 'timeout')

    def test_d_output_is_not_json(self):
        def garbage(command, cwd, env, timeout, cancel=None, **low):
            if 'dir' in command:
                return self.tool(command, cwd, env, timeout, cancel, **low)
            return subprocess.CompletedProcess(command, 0, '{"results": [', '')
        self.assert_not_clean(self.code_scan(garbage), 'broken JSON')

    def test_e_empty_output(self):
        def empty(command, cwd, env, timeout, cancel=None, **low):
            if 'dir' in command:
                return self.tool(command, cwd, env, timeout, cancel, **low)
            return subprocess.CompletedProcess(command, 0, '', '')
        self.assert_not_clean(self.code_scan(empty), 'empty output')

    def test_f_crash_exit_code(self):
        def crash(command, cwd, env, timeout, cancel=None, **low):
            if 'dir' in command:
                return self.tool(command, cwd, env, timeout, cancel, **low)
            return subprocess.CompletedProcess(command, 2, '', 'Fatal error')
        self.assert_not_clean(self.code_scan(crash), 'crash')

    def test_g_out_of_memory_on_every_retry(self):
        def oom(command, cwd, env, timeout, cancel=None, **low):
            if 'dir' in command:
                return self.tool(command, cwd, env, timeout, cancel, **low)
            return subprocess.CompletedProcess(command, 137, '', 'Killed')
        self.assert_not_clean(self.code_scan(oom), 'out of memory')

    def test_h_only_the_secrets_scanner_fails(self):
        def gitleaks_broken(command, cwd, env, timeout, cancel=None, **low):
            if 'dir' in command:
                return subprocess.CompletedProcess(command, 126, '', 'permission denied')
            return self.tool(command, cwd, env, timeout, cancel, **low)
        report = self.code_scan(gitleaks_broken)
        self.assertEqual(report['tools']['semgrep']['state'], 'completed')
        self.assert_not_clean(report, 'gitleaks broken, semgrep fine')

    def test_i_every_file_unreadable_is_not_a_coverage_gap(self):
        # Exit 0 with a well-formed answer that says: could not parse any file.
        def unreadable(command, cwd, env, timeout, cancel=None, **low):
            if 'dir' in command:
                return self.tool(command, cwd, env, timeout, cancel, **low)
            files = sorted(p.relative_to(Path(cwd)).as_posix() for p in (Path(cwd) / 'source').rglob('*.py'))
            errors = [{'type': 'Syntax error', 'level': 'warn', 'path': f} for f in files]
            return subprocess.CompletedProcess(command, 0, json.dumps({'results': [], 'errors': errors}), '')
        report = self.code_scan(unreadable)
        self.assertEqual(report['tools']['semgrep']['files_with_errors'], 2)
        self.assert_not_clean(report, 'no file readable')

    def test_j_one_unreadable_file_stays_a_gap(self):
        # The opposite must hold too: one Dockerfile Semgrep cannot parse is a gap,
        # shown but not blocking -- otherwise every real repository exits 2.
        def one_bad(command, cwd, env, timeout, cancel=None, **low):
            if 'dir' in command:
                return self.tool(command, cwd, env, timeout, cancel, **low)
            errors = [{'type': 'Syntax error', 'level': 'warn', 'path': 'source/lib/util.py'}]
            return subprocess.CompletedProcess(command, 0, json.dumps({'results': [], 'errors': errors}), '')
        report = self.code_scan(one_bad)
        self.assertEqual(report['state'], 'partial')
        self.assertEqual(self.gate(report)[0], 0)


if __name__ == '__main__':
    unittest.main()
