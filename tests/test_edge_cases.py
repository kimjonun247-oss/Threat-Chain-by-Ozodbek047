"""Inputs real repositories contain and toy ones do not (PLAN.md 4.2).

Each case runs the real snapshot and code-scan path (scanners.start) with the
stand-in scanner, so what is checked is ThreatChain's own handling: the file is
scanned, or it is skipped *and the report says so*; nothing crashes and
nothing silently disappears.
"""
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from zanjir import inventory, scanners, triage
from test_architecture import FakeScanner, Workspace


class EdgeCaseTests(Workspace):
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

    def scan(self):
        return scanners.start('demo', background=False)

    def paths(self, report):
        return sorted(f['path'] for f in report['findings'])

    def test_a_empty_project_is_a_clear_failure_not_a_clean_result(self):
        report = self.scan()
        self.assertEqual(report['state'], 'failed')
        self.assertEqual(report['findings'], [])
        self.assertIn('fayl', report.get('message', '') + str(report.get('error', '')))

    def test_b_cyrillic_and_uzbek_letters_in_paths(self):
        self.put('ilova/so‘rov.py', 'eval(a)\n')
        self.put('модуль/файл.py', 'eval(b)\n')
        self.put('oʻzbek/gʻisht.py', 'eval(c)\n')
        report = self.scan()
        self.assertEqual(report['state'], 'completed', report)
        self.assertEqual(self.paths(report), sorted(['ilova/so‘rov.py', 'модуль/файл.py', 'oʻzbek/gʻisht.py']))

    def test_c_a_very_long_file_name(self):
        name = 'a' * 200 + '.py'
        self.put('deep/' + name, 'eval(x)\n')
        self.put('ok.py', 'eval(y)\n')
        report = self.scan()
        self.assertIn(report['state'], ('completed', 'partial'))
        found = self.paths(report)
        self.assertIn('ok.py', found)
        if 'deep/' + name not in found:
            # Windows' 260-character limit: allowed only when the report names the file.
            self.assertIn('deep/' + name, report['coverage']['path_too_long']['files'])

    @unittest.skipIf(sys.platform == 'win32' and not os.environ.get('THREATCHAIN_TEST_SYMLINKS'),
                     'Windows: symlink yaratish Developer Mode talab qiladi')
    def test_d_symlinks_are_not_followed_and_are_counted(self):
        outside = self.tmp / 'outside'
        outside.mkdir()
        (outside / 'secret.py').write_text('eval(z)\n', encoding='utf-8')
        self.put('app.py', 'eval(a)\n')
        os.symlink(outside, self.source / 'linked_dir', target_is_directory=True)
        os.symlink(outside / 'secret.py', self.source / 'linked.py')
        report = self.scan()
        self.assertEqual(self.paths(report), ['app.py'])
        self.assertGreaterEqual(report['coverage']['skipped']['links'], 1)

    def test_e_a_file_over_the_size_limit_is_skipped_and_counted(self):
        self.put('big.py', 'x = 1\n' * (scanners.MAX_FILE // 6 + 10))
        self.put('small.py', 'eval(a)\n')
        report = self.scan()
        self.assertEqual(self.paths(report), ['small.py'])
        self.assertEqual(report['coverage']['skipped']['large'], 1)

    def test_f_crlf_and_lf_give_the_same_lines(self):
        self.put('lf.py', 'x = 1\neval(a)\n')
        self.put('crlf.py', b'x = 1\r\neval(a)\r\n')
        report = self.scan()
        lines = {f['path']: f['line'] for f in report['findings']}
        self.assertEqual(lines, {'lf.py': 2, 'crlf.py': 2})

    def test_g_a_folder_without_git_is_scanned_and_history_is_not_applicable(self):
        self.put('app.py', 'eval(a)\n')
        report = self.scan()
        self.assertEqual(report['state'], 'completed')
        self.assertFalse((self.source / '.git').exists())
        history = report['tools']['gitleaks'].get('history') or report.get('history_secrets') or {}
        self.assertNotEqual(history.get('state'), 'failed')

    def test_h_binary_and_utf16_files(self):
        self.put('image.bin', b'\x00\x01\x02eval(\x00')
        self.put('windows.ps1', 'eval(w)\r\n'.encode('utf-16'))
        report = self.scan()
        self.assertEqual(self.paths(report), ['windows.ps1'])
        self.assertEqual(report['coverage']['skipped']['binary'], 1)
        self.assertEqual(report['coverage'].get('transcoded_utf16'), 1)


class BrokenLockfileTests(unittest.TestCase):
    """A lockfile that does not parse is a stated gap, never an exception and never 'no packages'."""

    def test_broken_lockfiles_are_gaps(self):
        import tempfile
        root = Path(tempfile.mkdtemp())
        self.addCleanup(__import__('shutil').rmtree, root, True)
        (root / 'package-lock.json').write_text('{"lockfileVersion": 3, "packages": {', encoding='utf-8')
        (root / 'poetry.lock').write_text('[[package]\nname = ', encoding='utf-8')
        (root / 'requirements.txt').write_text('requests==2.31.0\n', encoding='utf-8')
        result = inventory.collect(root)
        names = {p.get('name') for p in result['packages']}
        self.assertIn('requests', names)
        gap_files = {str(g.get('path') or g.get('file') or g.get('manifest') or '') for g in result['gaps']}
        self.assertTrue(any('package-lock.json' in g for g in gap_files), result['gaps'])
        self.assertTrue(any('poetry.lock' in g for g in gap_files), result['gaps'])


if __name__ == '__main__':
    unittest.main()
