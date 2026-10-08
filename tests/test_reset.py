"""Clearing all scan results (zanjir/reset.py).

Removes every report directory's contents and the triage decisions, keeps the
directories themselves, and never touches anything outside the result dirs.
Run against a temporary DATA root so no real report is deleted.
"""
import tempfile
import unittest
from pathlib import Path

from zanjir import reset


class ClearResultsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._real = reset.DATA
        reset.DATA = self.tmp
        self.addCleanup(lambda: setattr(reset, 'DATA', self._real))
        # Populate every result dir with a report, plus a triage decision.
        for name in reset.RESULT_DIRS + reset.DECISION_DIRS:
            folder = self.tmp / name
            folder.mkdir(parents=True)
            (folder / 'report.json').write_text('{}', encoding='utf-8')
            sub = folder / 'run-1'
            sub.mkdir()
            (sub / 'report.json').write_text('{}', encoding='utf-8')
        # A directory that is NOT a result dir must be left untouched.
        keep = self.tmp / 'profiles'
        keep.mkdir(exist_ok=True)
        (keep / 'crapi.json').write_text('{}', encoding='utf-8')

    def test_all_result_dirs_are_emptied_but_kept(self):
        summary = reset.clear_results()
        self.assertEqual(summary['total'], len(reset.RESULT_DIRS + reset.DECISION_DIRS) * 2)
        for name in reset.RESULT_DIRS + reset.DECISION_DIRS:
            folder = self.tmp / name
            self.assertTrue(folder.is_dir(), f'{name} dir removed')
            self.assertEqual(list(folder.iterdir()), [], f'{name} not emptied')

    def test_targets_and_settings_are_untouched(self):
        reset.clear_results()
        self.assertTrue((self.tmp / 'profiles' / 'crapi.json').is_file())

    def test_a_missing_dir_is_not_an_error(self):
        # Remove one result dir entirely; clearing must still succeed.
        import shutil
        shutil.rmtree(self.tmp / reset.RESULT_DIRS[0])
        summary = reset.clear_results()
        self.assertIn(reset.RESULT_DIRS[0], summary['cleared'])
        self.assertEqual(summary['cleared'][reset.RESULT_DIRS[0]], 0)


if __name__ == '__main__':
    unittest.main()
