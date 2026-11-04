"""Dependency-stage progress on a large project (shortcomings review 2026-11-02, LP#8).

advisories.query_packages reports progress once per advisory, and every call
rewrote report.json (and its index/status/view/compare files): 20 000 advisories
were 20 000 full rewrites. And a progress write that hit an antivirus/OneDrive
lock raised out of the advisory loop and failed the whole stage.
"""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from zanjir import advisories as adv
from zanjir import dependencies as dep
from zanjir import repo_store, scanners


def chatty_query(calls):
    def query(packages, progress=None):
        for n in range(calls):
            progress(f'Zaiflik tavsiflari: {n + 1}/{calls}')
        return {}, {}, [], []
    return query


class ProgressTests(unittest.TestCase):
    def run_scan(self, write_json):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = base / 'repo'
            root.mkdir()
            (root / 'requirements.txt').write_text('demo-pkg==1.0.0\n', encoding='utf-8')
            with patch.object(dep, 'RUNS', base / 'runs'), patch.object(scanners, 'target_root', return_value=root), \
                    patch.object(adv, 'query_packages', side_effect=chatty_query(2000)), \
                    patch.object(adv, 'kev_catalog', return_value=({}, {'state': 'available'})), \
                    patch.object(dep.repo_store, 'write_json', write_json):
                return dep.start('test', False)

    def test_a_two_thousand_progress_calls_are_not_two_thousand_rewrites(self):
        real, writes = repo_store.write_json, []

        def counting(path, value):
            if path.name == 'report.json':
                writes.append(value.get('progress'))
            return real(path, value)
        report = self.run_scan(counting)
        self.assertEqual(report['state'], 'completed', report)
        self.assertLess(sum(1 for w in writes if str(w).startswith('Zaiflik')), 20, len(writes))

    def test_b_a_locked_progress_write_does_not_fail_the_stage(self):
        real = repo_store.write_json

        def locked_during_progress(path, value):
            if path.name == 'report.json' and str(value.get('progress', '')).startswith('Zaiflik'):
                raise PermissionError('locked by antivirus')
            return real(path, value)
        with patch.object(dep, 'PROGRESS_INTERVAL', 0):
            report = self.run_scan(locked_during_progress)
        self.assertEqual(report['state'], 'completed', report)
        self.assertFalse(dep.LOCK.locked())


if __name__ == '__main__':
    unittest.main()
