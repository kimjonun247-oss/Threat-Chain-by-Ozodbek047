"""Importing the old per-report reviews: the newest opinion wins, and a broken
file never stops the server (review of cba0ead, 2026-11-06).

The server now runs triage.migrate() at every start. Two things went wrong:
  - reviews were imported oldest first and an existing decision is never
    overwritten, so the OLDEST review stuck and the current one was lost --
    for good, since a second run imports nothing;
  - a malformed reviews.json raised AttributeError, which app.py did not
    catch, so the server would not start at all.
"""
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from isolation import isolate_triage
from zanjir import dependencies, findings_index, repo_store, triage

FP = 'e' * 24
OLD, NEW = '20261001T000000-aaaaaaaa', '20261010T000000-bbbbbbbb'
REPORTS = {OLD: {'id': OLD, 'profile_id': 'demo', 'input_sha256': 'a' * 64, 'findings': [{'fingerprint': FP}]},
           NEW: {'id': NEW, 'profile_id': 'demo', 'input_sha256': 'b' * 64, 'findings': [{'fingerprint': FP}]}}


def review(report_id, status, when):
    return {'report_id': report_id, 'fingerprint': FP, 'status': status, 'owner': 'AX', 'note': 'sabab',
            'updated_at': when}


class MigrationSafetyTests(unittest.TestCase):
    def setUp(self):
        isolate_triage(self)
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        (self.tmp / 'repo').mkdir()
        (self.tmp / 'deps').mkdir()
        for patcher in (patch.object(repo_store, 'REPO_RUNS', self.tmp / 'repo'),
                        patch.object(dependencies, 'RUNS', self.tmp / 'deps'),
                        patch.object(repo_store, 'get_report', lambda rid: REPORTS[rid]),
                        patch.object(triage, 'groups', lambda: {'demo': {'stages': {'repository': ['demo'],
                                                                                   'dependencies': ['demo-src']}}}),
                        patch.object(findings_index, 'triage_changed', lambda scope, fps: None)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def write(self, name, value):
        path = self.tmp / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value if isinstance(value, str) else json.dumps(value), encoding='utf-8')
        return path

    def test_a_the_newest_compose_review_wins(self):
        # Stored oldest first, as the old store did.
        self.write('repo/reviews.json', {'a' * 64 + ':' + FP: review(OLD, 'investigating', '2026-10-01T00:00:00+00:00'),
                                         'b' * 64 + ':' + FP: review(NEW, 'accepted_risk', '2026-10-10T00:00:00+00:00')})
        triage.migrate()
        decision = triage.read('demo')['decisions'][FP]
        self.assertEqual((decision['status'], decision['bound_to']), ('accepted_risk', 'b' * 64))
        self.assertEqual(triage.attach('repository', 'demo', REPORTS[NEW])['findings'][0]['triage']['status'],
                         'accepted_risk')

    def test_b_the_newest_cve_run_wins(self):
        for rid, status in (('20261001T000000-cccccccc', 'investigating'), ('20261010T000000-dddddddd', 'fix_planned')):
            self.write(f'deps/{rid}/report.json', {'id': rid, 'target': 'demo-src',
                                                   'findings': [{'id': 'GHSA-1', 'fingerprint': FP}]})
            self.write(f'deps/{rid}/reviews.json', {'findings': {'GHSA-1': {'status': status, 'owner': 'AX', 'note': 'n'}}})
        triage.migrate()
        self.assertEqual(triage.read('demo')['decisions'][FP]['status'], 'fix_planned')

    def test_c_malformed_files_are_skipped_not_raised(self):
        for content in ({'x:' + FP: 'oops'}, [1, 2], '"text"'):
            with self.subTest(content=content):
                (self.tmp / 'repo' / triage.MARKER).unlink(missing_ok=True)
                self.write('repo/reviews.json', content)
                self.write('deps/20261001T000000-eeeeeeee/report.json', {'id': 'x', 'target': 'demo-src', 'findings': []})
                self.write('deps/20261001T000000-eeeeeeee/reviews.json', {'findings': ['not', 'a', 'dict']})
                result = triage.migrate()
                self.assertEqual(result['count'], 0)
                self.assertTrue(result['notes'])

    def test_d_an_unreadable_file_is_tried_again_next_time(self):
        self.write('repo/reviews.json', '{not json')
        triage.migrate()
        self.assertFalse((self.tmp / 'repo' / triage.MARKER).exists())
        self.write('repo/reviews.json', {'b' * 64 + ':' + FP: review(NEW, 'false_positive', '2026-10-10T00:00:00+00:00')})
        triage.migrate()
        self.assertEqual(triage.read('demo')['decisions'][FP]['status'], 'false_positive')


class StartupTests(unittest.TestCase):
    def test_a_migration_errors_of_any_kind_never_stop_the_server(self):
        source = (Path(__file__).resolve().parent.parent / 'app.py').read_text(encoding='utf-8')
        block = source[source.index('moved = triage.migrate()'):]
        self.assertIn('except Exception', block[:400])


if __name__ == '__main__':
    unittest.main()
