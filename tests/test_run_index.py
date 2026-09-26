"""The run-listing cache must never become a second source of truth.

Measured gain: portfolio.overview() 89 ms -> 5 ms, dependencies.history() 84 ms
-> under 1 ms. That is only worth having if the listing can never show something
the report files do not say -- these tests hold it to that.
"""
import json
import os
import shutil
import tempfile
import sqlite3
import time
import unittest
from unittest import mock
from pathlib import Path

from zanjir import repo_store, run_index

FIELDS = ('id', 'target', 'created_at', 'state', 'count')


class Base(unittest.TestCase):
    def setUp(self):
        self.runs = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.runs, True)
        self.reads = []

    def write(self, rid, **fields):
        folder = self.runs / rid
        folder.mkdir(exist_ok=True)
        report = {'id': rid, 'target': 'app', 'created_at': rid, 'state': 'completed', 'count': 1, **fields}
        path = folder / 'report.json'
        path.write_text(json.dumps(report), encoding='utf-8')
        return path

    def read(self, rid):
        self.reads.append(rid)
        path = self.runs / rid / 'report.json'
        try:
            return json.loads(path.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            raise ValueError('topilmadi')

    def rows(self, **kw):
        return run_index.rows(self.runs, FIELDS, self.read, **kw)


class CacheUseTests(Base):
    def test_a_second_listing_reads_no_report_at_all(self):
        self.write('20260101T000001')
        self.write('20260101T000002')
        self.rows()
        self.reads.clear()
        self.assertEqual(len(self.rows()), 2)
        self.assertEqual(self.reads, [])

    def test_rows_are_newest_first_and_limited(self):
        for i in range(5):
            self.write(f'2026010{i + 1}T000000')
        rows = self.rows(limit=3)
        self.assertEqual([r['id'] for r in rows], ['20260105T000000', '20260104T000000', '20260103T000000'])


class FreshnessTests(Base):
    def test_a_report_rewritten_in_place_is_re_read(self):
        # A scan that finishes rewrites report.json; the listing must show the
        # final state, not the "running" row cached a moment earlier.
        path = self.write('20260101T000001', state='running', count=0)
        self.assertEqual(self.rows()[0]['state'], 'running')
        time.sleep(0.01)
        path.write_text(json.dumps({'id': '20260101T000001', 'target': 'app', 'created_at': '20260101T000001',
                                    'state': 'completed', 'count': 42}), encoding='utf-8')
        row = self.rows()[0]
        self.assertEqual((row['state'], row['count']), ('completed', 42))

    def test_an_edit_that_keeps_the_size_still_invalidates_via_mtime(self):
        path = self.write('20260101T000001', state='partial')
        self.rows()
        text = path.read_text(encoding='utf-8').replace('partial', 'failed_')
        path.write_text(text, encoding='utf-8')
        future = time.time() + 5
        os.utime(path, (future, future))
        self.assertEqual(self.rows()[0]['state'], 'failed_')

    def test_a_new_report_appears_and_a_deleted_one_disappears(self):
        self.write('20260101T000001')
        self.rows()
        self.write('20260101T000002')
        shutil.rmtree(self.runs / '20260101T000001')
        self.assertEqual([r['id'] for r in self.rows()], ['20260101T000002'])


class WriteThroughTests(Base):
    def test_a_report_rewritten_by_write_json_is_re_read_even_in_a_long_listing(self):
        self.write('20260101T000001', state='running', count=0)
        self.rows()
        self.reads.clear()
        repo_store.write_json(self.runs / '20260101T000001' / 'report.json',
                              {'id': '20260101T000001', 'target': 'app', 'created_at': '20260101T000001',
                               'state': 'completed', 'count': 42})
        # Even a listing too long for the per-row check sees the new state.
        with mock.patch.object(run_index, 'VERIFY_LIMIT', 0):
            row = self.rows()[0]
        self.assertEqual((row['state'], row['count']), ('completed', 42))
        self.assertEqual(self.reads, ['20260101T000001'])     # read once, through the module's read()

    def test_a_non_report_file_written_next_to_flat_reports_is_never_listed(self):
        def read_flat(rid):
            if not rid.startswith('2026'):
                raise ValueError('hisobot emas')
            return json.loads((self.runs / (rid + '.json')).read_text(encoding='utf-8'))
        repo_store.write_json(self.runs / '20260101T000001.json', {'id': '20260101T000001', 'created_at': 'x'})
        run_index.rows(self.runs, FIELDS, read_flat, flat=True)
        repo_store.write_json(self.runs / 'reviews.json', {'id': 'reviews', 'created_at': 'z'})
        rows = run_index.rows(self.runs, FIELDS, read_flat, flat=True)
        self.assertEqual([r['id'] for r in rows], ['20260101T000001'])

    def test_a_listing_is_one_query_not_a_stat_per_report(self):
        for i in range(40):
            self.write(f'2026{i // 28 + 1:02d}{i % 28 + 1:02d}T000000')
        self.rows()
        checked = []
        real = run_index.Path.stat

        def counting(path, *args, **kwargs):
            if path.name == 'report.json':
                checked.append(path.parent.name)
            return real(path, *args, **kwargs)

        with mock.patch.object(run_index.Path, 'stat', counting):
            rows = self.rows(limit=5)
        self.assertEqual([r['id'] for r in rows], sorted(checked, reverse=True))
        self.assertEqual(len(checked), 5)          # only the rows returned are re-checked


class RepairTests(Base):
    def test_a_deleted_index_is_rebuilt_silently(self):
        self.write('20260101T000001')
        self.rows()
        (self.runs / run_index.DB_NAME).unlink()
        self.assertEqual(len(self.rows()), 1)
        self.assertTrue((self.runs / run_index.DB_NAME).is_file())

    def test_a_damaged_index_file_is_replaced_not_trusted(self):
        self.write('20260101T000001', count=7)
        self.rows()
        (self.runs / run_index.DB_NAME).write_bytes(b'this is not a database' * 100)
        self.assertEqual(self.rows()[0]['count'], 7)
        self.assertEqual([r['id'] for r in self.rows()], ['20260101T000001'])

    def test_a_forged_index_row_with_a_stale_stamp_is_not_believed(self):
        self.write('20260101T000001', count=7)
        self.rows()
        connection = sqlite3.connect(str(self.runs / run_index.DB_NAME))
        connection.execute("UPDATE runs SET row=?", (json.dumps({'id': '20260101T000001', 'count': 999}),))
        connection.execute("UPDATE runs SET mtime_ns=1")
        connection.commit()
        connection.close()
        self.assertEqual(self.rows()[0]['count'], 7)

    def test_an_index_edited_while_nothing_ran_is_re_checked_by_a_new_process(self):
        # A long listing skips the per-row check; the once-per-process full check covers it.
        self.write('20260101T000001', count=7)
        self.rows()
        connection = sqlite3.connect(str(self.runs / run_index.DB_NAME))
        connection.execute("UPDATE runs SET row=?, mtime_ns=1", (json.dumps({'id': '20260101T000001', 'count': 999}),))
        connection.commit()
        connection.close()
        run_index._VERIFIED.clear()            # what a restart looks like
        with mock.patch.object(run_index, 'VERIFY_LIMIT', 0):
            self.assertEqual(self.rows()[0]['count'], 7)

    def test_without_a_usable_sqlite_the_json_cache_answers(self):
        self.write('20260101T000001', count=7)
        with mock.patch.object(run_index, '_rows_sqlite', side_effect=OSError('read-only')):
            self.assertEqual(self.rows()[0]['count'], 7)
        self.assertTrue((self.runs / run_index.CACHE_NAME).is_file())

    def test_a_corrupted_cache_is_ignored_not_trusted(self):
        self.write('20260101T000001', count=7)
        (self.runs / run_index.CACHE_NAME).write_text('{not json', encoding='utf-8')
        self.assertEqual(self.rows()[0]['count'], 7)

    def test_a_forged_cache_entry_with_a_stale_stamp_is_not_believed(self):
        self.write('20260101T000001', count=7)
        forged = {'version': 1, 'entries': {'20260101T000001': {'stamp': [1, 1], 'row': {'id': '20260101T000001', 'count': 999}}}}
        (self.runs / run_index.CACHE_NAME).write_text(json.dumps(forged), encoding='utf-8')
        self.assertEqual(self.rows()[0]['count'], 7)

    def test_an_unreadable_report_is_skipped_rather_than_breaking_the_listing(self):
        self.write('20260101T000001')
        bad = self.runs / '20260101T000002'
        bad.mkdir()
        (bad / 'report.json').write_text('{broken', encoding='utf-8')
        self.assertEqual([r['id'] for r in self.rows()], ['20260101T000001'])

    def test_a_missing_runs_folder_is_an_empty_listing(self):
        self.assertEqual(run_index.rows(self.runs / 'absent', FIELDS, self.read), [])


class FlatLayoutTests(Base):
    """repository-runs keeps <id>.json directly, next to reviews.json."""

    def read_flat(self, rid):
        if not rid.startswith('2026'):
            raise ValueError('hisobot emas')
        return json.loads((self.runs / (rid + '.json')).read_text(encoding='utf-8'))

    def test_non_report_files_and_the_cache_itself_are_never_listed(self):
        (self.runs / '20260101T000001.json').write_text(json.dumps({'id': '20260101T000001', 'created_at': 'x'}), encoding='utf-8')
        (self.runs / 'reviews.json').write_text('{}', encoding='utf-8')
        run_index.rows(self.runs, FIELDS, self.read_flat, flat=True)
        rows = run_index.rows(self.runs, FIELDS, self.read_flat, flat=True)
        self.assertEqual([r['id'] for r in rows], ['20260101T000001'])


class SharedReadTests(Base):
    """One read() now serves five modules, so its checks guard all of them."""

    def test_an_id_that_could_leave_the_folder_is_refused_before_any_path_is_built(self):
        for bad in ('../x', '..', '/etc/passwd', '20260101T000000-ABCDEF12', '', None, 42):
            with self.subTest(rid=bad), self.assertRaises(ValueError) as caught:
                run_index.read(self.runs, bad, 'yo‘q')
            self.assertIn('ID', str(caught.exception))

    def test_a_valid_id_with_no_report_gives_the_modules_own_message(self):
        with self.assertRaises(ValueError) as caught:
            run_index.read(self.runs, '20260101T000000-abcdef12', 'Image hisoboti topilmadi.')
        self.assertEqual(str(caught.exception), 'Image hisoboti topilmadi.')

    def test_every_scanner_module_uses_the_shared_read(self):
        root = Path(__file__).resolve().parents[1] / 'zanjir'
        for name in ('scanners', 'dependencies', 'images', 'webscan', 'pipeline'):
            with self.subTest(module=name):
                self.assertIn('run_index.read(', (root / (name + '.py')).read_text(encoding='utf-8'))


class ProductionWiringTests(unittest.TestCase):
    def test_every_listing_goes_through_the_index(self):
        # A module that kept its own full scan would quietly lose the speed-up.
        root = Path(__file__).resolve().parents[1] / 'zanjir'
        for name in ('scanners', 'dependencies', 'images', 'webscan', 'pipeline', 'repo_store'):
            with self.subTest(module=name):
                self.assertIn('run_index.rows(', (root / (name + '.py')).read_text(encoding='utf-8'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
