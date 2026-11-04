"""Regressions from the load test of 2026-10-09 (MUAMMOLAR.md, section H).

Every class is one thing that was measured breaking, or measured slow enough to
be unusable, on a real 26 499-file tree or on synthetic 50 000-finding reports.
The numbers are in the docstrings so a later reader can tell what "fixed" meant.
"""
import datetime
import json
import os
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from isolation import isolate_triage

from zanjir import (advisories, baseline, chains, findings_index, findings_store, inventory, pipeline, recovery, repo_store,
                    repository, run_index, scanners, triage)
from zanjir.engine import ROOT, available_memory_mb, process_alive
from zanjir.repository import port_mapping, scan_repository


class Workspace(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(__import__('shutil').rmtree, self.tmp, True)
        self.source = self.tmp / 'src'
        self.source.mkdir()

    def put(self, name, content='x = 1\n'):
        path = self.source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content if isinstance(content, bytes) else content.encode('utf-8'))
        return path


class SnapshotTests(Workspace):
    """H1: copying was 59% of a 15-minute scan, silent, and unbounded until it failed."""

    def test_a_an_oversized_project_is_refused_before_anything_is_copied(self):
        for index in range(30):
            self.put(f'f{index}.py', 'x = 1\n' * 200)
        with patch.object(scanners, 'MAX_TOTAL', 10_000), self.assertRaises(ValueError) as caught:
            scanners.snapshot(self.source, self.tmp / 'out')
        self.assertIn('Hech narsa nusxalanmadi', str(caught.exception))
        self.assertFalse((self.tmp / 'out').exists())

    def test_b_binaries_do_not_count_against_the_limit(self):
        self.put('a.py')
        self.put('blob.bin', b'\0' * 50_000)
        with patch.object(scanners, 'MAX_TOTAL', 10_000):
            coverage = scanners.snapshot(self.source, self.tmp / 'out')
        self.assertEqual((coverage['files'], coverage['skipped']['binary']), (1, 1))

    def test_c_progress_is_reported_and_names_the_total(self):
        for index in range(12):
            self.put(f'f{index}.py')
        seen = []
        with patch.object(scanners, 'PROGRESS_EVERY', 5):
            scanners.snapshot(self.source, self.tmp / 'out', progress=seen.append)
        self.assertTrue(seen and all('/12 fayl' in text for text in seen), seen)

    def test_d_a_cancellation_stops_the_copy(self):
        for index in range(5):
            self.put(f'f{index}.py')
        cancel = threading.Event()
        cancel.set()
        with self.assertRaises(scanners.Cancelled):
            scanners.snapshot(self.source, self.tmp / 'out', cancel=cancel)

    def test_e_a_path_too_long_for_windows_is_skipped_and_named_not_fatal(self):
        """Measured: one 214-character source path became 309 in the copy and
        failed the whole scan with FileNotFoundError."""
        self.put('ok.py')
        self.put('deep/' + 'n' * 60 + '.py')
        limit = len(str(self.tmp / 'out' / 'ok.py')) + 10
        with patch.object(scanners, 'IS_WINDOWS', True), patch.object(scanners, 'WINDOWS_PATH_LIMIT', limit):
            coverage = scanners.snapshot(self.source, self.tmp / 'out')
        self.assertEqual([e['path'] for e in coverage['manifest']], ['ok.py'])
        self.assertEqual(coverage['skipped']['path_too_long'], 1)
        self.assertEqual(coverage['path_too_long']['count'], 1)
        self.assertIn('THREATCHAIN_DATA_DIR', coverage['path_too_long']['action'])

    def test_f_an_ordinary_project_reports_the_same_four_counts_it_always_did(self):
        self.put('a.py')
        coverage = scanners.snapshot(self.source, self.tmp / 'out')
        self.assertEqual(sorted(coverage['skipped']), ['binary', 'excluded', 'large', 'links'])
        self.assertNotIn('path_too_long', coverage)
        self.assertNotIn('transcoded_utf16', coverage)

    def test_g_utf16_source_is_scanned_not_dropped_as_binary(self):
        self.put('win.py', 'password = eval(value)\n'.encode('utf-16'))
        coverage = scanners.snapshot(self.source, self.tmp / 'out')
        self.assertEqual((coverage['files'], coverage['skipped']['binary'], coverage['transcoded_utf16']), (1, 0, 1))
        self.assertEqual((self.tmp / 'out' / 'win.py').read_text(encoding='utf-8'), 'password = eval(value)\n')


class NormalizeSpeedTests(Workspace):
    """H2: 50 000 results reopened their files 50 000 times (41 s)."""

    def test_a_each_file_is_opened_once_per_normalisation(self):
        self.put('a.py', ''.join(f'call_{n}(x)\n' for n in range(200)))
        data = {'results': [{'check_id': 'r.x', 'path': 'a.py', 'start': {'line': n + 1}, 'extra': {}} for n in range(200)]}
        opened = []
        real = Path.open

        def counting(path, *args, **kwargs):
            if path.name == 'a.py':
                opened.append(1)
            return real(path, *args, **kwargs)
        with patch.object(Path, 'open', counting):
            rows = scanners.normalize('semgrep', data, self.source)
        self.assertEqual(len(opened), 1)
        self.assertEqual(len({row['fingerprint'] for row in rows}), 200)

    def test_b_a_changed_file_is_read_again_on_the_next_scan(self):
        data = {'results': [{'check_id': 'r.x', 'path': 'a.py', 'start': {'line': 1}, 'extra': {}}]}
        self.put('a.py', 'first(x)\n')
        before = scanners.normalize('semgrep', data, self.source)[0]['fingerprint']
        self.put('a.py', 'second(x)\n')
        self.assertNotEqual(scanners.normalize('semgrep', data, self.source)[0]['fingerprint'], before)


class CancelAndVersionTests(Workspace):
    """H3, H4: a code scan could not be stopped; a wrong tool version said nothing."""

    def scan(self, **patches):
        self.put('demo.txt', 'demo')
        result = subprocess.CompletedProcess([], 0, json.dumps({'results': [], 'errors': []}), '')
        with patch.object(scanners, 'RUNS', self.tmp / 'runs'), \
                patch.object(scanners, 'target_root', return_value=self.source), \
                patch.object(scanners, 'version', return_value=patches.pop('version', '1.2.3')), \
                patch.object(scanners, 'run_tool', return_value=patches.pop('run', result)), \
                patch.object(triage, 'record_scan', return_value=False):
            for name, value in patches.items():
                patcher = patch.object(scanners, name, value)
                patcher.start()
                self.addCleanup(patcher.stop)
            return scanners.start('test', background=False)

    def test_a_a_scan_cancelled_before_its_tools_is_cancelled_not_failed(self):
        real = scanners.snapshot

        def cancelling(*args, **kwargs):
            coverage = real(*args, **kwargs)
            next(iter(scanners.CANCEL.values())).set()
            return coverage
        report = self.scan(snapshot=cancelling)
        self.assertEqual(report['state'], 'cancelled')
        self.assertEqual(report['tools'], {})
        self.assertFalse(scanners.LOCK.locked())
        self.assertEqual(scanners.CANCEL, {})
        self.assertEqual(list((self.tmp / 'runs' / report['id']).glob('work-*')), [])

    def test_b_cancelling_a_scan_that_is_not_running_here_is_an_error(self):
        report = self.scan()
        with patch.object(scanners, 'RUNS', self.tmp / 'runs'), self.assertRaises(ValueError):
            scanners.cancel(report['id'])

    def test_c_the_report_records_who_owns_it(self):
        report = self.scan()
        self.assertEqual(report['pid'], os.getpid())
        self.assertNotIn('progress', report)

    def test_d_a_failing_tool_of_another_version_says_so(self):
        failed = subprocess.CompletedProcess([], 126, '', 'unknown flag')
        with patch.object(scanners, 'pinned_version', lambda tool: '8.30.1' if tool == 'gitleaks' else None):
            report = self.scan(version='8.24.3', run=failed)
        tool = report['tools']['gitleaks']
        self.assertEqual((tool['state'], tool['exit_code'], tool['version']), ('failed', 126, '8.24.3'))
        self.assertIn('8.24.3', tool['message'])
        self.assertIn('8.30.1', tool['message'])

    def test_e_the_pinned_versions_are_read_from_the_installer(self):
        scanners._PINNED.clear()
        self.assertRegex(scanners.pinned_version('gitleaks') or '', r'^\d+\.\d+\.\d+$')
        self.assertIsNone(scanners.version_note('gitleaks', scanners.pinned_version('gitleaks')))


class WorkerCountTests(unittest.TestCase):
    """H5: six workers on a machine with 1 GB free stopped it answering."""

    def test_a_small_projects_get_two_workers_when_memory_allows(self):
        # Since 2026-10-13 a small project is memory-capped too (tests/test_beta_scan.py).
        with patch.object(scanners, 'available_memory_mb', return_value=64000):
            self.assertEqual(scanners.semgrep_jobs(1), 2)

    def test_b_free_memory_caps_the_workers(self):
        with patch.object(scanners, 'available_memory_mb', return_value=800), patch.object(scanners.os, 'cpu_count', return_value=12):
            self.assertEqual(scanners.semgrep_jobs(5), 1)
        with patch.object(scanners, 'available_memory_mb', return_value=64000), patch.object(scanners.os, 'cpu_count', return_value=12):
            self.assertEqual(scanners.semgrep_jobs(5), 6)
        with patch.object(scanners, 'available_memory_mb', return_value=None), patch.object(scanners.os, 'cpu_count', return_value=12):
            self.assertEqual(scanners.semgrep_jobs(5), 6)

    def test_c_the_probes_answer_on_this_platform(self):
        self.assertTrue(available_memory_mb() is None or available_memory_mb() > 0)
        self.assertTrue(process_alive(os.getpid()))
        self.assertFalse(process_alive(0))


RID = '20260101T000000-aaaaaaaa'


class StatusSidecarTests(Workspace):
    """H6: a progress poll parsed the whole report -- 2.2 s for 46 MB."""

    def test_a_every_report_write_leaves_a_small_status_file(self):
        runs = self.tmp / 'runs'
        report = {'id': RID, 'target': 't', 'state': 'running', 'progress': 'semgrep', 'count': 3,
                  'findings': [{'x': 'y' * 1000}] * 50, 'pid': 7}
        repo_store.write_json(runs / RID / 'report.json', report)
        view = run_index.status(runs, RID)
        self.assertEqual((view['state'], view['progress'], view['count']), ('running', 'semgrep', 3))
        self.assertNotIn('findings', view)
        self.assertLess((runs / RID / 'status.json').stat().st_size, 400)

    def test_b_an_assessment_carries_its_stage_states(self):
        runs = self.tmp / 'runs'
        repo_store.write_json(runs / RID / 'report.json',
                              {'id': RID, 'state': 'running', 'stages': [{'kind': 'code', 'target': 't', 'state': 'running',
                                                                           'report': {'findings': [1, 2, 3]}}]})
        self.assertEqual(run_index.status(runs, RID)['stages'], [{'kind': 'code', 'target': 't', 'state': 'running', 'count': None}])

    def test_c_nothing_else_gets_a_sidecar_and_a_bad_id_gets_none(self):
        repo_store.write_json(self.tmp / 'other' / 'report.json', {'state': 'completed'})
        self.assertFalse((self.tmp / 'other' / 'status.json').exists())
        self.assertIsNone(run_index.status(self.tmp, '../etc'))
        self.assertIsNone(run_index.status(self.tmp, RID))


class RecoveryTests(Workspace):
    """H7: a killed scan stayed `running` for ever and left its source copy on disk."""

    def report(self, runs, rid, **fields):
        folder = runs / rid
        (folder / 'work-abc' / 'source').mkdir(parents=True)
        (folder / 'work-abc' / 'source' / 'a.py').write_text('x', encoding='utf-8')
        repo_store.write_json(folder / 'report.json', {'id': rid, 'target': 't', 'state': 'running', 'findings': [],
                                                        'created_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                                                        **fields})
        return folder

    def recover(self, runs):
        class Module:
            RUNS = runs
            CANCEL = {}
        with patch.object(recovery, '_modules', lambda: (Module,)):
            return recovery.recover()

    def dead_pid(self):
        process = subprocess.Popen([__import__('sys').executable, '-c', 'pass'])
        process.wait()
        return process.pid

    def test_a_a_report_whose_process_is_gone_is_closed_and_cleaned(self):
        runs = self.tmp / 'runs'
        folder = self.report(runs, RID, pid=self.dead_pid())
        self.assertEqual(self.recover(runs), [{'stage': 'runs', 'id': RID}])
        report = json.loads((folder / 'report.json').read_text(encoding='utf-8'))
        self.assertEqual((report['state'], report['error_type']), ('failed', 'Interrupted'))
        self.assertIn('finished_at', report)
        self.assertEqual(list(folder.glob('work-*')), [])

    def test_b_a_report_owned_by_a_live_process_is_left_alone(self):
        runs = self.tmp / 'runs'
        folder = self.report(runs, RID, pid=os.getpid())
        self.assertEqual(self.recover(runs), [])
        self.assertEqual(json.loads((folder / 'report.json').read_text(encoding='utf-8'))['state'], 'running')
        self.assertTrue((folder / 'work-abc').is_dir())

    def test_c_without_a_pid_only_age_decides(self):
        runs = self.tmp / 'runs'
        fresh = self.report(runs, RID)
        old = self.report(runs, '20200101T000000-bbbbbbbb', created_at='2020-01-01T00:00:00+00:00')
        self.assertEqual([row['id'] for row in self.recover(runs)], [old.name])
        self.assertEqual(json.loads((fresh / 'report.json').read_text(encoding='utf-8'))['state'], 'running')


class BoardStoreTests(unittest.TestCase):
    """H8: the board was one Python list, rebuilt whole -- 10.8 s and 520 MB for
    150 000 rows, and eight concurrent requests rebuilt it eight times (102 s)."""

    def setUp(self):
        isolate_triage(self)
        self.reads = []
        self.ids = {'app': '20260101T000000-aaaaaaaa', 'lib': '20260101T000000-bbbbbbbb'}

        def read(rid):
            self.reads.append(rid)
            time.sleep(0.05)
            target = next(t for t, i in self.ids.items() if i == rid)
            mark = 'a' if target == 'app' else 'b'
            return {'id': rid, 'target': target, 'state': 'completed', 'created_at': '2026-01-01T00:00:00+00:00',
                    'findings': [{'fingerprint': f'{mark}{n:023x}', 'rule_id': 'r', 'severity': 'ERROR', 'path': 'a.py',
                                  'line': n + 1, 'cwe_ids': [], 'owasp_top10_2025': []} for n in range(30)]}
        world = {'code': (read, lambda limit: [{'id': rid, 'target': target, 'state': 'completed'}
                                               for target, rid in self.ids.items()], 'target')}
        for name, value in (('sources', lambda: world), ('registered', lambda stage: set(self.ids) if stage == 'code' else set()),
                            ('chain_rows', lambda stage: []), ('project_of', lambda stage, target: '_' + target)):
            patcher = patch.object(findings_index, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        findings_index.invalidate()
        self.addCleanup(findings_index.invalidate)

    def expire(self):
        findings_store._STATE['at'] = 0.0               # older than any sync interval

    def test_a_concurrent_searches_read_each_report_once(self):
        results = []
        threads = [threading.Thread(target=lambda: results.append(findings_index.search()['total'])) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(results, [60] * 8)
        self.assertEqual(sorted(self.reads), sorted(self.ids.values()))

    def test_b_nothing_is_read_again_while_nothing_changed(self):
        findings_index.search()
        self.expire()
        findings_index.search(query='r', filters={'severity': 'HIGH'})
        self.assertEqual(len(self.reads), 2)

    def test_c_a_new_scan_of_one_target_reads_only_that_report(self):
        findings_index.search()
        self.reads.clear()
        self.ids['app'] = '20260102T000000-cccccccc'
        self.expire()
        self.assertEqual(findings_index.search()['total'], 60)
        self.assertEqual(self.reads, ['20260102T000000-cccccccc'])

    def test_d_a_decision_reaches_the_board_without_reading_a_report(self):
        findings_index.search()
        self.reads.clear()
        chosen = 'a' + '0' * 23
        triage.decide('_app', chosen, 'false_positive', 'tester', 'sabab')
        result = findings_index.search(filters={'status': 'false_positive'})
        self.assertEqual([row['fingerprint'] for row in result['rows']], [chosen])
        self.assertFalse(result['rows'][0]['open'])
        self.assertEqual(findings_index.search(filters={'state': 'open'})['total'], 59)
        self.assertEqual(self.reads, [])

    def test_e_a_decision_made_by_another_process_is_picked_up(self):
        findings_index.search()
        self.reads.clear()
        chosen = 'b' + '0' * 23
        with patch.object(findings_index, 'triage_changed', lambda scope, prints: None):
            triage.decide('_lib', chosen, 'accepted_risk', 'tester', 'sabab')
        self.expire()
        self.assertEqual(findings_index.search(filters={'status': 'accepted_risk'})['total'], 1)
        self.assertEqual(self.reads, [])

    def test_f_paging_sorting_and_facets_come_from_the_table(self):
        page = findings_index.search(offset=55, limit=50)
        self.assertEqual((page['total'], len(page['rows'])), (60, 5))
        self.assertEqual(page['facets']['project'], {'_app': 30, '_lib': 30})
        self.assertEqual(findings_index.search(filters={'project': '_lib'})['facets']['project'], {'_app': 30, '_lib': 30})
        detail = findings_index.detail('a' + '0' * 23)
        self.assertEqual((detail['row']['target'], detail['finding']['line']), ('app', 1))


class BoardRestartTests(BoardStoreTests):
    """A restart rebuilt the board from nothing: 18 s for 150 000 rows, 2 s when kept."""

    def setUp(self):
        super().setUp()
        self.folder = Path(tempfile.mkdtemp())
        self.addCleanup(__import__('shutil').rmtree, self.folder, True)
        saved = dict(findings_store._STATE)
        self.addCleanup(lambda: findings_store._STATE.update(saved, force=True, at=0.0))

    def restart(self):
        """What a new server process does: point at the kept file and search."""
        self.assertTrue(findings_store.persist(self.folder / 'board.sqlite3'))
        return findings_index.search()

    def test_g_a_restart_keeps_the_rows_and_reads_no_report(self):
        self.assertEqual(self.restart()['total'], 60)
        self.reads.clear()
        self.assertEqual(self.restart()['total'], 60)
        self.assertEqual(self.reads, [])

    def test_h_a_scan_made_while_the_server_was_down_is_still_noticed(self):
        self.restart()
        self.reads.clear()
        self.ids['lib'] = '20260103T000000-dddddddd'
        self.assertEqual(self.restart()['total'], 60)
        self.assertEqual(self.reads, ['20260103T000000-dddddddd'])

    def test_i_a_file_from_another_version_is_rebuilt_not_trusted(self):
        self.restart()
        db = findings_store.connect()
        db.execute('PRAGMA user_version = 1')
        db.close()
        self.reads.clear()
        self.assertEqual(self.restart()['total'], 60)
        self.assertEqual(len(self.reads), 2)

    def test_j_an_unreadable_file_is_replaced(self):
        (self.folder / 'board.sqlite3').write_bytes(b'not a database at all')
        self.assertEqual(self.restart()['total'], 60)


class BulkTriageTests(unittest.TestCase):
    """H9: closing 200 findings rewrote an 8.7 MB file 200 times (110 s)."""

    def setUp(self):
        isolate_triage(self)

    def test_a_many_decisions_are_one_write_and_still_one_event_each(self):
        prints = [f'{n:024x}' for n in range(60)]
        with patch.object(triage, 'write', wraps=triage.write) as write:
            records = triage.decide_many('_demo', prints + prints[:5], 'accepted_risk', 'tester', 'sabab')
        self.assertEqual(write.call_count, 1)
        self.assertEqual(len(records), 60)
        self.assertEqual(len(triage.events('_demo')), 60)
        stored = triage.read('_demo')['decisions']
        self.assertEqual({stored[p]['status'] for p in prints}, {'accepted_risk'})

    def test_b_one_bad_value_stores_nothing(self):
        with self.assertRaises(ValueError):
            triage.decide_many('_demo', ['0' * 24, 'not-a-fingerprint'], 'fixed', 'tester', 'sabab')
        with self.assertRaises(ValueError):
            triage.decide_many('_demo', ['0' * 24], 'fixed', '', 'sabab')
        self.assertEqual(triage.read('_demo')['decisions'], {})


class DependencyVolumeTests(Workspace):
    """H10: 40 services sharing 400 packages were refused; 2 500 of 4 000 advisories were dropped."""

    def monorepo(self, services, packages):
        for s in range(services):
            lock = {'name': f's{s}', 'lockfileVersion': 3, 'packages': {'': {'name': f's{s}'}}}
            for p in range(packages):
                lock['packages'][f'node_modules/pkg{p}'] = {'version': '1.0.0'}
            self.put(f'svc{s}/package.json', '{}')
            self.put(f'svc{s}/package-lock.json', json.dumps(lock))

    def test_a_the_limit_counts_distinct_packages_not_copies(self):
        self.monorepo(services=8, packages=10)
        with patch.object(inventory, 'MAX_PACKAGES', 15):
            found = inventory.collect(self.source)
        self.assertEqual((found['occurrences'], found['unique_packages']), (80, 10))

    def test_b_it_is_still_a_limit(self):
        # Still a bound, but it ends the walk with a `package_limit` gap and keeps
        # what was collected instead of failing the stage (shortcomings review
        # 2026-11-02, LP#12); the CI gate counts that as incomplete.
        self.monorepo(services=2, packages=10)
        for name, value in (('MAX_PACKAGES', 5), ('MAX_OCCURRENCES', 15)):
            with patch.object(inventory, name, value):
                found = inventory.collect(self.source)
            self.assertIn('package_limit', [gap['reason'] for gap in found['gaps']], name)
            self.assertTrue(found['packages'], name)

    def test_c_every_matched_advisory_is_fetched(self):
        def fetcher(url, payload=None, salt=''):
            if url.endswith('querybatch'):
                return {'results': [{'vulns': [{'id': 'GHSA-' + q['package']['name'], 'modified': 'x'}]}
                                    for q in payload['queries']]}, {}
            vid = url.rsplit('/', 1)[1]
            return {'id': vid, 'aliases': [], 'summary': 's', 'database_specific': {'severity': 'HIGH'},
                    'affected': [{'package': {'ecosystem': 'npm', 'name': vid[5:]}, 'ranges': []}]}, {}
        packages = [{'ecosystem': 'npm', 'name': f'pkg{n:05}', 'version': '1.0.0', 'manifest': 'package-lock.json'}
                    for n in range(1700)]
        matches, details, errors, _ = advisories.query_packages(packages, fetcher)
        self.assertEqual((len(details), errors), (1700, []))
        self.assertEqual(len(advisories.normalize(packages, matches, details, {}, True)), 1700)


def code_report(state='partial', **tools):
    return {'id': RID, 'target': 't', 'state': state, 'findings': [{'fingerprint': 'a' * 24}],
            'tools': tools or {'semgrep': {'state': 'partial', 'errors': 6}, 'gitleaks': {'state': 'completed'}}}


class GapBaselineTests(unittest.TestCase):
    """H11: 6 unparsed files of 26 499 made the scan `partial`, and a partial scan
    could be neither a baseline nor the ground a chain stands on."""

    def test_a_unread_files_alone_do_not_disqualify_a_baseline(self):
        self.assertTrue(baseline.gap_only(code_report()))
        self.assertTrue(baseline.usable(code_report()))
        self.assertTrue(baseline.usable(code_report(state='completed')))

    def test_b_a_tool_that_did_not_run_still_does(self):
        report = code_report(semgrep={'state': 'completed'}, gitleaks={'state': 'failed'})
        self.assertFalse(baseline.usable(report))
        self.assertFalse(baseline.usable(code_report(state='failed')))
        self.assertFalse(baseline.usable(code_report(state='cancelled')))

    def assessment(self, child):
        return {'id': RID, 'state': 'partial', 'selection': {},
                'stages': [{'kind': 'code', 'target': 't', 'state': child['state'], 'report': child},
                           {'kind': 'web', 'target': '', 'state': 'not_selected'}]}

    def test_c_the_same_line_is_drawn_for_an_assessment(self):
        self.assertTrue(baseline.usable(self.assessment(code_report())))
        broken = code_report(semgrep={'state': 'failed'}, gitleaks={'state': 'completed'})
        self.assertFalse(baseline.usable(self.assessment(broken)))

    def test_d_the_comparison_says_what_the_gap_can_do_to_it(self):
        result = baseline.diff(code_report(), code_report())
        self.assertIn(baseline.GAP_WARNING, result['warnings'])
        self.assertFalse(any('ishonchli emas' in text for text in result['warnings']))

    def test_e_a_chain_may_rest_on_a_gap_only_code_stage(self):
        report = self.assessment(code_report())
        self.assertIs(pipeline.stage_report(report, 'code'), report['stages'][0]['report'])
        broken = self.assessment(code_report(semgrep={'state': 'failed'}, gitleaks={'state': 'completed'}))
        self.assertIsNone(pipeline.stage_report(broken, 'code'))


class ChainVolumeTests(unittest.TestCase):
    """H12: 40 services built from `.` and 3 000 findings were 60 000 chain findings."""

    def result(self, count):
        repo = {'services': [{'id': 'web', 'build_context': '.', 'ports': [{'scope': 'all_interfaces'}]}], 'findings': []}
        code = {'findings': [{'tool': 'semgrep', 'rule_id': 'sqli', 'path': f'app/m{n:04}.py', 'line': 1,
                              'severity': 'ERROR', 'cwe_ids': ['CWE-89'], 'fingerprint': f'{n:024x}'}
                             for n in range(count)]}
        return chains.correlate_all({'code': code, 'repository': repo})

    def test_a_a_service_shows_the_limit_and_reports_the_rest(self):
        result = self.result(120)
        self.assertEqual(len(result['findings']), chains.CHAIN_LIMIT)
        gap = next(g for g in result['gaps'] if g['kind'] == 'chain_limit')
        self.assertEqual((gap['rule_id'], gap['service'], gap['shown'], gap['total']), ('SX-004', 'web', chains.CHAIN_LIMIT, 120))

    def test_b_the_same_ones_are_kept_on_every_scan(self):
        self.assertEqual([f['fingerprint'] for f in self.result(120)['findings']],
                         [f['fingerprint'] for f in self.result(120)['findings']])

    def test_c_under_the_limit_nothing_is_cut(self):
        result = self.result(chains.CHAIN_LIMIT)
        self.assertEqual(len(result['findings']), chains.CHAIN_LIMIT)
        self.assertFalse([g for g in result['gaps'] if g['kind'] == 'chain_limit'])


class ComposeScaleTests(Workspace):
    """H13: 201 services were refused, a published port range found nothing, `include:` was skipped."""

    def scan(self, text, name='docker-compose.yml'):
        self.put(name, text)
        return scan_repository(self.source, name)

    def test_a_a_port_range_is_an_exposure(self):
        report = self.scan('services:\n  web:\n    image: x\n    ports: ["8000-8010:8000-8010"]\n')
        self.assertEqual([f['rule_id'] for f in report['findings']], ['RP-001'])
        self.assertEqual(report['unknowns'], [])
        self.assertEqual(port_mapping('127.0.0.1:8000-8010:8000-8010')['scope'], 'loopback')

    def test_b_more_than_two_hundred_services(self):
        body = ''.join(f'  s{n}:\n    image: myorg/s{n}\n    ports: ["{9000 + n}:80"]\n' for n in range(450))
        report = self.scan('services:\n' + body)
        self.assertEqual(report['summary']['services'], 450)
        self.assertEqual(len(report['findings']), 450)

    def test_c_it_is_still_a_limit(self):
        # Still a bound, but no longer a failure (shortcomings review 2026-11-02,
        # LP#12): the first MAX_SERVICES are analysed, the rest are counted as
        # never reached, and the CI gate treats that as an incomplete check.
        with patch.object(repository, 'MAX_SERVICES', 2):
            report = self.scan('services:\n  a: {image: x}\n  b: {image: x}\n  c: {image: x}\n')
        self.assertEqual(report['summary']['services'], 2)
        self.assertEqual(report['coverage_gaps']['not_reached'], 1)

    def test_d_included_files_are_read_and_evidence_points_at_them(self):
        self.put('infra/db.yml', 'services:\n  db:\n    image: postgres:16\n  cache:\n    image: redis:7\n    ports: ["6379:6379"]\n')
        report = self.scan('include:\n  - infra/db.yml\n  - path: missing.yml\nservices:\n  web:\n    image: x\n    ports: ["80:80"]\n')
        self.assertEqual(sorted(s['id'] for s in report['services']), ['cache', 'db', 'web'])
        rules = {(f['rule_id'], f['service_id']) for f in report['findings']}
        self.assertTrue({('RP-001', 'web'), ('RP-001', 'cache'), ('RP-005', 'db')} <= rules, rules)
        cache = next(e for e in report['evidence'] if e['label'] == 'Xizmat' and e['value'] == 'cache')
        self.assertEqual((cache['path'], cache['line']), ('infra/db.yml', 5))      # where the service body starts
        self.assertTrue(any('missing.yml' in text for text in report['unknowns']))
        self.assertIn('infra/db.yml', [f['path'] for f in report['files']])

    def test_e_the_main_file_wins_and_an_include_cannot_leave_the_repository(self):
        self.put('other.yml', 'services:\n  web:\n    image: from-include\n')
        report = self.scan('include: [other.yml, ../outside.yml]\nservices:\n  web:\n    image: from-main\n')
        self.assertEqual([s['image'] for s in report['services']], ['from-main'])
        self.assertTrue(any('outside.yml' in text for text in report['unknowns']))

    def test_f_a_build_context_is_rebased_onto_the_repository_root(self):
        self.assertEqual(repository.rebase('deploy/docker-compose.yml', '../api'), 'api')
        self.assertEqual(repository.rebase('docker-compose.yml', 'api'), 'api')
        self.assertEqual(repository.rebase('docker-compose.yml', '.'), '.')
        self.assertEqual(repository.rebase('docker-compose.yml', '../elsewhere'), '../elsewhere')
        report = self.scan('services:\n  api:\n    build: ../api\n    ports: ["80:80"]\n', name='deploy/compose.yml')
        self.assertEqual(report['services'][0]['build_context'], 'api')


class RuleSourceTests(unittest.TestCase):
    """H14: `$REQ.GET` as a taint source matched `Command.GET` -- Selenium's
    `self.execute(Command.GET, ...)` was the one false finding that stopped the gate."""

    def test_a_django_request_data_is_matched_as_a_mapping_only(self):
        text = (ROOT / 'scanner-rules' / 'semgrep.yml').read_text(encoding='utf-8')
        lines = [line.strip() for line in text.splitlines()]
        self.assertNotIn('- pattern: $REQ.GET', lines)
        self.assertNotIn('- pattern: $REQ.POST', lines)
        self.assertIn('- pattern: $REQ.GET.get(...)', lines)
        self.assertIn('- pattern: $REQ.POST[...]', lines)

    def test_b_the_generic_key_allowlist_stays_narrow(self):
        """Measured on a 26 503-file tree: 35 of 66 generic-api-key hits were
        identifiers, stub annotations or time zones. The allowlist must stay
        limited to that one rule and must never accept a credential's shape."""
        import re
        import tomllib
        config = tomllib.loads((ROOT / 'scanner-rules' / 'gitleaks.toml').read_text(encoding='utf-8'))
        lists = [a for a in config.get('allowlists') or [] if a.get('targetRules')]
        self.assertEqual([a['targetRules'] for a in lists], [['generic-api-key']])
        patterns = [re.compile(p) for p in lists[0]['regexes']]
        allowed = lambda value: any(p.search(value) for p in patterns)
        for value in ('PASSWD_MAX', '_argon2.PASSWD_MAX', '_win32typing.PyIID', 'Europe/Dublin', 'America/Argentina/Buenos_Aires'):
            self.assertTrue(allowed(value), value)
        for value in ('sk_' + 'live_51HqLyjWDarjtT1zdp7dcXr2r', 'AI' + 'zaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI',
                      'gh' + 'p_16C7e42F292c6912E7710c838347Ae178B4a', 'a3f1c9e8b2d74f60a1b5c3d9e7f2a8b4',
                      'xo' + 'xb-2134123412-2341234123-AbCdEfGhIjKlMnOpQrStUvWx', 'Zm9vYmFyYmF6cXV4LnF1dXg='):
            self.assertFalse(allowed(value), value)


if __name__ == '__main__':
    unittest.main(verbosity=2)
