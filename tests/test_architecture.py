"""The three structural changes made for large projects (MUAMMOLAR.md, section I).

  1. Incremental scanning  -- a file that did not change is not read and not
                              scanned again (zanjir/scan_cache.py).
  2. Reports by reference  -- an assessment names its stage reports instead of
                              copying them; a large report has a page view.
  3. Bounded exports       -- paging on every report URL, a result limit on SARIF.

The findings board on SQLite is covered in tests/test_load_findings.py (H8).
Every test here states the property that makes the change safe, not only that
it is faster: an incremental scan must report exactly what a full one reports.
"""
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from zanjir import pipeline, repo_store, repository, run_index, sarif_export, scan_cache, scanners, triage
from zanjir.repository import merge_service, scan_repository


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


class FakeScanner:
    """Stands in for Semgrep: reports one finding per `eval(` line of every file
    in the folder it is run in, and remembers which files it was shown."""

    def __init__(self):
        self.runs = []

    def __call__(self, command, cwd, env, timeout, cancel=None, **low):
        if 'dir' in command:                                  # gitleaks: nothing found
            return subprocess.CompletedProcess(command, 0, '[]', '')
        seen, results = [], []
        for path in sorted((Path(cwd) / 'source').rglob('*')):
            if not path.is_file():
                continue
            relative = path.relative_to(Path(cwd) / 'source').as_posix()
            seen.append(relative)
            for number, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
                if 'eval(' in line:
                    results.append({'check_id': 'demo.eval', 'path': 'source/' + relative, 'start': {'line': number},
                                    'extra': {'severity': 'WARNING'}})
        self.runs.append(seen)
        return subprocess.CompletedProcess(command, 0, json.dumps({'results': results, 'errors': []}), '')


class IncrementalScanTests(Workspace):
    """Measured on real code: 37 s for a first scan, 7 s when nothing changed."""

    def setUp(self):
        super().setUp()
        self.put('a.py', 'eval(x)\n')
        self.put('pkg/b.py', 'y = 2\neval(y)\n')
        self.put('pkg/c.py', 'z = 3\n')
        self.tool = FakeScanner()
        for patcher in (patch.object(scanners, 'RUNS', self.tmp / 'runs'),
                        patch.object(scanners, 'target_root', return_value=self.source),
                        patch.object(scanners, 'version', return_value='1.2.3'),
                        patch.object(scanners, 'run_tool', self.tool),
                        patch.object(scanners, 'history_secrets', return_value=({'state': 'not_applicable'}, [])),
                        patch.object(triage, 'record_scan', return_value=False)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def scan(self, **kwargs):
        self.tool.runs.clear()
        report = scanners.start('demo', background=False, **kwargs)
        self.assertEqual(report['state'], 'completed', report)
        return report

    def what(self, report):
        return sorted((f['path'], f['line'], f['fingerprint']) for f in report['findings'])

    def test_a_an_unchanged_project_is_not_read_and_not_scanned_again(self):
        first = self.scan()
        self.assertEqual(first['coverage']['incremental'], {'mode': 'incremental', 'files_scanned': 3, 'files_reused': 0,
                                                             'files_not_reopened': 0})
        reads = []
        real = Path.read_bytes

        def counting(path):
            if self.source in path.parents:
                reads.append(path.name)
            return real(path)
        with patch.object(Path, 'read_bytes', counting):
            second = self.scan()
        self.assertEqual(reads, [], 'an unchanged file must not be opened')
        self.assertEqual(self.tool.runs, [], 'no scanner should have run')
        self.assertEqual(second['coverage']['incremental']['files_reused'], 3)
        self.assertEqual(second['tools']['semgrep']['files_reused'], 3)
        self.assertEqual(self.what(second), self.what(first))
        self.assertEqual(second['coverage']['snapshot_sha256'], first['coverage']['snapshot_sha256'])

    def test_b_only_the_edited_file_is_scanned_and_its_new_finding_appears(self):
        first = self.scan()
        self.put('pkg/c.py', 'z = 3\neval(z)\neval(z)\n')
        second = self.scan()
        self.assertEqual([run for run in self.tool.runs if run], [['pkg/c.py']])
        self.assertEqual(len(second['findings']), len(first['findings']) + 2)
        self.assertEqual(len({f['fingerprint'] for f in second['findings']}), 4)
        self.assertTrue(set(self.what(first)) <= set(self.what(second)))

    def test_c_an_incremental_result_equals_a_full_one(self):
        self.scan()
        self.put('a.py', 'safe = 1\n')
        self.put('new/d.py', 'eval(d)\n')
        (self.source / 'pkg' / 'c.py').unlink()
        incremental = self.scan()
        full = self.scan(full=True)
        self.assertEqual(full['coverage']['incremental']['mode'], 'full')
        self.assertEqual(self.what(incremental), self.what(full))
        self.assertEqual(incremental['coverage']['files'], full['coverage']['files'])
        self.assertEqual(incremental['coverage']['snapshot_sha256'], full['coverage']['snapshot_sha256'])

    def test_d_a_rule_or_tool_change_scans_everything_again(self):
        self.scan()
        with patch.object(scanners, 'version', return_value='9.9.9'):
            report = self.scan()
        self.assertEqual(report['tools']['semgrep']['files_scanned'], 3)
        with patch.object(scanners, 'tool_context', lambda tool, *rest: 'other-rules-' + tool):
            self.assertEqual(self.scan()['tools']['semgrep']['files_scanned'], 3)

    def test_e_a_tool_that_failed_is_asked_again_without_dragging_the_others_along(self):
        tool = self.tool

        def gitleaks_down(command, cwd, env, timeout, cancel=None, **low):
            if 'dir' in command:
                return subprocess.CompletedProcess(command, 126, '', 'unknown flag')
            return tool(command, cwd, env, timeout, cancel, **low)
        with patch.object(scanners, 'run_tool', gitleaks_down):
            scanners.start('demo', background=False)
            tool.runs.clear()
            report = scanners.start('demo', background=False)
        self.assertEqual(report['tools']['gitleaks']['state'], 'failed')
        self.assertEqual(report['tools']['semgrep']['files_scanned'], 0)
        self.assertEqual(tool.runs, [])
        self.assertEqual(len(report['findings']), 2)

    def test_f_the_environment_switch_forces_a_full_scan(self):
        self.scan()
        with patch.dict(os.environ, {scanners.FULL_SCAN_VARIABLE: '1'}):
            report = self.scan()
        self.assertEqual(report['coverage']['incremental']['mode'], 'full')
        self.assertEqual(self.tool.runs[0], ['a.py', 'pkg/b.py', 'pkg/c.py'])

    def test_g_a_damaged_cache_means_a_full_scan_not_an_error(self):
        first = self.scan()
        (scanners.cache_folder() / 'demo.sqlite3').write_bytes(b'not a database')
        second = self.scan()
        self.assertEqual(second['tools']['semgrep']['files_scanned'], 3)
        self.assertEqual(self.what(second), self.what(first))

    def test_h_the_cache_lives_beside_the_runs_never_in_the_project(self):
        self.scan()
        self.assertTrue((self.tmp / 'scan-cache' / 'demo.sqlite3').is_file())
        self.assertEqual(sorted(p.name for p in self.source.iterdir()), ['a.py', 'pkg'])


class ScanCacheTests(Workspace):
    def test_a_lookup_needs_the_same_size_and_mtime(self):
        cache = scan_cache.open_cache(self.tmp / 'c', 'demo')
        cache.remember('a.py', 10, 111, 'sha', 'text', 10)
        cache.finish()
        self.assertEqual(cache.lookup('a.py', 10, 111), ('sha', 'text', 10))
        self.assertIsNone(cache.lookup('a.py', 11, 111))
        self.assertIsNone(cache.lookup('a.py', 10, 112))
        cache.close()

    def test_b_results_of_a_file_that_is_gone_are_forgotten(self):
        cache = scan_cache.open_cache(self.tmp / 'c', 'demo')
        cache.store('ctx', 'semgrep', [('a.py', 's1', [{'x': 1}], []), ('b.py', 's2', [], [])])
        cache.remember('a.py', 1, 1, 's1', 'text', 1)
        cache.finish()
        cache.close()
        cache = scan_cache.open_cache(self.tmp / 'c', 'demo')
        cache.load({'semgrep': 'ctx'})
        self.assertEqual(cache.get('semgrep', 'a.py', 's1'), ([{'x': 1}], []))
        self.assertIsNone(cache.get('semgrep', 'b.py', 's2'))
        self.assertIsNone(cache.get('semgrep', 'a.py', 'other-content'))
        cache.load({'semgrep': 'another-context'})
        self.assertIsNone(cache.get('semgrep', 'a.py', 's1'))
        cache.close()

    def test_c_a_target_name_cannot_leave_the_cache_folder(self):
        self.assertIsNone(scan_cache.open_cache(self.tmp / 'c', '../escape'))
        self.assertIsNone(scan_cache.open_cache(self.tmp / 'c', ''))


class ToolProcessTests(Workspace):
    """A cancellation used to wait for the running scanner to finish on its own."""

    def test_a_output_is_returned_and_the_exit_code_kept(self):
        done = scanners.run_tool([sys.executable, '-c', 'import sys;print("out");print("err",file=sys.stderr);sys.exit(3)'],
                                 self.tmp, None, 60)
        self.assertEqual((done.returncode, done.stdout.strip(), done.stderr.strip()), (3, 'out', 'err'))
        self.assertEqual(list(self.tmp.glob('tmp*')), [])

    def test_b_a_cancellation_kills_the_running_tool(self):
        cancel = threading.Event()
        threading.Timer(1.0, cancel.set).start()
        with self.assertRaises(scanners.Cancelled):
            scanners.run_tool([sys.executable, '-c', 'import time;time.sleep(60)'], self.tmp, None, 120, cancel)

    def test_c_the_time_limit_kills_it_too(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            scanners.run_tool([sys.executable, '-c', 'import time;time.sleep(60)'], self.tmp, None, 1)


class ScanSlotTests(unittest.TestCase):
    """One global lock meant one code scan for the whole installation."""

    def slots(self, capacity):
        slots = scanners.ScanSlots()
        patcher = patch.object(scanners.ScanSlots, 'capacity', staticmethod(lambda: capacity))
        patcher.start()
        self.addCleanup(patcher.stop)
        return slots

    def test_a_the_default_is_one_scan_at_a_time_as_before(self):
        slots = self.slots(1)
        self.assertTrue(slots.acquire('a'))
        self.assertFalse(slots.acquire('b'))
        self.assertTrue(slots.locked())
        slots.release('a')
        self.assertFalse(slots.locked())

    def test_b_a_higher_setting_lets_different_projects_run_together(self):
        slots = self.slots(2)
        self.assertTrue(slots.acquire('a'))
        self.assertTrue(slots.acquire('b'))
        self.assertFalse(slots.acquire('c'))

    def test_c_one_project_is_never_scanned_twice_at_once(self):
        slots = self.slots(4)
        self.assertTrue(slots.acquire('a'))
        self.assertFalse(slots.acquire('a'))
        self.assertTrue(slots.locked('a'))
        self.assertFalse(slots.locked('b'))


RID = '20260101T000000-aaaaaaaa'
CHILD = '20260101T000001-bbbbbbbb'


def finding(n, severity='WARNING'):
    return {'fingerprint': f'{n:024x}', 'rule_id': 'r', 'path': 'a.py', 'line': n + 1, 'severity': severity,
            'tool': 'semgrep', 'message': 'm'}


class ReportViewTests(Workspace):
    """A report screen was sent the whole report: 55 MB for 50 000 findings."""

    def write(self, count, **fields):
        findings = [finding(n, 'ERROR' if n % 100 == 99 else 'WARNING') for n in range(count)]
        repo_store.write_json(self.tmp / 'runs' / RID / 'report.json',
                              {'id': RID, 'target': 't', 'state': 'completed', 'count': count, 'findings': findings, **fields})

    def test_a_a_small_report_has_no_view_and_is_returned_whole(self):
        self.write(50)
        self.assertIsNone(run_index.view(self.tmp / 'runs', RID))
        with patch.object(scanners, 'RUNS', self.tmp / 'runs'), patch.object(triage, 'TRIAGE', self.tmp / 'triage'):
            self.assertEqual(len(scanners.read_view(RID)['findings']), 50)

    def test_b_a_large_report_shows_its_worst_findings_and_says_how_many_there_are(self):
        total = run_index.VIEW_LIMIT + 700
        self.write(total)
        with patch.object(scanners, 'RUNS', self.tmp / 'runs'), patch.object(triage, 'TRIAGE', self.tmp / 'triage'):
            view = scanners.read_view(RID)
            full = scanners.read_report(RID)
        self.assertEqual((len(view['findings']), view['findings_total']), (run_index.VIEW_LIMIT, total))
        self.assertEqual(len(full['findings']), total)
        errors = sum(1 for f in full['findings'] if f['severity'] == 'ERROR')
        self.assertEqual(sum(1 for f in view['findings'] if f['severity'] == 'ERROR'), errors)
        self.assertIn(str(total), view['message'])
        self.assertIn('triage', view['findings'][0])

    def test_c_the_view_follows_the_report(self):
        self.write(run_index.VIEW_LIMIT + 1)
        self.assertIsNotNone(run_index.view(self.tmp / 'runs', RID))
        self.write(3)
        self.assertIsNone(run_index.view(self.tmp / 'runs', RID))

    def test_d_paging_returns_a_slice_and_the_total(self):
        import app
        report = {'id': RID, 'state': 'completed', 'findings': [finding(n) for n in range(25)]}
        page = app.page_of(report, {'offset': ['20'], 'limit': ['10']})
        self.assertEqual(([f['line'] for f in page['findings']], page['findings_total']), ([21, 22, 23, 24, 25], 25))
        self.assertIs(app.page_of(report, {}), report)
        self.assertEqual(len(app.page_of(report, {'limit': ['999999']})['findings']), 25)
        self.assertIs(app.page_of(report, {'limit': ['abc']}), report)


class AssessmentByReferenceTests(Workspace):
    """An assessment carried a copy of every stage report: 54 MB, rewritten per stage."""

    def setUp(self):
        super().setUp()
        for patcher in (patch.object(pipeline, 'RUNS', self.tmp / 'assessments'),
                        patch.object(scanners, 'RUNS', self.tmp / 'code'),
                        patch.object(triage, 'TRIAGE', self.tmp / 'triage')):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.child = {'id': CHILD, 'target': 't', 'state': 'completed', 'count': 40,
                      'findings': [finding(n) for n in range(40)], 'tools': {}}
        repo_store.write_json(scanners.RUNS / CHILD / 'report.json', self.child)
        self.report = {'id': RID, 'state': 'completed', 'created_at': '2026-01-01T00:00:00+00:00', 'selection': {},
                       'limits': '', 'chain_findings': [],
                       'stages': [{'kind': 'code', 'target': 't', 'state': 'completed', 'count': 40,
                                   'report_id': CHILD, 'report': self.child},
                                  {'kind': 'web', 'target': '', 'state': 'not_selected'}]}

    def test_a_the_file_names_the_stage_report_and_does_not_copy_it(self):
        repo_store.write_json(pipeline.RUNS / RID / 'report.json', pipeline.slim(self.report))
        stored = json.loads((pipeline.RUNS / RID / 'report.json').read_text(encoding='utf-8'))
        self.assertNotIn('report', stored['stages'][0])
        self.assertEqual(stored['stages'][0]['report_stored'], pipeline.REFERENCE)
        self.assertLess((pipeline.RUNS / RID / 'report.json').stat().st_size, 1000)
        self.assertIn('report', self.report['stages'][0], 'the in-memory report must be left alone')

    def test_b_reading_it_gives_back_what_every_consumer_expects(self):
        repo_store.write_json(pipeline.RUNS / RID / 'report.json', pipeline.slim(self.report))
        report = pipeline.read(RID)
        child = report['stages'][0]['report']
        self.assertEqual(len(child['findings']), 40)
        self.assertIn('triage', child['findings'][0])
        self.assertIn(CHILD, pipeline.markdown(report))
        self.assertEqual(len(pipeline.sarif(report)['runs'][0]['results']), 40)

    def test_c_an_assessment_written_before_this_still_opens(self):
        repo_store.write_json(pipeline.RUNS / RID / 'report.json', self.report)
        self.assertEqual(len(pipeline.read(RID)['stages'][0]['report']['findings']), 40)

    def test_d_a_stage_report_that_is_gone_is_said_not_hidden(self):
        repo_store.write_json(pipeline.RUNS / RID / 'report.json', pipeline.slim(self.report))
        __import__('shutil').rmtree(scanners.RUNS / CHILD)
        stage = pipeline.read(RID)['stages'][0]
        self.assertEqual((stage['report'], stage['report_missing'], stage['count']), (None, True, 40))

    def test_e_a_forged_reference_cannot_name_a_file_elsewhere(self):
        forged = pipeline.slim(self.report)
        forged['stages'][0]['report_id'] = '../../../etc/passwd'
        repo_store.write_json(pipeline.RUNS / RID / 'report.json', forged)
        self.assertTrue(pipeline.read(RID)['stages'][0]['report_missing'])


class SarifLimitTests(unittest.TestCase):
    def runs(self):
        make = lambda level, n: {'ruleId': f'{level}-{n}', 'level': level}
        return [{'results': [make('warning', n) for n in range(30)] + [make('error', n) for n in range(5)]},
                {'results': [make('note', n) for n in range(10)] + [make('error', 99)]}]

    def test_a_without_a_limit_nothing_changes(self):
        runs = self.runs()
        self.assertIs(sarif_export.limit_results(runs, None), runs)
        self.assertIs(sarif_export.limit_results(runs, 1000), runs)

    def test_b_the_most_severe_are_kept_and_the_total_is_recorded(self):
        limited = sarif_export.limit_results(self.runs(), 10)
        kept = [r['level'] for run in limited for r in run['results']]
        self.assertEqual((len(kept), kept.count('error')), (10, 6))
        self.assertEqual(limited[0]['properties']['threatchain:results_total'], 35)
        self.assertTrue(limited[1]['properties']['threatchain:truncated'])
        self.assertEqual(limited[1]['results'], [{'ruleId': 'error-99', 'level': 'error'}])


class ComposeExtendsTests(Workspace):
    """`extends:` was noted and skipped, so what a service inherited was invisible."""

    def scan(self, text):
        self.put('docker-compose.yml', text)
        return scan_repository(self.source, 'docker-compose.yml')

    def test_a_inherited_ports_and_privileges_are_seen(self):
        report = self.scan('services:\n  base:\n    image: x\n    privileged: true\n    ports: ["8080:80"]\n'
                           '  web:\n    extends: base\n    image: myorg/web\n    environment:\n      DEBUG: "true"\n')
        rules = {(f['rule_id'], f['service_id']) for f in report['findings']}
        self.assertTrue({('RP-001', 'web'), ('RP-006', 'web'), ('RP-008', 'web')} <= rules, rules)
        self.assertEqual(report['unknowns'], [])

    def test_b_a_base_in_another_file(self):
        self.put('common/base.yml', 'services:\n  base:\n    image: x\n    cap_add: [SYS_ADMIN]\n    ports: ["9000:90"]\n')
        report = self.scan('services:\n  api:\n    extends:\n      file: common/base.yml\n      service: base\n    image: myorg/api\n')
        self.assertIn(('RP-008', 'api'), {(f['rule_id'], f['service_id']) for f in report['findings']})
        self.assertIn('common/base.yml', [f['path'] for f in report['files']])

    def test_c_compose_merge_rules(self):
        merged = merge_service({'ports': ['80:80'], 'environment': ['A=1', 'B=2'], 'command': ['a'], 'depends_on': ['db'],
                                'labels': {'x': '1'}},
                               {'extends': 'base', 'ports': ['443:443'], 'environment': {'B': '3'}, 'command': ['b'],
                                'labels': {'y': '2'}})
        self.assertEqual(merged['ports'], ['80:80', '443:443'])
        self.assertEqual(merged['environment'], {'A': '1', 'B': '3'})
        self.assertEqual(merged['command'], ['b'])
        self.assertEqual(merged['labels'], {'x': '1', 'y': '2'})
        self.assertNotIn('depends_on', merged)
        self.assertNotIn('extends', merged)

    def test_d_what_cannot_be_resolved_is_named(self):
        for text in ('services:\n  a:\n    extends: missing\n    image: x\n',
                     'services:\n  a:\n    extends: b\n    image: x\n  b:\n    extends: a\n    image: x\n',
                     'services:\n  a:\n    extends:\n      file: nowhere.yml\n      service: s\n    image: x\n'):
            with self.subTest(text=text):
                report = self.scan(text)
                self.assertTrue(any('extends yechilmadi' in note for note in report['unknowns']), report['unknowns'])


class ResumableScanTests(IncrementalScanTests):
    """One run over a whole large project was all or nothing: an hour of work
    was thrown away by a time limit or a cancellation."""

    def setUp(self):
        super().setUp()
        patcher = patch.object(scanners, 'BATCH_FILES', 1)          # every file its own part
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_f_the_environment_switch_forces_a_full_scan(self):
        # The inherited check, for a scan that runs in parts: every file is
        # scanned again, one part each.
        self.scan()
        with patch.dict(os.environ, {scanners.FULL_SCAN_VARIABLE: '1'}):
            report = self.scan()
        self.assertEqual(report['coverage']['incremental']['mode'], 'full')
        self.assertEqual([run for run in self.tool.runs if run], [['a.py'], ['pkg/b.py'], ['pkg/c.py']])

    def stuck_on(self, name):
        tool = self.tool

        def run(command, cwd, env, timeout, cancel=None, **low):
            if 'dir' not in command and (Path(cwd) / 'source' / name).is_file():
                raise subprocess.TimeoutExpired(command, timeout)
            return tool(command, cwd, env, timeout, cancel, **low)
        return patch.object(scanners, 'run_tool', run)

    def test_i_a_part_that_runs_out_of_time_does_not_cost_the_others(self):
        with self.stuck_on('pkg/b.py'):
            report = scanners.start('demo', background=False)
        semgrep = report['tools']['semgrep']
        self.assertEqual((report['state'], semgrep['state'], semgrep['files_unscanned'], semgrep['files_scanned']),
                         ('partial', 'partial', 1, 2))
        self.assertIn('davom etadi', semgrep['message'])
        self.assertEqual([f['path'] for f in report['findings']], ['a.py'])
        self.assertEqual(list((scanners.RUNS / report['id']).glob('work-*')), [])

    def test_j_the_next_scan_continues_with_only_what_was_left(self):
        with self.stuck_on('pkg/b.py'):
            scanners.start('demo', background=False)
        report = self.scan()
        self.assertEqual([run for run in self.tool.runs if run], [['pkg/b.py']])
        self.assertNotIn('files_unscanned', report['tools']['semgrep'])
        self.assertEqual(sorted(f['path'] for f in report['findings']), ['a.py', 'pkg/b.py'])

    def test_k_unreached_files_make_the_scan_unfinished_not_a_coverage_gap(self):
        from zanjir import baseline, ci_gate
        with self.stuck_on('pkg/b.py'):
            report = scanners.start('demo', background=False)
        stage = {'kind': 'code', 'target': 'demo', 'state': report['state'], 'report': report}
        self.assertEqual(ci_gate.classify_stage(stage)[0], 'incomplete')
        self.assertFalse(baseline.usable(report))

    def test_l_a_tool_that_never_works_is_still_reported_as_failed(self):
        def broken(command, cwd, env, timeout, cancel=None, **low):
            return subprocess.CompletedProcess(command, 2, '', 'boom')
        with patch.object(scanners, 'run_tool', broken):
            report = scanners.start('demo', background=False)
        self.assertEqual((report['state'], report['tools']['semgrep']['state'], report['tools']['semgrep']['exit_code']),
                         ('failed', 'failed', 2))

    def test_m_a_cancellation_keeps_the_parts_already_finished(self):
        tool = self.tool

        def cancel_after_first(command, cwd, env, timeout, cancel=None, **low):
            done = tool(command, cwd, env, timeout, cancel, **low)
            if 'dir' not in command:
                cancel.set()
            return done
        with patch.object(scanners, 'run_tool', cancel_after_first):
            report = scanners.start('demo', background=False)
        self.assertEqual(report['state'], 'cancelled')
        self.tool.runs.clear()
        resumed = scanners.start('demo', background=False)
        self.assertEqual(resumed['state'], 'completed')
        scanned = sorted(path for run in self.tool.runs for path in run)
        self.assertEqual(scanned, ['pkg/b.py', 'pkg/c.py'], 'a.py was finished before the cancel and must not be redone')

    def test_n_parts_are_cut_by_count_and_by_size(self):
        work = self.tmp / 'w'
        (work / 'source').mkdir(parents=True)
        for name, size in (('a', 10), ('b', 10), ('c', 60), ('d', 10)):
            (work / 'source' / name).write_bytes(b'x' * size)
        with patch.object(scanners, 'BATCH_FILES', 100), patch.object(scanners, 'BATCH_BYTES', 50):
            self.assertEqual([part for part, _ in scanners.batches(work, {'a', 'b', 'c', 'd'})], [['a', 'b'], ['c'], ['d']])
        with patch.object(scanners, 'BATCH_FILES', 3), patch.object(scanners, 'BATCH_BYTES', 10 ** 9):
            self.assertEqual([len(part) for part, _ in scanners.batches(work, {'a', 'b', 'c', 'd'})], [3, 1])
        self.assertEqual(scanners.batches(work, set()), [])

    def test_o_a_rescan_that_only_retries_timed_out_files_keeps_the_cached_findings(self):
        # Measured on a 26 503-file tree: the first scan timed out on some files
        # and cached 23 152 results; the rescan retried only the timed-out files,
        # they timed out again, and the tool was marked failed -- dropping all
        # 23 152 cached findings. The cache must survive a rescan whose only new
        # work fails.
        with self.stuck_on('pkg/b.py'):
            first = scanners.start('demo', background=False)
        self.assertEqual(first['tools']['semgrep']['files_unscanned'], 1)
        self.assertEqual(sorted(f['path'] for f in first['findings']), ['a.py'])
        self.tool.runs.clear()
        with self.stuck_on('pkg/b.py'):
            rescan = scanners.start('demo', background=False)
        semgrep = rescan['tools']['semgrep']
        # pkg/b.py is the only file still without a cached result, so it is all
        # that is retried -- and it times out again (the fake tool records no run
        # because it never gets to run). The two cached files survive.
        self.assertEqual((semgrep['state'], semgrep['files_unscanned'], semgrep['files_reused']), ('partial', 1, 2))
        self.assertEqual(sorted(f['path'] for f in rescan['findings']), ['a.py'])

    def test_p_a_part_that_times_out_is_split_until_only_the_slow_file_is_left(self):
        # Measured: with the full rule pack two large parts timed out in a row
        # and 3 351 files were never scanned. Halving isolates the slow file.
        with patch.object(scanners, 'BATCH_FILES', 100), self.stuck_on('pkg/b.py'):
            report = scanners.start('demo', background=False)
        semgrep = report['tools']['semgrep']
        self.assertEqual((semgrep['files_scanned'], semgrep['files_unscanned']), (2, 1))
        self.assertEqual(sorted(path for run in self.tool.runs if run for path in run), ['a.py', 'pkg/c.py'])
        self.assertEqual([f['path'] for f in report['findings']], ['a.py'])

    def test_q_the_part_limit_follows_the_measured_pace(self):
        pace = scanners.PacedLimit(100)
        self.assertEqual(pace.limit(['f'] * 40, 10), 100)                  # nothing measured yet
        pace.observe(['f'] * 10, 50.0)                                       # 5 s per file
        self.assertEqual(pace.limit(['f'] * 40, 10), 600)                  # 3 x 40 x 5
        self.assertEqual(pace.limit(['f'] * 2, 10), 100)                   # never below the floor
        self.assertEqual(pace.limit(['f'] * 10 ** 6, 10), scanners.MAX_PART_SECONDS)


class ComposeOverrideTests(Workspace):
    """`docker compose up` merges the override file by itself; reading only the
    main file described a stack nobody runs."""

    MAIN = 'services:\n  web:\n    image: myorg/web\n    depends_on: [db]\n  db:\n    image: postgres:16\n'
    OVERRIDE = ('services:\n  web:\n    ports: ["8080:80"]\n    environment:\n      DEBUG: "true"\n'
                '  adminer:\n    image: adminer\n    ports: ["8081:8080"]\n')

    def test_a_ports_and_debug_published_by_the_override_are_seen(self):
        self.put('docker-compose.yml', self.MAIN)
        self.put('docker-compose.override.yml', self.OVERRIDE)
        report = scan_repository(self.source, 'docker-compose.yml')
        rules = {(f['rule_id'], f['service_id']) for f in report['findings']}
        self.assertTrue({('RP-001', 'web'), ('RP-006', 'web'), ('RP-001', 'adminer'), ('RP-005', 'db')} <= rules, rules)
        self.assertEqual(report['profile']['overrides'], ['docker-compose.override.yml'])
        self.assertIn('docker-compose.override.yml', [f['path'] for f in report['files']])
        added = next(e for e in report['evidence'] if e['label'] == 'Xizmat' and e['value'] == 'adminer')
        self.assertEqual(added['path'], 'docker-compose.override.yml')

    def test_b_without_an_override_nothing_changes(self):
        self.put('docker-compose.yml', self.MAIN)
        report = scan_repository(self.source, 'docker-compose.yml')
        self.assertEqual(report['findings'], [])
        self.assertNotIn('overrides', report['profile'])

    def test_c_only_a_default_named_file_has_an_implicit_override(self):
        self.put('deploy/prod.yml', self.MAIN)
        self.put('deploy/docker-compose.override.yml', self.OVERRIDE)
        self.assertEqual(scan_repository(self.source, 'deploy/prod.yml')['findings'], [])
        self.assertIsNone(repository.override_path('deploy/prod.yml'))
        self.assertEqual(repository.override_path('deploy/compose.yaml'), 'deploy/compose.override.yaml')

    def test_d_an_override_keeps_what_the_main_file_said(self):
        merged = merge_service({'image': 'a', 'depends_on': ['db'], 'ports': ['80:80']}, {'ports': ['443:443']}, keep_all=True)
        self.assertEqual((merged['depends_on'], merged['ports']), (['db'], ['80:80', '443:443']))

    def test_e_an_unreadable_override_is_named(self):
        self.put('docker-compose.yml', self.MAIN)
        self.put('docker-compose.override.yml', 'services: [not, a, mapping]\n')
        report = scan_repository(self.source, 'docker-compose.yml')
        self.assertTrue(any('override' in note for note in report['unknowns']), report['unknowns'])


class DependencySlotTests(unittest.TestCase):
    def test_a_the_dependency_stage_uses_the_same_per_project_slots(self):
        from zanjir import dependencies
        self.assertIsInstance(dependencies.LOCK, scanners.ScanSlots)
        self.assertIsNot(dependencies.LOCK, scanners.LOCK)
        self.assertFalse(dependencies.LOCK.locked())

    def test_b_a_refused_start_leaves_no_slot_taken(self):
        from zanjir import dependencies
        with patch.object(scanners, 'check_target', return_value=None), \
                patch.object(dependencies.LOCK, 'acquire', return_value=False), self.assertRaises(ValueError):
            dependencies.start('demo')
        self.assertFalse(dependencies.LOCK.locked('demo'))
        self.assertEqual(dependencies._TARGETS, {})


class CompareViewTests(Workspace):
    """Comparing two 50 000-finding reports parsed 92 MB to read a fraction of it."""

    def write(self, rid, count, extra=(), state='completed'):
        findings = [finding(n) for n in range(count)] + [finding(n) for n in extra]
        for row in findings:
            row['evidence'] = 'x' * 400                       # what a comparison never reads
        repo_store.write_json(scanners.RUNS / rid / 'report.json',
                              {'id': rid, 'target': 't', 'state': state, 'created_at': '2026-01-01T00:00:00+00:00',
                               'count': len(findings), 'findings': findings, 'tools': {'semgrep': {'state': state}}})

    def setUp(self):
        super().setUp()
        for patcher in (patch.object(scanners, 'RUNS', self.tmp / 'code'), patch.object(triage, 'TRIAGE', self.tmp / 'triage')):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_a_a_large_report_gets_a_view_with_every_identity_and_no_evidence(self):
        from zanjir import baseline
        total = run_index.VIEW_LIMIT + 5
        self.write(RID, total)
        view = run_index.compare_view(scanners.RUNS, RID)
        self.assertEqual(len(view['findings']), total)
        self.assertNotIn('evidence', view['findings'][0])
        self.assertLess((scanners.RUNS / RID / 'compare.json').stat().st_size,
                        (scanners.RUNS / RID / 'report.json').stat().st_size / 3)
        self.assertEqual(len(baseline.read_for_diff('code', RID)['findings']), total)

    def test_b_the_comparison_is_the_same_whichever_file_it_reads(self):
        from zanjir import baseline
        total = run_index.VIEW_LIMIT + 5
        self.write(CHILD, total)
        self.write(RID, total - 3, extra=(900001, 900002))
        with patch.object(baseline, 'history_rows', lambda stage, limit=10 ** 6: [
                {'id': RID, 'target': 't', 'state': 'completed'}, {'id': CHILD, 'target': 't', 'state': 'completed'}]):
            quick = baseline.compare('code', RID, CHILD)
            with patch.object(run_index, 'compare_view', lambda runs, rid: None):
                full = baseline.compare('code', RID, CHILD)
        self.assertEqual(quick['counts'], {'new': 2, 'gone': 3, 'unchanged': total - 3})
        self.assertEqual(quick['counts'], full['counts'])
        self.assertEqual([(r['fingerprint'], r['rule_id'], r['subject']) for r in quick['new']],
                         [(r['fingerprint'], r['rule_id'], r['subject']) for r in full['new']])

    def test_c_a_small_report_is_read_as_it_is(self):
        self.write(RID, 10)
        self.assertIsNone(run_index.compare_view(scanners.RUNS, RID))


class GateScopeTests(unittest.TestCase):
    """A linter's CVE and a base-image CVE nobody will fix stopped every build
    exactly like a reachable, fixable one. Both filters are opt-in."""

    def report(self):
        def dep(name, scopes, fixed):
            return {'package': {'name': name}, 'advisory_id': 'GHSA-' + name, 'severity': 'HIGH',
                    'fingerprint': name.ljust(24, '0'), 'occurrences': [{'scope': s} for s in scopes],
                    'fixed_versions': fixed}

        def image(name, fixed):
            return {'package': name, 'advisory_id': 'CVE-' + name, 'severity': 'CRITICAL',
                    'fingerprint': name.ljust(24, '1'), 'fixed_version': fixed}
        return {'stages': [
            {'kind': 'dependencies', 'target': 't', 'state': 'completed',
             'report': {'findings': [dep('pytest', ['development'], ['2']), dep('flask', ['runtime', 'development'], ['3']),
                                     dep('old', ['unknown'], [])]}},
            {'kind': 'images', 'target': 'i', 'state': 'completed',
             'report': {'findings': [image('libc', ''), image('openssl', '3.0.9')]}}]}

    def names(self, **options):
        from zanjir import ci_gate
        result = ci_gate.evaluate(self.report(), **options)
        return sorted(hit['subject'] for hit in result['hits']), result

    def test_a_the_default_counts_all_five(self):
        names, result = self.names()
        self.assertEqual(names, ['flask', 'libc', 'old', 'openssl', 'pytest'])
        self.assertNotIn('without_fix', result)

    def test_b_prod_only_leaves_out_what_is_declared_development_everywhere(self):
        names, result = self.names(prod_only=True)
        self.assertEqual(names, ['flask', 'libc', 'old', 'openssl'])        # flask is also a runtime dependency
        self.assertEqual(result['outside_shipped_code'], 1)

    def test_c_an_unknown_scope_counts_as_shipped(self):
        from zanjir import ci_gate
        self.assertFalse(ci_gate.dev_only({'occurrences': [{'scope': 'unknown'}]}))
        self.assertFalse(ci_gate.dev_only({'occurrences': []}))
        self.assertFalse(ci_gate.dev_only({}))
        self.assertTrue(ci_gate.dev_only({'occurrences': [{'scope': 'development'}, {'scope': 'development'}]}))

    def test_d_fixable_only_leaves_out_what_no_upgrade_can_fix_and_says_how_many(self):
        names, result = self.names(fixable_only=True)
        self.assertEqual(names, ['flask', 'openssl', 'pytest'])
        self.assertEqual(result['without_fix'], 2)
        self.assertEqual(result['total'], 5)

    def test_e_both_together(self):
        self.assertEqual(self.names(prod_only=True, fixable_only=True)[0], ['flask', 'openssl'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
