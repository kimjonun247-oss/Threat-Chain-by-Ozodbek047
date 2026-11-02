"""A run must always end, and end with the right state (shortcomings review 2026-11-02, LP#5/#6).

  - The status sidecar is written with retries: on Windows os.replace() fails while
    a poller holds the file, and losing the FINAL write left a run 'running' forever.
  - pipeline.run_stage and the job worker read the full report periodically even
    while the sidecar says 'running', so a lost sidecar write cannot hang them.
  - The job worker no longer re-parses the full report on every poll.
  - An unexpected exception in the web stage, or in a pipeline stage thread, ends
    that stage as failed instead of leaving it 'running'.
  - A failure in cross-scanner correlation keeps every finished stage result and
    marks the assessment partial, not failed.
"""
import shutil
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from zanjir import jobs, pipeline, repo_store, run_index, triage, webscan
from test_jobs import Isolated

RID = '20261102T000000-abcdef12'


def sidecar(folder, rid, state):
    path = folder / rid
    path.mkdir(parents=True, exist_ok=True)
    (path / run_index.STATUS_NAME).write_text('{"id": "%s", "state": "%s"}' % (rid, state), encoding='utf-8')


class WriteStatusRetryTests(unittest.TestCase):
    def setUp(self):
        self.folder = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.folder, True)

    def test_a_busy_destination_is_retried_not_dropped(self):
        real, calls = run_index.os.replace, []

        def busy_twice(src, dst):
            calls.append(dst)
            if len(calls) <= 2:
                raise PermissionError('in use')
            return real(src, dst)
        with mock.patch.object(run_index.os, 'replace', busy_twice):
            run_index.write_status(self.folder, {'id': RID, 'state': 'completed'})
        self.assertEqual(run_index.status(self.folder.parent, self.folder.name), None)  # rid mismatch guard
        self.assertIn('"completed"', (self.folder / run_index.STATUS_NAME).read_text(encoding='utf-8'))
        self.assertEqual(len(calls), 3)

    def test_b_a_destination_that_stays_busy_leaves_no_temporary_files(self):
        with mock.patch.object(run_index.os, 'replace', side_effect=PermissionError('in use')):
            run_index.write_status(self.folder, {'id': RID, 'state': 'completed'})
        self.assertEqual([p.name for p in self.folder.iterdir() if p.suffix == '.tmp'], [])


class FakeStage:
    """A stage module whose report finishes but whose sidecar stays 'running'."""

    def __init__(self, runs):
        self.RUNS = runs
        self.reads = 0

    def start(self, target):
        sidecar(self.RUNS, RID, 'running')
        return {'id': RID, 'state': 'queued'}

    def read(self, rid):
        self.reads += 1
        return {'id': rid, 'state': 'completed', 'count': 0, 'findings': []}

    def cancel(self, rid):
        return {'id': rid}


class RunStageFallbackTests(unittest.TestCase):
    def test_a_stuck_sidecar_does_not_hang_the_stage(self):
        runs = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, runs, True)
        fake = FakeStage(runs)
        commits = []
        with mock.patch.dict(pipeline.MODULES, {'iac': fake}), mock.patch.object(pipeline, 'FULL_READ_EVERY', 2):
            done = threading.Event()
            worker = threading.Thread(target=lambda: (pipeline.run_stage({'kind': 'iac', 'target': 'x'}, threading.Event(),
                                                                         lambda stage, **f: commits.append(f)), done.set()),
                                      daemon=True)
            worker.start()
            self.assertTrue(done.wait(10), 'run_stage never ended although the report says completed')
        self.assertEqual(commits[-1]['state'], 'completed')


class JobSidecarTests(Isolated):
    def test_a_the_full_report_is_not_reparsed_on_every_poll(self):
        runs = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, runs, True)
        fake = jobs.modules()['code']
        fake.RUNS = runs
        real_start = fake.start

        def start(target, *a, **k):
            started = real_start(target, *a, **k)
            rid = started['id']
            sidecar(runs, rid, 'running')

            def mirror():
                # A real scan thread writes the sidecar when it finishes (write_json ->
                # write_status); the fake's finish() only updates its dict, so mirror it.
                while fake.reports[rid].get('state') in ('queued', 'running'):
                    time.sleep(0.01)
                sidecar(runs, rid, fake.reports[rid]['state'])
            threading.Thread(target=mirror, daemon=True).start()
            return started
        reads = []
        real_read = fake.read

        def read(rid):
            reads.append(rid)
            return real_read(rid)
        fake.duration = 0.6
        with mock.patch.object(fake, 'start', start), mock.patch.object(fake, 'read', read), \
                mock.patch.object(jobs, 'FULL_READ_EVERY', 1000):
            jobs.enqueue('code', 'a')
            done = self.settle()
        self.assertEqual(done[0]['state'], 'completed')
        # 0.6 s at a 0.02 s poll is ~30 polls; with the sidecar only the final read remains.
        self.assertLess(len(reads), 4, reads)

    def test_b_a_stuck_sidecar_still_lets_the_job_finish(self):
        runs = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, runs, True)
        fake = jobs.modules()['code']
        fake.RUNS = runs
        real_start = fake.start

        def start(target, *a, **k):
            started = real_start(target, *a, **k)
            sidecar(runs, started['id'], 'running')          # never updated again
            return started
        fake.duration = 0.1
        with mock.patch.object(fake, 'start', start), mock.patch.object(jobs, 'FULL_READ_EVERY', 3):
            jobs.enqueue('code', 'a')
            self.assertEqual(self.settle()[0]['state'], 'completed')


class UnexpectedErrorTests(unittest.TestCase):
    def setUp(self):
        self.folder = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.folder, True)

    def test_a_an_unexpected_web_error_fails_the_run_and_frees_the_lock(self):
        report = {'id': RID, 'target': 'site', 'state': 'queued', 'findings': []}
        repo_store.write_json(self.folder / RID / 'report.json', report)
        self.assertTrue(webscan.LOCK.acquire(blocking=False))
        with mock.patch.object(webscan, 'RUNS', self.folder), \
                mock.patch.object(webscan, 'read', lambda rid: dict(report)), \
                mock.patch.object(webscan, 'rule_profile', side_effect=AttributeError('unexpected')), \
                mock.patch.object(triage, 'record_scan', return_value=False):
            result = webscan.execute({'id': 'site'}, RID, threading.Event())
        self.assertEqual(result['state'], 'failed')
        self.assertEqual(result['error_type'], 'AttributeError')
        self.assertTrue(webscan.LOCK.acquire(blocking=False), 'the web lock was not released')
        webscan.LOCK.release()

    def test_b_a_correlation_failure_keeps_the_stages_and_reads_partial(self):
        report = {'id': RID, 'created_at': webscan.now(), 'state': 'queued', 'stages': [],
                  'selection': {'target': '', 'repository_target': '', 'web_target': '', 'image_target': '',
                                'iac_target': ''}}
        self.assertTrue(pipeline.LOCK.acquire(blocking=False))
        with mock.patch.object(pipeline, 'RUNS', self.folder), \
                mock.patch.object(pipeline, 'read', lambda rid: dict(report, stages=[])), \
                mock.patch.object(pipeline, 'correlate_stages', side_effect=MemoryError()):
            result = pipeline.execute(RID, threading.Event())
        self.assertEqual(result['state'], 'partial')
        self.assertEqual(result['chain_findings'], [])
        self.assertEqual(result['chain_gaps'][0]['kind'], 'correlation_failed')


if __name__ == '__main__':
    unittest.main()
