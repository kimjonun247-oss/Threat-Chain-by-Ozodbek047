"""Scan queue, schedules and change notifications (zanjir/jobs.py, zanjir/notify.py)."""
import datetime
import json
import shutil
import socketserver
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from unittest import mock

from zanjir import jobs, notify, settings
from zanjir.httptest import listener

UTC = datetime.timezone.utc


class FakeScanner:
    """A scanner with the same surface as zanjir/scanners.py: LOCK, start, read, cancel."""

    def __init__(self, outcome='completed', duration=0.05, findings=()):
        self.LOCK = threading.Lock()
        self.outcome, self.duration, self.findings = outcome, duration, list(findings)
        self.reports, self.started = {}, []
        self.refuse = None

    def check_target(self, target):
        if target == 'missing':
            raise ValueError('Nishon yo‘q.')

    def start(self, target, background=True):
        if self.refuse:
            raise self.refuse
        if not self.LOCK.acquire(blocking=False):
            raise ValueError('Boshqa tekshiruv davom etmoqda.')
        rid = f'20260101T00000{len(self.started)}-{len(self.started):08x}'
        self.started.append(target)
        self.reports[rid] = {'id': rid, 'target': target, 'state': 'running', 'findings': []}

        def finish():
            time.sleep(self.duration)
            self.reports[rid].update(state=self.outcome, findings=list(self.findings), count=len(self.findings))
            self.LOCK.release()
        threading.Thread(target=finish, daemon=True).start()
        return {'id': rid, 'state': 'queued'}

    def read(self, rid):
        return self.reports[rid]

    def cancel(self, rid):
        return {'id': rid}


class Isolated(unittest.TestCase):
    def setUp(self):
        folder = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, folder, True)
        for name, value in (('JOBS', folder / 'jobs'), ('QUEUE', folder / 'jobs/queue.json'),
                            ('STATE', folder / 'jobs/state.json'), ('SCHEDULES', folder / 'schedules')):
            patcher = mock.patch.object(jobs, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = mock.patch.object(settings, 'PATH', folder / 'settings.json')
        patcher.start()
        self.addCleanup(patcher.stop)
        self.code, self.deps = FakeScanner(), FakeScanner()
        fake = {'code': self.code, 'dependencies': self.deps, 'images': FakeScanner(), 'iac': FakeScanner(),
                'web': FakeScanner(), 'assessment': FakeScanner()}
        patcher = mock.patch.object(jobs, 'modules', lambda: fake)
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch.object(jobs, 'check', lambda kind, target, payload: fake['code'].check_target(target))
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch.object(jobs, 'POLL', 0.02)
        patcher.start()
        self.addCleanup(patcher.stop)
        jobs._WORKER['stop'].clear()
        jobs._WORKER['running'].clear()

    def settle(self, timeout=5):
        """Tick until nothing is queued or running."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            jobs.tick()
            states = {job['state'] for job in jobs.load()}
            if not states & {'queued', 'running'}:
                return jobs.load()
            time.sleep(0.05)
        self.fail(f'navbat tugamadi: {jobs.load()}')


class QueueTests(Isolated):
    def test_the_same_scan_is_never_queued_twice(self):
        first = jobs.enqueue('code', 'app')
        second = jobs.enqueue('code', 'app')
        self.assertTrue(second['duplicate'])
        self.assertEqual(second['id'], first['id'])
        self.assertEqual(len(jobs.load()), 1)

    def test_queued_jobs_run_one_at_a_time_and_record_the_report(self):
        jobs.enqueue('code', 'a')
        jobs.enqueue('code', 'b')
        jobs.enqueue('dependencies', 'a')
        started = jobs.tick()
        self.assertEqual(len(started), 1)                 # default: one scan on the machine at a time
        done = self.settle()
        self.assertEqual([job['state'] for job in done], ['completed'] * 3)
        self.assertEqual(self.code.started, ['a', 'b'])
        self.assertTrue(all(job['report_id'] for job in done))

    def test_a_parallel_limit_lets_different_kinds_run_together_but_never_two_of_a_kind(self):
        settings.set_max_parallel(2)
        jobs.enqueue('code', 'a')
        jobs.enqueue('code', 'b')
        jobs.enqueue('dependencies', 'a')
        started = jobs.tick()
        self.assertEqual(sorted(job['kind'] for job in started), ['code', 'dependencies'])
        self.settle()

    def test_a_manual_scan_in_progress_makes_the_job_wait_not_fail(self):
        self.code.LOCK.acquire()
        jobs.enqueue('code', 'a')
        self.assertEqual(jobs.tick(), [])
        self.assertEqual(jobs.load()[0]['state'], 'queued')
        self.code.LOCK.release()
        self.assertEqual(self.settle()[0]['state'], 'completed')

    def test_outside_a_web_window_the_job_waits_for_it(self):
        from zanjir.webscan import PermissionWindowError
        later = datetime.datetime.now(UTC) + datetime.timedelta(hours=3)
        jobs.modules()['web'].refuse = PermissionWindowError('Ruxsat oynasidan tashqarida.', later)
        jobs.enqueue('web', 'shop')
        jobs.tick()
        for _ in range(50):
            job = jobs.load()[0]
            if job['state'] == 'waiting':
                break
            time.sleep(0.02)
        self.assertEqual(job['state'], 'waiting')
        self.assertEqual(job['not_before'], later.isoformat())
        self.assertEqual(jobs.tick(), [])                  # not before the window

    def test_a_refusal_is_a_failed_job_with_the_reason(self):
        self.code.refuse = ValueError('Nishon papkasi topilmadi.')
        jobs.enqueue('code', 'a')
        job = self.settle()[0]
        self.assertEqual((job['state'], job['message']), ('failed', 'Nishon papkasi topilmadi.'))

    def test_cancelling_a_queued_job(self):
        job = jobs.enqueue('code', 'a')
        self.assertEqual(jobs.cancel(job['id'])['state'], 'cancelled')
        self.assertEqual(jobs.tick(), [])

    def test_a_job_running_when_the_server_stopped_is_marked_interrupted(self):
        jobs.save([{'id': 'x', 'kind': 'code', 'target': 'a', 'state': 'running', 'payload': None}])
        jobs.recover()
        self.assertEqual(jobs.load()[0]['state'], 'interrupted')


class ScheduleTests(Isolated):
    def schedule(self, **extra):
        return jobs.save_schedule({'id': 'nightly', 'kind': 'code', 'target': 'app', 'days': 'mon-fri',
                                   'at': '02:30', 'timezone': '+05:00', **extra})

    def test_next_run_is_the_next_listed_day_in_the_zone(self):
        row = self.schedule()
        friday_noon = datetime.datetime(2026, 10, 2, 12, 0, tzinfo=datetime.timezone(datetime.timedelta(hours=5)))
        self.assertEqual(jobs.next_run(row, friday_noon), '2026-10-05T02:30:00+05:00')   # Monday

    def test_a_due_schedule_fires_once(self):
        row = self.schedule()
        created = datetime.datetime.fromisoformat(row['created_at'])
        due = jobs.last_due(row, created + datetime.timedelta(days=8))
        with mock.patch.object(jobs, 'now', lambda: due + datetime.timedelta(minutes=1)):
            first = jobs.fire_due(due + datetime.timedelta(minutes=1))
            again = jobs.fire_due(due + datetime.timedelta(minutes=5))
        self.assertEqual(len(first), 1)
        self.assertEqual(first[0]['source'], 'schedule')
        self.assertEqual(again, [])

    def test_missed_days_are_caught_up_once_not_per_day(self):
        row = self.schedule(days='mon-sun')
        created = datetime.datetime.fromisoformat(row['created_at'])
        # Server down for three days: only the latest missed run is queued.
        back = jobs.last_due(row, created + datetime.timedelta(days=4)) + datetime.timedelta(hours=1)
        self.assertEqual(len(jobs.fire_due(back)), 1)
        self.assertEqual(len([j for j in jobs.load() if j['state'] == 'queued']), 1)

    def test_a_schedule_created_after_todays_time_waits_for_tomorrow(self):
        row = self.schedule(days='mon-sun')
        self.assertEqual(jobs.fire_due(datetime.datetime.fromisoformat(row['created_at'])), [])

    def test_a_disabled_schedule_never_fires(self):
        row = self.schedule(days='mon-sun', enabled=False)
        created = datetime.datetime.fromisoformat(row['created_at'])
        self.assertEqual(jobs.fire_due(created + datetime.timedelta(days=2)), [])
        self.assertIsNone(jobs.schedules()[0]['next_run'])

    def test_bad_schedules_are_refused(self):
        for bad in ({'id': 'x!', 'kind': 'code', 'at': '02:00'}, {'id': 'ok', 'kind': 'code', 'at': '2am'},
                    {'id': 'ok', 'kind': 'code', 'at': '02:00', 'notify': 'sometimes'},
                    {'id': 'ok', 'kind': 'code', 'at': '02:00', 'days': 'someday'}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                jobs.save_schedule({'target': 'app', **bad})


def capture():
    """A local HTTP endpoint recording every JSON POST."""
    received = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            received.append(json.loads(self.rfile.read(int(self.headers['Content-Length']))))
            self.send_response(200)
            self.send_header('Content-Length', '2')
            self.end_headers()
            self.wfile.write(b'ok')
    return Handler, received


class SMTPHandler(socketserver.StreamRequestHandler):
    """Just enough SMTP to accept one message."""
    messages = []

    def handle(self):
        self.wfile.write(b'220 test\r\n')
        data, lines = False, []
        for raw in self.rfile:
            line = raw.decode('utf-8', 'replace').rstrip('\r\n')
            if data:
                if line == '.':
                    SMTPHandler.messages.append('\n'.join(lines))
                    data = False
                    self.wfile.write(b'250 queued\r\n')
                else:
                    lines.append(line)
                continue
            verb = line.split(' ')[0].upper()
            if verb in ('EHLO', 'HELO'):
                self.wfile.write(b'250 test\r\n')
            elif verb == 'DATA':
                data = True
                self.wfile.write(b'354 go\r\n')
            elif verb == 'QUIT':
                self.wfile.write(b'221 bye\r\n')
                return
            else:
                self.wfile.write(b'250 ok\r\n')


class NotifyTests(Isolated):
    def reports(self, before, after):
        stage_rows = [after, before]
        patchers = [mock.patch('zanjir.baseline.history_rows', lambda stage, limit=0: stage_rows),
                    mock.patch('zanjir.baseline.read_report', lambda stage, rid: {r['id']: r for r in stage_rows}[rid])]
        for patcher in patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

    @staticmethod
    def finding(fingerprint, rule='R1'):
        return {'fingerprint': fingerprint, 'rule_id': rule, 'severity': 'HIGH', 'path': 'app.py', 'title': 't'}

    def test_a_new_finding_is_a_change(self):
        before = {'id': 'r1', 'target': 'app', 'state': 'completed', 'findings': [self.finding('a' * 24)]}
        after = {'id': 'r2', 'target': 'app', 'state': 'completed',
                 'findings': [self.finding('a' * 24), self.finding('b' * 24, 'R2')]}
        self.reports(before, after)
        delta = notify.change('code', after)
        self.assertTrue(delta['changed'])
        self.assertEqual(delta['counts']['new'], 1)
        self.assertEqual(delta['new'][0]['rule_id'], 'R2')

    def test_the_same_result_is_not_a_change(self):
        before = {'id': 'r1', 'target': 'app', 'state': 'completed', 'findings': [self.finding('a' * 24)]}
        after = {'id': 'r2', 'target': 'app', 'state': 'completed', 'findings': [self.finding('a' * 24)]}
        self.reports(before, after)
        self.assertFalse(notify.change('code', after)['changed'])

    def test_a_scan_that_failed_is_a_change_even_with_no_findings(self):
        before = {'id': 'r1', 'target': 'app', 'state': 'completed', 'findings': []}
        after = {'id': 'r2', 'target': 'app', 'state': 'failed', 'findings': []}
        self.reports(before, after)
        self.assertTrue(notify.change('code', after)['changed'])

    def test_every_channel_gets_the_message_and_no_secret_leaks(self):
        handler, received = capture()
        SMTPHandler.messages = []
        smtp = socketserver.ThreadingTCPServer(('127.0.0.1', 0), SMTPHandler)
        threading.Thread(target=smtp.serve_forever, daemon=True).start()
        self.addCleanup(smtp.server_close)
        self.addCleanup(smtp.shutdown)
        before = {'id': 'r1', 'target': 'app', 'state': 'completed', 'findings': []}
        after = {'id': 'r2', 'target': 'app', 'state': 'completed', 'findings': [self.finding('b' * 24, 'R2')]}
        self.reports(before, after)
        with listener(handler) as url:
            config = {'webhook_url': url + '/hook', 'slack_webhook_url': url + '/slack',
                      'email': {'host': '127.0.0.1', 'port': smtp.server_address[1], 'security': 'none',
                                'username': '', 'password': '', 'sender': 'tc@example.test',
                                'recipients': ['sec@example.test']}}
            job = {'id': 'j1', 'kind': 'code', 'target': 'app', 'schedule_id': 'nightly'}
            event = notify.event_for(job, after, notify.change('code', after))
            results = notify.deliver(event, config)
        self.assertEqual(results, [{'channel': 'webhook', 'ok': True}, {'channel': 'slack', 'ok': True},
                                   {'channel': 'email', 'ok': True}])
        webhook, slack = received
        self.assertEqual((webhook['event'], webhook['counts']['new']), ('threatchain.scan_result_changed', 1))
        self.assertIn('R2', slack['text'])
        self.assertIn('Yangi: 1', SMTPHandler.messages[0].replace('=\n', ''))

    def test_an_unreachable_channel_is_reported_without_its_url(self):
        results = notify.deliver(notify.test_event(), {'webhook_url': 'http://127.0.0.1:9/secret-token-path'})
        self.assertEqual(results[0]['ok'], False)
        self.assertNotIn('secret-token-path', json.dumps(results))

    def test_a_scheduled_job_notifies_only_when_the_result_changed(self):
        before = {'id': 'r1', 'target': 'app', 'state': 'completed', 'findings': []}
        self.reports(before, dict(before, id='r2'))
        sent = []
        with mock.patch.object(notify, 'deliver', lambda event: sent.append(event) or [{'channel': 'webhook', 'ok': True}]):
            job = jobs.enqueue('code', 'app', notify='on_change')
            jobs.finish(job, {'id': 'r2', 'target': 'app', 'state': 'completed', 'findings': []})
            self.assertEqual(sent, [])
            self.assertFalse(jobs.load()[0]['change']['changed'])


class SettingsTests(Isolated):
    SLACK = 'https://hooks.slack.com/services/T000/B000/abcdefghijklmnop'

    def test_urls_are_stored_but_never_returned(self):
        status = settings.set_notifications({'slack_webhook_url': self.SLACK,
                                             'webhook_url': 'https://hooks.example.test/tc/9f8e7d6c5b4a'})
        self.assertTrue(status['slack']['present'])
        self.assertNotIn('abcdefghijklmnop', json.dumps(status))
        self.assertNotIn('9f8e7d6c5b4a'[:8], json.dumps(status))
        self.assertEqual(settings.notifications()['slack_webhook_url'], self.SLACK)

    def test_leaving_a_secret_out_keeps_it(self):
        settings.set_notifications({'slack_webhook_url': self.SLACK})
        settings.set_notifications({'webhook_url': 'https://hooks.example.test/x'})
        self.assertEqual(settings.notifications()['slack_webhook_url'], self.SLACK)
        settings.set_notifications({'slack_webhook_url': ''})
        self.assertNotIn('slack_webhook_url', settings.notifications())

    def test_plain_http_and_foreign_slack_hosts_are_refused(self):
        for bad in ({'webhook_url': 'http://hooks.example.test/x'},
                    {'slack_webhook_url': 'https://evil.example.test/services/x'}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                settings.set_notifications(bad)

    def test_the_smtp_password_from_the_environment_wins(self):
        settings.set_notifications({'email': {'host': 'smtp.example.test', 'port': 587, 'security': 'starttls',
                                              'username': 'tc', 'password': 'stored-pass', 'sender': 'tc@example.test',
                                              'recipients': 'a@example.test, b@example.test'}})
        self.assertEqual(settings.notifications()['email']['password'], 'stored-pass')
        with mock.patch.dict('os.environ', {'THREATCHAIN_SMTP_PASSWORD': 'env-pass'}):
            self.assertEqual(settings.notifications()['email']['password'], 'env-pass')
            self.assertTrue(settings.notification_status()['email']['password_from_env'])
        self.assertNotIn('stored-pass', json.dumps(settings.notification_status()))
        self.assertEqual(settings.notification_status()['email']['recipients'], ['a@example.test', 'b@example.test'])


if __name__ == '__main__':
    unittest.main()
