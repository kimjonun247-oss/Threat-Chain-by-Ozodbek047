"""Team mode: login, roles, sessions, throttling, audit log and TLS (zanjir/auth.py, app.py)."""
import argparse
import http.client
import json
import shutil
import ssl
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

import app
from app import Handler
from zanjir import auth, jobs, settings
from zanjir.httptest import listener

PASSWORD = 'correct horse battery'


class Isolated(unittest.TestCase):
    def setUp(self):
        folder = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, folder, True)
        for module, name, value in ((auth, 'USERS', folder / 'users.json'), (auth, 'AUDIT', folder / 'audit.jsonl'),
                                    (settings, 'PATH', folder / 'settings.json'),
                                    (jobs, 'QUEUE', folder / 'queue.json'), (jobs, 'JOBS', folder),
                                    (jobs, 'SCHEDULES', folder / 'schedules'), (auth, 'ITERATIONS', 1000)):
            patcher = mock.patch.object(module, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        auth._SESSIONS.clear()
        auth._FAILURES.clear()
        self.folder = folder

    def audit_lines(self):
        return [json.loads(line) for line in auth.AUDIT.read_text(encoding='utf-8').splitlines()]


class PasswordAndUserTests(Isolated):
    def test_passwords_are_salted_and_checked_in_constant_form(self):
        first, second = auth.hash_password(PASSWORD), auth.hash_password(PASSWORD)
        self.assertNotEqual(first, second)
        self.assertTrue(auth.check_password(PASSWORD, first))
        self.assertFalse(auth.check_password(PASSWORD + 'x', first))
        self.assertFalse(auth.check_password(PASSWORD, 'garbage'))
        self.assertNotIn(PASSWORD, first)

    def test_weak_passwords_and_bad_names_are_refused(self):
        for name, password in (('ok', 'short'), ('ok', 'a' * 20), ('Bad Name', PASSWORD), ('x', PASSWORD)):
            with self.subTest(name=name, password=password), self.assertRaises(ValueError):
                auth.add_user(name, 'viewer', password)

    def test_the_users_file_holds_no_password(self):
        auth.add_user('alice', 'admin', PASSWORD)
        self.assertNotIn(PASSWORD, auth.USERS.read_text(encoding='utf-8'))

    def test_the_last_admin_cannot_be_removed(self):
        auth.add_user('alice', 'admin', PASSWORD)
        auth.add_user('bob', 'viewer', PASSWORD)
        with self.assertRaises(ValueError):
            auth.remove_user('alice')
        auth.remove_user('bob')

    def test_roles_cover_each_other_in_order(self):
        viewer, operator, admin = ({'name': 'x', 'role': role} for role in auth.ROLES)
        self.assertTrue(auth.allowed(viewer, 'GET', '/api/findings'))
        self.assertFalse(auth.allowed(viewer, 'POST', '/api/jobs'))
        self.assertTrue(auth.allowed(operator, 'POST', '/api/jobs'))
        self.assertFalse(auth.allowed(operator, 'POST', '/api/registry/web'))
        self.assertFalse(auth.allowed(operator, 'POST', '/api/settings/notifications'))
        self.assertFalse(auth.allowed(operator, 'GET', '/api/audit'))
        self.assertTrue(auth.allowed(admin, 'POST', '/api/schedules'))
        self.assertTrue(auth.allowed(admin, 'GET', '/api/audit'))


class SessionTests(Isolated):
    def setUp(self):
        super().setUp()
        auth.add_user('alice', 'operator', PASSWORD)

    def test_five_failures_lock_the_account_even_for_the_right_password(self):
        for _ in range(auth.MAX_FAILURES):
            with self.assertRaises(ValueError):
                auth.login('alice', 'wrong password!!', '10.0.0.5')
        with self.assertRaises(PermissionError):
            auth.login('alice', PASSWORD, '10.0.0.6')
        actions = [row['action'] for row in self.audit_lines()]
        self.assertEqual(actions.count('login_failed'), auth.MAX_FAILURES)
        self.assertIn('login_throttled', actions)

    def test_an_idle_session_expires(self):
        clock = [1000.0]
        with mock.patch.object(auth.time, 'monotonic', lambda: clock[0]):
            token, _ = auth.login('alice', PASSWORD, '127.0.0.1')
            self.assertEqual(auth.session(token)['name'], 'alice')
            clock[0] += auth.IDLE + 1
            self.assertIsNone(auth.session(token))

    def test_a_password_change_ends_existing_sessions(self):
        token, _ = auth.login('alice', PASSWORD, '127.0.0.1')
        auth.set_password('alice', 'another long passphrase')
        self.assertIsNone(auth.session(token))

    def test_only_ids_reach_the_audit_log(self):
        picked = auth.payload_ids({'id': 'shop', 'url': 'https://user:secret@shop.example.test/x?token=abc',
                                   'password': PASSWORD, 'webhook_url': 'https://hooks.example.test/T/B/zzz',
                                   'text': 'rules: ...', 'fingerprints': ['a', 'b']})
        blob = json.dumps(picked)
        for secret in (PASSWORD, 'secret', 'token=abc', 'zzz', 'rules:'):
            self.assertNotIn(secret, blob)
        self.assertEqual(picked['id'], 'shop')
        self.assertEqual(picked['fingerprints'], 2)


class HttpTests(Isolated):
    """The real Handler: every /api/ call needs a session once a user exists."""

    def setUp(self):
        super().setUp()
        self.server = listener(Handler)
        self.url = self.server.__enter__()
        self.addCleanup(self.server.__exit__, None, None, None)
        self.port = int(self.url.rsplit(':', 1)[1])

    def call(self, method, path, body=None, cookie=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=10)
        headers = {'Host': f'127.0.0.1:{self.port}'}
        if cookie:
            headers['Cookie'] = cookie
        if body is not None:
            headers['Content-Type'] = 'application/json'
            body = json.dumps(body)
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        data = response.read()
        connection.close()
        return response.status, dict(response.getheaders()), data

    def login(self, name):
        status, headers, _ = self.call('POST', '/api/auth/login', {'username': name, 'password': PASSWORD})
        self.assertEqual(status, 200)
        return headers['Set-Cookie'].split(';')[0]

    def test_without_users_nothing_changes(self):
        self.assertEqual(self.call('GET', '/api/jobs')[0], 200)
        self.assertFalse(json.loads(self.call('GET', '/api/auth/me')[2])['auth_enabled'])

    def test_with_users_the_api_needs_a_session_but_the_page_does_not(self):
        auth.add_user('alice', 'viewer', PASSWORD)
        status, _, body = self.call('GET', '/api/jobs')
        self.assertEqual(status, 401)
        self.assertTrue(json.loads(body)['login_required'])
        self.assertEqual(self.call('GET', '/')[0], 200)
        cookie = self.login('alice')
        self.assertEqual(self.call('GET', '/api/jobs', cookie=cookie)[0], 200)

    def test_the_cookie_is_http_only_and_strict(self):
        auth.add_user('alice', 'viewer', PASSWORD)
        _, headers, _ = self.call('POST', '/api/auth/login', {'username': 'alice', 'password': PASSWORD})
        self.assertIn('HttpOnly', headers['Set-Cookie'])
        self.assertIn('SameSite=Strict', headers['Set-Cookie'])

    def test_a_viewer_cannot_start_a_scan_and_the_refusal_is_audited(self):
        auth.add_user('alice', 'viewer', PASSWORD)
        cookie = self.login('alice')
        status, _, _ = self.call('POST', '/api/jobs', {'kind': 'code', 'target': 'x'}, cookie=cookie)
        self.assertEqual(status, 403)
        refused = [row for row in self.audit_lines() if row['action'] == 'refused']
        self.assertEqual((refused[0]['user'], refused[0]['path']), ('alice', '/api/jobs'))

    def test_an_operator_cannot_change_settings_but_an_admin_can(self):
        auth.add_user('op', 'operator', PASSWORD)
        auth.add_user('boss', 'admin', PASSWORD)
        body = {'webhook_url': 'https://hooks.example.test/abc'}
        self.assertEqual(self.call('POST', '/api/settings/notifications', body, cookie=self.login('op'))[0], 403)
        self.assertEqual(self.call('POST', '/api/settings/notifications', body, cookie=self.login('boss'))[0], 200)

    def test_every_change_is_audited_with_user_status_and_ids_only(self):
        auth.add_user('boss', 'admin', PASSWORD)
        cookie = self.login('boss')
        self.call('POST', '/api/settings/notifications', {'webhook_url': 'https://hooks.example.test/s3cr3t'}, cookie=cookie)
        self.call('POST', '/api/jobs', {'kind': 'code', 'target': 'no-such-target'}, cookie=cookie)
        requests = [row for row in self.audit_lines() if row['action'] == 'request']
        self.assertEqual([(r['user'], r['path'], r['status']) for r in requests],
                         [('boss', '/api/settings/notifications', 200), ('boss', '/api/jobs', 400)])
        self.assertEqual(requests[1]['details'], {'target': 'no-such-target', 'kind': 'code'})
        self.assertNotIn('s3cr3t', auth.AUDIT.read_text(encoding='utf-8'))
        self.assertNotIn(PASSWORD, auth.AUDIT.read_text(encoding='utf-8'))
        entries = json.loads(self.call('GET', '/api/audit', cookie=cookie)[2])['entries']
        self.assertEqual(entries[0]['path'], '/api/jobs')

    def test_logout_ends_the_session(self):
        auth.add_user('alice', 'viewer', PASSWORD)
        cookie = self.login('alice')
        self.call('POST', '/api/auth/logout', {}, cookie=cookie)
        self.assertEqual(self.call('GET', '/api/jobs', cookie=cookie)[0], 401)

    def test_a_forged_cookie_is_not_a_session(self):
        auth.add_user('alice', 'admin', PASSWORD)
        self.assertEqual(self.call('GET', '/api/jobs', cookie=f'{auth.COOKIE}=forged')[0], 401)


class ExposureTests(Isolated):
    def args(self, **extra):
        values = {'bind': '0.0.0.0', 'port': 0, 'public_host': [], 'tls_cert': None, 'tls_key': None, **extra}
        return argparse.Namespace(**values)

    def parser(self):
        parser = argparse.ArgumentParser()
        parser.error = lambda message: (_ for _ in ()).throw(SystemExit(message))
        return parser

    def test_beyond_loopback_the_server_refuses_without_tls_users_and_a_host_name(self):
        with self.assertRaises(SystemExit) as caught:
            app.make_server(self.args(), self.parser())
        self.assertIn('TLS', str(caught.exception))
        cert, key = self.certificate()
        with self.assertRaises(SystemExit) as caught:
            app.make_server(self.args(tls_cert=cert, tls_key=key), self.parser())
        self.assertIn('admin', str(caught.exception))
        auth.add_user('boss', 'admin', PASSWORD)
        with self.assertRaises(SystemExit) as caught:
            app.make_server(self.args(tls_cert=cert, tls_key=key), self.parser())
        self.assertIn('--public-host', str(caught.exception))

    def certificate(self):
        if not shutil.which('openssl'):
            self.skipTest('openssl yo‘q')
        cert, key = self.folder / 'cert.pem', self.folder / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=localhost',
                        '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1', '-keyout', str(key), '-out', str(cert)],
                       check=True, capture_output=True)
        return str(cert), str(key)

    def test_over_tls_the_cookie_is_secure_and_hsts_is_sent(self):
        cert, key = self.certificate()
        auth.add_user('boss', 'admin', PASSWORD)
        for patcher in (mock.patch.object(app, 'TLS', [False]), mock.patch.object(app, 'PUBLIC_HOSTS', [])):
            patcher.start()
            self.addCleanup(patcher.stop)
        server = app.make_server(self.args(bind='127.0.0.1', tls_cert=cert, tls_key=key), self.parser())
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        port = server.server_port
        context = ssl.create_default_context(cafile=cert)
        connection = http.client.HTTPSConnection('127.0.0.1', port, context=context, timeout=10)
        connection.request('POST', '/api/auth/login', body=json.dumps({'username': 'boss', 'password': PASSWORD}),
                           headers={'Host': f'127.0.0.1:{port}', 'Content-Type': 'application/json'})
        response = connection.getresponse()
        response.read()
        self.assertEqual(response.status, 200)
        self.assertIn('Secure', response.getheader('Set-Cookie'))
        self.assertEqual(response.getheader('Strict-Transport-Security'), 'max-age=31536000')
        connection.close()
        # Plain HTTP to the TLS port gets nothing usable.
        plain = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
        with self.assertRaises((http.client.HTTPException, OSError)):
            plain.request('GET', '/api/auth/me', headers={'Host': f'127.0.0.1:{port}'})
            plain.getresponse().read()


if __name__ == '__main__':
    unittest.main()
