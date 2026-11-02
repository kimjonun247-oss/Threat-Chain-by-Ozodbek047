"""The dashboard itself under hostile requests (PLAN.md 5.1).

Raw http.client requests, so the paths reach the server exactly as written --
a browser or urllib would normalise `..` away before sending. Each check names
the attack it stands for:

  - path traversal through the static files and through report ids
  - cross-site requests (CSRF): foreign Origin, Sec-Fetch-Site, DNS rebinding
  - XSS: every HTML answer carries a script-only-from-self CSP, every JSON
    answer is JSON with nosniff, so an attacker-chosen string in a report
    cannot run as script
  - the server binds to loopback unless told otherwise
"""
import http.client
import json
import unittest
from pathlib import Path

import app
from app import Handler
from isolation import isolate_triage
from zanjir.httptest import listener

ROOT = Path(__file__).resolve().parent.parent


class WebSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = listener(Handler)
        cls.url = cls.server.__enter__()
        cls.port = int(cls.url.rsplit(':', 1)[1])

    @classmethod
    def tearDownClass(cls):
        cls.server.__exit__(None, None, None)

    def setUp(self):
        isolate_triage(self)

    def raw(self, method, path, headers=None, body=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=30)
        try:
            sent = {'Host': f'127.0.0.1:{self.port}', **(headers or {})}
            data = json.dumps(body).encode() if body is not None else None
            if data is not None:
                sent.setdefault('Content-Type', 'application/json')
            connection.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
            for key, value in sent.items():
                connection.putheader(key, value)
            if data is not None:
                connection.putheader('Content-Length', str(len(data)))
            connection.endheaders(data)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def test_malformed_json_body_gets_a_prompt_400_not_a_hang(self):
        # A small body of a valid declared length that is not JSON: the handler
        # reads it, json.loads fails, and send(400) must NOT drain_body() a second
        # read of the already-consumed body. With that bug the server blocked on
        # the second read until its own timeout, before writing the response, so a
        # short-timeout client never saw the 400. Audit 2026-10-26 B2.
        data = b'this-is-not-json'           # small: under DRAIN_LIMIT, so drain would read
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=15)
        try:
            connection.putrequest('POST', '/api/jobs', skip_host=True, skip_accept_encoding=True)
            connection.putheader('Host', f'127.0.0.1:{self.port}')
            connection.putheader('Content-Type', 'application/json')
            connection.putheader('Content-Length', str(len(data)))
            connection.endheaders(data)
            self.assertEqual(connection.getresponse().status, 400)   # times out here if B2 regresses
        finally:
            connection.close()

    # -- path traversal --------------------------------------------------------------
    def test_a_static_files_cannot_reach_outside_dist(self):
        secret = (ROOT / 'app.py').read_bytes()[:200]
        for path in ('/../app.py', '/..%2fapp.py', '/%2e%2e/app.py', '/dist/../app.py', '/..\\app.py',
                     '/%2e%2e%5capp.py', '/static/../../app.py', '//app.py', '/app.py', '/.git/config',
                     '/scanner-rules/semgrep.yml', '/profiles/settings.json'):
            status, _, body = self.raw('GET', path)
            self.assertNotIn(secret, body, path)
            self.assertNotIn(b'[core]', body, path)
            self.assertNotEqual(status, 500, path)

    def test_b_report_ids_cannot_name_a_file(self):
        for path in ('/api/scanners/reports/..%2f..%2fapp', '/api/scanners/reports/../../app.py',
                     '/api/assessments/reports/..%5c..%5capp/download', '/api/scanners/reports/20260101T000000-aaaaaaaa%00',
                     '/api/iac/reports/..%2f..%2fprofiles%2fsettings', '/api/images/reports/../../../etc/passwd'):
            status, _, body = self.raw('GET', path)
            self.assertIn(status, (400, 403, 404), path)
            self.assertNotIn(b'import ', body, path)

    # -- cross-site requests -----------------------------------------------------------
    def test_c_a_foreign_origin_cannot_start_anything(self):
        for headers in ({'Origin': 'http://evil.example'}, {'Origin': 'null'},
                        {'Sec-Fetch-Site': 'cross-site'},
                        {'Origin': f'http://127.0.0.1:{self.port}.evil.example'}):
            status, _, body = self.raw('POST', '/api/scanners/scan', headers, {'target': 'x'})
            self.assertEqual(status, 403, (headers, body))

    def test_d_dns_rebinding_host_is_refused(self):
        for host in ('evil.example', f'evil.example:{self.port}', f'127.0.0.1.evil.example:{self.port}', ''):
            status, _, _ = self.raw('GET', '/api/readiness', {'Host': host})
            self.assertEqual(status, 403, host)

    def test_e_same_origin_still_works(self):
        status, _, _ = self.raw('GET', '/api/readiness', {'Origin': f'http://127.0.0.1:{self.port}'})
        self.assertEqual(status, 200)

    # -- XSS ---------------------------------------------------------------------------------
    def test_f_html_answers_only_run_our_own_scripts(self):
        status, headers, body = self.raw('GET', '/')
        self.assertEqual(status, 200)
        policy = headers.get('Content-Security-Policy', '')
        for part in ("default-src 'self'", "script-src 'self'", "frame-ancestors 'none'", "base-uri 'none'"):
            self.assertIn(part, policy)
        self.assertNotIn("'unsafe-inline'", policy.split('script-src', 1)[1].split(';', 1)[0])
        self.assertNotIn("'unsafe-eval'", policy)
        self.assertEqual(headers.get('X-Content-Type-Options'), 'nosniff')

    def test_g_a_reflected_value_comes_back_as_json_not_html(self):
        payload = '<script>alert(1)</script>'
        status, headers, body = self.raw('POST', '/api/scanners/scan', {}, {'target': payload})
        self.assertIn(status, (400, 404, 409))
        self.assertTrue(headers.get('Content-Type', '').startswith('application/json'), headers)
        self.assertEqual(headers.get('X-Content-Type-Options'), 'nosniff')
        status, headers, _ = self.raw('GET', '/api/dependencies/reports?target=' + '%3Cscript%3E')
        self.assertTrue(headers.get('Content-Type', '').startswith('application/json'))

    def test_h_the_page_works_without_inline_script(self):
        # The UI builds HTML with innerHTML and escapeHTML (audited 2026-10-13:
        # report fields are escaped; the unescaped interpolations are constants,
        # numbers, ids and helpers that escape inside). Stored XSS that slipped
        # past an escape is still stopped by the CSP above -- which only holds as
        # long as the page itself needs no inline script or inline handler.
        import re
        page = (ROOT / 'dist' / 'index.html').read_text(encoding='utf-8')
        self.assertEqual(re.findall(r'<script(?![^>]*\bsrc=)[^>]*>', page), [])
        self.assertEqual(re.findall(r'\son[a-z]+\s*=', page), [])
        bundle = (ROOT / 'dist' / 'bundle.js').read_text(encoding='utf-8')
        self.assertNotRegex(bundle, r'\beval\(|new Function\(', "CSP has no 'unsafe-eval'")

    # -- binding -------------------------------------------------------------------------------
    def test_i_the_default_bind_is_loopback(self):
        parser = app.build_parser() if hasattr(app, 'build_parser') else None
        if parser is not None:
            self.assertEqual(parser.parse_args([]).bind, '127.0.0.1')
        else:
            source = (ROOT / 'app.py').read_text(encoding='utf-8')
            self.assertIn("add_argument('--bind', default='127.0.0.1'", source)


if __name__ == '__main__':
    unittest.main()
