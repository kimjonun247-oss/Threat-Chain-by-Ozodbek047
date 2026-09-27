"""Second-look confirmation of web findings (webscan.confirm_findings).

A single matching response is an observation. These targets are built to fool
one look -- an allow-listed CORS origin, an HTML page that quotes an env line,
a body that changes between requests, a single-page-app fallback -- and each
must come out as `not_reproduced` or `dismissed`, while the real thing is
`confirmed`.
"""
import itertools
import threading
import unittest
from http.server import BaseHTTPRequestHandler

from zanjir import webscan as w
from zanjir.httptest import listener

HTML_ENV = b'<html><body><h1>Setup guide</h1><p>Put DB_PASSWORD=changeme in your .env</p></body></html>'
REAL_ENV = b'DB_PASSWORD=Sup3rS3cret\nAPI_KEY=abcd1234\n# comment\n'
counter = itertools.count()


def site(routes, fallback=None, cors=None):
    """routes: path -> body (bytes) or callable returning bytes."""

    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def log_message(self, *_):
            pass

        def do_GET(self):
            path = self.path.split('?')[0]
            body = routes.get(path, fallback)
            body = body() if callable(body) else body
            status = 200 if body is not None else 404
            body = body if body is not None else b'not found'
            self.send_response(status)
            self.send_header('Content-Length', str(len(body)))
            origin = self.headers.get('Origin')
            if origin and cors and cors(origin):
                self.send_header('Access-Control-Allow-Origin', origin)
                self.send_header('Access-Control-Allow-Credentials', 'true')
            self.end_headers()
            self.wfile.write(body)
    return Handler


class ConfirmTests(unittest.TestCase):
    def collector(self, url, paths):
        profile = {'id': 't', 'url': url, 'owner': 'test', 'authorized_at': w.now(), 'allow_private': True,
                   'rate_delay': 0.5}
        collector = w.Collector(profile, set(paths), threading.Event())
        collector.delay = 0.01
        self.addCleanup(collector.close)
        return collector

    def first_look(self, collector, rule, path, extra=None):
        collector.fetch(path, extra_headers=extra)
        return w.finding(rule, 't', 'HIGH', path, 'e', 'fix', 'Nuclei')

    def test_a_real_env_file_is_confirmed(self):
        with listener(site({'/.env': REAL_ENV})) as url:
            c = self.collector(url, ['/.env'])
            findings = [self.first_look(c, 'zanjir-env', '/.env')]
            summary = w.confirm_findings(c, findings)
        self.assertEqual(findings[0]['confirmation']['state'], 'confirmed')
        self.assertTrue(findings[0]['verified'])
        self.assertEqual((summary['confirmed'], summary['requests']), (1, 1))

    def test_an_html_page_quoting_an_env_line_is_not_an_env_file(self):
        with listener(site({'/.env': HTML_ENV})) as url:
            c = self.collector(url, ['/.env'])
            findings = [self.first_look(c, 'zanjir-env', '/.env')]
            w.confirm_findings(c, findings)
        self.assertEqual(findings[0]['confirmation']['state'], 'not_reproduced')
        self.assertFalse(findings[0]['verified'])
        self.assertIn('KEY=VALUE', findings[0]['confirmation']['method'])

    def test_a_body_that_changes_between_requests_is_not_reproduced(self):
        with listener(site({'/backup.sql': lambda: f'CREATE TABLE t{next(counter)} (id int);'.encode()})) as url:
            c = self.collector(url, ['/backup.sql'])
            findings = [self.first_look(c, 'zanjir-sql-backup', '/backup.sql')]
            w.confirm_findings(c, findings)
        self.assertEqual(findings[0]['confirmation']['state'], 'not_reproduced')

    def test_an_allow_listed_origin_is_not_blind_reflection(self):
        allow = lambda origin: origin == w.CORS_PROBE_ORIGIN
        with listener(site({'/': b'<html>ok</html>'}, cors=allow)) as url:
            c = self.collector(url, ['/'])
            findings = [self.first_look(c, 'cors-reflected-origin-credentials', '/', {'Origin': w.CORS_PROBE_ORIGIN})]
            w.confirm_findings(c, findings)
        self.assertEqual(findings[0]['confirmation']['state'], 'not_reproduced')

    def test_blind_reflection_is_confirmed(self):
        with listener(site({'/': b'<html>ok</html>'}, cors=lambda origin: True)) as url:
            c = self.collector(url, ['/'])
            findings = [self.first_look(c, 'cors-reflected-origin-credentials', '/', {'Origin': w.CORS_PROBE_ORIGIN})]
            w.confirm_findings(c, findings)
        self.assertEqual(findings[0]['confirmation']['state'], 'confirmed')

    def test_a_single_page_app_fallback_is_dismissed_with_the_reason(self):
        spa = b'<!doctype html><html><body><div id=app></div><script>/* services: */</script></body></html>'
        with listener(site({}, fallback=spa)) as url:
            c = self.collector(url, ['/'])
            item = w.finding('ambiguous-fallback', 't', 'MEDIUM', '/', 'e', 'fix', verified=False)
            item['matched_rules'] = ['zanjir-env', 'zanjir-compose']
            findings = [item]
            summary = w.confirm_findings(c, findings)
        self.assertEqual(findings, [])
        self.assertEqual(summary['dismissed'], 1)
        self.assertIn('HTML', summary['dismissed_findings'][0]['confirmation']['method'])

    def test_a_fallback_that_serves_an_env_file_everywhere_is_confirmed(self):
        with listener(site({}, fallback=REAL_ENV)) as url:
            c = self.collector(url, ['/'])
            item = w.finding('ambiguous-fallback', 't', 'MEDIUM', '/', 'e', 'fix', verified=False)
            item['matched_rules'] = ['zanjir-env']
            findings = [item]
            w.confirm_findings(c, findings)
        self.assertEqual(findings[0]['confirmation']['state'], 'confirmed')
        self.assertEqual(findings[0]['severity'], 'HIGH')

    def test_the_confirmation_pass_never_exceeds_its_own_budget(self):
        routes = {f'/f{i}.sql': b'CREATE TABLE t (id int);' for i in range(w.CONFIRM_BUDGET + 5)}
        with listener(site(routes)) as url:
            c = self.collector(url, routes)
            findings = [self.first_look(c, 'zanjir-sql-backup', path) for path in routes]
            summary = w.confirm_findings(c, findings)
        self.assertEqual(summary['requests'], w.CONFIRM_BUDGET)
        self.assertEqual(summary['inconclusive'], 5)

    def test_structure_checks(self):
        self.assertTrue(w.structured(b'services:\n  web:\n    image: nginx\n', 'compose'))
        self.assertFalse(w.structured(b'<html>services:</html>', 'compose'))
        self.assertTrue(w.structured(b'{"openapi": "3.0.0", "paths": {}}', 'openapi'))
        self.assertFalse(w.structured(b'{"openapi": "3.0.0"}', 'openapi'))
        self.assertTrue(w.structured(b'[core]\n\trepositoryformatversion = 0\n', 'git'))
        self.assertFalse(w.structured(b'<!DOCTYPE html><p>CREATE TABLE</p>', 'sql'))


if __name__ == '__main__':
    unittest.main()
