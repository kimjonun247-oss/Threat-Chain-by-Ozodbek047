"""Every HTTP route, its status code and its response type -- frozen.

REJA.md's later phases add endpoints, change screens and move fields around. A
route that quietly starts answering 404, or starts returning a list where the
browser expects an object, is the failure mode this file exists to catch: it
does not show up in any unit test of the module behind the route.

Two properties make this safe to run in the suite:

  - Every run directory is patched to a temp copy of tests/fixtures/legacy/, so
    the real evidence folders are never read for state and never written to. It
    also means this file doubles as the "old reports still open through the API"
    check that B0 promises.
  - No request starts a scan. Every POST is probed with a payload the handler
    must reject, so the contract under test is the validation boundary, not the
    scanners. The one exception is /api/rules/validate, which only parses text.
"""
import http.client
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import Handler
from isolation import isolate_triage
from zanjir import dependencies, iac, images, pipeline, repo_store, scanners, webscan
from zanjir.httptest import listener

FIXTURES = Path(__file__).resolve().parent / 'fixtures/legacy'
# stage -> (module, attribute holding the run directory, file name inside a run
# folder or None when the module stores one flat file per report)
STAGES = {
    'code': (scanners, 'RUNS', 'report.json'),
    'dependencies': (dependencies, 'RUNS', 'report.json'),
    'images': (images, 'RUNS', 'report.json'),
    'web': (webscan, 'RUNS', 'report.json'),
    'assessment': (pipeline, 'RUNS', 'report.json'),
    'repository': (repo_store, 'REPO_RUNS', None),
    'iac': (iac, 'RUNS', 'report.json'),
}


def fixture(stage, label='newest'):
    return json.loads((FIXTURES / f'{stage}-{label}.json').read_text(encoding='utf-8'))


class ApiTests(unittest.TestCase):
    """One server, one temp evidence tree, shared by every check below."""

    def setUp(self):
        isolate_triage(self)

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.ids = {}
        cls.patchers = []
        for stage, (module, attribute, name) in STAGES.items():
            folder = cls.tmp / stage
            folder.mkdir(parents=True)
            report = fixture(stage)
            cls.ids[stage] = report['id']
            if name is None:
                (folder / f'{report["id"]}.json').write_text(json.dumps(report), encoding='utf-8')
            else:
                run = folder / report['id']
                run.mkdir()
                (run / name).write_text(json.dumps(report), encoding='utf-8')
                if stage == 'dependencies':
                    (run / 'inventory.json').write_text(json.dumps({'packages': []}), encoding='utf-8')
            patcher = patch.object(module, attribute, folder)
            patcher.start()
            cls.patchers.append(patcher)
        cls.server = listener(Handler)
        cls.url = cls.server.__enter__()
        cls.port = int(cls.url.rsplit(':', 1)[1])

    @classmethod
    def tearDownClass(cls):
        cls.server.__exit__(None, None, None)
        for patcher in cls.patchers:
            patcher.stop()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def call(self, method, path, payload=None, headers=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=15)
        try:
            body = json.dumps(payload) if payload is not None else None
            sent = {'Content-Type': 'application/json'} if body is not None else {}
            sent.update(headers or {})
            connection.request(method, path, body=body, headers=sent)
            response = connection.getresponse()
            return response.status, response.getheader('Content-Type') or '', response.read()
        finally:
            connection.close()

    def get(self, path):
        return self.call('GET', path)

    def json_get(self, path, expected=200):
        status, content_type, body = self.get(path)
        self.assertEqual(status, expected, f'{path}: {body[:200]}')
        self.assertTrue(content_type.startswith('application/json'), f'{path}: {content_type}')
        return json.loads(body)


class StaticAssetTests(ApiTests):
    def test_a_every_shipped_asset_is_served_with_its_type(self):
        expected = {'/': 'text/html', '/index.html': 'text/html',
                    '/app.js': 'text/javascript', '/scanners.js': 'text/javascript',
                    '/dependencies.js': 'text/javascript', '/pilot-dashboard.js': 'text/javascript',
                    '/web-pilot.js': 'text/javascript', '/iac.js': 'text/javascript',
                    '/shell.js': 'text/javascript', '/dashboard.js': 'text/javascript',
                    '/findings.js': 'text/javascript',
                    '/project.js': 'text/javascript',
                    '/portfolio.js': 'text/javascript',
                    '/style.css': 'text/css', '/dependencies.css': 'text/css',
                    '/favicon.svg': 'image/svg+xml'}
        for path, mime in expected.items():
            status, content_type, body = self.get(path)
            self.assertEqual(status, 200, path)
            self.assertTrue(content_type.startswith(mime), f'{path}: {content_type}')
            self.assertTrue(body, path)

    def test_b_unknown_page_is_a_json_404(self):
        self.assertIn('error', self.json_get('/nimadir', 404))

    def test_c_security_headers_on_every_response(self):
        status, _, _ = self.get('/')
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=15)
        try:
            connection.request('GET', '/')
            response = connection.getresponse()
            response.read()
            policy = response.getheader('Content-Security-Policy') or ''
        finally:
            connection.close()
        self.assertEqual(status, 200)
        for directive in ("default-src 'self'", "script-src 'self'", "style-src 'self'", "frame-ancestors 'none'"):
            self.assertIn(directive, policy)


class ListingTests(ApiTests):
    def test_a_overview_endpoints_return_objects(self):
        for path, keys in (('/api/health', {'ok', 'version', 'code_fingerprint'}),
                           ('/api/readiness', {'version', 'tools', 'targets', 'limits'}),
                           ('/api/portfolio', {'projects', 'stages'}),
                           ('/api/portfolio/targets', {'stages'}),
                           ('/api/rules', {'rules', 'summary', 'languages', 'severities'}),
                           ('/api/web/control-evidence', {'passed'}),
                           ('/api/scanners/pilot', {'state'}),
                           ('/api/settings', {'nvd_api_key', 'registration_enabled', 'python', 'version'}),
                           ('/api/findings', {'total', 'rows', 'facets', 'coverage'}),
                           ('/api/dashboard', {'system', 'totals', 'coverage', 'projects', 'recent', 'trend'})):
            document = self.json_get(path)
            self.assertIsInstance(document, dict, path)
            self.assertTrue(keys <= set(document), f'{path}: {sorted(keys - set(document))} yo‘q')

    def test_b_target_and_report_listings_return_lists(self):
        for path in ('/api/scanners/targets', '/api/scanners/reports',
                     '/api/images/targets', '/api/images/reports',
                     '/api/dependencies/reports', '/api/dependencies/reports?target=crapi-full',
                     '/api/iac/targets', '/api/iac/reports',
                     '/api/web/targets', '/api/web/reports', '/api/assessments/reports',
                     '/api/repository/profiles', '/api/repository/reports'):
            self.assertIsInstance(self.json_get(path), list, path)

    def test_b2_only_web_has_a_targets_route_under_the_shared_prefix(self):
        # /api/web and /api/assessments share one dispatch block; only webscan
        # answers /targets there. Frozen so a later phase notices if that moves.
        self.assertIsInstance(self.json_get('/api/web/targets'), list)
        self.assertIn('error', self.json_get('/api/assessments/targets', 404))

    def test_b1_the_findings_board_answers_and_names_what_was_not_scanned(self):
        board = self.json_get('/api/findings?limit=1')
        self.assertIsInstance(board['rows'], list)
        self.assertIn('unscanned', board['coverage'])
        self.assertIn('ball chiqarilmaydi', board['facets']['note'])
        self.assertIn('error', self.json_get('/api/findings/yo-q-bunday', 404))

    def test_b2_baseline_answers_with_a_reason_rather_than_an_error(self):
        # A first scan having nothing to compare with is the normal state of a
        # first scan, not a client error -- it must not put a red line in the
        # console of a healthy page. Bad input is still a 400.
        answer = self.json_get(f'/api/baseline/code/{self.ids["code"]}')
        self.assertFalse(answer['available'])
        self.assertIn('asosi', answer['reason'])
        self.assertIn('error', self.json_get('/api/baseline/nessus/' + self.ids['code'], 400))
        self.assertIn('error', self.json_get('/api/baseline/code', 404))

    def test_b3_the_triage_overview_answers_for_any_valid_scope(self):
        overview = self.json_get('/api/triage/chain-demo')
        self.assertEqual(overview['scope'], 'chain-demo')
        self.assertEqual(overview['decisions'], [])          # isolated store, nothing decided
        self.assertEqual(overview['sla_days'], {'CRITICAL': 7, 'HIGH': 30, 'MEDIUM': 90, 'LOW': 120})
        self.assertIn('error', self.json_get('/api/triage/..%2fetc', 400))

    def test_c_repository_reviews_is_an_object(self):
        self.assertIsInstance(self.json_get('/api/repository/reviews'), dict)

    def test_d_listings_show_the_fixture_reports(self):
        """The patched evidence tree is what the API is reading -- proof, not assumption."""
        for path, stage in (('/api/scanners/reports', 'code'), ('/api/images/reports', 'images'),
                            ('/api/dependencies/reports', 'dependencies'), ('/api/web/reports', 'web'),
                            ('/api/assessments/reports', 'assessment'),
                            ('/api/iac/reports', 'iac'),
                            ('/api/repository/reports', 'repository')):
            listed = {row['id'] for row in self.json_get(path)}
            self.assertEqual(listed, {self.ids[stage]}, path)

    def test_e_bad_query_parameters_are_refused_or_matched_against_nothing(self):
        # The two listings differ on purpose: repository validates the id because
        # it builds a path from it, while the dependency listing only filters rows
        # already read from disk, so an unmatched value is an empty list, not an
        # error. Both are recorded here so a later phase cannot quietly swap them.
        self.assertEqual(self.json_get('/api/dependencies/reports?target=../etc'), [])
        self.assertIn('error', self.json_get('/api/repository/reports?profile_id=../etc', 400))
        self.assertIn('error', self.json_get('/api/portfolio/trend', 400))


class ReportRouteTests(ApiTests):
    """Every per-report route, including the export formats."""

    ROUTES = {
        'code': ('/api/scanners/reports/{id}', ['download']),
        'iac': ('/api/iac/reports/{id}', ['download', 'markdown']),
        'dependencies': ('/api/dependencies/reports/{id}', ['download', 'inventory', 'markdown', 'reviews']),
        'images': ('/api/images/reports/{id}', ['download']),
        'web': ('/api/web/reports/{id}', ['download', 'markdown']),
        'assessment': ('/api/assessments/reports/{id}', ['download', 'markdown', 'sarif']),
        'repository': ('/api/repository/reports/{id}', ['download', 'sarif']),
    }

    def test_a_each_frozen_report_opens_through_its_own_route(self):
        for stage, (template, _) in self.ROUTES.items():
            document = self.json_get(template.format(id=self.ids[stage]))
            self.assertEqual(document['id'], self.ids[stage], stage)

    def test_b_each_export_format_answers_with_its_own_content_type(self):
        for stage, (template, formats) in self.ROUTES.items():
            for suffix in formats:
                path = template.format(id=self.ids[stage]) + '/' + suffix
                status, content_type, body = self.get(path)
                self.assertEqual(status, 200, f'{path}: {body[:200]}')
                expected = 'text/markdown' if suffix == 'markdown' else 'application/json'
                self.assertTrue(content_type.startswith(expected), f'{path}: {content_type}')
                self.assertTrue(body, path)

    def test_c_unknown_ids_and_formats_are_404_not_500(self):
        for stage, (template, _) in self.ROUTES.items():
            self.assertIn('error', self.json_get(template.format(id='20200101T000000-deadbeef'), 404))
            self.assertIn('error', self.json_get(template.format(id=self.ids[stage]) + '/unknown-format', 404))

    def test_d_a_path_outside_the_run_folder_is_refused(self):
        for stage, (template, _) in self.ROUTES.items():
            for attempt in ('..%2f..%2fetc%2fpasswd', 'not-a-run-id', '.', '..'):
                status, _, _ = self.get(template.format(id=attempt))
                self.assertEqual(status, 404, f'{stage}: {attempt}')


class WriteBoundaryTests(ApiTests):
    """Every POST route, probed only with payloads it must reject.

    A scan is never started here: these assertions are about the validation
    boundary, which is exactly the part later phases will be editing.
    """

    REJECTED = [
        ('/api/portfolio/register', {'id': 'x'}, 400),
        ('/api/portfolio/remove', {}, 400),
        # Triage: the boundary that stops a decision nobody can verify later.
        ('/api/triage', {'stage': 'code', 'report_id': 'yo-q', 'status': 'confirmed',
                         'owner': 'AX', 'note': 'asos', 'fingerprint': 'a' * 24}, 400),
        ('/api/triage', {'stage': 'nessus', 'report_id': 'yo-q', 'status': 'confirmed',
                         'owner': 'AX', 'note': 'asos', 'fingerprint': 'a' * 24}, 400),
        ('/api/triage/bulk', {'stage': 'code', 'report_id': 'yo-q'}, 400),
        ('/api/triage/nimadir', {'stage': 'code', 'report_id': 'yo-q', 'status': 'confirmed',
                                 'owner': 'AX', 'note': 'asos', 'fingerprint': 'a' * 24}, 404),
        ('/api/rules/save', {'name': 'x'}, 400),
        ('/api/rules/delete', {}, 400),
        # A rule-editor typo: this once escaped as a yaml.YAMLError past app.py's
        # `except ValueError` and closed the connection with no response at all.
        ('/api/rules/validate', {'text': 'bu yaml emas: ['}, 400),
        ('/api/rules/validate', {'text': 'rules:\n  - id: [ochilgan'}, 400),
        ('/api/web/scan', {'target': 'yo-q', 'online': True}, 400),
        ('/api/web/scan', {'target': 'pilot-crapi', 'online': False}, 400),
        ('/api/web/cancel', {'report_id': 'yo-q'}, 400),
        ('/api/assessments/scan', {'target': 'yo-q'}, 400),
        ('/api/assessments/cancel', {'report_id': 'yo-q'}, 400),
        ('/api/images/scan', {'target': 'yo-q', 'online': True}, 400),
        ('/api/images/scan', {'target': 'pilot-crapi-web', 'online': False}, 400),
        ('/api/images/cancel', {'report_id': 'yo-q'}, 400),
        ('/api/scanners/scan', {'target': 'yo-q'}, 400),
        ('/api/iac/scan', {'target': 'yo-q'}, 400),
        # The registry windows: validated values are accepted, a filesystem path
        # is refused unless the operator opted in when starting the server.
        ('/api/registry/image', {'id': 'x'}, 400),
        ('/api/registry/web', {'id': 'x', 'url': 'not-a-url', 'owner': 'AX'}, 400),
        ('/api/registry/project', {'id': 'x', 'root': '/'}, 403),
        ('/api/settings/nvd-key', {'key': 'bo‘sh joyli kalit'}, 400),
        ('/api/settings/nvd-key', {'nope': ''}, 400),
        ('/api/iac/cancel', {'report_id': 'yo-q'}, 400),
        ('/api/scanners/scan', {'target': 'crapi-full', 'extra': 1}, 400),
        ('/api/dependencies/scan', {'target': 'yo-q'}, 400),
        ('/api/dependencies/cancel', {'report_id': 'yo-q'}, 400),
        ('/api/dependencies/review', {'report_id': 'yo-q'}, 400),
        ('/api/dependencies/compare', {'before': 'yo-q', 'after': 'yo-q'}, 400),
        ('/api/repository/scan', {'profile_id': 'yo-q'}, 400),
        ('/api/repository/review', {'report_id': 'yo-q'}, 400),
        ('/api/repository/compare', {'before': 'yo-q'}, 400),
        ('/api/yo-q', {}, 404),
    ]

    def test_a_invalid_payloads_are_refused_with_a_message(self):
        for path, payload, expected in self.REJECTED:
            status, content_type, body = self.call('POST', path, payload)
            self.assertEqual(status, expected, f'{path}: {status} {body[:200]}')
            self.assertTrue(content_type.startswith('application/json'), path)
            self.assertIn('error', json.loads(body), path)

    def test_b_a_valid_rule_validates_without_touching_disk(self):
        rule = ('rules:\n'
                '  - id: namuna-qoida\n'
                '    languages: [python]\n'
                '    severity: WARNING\n'
                '    message: namuna\n'
                '    metadata:\n'
                '      cwe: "CWE-78"\n'
                '    pattern: eval(...)\n')
        status, _, body = self.call('POST', '/api/rules/validate', {'text': rule})
        self.assertEqual(status, 200, body[:300])
        self.assertTrue(json.loads(body)['valid'])

    def test_c_non_json_body_is_415_and_oversize_is_413(self):
        status, _, _ = self.call('POST', '/api/scanners/scan', headers={'Content-Type': 'text/plain'})
        self.assertEqual(status, 415)
        status, _, _ = self.call('POST', '/api/scanners/scan', {'target': 'x' * 4000})
        self.assertEqual(status, 413)


class LocalOnlyTests(ApiTests):
    """The three checks that keep this a local, single-user tool."""

    def test_a_cross_site_post_is_refused(self):
        status, _, body = self.call('POST', '/api/scanners/scan', {'target': 'crapi-full'},
                                    headers={'Origin': 'http://evil.example'})
        self.assertEqual(status, 403)
        self.assertIn('error', json.loads(body))

    def test_b_non_local_host_header_is_refused(self):
        status, _, _ = self.call('GET', '/api/readiness', headers={'Host': 'evil.example'})
        self.assertEqual(status, 403)

    def test_c_same_origin_post_still_works(self):
        status, _, _ = self.call('POST', '/api/rules/validate', {'text': 'rules: []'},
                                 headers={'Origin': f'http://127.0.0.1:{self.port}'})
        self.assertIn(status, (200, 400))       # rejected on content, not on origin


if __name__ == '__main__':
    unittest.main()
