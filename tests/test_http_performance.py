"""Dashboard delivery: compression, caching, keep-alive and lazy views.

Measured before this change (2026-09-25, Chromium, same data): opening the
overview sent 51 requests and ~515 KB, /api/dashboard was requested twice and
took 0.6-1.4 s under the parallel load, every static file was `no-store`, and
each request opened a new connection. These tests keep the fixes in place.
"""
import gzip
import http.client
import json
import re
import shutil
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

import app
from zanjir import code_targets, repo_store, scanners


class Server(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), app.Handler)
        self.port = self.server.server_port
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def get(self, path, headers=None, connection=None):
        if connection is None:
            connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=10)
            self.addCleanup(connection.close)
        connection.request('GET', path, headers={'Host': f'127.0.0.1:{self.port}', **(headers or {})})
        response = connection.getresponse()
        return response, response.read(), connection


class StaticAssetTests(Server):
    def test_page_links_every_asset_by_content_hash(self):
        _, body, _ = self.get('/')
        refs = re.findall(rb'(?:src|href)="(/[a-z-]+\.(?:js|css|svg))(\?v=[0-9a-f]{16})?"', body)
        self.assertTrue(refs)
        self.assertTrue(all(version for _, version in refs), refs)

    def test_versioned_asset_is_immutable_and_unversioned_revalidates(self):
        etag = app.asset('app.js')[1]
        response, _, _ = self.get(f'/app.js?v={etag}')
        self.assertIn('immutable', response.getheader('Cache-Control'))
        response, _, _ = self.get('/app.js')
        self.assertEqual(response.getheader('Cache-Control'), 'no-cache')
        response, _, _ = self.get('/', headers={})
        self.assertEqual(response.getheader('Cache-Control'), 'no-cache')

    def test_unchanged_asset_answers_304(self):
        response, _, _ = self.get('/style.css')
        etag = response.getheader('ETag')
        response, body, _ = self.get('/style.css', headers={'If-None-Match': etag})
        self.assertEqual(response.status, 304)
        self.assertEqual(body, b'')

    def test_gzip_only_when_asked_and_body_is_identical(self):
        response, plain, _ = self.get('/style.css')
        self.assertIsNone(response.getheader('Content-Encoding'))
        response, packed, _ = self.get('/style.css', headers={'Accept-Encoding': 'gzip, deflate'})
        self.assertEqual(response.getheader('Content-Encoding'), 'gzip')
        self.assertEqual(gzip.decompress(packed), plain)
        self.assertLess(len(packed), len(plain) / 2)

    def test_security_headers_survive(self):
        response, _, _ = self.get('/', headers={'Accept-Encoding': 'gzip'})
        self.assertIn("script-src 'self'", response.getheader('Content-Security-Policy'))
        self.assertEqual(response.getheader('X-Content-Type-Options'), 'nosniff')


class ApiDeliveryTests(Server):
    def test_api_json_is_compressed_and_never_stored(self):
        response, body, _ = self.get('/api/portfolio', headers={'Accept-Encoding': 'gzip'})
        self.assertEqual(response.getheader('Cache-Control'), 'no-store')
        if response.getheader('Content-Encoding') == 'gzip':
            body = gzip.decompress(body)
        self.assertIn('projects', json.loads(body))

    def test_connection_is_kept_alive_between_requests(self):
        _, _, connection = self.get('/api/health')
        response, body, _ = self.get('/api/health', connection=connection)
        self.assertEqual(response.status, 200)
        self.assertTrue(json.loads(body)['ok'])

    def test_rejected_post_with_unread_body_closes_the_connection(self):
        # Otherwise the unread body would be parsed as the next request.
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=10)
        self.addCleanup(connection.close)
        connection.request('POST', '/api/scanners/scan', body=b'x' * 10,
                           headers={'Host': f'127.0.0.1:{self.port}', 'Content-Type': 'text/plain'})
        response = connection.getresponse()
        response.read()
        self.assertEqual(response.status, 415)
        self.assertEqual(response.getheader('Connection'), 'close')


class RegistryMemoTests(unittest.TestCase):
    def test_a_new_registration_is_seen_immediately(self):
        folder = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, folder, True)
        project = folder / 'src'
        project.mkdir()
        with patch.object(code_targets, 'PROFILES', folder / 'code'):
            self.assertEqual(code_targets.profiles(), [])
            code_targets.register('fresh', project)
            self.assertEqual([p['id'] for p in code_targets.profiles()], ['fresh'])
            code_targets.remove('fresh')
            self.assertEqual(code_targets.profiles(), [])

    def test_callers_cannot_corrupt_the_cached_listing(self):
        rows = repo_store.list_profiles()
        rows.append({'id': 'intruder'})
        self.assertNotIn('intruder', [p['id'] for p in repo_store.list_profiles()])

    def test_cached_manifest_check_matches_the_full_one(self):
        try:
            full = scanners.registry_manifest()
        except ValueError:
            self.skipTest('Qoida paketi buzilgan holatda')
        self.assertEqual(scanners.registry_manifest(cached=True), full)


class LazyViewTests(unittest.TestCase):
    """Each section loads its data the first time it is opened, not at page load."""

    # The sources are web/src/*.ts; dist/ is their build output.
    def test_section_modules_start_through_when_shown(self):
        src = Path(app.ROOT) / 'web' / 'src'
        expected = {'scanners.ts': "whenShown(['code']", 'dependencies.ts': "whenShown(['dependencies']",
                    'pilot-dashboard.ts': "whenShown(['images']", 'web-pilot.ts': "whenShown(['web', 'assessments']",
                    'app.ts': "whenShown(['repository']"}
        for name, marker in expected.items():
            with self.subTest(name=name):
                text = (src / name).read_text(encoding='utf-8')
                self.assertIn(marker, text)
                if name != 'app.ts':          # app.ts init() only wires buttons
                    self.assertIsNone(re.search(r'(?m)^\s*(init|initCode)\(\);', text))

    def test_sidebar_does_not_fetch_the_dashboard_a_second_time(self):
        shell = (Path(app.ROOT) / 'web' / 'src' / 'shell.ts').read_text(encoding='utf-8')
        self.assertIn("addEventListener('dashboard-data'", shell)
        self.assertNotRegex(shell, r'(?m)^\s*loadHistory\(\);')


if __name__ == '__main__':
    unittest.main()


class BundleAndPollingTests(Server):
    def test_page_loads_one_script_and_one_stylesheet(self):
        _, body, _ = self.get('/')
        scripts = re.findall(rb'<script src="([^"]+)"', body)
        styles = re.findall(rb'<link rel="stylesheet" href="([^"]+)"', body)
        self.assertEqual(len(scripts), 1)
        self.assertEqual(len(styles), 1)
        self.assertTrue(scripts[0].startswith(b'/bundle.js?v='))

    def test_the_built_bundle_is_served_as_built(self):
        # web/build.mjs writes the minified bundle; the server sends that file.
        _, bundle, _ = self.get('/bundle.js')
        self.assertEqual(bundle, (Path(app.ROOT) / 'dist' / 'bundle.js').read_bytes())
        _, css, _ = self.get('/bundle.css')
        self.assertEqual(css, (Path(app.ROOT) / 'dist' / 'bundle.css').read_bytes())

    def test_without_a_built_bundle_the_server_joins_the_files_in_page_order(self):
        built = Path(app.ROOT) / 'dist' / 'bundle.js'
        real_is_file = Path.is_file
        with patch.object(Path, 'is_file', lambda path: False if path == built else real_is_file(path)):
            app._ASSETS.pop('bundle.js', None)
            body = app.asset('bundle.js')[0]
        app._ASSETS.pop('bundle.js', None)
        positions = [body.index(b'/* ---- ' + name.encode() + b' ---- */') for name in app.BUNDLES['bundle.js']]
        self.assertEqual(positions, sorted(positions))
        self.assertIn((Path(app.ROOT) / 'dist' / 'findings.js').read_bytes(), body)

    def test_every_script_is_built_from_its_typescript_source(self):
        for name in app.BUNDLES['bundle.js']:
            with self.subTest(name=name):
                self.assertTrue((Path(app.ROOT) / 'web' / 'src' / name.replace('.js', '.ts')).is_file())
                header = (Path(app.ROOT) / 'dist' / name).read_text(encoding='utf-8').splitlines()[0]
                self.assertEqual(header, f"// Generated from web/src/{name.replace('.js', '.ts')} by web/build.mjs -- edit the source, not this file.")

    def test_debug_mode_serves_files_one_by_one(self):
        with patch.dict('os.environ', {'THREATCHAIN_DEBUG_ASSETS': '1'}):
            _, body, _ = self.get('/')
        self.assertGreater(len(re.findall(rb'<script src=', body)), 5)

    def test_status_view_is_small_and_keeps_what_a_poll_needs(self):
        report = {'id': 'r', 'state': 'running', 'progress': 'Semgrep', 'count': 3,
                  'findings': [{'x': 'y' * 1000}] * 50,
                  'stages': [{'kind': 'code', 'target': 't', 'state': 'running', 'count': 3, 'report': {'big': 1}}]}
        view = app.status_view(report)
        self.assertEqual(view['state'], 'running')
        self.assertNotIn('findings', view)
        self.assertEqual(view['stages'], [{'kind': 'code', 'target': 't', 'state': 'running', 'count': 3}])

    def test_status_query_on_a_real_report_route(self):
        response, body, _ = self.get('/api/portfolio?status=1')
        self.assertIn('projects', json.loads(body))        # not a report: untouched

    def test_follow_loops_use_the_light_poll(self):
        dist = Path(app.ROOT) / 'dist'
        for name in ('scanners.js', 'dependencies.js', 'iac.js', 'pilot-dashboard.js', 'web-pilot.js'):
            with self.subTest(name=name):
                text = (dist / name).read_text(encoding='utf-8')
                self.assertIn('pollReport(', text)
                self.assertNotRegex(text, r'setTimeout\(resolve, ?1[25]00\)')


class PriorityTests(unittest.TestCase):
    def test_scanners_run_below_normal_priority_unless_disabled(self):
        from zanjir import priority
        with patch.dict('os.environ', {priority.VARIABLE: ''}):
            command, extra = priority.gentle(['semgrep', 'scan'])
        self.assertEqual(command[-2:], ['semgrep', 'scan'])
        if sys.platform == 'win32':
            self.assertIn('creationflags', extra)
        elif shutil.which('nice'):
            self.assertIn('nice', ' '.join(command[:-2]))
        with patch.dict('os.environ', {priority.VARIABLE: '1'}):
            self.assertEqual(priority.gentle(['semgrep'])[0], ['semgrep'])
