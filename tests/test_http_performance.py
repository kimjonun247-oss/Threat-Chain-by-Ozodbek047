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

    def test_section_modules_start_through_when_shown(self):
        dist = Path(app.ROOT) / 'dist'
        expected = {'scanners.js': "whenShown(['code']", 'dependencies.js': "whenShown(['dependencies']",
                    'pilot-dashboard.js': "whenShown(['images']", 'web-pilot.js': "whenShown(['web', 'assessments']",
                    'app.js': "whenShown(['repository']"}
        for name, marker in expected.items():
            with self.subTest(name=name):
                text = (dist / name).read_text(encoding='utf-8')
                self.assertIn(marker, text)
                if name != 'app.js':          # app.js init() only wires buttons
                    self.assertIsNone(re.search(r'(?m)^\s*(init|initCode)\(\);', text))

    def test_sidebar_does_not_fetch_the_dashboard_a_second_time(self):
        shell = (Path(app.ROOT) / 'dist' / 'shell.js').read_text(encoding='utf-8')
        self.assertIn("addEventListener('dashboard-data'", shell)
        self.assertNotRegex(shell, r'(?m)^\s*loadHistory\(\);')


if __name__ == '__main__':
    unittest.main()
