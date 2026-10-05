"""API inventory for the web scan (zanjir.api_inventory).

Two sources feed the inventory -- live spec URLs and spec files in the linked
source repo -- and every documented static endpoint gets one unauthenticated
GET. These tests cover parsing (only a real OpenAPI/Swagger doc counts), path
extraction (GET only, parameters inventoried but not probed), repo discovery
(bounded, spec-named files only), and the two findings it raises, driven against
a real loopback server so the GETs are genuine.
"""
import json
import tempfile
import threading
import unittest
from pathlib import Path
from http.server import BaseHTTPRequestHandler

from zanjir import api_inventory as inv
from zanjir import webscan as w
from zanjir.httptest import listener

SPEC = {
    'openapi': '3.0.0',
    'paths': {
        '/health': {'get': {}},
        '/users': {'get': {}},
        '/users/{id}': {'get': {}},     # parameterised: inventoried, never probed
        '/admin': {'post': {}},          # no GET: left out entirely
    },
}
SPEC_BYTES = json.dumps(SPEC).encode()


def site(routes):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def log_message(self, *_):
            pass

        def do_GET(self):
            path = self.path.split('?')[0]
            body = routes.get(path)
            body = body() if callable(body) else body
            status = 200 if body is not None else 404
            body = body if body is not None else b'nf'
            self.send_response(status)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    return Handler


class ParseTests(unittest.TestCase):
    def test_valid_json_spec(self):
        self.assertIsNotNone(inv.parse_spec(json.dumps(SPEC)))

    def test_valid_yaml_spec(self):
        self.assertIsNotNone(inv.parse_spec('swagger: "2.0"\npaths:\n  /a:\n    get: {}\n'))

    def test_html_is_not_a_spec(self):
        self.assertIsNone(inv.parse_spec('<html><body>openapi 3.0 paths</body></html>'))

    def test_json_without_paths_is_not_a_spec(self):
        self.assertIsNone(inv.parse_spec('{"openapi":"3.0.0"}'))

    def test_json_without_version_is_not_a_spec(self):
        self.assertIsNone(inv.parse_spec('{"paths":{"/a":{"get":{}}}}'))

    def test_empty_and_garbage(self):
        self.assertIsNone(inv.parse_spec(''))
        self.assertIsNone(inv.parse_spec('}{ not json'))


class PathTests(unittest.TestCase):
    def test_only_get_paths_including_parameterised(self):
        self.assertEqual(inv.spec_get_paths(SPEC), {'/health', '/users', '/users/{id}'})

    def test_post_only_path_excluded(self):
        self.assertNotIn('/admin', inv.spec_get_paths(SPEC))


class RepoDiscoveryTests(unittest.TestCase):
    def test_finds_spec_files_and_ignores_the_rest(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / 'openapi.json').write_bytes(SPEC_BYTES)
            (root / 'sub').mkdir()
            (root / 'sub' / 'swagger.yaml').write_text('swagger: "2.0"\npaths:\n  /x:\n    get: {}\n')
            (root / 'notes.txt').write_text('openapi 3.0 paths here but not a spec file suffix')
            (root / 'config.json').write_text('{"unrelated":true}')  # not a spec name
            found = dict(inv.discover_repo(root))
            labels = {Path(k).name for k in found}
            self.assertEqual(labels, {'openapi.json', 'swagger.yaml'})

    def test_oversized_spec_file_is_skipped(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            big = b'{"openapi":"3.0.0","paths":{"/a":{"get":{}},"_pad":"' + b'x' * (inv.MAX_SPEC_FILE_BYTES + 10) + b'"}}'
            (root / 'openapi.json').write_bytes(big)
            self.assertEqual(inv.discover_repo(root), [])

    def test_missing_root_is_empty(self):
        self.assertEqual(inv.discover_repo(Path('/no/such/dir/xyz')), [])


class LiveInventoryTests(unittest.TestCase):
    def collector(self, url):
        profile = {'id': 't', 'url': url, 'owner': 'test', 'authorized_at': w.now(),
                   'allow_private': True, 'rate_delay': 0.5}
        collector = w.Collector(profile, set(), threading.Event())
        collector.delay = 0.0
        self.addCleanup(collector.close)
        return collector

    def test_spec_at_nonstandard_url_is_reported_and_endpoints_probed(self):
        # Spec served at /api-docs (not a Nuclei-default path); /health and /users
        # answer, /secret 404s. Unauthenticated scan -> the two 2xx endpoints are
        # flagged, and the non-default spec URL raises api-spec-exposed.
        with listener(site({'/api-docs': SPEC_BYTES, '/health': b'ok', '/users': b'[]'})) as url:
            findings, inventory = inv.inventory_findings(self.collector(url), w.finding, authenticated=False)
        rules = {f['rule_id'] for f in findings}
        self.assertIn('api-spec-exposed', rules)
        self.assertIn('api-endpoint-unauthenticated', rules)
        self.assertEqual(inventory['documented_endpoints'], 3)       # /health /users /users/{id}
        self.assertEqual(inventory['parameterised_skipped'], 1)      # /users/{id} never probed
        unauth = next(f for f in findings if f['rule_id'] == 'api-endpoint-unauthenticated')
        self.assertIn('/health', unauth['evidence'])
        self.assertIn('/users', unauth['evidence'])

    def test_authenticated_scan_makes_no_without_auth_claim(self):
        with listener(site({'/api-docs': SPEC_BYTES, '/health': b'ok', '/users': b'[]'})) as url:
            findings, _ = inv.inventory_findings(self.collector(url), w.finding, authenticated=True)
        self.assertNotIn('api-endpoint-unauthenticated', {f['rule_id'] for f in findings})

    def test_no_spec_anywhere_yields_nothing(self):
        with listener(site({'/': b'<html>app</html>'})) as url:
            findings, inventory = inv.inventory_findings(self.collector(url), w.finding, authenticated=False)
        self.assertEqual(findings, [])
        self.assertEqual(inventory['documented_endpoints'], 0)

    def test_default_path_spec_is_not_double_reported_as_exposed(self):
        # A spec at /openapi.json is already the Nuclei template's job, so the
        # inventory must not raise its own api-spec-exposed for it (no duplicate),
        # but must still read it to drive the endpoint probes.
        with listener(site({'/openapi.json': SPEC_BYTES, '/health': b'ok', '/users': b'[]'})) as url:
            findings, inventory = inv.inventory_findings(self.collector(url), w.finding, authenticated=False)
        self.assertNotIn('api-spec-exposed', {f['rule_id'] for f in findings})
        self.assertIn('api-endpoint-unauthenticated', {f['rule_id'] for f in findings})
        self.assertEqual(inventory['documented_endpoints'], 3)

    def test_repo_spec_drives_inventory_without_a_live_spec(self):
        # The app exposes no spec, but the linked repo has one: the documented
        # endpoints are still known and probed.
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / 'openapi.json').write_bytes(SPEC_BYTES)
            with listener(site({'/health': b'ok', '/users': b'[]'})) as url:
                findings, inventory = inv.inventory_findings(
                    self.collector(url), w.finding, source_root=Path(d), authenticated=False)
        self.assertIn('api-endpoint-unauthenticated', {f['rule_id'] for f in findings})
        self.assertEqual(inventory['documented_endpoints'], 3)
        self.assertTrue(any(s['origin'] == 'repo' for s in inventory['spec_sources']))


if __name__ == '__main__':
    unittest.main()
