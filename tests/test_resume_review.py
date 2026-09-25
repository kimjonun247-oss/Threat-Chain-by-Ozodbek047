from http.server import BaseHTTPRequestHandler
import http.client
from pathlib import Path
import stat
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from app import Handler
import bundle_crapi as b
from zanjir import webscan as w, scanners, pipeline
from zanjir.httptest import listener
from validate_web import fixture


class RangeEvidenceTests(unittest.TestCase):
    def collect(self, content_range, body=b'hello', length=None):
        class RangeHandler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                self.send_response(206)
                for value in content_range:
                    self.send_header('Content-Range', value)
                self.send_header('Content-Length', str(len(body) if length is None else length))
                self.end_headers()
                self.wfile.write(body)

        with listener(RangeHandler) as url:
            collector = w.Collector({'url': url, 'allow_private': True}, {'/'}, threading.Event())
            collector.fetch('/')
            return collector.evidence[0]

    def test_complete_small_range_is_complete(self):
        row = self.collect(['bytes 0-4/5'])
        self.assertFalse(row['truncated'])
        self.assertEqual(row['content_range'], {'start': 0, 'end': 4, 'total': 5})
        self.assertEqual(row['bytes_read'], 5)

    def test_incomplete_unknown_and_malformed_ranges_remain_partial(self):
        for ranges in (['bytes 0-4/10'], ['bytes 1-5/6'], ['bytes 0-4/*'], [],
                       ['bytes 4-0/5'], ['bytes 0-5/5'], ['bytes 0-3/4'],
                       ['bytes 0-4/5', 'bytes 0-4/5'], ['bytes 0-4/' + '9' * 5000],
                       ['secret=DO_NOT_EXPORT']):
            with self.subTest(ranges=[r[:40] for r in ranges]):
                row = self.collect(ranges)
                self.assertTrue(row['truncated'])
                self.assertNotIn('DO_NOT_EXPORT', str(row))

    def test_premature_disconnect_remains_partial(self):
        row = self.collect(['bytes 0-4/5'], length=9)
        self.assertTrue(row['truncated'])

    def test_body_cap_still_applies_to_full_range(self):
        with patch.object(w, 'MAX_BODY', 4):
            row = self.collect(['bytes 0-4/5'])
        self.assertTrue(row['truncated'])
        self.assertEqual(row['bytes_read'], 4)

    def test_gateway_adapts_only_complete_range_and_preserves_original_evidence(self):
        from urllib.parse import urlsplit
        for cap, expected in ((65536, 200), (16, 206)):
            with self.subTest(cap=cap), fixture(ranged=True) as (url, _), patch.object(w, 'MAX_BODY', cap):
                collector = w.Collector({'url': url, 'allow_private': True}, {'/.git/config'}, threading.Event())
                server, base = w.gateway(collector)
                try:
                    parts = urlsplit(base)
                    connection = http.client.HTTPConnection(parts.hostname, parts.port, timeout=5)
                    connection.request('GET', parts.path + '/.git/config')
                    response = connection.getresponse()
                    response.read()
                    self.assertEqual(response.status, expected)
                    self.assertEqual(collector.evidence[0]['status'], 206)
                    self.assertEqual(collector.evidence[0]['nuclei_status'], expected)
                    connection.close()
                finally:
                    server.shutdown()
                    server.server_close()


class BundleSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'source'
        self.source.mkdir()
        self.app = self.root / 'app'
        self.target = self.app / 'work/repositories/crapi-stable'

    def test_repeat_copy_keeps_extra_files_and_excludes_git(self):
        (self.source / 'code.py').write_text('demo')
        for name in ('.git', '.github'):
            (self.source / name).mkdir()
            (self.source / name / 'metadata').write_text('excluded')
        first = b.bundle(self.source, self.app)
        (self.target / 'local-note.txt').write_text('user change')
        second = b.bundle(self.source, self.app)
        self.assertEqual(first['copied'], 1)
        self.assertEqual(second['copied'], 0)
        self.assertEqual(first['inventory_sha256'], second['inventory_sha256'])
        self.assertEqual((self.target / 'local-note.txt').read_text(), 'user change')
        self.assertFalse((self.target / '.git').exists())
        self.assertFalse((self.target / '.github').exists())

    def test_conflict_stops_before_copying_any_file(self):
        (self.source / 'a-new.py').write_text('new')
        (self.source / 'z-existing.py').write_text('upstream')
        self.target.mkdir(parents=True)
        (self.target / 'z-existing.py').write_text('user modification')
        with self.assertRaises(ValueError):
            b.bundle(self.source, self.app)
        self.assertFalse((self.target / 'a-new.py').exists())
        self.assertEqual((self.target / 'z-existing.py').read_text(), 'user modification')

    def test_overlapping_source_destination_is_rejected(self):
        with self.assertRaises(ValueError):
            b.bundle(self.root, self.app)

    def test_reparse_component_is_rejected(self):
        fake = SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT)
        with patch.object(Path, 'lstat', return_value=fake), self.assertRaises(ValueError):
            b.checked_path(self.target, self.app)

    def test_explicit_missing_crapi_source_never_falls_back(self):
        missing = self.root / 'missing'
        with patch.dict(scanners.os.environ, {'ZANJIR_CRAPI_ROOT': str(missing)}):
            self.assertEqual(scanners.crapi_root(), missing)
            with self.assertRaises(ValueError):
                scanners.target_root('crapi-full')

    def test_bundled_source_stays_preferred_without_override(self):
        self.target.mkdir(parents=True)
        with patch.object(scanners, 'ROOT', self.app), patch.dict(scanners.os.environ, {'ZANJIR_CRAPI_ROOT': ''}):
            self.assertEqual(scanners.crapi_root(), self.target)


class UserChangeRegressionTests(unittest.TestCase):
    def test_web_controls_are_actually_served_as_javascript(self):
        with listener(Handler) as url:
            connection = http.client.HTTPConnection('127.0.0.1', int(url.rsplit(':', 1)[1]), timeout=5)
            connection.request('GET', '/web-pilot.js')
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            self.assertIn('javascript', response.getheader('Content-Type'))
            self.assertEqual(response.read(), (w.ROOT / 'dist/web-pilot.js').read_bytes())
            connection.close()

    def test_detailed_markdown_preserves_all_stage_types_and_cutoff(self):
        examples = {
            'code': {'tool': 'Semgrep', 'rule_id': 'demo', 'path': 'file.py', 'line': 2, 'message': 'bad|pattern\nnext'},
            'dependencies': {'priority': 'P1', 'package': {'name': 'demo-package', 'version': '1.0'}, 'advisory_id': 'GHSA-demo', 'severity': 'HIGH'},
            'web': {'tool': 'Nuclei', 'severity': 'HIGH', 'path': '/.env', 'title': 'Exposed environment'},
            'images': {'package': 'demo-image-package', 'version': '1.0', 'advisory_id': 'CVE-demo', 'severity': 'HIGH'},
        }
        stages = [{'kind': kind, 'target': 'demo', 'state': 'completed', 'count': 41 if kind == 'code' else 1,
                   'report_id': kind + '-evidence', 'report': {'findings': [dict(value, raw='SECRET_NOT_FOR_EXPORT')] * (41 if kind == 'code' else 1)}} for kind, value in examples.items()]
        report = {'id': 'control', 'state': 'completed', 'created_at': '2026-09-15', 'limits': 'Synthetic fixture', 'stages': stages}
        result = pipeline.markdown(report)
        self.assertEqual(result.count('file.py:2'), 40)
        self.assertIn('yana 1 ta', result)
        self.assertIn('bad\\|pattern next', result)
        for expected in ('demo-package', '/.env', 'demo-image-package', 'code-evidence'):
            self.assertIn(expected, result)
        self.assertNotIn('SECRET_NOT_FOR_EXPORT', result)


if __name__ == '__main__':
    unittest.main()
