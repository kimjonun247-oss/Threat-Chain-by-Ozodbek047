import hashlib
import http.client
from http.server import BaseHTTPRequestHandler
import json
from pathlib import Path
import socket
import ssl
import tempfile
import threading
import unittest
from unittest.mock import patch

from app import Handler
from validate_web import fixture, DEMO_SECRET
from zanjir import webscan as w, pipeline as p
from zanjir.httptest import listener
from isolation import isolate_triage


class WebBoundaryTests(unittest.TestCase):
    def setUp(self):
        isolate_triage(self)

    def profile(self, url, private=True):
        return {'id': 'test-web', 'url': url, 'owner': 'Test operator', 'authorized_at': w.now(), 'allow_private': private}

    def test_refused_target_keeps_the_reason_in_the_report(self):
        # A link-local metadata address is refused on purpose; the report used to
        # say only "did not finish", indistinguishable from a crash.
        with tempfile.TemporaryDirectory() as temp, \
             patch.object(w, 'target_for', return_value=self.profile('http://169.254.169.254', private=False)), \
             patch.object(w, 'RUNS', Path(temp)):
            report = w.start('test-web', background=False)
        self.assertEqual(report['state'], 'failed')
        self.assertIn('ruxsat doirasiga mos emas', report['message'])
        self.assertEqual(report['requests'] if 'requests' in report else 0, 0)

    def test_url_rejects_ambiguous_or_credentialed_scope(self):
        invalid = ['file:///etc/passwd', 'http://user:pass@example.com', 'http://example.com/?token=secret',
                   'http://example.com/#token', 'http://example.com/%2e%2e', 'http://example.com/../admin',
                   'http://example.com:99999', 'http://example.com//admin', 'http://*.example.com',
                   'http://example.com\\@127.0.0.1', 'http://example.com./']
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError):
                w.canonical_url(value)
        self.assertEqual(w.canonical_url('https://EXAMPLE.com:443/api/'), 'https://example.com/api')

    def test_registration_preserves_scope_and_does_not_overwrite(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(w, 'PROFILES', Path(temp)):
            row = w.register('test-web', 'https://example.com/api/', 'Owner')
            self.assertEqual(row['url'], 'https://example.com/api')
            self.assertFalse(row['allow_private'])
            with self.assertRaises(FileExistsError):
                w.register('test-web', 'https://other.example', 'Owner')
            with self.assertRaises(ValueError):
                w.register('pilot-other', 'https://example.com', 'Owner')

    def test_public_scope_rejects_private_or_mixed_dns(self):
        answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('8.8.8.8', 443)),
                   (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 443))]
        with patch('socket.getaddrinfo', return_value=answers), self.assertRaises(ValueError):
            w.resolve(self.profile('https://example.com', private=False))

    def test_metadata_link_local_rejected_even_for_private_scope(self):
        with self.assertRaises(ValueError):
            w.resolve(self.profile('http://169.254.169.254'))

    def test_dns_is_pinned_and_get_response_is_bounded(self):
        with fixture() as (url, calls):
            collector = w.Collector(self.profile(url), {'/'}, threading.Event())
            # create_connection resolves literal IPs too; only the pinned IP may reach it.
            real = socket.getaddrinfo
            with patch('socket.getaddrinfo', side_effect=lambda host, *a, **kw: real(host, *a, **kw) if host == '127.0.0.1' else self.fail('unpinned DNS')):
                status, _, body = collector.fetch('/')
                self.assertEqual(status, 200)
                self.assertLessEqual(len(body), w.MAX_BODY)
                collector.fetch('/')
            self.assertEqual(calls, ['/'])
            self.assertEqual(collector.requests, 1)

    def test_redirect_is_not_followed(self):
        with fixture(redirect=True) as (url, calls):
            collector = w.Collector(self.profile(url), {'/'}, threading.Event())
            self.assertEqual(collector.fetch('/')[0], 302)
            self.assertEqual(calls, ['/'])

    def test_scope_gateway_rejects_unknown_paths_and_writes(self):
        with fixture() as (url, calls):
            collector = w.Collector(self.profile(url), {'/'}, threading.Event())
            server, base = w.gateway(collector)
            try:
                from urllib.parse import urlsplit
                parts = urlsplit(base)
                c = http.client.HTTPConnection(parts.hostname, parts.port, timeout=5)
                c.request('GET', parts.path + '/outside')
                r = c.getresponse(); r.read()
                self.assertEqual(r.status, 502)
                c.request('POST', parts.path)
                r = c.getresponse(); r.read()
                self.assertEqual(r.status, 501)
                c.close()
                self.assertEqual(calls, [])
            finally:
                server.shutdown(); server.server_close()

    def test_cancellation_sends_no_request(self):
        with fixture() as (url, calls):
            event = threading.Event(); event.set()
            collector = w.Collector(self.profile(url), {'/'}, event)
            with self.assertRaises(ValueError):
                collector.fetch('/')
            self.assertEqual(calls, [])

    def test_tls_uses_default_verifying_context(self):
        with patch.object(w, 'resolve', return_value=('8.8.8.8',443)):
            collector = w.Collector(self.profile('https://example.com', False), {'/'}, threading.Event())
            self.assertTrue(collector.context.check_hostname)
            self.assertEqual(collector.context.verify_mode, ssl.CERT_REQUIRED)

    def test_templates_are_pinned_get_only(self):
        templates, paths, digest = w.rule_profile()
        self.assertEqual(len(templates), 6)
        self.assertEqual(len(paths), 11)
        self.assertEqual(len(digest), 64)
        with patch.object(w, 'RULES', Path(tempfile.gettempdir())), self.assertRaises(OSError):
            w.rule_profile()

    def test_raw_extractor_secrets_never_enter_normalized_finding(self):
        with fixture() as (url, _):
            collector = w.Collector(self.profile(url), {'/.git/config'}, threading.Event())
            collector.fetch('/.git/config')
            templates, _, _ = w.rule_profile()
            raw = json.dumps({'template-id':'git-config','matched-at':'http://127.0.0.1:1234/token/.git/config',
                              'extracted-results':[DEMO_SECRET], 'request':DEMO_SECRET,'response':DEMO_SECRET})
            result, _ = w.normalize_nuclei(raw, 'http://127.0.0.1:1234/token', templates, collector, 'different')
            self.assertEqual(len(result), 1)
            self.assertNotIn(DEMO_SECRET, json.dumps(result))
            with self.assertRaises(ValueError):
                w.normalize_nuclei(raw.replace('127.0.0.1:1234', 'external.invalid'), 'http://127.0.0.1:1234/token', templates, collector, '')

    def test_soft404_match_is_suppressed(self):
        with fixture(fallback=True) as (url, _):
            collector = w.Collector(self.profile(url), {'/.env'}, threading.Event())
            _, _, body = collector.fetch('/.env')
            templates, _, _ = w.rule_profile()
            raw = json.dumps({'template-id':'zanjir-env','matched-at':'http://127.0.0.1:1234/token/.env'})
            result, suppressed = w.normalize_nuclei(raw, 'http://127.0.0.1:1234/token', templates, collector, hashlib.sha256(body).hexdigest())
            self.assertEqual([f['rule_id'] for f in result], ['ambiguous-fallback'])
            self.assertNotIn(DEMO_SECRET, json.dumps(result))
            self.assertEqual(suppressed, 1)

    def test_oversized_body_is_not_silently_complete(self):
        with fixture() as (url, _), patch.object(w, 'MAX_BODY', 16):
            collector=w.Collector(self.profile(url),{'/.env'},threading.Event())
            _,_,body=collector.fetch('/.env')
            self.assertEqual(len(body),16)
            self.assertTrue(collector.evidence[0]['truncated'])

    def test_failed_web_does_not_leave_lock_or_claim_clean(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(w, 'RUNS', Path(temp)), patch.object(w, 'resolve', side_effect=ValueError('DNS denied')):
            report = w.start('pilot-crapi', background=False)
            self.assertEqual(report['state'], 'failed')
            self.assertFalse(w.LOCK.locked())
            self.assertEqual(w.CANCEL, {})

    def test_http_rejects_url_injection_offline_scan_and_foreign_origin(self):
        with listener(Handler) as server:
            port = int(server.rsplit(':',1)[1])
            c = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
            for path, payload in [('/api/web/scan', {'target':'https://external.invalid','online':True}),
                                  ('/api/web/scan', {'target':'pilot-crapi','online':False}),
                                  ('/api/web/scan', {'target':'pilot-crapi','online':True,'command':'bad'}),
                                  ('/api/assessments/scan', {'target':'','web_target':'pilot-crapi','image_target':'','repository_target':'','online':False})]:
                c.request('POST', path, json.dumps(payload), {'Content-Type':'application/json'})
                r=c.getresponse();r.read();self.assertEqual(r.status,400)
            c.request('POST','/api/web/scan',json.dumps({'target':'pilot-crapi','online':True}),{'Origin':'https://external.invalid','Content-Type':'application/json'})
            r=c.getresponse();r.read();self.assertEqual(r.status,403)
            c.close()


class PipelineTests(unittest.TestCase):
    def setUp(self):
        isolate_triage(self)

    def test_report_read_retries_transient_sharing_conflict(self):
        from zanjir import repo_store
        with patch.object(Path,'read_text',side_effect=[PermissionError('sharing'),'{"state":"completed"}']):
            self.assertEqual(repo_store.read_json(Path('report.json')),{'state':'completed'})

    def test_report_replace_retries_short_windows_read_conflict(self):
        from zanjir import repo_store
        real=repo_store.os.replace
        attempts=[]
        def replace(src,dest):
            attempts.append(1)
            if len(attempts)==1:raise PermissionError('sharing conflict')
            return real(src,dest)
        with tempfile.TemporaryDirectory() as temp,patch.object(repo_store.os,'replace',side_effect=replace):
            path=Path(temp)/'report.json'
            repo_store.write_json(path,{'state':'completed'})
            self.assertEqual(json.loads(path.read_text()),{'state':'completed'})
            self.assertEqual(len(attempts),2)
            self.assertEqual(list(Path(temp).glob('*.tmp')),[])

    def test_partial_child_is_not_reported_as_completed(self):
        child={'id':'20260914T120000-1234abcd','state':'partial','count':1,'findings':[]}
        with tempfile.TemporaryDirectory() as temp, patch.object(p,'RUNS',Path(temp)), patch.object(w,'start',return_value={'id':child['id']}), patch.object(w,'read',return_value=child):
            report=p.start({'target':'','web_target':'pilot-crapi','image_target':'','repository_target':'','online':True},background=False)
            self.assertEqual(report['state'],'partial')
            self.assertEqual([s['kind'] for s in report['stages'] if s['state']=='not_selected'],['code','repository','dependencies','iac','images'])
            self.assertFalse(p.LOCK.locked())
            self.assertEqual(p.CANCEL,{})
            self.assertIn('report_sha256',next(s for s in report['stages'] if s['kind']=='web'))

    def test_start_failure_releases_lock(self):
        with patch.object(p.repo_store,'write_json',side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                p.start({'target':'','web_target':'pilot-crapi','image_target':'','repository_target':'','online':True})
        self.assertFalse(p.LOCK.locked())

    def test_cancel_during_passive_stages_never_starts_the_web_scan(self):
        # Passive stages now run side by side, but the web stage -- the only one
        # that sends requests to someone's system -- still runs last and alone.
        # A cancel raised while the passive stages run must mean that not a
        # single request reaches the target.
        child={'id':'20260914T120000-1234abcd','state':'completed','count':0,'findings':[]}
        def stop_and_return(*args):
            next(iter(p.CANCEL.values())).set()
            return child
        with tempfile.TemporaryDirectory() as temp, patch.object(p,'RUNS',Path(temp)), \
             patch.object(p.images,'targets',return_value=[{'id':'test-image'}]), \
             patch.object(p.images,'start',return_value={'id':child['id']}), \
             patch.object(p.images,'read',side_effect=stop_and_return), \
             patch.object(w,'start') as web_start:
            report=p.start({'target':'','web_target':'pilot-crapi','image_target':'test-image','repository_target':'','online':True},background=False)
            self.assertEqual(report['state'],'cancelled')
            web_start.assert_not_called()
            self.assertEqual(next(s for s in report['stages'] if s['kind']=='web')['state'],'cancelled')

    def test_passive_stages_run_at_the_same_time(self):
        # Measured on crAPI: code is CPU-bound, the image stage mostly waits on
        # Docker Hub. Running them together is the point of the change.
        import threading
        inside=set();overlap=[];guard=threading.Lock()
        def slow(kind):
            def start(target):
                with guard:
                    inside.add(kind)
                    if len(inside)>1:overlap.append(tuple(sorted(inside)))
                threading.Event().wait(0.3)
                with guard:inside.discard(kind)
                return {'id':'20260914T120000-1234abcd'}
            return start
        done={'id':'20260914T120000-1234abcd','state':'completed','count':0,'findings':[]}
        with tempfile.TemporaryDirectory() as temp, patch.object(p,'RUNS',Path(temp)), \
             patch.object(p.scanners,'target_root',return_value=Path(temp)), \
             patch.object(p.scanners,'start',side_effect=slow('code')), patch.object(p.scanners,'read_report',return_value=done), \
             patch.object(p.dependencies,'start',side_effect=slow('dependencies')), patch.object(p.dependencies,'read',return_value=done), \
             patch.object(p.images,'targets',return_value=[{'id':'test-image'}]), \
             patch.object(p.images,'start',side_effect=slow('images')), patch.object(p.images,'read',return_value=done):
            report=p.start({'target':'x','web_target':'','image_target':'test-image','repository_target':'','online':True},background=False)
        self.assertEqual(report['state'],'completed')
        self.assertTrue(overlap,'passiv bosqichlar ketma-ket bajarildi')

    def test_stage_rows_keep_their_order_whatever_order_they_finish_in(self):
        child={'id':'20260914T120000-1234abcd','state':'completed','count':0,'findings':[]}
        with tempfile.TemporaryDirectory() as temp, patch.object(p,'RUNS',Path(temp)), \
             patch.object(w,'start',return_value={'id':child['id']}), patch.object(w,'read',return_value=child), \
             patch.object(p.images,'targets',return_value=[{'id':'test-image'}]), \
             patch.object(p.images,'start',return_value={'id':child['id']}), patch.object(p.images,'read',return_value=child):
            report=p.start({'target':'','web_target':'pilot-crapi','image_target':'test-image','repository_target':'','online':True},background=False)
        self.assertEqual([s['kind'] for s in report['stages']],['code','repository','dependencies','iac','web','images'])

    def test_web_starts_only_after_every_passive_stage_has_finished(self):
        order=[]
        child={'id':'20260914T120000-1234abcd','state':'completed','count':0,'findings':[]}
        def image_read(*args):
            order.append('images-finished');return child
        def web_start(*args):
            order.append('web-started');return {'id':child['id']}
        with tempfile.TemporaryDirectory() as temp, patch.object(p,'RUNS',Path(temp)), \
             patch.object(w,'start',side_effect=web_start), patch.object(w,'read',return_value=child), \
             patch.object(p.images,'targets',return_value=[{'id':'test-image'}]), \
             patch.object(p.images,'start',return_value={'id':child['id']}), patch.object(p.images,'read',side_effect=image_read):
            p.start({'target':'','web_target':'pilot-crapi','image_target':'test-image','repository_target':'','online':True},background=False)
        self.assertEqual(order,['images-finished','web-started'])

    def test_chain_findings_correlate_code_and_repository_stages(self):
        # The gitleaks match sits under the "web" service's own build context,
        # and that service has a non-loopback port -- exactly the two
        # independently-unremarkable facts SX-001 is meant to combine.
        code_child = {'id':'20260914T120000-aaaaaaaa','state':'completed','count':1,
                      'findings':[{'tool':'gitleaks','rule_id':'generic-api-key','path':'services/web/config.py','line':3,'secret_value':'hidden'}]}
        repo_child = {'id':'20260914T120000-bbbbbbbb','summary':{'findings':0},'findings':[],
                      'services':[{'id':'web','build_context':'services/web','ports':[{'scope':'all_interfaces'}]}]}
        dep_child = {'id':'20260914T120000-dddddddd','state':'completed','count':0,'findings':[]}
        with tempfile.TemporaryDirectory() as temp, patch.object(p,'RUNS',Path(temp)), \
             patch.object(p.scanners,'target_root'), patch.object(p.repo_store,'profile_for'), \
             patch.object(p.scanners,'start',return_value={'id':code_child['id']}), \
             patch.object(p.scanners,'read_report',return_value=code_child), \
             patch.object(p.dependencies,'start',return_value={'id':dep_child['id']}), \
             patch.object(p.dependencies,'read',return_value=dep_child), \
             patch.object(p.repo_store,'scan_profile',return_value=repo_child):
            report=p.start({'target':'crapi-full','web_target':'','image_target':'','repository_target':'crapi','online':False},background=False)
            self.assertEqual(report['state'],'completed')
            self.assertEqual(len(report['chain_findings']),1)
            self.assertEqual(report['chain_findings'][0]['rule_id'],'SX-001')
            self.assertEqual(report['chain_findings'][0]['service_id'],'web')
            self.assertEqual(report['verification_summary']['total'],2)
            self.assertEqual(report['verification_summary']['manual_review_required'],2)

    def test_chain_findings_are_empty_when_repository_stage_not_selected(self):
        code_child = {'id':'20260914T120000-cccccccc','state':'completed','count':1,
                      'findings':[{'tool':'gitleaks','rule_id':'generic-api-key','path':'services/web/config.py','line':3,'secret_value':'hidden'}]}
        dep_child = {'id':'20260914T120000-eeeeeeee','state':'completed','count':0,'findings':[]}
        with tempfile.TemporaryDirectory() as temp, patch.object(p,'RUNS',Path(temp)), \
             patch.object(p.scanners,'target_root'), \
             patch.object(p.scanners,'start',return_value={'id':code_child['id']}), \
             patch.object(p.scanners,'read_report',return_value=code_child), \
             patch.object(p.dependencies,'start',return_value={'id':dep_child['id']}), \
             patch.object(p.dependencies,'read',return_value=dep_child):
            report=p.start({'target':'crapi-full','web_target':'','image_target':'','repository_target':'','online':False},background=False)
            self.assertEqual(report['chain_findings'],[])


class ActiveDastTests(unittest.TestCase):
    """New coverage beyond the fixed 6 Nuclei templates: bounded same-origin
    crawl, CORS reflection, cookie flags, fingerprint and error disclosure."""
    def setUp(self):
        isolate_triage(self)

    def profile(self, url):
        return {'id': 'test-web', 'url': url, 'owner': 'Test operator', 'authorized_at': w.now(), 'allow_private': True}

    def test_crawl_stays_same_origin_and_skips_non_navigable_links(self):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_GET(self):
                if self.path == '/':
                    body = (b'<html><a href="/about">About</a><a href="http://evil.example/x">Evil</a>'
                            b'<a href="javascript:alert(1)">JS</a><a href="/about#section">Anchor</a></html>')
                elif self.path == '/about':
                    body = b'<html>About page</html>'
                else:
                    self.send_response(404); self.send_header('Content-Length', '0'); self.end_headers(); return
                self.send_response(200)
                self.send_header('Content-Type', 'text/html')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        with listener(Handler) as url:
            collector = w.Collector(self.profile(url), {'/'}, threading.Event())
            pages = w.crawl(collector)
            self.assertEqual(pages, ['/', '/about'])
            self.assertNotIn('http://evil.example/x', collector.paths)

    def test_cors_reflected_origin_with_credentials_is_flagged(self):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_GET(self):
                self.send_response(200)
                origin = self.headers.get('Origin')
                if origin:
                    self.send_header('Access-Control-Allow-Origin', origin)
                    self.send_header('Access-Control-Allow-Credentials', 'true')
                self.send_header('Content-Length', '0')
                self.end_headers()
        with listener(Handler) as url:
            collector = w.Collector(self.profile(url), {'/'}, threading.Event())
            findings = w.cors_findings(collector)
            self.assertEqual([f['rule_id'] for f in findings], ['cors-reflected-origin-credentials'])
            self.assertEqual(findings[0]['cwe_ids'], ['CWE-942'])
            self.assertEqual(findings[0]['owasp_top10_2025'][0]['code'], 'A02')
            self.assertTrue(findings[0]['verified'])

    def test_cors_fixed_allowlist_is_not_flagged(self):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_GET(self):
                self.send_response(200)
                self.send_header('Access-Control-Allow-Origin', 'https://trusted.example')
                self.send_header('Content-Length', '0')
                self.end_headers()
        with listener(Handler) as url:
            collector = w.Collector(self.profile(url), {'/'}, threading.Event())
            self.assertEqual(w.cors_findings(collector), [])

    def test_cookie_missing_httponly_is_flagged_but_value_not_reused(self):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_GET(self):
                self.send_response(200)
                self.send_header('Set-Cookie', 'session=topsecretvalue; Path=/')
                self.send_header('Content-Length', '0')
                self.end_headers()
        with listener(Handler) as url:
            collector = w.Collector(self.profile(url), {'/'}, threading.Event())
            collector.fetch('/')
            findings = w.cookie_findings(collector, ['/'])
            self.assertEqual({f['rule_id'] for f in findings}, {'cookie-missing-httponly'})
            self.assertNotIn('topsecretvalue', json.dumps(findings))

    def test_fingerprint_header_is_surfaced(self):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_GET(self):
                self.send_response(200)
                self.send_header('X-Powered-By', 'PHP/7.2.0')
                self.send_header('Content-Length', '0')
                self.end_headers()
        with listener(Handler) as url:
            collector = w.Collector(self.profile(url), {'/'}, threading.Event())
            collector.fetch('/')
            findings = w.fingerprint_findings(collector, ['/'])
            self.assertTrue(all(f['rule_id'] == 'server-fingerprint' for f in findings))
            self.assertTrue(any('PHP/7.2.0' in f['evidence'] for f in findings))

    def test_default_python_server_header_is_also_treated_as_fingerprint(self):
        # http.server sends its own "Server: BaseHTTP/... Python/..." by default --
        # a real-world fingerprint leak too, not a test artifact to special-case away.
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-Length', '0')
                self.end_headers()
        with listener(Handler) as url:
            collector = w.Collector(self.profile(url), {'/'}, threading.Event())
            collector.fetch('/')
            findings = w.fingerprint_findings(collector, ['/'])
            self.assertEqual([f['rule_id'] for f in findings], ['server-fingerprint'])
            self.assertIn('Python', findings[0]['evidence'])

    def test_error_disclosure_flags_traceback_without_leaking_it(self):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_GET(self):
                body = b'Traceback (most recent call last):\n  File "app.py", line 1\nDB_PASSWORD=hunter2'
                self.send_response(500)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        with listener(Handler) as url:
            collector = w.Collector(self.profile(url), {'/'}, threading.Event())
            collector.fetch('/')
            findings = w.error_disclosure_findings(collector, ['/'])
            self.assertEqual([f['rule_id'] for f in findings], ['error-disclosure'])
            self.assertNotIn('hunter2', json.dumps(findings))
            self.assertEqual(findings[0]['owasp_top10_2025'][0]['code'], 'A10')

    def test_clean_response_produces_no_new_findings(self):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_GET(self):
                # send_response_only skips http.server's own default Server/Date
                # headers, so this response is genuinely fingerprint-free.
                self.send_response_only(200)
                self.send_header('Content-Length', '0')
                self.end_headers()
        with listener(Handler) as url:
            collector = w.Collector(self.profile(url), {'/'}, threading.Event())
            collector.fetch('/')
            self.assertEqual(w.cookie_findings(collector, ['/']), [])
            self.assertEqual(w.fingerprint_findings(collector, ['/']), [])
            self.assertEqual(w.error_disclosure_findings(collector, ['/']), [])


if __name__=='__main__':
    unittest.main()
