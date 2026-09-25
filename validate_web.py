"""Real Nuclei engine against synthetic vulnerable/fixed loopback fixtures."""
import argparse
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
from unittest.mock import patch
from zanjir import webscan, repo_store

DEMO_SECRET = 'ZANJIR_SYNTHETIC_SECRET_NOT_REAL_927316'
DATA = {
    '/': ('text/html', '<html><h1>Index of /</h1></html>'),
    '/.git/config': ('text/plain', '[core]\nrepositoryformatversion = 0\n[remote "origin"]\nurl = https://demo:' + DEMO_SECRET + '@example.invalid/demo.git\n'),
    '/.env': ('text/plain', 'APP_ENV=demo\nDB_PASSWORD=' + DEMO_SECRET + '\nDB_HOST=example.invalid\n'),
    '/backup.sql': ('text/plain', '-- MySQL dump\nCREATE TABLE demo (id int);\n'),
    '/docker-compose.yml': ('text/plain', 'services:\n  demo:\n    image: example.invalid/demo:fixture\n'),
    '/openapi.json': ('application/json', '{"openapi":"3.0.0","paths":{}}'),
}


@contextmanager
def fixture(fixed=False, fallback=False, redirect=False, ranged=False):
    calls = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            calls.append(self.path)
            if redirect and self.path == '/':
                self.send_response(302)
                self.send_header('Location', 'http://169.254.169.254/latest/meta-data/')
                self.send_header('Content-Length', '0')
                self.end_headers()
                return
            if fallback:
                status, mime, body = 200, 'text/plain', DATA['/.env'][1]
            elif not fixed and self.path in DATA:
                mime, body = DATA[self.path]
                status = 200
            elif self.path == '/':
                status, mime, body = 200, 'text/html', '<html><h1>Fixed fixture</h1></html>'
            else:
                status, mime, body = 404, 'text/plain', 'not found'
            raw = body.encode()
            full_range = ranged and status == 200
            if full_range:
                status = 206
            self.send_response(status)
            if full_range:
                self.send_header('Content-Range', f'bytes 0-{len(raw)-1}/{len(raw)}')
            self.send_header('Content-Type', mime)
            self.send_header('Content-Length', str(len(raw)))
            if fixed:
                self.send_header('X-Content-Type-Options', 'nosniff')
                self.send_header('Content-Security-Policy', "default-src 'self'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(raw)

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{server.server_port}', calls
    finally:
        server.shutdown()
        server.server_close()


def main():
    root = webscan.ROOT / 'validation-runs/web-control'
    created_at = webscan.now()
    repo_store.write_json(root / 'result.json', {'created_at': created_at, 'passed': False,
                          'state': 'not_finished', 'results': [], 'scope': 'Synthetic localhost control'})
    results = []
    for mode in ('vulnerable', 'fixed', 'soft404', 'full-range'):
        print('Real Nuclei control:', mode, flush=True)
        with fixture(fixed=mode == 'fixed', fallback=mode == 'soft404', ranged=mode == 'full-range') as (url, calls):
            profile = {'id': 'control-web', 'url': url, 'name': 'Synthetic control', 'owner': 'Zanjir local validation',
                       'allow_private': True, 'authorized_at': webscan.now()}
            with patch.object(webscan, 'target_for', return_value=profile), patch.object(webscan, 'RUNS', root):
                report = webscan.start('control-web', background=False)
            assert report['state'] == ('partial' if mode == 'soft404' else 'completed'), (mode, report)
            assert DEMO_SECRET not in json.dumps(report), 'Secret leaked into report'
            assert report['requests'] == len(calls), 'Unexpected request count'
            rules = {f['rule_id'] for f in report['findings'] if f['tool'] == 'Nuclei'}
            if mode in ('vulnerable', 'full-range'):
                assert rules == {'git-config', 'dir-listing', 'zanjir-env', 'zanjir-compose', 'zanjir-openapi', 'zanjir-sql-backup'}, rules
            else:
                assert not rules, (mode, rules)
            if mode == 'soft404':
                assert any(f['rule_id'] == 'ambiguous-fallback' for f in report['findings'])
            results.append({'mode': mode, 'id': report['id'], 'state': report['state'], 'requests': report['requests'],
                            'nuclei_matches': len(rules), 'total_findings': report['count'], 'secret_redacted': True})
    summary = {'created_at': created_at, 'passed': True, 'state': 'completed', 'engine': 'Nuclei 3.11.1', 'scope': 'Synthetic localhost; not a real company assessment', 'results': results}
    repo_store.write_json(root / 'result.json', summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    argparse.ArgumentParser(description='Nuclei’ning haqiqiy ishlashini sun’iy nazorat holatida tekshirish').parse_args()
    main()
