"""Impact-measuring target: counts requests, TCP connections, concurrency and spacing.
Modes: normal | overloaded (503 + Retry-After after 4 requests) | slow (1.5 s per answer after 3).
Usage: impact_target.py <port> <mode> <stats.json>"""
import json, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
PORT, MODE, OUT = int(sys.argv[1]), sys.argv[2], sys.argv[3]
lock = threading.Lock()
stats = {'requests': 0, 'connections': 0, 'active': 0, 'peak': 0, 'times': [], 'bytes_out': 0, 'statuses': {}}
PAGES = {'/': b'<html><body><a href="/a/">a</a><a href="/b">b</a><a href="/c">c</a></body></html>',
         '/a/': b'<html><body><a href="/a/x">x</a></body></html>', '/b': b'<html>b</html>', '/c': b'<html>c</html>',
         '/a/x': b'<html>x</html>'}
def dump():
    with lock:
        t = stats['times']; gaps = [round(b - a, 3) for a, b in zip(t, t[1:])]
        out = {k: v for k, v in stats.items() if k != 'times'}
        out['min_gap_s'] = min(gaps) if gaps else None
        out['duration_s'] = round(t[-1] - t[0], 2) if t else 0
        json.dump(out, open(OUT, 'w'))
class H(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def log_message(self, *a): pass
    def setup(self):
        super().setup()
        with lock: stats['connections'] += 1
    def do_GET(self):
        with lock:
            stats['requests'] += 1; stats['active'] += 1; stats['peak'] = max(stats['peak'], stats['active'])
            stats['times'].append(time.monotonic()); n = stats['requests']
        try:
            status, extra = 200, {}
            if MODE == 'overloaded' and n > 4:
                status, extra = 503, {'Retry-After': '3'}
            if MODE == 'slow' and n > 3:
                time.sleep(1.5)
            path = self.path.split('?')[0]
            body = PAGES.get(path, b'not found') if status == 200 else b'busy'
            if status == 200 and path not in PAGES: status = 404
            self.send_response(status)
            for k, v in extra.items(): self.send_header(k, v)
            self.send_header('Content-Type', 'text/html'); self.send_header('Content-Length', str(len(body)))
            self.end_headers(); self.wfile.write(body)
            with lock:
                stats['bytes_out'] += len(body); stats['statuses'][str(status)] = stats['statuses'].get(str(status), 0) + 1
        finally:
            with lock: stats['active'] -= 1
            dump()
_server = ThreadingHTTPServer(('127.0.0.1', PORT), H)
print('ready', flush=True)
_server.serve_forever()
