"""How much a web scan costs the target -- and that it backs off when asked.

Measured against a counting target before this change: 17 requests opened 17
TCP connections, a 503 with Retry-After was followed by 13 more requests, and a
server that slowed down was not given more room. These tests pin the fixes.
"""
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler

from zanjir import webscan as w
from zanjir.httptest import listener


def target(behaviour):
    """HTTP/1.1 handler; behaviour(n) -> (status, headers, delay) for request n."""
    seen = {'requests': 0, 'connections': 0}
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def log_message(self, *_):
            pass

        def setup(self):
            super().setup()
            with lock:
                seen['connections'] += 1

        def do_GET(self):
            with lock:
                seen['requests'] += 1
                n = seen['requests']
            status, headers, delay = behaviour(n)
            time.sleep(delay)
            body = b'<html>ok</html>'
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    return Handler, seen


class ImpactTests(unittest.TestCase):
    def collector(self, url, paths):
        profile = {'id': 't', 'url': url, 'owner': 'test', 'authorized_at': w.now(), 'allow_private': True,
                   'rate_delay': 0.5}
        collector = w.Collector(profile, set(paths), threading.Event())
        collector.delay = 0.01            # keep the suite fast; the policy under test is relative
        self.addCleanup(collector.close)
        return collector

    def test_sequential_requests_reuse_one_connection(self):
        handler, seen = target(lambda n: (200, {}, 0))
        with listener(handler) as url:
            collector = self.collector(url, ['/a', '/b', '/c', '/d'])
            for path in ('/a', '/b', '/c', '/d'):
                collector.fetch(path)
        self.assertEqual(seen['requests'], 4)
        self.assertEqual(seen['connections'], 1)
        self.assertEqual(collector.impact()['connections'], 1)

    def test_retry_after_is_obeyed_and_a_second_refusal_stops_the_scan(self):
        handler, seen = target(lambda n: (503, {'Retry-After': '1'}, 0) if n > 1 else (200, {}, 0))
        with listener(handler) as url:
            collector = self.collector(url, ['/a', '/b', '/c', '/d', '/e'])
            collector.fetch('/a')
            started = time.monotonic()
            collector.fetch('/b')                         # first 503: wait Retry-After, slow down
            collector.fetch('/c')                         # second 503: stop
            waited = time.monotonic() - started
            with self.assertRaises(ValueError):
                collector.fetch('/d')                     # nothing more is sent
        self.assertGreaterEqual(waited, 0.9)
        self.assertEqual(seen['requests'], 3)
        self.assertEqual(collector.stopped, 'server_busy')

    def test_429_without_retry_after_stops_at_once(self):
        handler, seen = target(lambda n: (429, {}, 0))
        with listener(handler) as url:
            collector = self.collector(url, ['/a', '/b'])
            collector.fetch('/a')
            with self.assertRaises(ValueError):
                collector.fetch('/b')
        self.assertEqual(seen['requests'], 1)
        self.assertEqual(collector.stopped, 'rate_limited')

    def test_a_long_retry_after_is_not_waited_out(self):
        self.assertIsNone(w.retry_after('3600'))
        self.assertEqual(w.retry_after('2'), 2.0)
        self.assertIsNone(w.retry_after('not a date'))

    def test_a_target_that_slows_down_gets_more_room_once_per_level(self):
        handler, _ = target(lambda n: (200, {}, 1.2 if n > 3 else 0))
        with listener(handler) as url:
            collector = self.collector(url, [f'/p{i}' for i in range(6)])
            for i in range(6):
                collector.fetch(f'/p{i}')
        self.assertEqual([s['reason'] for s in collector.slowdowns], ['slow_response'])
        self.assertGreaterEqual(collector.delay, 1.0)

    def test_repeated_connection_failures_open_the_circuit(self):
        profile = {'id': 't', 'url': 'http://127.0.0.1:9', 'owner': 'test', 'authorized_at': w.now(),
                   'allow_private': True}
        collector = w.Collector(profile, {'/a', '/b', '/c', '/d'}, threading.Event())
        collector.delay = 0.01
        for path in ('/a', '/b', '/c'):
            with self.assertRaises(OSError):
                collector.fetch(path)
            collector.next_request = 0
        self.assertEqual(collector.stopped, 'target_unreachable')
        with self.assertRaises(ValueError):
            collector.fetch('/d')

    def test_only_get_and_bounded_body_are_ever_used(self):
        impact = self.collector('http://127.0.0.1:9', []).impact()
        self.assertEqual(impact['method'], 'GET')
        self.assertEqual(impact['max_parallel_requests'], 1)
        self.assertEqual(impact['max_body_bytes'], w.MAX_BODY)


if __name__ == '__main__':
    unittest.main()
