"""Shared ephemeral-loopback-server helper used by the test suite (and by
webscan's own in-process gateway). Not demo-specific: this is generic test
infrastructure for driving app.py's Handler and other HTTP endpoints locally.
"""
from __future__ import annotations

import contextlib
import threading
from http.server import ThreadingHTTPServer


@contextlib.contextmanager
def listener(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.02), daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
