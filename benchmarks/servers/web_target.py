"""Benchmark web target: `vuln` exposes files, headers and errors a scan must report; `fixed` must yield
only the plain-HTTP finding. Usage: web_target.py <port> vuln|fixed"""
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
FIXED = sys.argv[2] == 'fixed'
PAGES = {
 '/': ('text/html', '<html><body><a href="/about">about</a><a href="/err?x=1">e</a><a href="/files/">files</a></body></html>'),
 '/about': ('text/html', '<html><body>about</body></html>'),
 '/err': ('text/html', '<html><body>Traceback (most recent call last):\n  File "/app/views.py", line 12, in index\nZeroDivisionError: division by zero</body></html>'),
 '/files/': ('text/html', '<html><head><title>Index of /files</title></head><body><h1>Index of /files</h1><a href="../">../</a><a href="a.txt">a.txt</a></body></html>'),
 '/.env': ('text/plain', 'DB_PASSWORD=Sup3rS3cret\nAPI_KEY=abcd1234\n'),
 '/backup.sql': ('text/plain', 'CREATE TABLE users (id int, pw text);\nINSERT INTO users VALUES (1,\'x\');\n'),
 '/docker-compose.yml': ('text/plain', 'services:\n  db:\n    image: postgres\n    environment:\n      POSTGRES_PASSWORD: example\n'),
 '/openapi.json': ('application/json', '{"openapi":"3.0.0","info":{"title":"t","version":"1"},"paths":{"/users":{}}}'),
 '/.git/config': ('text/plain', '[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = https://github.com/x/y.git\n'),
}
class H(BaseHTTPRequestHandler):
    server_version = 'nginx/1.14.0' if not FIXED else 'web'
    sys_version = ''
    def log_message(self,*a): pass
    def do_GET(self):
        path = self.path.split('?')[0]
        if FIXED and path not in ('/', '/about'):
            body, mime, status = b'not found', 'text/plain', 404
        elif path in PAGES:
            mime, text = PAGES[path]; body, status = text.encode(), (500 if path == '/err' else 200)
        else:
            body, mime, status = b'not found', 'text/plain', 404
        self.send_response(status)
        self.send_header('Content-Type', mime); self.send_header('Content-Length', str(len(body)))
        origin = self.headers.get('Origin')
        if FIXED:
            self.send_header('X-Content-Type-Options','nosniff'); self.send_header('Content-Security-Policy',"default-src 'self'; frame-ancestors 'none'")
            self.send_header('Set-Cookie','sid=abc; Secure; HttpOnly; SameSite=Lax')
        else:
            self.send_header('Set-Cookie','sid=abc; Path=/')
            self.send_header('X-Powered-By','PHP/5.6.40')
            if origin:
                self.send_header('Access-Control-Allow-Origin', origin); self.send_header('Access-Control-Allow-Credentials','true')
        self.end_headers(); self.wfile.write(body)
_server = ThreadingHTTPServer(('127.0.0.1', int(sys.argv[1])), H)
print('ready', flush=True)
_server.serve_forever()
