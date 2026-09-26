"""Local dashboard. Online advisory and image scans are explicit actions."""
from __future__ import annotations

import argparse
import datetime
import gzip
import hashlib
import json
import os
import mimetypes
import threading
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs

from zanjir.engine import ROOT
from zanjir import repo_store
from zanjir import scanners, dependencies, images, readiness, webscan, pipeline, custom_rules, portfolio, triage, baseline, iac, sbom
from zanjir import findings_index, settings, code_targets, dashboard, browse
from zanjir.repository import scan_repository, sarif

RUN_LOCK = threading.Lock()
# A one-element list rather than a plain global: the handler reads it at request
# time and main() sets it once, without either needing a `global` statement.
ALLOW_REGISTRATION = [False]


def code_fingerprint():
    """Hash of the server code this process actually loaded.

    Editing app.py does not affect a process that is already running, and there
    was no way to tell from outside -- a SARIF route that existed on disk kept
    returning 404 for a long debugging session because the server predated the
    edit. The dashboard compares this value against the files on disk and says
    plainly when a restart is needed.
    """
    digest = hashlib.sha256()
    for path in sorted((ROOT / 'zanjir').glob('*.py')) + [Path(__file__).resolve()]:
        try:
            digest.update(path.read_bytes())
        except OSError:
            continue
    return digest.hexdigest()[:16]


CODE_FINGERPRINT = code_fingerprint()
STARTED_AT = datetime.datetime.now(datetime.timezone.utc).isoformat()


# Static interface files: read once per change, hashed, and compressed once.
# index.html references every asset as /name?v=<hash>, so an asset URL names one
# exact content and can be cached "immutable"; editing a file changes its hash
# and therefore its URL. No build step is involved -- the rewrite happens here.
ASSET_NAMES = ('index.html', 'app.js', 'shell.js', 'dashboard.js', 'findings.js', 'project.js', 'scanners.js',
               'dependencies.js', 'pilot-dashboard.js', 'web-pilot.js', 'iac.js', 'portfolio.js',
               'style.css', 'dependencies.css', 'favicon.svg', 'bundle.js', 'bundle.css')
ASSET_TYPES = {".js": "text/javascript", ".css": "text/css", ".html": "text/html", ".svg": "image/svg+xml"}
_ASSETS = {}
_ASSETS_LOCK = threading.Lock()
COMPRESSIBLE = ('text/', 'application/json', 'image/svg+xml', 'text/markdown')
MIN_COMPRESS = 1024


# One script and one stylesheet instead of eleven and two: the files are served
# concatenated in the page's own order (all eleven are 'use strict' and share one
# global scope already, so behaviour is unchanged). THREATCHAIN_DEBUG_ASSETS=1
# serves them one by one again for debugging in the browser.
BUNDLES = {'bundle.js': ('app.js', 'shell.js', 'dashboard.js', 'findings.js', 'project.js', 'scanners.js',
                         'dependencies.js', 'pilot-dashboard.js', 'web-pilot.js', 'iac.js', 'portfolio.js'),
           'bundle.css': ('style.css', 'dependencies.css')}
ASSET_TYPES['.js'] = "text/javascript"


def bundling():
    return os.environ.get('THREATCHAIN_DEBUG_ASSETS', '').strip().lower() not in {'1', 'true', 'yes', 'on'}


def asset(name):
    """(body, etag, gzip_body) for one file of dist/, rebuilt only when it changes."""
    if name in BUNDLES:
        key = tuple(asset(part)[1] for part in BUNDLES[name])
        path = None
    else:
        path = ROOT / "dist" / name
        stat = path.stat()
        key = (stat.st_mtime_ns, stat.st_size)
    if name == 'index.html':
        # The page embeds the other files' hashes, so it depends on all of them.
        key = key + (bundling(),) + tuple(asset(other)[1] for other in ASSET_NAMES if other != 'index.html')
    with _ASSETS_LOCK:
        hit = _ASSETS.get(name)
    if hit and hit[0] == key:
        return hit[1]
    if name in BUNDLES:
        separator = b'\n;\n' if name.endswith('.js') else b'\n'
        body = separator.join(b'/* ---- ' + part.encode() + b' ---- */\n' + asset(part)[0] for part in BUNDLES[name])
    else:
        body = path.read_bytes()
    if name == 'index.html':
        text = body.decode('utf-8')
        if bundling():
            import re as _re
            for bundle, parts in BUNDLES.items():
                tag = (f'<script src="/{bundle}?v={asset(bundle)[1]}" defer></script>' if bundle.endswith('.js')
                       else f'<link rel="stylesheet" href="/{bundle}?v={asset(bundle)[1]}">')
                pattern = ('<script src="/{}" defer></script>' if bundle.endswith('.js')
                           else '<link rel="stylesheet" href="/{}">')
                first = True
                for part in parts:
                    needle = pattern.format(part)
                    text = text.replace(needle, tag if first else '', 1)
                    first = False
            text = _re.sub(r'\n[ \t]*\n', '\n', text)
        for other in ASSET_NAMES[1:]:
            text = text.replace(f'"/{other}"', f'"/{other}?v={asset(other)[1]}"')
        body = text.encode('utf-8')
    value = (body, hashlib.sha256(body).hexdigest()[:16], gzip.compress(body, 6))
    with _ASSETS_LOCK:
        _ASSETS[name] = (key, value)
    return value


STATUS_KEYS = ('id', 'target', 'state', 'progress', 'count', 'active_here', 'message', 'created_at', 'finished_at')


def status_view(report):
    """The part of a report a progress poll needs; stages without their reports."""
    view = {key: report[key] for key in STATUS_KEYS if key in report}
    if isinstance(report.get('stages'), list):
        view['stages'] = [{key: stage.get(key) for key in ('kind', 'target', 'state', 'count')}
                          for stage in report['stages'] if isinstance(stage, dict)]
    return view


class Handler(BaseHTTPRequestHandler):
    server_version = "ZanjirLocal/0.7"
    # Keep-alive: the page and its API calls reuse one connection instead of a
    # new TCP handshake per request (HTTP/1.0 closed every connection).
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def do_GET(self):
        self._guard(self._get)

    def do_POST(self):
        self._guard(self._post)

    def _guard(self, handler):
        """Answer every request, even when a handler raises something unexpected.

        An uncaught exception used to close the connection with no response at
        all (re-registering an existing image id, a remote target in the
        assessment form): the browser just hung and the operator saw nothing.
        The traceback still goes to the server log.
        """
        self._responded = False
        # A POST whose body was never read (rejected before reading) must not
        # leave those bytes on a kept-alive connection to be parsed as a request.
        self._body_read = self.command != 'POST'
        try:
            handler()
        except Exception as error:  # noqa: BLE001 -- the last line of defence
            import traceback
            traceback.print_exc()
            if not self._responded:
                try:
                    self.send(500, {'error': f'Server ichki xatosi ({type(error).__name__}). '
                                             'Tafsilot server logida; so‘rovni tekshirib qayta urinib ko‘ring.'})
                except OSError:
                    pass

    def accepts_gzip(self):
        return any(part.split(';')[0].strip() == 'gzip'
                   for part in (self.headers.get('Accept-Encoding') or '').split(','))

    def send(self, status, data, mime="application/json; charset=utf-8", attachment=None,
             cache="no-store", etag=None, gzipped=None):
        self._responded = True
        if getattr(self, '_status_only', False) and status == 200 and isinstance(data, dict) and 'state' in data:
            data = status_view(data)
        body = json.dumps(data, ensure_ascii=False).encode("utf-8") if isinstance(data, (dict, list)) else data
        encoded = None
        if self.accepts_gzip() and mime.startswith(COMPRESSIBLE):
            if gzipped is not None:
                encoded = gzipped
            elif len(body) >= MIN_COMPRESS:
                encoded = gzip.compress(body, 6)
        if encoded is not None and len(encoded) < len(body):
            body = encoded
        else:
            encoded = None
        self.send_response(status)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(body)))
        if mime.startswith(COMPRESSIBLE):
            self.send_header("Vary", "Accept-Encoding")
        if encoded is not None:
            self.send_header("Content-Encoding", "gzip")
        if etag:
            self.send_header("ETag", f'"{etag}"')
        if not getattr(self, '_body_read', True):
            self.send_header("Connection", "close")
            self.close_connection = True
        self.send_header("Cache-Control", cache)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        if attachment:
            self.send_header("Content-Disposition", f'attachment; filename="{attachment}"')
        self.end_headers()
        self.wfile.write(body)

    def local_request(self):
        port = self.server.server_port
        hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
        if self.headers.get("Host") not in hosts:
            self.send(403, {"error": "Faqat localhost orqali kirish mumkin."})
            return False
        origin = self.headers.get("Origin")
        if origin and origin not in {f"http://{host}" for host in hosts}:
            self.send(403, {"error": "Tashqi sahifadan so‘rov qabul qilinmaydi."})
            return False
        if self.headers.get("Sec-Fetch-Site") == "cross-site":
            self.send(403, {"error": "Cross-site so‘rov qabul qilinmaydi."})
            return False
        return True

    def _get(self):
        # ?status=1 on any report URL answers with the few fields a progress
        # poll needs. The page used to re-download the whole report -- up to
        # ~150 KB with findings -- every 1.2-1.5 s for the length of a scan.
        self._status_only = parse_qs(urlsplit(self.path).query).get('status') == ['1']
        if not self.local_request():
            return
        path = urlsplit(self.path).path
        for prefix, module in (('/api/web', webscan), ('/api/assessments', pipeline)):
            if path == prefix + '/targets' and module is webscan:
                return self.send(200, webscan.targets())
            if path == prefix + '/reports':
                return self.send(200, module.history())
            if path.startswith(prefix + '/reports/'):
                parts = path[len(prefix + '/reports/'):].split('/')
                allowed = {'download', 'markdown'} | ({'sarif'} if module is pipeline else set())
                if len(parts) not in (1, 2) or len(parts) == 2 and parts[1] not in allowed:
                    return self.send(404, {'error': 'Hisobot topilmadi.'})
                try:
                    report = module.read(parts[0])
                    if len(parts) == 1 and report['state'] in {'queued', 'running'}:
                        report = {**report, 'active_here': report['id'] in module.CANCEL}
                    if len(parts) == 2 and parts[1] == 'markdown':
                        return self.send(200, module.markdown(report).encode('utf-8'), 'text/markdown; charset=utf-8',
                                         attachment='threatchain-' + report['id'] + '.md')
                    if len(parts) == 2 and parts[1] == 'sarif':
                        return self.send(200, pipeline.sarif(report), attachment='threatchain-' + report['id'] + '.sarif')
                    return self.send(200, report, attachment='threatchain-' + report['id'] + '.json' if len(parts) == 2 else None)
                except ValueError as error:
                    return self.send(404, {'error': str(error)})
        if path == '/api/readiness':
            return self.send(200, readiness.status())
        if path == '/api/portfolio':
            return self.send(200, portfolio.overview())
        if path == '/api/portfolio/targets':
            return self.send(200, {'stages': [{'key': s, 'title': portfolio.STAGE_TITLES[s],
                                               'multi': s in portfolio.MULTI,
                                               'targets': sorted(portfolio.registered_targets()[s])}
                                              for s in portfolio.STAGES]})
        if path == '/api/portfolio/trend':
            query = parse_qs(urlsplit(self.path).query)
            try:
                return self.send(200, portfolio.trend(query.get('project', [''])[0],
                                                      query.get('stage', [''])[0],
                                                      int(query.get('limit', ['20'])[0])))
            except ValueError as error:
                return self.send(400, {'error': str(error)})
        if path == '/api/settings':
            status = settings.status(ALLOW_REGISTRATION[0])
            health = readiness.status()
            return self.send(200, {**status, 'version': health['version'],
                                   'free_disk_gb': health['free_disk_gb'],
                                   'code_fingerprint': health['code_fingerprint']})
        if path == '/api/registry/browse':
            # Behind the same flag as /api/registry/project: see zanjir/browse.py.
            if not ALLOW_REGISTRATION[0]:
                return self.send(403, {'error': 'Papka tanlash o‘chirilgan.',
                                       'hint': 'Serverni `python3 app.py --allow-registration` bilan ishga tushiring.'})
            query = parse_qs(urlsplit(self.path).query)
            try:
                return self.send(200, browse.listing(query.get('path', [''])[0][:400]))
            except ValueError as error:
                return self.send(400, {'error': str(error)})
        if path == '/api/dashboard':
            return self.send(200, dashboard.overview())
        if path == '/api/findings':
            query = parse_qs(urlsplit(self.path).query)
            one = lambda key: query.get(key, [''])[0]
            try:
                return self.send(200, findings_index.search(
                    query=one('q')[:200],
                    filters={key: one(key) for key in findings_index.FILTERS},
                    offset=int(one('offset') or 0), limit=int(one('limit') or 50)))
            except (ValueError, TypeError) as error:
                return self.send(400, {'error': str(error) or 'Filtr qiymati noto‘g‘ri.'})
        if path.startswith('/api/findings/'):
            try:
                return self.send(200, findings_index.detail(path[len('/api/findings/'):]))
            except ValueError as error:
                return self.send(404, {'error': str(error)})
        if path.startswith('/api/baseline/'):
            parts = path[len('/api/baseline/'):].split('/')
            if len(parts) != 2:
                return self.send(404, {'error': 'Bosqich va hisobot ID kerak.'})
            query = parse_qs(urlsplit(self.path).query)
            try:
                return self.send(200, baseline.compare_optional(parts[0], parts[1], query.get('baseline', [''])[0] or None))
            except ValueError as error:
                return self.send(400, {'error': str(error)})
        if path.startswith('/api/triage/'):
            try:
                return self.send(200, triage.overview(path[len('/api/triage/'):]))
            except ValueError as error:
                return self.send(400, {'error': str(error)})
        if path == '/api/rules':
            return self.send(200, {'rules': custom_rules.listing(), 'summary': custom_rules.summary(),
                                   'languages': sorted(custom_rules.LANGUAGES),
                                   'severities': sorted(custom_rules.SEVERITIES)})
        if path == '/api/web/control-evidence':
            try:
                evidence = json.loads((ROOT / 'validation-runs/web-control/result.json').read_text(encoding='utf-8'))
                return self.send(200, evidence)
            except (OSError, ValueError):
                return self.send(200, {'passed': False, 'results': [], 'scope': 'Nazorat sinovi hali bajarilmagan.'})
        if path == '/api/iac/targets':
            return self.send(200, iac.targets())
        if path == '/api/iac/reports':
            return self.send(200, iac.history())
        if path.startswith('/api/iac/reports/'):
            parts = path.split('/')
            if len(parts) not in (5, 6) or len(parts) == 6 and parts[5] not in {'download', 'markdown'}:
                return self.send(404, {'error': 'Hisobot topilmadi.'})
            try:
                report = iac.read(parts[4])
                if len(parts) == 5 and report['state'] in {'queued', 'running'}:
                    report = {**report, 'active_here': report['id'] in iac.CANCEL}
                if len(parts) == 6 and parts[5] == 'markdown':
                    return self.send(200, iac.markdown(report).encode('utf-8'), 'text/markdown; charset=utf-8',
                                     attachment='threatchain-iac-' + report['id'] + '.md')
                return self.send(200, report,
                                 attachment='threatchain-iac-' + report['id'] + '.json' if len(parts) == 6 else None)
            except ValueError as error:
                return self.send(404, {'error': str(error)})
        if path == '/api/images/targets':
            return self.send(200, images.targets())
        if path == '/api/images/reports':
            return self.send(200, images.history())
        if path == '/api/images/sbom':
            # One document for a whole project: ?project=<id>
            query = parse_qs(urlsplit(self.path).query)
            try:
                return self.send(200, project_sbom(query.get('project', [''])[0]),
                                 attachment='threatchain-sbom-' + (query.get('project', [''])[0] or 'project') + '.cdx.json')
            except ValueError as error:
                return self.send(400, {'error': str(error)})
        if path.startswith('/api/images/reports/'):
            parts = path.split('/')
            if len(parts) not in (5, 6) or len(parts) == 6 and parts[5] not in {'download', 'sbom'}:
                return self.send(404, {'error': 'Hisobot topilmadi.'})
            try:
                report = images.read(parts[4])
                if len(parts)==5 and report['state'] in {'queued','running'}:
                    report={**report,'active_here':report['id'] in images.CANCEL}
                if len(parts) == 6 and parts[5] == 'sbom':
                    try:
                        return self.send(200, sbom.build(report),
                                         attachment='threatchain-sbom-' + report['id'] + '.cdx.json')
                    except ValueError as error:
                        return self.send(409, {'error': str(error)})
                return self.send(200, report, attachment='threatchain-image-' + report['id'] + '.json' if len(parts) == 6 else None)
            except ValueError as error:
                return self.send(404, {'error': str(error)})
        if path=='/api/dependencies/reports':
            target=parse_qs(urlsplit(self.path).query).get('target',[None])[0]
            return self.send(200,dependencies.history(target))
        if path.startswith('/api/dependencies/reports/'):
            parts=path.split('/')
            if len(parts) not in (5,6) or len(parts)==6 and parts[5] not in {'download','inventory','markdown','reviews'}:
                return self.send(404,{'error':'Hisobot topilmadi.'})
            try:
                report=dependencies.read(parts[4])
                if len(parts)==5 and report['state'] in {'queued','running'}:
                    report={**report,'active_here':report['id'] in dependencies.CANCEL}
                if len(parts)==6:
                    if parts[5]=='reviews':return self.send(200,dependencies.reviews(report['id']))
                    if parts[5]=='inventory':return self.send(200,dependencies.read_inventory(report['id']),attachment='threatchain-inventory-'+report['id']+'.json')
                    if parts[5]=='markdown':return self.send(200,dependencies.markdown(report).encode('utf-8'),'text/markdown; charset=utf-8',attachment='threatchain-dependencies-'+report['id']+'.md')
                return self.send(200,report,attachment='threatchain-dependencies-'+report['id']+'.json' if len(parts)==6 else None)
            except ValueError as error:return self.send(404,{'error':str(error)})
        if path == '/api/scanners/targets':
            return self.send(200,scanners.targets())
        if path == '/api/scanners/pilot':
            return self.send(200,scanners.pilot_summary())
        if path == '/api/scanners/reports':
            return self.send(200,scanners.history())
        if path.startswith('/api/scanners/reports/'):
            parts=path.split('/')
            if len(parts) not in (5,6) or (len(parts)==6 and parts[5]!='download'):
                return self.send(404,{'error':'Hisobot topilmadi.'})
            try:report=scanners.read_report(parts[4])
            except ValueError as error:return self.send(404,{'error':str(error)})
            return self.send(200,report,attachment=f'threatchain-code-{report["id"]}.json' if len(parts)==6 else None)
        if path == "/api/health":
            return self.send(200, {"ok": True, "mode": "online-evidence-based", "version": "0.7.0",
                                   "code_fingerprint": CODE_FINGERPRINT, "started_at": STARTED_AT})
        if path == '/api/repository/profiles':
            return self.send(200,repo_store.list_profiles())
        if path == '/api/repository/reports':
            profile_id=parse_qs(urlsplit(self.path).query).get('profile_id',[None])[0]
            try:
                return self.send(200, repo_store.list_reports(profile_id))
            except ValueError as error:
                return self.send(400,{'error':str(error)})
        if path == '/api/repository/reviews':
            return self.send(200, repo_store.read_reviews())
        if path.startswith('/api/repository/reports/'):
            parts=path.split('/')
            if len(parts) not in (5,6) or (len(parts)==6 and parts[5] not in {'download','sarif'}):
                return self.send(404, {'error':'Hisobot topilmadi.'})
            try:
                report=repo_store.get_report(parts[4])
            except ValueError as error:
                return self.send(404, {'error':str(error)})
            if len(parts)==6:
                fmt=parts[5]
                return self.send(200, sarif(report) if fmt=='sarif' else report, attachment=f'threatchain-repository-{report["id"]}.{ "sarif" if fmt=="sarif" else "json"}')
            return self.send(200,report)
        name = 'index.html' if path in ('/', '/index.html') else path[1:]
        if name not in ASSET_NAMES:
            return self.send(404, {"error": "Sahifa topilmadi."})
        try:
            body, etag, gzipped = asset(name)
        except OSError:
            return self.send(503, {"error": "Interfeys fayli hali tayyor emas."})
        # A versioned URL names one exact content: cache it for a year. The page
        # itself and unversioned URLs revalidate (ETag -> 304 when unchanged).
        versioned = parse_qs(urlsplit(self.path).query).get('v') == [etag]
        cache = "public, max-age=31536000, immutable" if versioned and name != 'index.html' else "no-cache"
        if self.headers.get('If-None-Match') == f'"{etag}"':
            self._responded = True
            self.send_response(304)
            self.send_header("ETag", f'"{etag}"')
            self.send_header("Cache-Control", cache)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        mime = ASSET_TYPES[Path(name).suffix] + "; charset=utf-8"
        return self.send(200, body, mime, cache=cache, etag=etag, gzipped=gzipped)

    def _post(self):
        if not self.local_request():
            return
        if self.headers.get_content_type() != "application/json":
            return self.send(415, {"error": "JSON kutilmoqda."})
        path = urlsplit(self.path).path
        # Rule text is a whole YAML document, so that one endpoint gets a larger
        # ceiling; every other action stays on the original small limit.
        ceiling = (32768 if path.startswith('/api/rules') else
                   # 200 fingerprints of 24 characters plus a reason
                   16384 if path.startswith('/api/triage') else
                   8192 if path.startswith('/api/portfolio') else 2048)
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 1 or length > ceiling:
                return self.send(413, {"error": "So‘rov hajmi noto‘g‘ri."})
            payload = json.loads(self.rfile.read(length))
            self._body_read = True
            if not isinstance(payload, dict):
                raise ValueError("JSON obyekt kerak")
        except (ValueError, json.JSONDecodeError):
            return self.send(400, {"error": "So‘rov formati noto‘g‘ri."})
        if path.startswith('/api/portfolio'):
            try:
                if path == '/api/portfolio/register' and {'id', 'name', 'stages'} <= set(payload) <= {'id', 'name', 'stages', 'owner'}:
                    return self.send(200, portfolio.register(payload['id'], payload['name'],
                                                             payload['stages'], payload.get('owner', '')))
                if path == '/api/portfolio/remove' and set(payload) == {'id'}:
                    return self.send(200, portfolio.remove(payload['id']))
                return self.send(400, {'error': 'Amal yoki maydonlar noto‘g‘ri.'})
            except ValueError as error:
                return self.send(400, {'error': str(error)})
        if path == '/api/settings/nvd-key':
            try:
                if set(payload) != {'key'}:
                    raise ValueError('Faqat `key` maydoni kerak.')
                return self.send(200, settings.set_nvd_key(payload['key']))
            except ValueError as error:
                return self.send(400, {'error': str(error)})
        if path.startswith('/api/registry/'):
            try:
                if path == '/api/registry/image' and {'id', 'reference'} <= set(payload) <= {'id', 'reference', 'name', 'auth', 'replace'}:
                    return self.send(200, images.register(payload['id'], payload['reference'],
                                                          payload.get('name') or None,
                                                          auth=payload.get('auth') or 'none',
                                                          replace=payload.get('replace') is True))
                if path == '/api/registry/web' and {'id', 'url', 'owner'} <= set(payload) <= {
                        'id', 'url', 'owner', 'authenticated', 'rate_delay', 'replace', 'scan_window', 'daily_request_budget'}:
                    return self.send(200, webscan.register(payload['id'], payload['url'], payload['owner'],
                                                           authenticated=bool(payload.get('authenticated')),
                                                           rate_delay_seconds=payload.get('rate_delay'),
                                                           replace=payload.get('replace') is True,
                                                           scan_window=payload.get('scan_window'),
                                                           daily_request_budget=payload.get('daily_request_budget')))
                if path == '/api/registry/remove' and set(payload) == {'kind', 'id'}:
                    # Removes the registration only. Reports stay (they are evidence)
                    # and no file of the project itself is ever touched.
                    removers = {'image': images.remove, 'web': webscan.remove,
                                'code': code_targets.remove, 'repository': repo_store.remove_project}
                    if payload['kind'] not in removers:
                        raise ValueError('kind: image, web, code yoki repository.')
                    return self.send(200, removers[payload['kind']](payload['id']))
                if path == '/api/registry/remote' and {'id', 'url'} <= set(payload) <= {'id', 'url', 'ref', 'name'}:
                    # A git URL is a validated value, not a filesystem path: the
                    # boundary that keeps /api/registry/project behind a flag
                    # does not apply here, and no credential is accepted.
                    return self.send(200, code_targets.register_remote(
                        payload['id'], payload['url'], payload.get('ref') or '', payload.get('name') or None))
                if path == '/api/registry/project':
                    # repo_store.register_project() takes a filesystem path, and
                    # its own docstring says it is not a browser API: a page that
                    # could hand the server any path could have it copy and index
                    # a whole disk. That boundary is kept -- the endpoint exists
                    # but answers only when the operator started the server with
                    # --allow-registration. Otherwise it hands back the exact
                    # command to run, which is what the window shows.
                    if not ALLOW_REGISTRATION[0]:
                        raise PermissionError('Brauzerdan manba papkasini ro‘yxatga olish o‘chirilgan.')
                    if not {'id', 'root'} <= set(payload) <= {'id', 'root', 'compose', 'name'}:
                        raise ValueError('id va root maydonlari kerak.')
                    result = repo_store.register_project(
                        payload['id'], payload['root'], payload.get('compose') or None,
                        name=payload.get('name') or None)
                    print(f"Ro‘yxatga olindi (brauzer): {payload['id']} -> {payload['root']}", flush=True)
                    return self.send(200, result)
                return self.send(400, {'error': 'Amal yoki maydonlar noto‘g‘ri.'})
            except PermissionError as error:
                command = ('python3 app.py --register-project <id> --repo <yo‘l> --compose docker-compose.yml'
                           if payload.get('compose') else
                           'python3 check_dependencies.py --register <id> --repo <yo‘l>')
                return self.send(403, {'error': str(error) + ' Sababi: brauzerga ixtiyoriy fayl yo‘lini berish '
                                                             'serverga butun diskni o‘qishga yo‘l ochadi.',
                                       'command': command,
                                       'hint': 'Serverni `python3 app.py --allow-registration` bilan ishga '
                                               'tushirsangiz, bu oyna to‘g‘ridan-to‘g‘ri ro‘yxatga oladi.'})
            except ValueError as error:
                return self.send(400, {'error': str(error)})
        if path.startswith('/api/triage'):
            try:
                if path in ('/api/triage', '/api/triage/bulk'):
                    return self.send(200, triage.apply(payload))
                return self.send(404, {'error': 'Amal topilmadi.'})
            except ValueError as error:
                return self.send(400, {'error': str(error)})
        if path.startswith('/api/rules'):
            try:
                if path == '/api/rules/validate' and set(payload) == {'text'}:
                    return self.send(200, {'valid': True, 'rule_ids': custom_rules.validate(payload['text'])})
                if path == '/api/rules/save' and set(payload) <= {'name', 'text', 'note'} and {'name', 'text'} <= set(payload):
                    return self.send(200, custom_rules.save(payload['name'], payload['text'], payload.get('note', '')))
                if path == '/api/rules/delete' and set(payload) == {'name'}:
                    return self.send(200, custom_rules.delete(payload['name']))
                return self.send(400, {'error': 'Amal yoki maydonlar noto‘g‘ri.'})
            except ValueError as error:
                return self.send(400, {'error': str(error)})
        if path.startswith('/api/web/') or path.startswith('/api/assessments/'):
            try:
                if path == '/api/web/scan' and set(payload) == {'target', 'online'} and payload['online'] is True:
                    return self.send(202, webscan.start(payload['target']))
                if path == '/api/assessments/scan':
                    return self.send(202, pipeline.start(payload))
                if path in {'/api/web/cancel', '/api/assessments/cancel'} and set(payload) == {'report_id'}:
                    module = webscan if path.startswith('/api/web/') else pipeline
                    return self.send(200, module.cancel(payload['report_id']))
                return self.send(400, {'error': 'Ro‘yxatdagi nishon va to‘g‘ri maydonlar kerak; web uchun online: true.'})
            except ValueError as error:
                return self.send(400, {'error': str(error)})
        if path.startswith('/api/iac/'):
            try:
                if path == '/api/iac/scan' and set(payload) == {'target'} and isinstance(payload['target'], str):
                    return self.send(202, iac.start(payload['target']))
                if path == '/api/iac/cancel' and set(payload) == {'report_id'}:
                    return self.send(200, iac.cancel(payload['report_id']))
                return self.send(400, {'error': 'Ro‘yxatdagi loyiha ID kerak.'})
            except ValueError as error:
                return self.send(400, {'error': str(error)})
        if path.startswith('/api/images/'):
            try:
                if path == '/api/images/scan' and set(payload) == {'target', 'online'} and isinstance(payload['target'], str) and payload['online'] is True:
                    return self.send(202, images.start(payload['target']))
                if path == '/api/images/cancel' and set(payload) == {'report_id'}:
                    return self.send(200, images.cancel(payload['report_id']))
                return self.send(400, {'error': 'Ro‘yxatdagi image va online: true kerak.'})
            except ValueError as error:
                return self.send(400, {'error': str(error)})
        if path=='/api/scanners/scan':
            if set(payload)!={'target'} or not isinstance(payload['target'],str):
                return self.send(400,{'error':'Ro‘yxatdan o‘tgan loyiha ID kerak.'})
            try:return self.send(202,scanners.start(payload['target']))
            except ValueError as error:return self.send(400,{'error':str(error)})
        if path.startswith('/api/dependencies/'):
            try:
                if path=='/api/dependencies/scan' and set(payload)=={'target'} and isinstance(payload['target'],str):
                    return self.send(202,dependencies.start(payload['target']))
                if path=='/api/dependencies/cancel' and set(payload)=={'report_id'}:
                    return self.send(200,dependencies.cancel(payload['report_id']))
                if path=='/api/dependencies/review':return self.send(200,dependencies.review(payload))
                if path=='/api/dependencies/compare' and set(payload)=={'before','after'}:
                    return self.send(200,dependencies.compare(dependencies.read(payload['before']),dependencies.read(payload['after'])))
                return self.send(400,{'error':'Amal yoki maydonlar noto‘g‘ri. Faqat ro‘yxatdagi loyiha tekshiriladi.'})
            except ValueError as error:return self.send(400,{'error':str(error)})
        if path not in {'/api/repository/scan', '/api/repository/review', '/api/repository/compare'}:
            return self.send(404, {"error": "Amal topilmadi."})
        if not RUN_LOCK.acquire(blocking=False):
            return self.send(409, {"error": "Sinov davom etmoqda. Tugashini kuting."})
        try:
            if path == '/api/repository/scan':
                if set(payload)!={'profile_id'} or not isinstance(payload['profile_id'],str):
                    return self.send(400,{'error':'profile_id kerak.'})
                report=repo_store.scan_profile(payload['profile_id'])
            elif path == '/api/repository/review':
                report=repo_store.save_review(payload)
            else:
                if set(payload)!={'before','after'}:
                    return self.send(400,{'error':'before va after kerak.'})
                report=repo_store.compare_reports(repo_store.get_report(payload['before']),repo_store.get_report(payload['after']))
            self.send(200, report)
        except ValueError as error:
            self.send(400, {"error": str(error)})
        except Exception as error:
            print(f"Run failed: {type(error).__name__}: {error}", flush=True)
            self.send(500, {"error": "Sinov bajarilmadi. Server jurnalini tekshiring; bu muvaffaqiyatli tekshiruv emas."})
        finally:
            RUN_LOCK.release()


def project_sbom(project_id):
    """A merged CycloneDX document for every image a project registered.

    Images whose newest report predates SBOM support are counted in
    `threatchain:skipped_images` rather than silently left out: a document that
    quietly covers three of nine images is worse than one that says so.
    """
    meta = portfolio.projects().get(str(project_id or ''))
    if meta is None:
        raise ValueError('Bunday loyiha yo‘q.')
    identifiers = (meta.get('stages') or {}).get('images') or []
    if not identifiers:
        raise ValueError('Bu loyihaga image bog‘lanmagan.')
    history = images.history(limit=10 ** 6)
    reports = []
    for identifier in identifiers:
        row = next((r for r in history if r.get('target') == identifier
                    and r.get('state') in ('completed', 'partial')), None)
        if row:
            reports.append(images.read(row['id']))
    return sbom.merge(reports, name=str(project_id))


def main():
    parser = argparse.ArgumentParser(description="Zanjir lokal MVP")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument('--allow-registration', action='store_true',
                        help='Brauzerdagi “Nishon qo‘shish” oynasiga manba papkasini ro‘yxatga olishga ruxsat '
                             'beradi. Standart holatda o‘chirilgan: brauzer serverga ixtiyoriy fayl yo‘lini '
                             'bera olmasligi kerak.')
    parser.add_argument('--repository-profile',help='Registered project ID or crapi')
    parser.add_argument('--register-project',help='Register a local project ID for future source-only scans')
    parser.add_argument('--repo',help='Local repository directory for registration')
    parser.add_argument('--name',help='Project display name')
    parser.add_argument('--owner',default='',help='Project owner/team')
    parser.add_argument('--scan-repo',help='Read-only local repository directory')
    parser.add_argument('--compose',help='Compose path relative to repository')
    parser.add_argument('--env-file',help='Optional literal .env path relative to repository')
    parser.add_argument('--bindings',help='Optional JSON proxy bindings array')
    args = parser.parse_args()
    ALLOW_REGISTRATION[0] = bool(getattr(args, 'allow_registration', False))
    if args.register_project:
        if not args.repo or not args.compose:
            parser.error('--register-project requires --repo and --compose')
        from pathlib import Path
        try:
            bindings=json.loads(Path(args.bindings).read_text(encoding='utf-8')) if args.bindings else []
            registered=repo_store.register_project(args.register_project,args.repo,args.compose,args.env_file,bindings,args.name,args.owner)
        except (ValueError,OSError) as error:
            parser.error(str(error))
        print(json.dumps(registered,indent=2))
        return
    if args.repository_profile or args.scan_repo:
        if args.repository_profile:
            report=repo_store.scan_profile(args.repository_profile)
        else:
            if not args.compose:
                parser.error('--scan-repo requires --compose')
            from pathlib import Path
            bindings=json.loads(Path(args.bindings).read_text(encoding='utf-8')) if args.bindings else []
            report=repo_store.save_report(scan_repository(args.scan_repo,args.compose,args.env_file,bindings))
        print(json.dumps({'id':report['id'],'summary':report['summary'],'unknowns':report['unknowns']},indent=2))
        return
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.daemon_threads = True
    print(f"Zanjir lokal MVP: http://127.0.0.1:{server.server_port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
