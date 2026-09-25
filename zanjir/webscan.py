"""Bounded web checks: exact registered origin, pinned DNS, verified TLS, GET only.

Nuclei talks to an ephemeral loopback gateway. Only reviewed template paths are
forwarded. Response bodies remain in memory; the report contains hashes, not secrets.
"""
import collections
import datetime
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from urllib.parse import urlsplit, urljoin

from .engine import ROOT
from . import repo_store, scanners, taxonomy, run_index, findings as findings_mod, triage
from . import verification as verification_mod
from vendor import yaml

RUNS = ROOT / 'web-runs'
PROFILES = ROOT / 'profiles/web'
RULES = ROOT / 'scanner-rules/nuclei'
# Windows keeps the original .tools/nuclei/nuclei.exe; every other platform
# uses the vendored posix/ build installed by setup_nuclei.py.
BINARY = ROOT / '.tools/nuclei/nuclei.exe' if sys.platform.startswith('win') else ROOT / '.tools/nuclei/posix/nuclei'
LOCK = threading.Lock()
CANCEL = {}
# The scanned service should be able to tell who is calling it and find the
# operator who authorised it. An anonymous agent string on a real target is how
# a security scan gets mistaken for an attack.
# ASCII only: http.client encodes header values as latin-1, so a typographic
# apostrophe here makes every single request fail before it is sent.
USER_AGENT = 'ThreatChain/0.7 (authorised local security scan; owner recorded in report)'
# Minimum delay between requests, in seconds. The default is what the pilot has
# always used; a real service can be given more room per target.
DEFAULT_RATE_DELAY = 0.5
MAX_RATE_DELAY = 30.0
MAX_BODY = 65536
MAX_REQUESTS = 48
MAX_CRAWL_PAGES = 16
MAX_CRAWL_DEPTH = 2
TIMEOUT = 8
DEADLINE = 180
CORS_PROBE_ORIGIN = 'https://zanjir-cors-probe.invalid'
LIMITS = ('Cheklangan GET profili: kirishsiz javoblar, ochiq konfiguratsiya/fayl naqshlari, HTTP himoya sarlavhalari, '
          'CORS Origin aks ettirilishi, cookie bayroqlari va server xatosi orqali texnik ma’lumot sizishi tekshiriladi. '
          'Bir sahifadagi bir nechta Set-Cookie javobidan faqat oxirgisi tahlil qilinadi. '
          'Autentifikatsiya, biznes mantiqi, in’ektsiya (SQLi/XSS) sinovlari, ekspluatatsiya va barcha CVE qamrovi yo‘q. '
          'Redirect kuzatilmaydi; sirlar hisobotga kiritilmaydi. Topilma yo‘qligi xavfsizlik kafolati emas.')


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def auth_slug(target):
    return ''.join(c if c.isalnum() else '_' for c in str(target or '')).upper()


def auth_variable(target):
    return 'THREATCHAIN_WEB_AUTH_' + auth_slug(target)


def auth_for(profile):
    """The Authorization header for one target, taken from the environment only.

    An API behind a login cannot be scanned without one, and a token cannot be
    stored in this project: it would sit in a profile file, in backups and in
    every report that copied the profile. So the value is read from the process
    environment at request time, and what the report records is the name of the
    variable -- never its contents.
    """
    if not profile.get('authenticated'):
        return {}, {'mode': 'none', 'credentials_present': False,
                    'note': 'Autentifikatsiyasiz tekshirildi; faqat ochiq javoblar ko\u2018rildi.'}
    variable = auth_variable(profile['id'])
    value = os.environ.get(variable, '').strip()
    if not value:
        raise ValueError(f'{profile["id"]} autentifikatsiyali nishon sifatida ro\u2018yxatga olingan, lekin '
                         f'{variable} muhit o\u2018zgaruvchisi o\u2018rnatilmagan. Qiymat loyihada saqlanmaydi.')
    return ({'Authorization': value},
            {'mode': 'environment', 'credentials_present': True, 'variable': variable,
             'note': ('Authorization sarlavhasi faqat shu jarayonning muhitidan olindi. Qiymat hech qayerda '
                      'saqlanmaydi va hisobotda faqat o\u2018zgaruvchi nomi ko\u2018rinadi.')})


def rate_delay(profile):
    try:
        value = float(profile.get('rate_delay') or DEFAULT_RATE_DELAY)
    except (TypeError, ValueError):
        return DEFAULT_RATE_DELAY
    return min(MAX_RATE_DELAY, max(DEFAULT_RATE_DELAY, value))


def tls_state(wire):
    """What the certificate looked like at the moment of the handshake.

    Reported, never judged here: whether thirty days is too few is the
    operator's call, and this module only records what it saw.
    """
    import datetime as _dt
    try:
        certificate = wire.getpeercert() or {}
        names = {name: value for pairs in certificate.get('subject', ()) for name, value in pairs}
        issuer = {name: value for pairs in certificate.get('issuer', ()) for name, value in pairs}
        expires = certificate.get('notAfter')
        remaining = None
        if expires:
            try:
                moment = _dt.datetime.strptime(expires, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=_dt.timezone.utc)
                remaining = (moment - _dt.datetime.now(_dt.timezone.utc)).days
            except ValueError:
                remaining = None
        return {'protocol': wire.version(), 'cipher': (wire.cipher() or ('',))[0],
                'subject': names.get('commonName', ''), 'issuer': issuer.get('commonName', ''),
                'not_after': expires, 'days_remaining': remaining,
                'subject_alt_names': sorted({value for kind, value in certificate.get('subjectAltName', ())
                                             if kind == 'DNS'})[:20],
                'verified': True,
                'note': ('Sertifikat standart ishonch zanjiri bilan tekshirildi. Muddat va nomlar qayd etildi; '
                         'ularning yetarliligini mutaxassis baholaydi.')}
    except (OSError, ValueError, AttributeError):
        return None


def canonical_url(value):
    if not isinstance(value, str) or len(value) > 500 or not value.isascii():
        raise ValueError('ASCII URL kerak; xalqaro domen uchun punycode ishlating.')
    parts = urlsplit(value)
    if parts.scheme not in {'http', 'https'} or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError('Faqat http/https URL; login, parol, query va fragment bo‘lmasin.')
    host = parts.hostname.lower()
    if not re.fullmatch(r'[a-z0-9.-]+', host) or host.endswith('.') or '..' in host:
        raise ValueError('Domen yoki IPv4 kerak; wildcard va IPv6 bu pilotda qo‘llanmaydi.')
    port = parts.port or (443 if parts.scheme == 'https' else 80)
    if not 1 <= port <= 65535:
        raise ValueError('Port noto‘g‘ri.')
    path = parts.path.rstrip('/')
    if not re.fullmatch(r'(?:/[A-Za-z0-9._~-]+)*', path) or any(p in {'.', '..'} for p in path.split('/')):
        raise ValueError('URL bazaviy yo‘li oddiy segmentlardan iborat bo‘lsin.')
    authority = host + (':' + str(port) if port != (443 if parts.scheme == 'https' else 80) else '')
    return f'{parts.scheme}://{authority}{path}'


def register(target, url, owner, allow_private=False, authenticated=False, rate_delay_seconds=None, replace=False):
    if not isinstance(target, str) or not repo_store.PROFILE_ID.fullmatch(target) or target.startswith('pilot-'):
        raise ValueError('2–40 belgili loyiha ID kerak; pilot- nomlari band.')
    if not isinstance(owner, str) or not 1 <= len(owner.strip()) <= 120 or type(allow_private) is not bool:
        raise ValueError('Ruxsat bergan mas’ul nomi kerak.')
    if type(authenticated) is not bool:
        raise ValueError('authenticated qiymati true yoki false bo‘lishi kerak.')
    row = {'id': target, 'name': target, 'url': canonical_url(url), 'owner': owner.strip(),
           'allow_private': allow_private, 'authorized_at': now(),
           'authenticated': authenticated,
           'rate_delay': rate_delay({'rate_delay': rate_delay_seconds})}
    if authenticated:
        # The variable name is stored so the operator can see what to export;
        # the value itself never is.
        row['auth_variable'] = auth_variable(target)
    # A CLI confirmation records scope; this is not independent proof of ownership.
    path = PROFILES / (target + '.json')
    if path.exists() and not replace:
        raise ValueError('Bu nishon ID allaqachon ro‘yxatda. Yangilash uchun “Mavjud bo‘lsa yangilash”ni belgilang '
                         '(API: "replace": true); ruxsat qaytadan qayd etiladi.')
    repo_store.write_json(path, row)
    return row


def remove(target):
    """Drop a registration; past reports stay in the history."""
    path = PROFILES / (str(target) + '.json')
    if not repo_store.PROFILE_ID.fullmatch(str(target)) or str(target).startswith('pilot-') or not path.is_file():
        raise ValueError('Bunday ro‘yxatdagi web nishon yo‘q (pilot- nishonlari o‘chirilmaydi).')
    path.unlink()
    return {'id': target, 'removed': True, 'note': 'Oldingi hisobotlar tarixda saqlanib qoldi.'}


def targets():
    rows = [{'id': 'pilot-crapi', 'name': 'OWASP crAPI · lokal web', 'url': 'http://127.0.0.1:18888',
             'owner': 'Foydalanuvchi ruxsat bergan lokal crAPI laboratoriyasi', 'allow_private': True,
             'authorized_at': 'existing_local_lab'}]
    for path in sorted(PROFILES.glob('*.json')):
        try:
            row = json.loads(path.read_text(encoding='utf-8'))
            if (row['id'] == path.stem and repo_store.PROFILE_ID.fullmatch(row['id']) and
                    not row['id'].startswith('pilot-') and canonical_url(row['url']) == row['url'] and
                    type(row['allow_private']) is bool and isinstance(row['owner'], str) and row['owner'].strip()):
                rows.append(row)
        except (OSError, ValueError, KeyError, TypeError):
            continue
    return rows


def target_for(target):
    if not isinstance(target, str):
        raise ValueError('Ro‘yxatdagi web nishon ID kerak.')
    row = next((t for t in targets() if t['id'] == target), None)
    if row is None:
        raise ValueError('Web nishon ro‘yxatda yo‘q. CHECK-WEB.cmd orqali ruxsat doirasini kiriting.')
    return row


def resolve(profile):
    parts = urlsplit(profile['url'])
    port = parts.port or (443 if parts.scheme == 'https' else 80)
    found = sorted({item[4][0] for item in socket.getaddrinfo(parts.hostname, port, socket.AF_INET, socket.SOCK_STREAM)})
    if not found:
        raise ValueError('DNS manzili topilmadi.')
    for value in found:
        ip = ipaddress.ip_address(value)
        if ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved or (not ip.is_global and not profile['allow_private']):
            raise ValueError('DNS manzili ruxsat doirasiga mos emas. Lokal/intranet nishoni alohida ro‘yxatga olinadi.')
    # Every connection uses this literal address; Host and TLS SNI retain the approved hostname.
    return found[0], port


def rule_profile():
    manifest = json.loads((RULES / 'manifest.json').read_text(encoding='utf-8'))
    templates = {}
    paths = {'/'}
    for item in manifest['templates']:
        name = item['file']
        if not re.fullmatch(r'[a-z0-9-]+\.yaml', name):
            raise ValueError('Template fayli noto‘g‘ri.')
        raw = (RULES / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != item['sha256']:
            raise ValueError('Template xeshi o‘zgargan. Qoidalar profilini tekshiring.')
        try:
            data = yaml.safe_load(raw)
        except yaml.YAMLError as error:
            # The hash matched, so this file is the one the manifest names; if it
            # still will not parse, say so as a ValueError like every other
            # profile problem rather than letting it escape the handler.
            raise ValueError(f'{name}: YAML o‘qilmadi — ' + str(getattr(error, 'problem', error))[:200]) from None
        if set(data) != {'id', 'info', 'http'} or len(data['http']) != 1:
            raise ValueError('Faqat tekshirilgan oddiy HTTP template mumkin.')
        request = data['http'][0]
        if request['method'] != 'GET' or set(request) - {'method', 'path', 'matchers', 'matchers-condition', 'extractors'}:
            raise ValueError('GET va qat’iy yo‘llardan boshqa template amali qabul qilinmaydi.')
        for path in request['path']:
            suffix = path.removeprefix('{{BaseURL}}')
            if path == suffix or not re.fullmatch(r'(?:/[A-Za-z0-9._~-]+)*', suffix) or any(p in {'.', '..'} for p in suffix.split('/')):
                raise ValueError('Template tashqi/dinamik yo‘lga ega.')
            paths.add(suffix or '/')
        templates[data['id']] = {'file': name, 'title': data['info']['name'], 'severity': data['info']['severity'].upper(),
                                 'sha256': item['sha256'], 'origin': item['origin']}
    if len(templates) != 6 or len(paths) > 24:
        raise ValueError('Kutilgan 6 template profili yo‘q yoki juda keng.')
    return templates, paths, hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()


def response_range(response):
    """Export only numeric range metadata; malformed or unknown ranges stay partial."""
    if response.status != 206:
        return None
    value = response.getheader('Content-Range', '')
    # Bound numeric parsing too. Duplicate fields are comma joined and rejected.
    match = re.fullmatch(r'bytes ([0-9]{1,20})-([0-9]{1,20})/([0-9]{1,20})', value, re.IGNORECASE)
    if not match:
        return None
    start, end, total = map(int, match.groups())
    if start > end or end >= total:
        return None
    return {'start': start, 'end': end, 'total': total}


class Collector:
    def __init__(self, profile, paths, cancel):
        self.profile = profile
        self.parts = urlsplit(profile['url'])
        self.ip, self.port = resolve(profile)
        self.context = ssl.create_default_context() if self.parts.scheme == 'https' else None
        self.paths = paths
        self.cancel = cancel
        self.started = time.monotonic()
        # Recorded from the first successful handshake. A scan of a real service
        # should say what its certificate looked like at that moment -- an expiry
        # three days away is a finding the HTTP checks would never see.
        self.tls = None
        self.auth_headers, self.auth_meta = auth_for(profile)
        self.delay = rate_delay(profile)
        self.next_request = 0.0
        self.lock = threading.Lock()
        self.cache = {}
        self.evidence = []
        self.errors = []
        self.requests = 0
        self.blocked = 0

    def allow(self, path):
        """Let the bounded same-origin crawler register a newly discovered path."""
        with self.lock:
            self.paths.add(path)

    def fetch(self, path, extra_headers=None):
        variant = tuple(sorted((extra_headers or {}).items()))
        cache_key = (path, variant)
        with self.lock:
            if cache_key in self.cache:
                return self.cache[cache_key]
            if path not in self.paths:
                self.blocked += 1
                raise ValueError('Yo‘l profilga kirmaydi.')
            if self.cancel.is_set() or time.monotonic() - self.started > DEADLINE or self.requests >= MAX_REQUESTS:
                raise ValueError('Jarayon to‘xtatilgan yoki so‘rov/vaqt chegarasiga yetdi.')
            if self.cancel.wait(max(0, self.next_request - time.monotonic())):
                raise ValueError('Jarayon bekor qilingan.')
            self.next_request = time.monotonic() + self.delay
            self.requests += 1
            upstream_path = self.parts.path + path if path != '/' else (self.parts.path or '/')
            conn = http.client.HTTPConnection(self.parts.hostname, self.port, timeout=TIMEOUT)
            wire = None
            response = None
            watchdog = None
            try:
                wire = socket.create_connection((self.ip, self.port), timeout=TIMEOUT)
                if self.context:
                    wire = self.context.wrap_socket(wire, server_hostname=self.parts.hostname)
                    if self.tls is None:
                        self.tls = tls_state(wire)
                def abort_slow_response():
                    try:
                        wire.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                # Header parsing also needs a total deadline against slow trickle responses.
                watchdog = threading.Timer(min(TIMEOUT, max(0.01, self.started + DEADLINE - time.monotonic())), abort_slow_response)
                watchdog.daemon = True
                watchdog.start()
                conn.sock = wire
                request_headers = {'Host': self.parts.netloc, 'User-Agent': USER_AGENT,
                                    'Accept-Encoding': 'identity', 'Range': f'bytes=0-{MAX_BODY - 1}', 'Connection': 'close'}
                # The operator's own credential for this target, read from the
                # process environment at request time. It is never stored and
                # never written into a report -- only the variable's name is.
                request_headers.update(self.auth_headers)
                if extra_headers:
                    request_headers.update(extra_headers)
                conn.request('GET', upstream_path, headers=request_headers)
                # Keep the socket object alive until our bounded read ends. getresponse()
                # closes HTTP/1.0 sockets early (the response file still owns its handle).
                response = http.client.HTTPResponse(wire)
                response.begin()
                # Read incrementally with a total deadline, not an unbounded trickle timeout.
                body = bytearray()
                stop = min(self.started + DEADLINE, time.monotonic() + TIMEOUT)
                while len(body) <= MAX_BODY:
                    remaining = stop - time.monotonic()
                    if remaining <= 0 or self.cancel.is_set():
                        raise TimeoutError('Response deadline')
                    wire.settimeout(min(TIMEOUT, remaining))
                    chunk = response.read1(min(8192, MAX_BODY + 1 - len(body)))
                    if not chunk:
                        break
                    body.extend(chunk)
                byte_range = response_range(response)
                # A requested prefix may contain the entire small resource (RFC 9110
                # 14.1.2). A 206 status alone does not prove a truncated body.
                full_range = byte_range is not None and byte_range['start'] == 0 and byte_range['end'] + 1 == byte_range['total'] == len(body)
                truncated = len(body) > MAX_BODY or bool(response.length) or (response.status == 206 and not full_range)
                raw = bytes(body[:MAX_BODY])
                headers = {k.lower(): v for k, v in response.getheaders()}
                row = {'path': path, 'status': response.status, 'bytes_read': len(raw), 'truncated': truncated,
                       'unsupported_encoding': headers.get('content-encoding', '').lower() not in {'', 'identity'},
                       'body_sha256': hashlib.sha256(raw).hexdigest(), 'observed_at': now()}
                if byte_range is not None:
                    row['content_range'] = byte_range
                if variant:
                    row['probe'] = 'cors_origin_reflection'
                self.evidence.append(row)
                result = (response.status, headers, raw)
                self.cache[cache_key] = result
                if response.status == 429:
                    self.cancel.set()
                    self.errors.append({'path': path, 'type': 'rate_limited'})
                return result
            except (OSError, http.client.HTTPException, ValueError) as error:
                # Never export response content, headers, or exception strings containing secrets.
                self.errors.append({'path': path, 'type': type(error).__name__})
                raise
            finally:
                if watchdog is not None:
                    watchdog.cancel()
                if response is not None:
                    response.close()
                conn.close()
                if wire is not None:
                    wire.close()


def finding(rule, title, severity, path, evidence, fix, tool='ThreatChain HTTP', verified=True):
    tags = taxonomy.tag_static(tool, rule)
    note = ('Nishonning haqiqiy HTTP javobida bevosita kuzatilgan; amaliy xavf darajasi va biznes ta’siri baribir mutaxassis tomonidan baholanishi kerak.'
            if verified else
            'Bir xil fallback javobi tufayli aniq fayl/holat tasdiqlanmadi; qo‘lda tekshirish shart.')
    return {'id': hashlib.sha256((rule + ':' + path).encode()).hexdigest()[:24],
            # Only GET is ever sent; the method is in the identity so a later
            # check using another one cannot collide with this finding.
            'fingerprint': findings_mod.fingerprint('web', {'rule_id': rule, 'path': path, 'method': 'GET'}),
            'rule_id': rule, 'title': title,
            'severity': severity, 'path': path, 'tool': tool, 'state': 'needs_review', 'evidence': evidence, 'remediation': fix,
            'cwe_ids': tags['cwe_ids'], 'owasp_top10_2025': tags['owasp_top10_2025'],
            'verified': verified, 'verification_note': note}


def header_findings(collector):
    status, headers, body = collector.fetch('/')
    result = []
    if collector.parts.scheme == 'http':
        result.append(finding('http-transport', 'Nishon HTTP orqali ochilgan', 'LOW', '/', 'Ulanish TLS ishlatmaydi.',
                              'Tashqi foydalanuvchilar uchun HTTPS ni majburiy qiling; lokal laboratoriya holatini alohida baholang.'))
    if not 200 <= status < 300:
        return result
    checks = [('x-content-type-options', 'nosniff', 'LOW', 'Brauzer content-type himoyasi yo‘q', 'X-Content-Type-Options: nosniff sozlang.')]
    if collector.parts.scheme == 'https':
        checks.append(('strict-transport-security', 'max-age=', 'LOW', 'HSTS sarlavhasi yo‘q', 'HTTPS to‘g‘ri ishlagach HSTS siyosatini belgilang.'))
    for name, expected, severity, title, fix in checks:
        if expected not in headers.get(name, '').lower():
            result.append(finding(name, title, severity, '/', 'Kutilgan himoya qiymati kuzatilmadi; HTTP ' + str(status), fix))
    if 'text/html' in headers.get('content-type', '').lower():
        if not headers.get('content-security-policy'):
            result.append(finding('csp-missing', 'HTML javobida CSP yo‘q', 'LOW', '/', 'Content-Security-Policy kuzatilmadi.',
                                  'Ilovaga mos CSP yarating, avval report-only rejimida sinang.'))
        if not headers.get('x-frame-options') and 'frame-ancestors' not in headers.get('content-security-policy', '').lower():
            result.append(finding('frame-protection', 'Sahifani iframe ichida ochish himoyasi ko‘rinmadi', 'LOW', '/',
                                  'X-Frame-Options va CSP frame-ancestors kuzatilmadi.', 'CSP frame-ancestors siyosatini ilova talabiga mos sozlang.'))
    return result


LINK_PATTERN = re.compile(rb'(?:href|src|action)\s*=\s*["\']([^"\'#>]+)', re.IGNORECASE)


def extract_links(base_path, content_type, body):
    """Same-origin, navigable-looking hrefs from an HTML response. No script execution."""
    if 'html' not in content_type.lower():
        return []
    links = []
    for match in LINK_PATTERN.finditer(body):
        try:
            raw = match.group(1).decode('ascii')
        except UnicodeDecodeError:
            continue
        if raw.startswith(('http://', 'https://', '//', 'mailto:', 'tel:', 'javascript:', 'data:')):
            continue
        path = urlsplit(urljoin(base_path, raw)).path or '/'
        core = path.rstrip('/') or '/'
        if not re.fullmatch(r'(?:/[A-Za-z0-9._~-]+)*', core) or any(part in {'.', '..'} for part in core.split('/')):
            continue
        # The trailing slash is part of the address: `/files/` and `/files` are
        # different resources, and on most servers only the first is the
        # directory. Stripping it turned every directory link into a 404, so a
        # directory listing linked from the site was never seen. The query string
        # is still dropped on purpose -- a GET with parameters may change state.
        links.append(core + '/' if path.endswith('/') and core != '/' else core)
    return links


def crawl(collector, seed='/'):
    """Bounded same-origin GET crawl (BFS) so header/CORS/cookie checks reach more
    than the fixed Nuclei template paths. Shares the collector's own rate limit,
    request budget and deadline; never follows off-origin or non-GET-safe links."""
    queue = collections.deque([(seed, 0)])
    seen = {seed}
    pages = []
    while queue and len(pages) < MAX_CRAWL_PAGES:
        path, depth = queue.popleft()
        collector.allow(path)
        try:
            status, headers, body = collector.fetch(path)
        except (ValueError, OSError, http.client.HTTPException, TimeoutError):
            continue
        pages.append(path)
        if depth >= MAX_CRAWL_DEPTH or not 200 <= status < 300:
            continue
        for link in extract_links(path, headers.get('content-type', ''), body):
            if link not in seen and len(seen) < MAX_CRAWL_PAGES * 3:
                seen.add(link)
                queue.append((link, depth + 1))
    return pages


def cors_findings(collector):
    """One extra request: does the target blindly reflect an arbitrary Origin
    together with credentials, letting any third-party site read authenticated
    responses via a victim's browser?"""
    try:
        _, headers, _ = collector.fetch('/', extra_headers={'Origin': CORS_PROBE_ORIGIN})
    except (ValueError, OSError, http.client.HTTPException, TimeoutError):
        return []
    acao = headers.get('access-control-allow-origin', '')
    acac = headers.get('access-control-allow-credentials', '').strip().lower()
    if acao == CORS_PROBE_ORIGIN and acac == 'true':
        return [finding('cors-reflected-origin-credentials', 'CORS: so‘ralgan Origin ko‘r-ko‘rona aks ettirilib, credentials ruxsat etilgan',
                'HIGH', '/', f"Sinov uchun yuborilgan Origin ({CORS_PROBE_ORIGIN}) aynan aks ettirildi va Access-Control-Allow-Credentials: true bilan birga keldi.",
                'Faqat aniq ishonchli originlar ro‘yxatini qaytaring; so‘ralgan Originni ko‘r-ko‘rona aks ettirishni to‘xtating.')]
    if acao == '*' and acac == 'true':
        return [finding('cors-wildcard-credentials', 'CORS: wildcard va credentials bir vaqtda ruxsat etilgan',
                'HIGH', '/', 'Access-Control-Allow-Origin: * va Access-Control-Allow-Credentials: true bir javobda qaytarildi.',
                'Wildcard bilan credentials birga ishlatilmaydi; aniq originlar ro‘yxatiga o‘ting.')]
    return []


def cookie_findings(collector, pages):
    result = []
    seen_names = set()
    for path in pages:
        cached = collector.cache.get((path, ()))
        if not cached:
            continue
        _, headers, _ = cached
        raw = headers.get('set-cookie', '')
        if not raw:
            continue
        name = raw.split('=', 1)[0].strip()
        if not name or name in seen_names:
            continue
        seen_names.add(name)
        lowered = raw.lower()
        if collector.parts.scheme == 'https' and 'secure' not in lowered:
            result.append(finding('cookie-missing-secure', f'Cookie “{name}”da Secure atributi yo‘q', 'LOW', path,
                          f'Set-Cookie: {name}=... javobida Secure kuzatilmadi.',
                          'HTTPS ustida ishlaydigan cookie uchun Secure atributini qo‘shing.'))
        if 'httponly' not in lowered:
            result.append(finding('cookie-missing-httponly', f'Cookie “{name}”da HttpOnly atributi yo‘q', 'MEDIUM', path,
                          f'Set-Cookie: {name}=... javobida HttpOnly kuzatilmadi.',
                          'JavaScript orqali o‘qish shart bo‘lmasa, HttpOnly atributini qo‘shing (XSS orqali o‘g‘irlanishni qiyinlashtiradi).'))
    return result


FINGERPRINT_HEADERS = ('server', 'x-powered-by', 'x-aspnet-version', 'x-generator')
VERSION_TOKEN = re.compile(r'\d+(?:\.\d+)+|/\d+')


def fingerprint_findings(collector, pages):
    result = []
    seen = set()
    for path in pages:
        cached = collector.cache.get((path, ()))
        if not cached:
            continue
        _, headers, _ = cached
        for name in FINGERPRINT_HEADERS:
            value = headers.get(name, '').strip()
            # `Server: web` or `Server: nginx` names no version; only the headers
            # that exist to name technology count without a version number.
            if name == 'server' and not VERSION_TOKEN.search(value):
                continue
            if value and (name, value) not in seen:
                seen.add((name, value))
                result.append(finding('server-fingerprint', 'Server/texnologiya versiyasi sarlavhada oshkor qilingan', 'LOW', path,
                              f'{name}: {value}', 'Ishlab chiqarish muhitida bu sarlavhani olib tashlang yoki umumiy qiymatga almashtiring.'))
    return result


ERROR_PATTERN = re.compile(rb'(?i)(traceback \(most recent|fatal error:|exception in thread|at java\.[a-z.]+\(|'
                            rb'stack trace:|django\.core\.exceptions|unhandled exception|internal server error.{0,40}(line|file) )')


# A stack trace is unmistakable even when the framework answers 200 (debug
# pages, APIs that wrap errors in a success status). Only these specific shapes
# count below 500, so documentation that merely mentions "stack trace" does not.
STRONG_ERROR_PATTERN = re.compile(rb'(traceback \(most recent call last\):\s*\n\s*file "|'
                                  rb'exception in thread "[^"\n]*" [a-z.]+(exception|error)|'
                                  rb'\n\s+at [a-z][a-z0-9_.$]+\([a-z0-9_]+\.java:\d+\)|'
                                  rb'(fatal error|parse error|warning)</b>:.{0,200} on line <b>\d+)', re.IGNORECASE)
DIRECTORY_LISTING = re.compile(rb'<title>\s*(index of /|directory listing for /)|<h1>\s*(index of /|directory listing for /)',
                               re.IGNORECASE)


def directory_listing_findings(collector, pages):
    """A crawled page that is an auto-generated directory index (CWE-548).

    Nuclei's dir-listing template probes only the site root; a listing under a
    linked folder (`/files/`, `/uploads/`) was invisible.
    """
    result = []
    for path in pages:
        cached = collector.cache.get((path, ()))
        if cached and 200 <= cached[0] < 300 and DIRECTORY_LISTING.search(cached[2][:4096]):
            result.append(finding('http-dir-listing', 'Papka tarkibi ochiq ro‘yxat sifatida ko‘rsatiladi', 'MEDIUM', path,
                                  'Javob avtomatik papka indeksiga mos keladi (fayl nomlari hisobotga kiritilmaydi).',
                                  'Veb-serverda papka indeksini o‘chiring (nginx: autoindex off; Apache: Options -Indexes).'))
    return result


def error_disclosure_findings(collector, pages):
    result = []
    for path in pages:
        cached = collector.cache.get((path, ()))
        if not cached:
            continue
        status, _, body = cached
        if (status >= 500 and ERROR_PATTERN.search(body)) or STRONG_ERROR_PATTERN.search(body):
            result.append(finding('error-disclosure', 'Server xatosi ichki texnik tafsilotlarni oshkor qilishi mumkin', 'MEDIUM', path,
                          f'HTTP {status} javobida stek-iz/texnik xato belgilariga o‘xshash matn topildi (qiymat hisobotga kiritilmaydi).',
                          'Ishlab chiqarish muhitida umumiy xato sahifasini qaytaring; texnik tafsilotlarni faqat serverning o‘z logiga yozing.'))
    return result


def gateway(collector):
    token = '/' + uuid.uuid4().hex

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            if (self.headers.get('Host') != f'127.0.0.1:{self.server.server_port}' or
                    not (self.path == token or self.path.startswith(token + '/'))):
                self.send_error(403)
                return
            path = self.path[len(token):] or '/'
            try:
                status, headers, body = collector.fetch(path)
                evidence = next(row for row in collector.evidence if row['path'] == path)
                # Reviewed templates describe whole resources. Present a fully
                # collected 206 as 200 inside this local adapter; keep the actual
                # upstream status and byte range in the exported evidence.
                if status == 206 and not evidence['truncated'] and not evidence['unsupported_encoding']:
                    status = 200
                evidence['nuclei_status'] = status
                # Do not let upstream redirects, cookies, or auth headers escape the gate.
                self.send_response(status)
                self.send_header('Content-Type', headers.get('content-type', 'application/octet-stream'))
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except (OSError, ValueError, http.client.HTTPException):
                self.send_error(502)

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f'http://127.0.0.1:{server.server_port}{token}'


def normalize_nuclei(raw, base, templates, collector, missing_hash):
    findings = {}
    suppressed = 0
    ambiguous = set()
    for line in raw.splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        rule = row.get('template-id')
        matched = row.get('matched-at', '')
        if rule not in templates or not isinstance(matched, str) or not (matched == base or matched.startswith(base + '/')):
            raise ValueError('Nuclei natijasi tanlangan profil/doiraga mos emas.')
        path = matched[len(base):] or '/'
        evidence = next((e for e in collector.evidence if e['path'] == path), None)
        if not evidence or path not in collector.paths:
            raise ValueError('Nuclei topilmasiga tarmoq dalili topilmadi.')
        if path != '/' and evidence['body_sha256'] == missing_hash:
            suppressed += 1
            ambiguous.add(rule)
            continue
        if evidence['status'] not in {200, 206}:
            suppressed += 1
            continue
        info = templates[rule]
        fix = ('API hujjati ataylab ochiq bo‘lishi mumkin; kirish siyosatini tekshiring.' if rule == 'zanjir-openapi' else
               'Faylni public web papkadan olib tashlang yoki kirishni cheklang. Sir ochilgan bo‘lsa uni almashtiring, keyin qayta tekshiring.')
        f = finding(rule, info['title'], info['severity'], path, evidence, fix, 'Nuclei')
        f['template_sha256'] = info['sha256']
        findings[f['id']] = f
    if ambiguous:
        f = finding('ambiguous-fallback', 'Bir xil fallback javobida sezgir mazmun naqshi bor', 'MEDIUM', '/',
                    'Mavjud bo‘lmagan yo‘l ham ayni mazmunni qaytardi. Aniq fayl ochiqligi tasdiqlanmagan. Mos qoidalar: ' + ', '.join(sorted(ambiguous)),
                    'Fallback javobini ko‘rib chiqing: namunaviy matnmi yoki haqiqiy maxfiy konfiguratsiyami? Haqiqiy sir bo‘lsa almashtiring.',
                    verified=False)
        findings[f['id']] = f
    return list(findings.values()), suppressed


def run_nuclei(collector, templates, folder, cancel, missing_hash):
    provenance = json.loads((BINARY.parent / 'provenance.json').read_text(encoding='utf-8'))
    if hashlib.sha256(BINARY.read_bytes()).hexdigest() != provenance['binary_sha256']:
        raise ValueError('Nuclei binary xeshi mos emas.')
    server, base = gateway(collector)
    try:
        with tempfile.TemporaryDirectory(prefix='nuclei-', dir=folder) as temporary:
            work = Path(temporary)
            env = scanners.environment(work)
            for provider in ('PUBLIC', 'GITHUB', 'GITLAB', 'AWS', 'AZURE'):
                env['DISABLE_NUCLEI_TEMPLATES_' + provider + '_DOWNLOAD'] = 'true'
            env['NUCLEI_TEMPLATES_DIR'] = str(RULES)
            (work / 'config.yaml').write_text('{}\n')
            command = [str(BINARY), '-u', base, '-config', str(work / 'config.yaml'),
                       '-jsonl', '-silent', '-nc', '-or', '-ot', '-duc', '-ni', '-dr', '-no-stdin',
                       '-c', '1', '-bs', '1', '-rl', '2', '-timeout', '12', '-retries', '0', '-mhe', '0',
                       '-rsr', str(MAX_BODY), '-rss', str(MAX_BODY)]
            for template in templates.values():
                command += ['-t', str(RULES / template['file'])]
            # Raw output can contain extractors. Keep it in process memory only.
            process = subprocess.Popen(command, cwd=work, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            started = time.monotonic()
            try:
                while True:
                    try:
                        out, err = process.communicate(timeout=0.3)
                        break
                    except subprocess.TimeoutExpired:
                        if cancel.is_set() or time.monotonic() - started > DEADLINE:
                            process.kill()
                            process.communicate()
                            raise ValueError('Nuclei bekor qilindi yoki vaqt chegarasiga yetdi.')
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()
            if process.returncode != 0 or len(out) > 4 * 1024 * 1024 or b'Could not run' in err:
                raise ValueError('Nuclei jarayoni muvaffaqiyatli tugamadi; bu toza natija emas.')
            findings, suppressed = normalize_nuclei(out.decode('utf-8'), base, templates, collector, missing_hash)
            return findings, {'name': 'Nuclei', 'version': provenance['version'], 'binary_sha256': provenance['binary_sha256'],
                              'state': 'completed', 'templates': len(templates), 'suppressed_soft404': suppressed}
    finally:
        server.shutdown()
        server.server_close()


def read(rid):
    report = run_index.read(RUNS, rid, 'Web hisoboti topilmadi.')
    return triage.attach('web', report.get('target'), report)


def history(limit=30):
    return run_index.rows(RUNS, ('id', 'target', 'url', 'created_at', 'state', 'count'), read, limit=limit)


def execute(profile, rid, event):
    folder = RUNS / rid
    report = read(rid)
    collector = None
    report.update(state='running', progress='Ruxsat doirasi, DNS va tarmoq tekshirilmoqda.')
    repo_store.write_json(folder / 'report.json', report)
    try:
        templates, paths, profile_hash = rule_profile()
        missing = '/zanjir-missing-' + uuid.uuid4().hex
        collector = Collector(profile, paths | {missing}, event)
        report['profile_sha256'] = profile_hash
        report['resolved_ip'] = collector.ip
        report['authentication'] = collector.auth_meta
        report['rate_delay_seconds'] = collector.delay
        report['user_agent'] = USER_AGENT
        report['templates'] = templates
        report['findings'] = header_findings(collector)
        report['progress'] = 'Bir xil manbadagi sahifalar bosib chiqilmoqda (cheklangan chuqurlik).'
        repo_store.write_json(folder / 'report.json', report)
        pages = crawl(collector)
        report['crawled_pages'] = pages
        report['findings'] += cors_findings(collector)
        report['findings'] += cookie_findings(collector, pages)
        report['findings'] += fingerprint_findings(collector, pages)
        report['findings'] += error_disclosure_findings(collector, pages)
        report['findings'] += directory_listing_findings(collector, pages)
        missing_status, _, missing_body = collector.fetch(missing)
        report.update(count=len(report['findings']), progress='Nuclei tanlangan GET qoidalarini bajarmoqda.')
        repo_store.write_json(folder / 'report.json', report)
        findings, tool = run_nuclei(collector, templates, folder, event, hashlib.sha256(missing_body).hexdigest())
        report['findings'] += findings
        report['tool'] = tool
        report['state'] = 'completed'
    except (OSError, ValueError, KeyError, TypeError, http.client.HTTPException, subprocess.SubprocessError) as error:
        report['state'] = 'cancelled' if event.is_set() else 'partial' if report['findings'] else 'failed'
        report['error_type'] = type(error).__name__
        report['message'] = 'Tekshiruv to‘liq tugamadi. Nishon ishlashi, TLS sertifikati va Nuclei o‘rnatilishini tekshiring.'
        if isinstance(error, ConnectionRefusedError):
            report['message'] = 'Tanlangan saytga ulanish rad etildi. Lokal crAPI uchun Docker Desktop va PILOT-START.cmd orqali xizmatlarni ishga tushiring.'
        elif isinstance(error, ssl.SSLCertVerificationError):
            report['message'] = 'Nishon TLS sertifikati tasdiqlanmadi. Sertifikat zanjiri va domenini tuzating; tekshiruv o‘chirilmaydi.'
        elif type(error) is ValueError and str(error):
            # This module's own refusals (scope, DNS, template profile) are
            # ValueErrors with an operator-facing sentence. Replacing it with the
            # generic text above hid, for example, that a metadata address was
            # refused on purpose -- the operator could not tell a block from a bug.
            report['message'] = 'Tekshiruv to‘xtatildi: ' + str(error)[:300]
    finally:
        if collector:
            report['requests'] = collector.requests
            report['evidence'] = collector.evidence
            report['errors'] = collector.errors
            report['blocked_requests'] = collector.blocked
            # Captured on the first handshake, so it only exists for an https
            # target that actually answered.
            report['tls'] = collector.tls
            report['coverage'] = {'attempted_paths': [e['path'] for e in collector.evidence],
                                  'unvisited_paths': sorted(collector.paths - {e['path'] for e in collector.evidence}),
                                  'restricted_responses': sum(e['status'] in {401, 403, 429} for e in collector.evidence),
                                  'redirects': sum(300 <= e['status'] < 400 for e in collector.evidence),
                                  'truncated_responses': sum(e['truncated'] for e in collector.evidence),
                                  'unsupported_encodings': sum(e['unsupported_encoding'] for e in collector.evidence),
                                  'ambiguous_fallback_matches': report.get('tool', {}).get('suppressed_soft404', 0)}
            if report['state'] == 'completed' and (collector.errors or collector.blocked or report['coverage']['unvisited_paths'] or
                    report['coverage']['restricted_responses'] or report['coverage']['redirects'] or report['coverage']['truncated_responses'] or
                    report['coverage']['unsupported_encodings'] or report['coverage']['ambiguous_fallback_matches'] or
                    any(e['status'] not in {200, 206, 404, 410} for e in collector.evidence)):
                report['state'] = 'partial'
        report['count'] = len(report['findings'])
        report['severity_counts'] = dict(collections.Counter(f['severity'] for f in report['findings']))
        report['verification_summary'] = verification_mod.summarize(report['findings'])
        report['finished_at'] = now()
        report['progress'] = 'Jarayon yakunlandi; holat va qamrovni ko‘ring.'
        try:
            repo_store.write_json(folder / 'report.json', report)
            triage.record_scan('web', report)
        finally:
            CANCEL.pop(rid, None)
            LOCK.release()
    return report


def start(target, background=True):
    profile = target_for(target)
    if not LOCK.acquire(blocking=False):
        raise ValueError('Boshqa web tekshiruvi davom etmoqda.')
    rid = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S') + '-' + uuid.uuid4().hex[:8]
    event = threading.Event()
    try:
        repo_store.write_json(RUNS / rid / 'report.json', {'id': rid, 'target': target, 'url': profile['url'],
                             'authorization': {'owner': profile['owner'], 'recorded_at': profile['authorized_at']},
                             'created_at': now(), 'state': 'queued', 'count': 0, 'findings': [], 'limits': LIMITS,
                             'scope': 'Exact registered origin and base path; GET, 2 req/s, 32 requests, 64 KiB/response, 180 s.'})
        CANCEL[rid] = event
        if background:
            threading.Thread(target=execute, args=(profile, rid, event), daemon=True).start()
            return {'id': rid, 'state': 'queued'}
    except Exception:
        CANCEL.pop(rid, None)
        LOCK.release()
        raise
    return execute(profile, rid, event)


def cancel(rid):
    read(rid)
    if rid not in CANCEL:
        raise ValueError('Bu web jarayoni ushbu serverda ishlamayapti.')
    CANCEL[rid].set()
    return {'id': rid, 'state': 'cancellation_requested'}


def markdown(report):
    def cell(value):
        return str(value).replace('|', '\\|').replace('\n', ' ').replace('\r', ' ')
    verification = verification_mod.summarize(report.get('findings', []))
    lines = ['# Zanjir — web tekshiruvi', '', 'Nishon: ' + report['url'], 'Holat: ' + report['state'],
             'Hisobot: ' + report['id'], '', report['limits'], '',
             f"Tasdiqlash: {verification['confirmed_by_evidence']} dalil bilan tasdiqlangan / "
             f"{verification['manual_review_required']} qo‘lda tekshirish talab qiladi (jami {verification['total']}).", '',
             '| Vosita | Og‘irlik | Yo‘l | Topilma | CWE | OWASP Top 10 | Tasdiqlangan | Tuzatish |',
             '|---|---|---|---|---|---|---|---|']
    for f in report['findings']:
        owasp = ', '.join(o['code'] for o in f.get('owasp_top10_2025') or []) or '\u2014'
        lines.append('| ' + ' | '.join(cell(v) for v in (f['tool'], f['severity'], f['path'], f['title'],
                     ', '.join(f.get('cwe_ids') or []) or '\u2014', owasp,
                     'Ha' if f.get('verified') else 'Yo\u2018q, qo\u2018lda tekshirish kerak', f['remediation'])) + ' |')
    lines += ['', 'Qamrov: ' + cell(json.dumps(report.get('coverage', {}), ensure_ascii=False))]
    return '\n'.join(lines) + '\n'
