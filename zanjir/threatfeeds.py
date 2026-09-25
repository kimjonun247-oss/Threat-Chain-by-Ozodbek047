"""Read-only NVD (CWE/CVSS) and FIRST.org EPSS enrichment. Bounded, cached, best-effort.

Mirrors advisories.py's fetch discipline: a fixed URL allowlist, no ambient
proxy credentials, no redirects, and a 24h disk cache under advisory-cache/.
NVD's public quota (5 req/30s, or 50 req/30s with an optional NVD_API_KEY env
var) makes per-CVE enrichment slow at scale, so callers should treat this as
best-effort supplementary detail, not a required step.
"""
import hashlib
import json
import os
import re
import threading
import time
import urllib.error
import urllib.request

from .engine import ROOT
from . import nettrust, repo_store

_SSL_CONTEXT = nettrust.ssl_context()

CACHE = ROOT / 'advisory-cache'
NVD = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
EPSS = 'https://api.first.org/data/v1/epss'
CVE_ID = re.compile(r'^CVE-\d{4}-\d{4,}$')
TTL = 24 * 60 * 60
def nvd_api_key():
    """Read at call time, not at import: a key set from the settings window has
    to take effect without restarting the server."""
    from . import settings
    try:
        return settings.nvd_key()
    except (OSError, ValueError):
        return os.environ.get('NVD_API_KEY', '').strip() or None


# Kept as a module attribute for callers written before the settings window
# existed; it reflects the environment only.
NVD_API_KEY = os.environ.get('NVD_API_KEY', '').strip() or None
NVD_BUDGET_DEFAULT = 40

_rate_lock = threading.Lock()
_last_call = [0.0]


def min_interval():
    """NVD's own published limits: 5 requests / 30 s without a key, 50 with one.
    Read per call so a key added from the settings window changes the pace
    immediately instead of at the next restart."""
    return 0.7 if nvd_api_key() else 6.5


class FeedError(ValueError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise FeedError('unexpected_feed_redirect')


def _cache_get(key):
    try:
        cached = json.loads((CACHE / (key + '.json')).read_text(encoding='utf-8'))
        if 0 <= time.time() - cached['stored_at'] < TTL:
            return cached['data']
    except (OSError, ValueError, KeyError, TypeError):
        pass
    return None


def _cache_set(key, data):
    repo_store.write_json(CACHE / (key + '.json'), {'stored_at': time.time(), 'data': data})


def _get(url, headers=None):
    if not (url.startswith(NVD + '?cveId=') or url.startswith(EPSS + '?cve=')):
        raise FeedError('feed_url_not_allowed')
    request = urllib.request.Request(url, headers={'Accept': 'application/json', 'User-Agent': 'Zanjir/0.6', **(headers or {})})
    opener = urllib.request.build_opener(nettrust.proxy_handler(), NoRedirect(), urllib.request.HTTPSHandler(context=_SSL_CONTEXT))
    for attempt in range(2):
        try:
            with opener.open(request, timeout=20) as response:
                raw = response.read(4 * 1024 * 1024 + 1)
                if len(raw) > 4 * 1024 * 1024:
                    raise FeedError('feed_response_too_large')
                return json.loads(raw)
        except urllib.error.HTTPError as error:
            if attempt == 0 and error.code in {403, 429, 500, 502, 503, 504}:
                time.sleep(2)
                continue
            raise FeedError('feed_http_' + str(error.code)) from None
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
            if attempt == 0:
                time.sleep(1)
                continue
            raise FeedError('feed_unavailable_or_invalid_json') from None


def nvd_weaknesses(cve_id):
    """Best-effort CWE lookup for one CVE via NVD. Never raises; returns [] on any failure."""
    if not CVE_ID.fullmatch(cve_id):
        return []
    key = hashlib.sha256(('nvd-weaknesses:' + cve_id).encode()).hexdigest()
    cached = _cache_get(key)
    if cached is not None:
        return cached
    with _rate_lock:
        wait = min_interval() - (time.time() - _last_call[0])
        if wait > 0:
            time.sleep(wait)
        ids = []
        try:
            key = nvd_api_key()
            headers = {'apiKey': key} if key else {}
            data = _get(NVD + '?cveId=' + cve_id, headers)
            for vuln in data.get('vulnerabilities', []) if isinstance(data, dict) else []:
                for weakness in vuln.get('cve', {}).get('weaknesses', []):
                    for description in weakness.get('description', []):
                        match = re.fullmatch(r'CWE-(\d+)', str(description.get('value', '')))
                        if match:
                            ids.append(int(match.group(1)))
            ids = sorted(set(ids))
        except (FeedError, AttributeError, TypeError):
            ids = []
        finally:
            _last_call[0] = time.time()
    _cache_set(key, ids)
    return ids


def enrich_cwe(primary_cves, budget=NVD_BUDGET_DEFAULT):
    """Fill in CWE gaps for CVEs OSV/GHSA did not already tag, within a fixed call budget.

    Returns {cve: [cwe_numbers]}. Cached lookups do not count against the budget.
    """
    result = {}
    spent = 0
    for cve in primary_cves:
        key = hashlib.sha256(('nvd-weaknesses:' + cve).encode()).hexdigest()
        cached = _cache_get(key)
        if cached is not None:
            result[cve] = cached
            continue
        if spent >= budget:
            continue
        result[cve] = nvd_weaknesses(cve)
        spent += 1
    return result


def epss_scores(cve_ids):
    """Batched EPSS lookup (100 CVEs/request). Missing entries are simply absent from the result."""
    ids = sorted({c for c in cve_ids if CVE_ID.fullmatch(c)})
    result = {}
    for start in range(0, len(ids), 100):
        batch = ids[start:start + 100]
        key = hashlib.sha256(('epss:' + ','.join(batch)).encode()).hexdigest()
        cached = _cache_get(key)
        if cached is None:
            try:
                data = _get(EPSS + '?cve=' + ','.join(batch))
                cached = {row['cve']: {'epss': float(row['epss']), 'percentile': float(row['percentile'])}
                          for row in data.get('data', []) if isinstance(row, dict) and CVE_ID.fullmatch(str(row.get('cve', '')))}
            except (FeedError, KeyError, ValueError, TypeError):
                cached = {}
            _cache_set(key, cached)
        result.update(cached)
    return result
