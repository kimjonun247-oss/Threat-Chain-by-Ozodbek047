"""TLS trust and proxy policy for every outbound download and advisory query.

Two problems made the platform unusable on corporate networks:

- `certifi` was preferred over everything, so an operator's `SSL_CERT_FILE` /
  `SSL_CERT_DIR` (the standard way to trust a TLS-inspecting proxy's CA) was
  ignored and every download failed with CERTIFICATE_VERIFY_FAILED.
- ambient proxy variables were always bypassed, so a network where a proxy is
  the only way out could not reach OSV, NVD, CISA KEV or a release page at all.

The trust order is now: the operator's explicit `SSL_CERT_FILE`/`SSL_CERT_DIR`,
then certifi, then the system store. Proxies stay bypassed by default -- the
original reason holds: ambient proxy settings (and credentials embedded in them)
are not forwarded unless the operator asks -- and `THREATCHAIN_USE_PROXY=1`
opts in to the standard HTTPS_PROXY/NO_PROXY handling. Verification is never
switched off.
"""
import os
import ssl
import urllib.request

PROXY_VARIABLE = 'THREATCHAIN_USE_PROXY'


def ssl_context():
    cafile = os.environ.get('SSL_CERT_FILE') or None
    capath = os.environ.get('SSL_CERT_DIR') or None
    if cafile and not os.path.isfile(cafile):
        cafile = None
    if capath and not os.path.isdir(capath):
        capath = None
    if cafile or capath:
        return ssl.create_default_context(cafile=cafile, capath=capath)
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


def use_proxy():
    return os.environ.get(PROXY_VARIABLE, '').strip().lower() in {'1', 'true', 'yes', 'on'}


def proxy_handler():
    """Ambient proxies only on explicit opt-in; otherwise a direct connection."""
    return urllib.request.ProxyHandler() if use_proxy() else urllib.request.ProxyHandler({})
