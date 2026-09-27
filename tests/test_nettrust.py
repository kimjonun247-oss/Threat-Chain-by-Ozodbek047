"""TLS trust and proxy policy for outbound feeds and downloads."""
import os
import tempfile
import unittest
import urllib.request
from unittest.mock import patch

from zanjir import nettrust


class TrustTests(unittest.TestCase):
    def test_operator_ca_bundle_wins_over_certifi(self):
        # A TLS-inspecting corporate proxy is trusted through SSL_CERT_FILE; the
        # old code always used certifi and so could never download anything there.
        with tempfile.NamedTemporaryFile(suffix='.pem') as bundle, \
             patch.dict(os.environ, {'SSL_CERT_FILE': bundle.name}), \
             patch('ssl.create_default_context') as create:
            nettrust.ssl_context()
        self.assertEqual(create.call_args.kwargs['cafile'], bundle.name)

    def test_missing_bundle_path_falls_back_instead_of_failing(self):
        with patch.dict(os.environ, {'SSL_CERT_FILE': '/nonexistent/ca.pem', 'SSL_CERT_DIR': ''}):
            context = nettrust.ssl_context()
        self.assertTrue(context.check_hostname)

    def test_verification_is_never_disabled(self):
        self.assertTrue(nettrust.ssl_context().check_hostname)


class ProxyTests(unittest.TestCase):
    def test_ambient_proxy_is_bypassed_by_default(self):
        with patch.dict(os.environ, {'HTTPS_PROXY': 'http://proxy.invalid:3128'}, clear=False):
            os.environ.pop(nettrust.PROXY_VARIABLE, None)
            self.assertEqual(nettrust.proxy_handler().proxies, {})

    def test_proxy_is_used_on_explicit_opt_in(self):
        # Replace the whole environment: a lowercase https_proxy of the machine
        # running the suite would otherwise take precedence.
        with patch.dict(os.environ, {'HTTPS_PROXY': 'http://proxy.invalid:3128', nettrust.PROXY_VARIABLE: '1'},
                        clear=True):
            handler = nettrust.proxy_handler()
        self.assertIsInstance(handler, urllib.request.ProxyHandler)
        self.assertEqual(handler.proxies.get('https'), 'http://proxy.invalid:3128')


if __name__ == '__main__':
    unittest.main()
