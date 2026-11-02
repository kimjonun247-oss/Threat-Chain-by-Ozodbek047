"""NVD / EPSS enrichment caching (shortcomings review 2026-11-02, LP#1 and LP#9).

LP#1: nvd_weaknesses() reused the name `key` for the NVD API key, overwriting the
cache key. With no API key configured (the default) `_cache_set(None, ...)` raised
TypeError outside every handler and failed the whole dependency stage; with a key
configured, the secret became a file name in advisory-cache/.

LP#9: a feed outage was cached as "nothing found" for the normal 24-hour TTL, so one
NVD/EPSS hiccup silently removed CWE/EPSS data from every scan for a day.
"""
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from zanjir import threatfeeds

CVE = 'CVE-2021-44228'
NVD_REPLY = {'vulnerabilities': [{'cve': {'weaknesses': [{'description': [{'value': 'CWE-502'}]}]}}]}


class FeedCacheTests(unittest.TestCase):
    def setUp(self):
        self.cache = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.cache, True)
        for patcher in (patch.object(threatfeeds, 'CACHE', self.cache),
                        patch.object(threatfeeds, 'min_interval', return_value=0)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def names(self):
        return sorted(p.name for p in self.cache.iterdir())

    def test_a_no_api_key_does_not_crash_and_caches_under_the_hash(self):
        with patch.object(threatfeeds, 'nvd_api_key', return_value=None), \
                patch.object(threatfeeds, '_get', return_value=NVD_REPLY):
            self.assertEqual(threatfeeds.nvd_weaknesses(CVE), [502])
        self.assertEqual(len(self.names()), 1)
        self.assertRegex(self.names()[0], r'^[0-9a-f]{64}\.json$')

    def test_b_the_api_key_never_reaches_the_disk(self):
        secret = 'SECRET-NVD-KEY-0123456789'
        with patch.object(threatfeeds, 'nvd_api_key', return_value=secret), \
                patch.object(threatfeeds, '_get', return_value=NVD_REPLY):
            threatfeeds.nvd_weaknesses(CVE)
        for path in self.cache.iterdir():
            self.assertNotIn(secret, path.name)
            self.assertNotIn(secret, path.read_text(encoding='utf-8'))

    def test_c_a_second_lookup_is_served_from_the_cache(self):
        with patch.object(threatfeeds, 'nvd_api_key', return_value=None), \
                patch.object(threatfeeds, '_get', return_value=NVD_REPLY) as fetch:
            threatfeeds.nvd_weaknesses(CVE)
            threatfeeds.nvd_weaknesses(CVE)
        self.assertEqual(fetch.call_count, 1)

    def test_d_an_nvd_outage_is_not_cached_as_nothing_found(self):
        with patch.object(threatfeeds, 'nvd_api_key', return_value=None):
            with patch.object(threatfeeds, '_get', side_effect=threatfeeds.FeedError('503')):
                self.assertEqual(threatfeeds.nvd_weaknesses(CVE), [])
            self.assertEqual(self.names(), [], 'a failed lookup must not be cached')
            with patch.object(threatfeeds, '_get', return_value=NVD_REPLY):
                self.assertEqual(threatfeeds.nvd_weaknesses(CVE), [502])

    def test_e_an_epss_outage_is_not_cached_as_nothing_found(self):
        reply = {'data': [{'cve': CVE, 'epss': '0.97', 'percentile': '0.99'}]}
        with patch.object(threatfeeds, '_get', side_effect=threatfeeds.FeedError('503')):
            self.assertEqual(threatfeeds.epss_scores([CVE]), {})
        self.assertEqual(self.names(), [])
        with patch.object(threatfeeds, '_get', return_value=reply):
            self.assertEqual(threatfeeds.epss_scores([CVE])[CVE]['epss'], 0.97)

    def test_f_a_cve_with_no_cwe_is_still_cached(self):
        # "NVD answered, there is no CWE" is a real answer and stays cached.
        with patch.object(threatfeeds, 'nvd_api_key', return_value=None), \
                patch.object(threatfeeds, '_get', return_value={'vulnerabilities': []}):
            self.assertEqual(threatfeeds.nvd_weaknesses(CVE), [])
        self.assertEqual(len(self.names()), 1)
        self.assertEqual(json.loads((self.cache / self.names()[0]).read_text(encoding='utf-8'))['data'], [])


if __name__ == '__main__':
    unittest.main()
