"""The web stage's request budget on a large site (shortcomings review 2026-11-02, LP#3).

All checks shared one 48-request budget, spent in order: header, crawl, CORS, then
the supplementary API inventory (17 spec URLs + up to 24 endpoint probes). On a
large site that pass used the budget up, the missing-path baseline failed, and
Nuclei -- the .env/.git/SQL-dump checks -- never ran. Now the inventory gets only
what remains after the core checks are reserved, records what it left out, and
the confirmation pass gets the CONFIRM_BUDGET the documented scope promises.
"""
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from zanjir import api_inventory as inv
from zanjir import webscan as w
from test_api_inventory import SPEC_BYTES, listener, site


def collector_for(test, url):
    profile = {'id': 't', 'url': url, 'owner': 'test', 'authorized_at': w.now(),
               'allow_private': True, 'rate_delay': 0.5}
    collector = w.Collector(profile, set(), threading.Event())
    collector.delay = 0.0
    test.addCleanup(collector.close)
    return collector


class InventoryBudgetTests(unittest.TestCase):
    def test_a_the_inventory_never_spends_more_than_its_budget(self):
        with listener(site({'/': b'<html>app</html>'})) as url:
            collector = collector_for(self, url)
            before = collector.requests
            _, inventory = inv.inventory_findings(collector, w.finding, authenticated=False, budget=3)
            self.assertLessEqual(collector.requests - before, 3)
        self.assertEqual(inventory['request_budget'], 3)
        self.assertEqual(inventory['spec_paths_not_tried'],
                         len(inv.NUCLEI_SPEC_PATHS + inv.EXTRA_SPEC_PATHS) - 3)

    def test_b_endpoints_left_out_by_the_budget_are_counted(self):
        with listener(site({'/api-docs': SPEC_BYTES, '/health': b'ok', '/users': b'[]'})) as url:
            collector = collector_for(self, url)
            # Enough to find the spec at /api-docs (5th path in the list), not to probe.
            position = (inv.NUCLEI_SPEC_PATHS + inv.EXTRA_SPEC_PATHS).index('/api-docs') + 1
            # Every spec path is tried before probing; give exactly enough for those.
            budget = len(inv.NUCLEI_SPEC_PATHS + inv.EXTRA_SPEC_PATHS)
            _, inventory = inv.inventory_findings(collector, w.finding, authenticated=False, budget=budget)
        self.assertGreaterEqual(budget, position)
        self.assertEqual(inventory['documented_endpoints'], 3)
        self.assertEqual(inventory['probed_count'], 0)
        self.assertEqual(inventory['endpoints_not_probed'], 2)       # /health and /users, unchecked

    def test_c_a_live_spec_that_does_not_parse_is_named(self):
        with listener(site({'/openapi.json': b'{"openapi": "3.0.0", "paths": {"/a": '})) as url:
            _, inventory = inv.inventory_findings(collector_for(self, url), w.finding, authenticated=False)
        self.assertIn('/openapi.json', inventory['unparsed_live_specs'])


class CollectorLimitTests(unittest.TestCase):
    def test_the_limit_stops_requests_and_can_be_raised_for_confirmation(self):
        with listener(site({'/a': b'1', '/b': b'2', '/c': b'3'})) as url:
            collector = collector_for(self, url)
            for path in ('/a', '/b', '/c'):
                collector.allow(path)
            collector.limit = 2
            collector.fetch('/a')
            collector.fetch('/b')
            with self.assertRaises(ValueError):
                collector.fetch('/c')
            collector.limit = 3                       # what execute() does before confirm_findings
            self.assertEqual(collector.fetch('/c')[0], 200)

    def test_collection_starts_at_max_requests(self):
        with listener(site({'/': b'ok'})) as url:
            self.assertEqual(collector_for(self, url).limit, w.MAX_REQUESTS)


class RepoWalkTests(unittest.TestCase):
    def test_a_node_modules_is_not_walked(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / 'node_modules' / 'pkg').mkdir(parents=True)
            (root / 'node_modules' / 'pkg' / 'openapi.json').write_bytes(SPEC_BYTES)
            (root / 'src').mkdir()
            (root / 'src' / 'openapi.json').write_bytes(SPEC_BYTES)
            labels = {Path(label).as_posix() for label, _ in inv.discover_repo(root)}
        self.assertEqual(labels, {'src/openapi.json'})

    def test_b_a_walk_that_hits_its_cap_says_so(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for n in range(10):
                (root / f'file{n}.txt').write_text('x', encoding='utf-8')
            notes = []
            with mock.patch.object(inv, 'MAX_REPO_WALK_ENTRIES', 3):
                inv.discover_repo(root, notes)
        self.assertTrue(notes and 'chegarasi' in notes[0], notes)


if __name__ == '__main__':
    unittest.main()
