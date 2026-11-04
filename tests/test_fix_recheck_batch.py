"""Proposed fix versions are re-checked in batches (shortcomings review 2026-11-02, LP#7).

dependency_plan used to call recheck() once per vulnerable package: up to
MAX_ROUNDS OSV look-ups each, one after another, with no progress and no way to
cancel -- 2 000 vulnerable packages were up to 6 000 sequential round trips.
recheck_many asks for every package in one call per round. These tests hold it
to the per-package answer exactly and count the calls.
"""
import random
import unittest

from zanjir import fixes


class FakeOSV:
    """Each package version is affected by advisories that are fixed in a later version."""

    def __init__(self, seed, packages):
        rng = random.Random(seed)
        self.affected = {}            # (eco, name, version) -> [(advisory, fixed version)]
        for eco, name in packages:
            chain = sorted({f'1.{n}.0' for n in range(rng.randrange(1, 6))}, key=fixes.version_key)
            for here, there in zip(chain, chain[1:]):
                if rng.random() < 0.7:
                    self.affected[(eco, name, here)] = [(f'GHSA-{name}-{here}', there)]
        self.down = {(eco, name) for eco, name in packages if rng.random() < 0.1}
        self.calls = 0

    def __call__(self, packages):
        self.calls += 1
        matches, details, errors = {}, {}, []
        for p in packages:
            key = (p['ecosystem'], p['name'], p['version'])
            if (key[0], key[1]) in self.down:
                errors.append({'package': list(key), 'reason': 'osv_query_incomplete'})
                continue
            rows = self.affected.get(key, [])
            matches[key] = [advisory for advisory, _ in rows]
            for advisory, fixed in rows:
                details[advisory] = {'affected': [{'ranges': [{'events': [{'fixed': fixed}]}]}]}
        return matches, details, errors, []


class BatchTests(unittest.TestCase):
    def test_a_the_batch_answers_exactly_what_one_by_one_answers(self):
        for seed in range(20):
            packages = [('PyPI', f'p{n}') for n in range(60)]
            targets = {(eco, name, '0.9'): (eco, name, '1.0.0') for eco, name in packages}
            batch = fixes.recheck_many(FakeOSV(seed, packages), targets)
            one = FakeOSV(seed, packages)
            single = {key: fixes.recheck(one, *target) for key, target in targets.items()}
            self.assertEqual(batch, single, seed)

    def test_b_at_most_max_rounds_calls_whatever_the_package_count(self):
        packages = [('npm', f'p{n}') for n in range(500)]
        osv = FakeOSV(3, packages)
        fixes.recheck_many(osv, {(eco, name, '0.9'): (eco, name, '1.0.0') for eco, name in packages})
        self.assertLessEqual(osv.calls, fixes.MAX_ROUNDS)

    def test_c_a_cancelled_scan_is_not_reported_as_an_outage(self):
        def cancelled(packages):
            raise InterruptedError('cancelled')
        with self.assertRaises(InterruptedError):
            fixes.recheck_many(cancelled, {1: ('PyPI', 'x', '1.0')})

    def test_d_the_plan_uses_one_call_per_round(self):
        calls = []

        def query(packages):
            calls.append(len(packages))
            return {(p['ecosystem'], p['name'], p['version']): [] for p in packages}, {}, [], []
        findings = [{'package': {'ecosystem': 'PyPI', 'name': f'p{n}', 'version': '1.0'}, 'advisory_id': f'A{n}',
                     'fixed_versions': ['1.1'], 'occurrences': []} for n in range(300)]
        plan = fixes.dependency_plan(findings, {}, query)
        self.assertEqual(calls, [300])
        self.assertTrue(all(row['target_check'] == 'clean' for row in plan['packages']))


if __name__ == '__main__':
    unittest.main()
