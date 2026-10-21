"""The board's order (PLAN.md 3.4): severity first, then -- within one severity
-- reachable before unknown, shipped code before test/vendored, fixable before
no-fix. Documented in BETA_READINESS.md ("Ustuvorlik tartibi")."""
import unittest
from unittest.mock import patch

from isolation import isolate_triage
from zanjir import findings_index, findings_store


class PriorityValueTests(unittest.TestCase):
    def test_each_question_has_its_own_weight_and_reachability_counts_most(self):
        p = findings_store.priority
        self.assertEqual(p({'stage': 'chain', 'reachable': True, 'path_class': 'prod'}), 0)
        self.assertEqual(p({'stage': 'dependencies', 'reachable': True, 'path_class': 'prod'}), 1)   # no fix
        self.assertEqual(p({'stage': 'code', 'path_class': 'test'}), 4 + 2)
        self.assertEqual(p({'stage': 'images', 'fixed_version': '1.2.4', 'path_class': 'prod'}), 4)
        self.assertLess(p({'stage': 'code', 'path_class': 'prod'}), p({'stage': 'code', 'path_class': 'vendored'}))


class BoardOrderTests(unittest.TestCase):
    def setUp(self):
        isolate_triage(self)
        rid = '20260101T000000-aaaaaaaa'

        def read(_):
            def f(n, path, severity='ERROR'):
                return {'fingerprint': f'{n:024x}', 'rule_id': f'r{n}', 'severity': severity, 'path': path,
                        'line': 1, 'cwe_ids': [], 'owasp_top10_2025': [], 'tool': 'semgrep'}
            return {'id': rid, 'target': 'app', 'state': 'completed', 'created_at': '2026-01-01T00:00:00+00:00',
                    'findings': [f(1, 'tests/test_a.py'), f(2, 'vendor/x/b.py'), f(3, 'app/c.py'),
                                 f(4, 'app/d.py', 'WARNING')]}
        world = {'code': (read, lambda limit: [{'id': rid, 'target': 'app', 'state': 'completed'}], 'target')}
        for name, value in (('sources', lambda: world), ('registered', lambda stage: {'app'} if stage == 'code' else set()),
                            ('chain_rows', lambda stage: []), ('project_of', lambda stage, target: '_app')):
            patcher = patch.object(findings_index, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        findings_index.invalidate()
        self.addCleanup(findings_index.invalidate)

    def test_shipped_code_first_within_a_severity_and_severity_still_first(self):
        rows = findings_index.search()['rows']
        order = [(r['severity_scale'], r['path_class']) for r in rows]
        self.assertEqual(order[0][1], 'prod')
        self.assertEqual(sorted(c for _, c in order[1:3]), ['test', 'vendored'])
        self.assertEqual(order[3][1], 'prod')                        # the WARNING comes after every ERROR
        self.assertNotEqual(order[3][0], order[0][0])


if __name__ == '__main__':
    unittest.main()
