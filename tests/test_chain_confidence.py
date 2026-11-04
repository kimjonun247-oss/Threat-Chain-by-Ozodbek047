"""Every chain says why it exists and how far to trust it (PLAN.md 3.3).

Each chain rule gets a positive case (the chain is built, its `why` names each
link with the scanner that reported it, its confidence is the documented one)
and negative cases where a chain must NOT be built: the finding sits in test or
vendored code, the service is reachable only on loopback, the file is outside
the service's build context.
"""
import unittest

from zanjir import chains
from test_chains import cve, exposed, gitleaks, image_report, links, service, weakness


def everything(code=None, repository=None, deps=None, images=None, link_map=None):
    return chains.correlate_all({'code': code, 'repository': repository, 'dependencies': deps},
                                links=link_map, image_reports=images)['findings']


def repo(*services, findings=()):
    return {'services': list(services), 'findings': list(findings)}


class WhyAndConfidenceTests(unittest.TestCase):
    def one(self, rows, rule):
        picked = [r for r in rows if r['rule_id'] == rule]
        self.assertEqual(len(picked), 1, [r['rule_id'] for r in rows])
        row = picked[0]
        self.assertIn(row['confidence']['level'], ('low', 'medium', 'high'))
        self.assertTrue(row['confidence']['reasons'])
        self.assertGreaterEqual(len(row['why']), 2, row['why'])
        return row

    # -- SX-001 ---------------------------------------------------------------------
    def test_sx001_provider_key_is_high_generic_is_low(self):
        aws = self.one(everything({'findings': [gitleaks('svc/web/a.py', rule_id='aws-access-token')]},
                                  repo(service('web', 'svc/web'))), 'SX-001')
        self.assertEqual(aws['confidence']['level'], 'high')
        self.assertTrue(any(w.startswith('Gitleaks aws-access-token: svc/web/a.py:5') for w in aws['why']), aws['why'])
        self.assertTrue(any('host portidan ochiq' in w for w in aws['why']))
        generic = self.one(everything({'findings': [gitleaks('svc/web/a.py')]}, repo(service('web', 'svc/web'))), 'SX-001')
        self.assertEqual(generic['confidence']['level'], 'low')

    def test_sx001_negatives(self):
        for code, services in (({'findings': [gitleaks('svc/web/tests/fixtures/k.py', rule_id='aws-access-token')]},
                                [service('web', 'svc/web')]),                                  # test code
                               ({'findings': [gitleaks('svc/web/a.py', rule_id='aws-access-token')]},
                                [service('web', 'svc/web', loopback=True)]),                   # loopback only
                               ({'findings': [gitleaks('svc/api/a.py', rule_id='aws-access-token')]},
                                [service('web', 'svc/web')])):                                 # other service
            self.assertEqual([r for r in everything(code, repo(*services)) if r['rule_id'] == 'SX-001'], [])

    # -- SX-004 ---------------------------------------------------------------------
    def test_sx004_whole_repository_context_is_low(self):
        scoped = self.one(everything({'findings': [weakness('svc/web/db.py')]}, repo(service('web', 'svc/web'))), 'SX-004')
        self.assertEqual(scoped['confidence']['level'], 'medium')
        self.assertTrue(any('semgrep sql-injection (CWE-89): svc/web/db.py:42' in w for w in scoped['why']), scoped['why'])
        whole = self.one(everything({'findings': [weakness('svc/web/db.py')]}, repo(service('web', '.'))), 'SX-004')
        self.assertEqual(whole['confidence']['level'], 'low')
        self.assertTrue(any('butun repozitoriy' in r for r in whole['confidence']['reasons']))
        warning = self.one(everything({'findings': [weakness('svc/web/db.py', severity='WARNING')]},
                                      repo(service('web', 'svc/web'))), 'SX-004')
        self.assertEqual(warning['confidence']['level'], 'low')

    def test_sx004_negatives(self):
        for finding in (weakness('svc/web/vendor/lib/db.py'), weakness('svc/web/db.py', cwe='CWE-327'),
                        weakness('svc/web/db.py', severity='INFO'), weakness('svc/web/test_db.py')):
            rows = everything({'findings': [finding]}, repo(service('web', 'svc/web')))
            self.assertEqual([r for r in rows if r['rule_id'] == 'SX-004'], [], finding)

    # -- SX-002 / SX-003 ----------------------------------------------------------------
    def test_sx002_kev_is_high_but_a_name_only_link_brings_it_down(self):
        declared = self.one(everything(repository=repo(exposed()), images={'img-app': image_report([cve(exploited=True)])},
                                       link_map=links(how='declared')), 'SX-002')
        self.assertEqual(declared['confidence']['level'], 'high')
        self.assertTrue(any('CISA KEV' in w for w in declared['why']))
        by_name = self.one(everything(repository=repo(exposed()), images={'img-app': image_report([cve(exploited=True)])},
                                      link_map=links(how='image_name')), 'SX-002')
        self.assertEqual(by_name['confidence']['level'], 'low')

    def test_sx003_needs_debug_and_a_fix(self):
        debug = {'rule_id': 'RP-006', 'service_id': 'web'}
        rows = everything(repository=repo(exposed(), findings=[debug]),
                          images={'img-app': image_report([cve(exploited=True, fixed='1.0.1')])},
                          link_map=links(how='declared'))
        row = self.one(rows, 'SX-003')
        self.assertTrue(any('RP-006' in w for w in row['why']))
        no_fix = everything(repository=repo(exposed(), findings=[debug]),
                            images={'img-app': image_report([cve(exploited=True)])}, link_map=links(how='declared'))
        self.assertEqual([r for r in no_fix if r['rule_id'] == 'SX-003'], [])

    def test_sx002_negatives(self):
        for services, findings in (([exposed(ports=(('127.0.0.1', '8080', 8080, 'loopback'),))], [cve(exploited=True)]),
                                   ([exposed()], [cve(severity='MEDIUM')])):
            rows = everything(repository=repo(*services), images={'img-app': image_report(findings)},
                              link_map=links(how='declared'))
            self.assertEqual([r for r in rows if r['rule_id'] in ('SX-002', 'SX-003')], [])

    # -- SX-007 ---------------------------------------------------------------------
    def test_sx007_names_the_escape_and_the_entry(self):
        rows = everything({'findings': [weakness('svc/web/db.py')]},
                          repo(service('web', 'svc/web'), findings=[{'rule_id': 'RP-008', 'service_id': 'web'}]))
        row = self.one(rows, 'SX-007')
        self.assertTrue(any('RP-007' in w and 'RP-008' in w for w in row['why']))
        none = everything({'findings': [weakness('svc/web/db.py')]}, repo(service('web', 'svc/web')))
        self.assertEqual([r for r in none if r['rule_id'] == 'SX-007'], [])

    # -- general ---------------------------------------------------------------------------
    def test_confidence_never_changes_level_or_identity(self):
        code = {'findings': [weakness('svc/web/db.py')]}
        plain = chains.code_weakness_chains(code, repo(service('web', 'svc/web')))[0]
        assessed = self.one(everything(code, repo(service('web', 'svc/web'))), 'SX-004')
        self.assertEqual((assessed['level'], assessed['fingerprint']), (plain['level'], plain['fingerprint']))


if __name__ == '__main__':
    unittest.main()
