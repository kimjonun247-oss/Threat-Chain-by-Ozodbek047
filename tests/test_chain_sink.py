"""Chains are cut per (rule, service) as they are built (shortcomings review 2026-11-02, LP#4).

correlate_all used to build every services x findings pair and cut afterwards:
100 whole-repository services x 5 000 findings measured 1.2 GB and three minutes
to keep 10 000. ChainSink applies the same cut while the chains arrive. These
tests hold it to the old algorithm exactly -- same chains, same order, same gaps.
"""
import json
import random
import unittest

from zanjir import chains
from test_chains import service, weakness


def old_limit_per_service(findings):
    """The previous implementation, verbatim in behaviour: group, sort the whole group, cut."""
    groups = {}
    for finding in findings:
        groups.setdefault((finding.get('rule_id'), finding.get('service_id')), []).append(finding)
    kept, gaps = [], []
    for (rule, svc), members in groups.items():
        if len(members) > chains.CHAIN_LIMIT:
            members = sorted(members, key=lambda f: (0 if f.get('level') == 'error' else 1,
                                                     json.dumps(f.get('evidence'), sort_keys=True, default=str),
                                                     str(f.get('fingerprint'))))
            gaps.append({'rule_id': rule, 'service': svc, 'total': len(members)})
            members = members[:chains.CHAIN_LIMIT]
        kept += members
    return kept, gaps


def synthetic(rng, count):
    rows = []
    for n in range(count):
        rows.append({'rule_id': rng.choice(['SX-001', 'SX-004', 'SX-007']),
                     'service_id': rng.choice(['web', 'api', 'worker', 'tiny']),
                     'level': rng.choice(['error', 'warning']),
                     'fingerprint': f'{rng.randrange(400):04d}',          # deliberate duplicates / ties
                     'evidence': {'code_path': f'a/{rng.randrange(60)}.py:{rng.randrange(9)}'}})
    # 'tiny' groups stay under the limit and must keep their arrival order.
    return rows


class EquivalenceTests(unittest.TestCase):
    def test_a_same_kept_chains_same_order_same_gaps_as_the_old_cut(self):
        for seed in range(25):
            rng = random.Random(seed)
            rows = synthetic(rng, rng.randrange(1, 1500))
            old_kept, old_gaps = old_limit_per_service(rows)
            sink = chains.ChainSink()
            sink.extend(rows)
            new_kept, new_gaps = sink.finish()
            self.assertEqual([id(f) for f in new_kept], [id(f) for f in old_kept], seed)
            self.assertEqual([(g['rule_id'], g['service'], g['total']) for g in new_gaps],
                             [(g['rule_id'], g['service'], g['total']) for g in old_gaps], seed)

    def test_b_a_group_never_holds_more_than_twice_the_limit(self):
        sink = chains.ChainSink()
        for n in range(10 * chains.CHAIN_LIMIT):
            sink.append({'rule_id': 'SX-004', 'service_id': 'web', 'level': 'error', 'fingerprint': str(n),
                         'evidence': {'n': n}})
            self.assertLessEqual(len(sink.groups[('SX-004', 'web')]), 2 * chains.CHAIN_LIMIT)
        kept, gaps = sink.finish()
        self.assertEqual(len(kept), chains.CHAIN_LIMIT)
        self.assertEqual(gaps[0]['total'], 10 * chains.CHAIN_LIMIT)


class ScaleTests(unittest.TestCase):
    def test_whole_repository_services_x_many_findings_keep_only_the_cut(self):
        repo = {'services': [service(f's{i}', '.') for i in range(40)], 'findings': []}
        code = {'findings': [weakness(f'app/m{i}.py', line=i + 1) for i in range(600)]}
        out = chains.correlate_all({'code': code, 'repository': repo, 'dependencies': None})
        sx004 = [f for f in out['findings'] if f['rule_id'] == 'SX-004']
        self.assertEqual(len(sx004), 40 * chains.CHAIN_LIMIT)
        limits = [g for g in out['gaps'] if g.get('kind') == 'chain_limit' and g['rule_id'] == 'SX-004']
        self.assertEqual(len(limits), 40)
        self.assertTrue(all(g['total'] == 600 for g in limits))

    def test_the_builders_still_return_a_list_when_called_alone(self):
        rows = chains.code_weakness_chains({'findings': [weakness('svc/web/db.py')]},
                                           {'services': [service('web', 'svc/web')]})
        self.assertEqual(len(rows), 1)


if __name__ == '__main__':
    unittest.main()
