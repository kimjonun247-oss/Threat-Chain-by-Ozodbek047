"""Every decision about a finding lands in one store, the one every page reads.

UI review 2026-11-04 found two ways a decision went missing:

  - A chain finding (SX-00X) could not be decided at all. The board sent it as
    a Compose decision with the assessment's id, the server looked for a Compose
    report of that id and answered 404. The assessment view and the board also
    disagreed on whose store a chain decision lives in (code target vs Compose
    target), so a stored one would not have shown on both.
  - The Compose and CVE pages saved into their own per-report review files.
    The board, the dashboard and the project page never read those: a risk
    accepted on the Compose page still counted as "not reviewed" everywhere.
"""
import http.client
import json
import unittest
from unittest.mock import patch

from app import Handler
from isolation import isolate_triage
from zanjir import findings_index, pipeline, triage
from zanjir.httptest import listener

CHAIN_FP = 'c' * 24
DEP_FP = 'd' * 24
REPO_FP = 'e' * 24

ASSESSMENT = {'id': '20261013T060120-60c4ce34', 'state': 'completed',
              'stages': [{'kind': 'code', 'target': 'other-src'}, {'kind': 'repository', 'target': 'demo'}],
              'chain_findings': [{'fingerprint': CHAIN_FP, 'rule_id': 'SX-001', 'level': 'error',
                                  'title': 'Sir va ochiq port'}]}
COMPOSE = {'id': '20261013T060121-aaaaaaaa', 'profile_id': 'demo', 'input_sha256': 'f' * 64,
           'findings': [{'fingerprint': REPO_FP, 'rule_id': 'RP-001', 'level': 'warning'}]}
CVE = {'id': '20261013T060122-bbbbbbbb', 'target': 'demo-src',
       'findings': [{'id': 'GHSA-1', 'fingerprint': DEP_FP, 'severity': 'HIGH'}]}


class Base(unittest.TestCase):
    def setUp(self):
        isolate_triage(self)
        # The Compose target belongs to project "demo"; the code target of the
        # same assessment belongs to no project. That is what tells the two old
        # rules apart: one of them found the decision, the other did not.
        for patcher in (
                patch.object(triage, 'groups', lambda: {'demo': {'stages': {'repository': ['demo'],
                                                                            'dependencies': ['demo-src']}}}),
                patch.object(triage, 'readers', lambda: {
                    'repository': (lambda rid: COMPOSE, 'profile_id'),
                    'dependencies': (lambda rid: CVE, 'target')}),
                patch.object(pipeline, 'read', lambda rid: ASSESSMENT),
                patch.object(pipeline, 'history', lambda limit=30: [{'id': ASSESSMENT['id'], 'state': 'completed'}]),
                patch.object(findings_index, 'triage_changed', lambda scope, fps: None)):
            patcher.start()
            self.addCleanup(patcher.stop)

    @staticmethod
    def decision(**fields):
        return {'status': 'accepted_risk', 'owner': 'AX', 'note': 'Ichki tarmoq; xavf qabul qilindi.', **fields}


class ChainDecisionTests(Base):
    def test_a_a_chain_finding_can_be_decided(self):
        stored = triage.apply(self.decision(stage='chain', report_id=ASSESSMENT['id'], fingerprint=CHAIN_FP))
        self.assertEqual(stored['scope'], 'demo')
        self.assertIn(CHAIN_FP, triage.read('demo')['decisions'])

    def test_b_the_assessment_view_shows_the_decision(self):
        triage.apply(self.decision(stage='chain', report_id=ASSESSMENT['id'], fingerprint=CHAIN_FP))
        chain = pipeline.attach_triage(ASSESSMENT)['chain_findings']
        self.assertEqual(chain[0]['triage']['status'], 'accepted_risk')

    def test_c_the_board_files_the_chain_under_the_same_project(self):
        rows = findings_index.chain_rows('repository')
        self.assertEqual([row['project'] for row in rows], ['demo'])

    def test_c2_the_board_keeps_the_chains_original_for_the_detail_panel(self):
        # It stored none, so every chain's panel said "Asl yozuv topilmadi".
        from zanjir import findings_store
        rows = findings_index.chain_rows('repository')
        self.assertEqual(rows[0]['_finding']['rule_id'], 'SX-001')
        self.assertNotIn('triage', rows[0]['_finding'])
        item = dict(rows[0])
        record = findings_store.record(item, item.pop('_finding'), None)
        self.assertIn('SX-001', record[-1])
        self.assertNotIn('_finding', record[-2])

    def test_d_a_fingerprint_that_is_not_a_chain_of_that_assessment_is_refused(self):
        with self.assertRaises(ValueError):
            triage.apply(self.decision(stage='chain', report_id=ASSESSMENT['id'], fingerprint='9' * 24))

    def test_e_an_assessment_with_no_compose_or_code_stage_is_refused_plainly(self):
        with patch.object(pipeline, 'read', lambda rid: {'id': rid, 'stages': [], 'chain_findings': []}):
            with self.assertRaisesRegex(ValueError, 'Compose yoki kod'):
                triage.apply(self.decision(stage='chain', report_id=ASSESSMENT['id'], fingerprint=CHAIN_FP))


class LegacyEndpointTests(Base):
    def test_a_a_compose_page_decision_lands_in_the_one_store(self):
        triage.from_legacy('repository', self.decision(report_id=COMPOSE['id'], fingerprint=REPO_FP))
        decision = triage.read('demo')['decisions'][REPO_FP]
        self.assertEqual(decision['status'], 'accepted_risk')
        # Bound to the source snapshot, as Compose reviews always were.
        self.assertEqual(decision['bound_to'], COMPOSE['input_sha256'])

    def test_b_a_cve_page_decision_is_found_by_its_finding_id(self):
        triage.from_legacy('dependencies', self.decision(report_id=CVE['id'], finding_id='GHSA-1',
                                                         status='fix_planned'))
        self.assertEqual(triage.read('demo')['decisions'][DEP_FP]['status'], 'fix_planned')

    def test_c_new_is_not_a_decision_and_unknown_fields_are_refused(self):
        for stage, payload in (('repository', self.decision(report_id=COMPOSE['id'], fingerprint=REPO_FP, status='new')),
                               ('repository', self.decision(report_id=COMPOSE['id'], fingerprint=REPO_FP, extra='x')),
                               ('dependencies', self.decision(report_id=CVE['id'], finding_id='GHSA-404'))):
            with self.assertRaises(ValueError):
                triage.from_legacy(stage, payload)
        self.assertEqual(triage.read('demo')['decisions'], {})


class LegacyHttpTests(Base):
    def setUp(self):
        super().setUp()
        server = listener(Handler)
        url = server.__enter__()
        self.addCleanup(server.__exit__, None, None, None)
        self.port = int(url.rsplit(':', 1)[1])

    def post(self, path, payload):
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=60)
        try:
            connection.request('POST', path, body=json.dumps(payload), headers={'Content-Type': 'application/json'})
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def test_a_both_old_endpoints_write_where_the_board_reads(self):
        status, body = self.post('/api/repository/review', self.decision(report_id=COMPOSE['id'], fingerprint=REPO_FP))
        self.assertEqual(status, 200, body)
        # An old client reads the saved record itself: status and updated_at.
        self.assertEqual(body['status'], 'accepted_risk')
        self.assertTrue(body['updated_at'])
        status, body = self.post('/api/dependencies/review', self.decision(report_id=CVE['id'], finding_id='GHSA-1'))
        self.assertEqual(status, 200, body)
        self.assertEqual((body['status'], body['finding_id']), ('accepted_risk', 'GHSA-1'))
        self.assertEqual(sorted(triage.read('demo')['decisions']), sorted([REPO_FP, DEP_FP]))

    def test_b_the_triage_endpoint_takes_a_chain_decision(self):
        status, body = self.post('/api/triage', self.decision(stage='chain', report_id=ASSESSMENT['id'],
                                                               fingerprint=CHAIN_FP))
        self.assertEqual(status, 200, body)


if __name__ == '__main__':
    unittest.main()
