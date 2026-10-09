"""Decisions about findings, and the three things that must stay true about them.

  1. A decision outlives the report it was made from. That is the whole reason
     this store exists: the two mechanisms it replaces were keyed by report and
     evaporated on the next scan.
  2. Nothing is ever inferred. No status is set because a finding stopped
     appearing, and no count is combined into a score.
  3. The audit trail only grows.
"""
import datetime
import http.client
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import Handler
from isolation import isolate_triage
from zanjir import findings, triage
from zanjir.httptest import listener

NOW = datetime.datetime(2026, 9, 23, 12, 0, tzinfo=datetime.timezone.utc)


def finding(fingerprint, severity='HIGH', **extra):
    return {'fingerprint': fingerprint, 'severity': severity, 'rule_id': 'r', 'path': 'a.py', **extra}


class Base(unittest.TestCase):
    def setUp(self):
        self.store = isolate_triage(self)
        # A fixed grouping: the real one is built from five registries and this
        # file is about decisions, not about how projects are discovered.
        patcher = patch.object(triage, 'groups', lambda: {
            'demo': {'stages': {'code': ['demo-src'], 'dependencies': ['demo-src'], 'repository': ['demo'],
                                'images': ['demo-img'], 'web': ['demo-url']}}})
        patcher.start()
        self.addCleanup(patcher.stop)


class ScopeTests(Base):
    def test_a_one_project_covers_its_differently_named_targets(self):
        """crAPI is `crapi-full` for code and `crapi` for Compose; a decision on
        one must be filed under the same project as a decision on the other."""
        self.assertEqual(triage.scope_for('code', 'demo-src'), 'demo')
        self.assertEqual(triage.scope_for('repository', 'demo'), 'demo')
        self.assertEqual(triage.scope_for('images', 'demo-img'), 'demo')

    def test_b_an_ungrouped_target_gets_its_own_scope_not_a_neighbours(self):
        self.assertEqual(triage.scope_for('code', 'boshqa-loyiha'), '_boshqa-loyiha')

    def test_c_an_unusable_target_is_refused(self):
        for bad in ('', '../etc', 'A' * 200, 'x/y'):
            with self.assertRaises(ValueError):
                triage.scope_for('code', bad)


class DecisionTests(Base):
    def test_a_a_decision_survives_a_second_scan(self):
        """The property the whole module exists for."""
        triage.decide('demo', 'a' * 24, 'accepted_risk', 'AX', 'Ichki tarmoqda, xavf qabul qilindi.')
        first = triage.attach('code', 'demo-src', {'findings': [finding('a' * 24)]})
        self.assertEqual(first['findings'][0]['triage']['status'], 'accepted_risk')
        # A later scan produces a brand new report; the decision is still there.
        second = triage.attach('code', 'demo-src', {'id': 'boshqa', 'findings': [finding('a' * 24)]})
        self.assertEqual(second['findings'][0]['triage']['status'], 'accepted_risk')
        self.assertEqual(second['findings'][0]['triage']['owner'], 'AX')

    def test_b_every_status_is_accepted_and_nothing_else_is(self):
        for status in triage.STATUSES:
            with self.subTest(status=status):
                self.assertEqual(triage.decide('demo', 'b' * 24, status, 'AX', 'asos')['status'], status)
        for bad in ('new', 'wontfix', '', 'ACCEPTED_RISK', None):
            with self.assertRaises(ValueError):
                triage.decide('demo', 'b' * 24, bad, 'AX', 'asos')

    def test_c_a_decision_without_an_owner_or_a_reason_is_refused(self):
        for owner, note in (('', 'asos'), ('   ', 'asos'), ('AX', ''), ('AX', '   '), ('AX', 'x' * 1001)):
            with self.assertRaises(ValueError):
                triage.decide('demo', 'c' * 24, 'confirmed', owner, note)

    def test_d_a_malformed_fingerprint_is_refused(self):
        for bad in ('', 'ZZZ', 'a' * 23, 'a' * 25, 'A' * 24):
            with self.assertRaises(ValueError):
                triage.decide('demo', bad, 'confirmed', 'AX', 'asos')

    def test_e_the_audit_trail_only_grows(self):
        for status in ('investigating', 'confirmed', 'fixed'):
            triage.decide('demo', 'd' * 24, status, 'AX', 'asos ' + status)
        events = triage.events('demo')
        self.assertEqual([e['status'] for e in events], ['investigating', 'confirmed', 'fixed'])
        self.assertEqual(len({e['event_id'] for e in events}), 3)
        # The current view holds only the latest; the history holds all of them.
        self.assertEqual(triage.read('demo')['decisions']['d' * 24]['status'], 'fixed')

    def test_f_decisions_of_one_project_do_not_leak_into_another(self):
        triage.decide('demo', 'e' * 24, 'false_positive', 'AX', 'asos')
        other = triage.attach('code', 'boshqa-loyiha', {'findings': [finding('e' * 24)]})
        self.assertIsNone(other['findings'][0]['triage']['status'])


class SuppressionTests(Base):
    def test_a_closed_findings_are_counted_apart_from_open_ones(self):
        triage.decide('demo', 'a' * 24, 'false_positive', 'AX', 'asos')
        triage.decide('demo', 'b' * 24, 'accepted_risk', 'AX', 'asos')
        triage.decide('demo', 'c' * 24, 'investigating', 'AX', 'asos')
        report = triage.attach('code', 'demo-src', {'findings': [
            finding('a' * 24), finding('b' * 24), finding('c' * 24), finding('d' * 24)]})
        summary = report['triage_summary']
        self.assertEqual(summary['total'], 4)
        self.assertEqual(summary['suppressed'], 2)
        self.assertEqual(summary['untriaged'], 1)
        self.assertEqual(summary['open'], 2)          # investigating + untriaged
        self.assertEqual(summary['by_status']['false_positive'], 1)

    def test_b_the_summary_states_that_it_is_not_a_score(self):
        report = triage.attach('code', 'demo-src', {'findings': [finding('a' * 24)]})
        self.assertIn('ball', report['triage_summary']['note'])
        self.assertNotIn('score', json.dumps(report['triage_summary']))

    def test_c_a_finding_without_a_fingerprint_is_counted_as_such(self):
        report = triage.attach('code', 'demo-src', {'findings': [{'rule_id': 'r', 'severity': 'LOW'}]})
        self.assertIsNone(report['findings'][0]['triage'])
        self.assertEqual(report['triage_summary']['no_fingerprint'], 1)


class SlaTests(Base):
    def test_a_each_severity_gets_the_defectdojo_window(self):
        self.assertEqual(triage.SLA_DAYS, {'CRITICAL': 7, 'HIGH': 30, 'MEDIUM': 90, 'LOW': 120})

    def test_b_an_unrated_finding_gets_no_deadline(self):
        """An invented deadline is worse than none."""
        self.assertIsNone(triage.sla(None, NOW.isoformat(), NOW))
        self.assertIsNone(triage.severity_of({'severity': 'UNKNOWN'}))
        self.assertIsNone(triage.sla(triage.severity_of({'severity': 'UNKNOWN'}), NOW.isoformat(), NOW))

    def test_c_a_deadline_is_counted_from_when_the_finding_was_first_seen(self):
        old = (NOW - datetime.timedelta(days=40)).isoformat()
        triage.observe('demo', [finding('a' * 24, 'HIGH')], old)
        report = triage.attach('code', 'demo-src', {'findings': [finding('a' * 24, 'HIGH')]}, at=NOW)
        view = report['findings'][0]['triage']
        self.assertEqual(view['first_seen'], old)
        self.assertTrue(view['sla']['overdue'])
        self.assertEqual(view['sla']['days'], 30)
        self.assertEqual(report['triage_summary']['overdue'], 1)

    def test_d_first_seen_never_moves_forward(self):
        old = (NOW - datetime.timedelta(days=40)).isoformat()
        triage.observe('demo', [finding('a' * 24)], old)
        triage.observe('demo', [finding('a' * 24)], NOW.isoformat())
        seen = triage.read('demo')['seen']['a' * 24]
        self.assertEqual(seen['first_seen'], old)
        self.assertEqual(seen['last_seen'], NOW.isoformat())

    def test_e_a_closed_finding_has_no_deadline(self):
        triage.observe('demo', [finding('a' * 24)], (NOW - datetime.timedelta(days=40)).isoformat())
        triage.decide('demo', 'a' * 24, 'accepted_risk', 'AX', 'asos')
        report = triage.attach('code', 'demo-src', {'findings': [finding('a' * 24)]}, at=NOW)
        self.assertIsNone(report['findings'][0]['triage']['sla'])
        self.assertEqual(report['triage_summary']['overdue'], 0)

    def test_f_each_scanners_own_scale_lands_on_one_scale(self):
        self.assertEqual(triage.severity_of({'severity': 'ERROR'}), 'HIGH')
        self.assertEqual(triage.severity_of({'severity': 'WARNING'}), 'MEDIUM')
        self.assertEqual(triage.severity_of({'severity': 'INFO'}), 'LOW')
        self.assertEqual(triage.severity_of({'level': 'note'}), 'LOW')       # repository SARIF level
        self.assertEqual(triage.severity_of({'level': 'error'}), 'HIGH')

    def test_g_a_scan_that_failed_does_not_start_the_clock(self):
        for state in ('failed', 'cancelled', 'queued', 'running'):
            self.assertFalse(triage.record_scan('code', {'state': state, 'target': 'demo-src',
                                                         'findings': [finding('a' * 24)]}))
        self.assertEqual(triage.read('demo')['seen'], {})
        self.assertTrue(triage.record_scan('code', {'state': 'partial', 'target': 'demo-src',
                                                    'created_at': NOW.isoformat(),
                                                    'findings': [finding('a' * 24)]}))


class BoundDecisionTests(Base):
    """Repository reviews have always expired when the source changed; they still do."""

    def test_a_a_bound_decision_does_not_carry_to_a_changed_source(self):
        triage.decide('demo', 'a' * 24, 'false_positive', 'AX', 'asos', bound_to='snapshot-1')
        same = triage.attach('repository', 'demo', {'input_sha256': 'snapshot-1', 'findings': [finding('a' * 24)]})
        self.assertEqual(same['findings'][0]['triage']['status'], 'false_positive')
        self.assertFalse(same['findings'][0]['triage']['stale'])
        changed = triage.attach('repository', 'demo', {'input_sha256': 'snapshot-2', 'findings': [finding('a' * 24)]})
        view = changed['findings'][0]['triage']
        self.assertIsNone(view['status'])
        self.assertTrue(view['stale'])
        self.assertTrue(view['open'])
        self.assertEqual(changed['triage_summary']['suppressed'], 0)

    def test_b_an_unbound_decision_carries_everywhere(self):
        triage.decide('demo', 'a' * 24, 'false_positive', 'AX', 'asos')
        for snapshot in ('snapshot-1', 'snapshot-2', None):
            report = triage.attach('repository', 'demo', {'input_sha256': snapshot, 'findings': [finding('a' * 24)]})
            self.assertEqual(report['findings'][0]['triage']['status'], 'false_positive')


class MigrationTests(Base):
    """The two old stores are read, never rewritten."""

    def setUp(self):
        super().setUp()
        self.runs = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.runs, True)

    def dependency_review(self, with_fingerprint):
        from zanjir import dependencies
        run = self.runs / '20260101T000000-aaaaaaaa'
        run.mkdir(parents=True)
        row = {'id': 'oldid0000000000000000000', 'package': {'ecosystem': 'PyPI', 'name': 'flask', 'version': '2.0'},
               'advisory_id': 'CVE-2026-1', 'severity': 'HIGH'}
        if with_fingerprint:
            row['fingerprint'] = findings.fingerprint(
                'dependencies', {'ecosystem': 'PyPI', 'package': 'flask', 'advisory_id': 'CVE-2026-1'})
        (run / 'report.json').write_text(json.dumps({'id': run.name, 'target': 'demo-src', 'findings': [row]}),
                                         encoding='utf-8')
        (run / 'reviews.json').write_text(json.dumps({'inventory_sha256': 'x', 'findings': {
            'oldid0000000000000000000': {'status': 'accepted_risk', 'owner': 'Zanjir QA',
                                         'note': 'Eski qaror', 'updated_at': '2026-01-01T00:00:00+00:00'}}}),
            encoding='utf-8')
        return patch.object(dependencies, 'RUNS', self.runs), run

    def test_a_an_old_review_is_imported_and_the_source_is_left_alone(self):
        patcher, run = self.dependency_review(with_fingerprint=True)
        before = (run / 'reviews.json').read_bytes()
        with patcher:
            result = triage.migrate()
        self.assertEqual(result['count'], 1)
        self.assertEqual((run / 'reviews.json').read_bytes(), before, 'manba fayl o‘zgargan')
        self.assertTrue((run / triage.MARKER).is_file())
        stored = triage.read('demo')['decisions']
        self.assertEqual(list(stored.values())[0]['status'], 'accepted_risk')
        self.assertEqual(list(stored.values())[0]['owner'], 'Zanjir QA')

    def test_b_a_pre_b1_report_still_migrates_because_the_identity_is_recomputed(self):
        patcher, _ = self.dependency_review(with_fingerprint=False)
        with patcher:
            self.assertEqual(triage.migrate()['count'], 1)
        expected = findings.fingerprint('dependencies', {'ecosystem': 'PyPI', 'package': 'flask',
                                                         'advisory_id': 'CVE-2026-1'})
        self.assertIn(expected, triage.read('demo')['decisions'])

    def test_c_running_it_twice_imports_nothing_twice(self):
        patcher, _ = self.dependency_review(with_fingerprint=True)
        with patcher:
            self.assertEqual(triage.migrate()['count'], 1)
            self.assertEqual(triage.migrate()['count'], 0)
        self.assertEqual(len(triage.events('demo')), 1)

    def test_d_a_dry_run_writes_nothing(self):
        patcher, run = self.dependency_review(with_fingerprint=True)
        with patcher:
            result = triage.migrate(dry_run=True)
        self.assertEqual(result['count'], 1)
        self.assertTrue(result['dry_run'])
        self.assertFalse((run / triage.MARKER).is_file())
        self.assertEqual(triage.read('demo')['decisions'], {})

    def test_e_a_newer_decision_is_never_overwritten_by_an_old_review(self):
        patcher, _ = self.dependency_review(with_fingerprint=True)
        fingerprint = findings.fingerprint('dependencies', {'ecosystem': 'PyPI', 'package': 'flask',
                                                            'advisory_id': 'CVE-2026-1'})
        triage.decide('demo', fingerprint, 'confirmed', 'AX', 'yangi qaror')
        with patcher:
            triage.migrate()
        self.assertEqual(triage.read('demo')['decisions'][fingerprint]['status'], 'confirmed')


class ApiTests(unittest.TestCase):
    """The endpoints, including the checks that stop an unverifiable decision."""

    def setUp(self):
        isolate_triage(self)
        self.report = {'id': '20260101T000000-aaaaaaaa', 'target': 'demo-src', 'state': 'completed',
                       'findings': [finding('a' * 24), finding('b' * 24)]}
        self.patchers = [
            patch.object(triage, 'groups', lambda: {'demo': {'stages': {'code': ['demo-src']}}}),
            patch.object(triage, 'readers', lambda: {'code': (lambda rid: self.report, 'target')}),
        ]
        for patcher in self.patchers:
            patcher.start()
            self.addCleanup(patcher.stop)
        self.server = listener(Handler)
        self.url = self.server.__enter__()
        self.addCleanup(self.server.__exit__, None, None, None)
        self.port = int(self.url.rsplit(':', 1)[1])

    def call(self, method, path, payload=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=15)
        try:
            body = json.dumps(payload) if payload is not None else None
            connection.request(method, path, body=body, headers={'Content-Type': 'application/json'})
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def decision(self, **extra):
        return {'stage': 'code', 'report_id': self.report['id'], 'status': 'accepted_risk',
                'owner': 'AX', 'note': 'Ichki tarmoq; xavf qabul qilindi.', **extra}

    def test_a_one_decision_is_stored_and_read_back(self):
        status, body = self.call('POST', '/api/triage', self.decision(fingerprint='a' * 24))
        self.assertEqual(status, 200, body)
        self.assertEqual(body['scope'], 'demo')
        status, overview = self.call('GET', '/api/triage/demo')
        self.assertEqual(status, 200)
        self.assertEqual([row['fingerprint'] for row in overview['decisions']], ['a' * 24])
        self.assertEqual(overview['sla_days'], triage.SLA_DAYS)

    def test_b_many_decisions_in_one_call(self):
        status, body = self.call('POST', '/api/triage/bulk',
                                 self.decision(fingerprints=['a' * 24, 'b' * 24]))
        self.assertEqual(status, 200, body)
        self.assertEqual(sorted(body['decisions']), ['a' * 24, 'b' * 24])

    def test_b2_a_bulk_decision_writes_the_decisions_file_once(self):
        # The whole batch is one file write, not one per finding (load-test #6).
        with patch.object(triage, 'write', wraps=triage.write) as writer:
            status, _ = self.call('POST', '/api/triage/bulk',
                                  self.decision(fingerprints=['a' * 24, 'b' * 24]))
        self.assertEqual(status, 200)
        self.assertEqual(writer.call_count, 1)

    def test_c_a_fingerprint_that_is_not_in_the_report_is_refused(self):
        status, body = self.call('POST', '/api/triage', self.decision(fingerprint='f' * 24))
        self.assertEqual(status, 400)
        self.assertIn('yo‘q', body['error'])
        self.assertEqual(triage.read('demo')['decisions'], {})

    def test_d_malformed_requests_are_refused(self):
        for payload in (self.decision(),                                        # na fingerprint, na fingerprints
                        self.decision(fingerprint='a' * 24, fingerprints=['b' * 24]),
                        self.decision(fingerprint='a' * 24, status='wontfix'),
                        self.decision(fingerprint='a' * 24, owner=''),
                        self.decision(fingerprint='a' * 24, stage='nessus'),
                        self.decision(fingerprints=['a' * 24] * 201)):
            status, body = self.call('POST', '/api/triage', payload)
            self.assertEqual(status, 400, payload)
            self.assertIn('error', body)

    def test_e_an_unknown_project_and_an_unknown_action_are_refused(self):
        self.assertEqual(self.call('GET', '/api/triage/../etc')[0], 400)
        self.assertEqual(self.call('POST', '/api/triage/nimadir', self.decision(fingerprint='a' * 24))[0], 404)

    def test_f_a_stored_decision_shows_on_the_report(self):
        self.call('POST', '/api/triage', self.decision(fingerprint='a' * 24))
        attached = triage.attach('code', 'demo-src', self.report)
        self.assertEqual(attached['findings'][0]['triage']['status'], 'accepted_risk')
        self.assertEqual(attached['triage_summary']['suppressed'], 1)


if __name__ == '__main__':
    unittest.main()
