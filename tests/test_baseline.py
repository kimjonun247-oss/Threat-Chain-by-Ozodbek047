"""A gate that only judges what a change introduced -- and the honesty rules that keep it usable.

The old gate counted every gate-relevant finding in the run. On a project that
already has a hundred, that gate fails on day one and gets switched off, which
is worse than no gate at all. The baseline mode fixes that, and these tests
protect the three ways it could fix it dishonestly:

  - by comparing against a scan that covered less,
  - by treating a finding it cannot identify as old,
  - by calling a disappeared finding fixed.
"""
import unittest
from unittest.mock import patch

from isolation import isolate_triage
from zanjir import baseline, ci_gate, triage


def code(fingerprint, rule='r', severity='ERROR', tool='semgrep', path='a.py', line=1, **extra):
    return {'fingerprint': fingerprint, 'rule_id': rule, 'severity': severity, 'tool': tool,
            'path': path, 'line': line, **extra}


def assessment(findings, state='completed', rid='20260101T000000-aaaaaaaa', chain=(), selection=None):
    return {'id': rid, 'state': state, 'selection': selection or {'target': 'app'},
            'stages': [{'kind': 'code', 'target': 'app', 'report': {'findings': list(findings)}}],
            'chain_findings': list(chain)}


class DiffTests(unittest.TestCase):
    def test_a_findings_are_matched_by_identity_not_by_count(self):
        before = assessment([code('a' * 24), code('b' * 24)])
        after = assessment([code('b' * 24), code('c' * 24)], rid='20260102T000000-bbbbbbbb')
        result = baseline.diff(before, after)
        self.assertEqual([row['fingerprint'] for row in result['new']], ['c' * 24])
        self.assertEqual([row['fingerprint'] for row in result['gone']], ['a' * 24])
        self.assertEqual(result['counts'], {'new': 1, 'gone': 1, 'unchanged': 1})

    def test_b_a_disappeared_finding_is_never_called_fixed(self):
        result = baseline.diff(assessment([code('a' * 24)]), assessment([]))
        self.assertEqual(result['counts']['gone'], 1)
        self.assertNotIn('fixed', str(result).lower())
        self.assertIn('tuzatilgan degani emas', result['note'])

    def test_c_an_incomplete_baseline_is_reported_not_smoothed_over(self):
        result = baseline.diff(assessment([], state='partial'), assessment([code('a' * 24)]))
        self.assertTrue(any('partial' in w for w in result['warnings']))

    def test_d_shrinking_coverage_in_the_current_run_is_reported(self):
        result = baseline.diff(assessment([code('a' * 24)]), assessment([], state='partial'))
        self.assertTrue(any('kamroq qamrab' in w for w in result['warnings']))

    def test_e_findings_with_no_identity_are_counted_apart(self):
        before = assessment([{'rule_id': 'r'}])
        after = assessment([{'rule_id': 'r'}, code('a' * 24)])
        result = baseline.diff(before, after)
        self.assertEqual(result['counts']['new'], 1)
        self.assertTrue(any('Identifikatorsiz' in w for w in result['warnings']))

    def test_f_chain_findings_take_part_in_the_comparison(self):
        after = assessment([], chain=[{'fingerprint': 'f' * 24, 'rule_id': 'SX-001'}])
        result = baseline.diff(assessment([]), after)
        self.assertEqual([row['stage'] for row in result['new']], ['chain'])


class LastGreenTests(unittest.TestCase):
    def rows(self):
        return [{'id': '4', 'target': 'app', 'state': 'partial'},
                {'id': '3', 'target': 'app', 'state': 'completed'},
                {'id': '2', 'target': 'boshqa', 'state': 'completed'},
                {'id': '1', 'target': 'app', 'state': 'completed'}]

    def test_a_the_newest_completed_scan_of_the_same_target_wins(self):
        with patch.object(baseline, 'history_rows', lambda stage, limit=None: self.rows()):
            self.assertEqual(baseline.since_last_green('code', 'app'), '3')

    def test_b_scans_newer_than_the_one_being_judged_are_not_used(self):
        with patch.object(baseline, 'history_rows', lambda stage, limit=None: self.rows()):
            self.assertEqual(baseline.since_last_green('code', 'app', before_id='3'), '1')

    def test_c_an_unfinished_scan_is_never_a_baseline(self):
        """It proves nothing about what it did not reach."""
        rows = [{'id': '2', 'target': 'app', 'state': 'partial'},
                {'id': '1', 'target': 'app', 'state': 'failed'}]
        with patch.object(baseline, 'history_rows', lambda stage, limit=None: rows):
            self.assertIsNone(baseline.since_last_green('code', 'app'))

    def test_d_an_unknown_stage_is_refused(self):
        with self.assertRaises(ValueError):
            baseline.history_rows('nessus')


class DuplicateTests(unittest.TestCase):
    """Two scanners on one line is one issue reported twice -- linked, never merged."""

    def rows(self):
        return [code('a' * 24, 'detected-stripe-api-key', tool='semgrep', path='app/config.py', line=7),
                code('b' * 24, 'stripe-access-token', tool='gitleaks', path='app/config.py', line=7),
                code('c' * 24, 'missing-user', tool='semgrep', path='app/Dockerfile', line=5)]

    def test_a_the_second_scanner_links_to_the_first_and_both_stay(self):
        rows = self.rows()
        self.assertEqual(baseline.link_duplicates(rows), 1)
        self.assertEqual(rows[0]['duplicate_of'], 'b' * 24)      # gitleaks is the primary
        self.assertNotIn('duplicate_of', rows[1])
        self.assertNotIn('duplicate_of', rows[2])
        self.assertEqual(len(rows), 3, 'hech narsa birlashtirilmasligi kerak')

    def test_b_the_primary_is_the_same_on_every_run(self):
        first = self.rows()
        second = list(reversed(self.rows()))
        baseline.link_duplicates(first)
        baseline.link_duplicates(second)
        self.assertEqual({f['rule_id']: f.get('duplicate_of') for f in first},
                         {f['rule_id']: f.get('duplicate_of') for f in second})

    def test_c_one_scanner_twice_on_a_line_is_not_a_duplicate(self):
        rows = [code('a' * 24, 'r1', tool='semgrep'), code('b' * 24, 'r2', tool='semgrep')]
        self.assertEqual(baseline.link_duplicates(rows), 0)

    def test_d_different_lines_are_never_linked(self):
        rows = [code('a' * 24, tool='semgrep', line=7), code('b' * 24, tool='gitleaks', line=8)]
        self.assertEqual(baseline.link_duplicates(rows), 0)


class GateTests(unittest.TestCase):
    def setUp(self):
        isolate_triage(self)

    def report(self, findings, **kwargs):
        return assessment(findings, **kwargs)

    def test_a_without_the_new_flags_the_gate_counts_what_it_always_counted(self):
        """The regression test for the promise that default behaviour is unchanged."""
        report = self.report([code('a' * 24, severity='ERROR'), code('b' * 24, severity='WARNING')])
        result = ci_gate.evaluate(report)
        self.assertEqual(result['count'], 1)                  # ERROR counts, WARNING does not
        self.assertFalse(result['passed'])
        self.assertEqual(result['fail_on'], 'any')
        self.assertTrue(ci_gate.evaluate(report, allow=1)['passed'])

    def test_b_a_new_finding_stops_the_build_and_an_old_one_does_not(self):
        before = self.report([code('a' * 24)])
        after = self.report([code('a' * 24), code('c' * 24)], rid='20260102T000000-bbbbbbbb')
        self.assertFalse(ci_gate.evaluate(after, baseline=before, fail_on='new')['passed'])
        unchanged = self.report([code('a' * 24)], rid='20260102T000000-bbbbbbbb')
        result = ci_gate.evaluate(unchanged, baseline=before, fail_on='new')
        self.assertTrue(result['passed'])
        self.assertEqual(result['count'], 0)
        self.assertEqual(result['total'], 1, 'eski topilma yo‘qolmasligi kerak, faqat sanalmaydi')

    def test_c_severity_narrows_which_new_findings_count(self):
        before = self.report([])
        after = self.report([code('a' * 24, severity='ERROR'),          # -> HIGH
                             code('b' * 24, tool='gitleaks', severity=None)])
        self.assertEqual(ci_gate.evaluate(after, baseline=before, fail_on='new')['count'], 2)
        self.assertEqual(ci_gate.evaluate(after, baseline=before, fail_on='new-high')['count'], 1)
        self.assertEqual(ci_gate.evaluate(after, baseline=before, fail_on='new-critical')['count'], 0)

    def test_d_a_finding_with_no_identity_is_always_counted(self):
        """It cannot be shown to be old, so the gate never guesses towards passing."""
        before = self.report([])
        after = self.report([{'rule_id': 'r', 'tool': 'gitleaks', 'path': 'a.py'}])
        result = ci_gate.evaluate(after, baseline=before, fail_on='new-critical')
        self.assertEqual(result['count'], 1)
        self.assertEqual(result['hits'][0]['why'], 'identifikatorsiz')

    def test_e_a_missing_baseline_is_refused_not_passed(self):
        for bad in (None, '', []):
            with self.assertRaises(ValueError):
                ci_gate.evaluate(self.report([]), baseline=bad, fail_on='new')

    def test_f_an_unknown_fail_mode_is_refused(self):
        with self.assertRaises(ValueError):
            ci_gate.evaluate(self.report([]), fail_on='maybe')

    def test_g_respect_triage_drops_closed_findings_and_says_so(self):
        closed = code('a' * 24)
        closed['triage'] = {'suppressed': True, 'status': 'accepted_risk'}
        report = self.report([closed, code('b' * 24)])
        self.assertEqual(ci_gate.evaluate(report)['count'], 2)
        result = ci_gate.evaluate(report, respect_triage=True)
        self.assertEqual(result['count'], 1)
        self.assertEqual(result['suppressed_by_triage'], 1)
        self.assertTrue(any('tuzatilgani emas' in note for note in result['notes']))

    def test_h_a_stale_decision_does_not_suppress(self):
        """A decision bound to a source snapshot that changed is not in force."""
        stale = code('a' * 24)
        stale['triage'] = {'suppressed': False, 'stale': True, 'status': None}
        self.assertEqual(ci_gate.evaluate(self.report([stale]), respect_triage=True)['count'], 1)

    def test_i_the_baseline_warnings_are_carried_into_the_gate_result(self):
        before = self.report([], state='partial')
        result = ci_gate.evaluate(self.report([code('a' * 24)]), baseline=before, fail_on='new')
        self.assertEqual(result['baseline']['state'], 'partial')
        self.assertTrue(any('partial' in note for note in result['notes']))

    def test_j_every_hit_carries_what_the_filters_need(self):
        result = ci_gate.evaluate(self.report([code('a' * 24)]))
        self.assertEqual(set(result['hits'][0]) >= {'fingerprint', 'severity', 'severity_scale', 'stage'}, True)
        self.assertEqual(result['hits'][0]['severity_scale'], 'HIGH')


class SuppressedTests(unittest.TestCase):
    def test_a_only_findings_a_person_closed_are_suppressed(self):
        report = assessment([
            {**code('a' * 24), 'triage': {'suppressed': True}},
            {**code('b' * 24), 'triage': {'suppressed': False}},
            {**code('c' * 24), 'triage': None},
            code('d' * 24)])
        self.assertEqual(baseline.suppressed(report), {'a' * 24})

    def test_b_the_status_names_match_the_triage_module(self):
        self.assertEqual(set(triage.SUPPRESSING), {'false_positive', 'accepted_risk'})


if __name__ == '__main__':
    unittest.main()
