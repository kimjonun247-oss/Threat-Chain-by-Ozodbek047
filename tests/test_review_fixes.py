"""Regression tests for the 2026-10-26 code-review audit.

Each test reproduces one defect found in the audit and locks its fix. Grouped
by the module under review; see the audit summary for the finding numbers.
"""
import math
import os
import sys
import tempfile
import unittest
from pathlib import Path

from zanjir import advisories, fixes, kubernetes, pathclass, scanners, webscan

# Note: a reviewed finding about `--fail-on new-high` dropping unrated secrets
# was investigated and REJECTED as a false positive -- new-high/new-critical are
# severity-narrowed by design (test_baseline.GateTests.test_c), and a secret is
# still caught by `--fail-on any` and `--fail-on new`. No change was made.


# ---- D5: pathclass must not treat a prod `coverage/` module as generated ----
class PathClassTests(unittest.TestCase):
    def test_coverage_dir_is_not_generated(self):
        # "coverage" is an ordinary domain word (insurance/health); a prod module
        # under coverage/ must stay prod so --prod-only and chains still see it.
        self.assertEqual(pathclass.classify('coverage/billing.py'), pathclass.PROD)

    def test_htmlcov_is_still_generated(self):
        # htmlcov is unambiguous (coverage HTML report) and stays generated.
        self.assertEqual(pathclass.classify('htmlcov/index.html'), 'generated')


# ---- D4: an allow-all NetworkPolicy must not count as a restriction ----
class NetworkPolicyTests(unittest.TestCase):
    def _policy(self, ingress):
        return {'document': {'spec': {'policyTypes': ['Ingress'],
                                      'podSelector': {'matchLabels': {'app': 'db'}},
                                      'ingress': ingress}}}

    def test_allow_all_ingress_does_not_restrict(self):
        # ingress: [{}] selects the pod but permits traffic from everywhere.
        self.assertFalse(kubernetes._restricts(self._policy([{}]), {'app': 'db'}))

    def test_real_from_rule_still_restricts(self):
        restrictive = self._policy([{'from': [{'podSelector': {'matchLabels': {'app': 'web'}}}]}])
        self.assertTrue(kubernetes._restricts(restrictive, {'app': 'db'}))

    def test_default_deny_empty_ingress_restricts(self):
        # No ingress key at all = default-deny, a real restriction.
        pol = {'document': {'spec': {'policyTypes': ['Ingress'],
                                     'podSelector': {'matchLabels': {'app': 'db'}}}}}
        self.assertTrue(kubernetes._restricts(pol, {'app': 'db'}))


# ---- D3: CVSS v3.1 Base score for Scope=Changed ----
# The audit first "fixed" this by moving the Base impact to the 0.9731 / ^13 form,
# but that form is the Environmental ModifiedImpact (spec 7.3); the Base impact
# (spec 7.1) keeps (ISS-0.02)^15. Its test re-derived the same wrong formula, so it
# could not catch the error. These are published Base scores instead, checked
# against the code -- not against a second copy of the code's formula.
class CvssTests(unittest.TestCase):
    KNOWN_BASE_SCORES = {
        'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H': 9.9,   # 10.0 under the Environmental form
        'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H': 10.0,
        'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H': 9.1,
        'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N': 6.1,   # typical reflected XSS
        'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H': 9.8,
    }

    def test_scope_changed_base_scores_match_the_published_values(self):
        for vector, expected in self.KNOWN_BASE_SCORES.items():
            self.assertEqual(advisories.cvss3_base(vector), expected, vector)


# ---- D6: openssl-style release letters must sort ABOVE the bare release ----
class VersionKeyTests(unittest.TestCase):
    def test_openssl_release_letter_is_newer_than_bare(self):
        # 1.0.1g (Heartbleed fix) is NEWER than 1.0.1, and so is 1.0.1a.
        self.assertGreater(fixes.version_key('1.0.1a'), fixes.version_key('1.0.1'))
        self.assertGreater(fixes.version_key('1.0.1g'), fixes.version_key('1.0.1a'))

    def test_next_fix_finds_the_release_letter(self):
        self.assertEqual(fixes.next_fix('1.0.1', ['1.0.1a']), '1.0.1a')

    def test_semver_prerelease_still_sorts_below_release(self):
        # These are the existing guarantees that must not regress.
        self.assertLess(fixes.version_key('2.0.0-beta'), fixes.version_key('2.0.0'))
        self.assertLess(fixes.version_key('1.0.0a1'), fixes.version_key('1.0.0'))  # PEP 440 alpha
        self.assertLess(fixes.version_key('1.0.0-rc1'), fixes.version_key('1.0.0'))


# ---- B3: the reported web-scan scope must match the enforced request ceiling ----
class ScopeTextTests(unittest.TestCase):
    def test_scope_mentions_the_actual_request_ceiling(self):
        text = webscan.scope_text()
        self.assertIn(str(webscan.MAX_REQUESTS), text)
        self.assertNotIn('32 requests', text)  # the old hard-coded, exceeded number


# ---- A6: findings are sorted deterministically even on a full (no-cache) scan ----
class MergeSortTests(unittest.TestCase):
    def test_full_scan_findings_are_sorted(self):
        fresh = [{'path': 'b.py', 'line': 2, 'rule_id': 'r2'},
                 {'path': 'a.py', 'line': 9, 'rule_id': 'r1'},
                 {'path': 'a.py', 'line': 1, 'rule_id': 'r3'}]
        findings, _errors, reused, _rows = scanners.merge_results(
            'semgrep', fresh, [], cache=None, entries=[], scanned=set(), skip=set())
        got = [(f['path'], f['line']) for f in findings]
        self.assertEqual(got, sorted(got))


# ---- A1: one malformed result row must not discard the whole batch ----
class NormalizeRowTests(unittest.TestCase):
    def test_bad_row_is_skipped_not_fatal(self):
        with tempfile.TemporaryDirectory() as d:
            source = Path(d)
            (source / 'app.py').write_text('import os\nx = 1\n', encoding='utf-8')
            data = {'results': [
                {'check_id': 'good.rule', 'path': 'app.py', 'start': {'line': 1},
                 'extra': {'severity': 'ERROR', 'metadata': {}}},
                {'check_id': 'bad.rule', 'path': 'app.py', 'start': {'line': 0},  # line<1: invalid
                 'extra': {'severity': 'ERROR', 'metadata': {}}},
            ]}
            result = scanners.normalize('semgrep', data, source)
            self.assertEqual([f['rule_id'] for f in result], ['good.rule'])


import datetime                                        # noqa: E402
from unittest.mock import patch                       # noqa: E402
from isolation import isolate_triage                   # noqa: E402
from zanjir import findings_index, findings_store, recovery       # noqa: E402


# ---- A2: the per-file line cache is local to one normalize(), not a global ----
class LineCacheIsolationTests(unittest.TestCase):
    def test_normalize_does_not_touch_the_module_global(self):
        with tempfile.TemporaryDirectory() as d:
            source = Path(d)
            (source / 'app.py').write_text('a = 1\nb = 2\n', encoding='utf-8')
            data = {'results': [{'check_id': 'r', 'path': 'app.py', 'start': {'line': 1},
                                 'extra': {'severity': 'ERROR', 'metadata': {}}}]}
            scanners.normalize('semgrep', data, source)
        # No shared module state means two concurrent scans cannot cross-feed.
        self.assertEqual(scanners._LINES, {'source': None, 'files': {}})

    def test_source_line_requires_a_caller_owned_cache(self):
        with tempfile.TemporaryDirectory() as d:
            source = Path(d)
            (source / 'a.py').write_text('first\nsecond\n', encoding='utf-8')
            cache = {'source': None, 'files': {}}
            self.assertEqual(scanners.source_line(source, 'a.py', 2, cache).strip(), 'second')
            self.assertIn('a.py', cache['files'])          # the caller's cache, not a global


# ---- A3: a reused PID must not keep an orphaned scan 'running' forever ----
class StaleRecoveryTests(unittest.TestCase):
    def _report(self, hours_ago):
        when = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=hours_ago)
        return {'pid': os.getpid(), 'created_at': when.isoformat()}     # os.getpid() is a live pid

    def test_live_pid_but_older_than_the_limit_is_stale(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        self.assertTrue(recovery._stale(self._report(hours_ago=7), now))    # PID reuse case

    def test_live_pid_within_the_limit_is_not_stale(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        self.assertFalse(recovery._stale(self._report(hours_ago=1), now))   # still running


# ---- A4: the first-part time budget scales with the whole-snapshot size ----
class PacedLimitScaleTests(unittest.TestCase):
    def test_first_part_floor_uses_the_overall_scale(self):
        self.assertEqual(scanners.PacedLimit(100, scale=4).limit([], 1), 400)
        self.assertEqual(scanners.PacedLimit(100).limit([], 1), 100)        # default scale 1


from unittest.mock import patch                       # noqa: E402
from isolation import isolate_triage                   # noqa: E402
from zanjir import findings_index, findings_store       # noqa: E402


class BoardCase(unittest.TestCase):
    """Seed the board from an in-memory set of code reports, like test_priority."""
    def install(self, reports, project_of):
        # reports: {target: [finding, ...]}; project_of: {target: project}
        isolate_triage(self)
        listing = [{'id': 'r-' + t, 'target': t, 'state': 'completed'} for t in reports]

        def read(rid):
            target = rid[len('r-'):]
            return {'id': rid, 'target': target, 'state': 'completed',
                    'created_at': '2026-01-01T00:00:00+00:00', 'findings': reports[target]}
        world = {'code': (read, lambda limit: list(listing), 'target')}
        for name, value in (('sources', lambda: world),
                            ('registered', lambda stage: set(reports) if stage == 'code' else set()),
                            ('chain_rows', lambda stage: []),
                            ('project_of', lambda stage, target: project_of.get(target, ''))):
            p = patch.object(findings_index, name, value)
            p.start()
            self.addCleanup(p.stop)
        findings_index.invalidate()
        self.addCleanup(findings_index.invalidate)

    @staticmethod
    def finding(n, path='app/x.py', severity='HIGH'):
        return {'fingerprint': f'{n:024x}', 'rule_id': f'CVE-{n}', 'severity': severity, 'path': path,
                'line': 1, 'cwe_ids': [], 'owasp_top10_2025': [], 'tool': 'semgrep'}


# ---- C1: detail() resolves a shared fingerprint to the project asked for ----
class DetailProjectScopeTests(BoardCase):
    def test_shared_fingerprint_resolves_to_the_requested_project(self):
        shared = self.finding(1)                       # same fingerprint in both projects
        self.install({'a': [dict(shared)], 'b': [dict(shared)]},
                     {'a': 'proj-a', 'b': 'proj-b'})
        fp = f'{1:024x}'
        self.assertEqual(findings_index.detail(fp, 'proj-b')['row']['project'], 'proj-b')
        self.assertEqual(findings_index.detail(fp, 'proj-a')['row']['project'], 'proj-a')


# ---- C2: the '—' facet sentinel selects the no-project rows, not zero ----
class FacetSentinelTests(BoardCase):
    def test_dash_project_facet_filters_to_the_no_project_rows(self):
        self.install({'a': [self.finding(1)]}, {'a': ''})      # project_of -> '' (no project)
        facets = findings_index.search()['facets']['project']
        self.assertIn('—', facets)                              # the chip exists and counts 1
        self.assertEqual(facets['—'], 1)
        got = findings_index.search(filters={'project': '—'})
        self.assertEqual(got['total'], 1)                       # clicking it returns that row


# ---- C4: one malformed finding must not wedge the whole board ----
class MalformedFindingTests(BoardCase):
    def test_a_bad_finding_is_skipped_and_the_board_still_builds(self):
        self.install({'a': [self.finding(1), 'this is not a dict', self.finding(2)]}, {'a': 'proj-a'})
        result = findings_index.search()                        # must not raise
        rules = {r['rule_id'] for r in result['rows']}
        self.assertEqual(rules, {'CVE-1', 'CVE-2'})             # the two good ones survive


# ---- C3: bulk redecorate must not hit SQLite's bound-variable limit ----
class RedecorateChunkTests(BoardCase):
    def test_tens_of_thousands_of_fingerprints_do_not_raise(self):
        self.install({'a': [self.finding(1)]}, {'a': 'proj-a'})
        findings_index.search()                                 # build the board first
        db = findings_store.connect()
        try:
            many = [f'{i:024x}' for i in range(40000)]          # well over SQLITE_MAX_VARIABLE_NUMBER
            self.assertIsInstance(findings_store.redecorate(db, 'proj-a', fingerprints=many), int)
        finally:
            db.close()


import importlib                                       # noqa: E402
import io                                               # noqa: E402
import contextlib                                       # noqa: E402


# ---- E2: an optional-component failure must not fail setup_all (exit 0) ----
class SetupAllExitTests(unittest.TestCase):
    def _run_with(self, outcome):
        setup_all = importlib.import_module('setup_all')

        def fake_run(step, force):
            return {'ok': outcome(step), 'seconds': 0, 'output': ['stub']}
        with patch.object(setup_all, 'run', fake_run), patch.object(sys, 'argv', ['setup_all.py']):
            with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as caught:
                setup_all.main()
        code = caught.exception.code
        return code if isinstance(code, int) else 1

    def test_only_optional_failures_exit_zero(self):
        self.assertEqual(self._run_with(lambda step: not step['optional']), 0)

    def test_a_required_failure_exits_nonzero(self):
        self.assertNotEqual(self._run_with(lambda step: False), 0)


if __name__ == '__main__':
    unittest.main()
