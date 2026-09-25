"""The bundled synthetic sample exists so the chain rules are visible out of the box.

The bundled crAPI copy uses ready-made `image:` for every service and has no
`build:`, so it produces no build context and the cross-scanner chain (SX-001)
could never appear in a default installation. samples/chain-demo fills that gap,
and these tests keep it doing so: if someone "tidies up" the sample's compose
file, the project's own differentiator silently stops being demonstrable.
"""
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vendor import yaml

from zanjir import chains, repo_store, scanners
from zanjir.engine import ROOT
from isolation import isolate_triage

SAMPLE = ROOT / 'samples/chain-demo'
FAKE_KEY = 'sk_live_51NxxFAKEexampleKEYforTHREATCHAINdemo00'


class ScanInTempStore(unittest.TestCase):
    """Base class: scan the sample without writing into the real report store.

    repo_store.scan_profile() persists a report. Left unpatched, every test run
    would add rows to repository-runs/ and, because the listing keeps only the
    most recent 30, eventually push the project's real crAPI evidence out of
    view. Tests must not be able to do that.
    """

    def setUp(self):
        isolate_triage(self)
        self.runs = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.runs, True)
        patcher = patch.object(repo_store, 'REPO_RUNS', self.runs)
        patcher.start()
        self.addCleanup(patcher.stop)

    def scan(self):
        return repo_store.scan_profile('chain-demo')


class SampleShapeTests(unittest.TestCase):
    def test_the_sample_is_present_with_its_provenance(self):
        self.assertTrue((SAMPLE / 'docker-compose.yml').is_file())
        self.assertTrue((SAMPLE / 'app/config.py').is_file())
        provenance = json.loads((SAMPLE / 'zanjir-provenance.json').read_text(encoding='utf-8'))
        self.assertEqual(provenance['source_type'], 'bundled_synthetic_sample')

    def test_the_compose_still_declares_a_build_context(self):
        # Without `build:` there is no build context, and SX-001 can never fire.
        compose = yaml.safe_load((SAMPLE / 'docker-compose.yml').read_text(encoding='utf-8'))
        self.assertIn('build', compose['services']['web'])

    def test_the_exposed_port_is_not_loopback_only(self):
        # Every chain rule in this sample requires a non-loopback published port.
        compose = yaml.safe_load((SAMPLE / 'docker-compose.yml').read_text(encoding='utf-8'))
        ports = compose['services']['web']['ports']
        self.assertTrue(any(not str(p).startswith('127.0.0.1') for p in ports))

    def test_the_sample_readme_says_plainly_that_the_key_is_fake(self):
        text = (SAMPLE / 'README.md').read_text(encoding='utf-8').lower()
        self.assertIn('soxta', text)


class RegistrationTests(unittest.TestCase):
    def test_the_sample_is_a_bundled_repository_profile(self):
        rows = {p['id']: p for p in repo_store.list_profiles()}
        self.assertEqual(rows['chain-demo']['mode'], 'bundled_sample')

    def test_the_sample_is_also_offered_as_a_source_target(self):
        # Both stages must be selectable, or the two reports can never be correlated.
        rows = {t['id']: t for t in scanners.targets()}
        self.assertIn('chain-demo', rows)
        self.assertTrue(rows['chain-demo']['available'])

    def test_its_root_resolves_inside_the_application_folder(self):
        root = scanners.target_root('chain-demo')
        self.assertTrue(root.is_relative_to(ROOT))
        self.assertEqual(root, SAMPLE.resolve())

    def test_crapi_is_not_duplicated_as_a_bundled_source_target(self):
        # crAPI already appears as 'crapi-full', which honours ZANJIR_CRAPI_ROOT.
        self.assertNotIn('crapi', scanners.bundled_code_samples())


class ChainRuleTests(ScanInTempStore):
    """The repository scan is synchronous and needs no external tool, so this is cheap."""

    def setUp(self):
        isolate_triage(self)
        super().setUp()
        self.report = self.scan()
        self.rules = {f['rule_id'] for f in self.report['findings']}

    def test_every_chain_rule_the_sample_is_built_for_actually_fires(self):
        for rule in ('RP-001', 'RP-005', 'RP-006', 'RP-007', 'RP-008'):
            with self.subTest(rule=rule):
                self.assertIn(rule, self.rules)

    def test_the_privilege_chain_rules_are_reported_at_error_level(self):
        # RP-007/008 end in host-level compromise, so they gate CI.
        for finding in self.report['findings']:
            if finding['rule_id'] in ('RP-007', 'RP-008'):
                self.assertEqual(finding['level'], 'error')

    def test_the_web_service_carries_a_build_context_for_correlation(self):
        web = next(s for s in self.report['services'] if s['id'] == 'web')
        self.assertEqual(web['build_context'], 'app')


class CrossScannerTests(ScanInTempStore):
    """SX-001 against the real repository report, with a stand-in Gitleaks match.

    correlate() is a pure function, so the chain can be proven without Gitleaks
    installed -- which keeps this test runnable in any environment.
    """

    def code_report(self, path='app/config.py'):
        return {'findings': [{'tool': 'gitleaks', 'rule_id': 'stripe-access-token',
                              'path': path, 'line': 7, 'secret_value': 'hidden'}]}

    def test_the_sample_produces_the_cross_scanner_chain(self):
        repository = self.scan()
        findings = chains.correlate(self.code_report(), repository)
        self.assertEqual([f['rule_id'] for f in findings], ['SX-001'])
        finding = findings[0]
        self.assertEqual(finding['service_id'], 'web')
        self.assertEqual(sorted(finding['cwe_ids']), ['CWE-668', 'CWE-798'])
        self.assertEqual(sorted(o['code'] for o in finding['owasp_top10_2025']), ['A01', 'A07'])
        self.assertFalse(finding['verified'])

    def test_a_secret_outside_the_build_context_does_not_correlate(self):
        repository = self.scan()
        self.assertEqual(chains.correlate(self.code_report('docs/notes.md'), repository), [])

    def test_the_secret_value_never_reaches_the_chain_finding(self):
        repository = self.scan()
        blob = json.dumps(chains.correlate(self.code_report(), repository), ensure_ascii=False)
        self.assertNotIn(FAKE_KEY, blob)
        self.assertNotIn('secret_value', blob)

    def test_the_repository_report_itself_never_carries_the_key(self):
        blob = json.dumps(self.scan(), ensure_ascii=False)
        self.assertNotIn(FAKE_KEY, blob)


if __name__ == '__main__':
    unittest.main(verbosity=2)
