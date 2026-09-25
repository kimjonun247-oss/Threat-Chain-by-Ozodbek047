import unittest

from zanjir.ci_gate import evaluate, gate_relevant, incomplete_stages


class CiGateTests(unittest.TestCase):
    def test_clean_report_passes_with_default_zero_allowance(self):
        report = {'stages': [{'kind': 'code', 'report': {'findings': []}}], 'chain_findings': []}
        result = evaluate(report)
        self.assertTrue(result['passed'])
        self.assertEqual(result['count'], 0)

    def test_repository_error_level_finding_fails_the_gate(self):
        # An 'error'-level repository finding is a chain rule (e.g. RP-004/007/008)
        # whose direct consequence is auth bypass or host compromise -- always gate-relevant.
        report = {'stages': [{'kind': 'repository', 'report': {'findings': [
            {'rule_id': 'RP-004', 'level': 'error', 'service_id': 'backend', 'title': 'Gateway ishonch sarlavhasi'}
        ]}}], 'chain_findings': []}
        result = evaluate(report)
        self.assertFalse(result['passed'])
        self.assertEqual(result['count'], 1)
        self.assertEqual(result['hits'][0]['stage'], 'repository')

    def test_repository_warning_level_finding_does_not_fail_the_gate(self):
        report = {'stages': [{'kind': 'repository', 'report': {'findings': [
            {'rule_id': 'RP-001', 'level': 'warning', 'service_id': 'web', 'title': 'Host port'}
        ]}}], 'chain_findings': []}
        self.assertTrue(evaluate(report)['passed'])

    def test_critical_dependency_finding_fails_the_gate(self):
        report = {'stages': [{'kind': 'dependencies', 'report': {'findings': [
            {'package': {'name': 'lodash', 'version': '4.17.15'}, 'advisory_id': 'CVE-2020-8203', 'severity': 'CRITICAL'}
        ]}}], 'chain_findings': []}
        result = evaluate(report)
        self.assertFalse(result['passed'])
        self.assertEqual(result['hits'][0]['subject'], 'lodash')

    def test_low_severity_dependency_finding_does_not_fail_the_gate(self):
        report = {'stages': [{'kind': 'dependencies', 'report': {'findings': [
            {'package': {'name': 'x', 'version': '1'}, 'advisory_id': 'CVE-1', 'severity': 'LOW'}
        ]}}], 'chain_findings': []}
        self.assertTrue(evaluate(report)['passed'])

    def test_high_severity_web_finding_fails_the_gate(self):
        report = {'stages': [{'kind': 'web', 'report': {'findings': [
            {'rule_id': 'zanjir-env', 'path': '/.env', 'severity': 'HIGH', 'title': '.env exposed'}
        ]}}], 'chain_findings': []}
        self.assertFalse(evaluate(report)['passed'])

    def test_any_chain_finding_fails_the_gate_regardless_of_its_own_level(self):
        report = {'stages': [], 'chain_findings': [
            {'rule_id': 'SX-001', 'service_id': 'web', 'title': 'Hardcoded secret', 'level': 'warning'}
        ]}
        result = evaluate(report)
        self.assertFalse(result['passed'])
        self.assertEqual(result['hits'][0]['stage'], 'chain')

    def test_allow_threshold_permits_a_bounded_number_of_hits(self):
        report = {'stages': [{'kind': 'web', 'report': {'findings': [
            {'rule_id': 'a', 'path': '/x', 'severity': 'HIGH', 'title': 'x'},
            {'rule_id': 'b', 'path': '/y', 'severity': 'HIGH', 'title': 'y'},
        ]}}], 'chain_findings': []}
        self.assertFalse(evaluate(report, allow=1)['passed'])
        self.assertTrue(evaluate(report, allow=2)['passed'])

    def test_not_selected_stage_is_skipped_without_error(self):
        report = {'stages': [{'kind': 'images', 'target': '', 'state': 'not_selected'}], 'chain_findings': []}
        self.assertEqual(gate_relevant(report), [])

    def test_gitleaks_finding_always_fails_the_gate(self):
        report = {'stages': [{'kind': 'code', 'report': {'findings': [
            {'tool': 'gitleaks', 'rule_id': 'stripe-access-token', 'path': 'app/config.py', 'severity': None}
        ]}}], 'chain_findings': []}
        result = evaluate(report)
        self.assertFalse(result['passed'])
        self.assertEqual(result['hits'][0]['stage'], 'code')
        self.assertEqual(result['hits'][0]['detail'], 'Gitleaks')

    def test_semgrep_error_severity_fails_the_gate(self):
        report = {'stages': [{'kind': 'code', 'report': {'findings': [
            {'tool': 'semgrep', 'rule_id': 'subprocess-shell-true', 'path': 'a.py', 'severity': 'ERROR'}
        ]}}], 'chain_findings': []}
        self.assertFalse(evaluate(report)['passed'])

    def test_semgrep_warning_and_info_do_not_fail_the_gate(self):
        # Hundreds of these appear on a real repository; a gate that always fails
        # is a gate nobody reads.
        report = {'stages': [{'kind': 'code', 'report': {'findings': [
            {'tool': 'semgrep', 'rule_id': 'a', 'path': 'a.py', 'severity': 'WARNING'},
            {'tool': 'semgrep', 'rule_id': 'b', 'path': 'b.py', 'severity': 'INFO'},
            {'tool': 'semgrep', 'rule_id': 'c', 'path': 'c.py', 'severity': None},
        ]}}], 'chain_findings': []}
        self.assertTrue(evaluate(report)['passed'])


class IncompleteStageTests(unittest.TestCase):
    def test_partial_or_failed_selected_stage_is_incomplete(self):
        # A dependency stage left partial by an unreachable OSV must not read as
        # "no known vulnerabilities" -- the CLI turns this list into exit code 2.
        report = {'stages': [{'kind': 'code', 'target': 'app', 'state': 'completed'},
                             {'kind': 'dependencies', 'target': 'app', 'state': 'partial'},
                             {'kind': 'images', 'target': 'img', 'state': 'failed'},
                             {'kind': 'web', 'target': '', 'state': 'not_selected'}]}
        self.assertEqual([(r['kind'], r['state']) for r in incomplete_stages(report)],
                         [('dependencies', 'partial'), ('images', 'failed')])

    def test_no_lockfile_is_a_finished_stage(self):
        report = {'stages': [{'kind': 'dependencies', 'target': 'app', 'state': 'no_supported_packages'},
                             {'kind': 'code', 'target': 'app', 'state': 'completed'}]}
        self.assertEqual(incomplete_stages(report), [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
