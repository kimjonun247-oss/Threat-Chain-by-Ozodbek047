import unittest

from zanjir import sarif_export


def make_report():
    return {
        'stages': [
            {'kind': 'code', 'report': {'findings': [
                {'tool': 'gitleaks', 'rule_id': 'aws-access-token', 'path': 'app/config.py', 'line': 3,
                 'message': 'Secret-like text found.', 'cwe_ids': ['CWE-798']},
                {'tool': 'semgrep', 'rule_id': 'zanjir.python.eval', 'path': 'app/main.py', 'line': 10,
                 'message': 'Dangerous eval() call.', 'cwe_ids': ['CWE-95']},
            ]}},
            {'kind': 'repository', 'report': {
                'findings': [{'rule_id': 'RP-001', 'title': 'Host interfeysiga chiqarilgan port', 'level': 'warning',
                              'detail': 'Host interfeysi: 0.0.0.0.', 'fingerprint': 'abc123', 'evidence_ids': ['R001']}],
                'evidence': [{'id': 'R001', 'path': 'docker-compose.yml', 'line': 5, 'label': 'Host port mapping', 'value': {}}],
            }},
            {'kind': 'dependencies', 'report': {'findings': [
                {'package': {'name': 'lodash', 'version': '4.17.15'}, 'advisory_id': 'CVE-2020-8203',
                 'summary': 'Prototype pollution.', 'severity': 'CRITICAL', 'cwe_ids': ['CWE-1321']},
            ]}},
            {'kind': 'images', 'report': {'findings': [
                {'package': 'openssl', 'version': '1.1.1', 'advisory_id': 'CVE-2022-0001',
                 'title': 'Buffer overflow.', 'severity': 'HIGH', 'cwe_ids': ['CWE-120']},
            ]}},
            {'kind': 'web', 'report': {'findings': [
                {'rule_id': 'zanjir-env', 'title': 'Ochiq muhit konfiguratsiyasi (.env)', 'path': '/.env',
                 'severity': 'HIGH', 'cwe_ids': ['CWE-522']},
            ]}},
        ],
        'chain_findings': [
            {'rule_id': 'SX-001', 'title': 'Ochiq xizmat manbasida qattiq kodlangan sir topildi', 'level': 'warning',
             'cwe_ids': ['CWE-798', 'CWE-668'], 'evidence': {'gitleaks_path': 'app/config.py', 'gitleaks_line': 3}},
        ],
    }


class SarifExportTests(unittest.TestCase):
    def test_every_stage_and_chain_finding_becomes_a_result(self):
        doc = sarif_export.build(make_report())
        self.assertEqual(doc['version'], '2.1.0')
        total_results = sum(len(run['results']) for run in doc['runs'])
        self.assertEqual(total_results, 7)  # 2 code + 1 repository + 1 dependencies + 1 images + 1 web + 1 chain

    def test_chain_finding_gets_its_own_run_with_a_location(self):
        doc = sarif_export.build(make_report())
        chain_run = next(run for run in doc['runs'] if any(r['ruleId'] == 'SX-001' for r in run['results']))
        result = chain_run['results'][0]
        self.assertEqual(result['locations'][0]['physicalLocation']['artifactLocation']['uri'], 'app/config.py')
        self.assertEqual(result['locations'][0]['physicalLocation']['region']['startLine'], 3)

    def test_severity_maps_to_sarif_level(self):
        doc = sarif_export.build(make_report())
        dep_run = next(run for run in doc['runs'] if any('CVE-2020-8203' == r['ruleId'] for r in run['results']))
        self.assertEqual(dep_run['results'][0]['level'], 'error')  # CRITICAL -> error

    def test_findings_without_a_path_have_no_location_but_still_appear(self):
        doc = sarif_export.build(make_report())
        images_run = next(run for run in doc['runs'] if any('CVE-2022-0001' == r['ruleId'] for r in run['results']))
        self.assertNotIn('locations', images_run['results'][0])

    def test_missing_child_report_is_skipped_without_error(self):
        report = {'stages': [{'kind': 'web', 'target': '', 'state': 'not_selected'}], 'chain_findings': []}
        doc = sarif_export.build(report)
        self.assertEqual(sum(len(run['results']) for run in doc['runs']), 0)

    def test_empty_report_produces_a_valid_empty_document(self):
        doc = sarif_export.build({'stages': [], 'chain_findings': []})
        self.assertEqual(doc['runs'], [{'tool': {'driver': {'name': 'ThreatChain', 'rules': []}}, 'results': []}])


if __name__ == '__main__':
    unittest.main(verbosity=2)
