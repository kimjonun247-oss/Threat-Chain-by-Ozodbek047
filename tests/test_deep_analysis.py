"""Optional CodeQL stage (zanjir/deep_analysis.py) -- the parts that need no CodeQL binary.

The real run is benchmarks/run.py --only deep (inter-file SQL injection,
command injection and XSS, each flow crossing files).
"""
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from zanjir import deep_analysis, settings

SARIF = {'runs': [{'tool': {'driver': {'name': 'CodeQL', 'rules': [
    {'id': 'py/sql-injection', 'shortDescription': {'text': 'SQL query built from user-controlled sources'},
     'properties': {'tags': ['security', 'external/cwe/cwe-089'], 'security-severity': '8.8', 'problem.severity': 'error'}}]}},
    'results': [{'ruleId': 'py/sql-injection', 'message': {'text': 'This SQL query depends on a user-provided value.'},
                 'locations': [{'physicalLocation': {'artifactLocation': {'uri': 'store.py'}, 'region': {'startLine': 8}}}],
                 'codeFlows': [{'threadFlows': [{'locations': [
                     {'location': {'physicalLocation': {'artifactLocation': {'uri': 'app.py'}, 'region': {'startLine': 11}}}},
                     {'location': {'physicalLocation': {'artifactLocation': {'uri': 'store.py'}, 'region': {'startLine': 12}}}},
                     {'location': {'physicalLocation': {'artifactLocation': {'uri': 'store.py'}, 'region': {'startLine': 8}}}}]}]}]},
                {'ruleId': 'py/sql-injection', 'message': {'text': 'outside'},
                 'locations': [{'physicalLocation': {'artifactLocation': {'uri': '../../etc/passwd'}, 'region': {'startLine': 1}}}]}]}]}


class DeepAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.source = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.source, True)

    def test_sarif_becomes_findings_with_the_data_flow(self):
        rows = deep_analysis.normalize(SARIF, self.source)
        self.assertEqual(len(rows), 1)                    # the path outside the snapshot is dropped
        row = rows[0]
        self.assertEqual((row['tool'], row['rule_id'], row['path'], row['line'], row['severity']),
                         ('codeql', 'py/sql-injection', 'store.py', 8, 'ERROR'))
        self.assertEqual(row['cwe_ids'][0], 'CWE-89')
        self.assertEqual(row['data_flow'], {'source': 'app.py:11', 'sink': 'store.py:8', 'steps': 3,
                                            'files': ['app.py', 'store.py'], 'cross_file': True})
        self.assertFalse(row['verified'])
        self.assertEqual(len(row['fingerprint']), 24)

    def test_languages_are_split_by_what_codeql_can_analyse_without_a_build(self):
        for name in ('a.py', 'b.ts', 'c.go', 'd.php', 'e.java'):
            (self.source / name).write_text('x', encoding='utf-8')
        self.assertEqual(deep_analysis.languages(self.source), (['java', 'javascript', 'python'], ['go'], ['php']))

    def test_without_codeql_the_stage_fails_with_the_install_command(self):
        with mock.patch.object(deep_analysis, 'installed', lambda: False):
            record, rows = deep_analysis.run(self.source, self.source, {})
        self.assertEqual((record['state'], rows), ('failed', []))
        self.assertIn('setup_codeql.py', record['message'])

    def test_it_is_off_until_switched_on(self):
        with mock.patch.object(settings, 'PATH', self.source / 'settings.json'):
            self.assertFalse(deep_analysis.enabled())
            settings.set_deep_analysis(True)
            self.assertTrue(deep_analysis.enabled())
            with self.assertRaises(ValueError):
                settings.set_deep_analysis('yes')


if __name__ == '__main__':
    unittest.main()
