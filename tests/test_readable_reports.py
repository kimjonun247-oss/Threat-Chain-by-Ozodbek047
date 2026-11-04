"""The downloaded reports read like reports (UI review 2026-11-04).

A reader of the Markdown export used to meet raw codes where words belong
(`Holat: completed`, `code / repository`, `warning`), timestamps in UTC with
microseconds, an old product name in the title, rows in scanner order rather
than worst first, and no word about which chain rules never ran. The code
report had no Markdown at all although the export window offered one, and a
chain finding other than SX-001 left the SARIF export without a location.
"""
import http.client
import unittest
from unittest.mock import patch

from app import Handler
from zanjir import pipeline, report_text, sarif_export, scanners
from zanjir.httptest import listener

CODE = [{'tool': 'gitleaks', 'rule_id': 'stripe', 'path': 'app/config.py', 'line': 7, 'message': 'Sir',
         'secret_value': 'hidden', 'cwe_ids': ['CWE-798']},
        {'tool': 'semgrep', 'rule_id': 'sqli', 'path': 'app/db.py', 'line': 3, 'message': 'SQL', 'severity': 'ERROR',
         'cwe_ids': ['CWE-89']}]
ASSESSMENT = {
    'id': '20261013T060120-60c4ce34', 'state': 'completed', 'created_at': '2026-10-13T06:01:20.981809+00:00',
    'finished_at': '2026-10-13T06:01:35.275889+00:00', 'limits': 'Cheklovlar.',
    'stages': [{'kind': 'code', 'target': 'demo', 'state': 'completed', 'count': 2, 'report_id': 'r-code',
                'report': {'findings': CODE}},
               {'kind': 'repository', 'target': 'demo', 'state': 'completed', 'count': 2, 'report_id': 'r-repo',
                'report': {'findings': [{'rule_id': 'RP-001', 'service_id': 'web', 'title': 'Port', 'level': 'warning'},
                                        {'rule_id': 'RP-007', 'service_id': 'web', 'title': 'Socket', 'level': 'error'}]}},
               {'kind': 'images', 'state': 'not_selected'}],
    'chain_gaps': [{'detail': 'Image bosqichi tanlanmagan; SX-002 tekshirilmadi.'}],
    'chain_findings': [{'rule_id': 'SX-007', 'service_id': 'web', 'level': 'error', 'title': 'Kirish',
                        'fingerprint': 'f' * 24, 'evidence': {'entry_path': 'app/config.py:7', 'build_context': 'app'}}],
}


class AssessmentMarkdownTests(unittest.TestCase):
    def setUp(self):
        patcher = patch.object(pipeline, 'project_name', lambda report: 'Demo loyiha')
        patcher.start()
        self.addCleanup(patcher.stop)
        self.text = pipeline.markdown(ASSESSMENT)

    def test_a_states_and_stages_are_words_not_codes(self):
        self.assertIn('Holat: Tugadi', self.text)
        self.assertIn('| Kod va sirlar | demo | Tugadi |', self.text)
        self.assertIn('Tanlanmagan', self.text)
        for code in ('completed', 'not_selected', '| code |', '| warning', '| error'):
            self.assertNotIn(code, self.text)

    def test_b_title_project_and_local_time(self):
        self.assertTrue(self.text.startswith('# ThreatChain — to‘liq tekshiruv hisoboti'))
        self.assertIn('Loyiha: Demo loyiha', self.text)
        self.assertNotIn('.981809', self.text)
        self.assertRegex(self.text, r'Boshlangan: 2026-10-1[23] \d\d:\d\d')

    def test_c_rows_are_worst_first_and_severity_is_in_words(self):
        socket, port = self.text.index('RP-007'), self.text.index('RP-001')
        self.assertLess(socket, port)
        self.assertIn('| Yuqori | semgrep | sqli', self.text)
        self.assertIn('| Baholanmagan | gitleaks | stripe', self.text)
        self.assertLess(self.text.index('sqli'), self.text.index('| Baholanmagan | gitleaks'))

    def test_d_rules_that_never_ran_are_named(self):
        self.assertIn('## Tekshirilmagan qismlar', self.text)
        self.assertIn('SX-002 tekshirilmadi', self.text)

    def test_e_a_severity_summary_without_a_total(self):
        self.assertIn('Og‘irlik bo‘yicha: Kritik 0 · Yuqori 3 · O‘rta 1 · Past 0 · Baholanmagan 1', self.text)


class SharedWordsTests(unittest.TestCase):
    def test_a_a_value_that_is_not_a_timestamp_is_kept(self):
        self.assertEqual(report_text.when('t'), 't')

    def test_b_an_unknown_state_is_shown_as_it_is(self):
        self.assertEqual(report_text.state('brand_new'), 'brand_new')


class CodeMarkdownTests(unittest.TestCase):
    REPORT = {'id': '20261013T060121-c0bc5876', 'target': 'demo', 'state': 'completed',
              'created_at': '2026-10-13T06:01:21+00:00', 'limits': 'Cheklov.', 'findings': CODE,
              'coverage': {'files': 6, 'skipped': {'binary': 1}}, 'tools': {'semgrep': {'state': 'completed', 'count': 1}}}

    def test_a_worst_first_and_no_secret(self):
        text = scanners.markdown(self.REPORT)
        self.assertLess(text.index('sqli'), text.index('stripe'))
        self.assertNotIn('hidden', text)
        self.assertIn('1 ta binar', text)

    def test_b_an_empty_report_says_it_is_not_a_clean_bill(self):
        text = scanners.markdown({**self.REPORT, 'findings': []})
        self.assertIn('xavfsizlik xulosasi emas', text)

    def test_c_the_route_serves_it(self):
        with patch.object(scanners, 'read_report', lambda rid: self.REPORT):
            with listener(Handler) as url:
                connection = http.client.HTTPConnection('127.0.0.1', int(url.rsplit(':', 1)[1]), timeout=60)
                try:
                    connection.request('GET', '/api/scanners/reports/' + self.REPORT['id'] + '/markdown')
                    response = connection.getresponse()
                    body = response.read().decode('utf-8')
                finally:
                    connection.close()
        self.assertEqual(response.status, 200, body)
        self.assertIn('text/markdown', response.getheader('Content-Type'))
        self.assertIn('kod va sirlar tekshiruvi', body)


class BoardCsvTests(unittest.TestCase):
    ROWS = [{'severity_scale': 'HIGH', 'stage': 'code', 'project': 'demo', 'target': 'demo-src', 'rule_id': 'sqli',
             'title': '=HYPERLINK("http://x")', 'subject': 'app/db.py:3', 'cwe_ids': ['CWE-89'], 'status': None,
             'owner': None, 'overdue': True, 'first_seen': None, 'report_id': 'r1', 'fingerprint': 'a' * 24}]

    def export(self, rows, total=None):
        from zanjir import findings_index, findings_store
        calls = []

        def search(index, query, filters, offset, limit):
            calls.append(filters)
            return {'total': len(rows) if total is None else total, 'rows': rows[offset:offset + limit]}
        with patch.object(findings_store, 'search', search):
            return findings_index.export_csv('', {'severity': 'HIGH'}), calls

    def test_a_words_a_bom_and_the_filters_on_screen(self):
        text, calls = self.export(self.ROWS)
        self.assertTrue(text.startswith('﻿'), 'Excel needs the BOM to read o‘ and g‘')
        self.assertIn('Yuqori,Kod va sirlar,demo', text)
        self.assertIn('Ko‘rilmagan', text)
        self.assertEqual(calls[0], {'severity': 'HIGH'})

    def test_b_a_cell_a_spreadsheet_would_run_is_neutralised(self):
        text, _ = self.export(self.ROWS)
        self.assertIn('"\'=HYPERLINK(""http://x"")"', text)

    def test_c_a_cut_list_says_so(self):
        from zanjir import findings_index
        with patch.object(findings_index, 'EXPORT_LIMIT', 1):
            text, _ = self.export(self.ROWS * 3)
        self.assertIn('yana 2 ta topilma', text)


class ChainSarifTests(unittest.TestCase):
    def test_a_every_chain_rule_gets_a_location(self):
        entries = sarif_export._chain_entries(ASSESSMENT['chain_findings'])
        self.assertEqual((entries[0]['path'], entries[0]['line']), ('app/config.py', 7))

    def test_b_with_only_a_build_folder_the_folder_is_named_not_a_guessed_file(self):
        entries = sarif_export._chain_entries([{**ASSESSMENT['chain_findings'][0], 'evidence': {'build_context': 'app/'}}])
        self.assertEqual((entries[0]['path'], entries[0]['line']), ('app', None))


if __name__ == '__main__':
    unittest.main()
