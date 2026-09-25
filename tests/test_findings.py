"""The shared finding identity: what must stay the same, and what must not.

Everything B2 and B3 will build -- triage decisions that survive a rescan, a
baseline that tells a new finding from an old one -- rests on these properties.
They are asserted through the scanners' own normalisation code rather than by
calling findings.fingerprint() directly, because the part that breaks in
practice is a module passing the wrong field, not the hash itself.
"""
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from zanjir import advisories, chains, findings, images, sarif_export, scanners, webscan

SOURCE = """import os\nimport requests\n\nAPI = "https://example.test"\n\n\ndef fetch(url):\n    return requests.get(url, verify=False)\n"""


class ModuleTests(unittest.TestCase):
    def test_a_unknown_tool_and_wrong_fields_are_refused(self):
        with self.assertRaises(ValueError):
            findings.fingerprint('nessus', {})
        with self.assertRaises(ValueError):
            findings.fingerprint('semgrep', {'rule_id': 'r', 'path': 'a.py'})          # yetmaydi
        with self.assertRaises(ValueError):
            findings.fingerprint('semgrep', {'rule_id': 'r', 'path': 'a.py', 'context': 'x', 'line': 3})  # ortiqcha

    def test_b_repository_keeps_its_own_identity(self):
        """It already had one, and its saved reviews are keyed by it."""
        for tool in findings.REUSED:
            with self.assertRaises(ValueError):
                findings.fingerprint(tool, {})

    def test_c_whitespace_and_indentation_do_not_change_an_identity(self):
        plain = findings.fingerprint('semgrep', {'rule_id': 'r', 'path': 'a.py', 'context': 'return get(u, verify=False)'})
        indented = findings.fingerprint('semgrep', {'rule_id': 'r', 'path': 'a.py',
                                                    'context': '\t    return get(u,   verify=False)   \n'})
        self.assertEqual(plain, indented)

    def test_d_a_long_line_cannot_put_a_whole_file_into_the_hash(self):
        long_line = 'x' * 5000
        self.assertEqual(len(findings.context(long_line)), findings.CONTEXT_LIMIT)

    def test_e_identity_is_24_hex_characters(self):
        value = findings.fingerprint('web', {'rule_id': 'r', 'path': '/', 'method': 'GET'})
        self.assertRegex(value, r'^[0-9a-f]{24}$')

    def test_e2_every_scanner_that_produces_findings_declares_an_identity(self):
        """A new scanner must not be able to ship without one: a stage whose
        findings have no fingerprint is invisible to triage and to the baseline,
        and nothing else would report that."""
        declared = set(findings.FIELDS_PER_TOOL) | set(findings.REUSED)
        produced = {'semgrep', 'gitleaks', 'pmd', 'dependencies', 'images', 'web', 'repository', 'chain', 'iac'}
        self.assertEqual(produced - declared, set(), 'identitetsiz skaner qolgan')

    def test_f_version_is_part_of_the_hash(self):
        """A future v2 must not be able to collide with a v1 identity."""
        before = findings.fingerprint('web', {'rule_id': 'r', 'path': '/', 'method': 'GET'})
        original = findings.VERSION
        try:
            findings.VERSION = 'threatchain/v2'
            after = findings.fingerprint('web', {'rule_id': 'r', 'path': '/', 'method': 'GET'})
        finally:
            findings.VERSION = original
        self.assertNotEqual(before, after)


class CodeScannerTests(unittest.TestCase):
    """normalize() is the real code path; the scanner output around it is synthetic."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.source = self.tmp / 'source'
        self.source.mkdir()
        self.write(SOURCE)

    def write(self, text, name='app.py'):
        (self.source / name).write_text(text, encoding='utf-8')

    def semgrep(self, path='app.py', line=8, rule='zanjir.python.tls-verification-disabled'):
        return {'results': [{'check_id': rule, 'path': path, 'start': {'line': line},
                             'extra': {'severity': 'ERROR', 'metadata': {'cwe': ['CWE-295: x']}}}]}

    def gitleaks(self, path='app.py', line=4, column=7, entropy=4.5, rule='generic-api-key'):
        return [{'RuleID': rule, 'File': path, 'StartLine': line, 'StartColumn': column,
                 'Entropy': entropy, 'Secret': 'REDACTED', 'Match': 'REDACTED'}]

    def pmd(self, path='app.py', line=8, rule='ApexSOQLInjection'):
        return {'files': [{'filename': path, 'violations': [{'rule': rule, 'beginline': line, 'priority': 3}]}]}

    def one(self, tool, data):
        rows = scanners.normalize(tool, data, self.source)
        self.assertEqual(len(rows), 1)
        return rows[0]

    def test_a_every_code_tool_produces_a_fingerprint(self):
        for tool, data in (('semgrep', self.semgrep()), ('gitleaks', self.gitleaks()), ('pmd', self.pmd())):
            with self.subTest(tool=tool):
                self.assertRegex(self.one(tool, data)['fingerprint'], r'^[0-9a-f]{24}$')

    def test_b_scanning_the_same_code_twice_gives_the_same_identity(self):
        for tool, data in (('semgrep', self.semgrep()), ('gitleaks', self.gitleaks()), ('pmd', self.pmd())):
            with self.subTest(tool=tool):
                self.assertEqual(self.one(tool, data)['fingerprint'], self.one(tool, data)['fingerprint'])

    def test_c_ten_lines_added_at_the_top_do_not_change_the_identity(self):
        """The property the whole design exists for: an unrelated edit above a
        finding must not present it as new and drop its triage decision."""
        before = self.one('semgrep', self.semgrep(line=8))['fingerprint']
        self.write('# yangi izoh\n' * 10 + SOURCE)
        after = self.one('semgrep', self.semgrep(line=18))['fingerprint']
        self.assertEqual(before, after)

    def test_d_reindenting_the_matched_line_does_not_change_the_identity(self):
        before = self.one('semgrep', self.semgrep(line=8))['fingerprint']
        self.write(SOURCE.replace('    return requests.get', '        return requests.get'))
        self.assertEqual(self.one('semgrep', self.semgrep(line=8))['fingerprint'], before)

    def test_e_a_different_rule_file_or_line_text_is_a_different_finding(self):
        base = self.one('semgrep', self.semgrep())['fingerprint']
        self.assertNotEqual(self.one('semgrep', self.semgrep(rule='zanjir.python.eval'))['fingerprint'], base)
        self.write(SOURCE, 'other.py')
        self.assertNotEqual(self.one('semgrep', self.semgrep(path='other.py'))['fingerprint'], base)
        self.write(SOURCE.replace('verify=False', 'verify=False, timeout=1'))
        self.assertNotEqual(self.one('semgrep', self.semgrep())['fingerprint'], base)

    def test_f_two_secrets_of_one_rule_in_one_file_stay_apart(self):
        first = self.one('gitleaks', self.gitleaks(column=7, entropy=4.5))['fingerprint']
        second = self.one('gitleaks', self.gitleaks(column=31, entropy=4.9))['fingerprint']
        self.assertNotEqual(first, second)

    def test_g_the_secret_cannot_be_recovered_and_is_never_stored(self):
        """gitleaks runs with --redact=100, so nothing secret reaches the hash."""
        self.assertNotIn('secret', findings.FIELDS_PER_TOOL['gitleaks'])
        row = self.one('gitleaks', self.gitleaks())
        self.assertEqual(row['secret_value'], 'hidden')
        # The identity is reproducible from the four public fields alone, which is
        # only possible because none of it comes from the secret's contents.
        self.assertEqual(row['fingerprint'],
                         findings.fingerprint('gitleaks', {'rule_id': 'generic-api-key', 'path': 'app.py',
                                                           'column': 7, 'entropy': 4.5}))

    def test_h_a_missing_source_line_still_yields_an_identity(self):
        """A file that cannot be read must weaken the identity, not break the scan."""
        row = self.one('semgrep', self.semgrep(line=9999))
        self.assertRegex(row['fingerprint'], r'^[0-9a-f]{24}$')


class OtherScannerTests(unittest.TestCase):
    def test_a_web_findings_carry_a_fingerprint_and_keep_their_id(self):
        row = webscan.finding('http-transport', 'sarlavha', 'LOW', '/api', 'dalil', 'tuzatish')
        self.assertRegex(row['fingerprint'], r'^[0-9a-f]{24}$')
        self.assertRegex(row['id'], r'^[0-9a-f]{24}$')
        self.assertNotEqual(row['fingerprint'], row['id'])
        other = webscan.finding('http-transport', 'sarlavha', 'LOW', '/boshqa', 'dalil', 'tuzatish')
        self.assertNotEqual(row['fingerprint'], other['fingerprint'])

    def trivy(self, target, package='openssl', version='1.1.1', advisory='CVE-2026-1'):
        return {'ArtifactType': 'container_image',
                'Results': [{'Target': target, 'Class': 'os-pkgs', 'Type': 'debian', 'Packages': [],
                             'Vulnerabilities': [{'PkgName': package, 'InstalledVersion': version,
                                                  'VulnerabilityID': advisory, 'Severity': 'CRITICAL'}]}]}

    def test_b_the_same_cve_in_two_images_is_two_findings(self):
        """The module's own `id` cannot tell them apart; the fingerprint must."""
        first = images.normalize(self.trivy('rootfs'), 'pilot-crapi-web')['findings'][0]
        second = images.normalize(self.trivy('rootfs'), 'pilot-crapi-identity')['findings'][0]
        self.assertEqual(first['id'], second['id'])
        self.assertNotEqual(first['fingerprint'], second['fingerprint'])

    def test_c_an_image_rebuild_keeps_the_identity_of_an_unfixed_finding(self):
        """Trivy's scan target is a layer path and changes between builds."""
        before = images.normalize(self.trivy('rootfs'), 'pilot-crapi-web')['findings'][0]
        after = images.normalize(self.trivy('sha256:0bc/rootfs'), 'pilot-crapi-web')['findings'][0]
        self.assertNotEqual(before['id'], after['id'])
        self.assertEqual(before['fingerprint'], after['fingerprint'])

    def test_d_an_upgrade_that_does_not_fix_the_cve_keeps_the_same_identity(self):
        """Same rule as dependencies below: a still-unfixed CVE is still the same
        finding, and an upgrade that does fix it removes the finding anyway."""
        before = images.normalize(self.trivy('rootfs', version='1.1.1'), 'app')['findings'][0]
        after = images.normalize(self.trivy('rootfs', version='1.1.2'), 'app')['findings'][0]
        self.assertNotEqual(before['id'], after['id'])
        self.assertEqual(before['fingerprint'], after['fingerprint'])

    def test_d2_a_different_package_with_the_same_cve_stays_apart(self):
        first = images.normalize(self.trivy('rootfs', package='openssl'), 'app')['findings'][0]
        second = images.normalize(self.trivy('rootfs', package='libssl'), 'app')['findings'][0]
        self.assertNotEqual(first['fingerprint'], second['fingerprint'])

    def advisory_rows(self, version):
        package = {'ecosystem': 'PyPI', 'name': 'flask', 'version': version, 'path': 'requirements.txt'}
        record = {'id': 'CVE-2026-77', 'summary': 'x', 'affected': [], 'severity': [],
                  'database_specific': {'severity': 'HIGH'}}
        key = ('PyPI', 'flask', version)
        return advisories.normalize([package], {key: [record['id']]}, {record['id']: record}, {}, True)

    def test_e_a_dependency_keeps_its_identity_across_a_version_bump(self):
        before = self.advisory_rows('2.0.0')[0]
        after = self.advisory_rows('2.0.1')[0]
        self.assertNotEqual(before['id'], after['id'])
        self.assertEqual(before['fingerprint'], after['fingerprint'])


class ChainTests(unittest.TestCase):
    def reports(self, secret_fingerprint='aaaaaaaaaaaaaaaaaaaaaaaa'):
        code = {'findings': [{'tool': 'gitleaks', 'rule_id': 'stripe-access-token', 'path': 'app/config.py',
                              'line': 7, 'fingerprint': secret_fingerprint}]}
        repository = {'services': [{'id': 'web', 'build_context': 'app', 'image': '',
                                    'ports': [{'host_ip': '0.0.0.0', 'host_port': '8080', 'scope': 'all-interfaces'}],
                                    'networks': []}]}
        return code, repository

    def test_a_a_chain_finding_is_identified_by_its_components(self):
        rows = chains.correlate(*self.reports())
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['fingerprint'], findings.derived('SX-001', ['web', 'a' * 24]))

    def test_b_a_different_secret_is_a_different_chain(self):
        first = chains.correlate(*self.reports('a' * 24))[0]['fingerprint']
        second = chains.correlate(*self.reports('b' * 24))[0]['fingerprint']
        self.assertNotEqual(first, second)

    def test_c_a_pre_b1_report_without_fingerprints_still_correlates(self):
        code, repository = self.reports()
        del code['findings'][0]['fingerprint']
        rows = chains.correlate(code, repository)
        self.assertRegex(rows[0]['fingerprint'], r'^[0-9a-f]{24}$')


class SarifTests(unittest.TestCase):
    """GitHub and GitLab track a result across runs by partialFingerprints."""

    def report(self):
        return {
            'id': '20260101T000000-abcdef12', 'state': 'completed', 'created_at': '', 'limits': '',
            'selection': {}, 'stages': [
                {'kind': 'code', 'report': {'findings': [
                    {'tool': 'semgrep', 'rule_id': 'r', 'path': 'a.py', 'line': 1,
                     'severity': 'ERROR', 'fingerprint': 'c' * 24, 'cwe_ids': []}]}},
                {'kind': 'dependencies', 'report': {'findings': [
                    {'package': {'name': 'flask', 'version': '2.0'}, 'advisory_id': 'CVE-1',
                     'severity': 'HIGH', 'fingerprint': 'd' * 24, 'cwe_ids': []}]}},
                {'kind': 'images', 'report': {'findings': [
                    {'package': 'openssl', 'version': '1.1', 'advisory_id': 'CVE-2',
                     'severity': 'HIGH', 'fingerprint': 'e' * 24, 'cwe_ids': []}]}},
                {'kind': 'web', 'report': {'findings': [
                    {'rule_id': 'w', 'title': 'x', 'path': '/', 'severity': 'LOW',
                     'fingerprint': 'f' * 24, 'cwe_ids': []}]}},
            ],
            'chain_findings': [{'rule_id': 'SX-001', 'title': 'x', 'level': 'warning',
                                'cwe_ids': [], 'fingerprint': '9' * 24, 'evidence': {}}],
        }

    def test_a_every_stage_carries_its_fingerprint_into_sarif(self):
        document = sarif_export.build(self.report())
        seen = [result.get('partialFingerprints', {}).get(findings.VERSION)
                for run in document['runs'] for result in run['results']]
        self.assertEqual(seen, ['c' * 24, 'd' * 24, 'e' * 24, 'f' * 24, '9' * 24])

    def test_b_a_pre_b1_report_exports_without_the_key_rather_than_a_null(self):
        report = self.report()
        for stage in report['stages']:
            for row in stage['report']['findings']:
                del row['fingerprint']
        for row in report['chain_findings']:
            del row['fingerprint']
        document = sarif_export.build(report)
        for run in document['runs']:
            for result in run['results']:
                self.assertNotIn('partialFingerprints', result)


if __name__ == '__main__':
    unittest.main()
