"""The IaC stage, the SBOM export and the three nginx checks added in B5.

All three close the same kind of gap: a layer that was simply not read, which on
any dashboard is indistinguishable from a clean one.
"""
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from isolation import isolate_triage
from zanjir import findings, iac, pipeline, repository, sbom


def misconfig(check='DS-0002', severity='HIGH', status='FAIL', line=None, provider='Dockerfile'):
    row = {'ID': check, 'Title': 'Image user should not be root', 'Message': 'Specify a USER',
           'Resolution': 'Add USER', 'Severity': severity, 'Status': status,
           'Type': 'Dockerfile Security Check', 'PrimaryURL': 'https://avd.aquasec.com/misconfig/' + check.lower(),
           'CauseMetadata': {'Provider': provider, 'Service': 'general'}}
    if line:
        row['CauseMetadata']['StartLine'] = line
    return row


def trivy_config(rows, target='app/Dockerfile'):
    return {'Results': [{'Target': target, 'Type': 'dockerfile', 'Misconfigurations': list(rows)}]}


class NormaliseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        (self.tmp / 'app').mkdir(parents=True)
        (self.tmp / 'app/Dockerfile').write_text('FROM alpine\n', encoding='utf-8')

    def test_a_a_failing_check_becomes_a_tagged_finding(self):
        report = iac.normalize(trivy_config([misconfig(line=3)]), self.tmp)
        self.assertEqual(report['count'], 1)
        row = report['findings'][0]
        self.assertEqual(row['rule_id'], 'DS-0002')
        self.assertEqual(row['path'], 'app/Dockerfile')
        self.assertEqual(row['line'], 3)
        self.assertEqual(row['severity'], 'HIGH')
        self.assertEqual(row['level'], 'error')
        self.assertEqual(row['cwe_ids'], ['CWE-250'])
        self.assertFalse(row['verified'])
        self.assertRegex(row['fingerprint'], r'^[0-9a-f]{24}$')

    def test_b_only_failures_are_findings(self):
        report = iac.normalize(trivy_config([misconfig(status='PASS'), misconfig(status='EXCEPTION')]), self.tmp)
        self.assertEqual(report['count'], 0)
        self.assertEqual(report['coverage'][0]['checks'], 2, 'qamrov baribir ko‘rsatilishi kerak')

    def test_c_an_unmapped_check_keeps_its_id_and_gets_no_category(self):
        """A guessed OWASP category is worse than an honest blank."""
        report = iac.normalize(trivy_config([misconfig(check='DS-9999')]), self.tmp)
        row = report['findings'][0]
        self.assertEqual(row['cwe_ids'], [])
        self.assertEqual(row['owasp_top10_2025'], [])
        self.assertEqual(report['untagged_checks'], ['DS-9999'])
        self.assertIn('taxmin qilinmaydi', report['untagged_note'])

    def test_d_a_malformed_result_is_refused(self):
        for bad in ({}, {'Results': 'x'}, {'Results': ['x']}):
            with self.assertRaises(ValueError):
                iac.normalize(bad, self.tmp)

    def test_e_the_identity_separates_two_providers_sharing_a_check_id(self):
        docker = iac.normalize(trivy_config([misconfig(provider='Dockerfile')]), self.tmp)['findings'][0]
        kube = iac.normalize(trivy_config([misconfig(provider='Kubernetes')]), self.tmp)['findings'][0]
        self.assertNotEqual(docker['fingerprint'], kube['fingerprint'])

    def test_f_the_identity_ignores_the_line_number(self):
        """Trivy reports a line for some checks and not others; the identity must
        not depend on which kind a check happens to be."""
        with_line = iac.normalize(trivy_config([misconfig(line=3)]), self.tmp)['findings'][0]
        without = iac.normalize(trivy_config([misconfig()]), self.tmp)['findings'][0]
        self.assertEqual(with_line['fingerprint'], without['fingerprint'])
        self.assertIn('iac', findings.FIELDS_PER_TOOL)


class PipelineStageTests(unittest.TestCase):
    def setUp(self):
        isolate_triage(self)

    def test_a_a_payload_without_iac_target_is_still_valid(self):
        """Every caller written before B5 keeps working unchanged."""
        pipeline.validate({'target': '', 'web_target': '', 'image_target': '',
                           'repository_target': 'chain-demo', 'online': True})

    def test_b_an_empty_iac_target_is_accepted_and_selects_nothing(self):
        pipeline.validate({'target': '', 'web_target': '', 'image_target': '',
                           'repository_target': 'chain-demo', 'iac_target': '', 'online': True})

    def test_c_an_unknown_iac_target_is_refused(self):
        with self.assertRaises(ValueError):
            pipeline.validate({'target': '', 'web_target': '', 'image_target': '',
                               'repository_target': 'chain-demo', 'iac_target': 'yo-q', 'online': True})

    def test_d_an_unknown_field_is_still_refused(self):
        with self.assertRaises(ValueError):
            pipeline.validate({'target': '', 'web_target': '', 'image_target': '',
                               'repository_target': 'chain-demo', 'nimadir': '', 'online': True})

    def test_e_iac_is_a_passive_stage_and_has_a_title(self):
        self.assertIn('iac', pipeline.PASSIVE_STAGES)
        self.assertIn('iac', pipeline.STAGE_TITLES)
        self.assertIn('iac', pipeline.MODULES)

    def test_f_stage_rows_render_the_iac_stage(self):
        headers, rows = pipeline.stage_rows('iac', [{'rule_id': 'DS-0002', 'severity': 'HIGH',
                                                     'path': 'Dockerfile', 'line': 3, 'title': 'root'}])
        self.assertEqual(headers, ('Tekshiruv', 'Og‘irlik', 'Fayl', 'Sarlavha'))
        self.assertEqual(rows, [('DS-0002', 'HIGH', 'Dockerfile:3', 'root')])


class SbomTests(unittest.TestCase):
    def report(self, packages=(), **extra):
        return {'id': '20260101T000000-aaaaaaaa', 'target': 'img-app', 'state': 'completed',
                'created_at': '2026-01-01T00:00:00+00:00',
                'reference': 'acme/app@sha256:' + 'a' * 64, 'tool': {'version': '0.74.0'},
                'packages': list(packages), **extra}

    def package(self, name='openssl', version='3.0.1', purl='pkg:apk/alpine/openssl@3.0.1', licenses=('MIT',)):
        return {'name': name, 'version': version, 'purl': purl, 'type': 'alpine',
                'target': 'rootfs', 'licenses': list(licenses)}

    def test_a_a_cyclonedx_document_is_produced(self):
        document = sbom.build(self.report([self.package()]))
        self.assertEqual(document['bomFormat'], 'CycloneDX')
        self.assertEqual(document['specVersion'], '1.6')
        self.assertTrue(document['serialNumber'].startswith('urn:uuid:'))
        self.assertEqual(document['metadata']['component']['type'], 'container')
        component = document['components'][0]
        self.assertEqual((component['name'], component['version']), ('openssl', '3.0.1'))
        self.assertEqual(component['purl'], 'pkg:apk/alpine/openssl@3.0.1')
        self.assertEqual(component['licenses'], [{'license': {'name': 'MIT'}}])

    def test_a2_the_document_carries_every_field_the_spec_requires(self):
        """No JSON-Schema validator is available (this project has no Python
        dependencies), so the required fields of CycloneDX 1.6 are asserted
        directly. The document was additionally cross-checked against Trivy's
        own `--format cyclonedx` output for the same image: all 14 PURLs matched
        exactly, with nothing missing and nothing invented."""
        document = sbom.build(self.report([self.package()]))
        self.assertEqual(document['$schema'], 'http://cyclonedx.org/schema/bom-1.6.schema.json')
        for field in ('bomFormat', 'specVersion', 'version', 'metadata', 'components'):
            self.assertIn(field, document)
        self.assertIsInstance(document['version'], int)
        self.assertRegex(document['serialNumber'], r'^urn:uuid:[0-9a-f-]{36}$')
        self.assertIn('timestamp', document['metadata'])
        for component in document['components']:
            self.assertIn(component['type'], {'library', 'application', 'container', 'framework',
                                              'operating-system', 'device', 'file'})
            self.assertTrue(component['name'])
            self.assertIn('bom-ref', component)

    def test_b_a_report_without_a_package_list_is_an_error_not_an_empty_sbom(self):
        """An SBOM claiming zero components would be a false statement."""
        report = self.report()
        del report['packages']
        with self.assertRaises(ValueError) as caught:
            sbom.build(report)
        self.assertIn('qayta skanerlang', str(caught.exception))

    def test_c_a_package_without_a_purl_still_gets_a_stable_reference(self):
        first = sbom.build(self.report([self.package(purl='')]))['components'][0]['bom-ref']
        again = sbom.build(self.report([self.package(purl='')]))['components'][0]['bom-ref']
        self.assertEqual(first, again)
        self.assertTrue(first.startswith('urn:threatchain:'))

    def test_d_the_coverage_limit_is_stated_in_the_document(self):
        document = sbom.build(self.report([self.package()]))
        note = [p for p in document['metadata']['properties'] if p['name'] == 'threatchain:coverage_note']
        self.assertTrue(note and 'to‘liq kafolati emas' in note[0]['value'])

    def test_e_a_merged_document_keeps_the_images_apart(self):
        first = self.report([self.package()], target='img-a')
        second = self.report([self.package()], target='img-b')
        document = sbom.merge([first, second], name='loyiha')
        self.assertEqual(len(document['components']), 2, 'bir xil paket ikki image uchun birlashtirilmasligi kerak')
        self.assertEqual(len({c['bom-ref'] for c in document['components']}), 2)
        self.assertEqual(document['dependencies'][0]['ref'], 'loyiha')

    def test_f_images_without_a_package_list_are_counted_not_dropped(self):
        usable = self.report([self.package()], target='img-a')
        old = self.report(target='img-b')
        del old['packages']
        document = sbom.merge([usable, old], name='loyiha')
        skipped = [p for p in document['metadata']['properties'] if p['name'] == 'threatchain:skipped_images']
        self.assertEqual(skipped[0]['value'], '1')

    def test_g_merging_nothing_usable_is_an_error(self):
        old = self.report(target='img-b')
        del old['packages']
        with self.assertRaises(ValueError):
            sbom.merge([old])


class NginxCheckTests(unittest.TestCase):
    """RP-009, RP-010 and RP-011: three ways an nginx file undoes its own protection."""

    def checks(self, text):
        return {(i['rule'], i['location']) for i in repository.nginx_checks(repository.nginx_tree(text, {}))}

    def test_a_alias_without_a_trailing_slash_on_the_location_is_traversable(self):
        self.assertIn(('RP-009', '/files'),
                      self.checks('server { location /files { alias /var/data/; } }'))

    def test_b_a_trailing_slash_makes_the_same_pair_safe(self):
        self.assertEqual(self.checks('server { location /safe/ { alias /var/data/; } }'), set())

    def test_c_an_exact_or_regex_location_is_not_traversable(self):
        for modifier in ('=', '~', '~*', '^~'):
            self.assertEqual(self.checks('server { location %s /files { alias /var/data/; } }' % modifier), set(),
                             modifier)

    def test_d_a_client_controlled_upstream_is_ssrf(self):
        for variable in ('$http_x_target', '$arg_url', '$host', '$request_uri'):
            self.assertIn(('RP-010', '/fetch'),
                          self.checks('server { location /fetch { proxy_pass http://%s/x; } }' % variable), variable)

    def test_e_a_fixed_upstream_is_not_ssrf(self):
        self.assertEqual(self.checks('server { location /api { proxy_pass http://backend:80; } }'), set())

    def test_f_an_internal_variable_upstream_is_not_flagged(self):
        """$backend comes from an upstream block or a map, not from the caller."""
        self.assertEqual(self.checks('server { location /api { proxy_pass http://$backend; } }'), set())

    def test_g_a_nested_add_header_drops_the_parent_security_headers(self):
        text = ('server { add_header Strict-Transport-Security "max-age=1"; '
                'location /api { add_header X-Cache HIT; } }')
        issues = repository.nginx_checks(repository.nginx_tree(text, {}))
        self.assertEqual([i['rule'] for i in issues], ['RP-011'])
        self.assertEqual(issues[0]['value'], 'strict-transport-security')

    def test_h_a_block_that_adds_no_header_of_its_own_keeps_inheriting(self):
        text = 'server { add_header Strict-Transport-Security "max-age=1"; location /api { proxy_pass http://b; } }'
        self.assertEqual(self.checks(text), set())

    def test_i_re_declaring_the_header_is_not_a_finding(self):
        text = ('server { add_header Strict-Transport-Security "max-age=1"; '
                'location /api { add_header Strict-Transport-Security "max-age=1"; add_header X-Cache HIT; } }')
        self.assertEqual(self.checks(text), set())

    def test_j_dropping_a_non_security_header_is_not_a_finding(self):
        text = 'server { add_header X-Powered-By nginx; location /api { add_header X-Cache HIT; } }'
        self.assertEqual(self.checks(text), set())

    def test_k_every_new_rule_has_text_and_a_cwe(self):
        from zanjir import taxonomy
        for rule in repository.NGINX_CHECK_RULES:
            self.assertIn(rule, repository.RULES)
            self.assertTrue(taxonomy.tag_static('repository', rule)['cwe_ids'], rule)


if __name__ == '__main__':
    unittest.main()
