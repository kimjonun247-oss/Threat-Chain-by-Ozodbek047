import unittest

from zanjir import chains, portfolio
from zanjir.chains import correlate


def gitleaks(path, line=5, rule_id='generic-api-key'):
    return {'tool': 'gitleaks', 'rule_id': rule_id, 'path': path, 'line': line, 'secret_value': 'hidden'}


def service(sid, build_context, loopback=False):
    scope = 'loopback' if loopback else 'all_interfaces'
    return {'id': sid, 'build_context': build_context, 'ports': [{'scope': scope}]}


def weakness(path, cwe='CWE-89', tool='semgrep', severity='ERROR', rule_id='sql-injection', line=42):
    return {'tool': tool, 'rule_id': rule_id, 'path': path, 'line': line, 'severity': severity,
            'cwe_ids': [cwe], 'fingerprint': path + ':' + cwe}


class ChainSecretsTests(unittest.TestCase):
    def test_secret_in_exposed_service_source_is_flagged(self):
        # Individually plausible: a hardcoded value in dev code, and publishing
        # a port, are each ordinary. Combined: however that service is later
        # breached, the secret is already sitting right there for the taking.
        code_report = {'findings': [gitleaks('services/web/config.py')]}
        repository_report = {'services': [service('web', 'services/web')]}
        findings = correlate(code_report, repository_report)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f['rule_id'], 'SX-001')
        self.assertEqual(f['service_id'], 'web')
        self.assertFalse(f['verified'])
        self.assertEqual(f['cwe_ids'], ['CWE-798', 'CWE-668'])
        self.assertEqual({o['code'] for o in f['owasp_top10_2025']}, {'A07', 'A01'})

    def test_secret_value_is_never_reused_or_reexposed(self):
        code_report = {'findings': [gitleaks('services/web/config.py')]}
        repository_report = {'services': [service('web', 'services/web')]}
        findings = correlate(code_report, repository_report)
        self.assertNotIn('secret_value', findings[0])
        self.assertNotIn('secret_value', findings[0]['evidence'])

    def test_loopback_only_exposure_is_not_flagged(self):
        code_report = {'findings': [gitleaks('services/web/config.py')]}
        repository_report = {'services': [service('web', 'services/web', loopback=True)]}
        self.assertEqual(correlate(code_report, repository_report), [])

    def test_service_without_build_context_is_not_flagged(self):
        code_report = {'findings': [gitleaks('services/web/config.py')]}
        repository_report = {'services': [service('web', None)]}
        self.assertEqual(correlate(code_report, repository_report), [])

    def test_secret_under_unrelated_service_path_is_not_flagged(self):
        code_report = {'findings': [gitleaks('services/other/config.py')]}
        repository_report = {'services': [service('web', 'services/web')]}
        self.assertEqual(correlate(code_report, repository_report), [])

    def test_similarly_prefixed_sibling_directory_is_not_confused_for_a_match(self):
        # "services/web-admin" must not match build_context "services/web".
        code_report = {'findings': [gitleaks('services/web-admin/config.py')]}
        repository_report = {'services': [service('web', 'services/web')]}
        self.assertEqual(correlate(code_report, repository_report), [])

    def test_root_build_context_chains_every_source_path(self):
        # `build: .` normalises to build_context '' -- the whole source tree is
        # this service's -- so a root-level finding must chain. Leaving it as '.'
        # (or None) is the SCAN-1 false negative: `app.py` has no `./` to match.
        code_report = {'findings': [gitleaks('config.py'), gitleaks('app/db.py')]}
        repository_report = {'services': [service('web', '')]}
        findings = correlate(code_report, repository_report)
        self.assertEqual(len(findings), 2)
        self.assertEqual({f['service_id'] for f in findings}, {'web'})
        self.assertIn('loyiha ildizi', findings[0]['detail'])

    def test_in_context_matches_root_but_a_sub_path_stays_scoped(self):
        self.assertTrue(chains.in_context('anything/here.py', ''))     # root build: all paths
        self.assertTrue(chains.in_context('services/web/x.py', 'services/web'))
        self.assertFalse(chains.in_context('services/web-admin/x.py', 'services/web'))
        self.assertFalse(chains.in_context('other/x.py', 'services/web'))

    def test_semgrep_findings_are_not_treated_as_secrets(self):
        code_report = {'findings': [{'tool': 'semgrep', 'rule_id': 'x', 'path': 'services/web/app.py', 'line': 1}]}
        repository_report = {'services': [service('web', 'services/web')]}
        self.assertEqual(correlate(code_report, repository_report), [])

    def test_empty_reports_produce_no_findings(self):
        self.assertEqual(correlate({}, {}), [])
        self.assertEqual(correlate(None, None), [])


if __name__ == '__main__':
    unittest.main(verbosity=2)


# -- SX-002 / SX-003: an exposed service and the CVEs of the image it runs -----

def exposed(sid='web', image='acme/app:1.0', ports=(('0.0.0.0', '8080', 8080, 'all_interfaces'),)):
    return {'id': sid, 'image': image, 'build_context': None, 'networks': ['default'],
            'ports': [{'host_ip': ip, 'published': published, 'target': target, 'protocol': 'tcp', 'scope': scope}
                      for ip, published, target, scope in ports]}


def internal(sid='db', image='postgres:14'):
    return {'id': sid, 'image': image, 'build_context': None, 'networks': ['default'], 'ports': []}


def cve(advisory='CVE-2026-1', severity='CRITICAL', exploited=False, fixed='', package='openssl'):
    return {'advisory_id': advisory, 'package': package, 'version': '1.0.0', 'severity': severity,
            'known_exploited': exploited, 'kev_added_on': '2026-01-01' if exploited else None,
            'epss': {'epss': 0.94, 'percentile': 0.99} if exploited else None, 'fixed_version': fixed}


def image_report(findings, target='img-app', state='completed', kev='available'):
    return {'id': '20260101T000000-aaaaaaaa', 'target': target, 'state': state,
            'reference': 'acme/app@sha256:' + 'a' * 64, 'kev': {'state': kev}, 'findings': list(findings)}


def links(target='img-app', service='web', how='image_name'):
    return {target: {'service': service, 'how': how}}


class ImageChainTests(unittest.TestCase):
    def run_chain(self, services, images, link_map, rp006=(), ambiguous=()):
        return chains.image_chains({'services': services}, images, link_map, set(rp006), ambiguous)

    def test_a_exposed_service_with_a_known_exploited_cve_is_flagged(self):
        rows, gaps = self.run_chain([exposed()], {'img-app': image_report([cve(exploited=True)])}, links())
        self.assertEqual([r['rule_id'] for r in rows], ['SX-002'])
        row = rows[0]
        self.assertEqual(row['service_id'], 'web')
        self.assertEqual(row['level'], 'error')          # KEV outranks a plain CRITICAL
        self.assertFalse(row['verified'])
        self.assertEqual(row['cwe_ids'], ['CWE-1395', 'CWE-668'])
        self.assertEqual({o['code'] for o in row['owasp_top10_2025']}, {'A03', 'A01'})
        self.assertEqual(gaps, [])

    def test_b_the_evidence_names_both_halves_of_the_chain(self):
        rows, _ = self.run_chain([exposed()], {'img-app': image_report([cve(exploited=True, fixed='1.0.1')])}, links())
        evidence = rows[0]['evidence']
        self.assertEqual(evidence['compose_service'], 'web')
        self.assertIn('0.0.0.0:8080', evidence['host_ports'])
        self.assertTrue(evidence['image_reference'].startswith('acme/app@sha256:'))
        self.assertEqual(evidence['advisory_id'], 'CVE-2026-1')
        self.assertEqual(evidence['kev_added_on'], '2026-01-01')
        self.assertEqual(evidence['epss'], 0.94)
        self.assertEqual(evidence['fixed_version'], '1.0.1')
        self.assertEqual(evidence['link'], 'image_name')

    def test_c_a_loopback_only_service_is_not_exposed(self):
        """crAPI binds every port to 127.0.0.1, which is exactly this case."""
        service = exposed(ports=(('127.0.0.1', '8080', 8080, 'loopback'),))
        rows, gaps = self.run_chain([service], {'img-app': image_report([cve(exploited=True)])}, links())
        self.assertEqual(rows, [])
        self.assertEqual(gaps, [])

    def test_d_an_internal_service_is_not_chained(self):
        rows, _ = self.run_chain([internal()], {'img-db': image_report([cve(exploited=True)], target='img-db')},
                                 links('img-db', 'db'))
        self.assertEqual(rows, [])

    def test_e_a_low_severity_cve_alone_is_not_a_chain(self):
        rows, _ = self.run_chain([exposed()], {'img-app': image_report([cve(severity='HIGH')])}, links())
        self.assertEqual(rows, [])

    def test_f_a_critical_cve_without_kev_still_chains_at_warning_level(self):
        rows, _ = self.run_chain([exposed()], {'img-app': image_report([cve(severity='CRITICAL')])}, links())
        self.assertEqual([(r['rule_id'], r['level']) for r in rows], [('SX-002', 'warning')])

    def test_g_an_unlinked_image_is_reported_not_skipped(self):
        """An unchecked image must not look like a clean one."""
        rows, gaps = self.run_chain([exposed()], {'img-app': image_report([cve(exploited=True)])}, {})
        self.assertEqual(rows, [])
        self.assertEqual([g['kind'] for g in gaps], ['image_unlinked'])
        self.assertIn('bog‘lanmadi', gaps[0]['detail'])

    def test_h_a_missing_kev_catalogue_is_stated_and_the_rule_keeps_working(self):
        """Treating "KEV unavailable" as "nothing is exploited" would be the silent,
        wrong answer; the severity half of the condition still works."""
        images = {'img-app': image_report([cve(severity='CRITICAL')], kev='unavailable')}
        rows, gaps = self.run_chain([exposed()], images, links())
        self.assertEqual([r['rule_id'] for r in rows], ['SX-002'])
        self.assertEqual([g['kind'] for g in gaps], ['kev_unavailable'])
        self.assertIn('o‘tkazib yuborilgan', gaps[0]['detail'])

    def test_i_an_unfinished_image_scan_is_a_gap_not_a_silence(self):
        images = {'img-app': image_report([cve(exploited=True)], state='failed')}
        rows, gaps = self.run_chain([exposed()], images, links())
        self.assertEqual(rows, [])
        self.assertEqual([g['kind'] for g in gaps], ['image_not_scanned'])

    def test_j_sx003_needs_all_three_conditions(self):
        images = {'img-app': image_report([cve(exploited=True, fixed='1.0.1')])}
        with_debug = self.run_chain([exposed()], images, links(), rp006=['web'])[0]
        self.assertEqual(sorted(r['rule_id'] for r in with_debug), ['SX-002', 'SX-003'])
        # no debug
        self.assertEqual(sorted(r['rule_id'] for r in self.run_chain([exposed()], images, links())[0]), ['SX-002'])
        # debug but no fix available
        no_fix = {'img-app': image_report([cve(exploited=True, fixed='')])}
        self.assertEqual(sorted(r['rule_id'] for r in self.run_chain([exposed()], no_fix, links(), ['web'])[0]),
                         ['SX-002'])

    def test_j2_sx003_is_linked_to_the_sx002_it_escalates(self):
        """Two findings, one problem: kept apart because their fixes differ, linked
        so nobody reads them as two separate CVEs."""
        images = {'img-app': image_report([cve(exploited=True, fixed='1.0.1')])}
        rows, _ = self.run_chain([exposed()], images, links(), rp006=['web'])
        sx002 = next(r for r in rows if r['rule_id'] == 'SX-002')
        sx003 = next(r for r in rows if r['rule_id'] == 'SX-003')
        self.assertEqual(sx003['escalates'], sx002['fingerprint'])
        self.assertEqual(sx003['evidence']['escalates'], sx002['fingerprint'])
        self.assertNotIn('escalates', sx002)

    def test_k_identities_are_stable_and_distinct_per_rule(self):
        images = {'img-app': image_report([cve(exploited=True, fixed='1.0.1')])}
        first = self.run_chain([exposed()], images, links(), ['web'])[0]
        again = self.run_chain([exposed()], images, links(), ['web'])[0]
        self.assertEqual([r['fingerprint'] for r in first], [r['fingerprint'] for r in again])
        self.assertEqual(len({r['fingerprint'] for r in first}), 2)

    def test_k2_one_image_behind_two_services_gets_its_own_gap(self):
        """Different from "unlinked": the operator fixes it by naming the service."""
        rows, gaps = self.run_chain([exposed('web'), exposed('worker')],
                                    {'img-app': image_report([cve(exploited=True)])}, {},
                                    ambiguous=[{'image': 'img-app', 'services': ['web', 'worker']}])
        self.assertEqual(rows, [])
        self.assertEqual([g['kind'] for g in gaps], ['image_ambiguous'])
        self.assertIn('bir nechta xizmat', gaps[0]['detail'])

    def test_l_two_images_of_one_project_are_judged_separately(self):
        services = [exposed('web', 'acme/app:1.0'), exposed('api', 'acme/api:1.0')]
        images = {'img-app': image_report([cve(exploited=True)]),
                  'img-api': image_report([cve(severity='LOW')], target='img-api')}
        rows, _ = self.run_chain(services, images, {**links(), **links('img-api', 'api')})
        self.assertEqual([(r['rule_id'], r['service_id']) for r in rows], [('SX-002', 'web')])


class CorrelateAllTests(unittest.TestCase):
    def test_a_a_stage_that_was_not_selected_is_named_as_a_gap(self):
        result = chains.correlate_all({'repository': {'services': [exposed()], 'findings': []}})
        self.assertEqual([g['kind'] for g in result['gaps']], ['stage_missing', 'stage_missing'])
        self.assertIn('Kod bosqichi', result['gaps'][0]['detail'])
        self.assertIn('Image bosqichi', result['gaps'][1]['detail'])

    def test_b_without_the_repository_stage_no_chain_can_run(self):
        result = chains.correlate_all({'code': {'findings': [gitleaks('a/b.py')]}})
        self.assertEqual(result['findings'], [])
        self.assertIn('Repository', result['gaps'][0]['detail'])

    def test_c_both_families_run_together(self):
        code = {'findings': [gitleaks('app/config.py')]}
        repository = {'services': [service('web', 'app'), exposed('api', 'acme/api:1.0')],
                      'findings': [{'rule_id': 'RP-006', 'service_id': 'api'}]}
        images = {'img-api': image_report([cve(exploited=True, fixed='2.0')], target='img-api')}
        result = chains.correlate_all({'code': code, 'repository': repository},
                                      links=links('img-api', 'api'), image_reports=images)
        self.assertEqual(sorted({r['rule_id'] for r in result['findings']}), ['SX-001', 'SX-002', 'SX-003'])


class ImageLinkTests(unittest.TestCase):
    """Matching a registered image to the Compose service that runs it."""

    def test_a_a_tag_a_digest_and_an_interpolation_are_the_same_image(self):
        for reference in ('crapi/crapi-web:${VERSION:-latest}', 'crapi/crapi-web@sha256:' + 'b' * 64,
                          'crapi/crapi-web', 'docker.io/crapi/crapi-web:latest'):
            self.assertEqual(portfolio.repository_name(reference), 'crapi/crapi-web', reference)

    def test_b_a_registry_host_port_is_not_a_tag(self):
        self.assertEqual(portfolio.repository_name('registry.example.com:5000/app:1.0'),
                         'registry.example.com:5000/app')

    def test_c_an_explicit_service_wins_over_the_name_match(self):
        stages = {'images': [{'id': 'img-app', 'service': 'qo-lda'}]}
        result = portfolio.link_images(stages, [exposed('web', 'acme/app:1.0')],
                                       targets=[{'id': 'img-app', 'reference': 'acme/app@sha256:' + 'a' * 64}])
        self.assertEqual(result['links']['img-app'], {'service': 'qo-lda', 'how': 'declared'})

    def test_d_no_match_is_reported_never_guessed(self):
        result = portfolio.link_images({'images': ['img-app']}, [exposed('web', 'boshqa/image:1.0')],
                                       targets=[{'id': 'img-app', 'reference': 'acme/app@sha256:' + 'a' * 64}])
        self.assertEqual(result['links'], {})
        self.assertEqual(result['unlinked'], ['img-app'])

    def test_e_one_image_behind_two_services_is_ambiguous_not_guessed(self):
        services = [exposed('web', 'acme/app:1.0'), exposed('worker', 'acme/app:1.0')]
        result = portfolio.link_images({'images': ['img-app']}, services,
                                       targets=[{'id': 'img-app', 'reference': 'acme/app@sha256:' + 'a' * 64}])
        self.assertEqual(result['links'], {})
        self.assertEqual(result['ambiguous'], [{'image': 'img-app', 'services': ['web', 'worker']}])


class CodeWeaknessChainTests(unittest.TestCase):
    """SX-004: an externally exploitable code weakness reachable through an
    exposed service's own port -- 'reachable' becomes 'directly attackable'."""

    def test_exploitable_weakness_in_exposed_service_is_flagged(self):
        code = {'findings': [weakness('services/web/db.py')]}
        repo = {'services': [service('web', 'services/web')]}
        findings = chains.code_weakness_chains(code, repo)
        self.assertEqual([f['rule_id'] for f in findings], ['SX-004'])
        self.assertIn('CWE-89', findings[0]['cwe_ids'])
        self.assertIn('CWE-668', findings[0]['cwe_ids'])
        self.assertEqual(findings[0]['level'], 'error')

    def test_non_exploitable_class_is_not_chained(self):
        code = {'findings': [weakness('services/web/crypto.py', cwe='CWE-327')]}
        repo = {'services': [service('web', 'services/web')]}
        self.assertEqual(chains.code_weakness_chains(code, repo), [])

    def test_info_level_weakness_is_not_chained(self):
        code = {'findings': [weakness('services/web/db.py', severity='INFO')]}
        repo = {'services': [service('web', 'services/web')]}
        self.assertEqual(chains.code_weakness_chains(code, repo), [])

    def test_gitleaks_secret_is_not_double_counted_here(self):
        code = {'findings': [gitleaks('services/web/config.py')]}
        repo = {'services': [service('web', 'services/web')]}
        self.assertEqual(chains.code_weakness_chains(code, repo), [])

    def test_loopback_only_service_is_not_flagged(self):
        code = {'findings': [weakness('services/web/db.py')]}
        repo = {'services': [service('web', 'services/web', loopback=True)]}
        self.assertEqual(chains.code_weakness_chains(code, repo), [])

    def test_weakness_under_unrelated_service_path_is_not_flagged(self):
        code = {'findings': [weakness('services/other/db.py')]}
        repo = {'services': [service('web', 'services/web')]}
        self.assertEqual(chains.code_weakness_chains(code, repo), [])


class EolImageChainTests(unittest.TestCase):
    """SX-005: an exposed service whose base image is past end-of-life -- no
    vendor fix will come, so the exposure is permanent, not a race."""

    @staticmethod
    def _image(eosl=True, name='9'):
        return {'state': 'completed', 'os': {'Family': 'debian', 'Name': name, 'EOSL': eosl}, 'findings': []}

    def test_eol_base_image_on_exposed_service_is_flagged(self):
        repo = {'services': [service('web', 'services/web')]}
        findings = chains.eol_image_chains(repo, {'img-web': self._image()},
                                           {'img-web': {'service': 'web', 'how': 'tag'}})
        self.assertEqual([f['rule_id'] for f in findings], ['SX-005'])
        self.assertIn('CWE-1104', findings[0]['cwe_ids'])
        self.assertEqual(findings[0]['level'], 'error')

    def test_supported_os_is_not_flagged(self):
        repo = {'services': [service('web', 'services/web')]}
        self.assertEqual(chains.eol_image_chains(repo, {'img-web': self._image(eosl=False, name='12')},
                                                 {'img-web': {'service': 'web', 'how': 'tag'}}), [])

    def test_eol_image_on_loopback_service_is_not_flagged(self):
        repo = {'services': [service('web', 'services/web', loopback=True)]}
        self.assertEqual(chains.eol_image_chains(repo, {'img-web': self._image()},
                                                 {'img-web': {'service': 'web', 'how': 'tag'}}), [])

    def test_unlinked_eol_image_is_not_flagged(self):
        repo = {'services': [service('web', 'services/web')]}
        self.assertEqual(chains.eol_image_chains(repo, {'img-web': self._image()}, {}), [])


def dep_finding(manifest, priority='P1', kev=True, advisory='CVE-2021-1', cwe='CWE-502', pkg='badlib'):
    return {'priority': priority, 'known_exploited': kev, 'advisory_id': advisory, 'cwe_ids': [cwe],
            'package': {'ecosystem': 'PyPI', 'name': pkg, 'version': '1.0'}, 'fingerprint': advisory,
            'occurrences': [{'manifest': manifest, 'locator': 'line:3', 'scope': 'declared'}]}


class DependencyChainTests(unittest.TestCase):
    """SX-006: an exposed service whose source dependencies carry a KEV or
    critical CVE -- caught at source, no built image needed."""

    def test_p1_dependency_in_exposed_service_is_flagged(self):
        dep = {'findings': [dep_finding('services/web/requirements.txt')]}
        repo = {'services': [service('web', 'services/web')]}
        findings = chains.dependency_chains(dep, repo)
        self.assertEqual([f['rule_id'] for f in findings], ['SX-006'])
        self.assertIn('CWE-668', findings[0]['cwe_ids'])
        self.assertEqual(findings[0]['level'], 'error')

    def test_lower_priority_dependency_is_not_chained(self):
        dep = {'findings': [dep_finding('services/web/requirements.txt', priority='P3', kev=False)]}
        repo = {'services': [service('web', 'services/web')]}
        self.assertEqual(chains.dependency_chains(dep, repo), [])

    def test_dependency_outside_the_service_is_not_chained(self):
        dep = {'findings': [dep_finding('services/other/requirements.txt')]}
        repo = {'services': [service('web', 'services/web')]}
        self.assertEqual(chains.dependency_chains(dep, repo), [])

    def test_loopback_service_is_not_chained(self):
        dep = {'findings': [dep_finding('services/web/requirements.txt')]}
        repo = {'services': [service('web', 'services/web', loopback=True)]}
        self.assertEqual(chains.dependency_chains(dep, repo), [])


class EscapeEscalationChainTests(unittest.TestCase):
    """SX-007: an exposed service that can be broken into (code weakness or
    secret) and break out (docker.sock / privileged)."""

    @staticmethod
    def _repo(escape_rule='RP-007'):
        return {'services': [service('web', 'services/web')],
                'findings': [{'rule_id': escape_rule, 'service_id': 'web'}]}

    def test_exploitable_weakness_on_escape_service_is_flagged(self):
        code = {'findings': [weakness('services/web/db.py')]}
        findings = chains.escape_escalation_chains(code, self._repo('RP-007'))
        self.assertEqual([f['rule_id'] for f in findings], ['SX-007'])
        self.assertIn('CWE-250', findings[0]['cwe_ids'])
        self.assertEqual(findings[0]['evidence']['entry_kind'], 'code_weakness')

    def test_secret_on_privileged_service_is_flagged(self):
        code = {'findings': [gitleaks('services/web/config.py')]}
        findings = chains.escape_escalation_chains(code, self._repo('RP-008'))
        self.assertEqual([f['rule_id'] for f in findings], ['SX-007'])
        self.assertEqual(findings[0]['evidence']['entry_kind'], 'secret')

    def test_without_escape_primitive_nothing_is_flagged(self):
        code = {'findings': [weakness('services/web/db.py')]}
        repo = {'services': [service('web', 'services/web')], 'findings': []}
        self.assertEqual(chains.escape_escalation_chains(code, repo), [])

    def test_without_code_entry_nothing_is_flagged(self):
        code = {'findings': [weakness('services/web/crypto.py', cwe='CWE-327')]}  # not exploitable-class
        self.assertEqual(chains.escape_escalation_chains(code, self._repo()), [])
