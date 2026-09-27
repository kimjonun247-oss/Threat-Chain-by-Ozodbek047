"""Registering, replacing and removing targets -- and remote targets in every stage.

Found in the 2026-09-25 per-tool run:
  - re-registering an image or web id raised FileExistsError and the server
    closed the connection with no answer; there was no way to update a target
    (the old alpine:3.10 registration had to be deleted by hand);
  - a remote git target crashed the assessment, the dependency stage and the
    CI gate with KeyError('root');
  - a code id could not also name the project's Compose profile, with an error
    about the crapi name.
"""
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from zanjir import code_targets, images, pipeline, repo_store, scanners, webscan


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        for module, name in ((images, 'images'), (webscan, 'web'), (code_targets, 'code')):
            patcher = patch.object(module, 'PROFILES', self.tmp / name)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = patch.object(repo_store, 'LOCAL_PROFILES', self.tmp / 'local')
        patcher.start()
        self.addCleanup(patcher.stop)


class ReplaceAndRemoveTests(Base):
    def test_duplicate_image_is_a_clear_error_and_replace_updates_it(self):
        images.register('alpine', 'alpine:3.10')
        with self.assertRaises(ValueError) as caught:
            images.register('alpine', 'alpine:3.24')
        self.assertIn('allaqachon', str(caught.exception))
        row = images.register('alpine', 'alpine:3.24', replace=True)
        self.assertEqual(row['reference'], 'docker.io/library/alpine:3.24')
        stored = json.loads((self.tmp / 'images/alpine.json').read_text(encoding='utf-8'))
        self.assertEqual(stored['reference'], 'docker.io/library/alpine:3.24')
        self.assertIn('replaced_at', stored)

    def test_duplicate_web_target_is_a_clear_error_and_replace_updates_it(self):
        webscan.register('site', 'https://example.com', 'owner')
        with self.assertRaises(ValueError):
            webscan.register('site', 'https://example.org', 'owner')
        self.assertEqual(webscan.register('site', 'https://example.org', 'owner', replace=True)['url'],
                         'https://example.org')

    def test_remove_drops_only_the_registration(self):
        images.register('gone', 'alpine:3.24')
        webscan.register('gone', 'https://example.com', 'owner')
        images.remove('gone')
        webscan.remove('gone')
        self.assertFalse((self.tmp / 'images/gone.json').exists())
        self.assertFalse((self.tmp / 'web/gone.json').exists())
        with self.assertRaises(ValueError):
            images.remove('gone')

    def test_pilot_and_bundled_targets_cannot_be_removed(self):
        with self.assertRaises(ValueError):
            images.remove('pilot-crapi-web')
        with self.assertRaises(ValueError):
            repo_store.remove_project('crapi')

    def test_code_and_compose_may_share_an_id(self):
        root = self.tmp / 'project'
        root.mkdir()
        (root / 'docker-compose.yml').write_text('services:\n  web:\n    image: nginx\n', encoding='utf-8')
        code_targets.register('shop', root)
        result = repo_store.register_project('shop', root, 'docker-compose.yml')
        self.assertEqual(result['id'], 'shop')
        self.assertEqual([row['id'] for row in scanners.targets()].count('shop'), 1)

    def test_bundled_id_error_names_the_real_reason(self):
        with self.assertRaises(ValueError) as caught:
            repo_store.register_project('chain-demo', self.tmp, 'docker-compose.yml')
        self.assertIn('namuna', str(caught.exception))


class RemoteTargetStageTests(Base):
    def setUp(self):
        super().setUp()
        code_targets.register_remote('remote-app', 'https://github.com/example/app.git')

    def test_assessment_validation_accepts_a_remote_target_without_cloning(self):
        with patch('zanjir.remote_source.clone') as clone:
            pipeline.validate({'target': 'remote-app', 'repository_target': '', 'web_target': '',
                               'image_target': '', 'online': True})
        clone.assert_not_called()

    def test_target_root_on_a_remote_target_is_a_value_error(self):
        with self.assertRaises(ValueError) as caught:
            scanners.target_root('remote-app')
        self.assertIn('masofaviy', str(caught.exception))

    def test_dependency_stage_reads_the_clone(self):
        from zanjir import dependencies
        clone = self.tmp / 'clone' / 'src'
        clone.mkdir(parents=True)
        (clone / 'requirements.txt').write_text('flask==0.12\n', encoding='utf-8')
        runs = self.tmp / 'runs'
        with patch('zanjir.remote_source.clone', return_value=(clone, {'source_type': 'remote_git'})), \
             patch.object(dependencies, 'RUNS', runs), \
             patch('zanjir.advisories.query_packages', return_value=({}, {}, [], [])), \
             patch('zanjir.advisories.kev_catalog', return_value=({}, {'state': 'available'})), \
             patch('zanjir.advisories.enrich'), patch('zanjir.triage.record_scan'):
            report = dependencies.start('remote-app', background=False)
        self.assertEqual(report['source']['source_type'], 'remote_git')
        self.assertEqual(report['coverage']['unique_packages'], 1)


if __name__ == '__main__':
    unittest.main()


class GateReasonTests(unittest.TestCase):
    """Which code findings stop the build (2026-09-25 benchmark: 16/27 -> 24/30)."""

    def reason(self, **finding):
        from zanjir import ci_gate
        return ci_gate.code_gate_reason({'tool': 'semgrep', **finding})

    def test_high_impact_cwe_with_medium_confidence_counts(self):
        self.assertTrue(self.reason(severity='WARNING', cwe_ids=['CWE-502'], rule_meta={'confidence': 'medium'}))

    def test_audit_rule_or_low_confidence_does_not(self):
        self.assertFalse(self.reason(severity='WARNING', cwe_ids=['CWE-78'], rule_meta={'confidence': 'low'}))
        self.assertFalse(self.reason(severity='WARNING', cwe_ids=['CWE-78'],
                                     rule_meta={'confidence': 'high', 'subcategory': 'audit'}))
        self.assertFalse(self.reason(severity='WARNING', cwe_ids=['CWE-78']))

    def test_medium_impact_class_does_not(self):
        self.assertFalse(self.reason(severity='WARNING', cwe_ids=['CWE-327'], rule_meta={'confidence': 'high'}))

    def test_pmd_security_rule_counts_on_its_cwe(self):
        from zanjir import ci_gate
        self.assertTrue(ci_gate.code_gate_reason({'tool': 'pmd', 'severity': 'WARNING', 'cwe_ids': ['CWE-89']}))

    def test_local_rules_keep_their_own_message(self):
        messages = scanners.local_messages()
        self.assertIn('zanjir.python.sql-injection', messages)
        self.assertNotIn('Koddagi xavfli amal', messages['zanjir.python.sql-injection'])


class SbomVulnerabilityTests(unittest.TestCase):
    def test_each_match_points_at_its_component(self):
        from zanjir import sbom
        report = {'id': 'r', 'reference': 'docker.io/library/x:1', 'target': 'x', 'packages': [
            {'name': 'openssl', 'version': '1.1.1', 'purl': 'pkg:apk/alpine/openssl@1.1.1', 'target': 'x (alpine)'}],
            'findings': [{'advisory_id': 'CVE-2022-0778', 'package': 'openssl', 'version': '1.1.1',
                          'target': 'x (alpine)', 'severity': 'HIGH', 'fixed_version': '1.1.1n',
                          'cwe_ids': ['CWE-835'], 'title': 'loop'}]}
        document = sbom.build(report)
        vuln = document['vulnerabilities'][0]
        self.assertEqual(vuln['id'], 'CVE-2022-0778')
        self.assertEqual(vuln['affects'], [{'ref': 'pkg:apk/alpine/openssl@1.1.1'}])
        self.assertEqual(vuln['ratings'][0]['severity'], 'high')
        self.assertEqual(vuln['cwes'], [835])


@unittest.skipUnless(scanners.gitleaks_exe().is_file() and shutil.which('git'), 'Gitleaks yoki git o‘rnatilmagan')
class GitHistorySecretTests(unittest.TestCase):
    def test_a_secret_removed_from_the_tree_is_still_reported_from_history(self):
        import subprocess
        repo = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, repo, True)
        git = ['git', '-C', str(repo), '-c', 'user.email=t@t', '-c', 'user.name=t']
        subprocess.run(['git', 'init', '-q', str(repo)], check=True)
        token = 'ghp_' + 'aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xY2zA4'
        (repo / 'leak.py').write_text(f'TOKEN = "{token}"\n', encoding='utf-8')
        subprocess.run(git + ['add', '-A'], check=True)
        subprocess.run(git + ['commit', '-qm', 'leak'], check=True)
        subprocess.run(git + ['rm', '-q', 'leak.py'], check=True)
        subprocess.run(git + ['commit', '-qm', 'remove'], check=True)
        work = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, work, True)
        summary, found = scanners.history_secrets(repo, [], scanners.environment(work), work)
        self.assertEqual(summary['state'], 'completed')
        self.assertEqual([f['path'] for f in found], ['leak.py'])
        self.assertIn('commit', found[0]['history'])
        self.assertNotIn(token, json.dumps(found))

    def test_no_git_folder_is_not_applicable(self):
        folder = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, folder, True)
        self.assertEqual(scanners.history_secrets(folder, [], {}, folder)[0]['state'], 'not_applicable')
