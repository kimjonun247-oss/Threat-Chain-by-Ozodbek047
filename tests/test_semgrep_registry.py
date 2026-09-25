"""Tests for the official Semgrep rule pack: integrity, tagging and leak safety."""
import hashlib
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from zanjir import scanners as s
from zanjir import taxonomy


def write_pack(root, files):
    """files: {relative path: yaml text}. Returns the manifest dict it wrote."""
    entries = []
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')
        entries.append({'file': rel, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                        'rules': 1, 'origin': 'https://example.invalid/' + rel})
    manifest = {'source': 'semgrep/semgrep-rules', 'commit': 'a' * 40, 'rules': len(entries),
                'files': len(entries), 'languages': sorted({r.split('/')[0] for r in files}),
                'entries': entries}
    (root / 'manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
    return manifest


RULE = ('rules:\n'
        '- id: demo-shell\n'
        '  message: Found shell=True in $FUNC. Use shell=False instead.\n'
        '  languages: [python]\n'
        '  severity: ERROR\n'
        '  pattern: demo(...)\n')


class RegistryIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(__import__('tempfile').mkdtemp())
        self.addCleanup(__import__('shutil').rmtree, self.tmp, True)
        self.pack = self.tmp / 'semgrep-registry'
        self.pack.mkdir()
        s._MESSAGES.clear()
        self.addCleanup(s._MESSAGES.clear)

    def registry(self):
        return patch.object(s, 'semgrep_registry', lambda: self.pack)

    def test_missing_pack_is_not_an_error_so_scans_still_run_on_local_rules(self):
        with patch.object(s, 'semgrep_registry', lambda: self.tmp / 'absent'):
            self.assertIsNone(s.registry_manifest())

    def test_manifest_is_read_when_every_file_matches_its_recorded_hash(self):
        write_pack(self.pack, {'python/demo.yaml': RULE})
        with self.registry():
            self.assertEqual(s.registry_manifest()['rules'], 1)

    def test_edited_rule_file_is_rejected_rather_than_silently_shrinking_coverage(self):
        write_pack(self.pack, {'python/demo.yaml': RULE})
        (self.pack / 'python/demo.yaml').write_text(RULE.replace('demo(...)', 'never_matches(...)'), encoding='utf-8')
        with self.registry(), self.assertRaises(ValueError):
            s.registry_manifest()

    def test_deleted_rule_file_is_rejected(self):
        write_pack(self.pack, {'python/demo.yaml': RULE})
        (self.pack / 'python/demo.yaml').unlink()
        with self.registry(), self.assertRaises(ValueError):
            s.registry_manifest()

    def test_command_layers_the_pack_on_top_of_the_local_rules(self):
        # The merged file is pointed away so this covers the directory layering;
        # MergedRuleFileTests covers the merged path.
        with self.registry(), patch.object(s, 'merged_rules', lambda: self.tmp / 'absent.yml'):
            command = s.tool_commands(self.tmp, registry=True)['semgrep']
        configs = [command[i + 1] for i, a in enumerate(command) if a == '--config']
        self.assertEqual(len(configs), 2)
        self.assertTrue(configs[0].endswith('semgrep.yml'))
        self.assertEqual(configs[1], str(self.pack))

    def test_command_uses_only_local_rules_when_the_pack_is_absent(self):
        command = s.tool_commands(self.tmp, registry=False)['semgrep']
        self.assertEqual([a for a in command if a == '--config'], ['--config'])


class RuleMessageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(__import__('tempfile').mkdtemp())
        self.addCleanup(__import__('shutil').rmtree, self.tmp, True)
        self.pack = self.tmp / 'semgrep-registry'
        self.pack.mkdir()
        s._MESSAGES.clear()
        self.addCleanup(s._MESSAGES.clear)

    def test_message_comes_from_the_rule_file_not_from_scanner_output(self):
        # Semgrep interpolates matched source text into its own extra.message; the
        # rule file's wording keeps the metavariable placeholder instead, so nothing
        # from the scanned project can reach the report through this field.
        manifest = write_pack(self.pack, {'python/demo.yaml': RULE})
        with patch.object(s, 'semgrep_registry', lambda: self.pack):
            messages = s.registry_messages(manifest)
        self.assertIn('$FUNC', messages['demo-shell'])

    def test_clean_message_collapses_whitespace_and_bounds_length(self):
        self.assertEqual(s.clean_message('  a\n\n  b  '), 'a b')
        self.assertEqual(len(s.clean_message('x' * 900)), 400)
        self.assertIsNone(s.clean_message('   '))
        self.assertIsNone(s.clean_message(None))


class MetadataTaggingTests(unittest.TestCase):
    def test_cwe_identifier_is_parsed_out_of_the_rules_own_metadata(self):
        tags = taxonomy.tag_from_metadata(["CWE-78: Improper Neutralization of Special Elements"])
        self.assertEqual(tags['cwe_ids'], ['CWE-78'])
        self.assertEqual([o['code'] for o in tags['owasp_top10_2025']], ['A05'])

    def test_several_cwes_are_all_kept_and_sorted(self):
        tags = taxonomy.tag_from_metadata(['CWE-89: SQL Injection', 'CWE-22: Path Traversal'])
        self.assertEqual(tags['cwe_ids'], ['CWE-22', 'CWE-89'])

    def test_a_plain_string_is_accepted_as_well_as_a_list(self):
        self.assertEqual(taxonomy.tag_from_metadata('CWE-798: Hardcoded Credentials')['cwe_ids'], ['CWE-798'])

    def test_missing_or_unparsable_metadata_returns_none_so_the_caller_falls_back(self):
        self.assertIsNone(taxonomy.tag_from_metadata(None))
        self.assertIsNone(taxonomy.tag_from_metadata([]))
        self.assertIsNone(taxonomy.tag_from_metadata(['no identifier here']))

    def test_unknown_cwe_is_kept_but_never_guessed_into_an_owasp_category(self):
        tags = taxonomy.tag_from_metadata(['CWE-999999: Invented'])
        self.assertEqual(tags['cwe_ids'], ['CWE-999999'])
        self.assertEqual(tags['owasp_top10_2025'], [])


class NormalizeTests(unittest.TestCase):
    def source(self, name='a.py'):
        root = Path(__import__('tempfile').mkdtemp())
        self.addCleanup(__import__('shutil').rmtree, root, True)
        (root / name).write_text('x = 1\n', encoding='utf-8')
        return root

    def row(self, **extra):
        base = {'severity': 'ERROR', 'metadata': {'cwe': ['CWE-78: OS Command Injection']}}
        base.update(extra)
        return {'results': [{'check_id': 'demo-shell', 'path': 'a.py', 'start': {'line': 1}, 'extra': base}]}

    def test_official_rule_severity_and_cwe_reach_the_finding(self):
        root = self.source()
        finding = s.normalize('semgrep', self.row(), root, {'demo-shell': 'Rule wording'})[0]
        self.assertEqual(finding['severity'], 'ERROR')
        self.assertEqual(finding['cwe_ids'], ['CWE-78'])
        self.assertEqual(finding['message'], 'Rule wording')
        self.assertFalse(finding['verified'])

    def test_scanner_supplied_message_is_ignored_in_favour_of_the_rule_file(self):
        root = self.source()
        row = self.row(message="Found secret 'sk_live_REAL_VALUE' in code")
        finding = s.normalize('semgrep', row, root, {'demo-shell': 'Rule wording'})[0]
        self.assertNotIn('sk_live_REAL_VALUE', finding['message'])
        self.assertEqual(finding['message'], 'Rule wording')

    def test_local_rule_without_metadata_falls_back_to_the_projects_own_table(self):
        root = self.source()
        row = {'results': [{'check_id': 'zanjir.python.eval', 'path': 'a.py', 'start': {'line': 1}, 'extra': {}}]}
        finding = s.normalize('semgrep', row, root, {})[0]
        self.assertIsNone(finding['severity'])
        self.assertEqual(finding['cwe_ids'], taxonomy.tag_static('semgrep', 'zanjir.python.eval')['cwe_ids'])

    def test_unexpected_severity_value_is_dropped_rather_than_passed_through(self):
        root = self.source()
        finding = s.normalize('semgrep', self.row(severity='CATASTROPHIC'), root, {})[0]
        self.assertIsNone(finding['severity'])


class ErrorKindTests(unittest.TestCase):
    def test_errors_are_grouped_by_kind_most_frequent_first(self):
        kinds = s.error_kinds([{'type': 'Other syntax error'}, {'type': 'Missing plugin'},
                               {'type': 'Other syntax error'}])
        self.assertEqual(list(kinds), ['Other syntax error', 'Missing plugin'])
        self.assertEqual(kinds['Other syntax error'], 2)

    def test_an_error_without_a_usable_kind_is_still_counted(self):
        self.assertEqual(s.error_kinds([{}, {'type': 7}]), {'Boshqa': 2})

    def test_no_errors_gives_an_empty_breakdown(self):
        self.assertEqual(s.error_kinds([]), {})


class RuleSetLabelTests(unittest.TestCase):
    def test_label_names_the_pack_size_and_language_count_when_installed(self):
        label = s.rule_set_label('semgrep', {'rules': 1343, 'languages': ['python', 'go']})
        self.assertIn('1343', label)
        self.assertIn('2 til', label)

    def test_label_reports_only_the_local_rules_when_the_pack_is_absent(self):
        self.assertEqual(s.rule_set_label('semgrep', None), 'ThreatChain 7 lokal qoida')


class ErrorFileTests(unittest.TestCase):
    """A coverage gap must name the files and the remedy, not just a count."""

    def source(self, files):
        root = Path(__import__('tempfile').mkdtemp())
        self.addCleanup(__import__('shutil').rmtree, root, True)
        for rel, text in files.items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding='utf-8')
        return root

    def errors(self, *paths):
        return [{'type': 'Other syntax error', 'level': 'warn', 'path': 'work/abc/source/' + p} for p in paths]

    def test_a_go_template_under_templates_is_recognised_as_a_helm_chart(self):
        root = self.source({'deploy/helm/templates/app/deployment.yaml': 'kind: {{ .Values.kind }}\n'})
        groups = s.error_files(self.errors('deploy/helm/templates/app/deployment.yaml'), root)
        self.assertEqual(list(groups), ['helm_template'])
        self.assertEqual(groups['helm_template']['count'], 1)
        self.assertIn('helm template', groups['helm_template']['action'])

    def test_plain_yaml_under_templates_is_not_called_a_helm_chart(self):
        # The directory name alone is not enough; the file must actually be a template.
        root = self.source({'deploy/helm/templates/app/plain.yaml': 'kind: Deployment\n'})
        groups = s.error_files(self.errors('deploy/helm/templates/app/plain.yaml'), root)
        self.assertEqual(list(groups), ['other'])

    def test_a_file_outside_a_templates_directory_is_other(self):
        root = self.source({'src/broken.yaml': 'a: {{ oops\n'})
        groups = s.error_files(self.errors('src/broken.yaml'), root)
        self.assertEqual(list(groups), ['other'])

    def test_the_listed_file_names_are_relative_to_the_snapshot(self):
        root = self.source({'deploy/helm/templates/a.yaml': '{{ x }}\n'})
        groups = s.error_files(self.errors('deploy/helm/templates/a.yaml'), root)
        self.assertEqual(groups['helm_template']['files'], ['deploy/helm/templates/a.yaml'])

    def test_the_file_list_is_bounded_while_the_count_stays_exact(self):
        files = {f'deploy/helm/templates/f{i}.yaml': '{{ x }}\n' for i in range(60)}
        root = self.source(files)
        groups = s.error_files(self.errors(*files), root)
        self.assertEqual(groups['helm_template']['count'], 60)
        self.assertEqual(len(groups['helm_template']['files']), s.MAX_LISTED_FILES)

    def test_no_errors_gives_no_groups(self):
        self.assertEqual(s.error_files([], Path('.')), {})


class MergedRuleFileTests(unittest.TestCase):
    """The pack is handed to Semgrep as one file because opening 1327 costs more
    than scanning. Measured on crAPI: config_time 33.4s vs 6.2s, findings
    identical (138 both ways).
    """

    def setUp(self):
        self.tmp = Path(__import__('tempfile').mkdtemp())
        self.addCleanup(__import__('shutil').rmtree, self.tmp, True)
        self.pack = self.tmp / 'semgrep-registry'
        self.pack.mkdir()
        self.merged = self.tmp / 'semgrep-merged.yml'
        s._MESSAGES.clear()
        self.addCleanup(s._MESSAGES.clear)

    def patched(self):
        return (patch.object(s, 'semgrep_registry', lambda: self.pack),
                patch.object(s, 'merged_rules', lambda: self.merged))

    def test_the_merged_file_is_used_when_it_exists(self):
        self.merged.write_text('rules: []\n', encoding='utf-8')
        a, b = self.patched()
        with a, b:
            command = s.tool_commands(self.tmp, registry=True)['semgrep']
        configs = [command[i + 1] for i, arg in enumerate(command) if arg == '--config']
        self.assertEqual(configs[1], str(self.merged))

    def test_the_directory_is_used_when_no_merged_file_was_produced(self):
        # Packs installed before merging existed must keep working.
        a, b = self.patched()
        with a, b:
            command = s.tool_commands(self.tmp, registry=True)['semgrep']
        configs = [command[i + 1] for i, arg in enumerate(command) if arg == '--config']
        self.assertEqual(configs[1], str(self.pack))

    def test_the_merged_file_lives_outside_the_registry_directory(self):
        """Inside it, `--config <dir>` would load every rule twice.

        This is not hypothetical: the first attempt placed it inside and each
        rule was read a second time, which changed the findings.
        """
        self.assertFalse(s.merged_rules().resolve().is_relative_to(s.semgrep_registry().resolve()))

    def test_an_edited_merged_file_is_rejected(self):
        manifest = write_pack(self.pack, {'python/demo.yaml': RULE})
        self.merged.write_text(RULE, encoding='utf-8')
        manifest['merged'] = {'file': self.merged.name, 'rules': 1,
                              'sha256': hashlib.sha256(self.merged.read_bytes()).hexdigest()}
        (self.pack / 'manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
        a, b = self.patched()
        with a, b:
            self.assertEqual(s.registry_manifest()['merged']['rules'], 1)
            self.merged.write_text(RULE.replace('demo(...)', 'never(...)'), encoding='utf-8')
            with self.assertRaises(ValueError):
                s.registry_manifest()

    def test_a_missing_merged_file_the_manifest_promised_is_rejected(self):
        manifest = write_pack(self.pack, {'python/demo.yaml': RULE})
        manifest['merged'] = {'file': 'semgrep-merged.yml', 'rules': 1, 'sha256': 'a' * 64}
        (self.pack / 'manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
        a, b = self.patched()
        with a, b, self.assertRaises(ValueError):
            s.registry_manifest()

    def test_rule_files_without_a_manifest_are_an_error_not_a_silent_downgrade(self):
        """An interrupted install left rules with no manifest, which read as
        "no pack installed" -- a scan would quietly drop to seven local rules."""
        (self.pack / 'python').mkdir()
        (self.pack / 'python/demo.yaml').write_text(RULE, encoding='utf-8')
        with patch.object(s, 'semgrep_registry', lambda: self.pack), self.assertRaises(ValueError) as caught:
            s.registry_manifest()
        self.assertIn('chala', str(caught.exception))

    def test_an_empty_directory_still_means_simply_not_installed(self):
        with patch.object(s, 'semgrep_registry', lambda: self.tmp / 'absent'):
            self.assertIsNone(s.registry_manifest())


if __name__ == '__main__':
    unittest.main(verbosity=2)
