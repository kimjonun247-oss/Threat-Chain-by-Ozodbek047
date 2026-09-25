"""Tests for operator-authored Semgrep rules added from the web interface.

Semgrep's own rule parser is stubbed in most tests: it is a real subprocess taking
seconds, and what is under test here is this module's own gatekeeping. One test
leaves it in place to prove it is actually reached.
"""
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from zanjir import custom_rules as cr

GOOD = """rules:
  - id: local.demo-eval
    languages: [python]
    severity: ERROR
    message: Demo eval rule
    pattern: eval(...)
    metadata:
      cwe: ["CWE-95: Eval Injection"]
"""


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.dir = self.tmp / 'local'
        patcher = patch.object(cr, 'DIRECTORY', self.dir)
        patcher.start()
        self.addCleanup(patcher.stop)

    def no_semgrep(self):
        return patch.object(cr, 'semgrep_validate', lambda text: None)


class StructureTests(Base):
    def reject(self, text, fragment):
        with self.no_semgrep(), self.assertRaises(ValueError) as caught:
            cr.validate(text)
        self.assertIn(fragment, str(caught.exception))

    def test_a_well_formed_rule_is_accepted_and_returns_its_ids(self):
        with self.no_semgrep():
            self.assertEqual(cr.validate(GOOD), ['local.demo-eval'])

    def test_fix_is_refused_because_a_scanner_must_not_edit_source(self):
        self.reject(GOOD.replace('    pattern:', '    fix: "0"\n    pattern:'), 'fix')

    def test_engine_options_are_refused(self):
        self.reject(GOOD.replace('    pattern:', '    options: {}\n    pattern:'), 'options')

    def test_unknown_keys_are_refused_rather_than_silently_ignored(self):
        self.reject(GOOD.replace('    pattern:', '    surprise: 1\n    pattern:'), 'surprise')

    def test_missing_cwe_is_refused_because_owasp_is_never_guessed(self):
        self.reject(GOOD.split('    metadata:')[0], 'metadata.cwe')

    def test_cwe_without_a_number_is_refused(self):
        self.reject(GOOD.replace('"CWE-95: Eval Injection"', '"eval is bad"'), 'metadata.cwe')

    def test_severity_outside_the_three_semgrep_levels_is_refused(self):
        self.reject(GOOD.replace('ERROR', 'CRITICAL'), 'severity')

    def test_language_the_bundled_engine_cannot_parse_is_refused(self):
        self.reject(GOOD.replace('[python]', '[cobol]'), 'cobol')

    def test_a_rule_without_any_pattern_key_is_refused(self):
        self.reject(GOOD.replace('    pattern: eval(...)\n', ''), 'naqsh')

    def test_id_with_unsafe_characters_is_refused(self):
        self.reject(GOOD.replace('local.demo-eval', '../escape'), '`id`')

    def test_top_level_must_be_exactly_one_rules_key(self):
        self.reject('rules: []\nextra: 1\n', '`rules:`')

    def test_empty_rule_list_is_refused(self):
        self.reject('rules: []\n', 'bo‘sh')

    def test_yaml_anchors_are_refused(self):
        self.reject('rules: &a\n  - id: x\nother: *a\n', 'alias')

    def test_oversized_text_is_refused_before_parsing(self):
        self.reject('rules:\n' + '# padding\n' * 4000, 'KiB')

    def test_duplicate_ids_inside_one_file_are_refused(self):
        self.reject(GOOD + GOOD.split('rules:\n')[1], 'takrorlangan')

    def test_more_rules_than_the_cap_are_refused(self):
        body = ''.join(GOOD.split('rules:\n')[1].replace('local.demo-eval', f'local.r{i}') for i in range(cr.MAX_RULES + 1))
        self.reject('rules:\n' + body, str(cr.MAX_RULES))


class StorageTests(Base):
    def test_saving_then_listing_round_trips_the_rule(self):
        with self.no_semgrep():
            saved = cr.save('my-rules', GOOD, note='Izoh')
        self.assertEqual(saved['rule_ids'], ['local.demo-eval'])
        rows = cr.listing()
        self.assertEqual([r['name'] for r in rows], ['my-rules'])
        self.assertEqual(rows[0]['note'], 'Izoh')
        self.assertEqual(rows[0]['text'], GOOD)
        self.assertEqual(cr.summary(), {'files': 1, 'rules': 1})

    def test_a_second_file_cannot_reuse_an_id_already_registered(self):
        with self.no_semgrep():
            cr.save('first', GOOD)
            with self.assertRaises(ValueError) as caught:
                cr.save('second', GOOD)
        self.assertIn('local.demo-eval', str(caught.exception))

    def test_resaving_the_same_file_is_allowed_because_it_replaces_itself(self):
        with self.no_semgrep():
            cr.save('first', GOOD)
            saved = cr.save('first', GOOD.replace('Demo eval rule', 'Yangilangan matn'))
        self.assertIn('Yangilangan matn', cr.listing()[0]['text'])
        self.assertEqual(saved['rule_ids'], ['local.demo-eval'])

    def test_file_name_cannot_escape_the_rules_directory(self):
        for name in ('../escape', 'a/b', 'A-Upper', 'x'):
            with self.assertRaises(ValueError):
                cr.safe_name(name)

    def test_delete_removes_the_rule_and_its_metadata(self):
        with self.no_semgrep():
            cr.save('gone', GOOD)
        cr.delete('gone')
        self.assertEqual(cr.listing(), [])
        self.assertFalse((self.dir / 'gone.meta.json').exists())

    def test_deleting_something_that_is_not_there_is_an_error_not_a_silent_success(self):
        with self.assertRaises(ValueError):
            cr.delete('absent')

    def test_active_is_none_until_a_rule_exists(self):
        self.assertIsNone(cr.active())
        with self.no_semgrep():
            cr.save('present', GOOD)
        self.assertEqual(cr.active(), self.dir)

    def test_messages_come_from_the_rule_file_so_no_scanned_content_can_leak(self):
        with self.no_semgrep():
            cr.save('msg-rules', GOOD)
        self.assertEqual(cr.messages(), {'local.demo-eval': 'Demo eval rule'})

    def test_note_longer_than_the_cap_is_refused(self):
        with self.no_semgrep(), self.assertRaises(ValueError):
            cr.save('note-rules', GOOD, note='x' * 501)


class SemgrepValidationTests(Base):
    """The one test that actually runs Semgrep, proving the stub above hides a real step."""

    def test_a_pattern_semgrep_cannot_parse_is_refused(self):
        from zanjir import scanners
        if not scanners.semgrep_exe().is_file():
            self.skipTest('Semgrep bu muhitda o‘rnatilmagan.')
        with self.assertRaises(ValueError) as caught:
            cr.validate(GOOD.replace('eval(...)', 'eval(((('))
        self.assertIn('Semgrep', str(caught.exception))


if __name__ == '__main__':
    unittest.main(verbosity=2)
