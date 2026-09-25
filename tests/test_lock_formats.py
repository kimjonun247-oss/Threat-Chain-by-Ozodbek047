"""Lock-file parsers for the ecosystems beyond npm/PyPI/Go.

Only formats that state an exact version are read. A version that would have to
be resolved by running a build tool is deliberately left out: this module never
executes repository code, so it would have to guess, and a guessed version
produces advisory matches that look like evidence but are not.

The recurring trap these tests guard is the opposite of a missing package -- a
*constraint* being read as a version. `rack (~> 2.0.9)` inside a Gemfile.lock
spec is a requirement, not a fact, and treating it as one would attach real CVEs
to a version nobody installed.
"""
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from zanjir import inventory


class ParserBase(unittest.TestCase):
    def write(self, name, text):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        (root / name).write_text(text, encoding='utf-8')
        return root

    def collect(self, name, text):
        data = inventory.collect(self.write(name, text))
        return data['packages'], data['gaps']


class PipfileLockTests(ParserBase):
    LOCK = json.dumps({'default': {'requests': {'version': '==2.25.1'},
                                   'local-pkg': {'path': '.'}},
                       'develop': {'pytest': {'version': '==7.1.0'}}})

    def test_exact_pins_become_packages_with_their_scope(self):
        rows, _ = self.collect('Pipfile.lock', self.LOCK)
        found = {r['name']: r for r in rows}
        self.assertEqual(found['requests']['version'], '2.25.1')
        self.assertEqual(found['requests']['ecosystem'], 'PyPI')
        self.assertEqual(found['requests']['scope'], 'runtime')
        self.assertEqual(found['pytest']['scope'], 'development')

    def test_an_entry_without_a_released_version_is_a_gap_not_a_guess(self):
        rows, gaps = self.collect('Pipfile.lock', self.LOCK)
        self.assertNotIn('local-pkg', {r['name'] for r in rows})
        self.assertEqual([g['reason'] for g in gaps], ['python_lock_entry_not_versioned'])

    def test_a_lock_derived_pin_is_labelled_as_lock_evidence(self):
        # Not 'declared_exact_version': no human wrote this pin.
        rows, _ = self.collect('Pipfile.lock', self.LOCK)
        self.assertTrue(all(r['evidence_kind'] == 'lockfile_version' for r in rows))


class GemfileLockTests(ParserBase):
    LOCK = ('GEM\n  remote: https://rubygems.org/\n  specs:\n'
            '    actionpack (6.1.4)\n      actionview (= 6.1.4)\n      rack (~> 2.0.9)\n'
            '    rack (2.2.3)\n\nPLATFORMS\n  ruby\n')

    def test_only_the_resolved_spec_rows_become_packages(self):
        rows, _ = self.collect('Gemfile.lock', self.LOCK)
        self.assertEqual({(r['name'], r['version']) for r in rows},
                         {('actionpack', '6.1.4'), ('rack', '2.2.3')})

    def test_a_nested_constraint_is_never_read_as_a_version(self):
        # `rack (~> 2.0.9)` is what actionpack requires, not what is installed.
        rows, _ = self.collect('Gemfile.lock', self.LOCK)
        self.assertNotIn('2.0.9', {r['version'] for r in rows})
        self.assertNotIn('6.1.4', {r['version'] for r in rows if r['name'] == 'actionview'})

    def test_sections_after_specs_do_not_leak_into_the_inventory(self):
        rows, _ = self.collect('Gemfile.lock', self.LOCK)
        self.assertNotIn('ruby', {r['name'] for r in rows})


class GradleLockfileTests(ParserBase):
    LOCK = ('# This is a Gradle generated file for dependency locking.\n'
            'com.fasterxml.jackson.core:jackson-databind:2.13.0=compileClasspath,runtimeClasspath\n'
            'org.springframework:spring-web:5.3.18=runtimeClasspath\n'
            'empty=annotationProcessor\n')

    def test_coordinates_become_maven_packages(self):
        rows, _ = self.collect('gradle.lockfile', self.LOCK)
        found = {r['name']: r['version'] for r in rows}
        self.assertEqual(found['com.fasterxml.jackson.core:jackson-databind'], '2.13.0')
        self.assertEqual(found['org.springframework:spring-web'], '5.3.18')
        self.assertTrue(all(r['ecosystem'] == 'Maven' for r in rows))

    def test_comments_and_the_empty_marker_are_ignored_without_a_gap(self):
        rows, gaps = self.collect('gradle.lockfile', self.LOCK)
        self.assertEqual(len(rows), 2)
        self.assertEqual(gaps, [])

    def test_a_malformed_coordinate_is_reported_rather_than_dropped(self):
        _, gaps = self.collect('gradle.lockfile', 'not-a-coordinate=runtimeClasspath\n')
        self.assertEqual([g['reason'] for g in gaps], ['gradle_coordinate_unresolved'])


class ComposerLockTests(ParserBase):
    LOCK = json.dumps({'packages': [{'name': 'monolog/monolog', 'version': 'v2.3.5'},
                                    {'name': 'psr/log', 'version': '1.1.4'}],
                       'packages-dev': [{'name': 'phpunit/phpunit', 'version': '9.5.10'}]})

    def test_packages_are_read_with_their_scope(self):
        rows, _ = self.collect('composer.lock', self.LOCK)
        found = {r['name']: r for r in rows}
        self.assertEqual(found['psr/log']['ecosystem'], 'Packagist')
        self.assertEqual(found['monolog/monolog']['scope'], 'runtime')
        self.assertEqual(found['phpunit/phpunit']['scope'], 'development')

    def test_a_leading_v_is_dropped_because_advisories_omit_it(self):
        rows, _ = self.collect('composer.lock', self.LOCK)
        self.assertEqual({r['name']: r['version'] for r in rows}['monolog/monolog'], '2.3.5')


class TomlLockTests(ParserBase):
    POETRY = '[[package]]\nname = "django"\nversion = "4.2.1"\n\n[[package]]\nname = "urllib3"\nversion = "1.26.5"\n'
    CARGO = '[[package]]\nname = "serde"\nversion = "1.0.152"\n'

    def setUp(self):
        if inventory.tomllib is None:
            self.skipTest('tomllib faqat Python 3.11+ da bor')

    def test_poetry_lock_maps_to_pypi(self):
        rows, _ = self.collect('poetry.lock', self.POETRY)
        self.assertEqual({(r['ecosystem'], r['name'], r['version']) for r in rows},
                         {('PyPI', 'django', '4.2.1'), ('PyPI', 'urllib3', '1.26.5')})

    def test_uv_lock_uses_the_same_shape(self):
        rows, _ = self.collect('uv.lock', self.POETRY)
        self.assertEqual(len(rows), 2)

    def test_cargo_lock_maps_to_crates_io(self):
        rows, _ = self.collect('Cargo.lock', self.CARGO)
        self.assertEqual(rows[0]['ecosystem'], 'crates.io')

    def test_an_entry_missing_its_version_is_a_gap(self):
        _, gaps = self.collect('poetry.lock', '[[package]]\nname = "x"\n')
        self.assertEqual([g['reason'] for g in gaps], ['lock_entry_not_versioned'])


class UnsupportedManifestTests(ParserBase):
    def test_a_build_script_is_refused_with_the_command_that_fixes_it(self):
        # build.gradle.kts states ranges and properties, not resolved versions;
        # the operator is told to generate the lock file this module can read.
        _, gaps = self.collect('build.gradle.kts', 'dependencies { implementation("a:b:1.0") }\n')
        self.assertEqual([g['reason'] for g in gaps], ['gradle_lockfile_missing'])

    def test_maven_gets_its_own_reason(self):
        _, gaps = self.collect('pom.xml', 'x\n')
        self.assertEqual([g['reason'] for g in gaps], ['maven_lockfile_missing'])

    def test_pyproject_exact_pins_are_read_and_the_rest_stays_a_gap(self):
        """B8: a line that already says `flask==2.3.2` needs no build tool to
        resolve, so it is evidence. A range or a computed value still is not."""
        text = ('[project]\nname = "x"\n'
                'dependencies = ["flask==2.3.2", "requests>=2.0", "chromadb"]\n'
                '[project.optional-dependencies]\ndev = ["pytest==7.4.0"]\n'
                '[tool.poetry.dependencies]\nignored = "^1.0"\n')
        rows, gaps = self.collect('pyproject.toml', text)
        self.assertEqual({(r['name'], r['version']) for r in rows},
                         {('flask', '2.3.2'), ('pytest', '7.4.0')})
        self.assertEqual([g['reason'] for g in gaps], ['python_pyproject_not_exact_pin'] * 2)
        self.assertNotIn('ignored', {r['name'] for r in rows}, 'tool-ga xos jadval o‘qilmasligi kerak')

    def test_a_marked_pin_is_read_but_marked_conditional(self):
        rows, _ = self.collect('pyproject.toml',
                               '[project]\ndependencies = ["urllib3==1.26.5 ; python_version < \'3.12\'"]\n')
        self.assertEqual(rows[0]['scope'], 'conditional')

    def test_an_unreadable_pyproject_says_so(self):
        _, gaps = self.collect('pyproject.toml', 'bu toml emas: [\n')
        self.assertEqual([g['reason'] for g in gaps], ['toml_unreadable'])

    def test_no_unsupported_manifest_still_reports_the_bare_old_reason(self):
        # Every entry in UNSUPPORTED must carry an actionable hint.
        self.assertEqual(set(inventory.UNSUPPORTED) - set(inventory.UNSUPPORTED_HINTS), set())


class ScopeDescriptionTests(unittest.TestCase):
    def test_the_stated_scope_names_the_formats_that_are_actually_read(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        scope = inventory.collect(root)['scope']
        for word in ('Gradle', 'Gemfile.lock', 'composer.lock', 'Cargo.lock'):
            self.assertIn(word, scope)
        # And it says plainly what is not covered.
        self.assertIn('pom.xml', scope)


if __name__ == '__main__':
    unittest.main(verbosity=2)
