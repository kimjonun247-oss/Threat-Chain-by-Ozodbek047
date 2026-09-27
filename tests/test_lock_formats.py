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
    CARGO = ('[[package]]\nname = "serde"\nversion = "1.0.152"\n'
             'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
             '[[package]]\nname = "my-workspace-crate"\nversion = "0.1.0"\n')

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

    def test_a_workspace_crate_is_a_gap_not_a_crates_io_release(self):
        # ripgrep's lock lists 11 of its own crates with no source; matching them
        # against crates.io advisories would attach someone else's CVEs.
        rows, gaps = self.collect('Cargo.lock', self.CARGO)
        self.assertNotIn('my-workspace-crate', {r['name'] for r in rows})
        self.assertEqual([g['reason'] for g in gaps], ['lock_entry_local_or_git'])

    def test_an_entry_missing_its_version_is_a_gap(self):
        _, gaps = self.collect('poetry.lock', '[[package]]\nname = "x"\n')
        self.assertEqual([g['reason'] for g in gaps], ['lock_entry_not_versioned'])


CORPUS = Path(__file__).resolve().parents[1] / 'benchmarks' / 'corpus' / 'jvm-dotnet'


class BuildToolOutputTests(ParserBase):
    """Real `mvn dependency:tree` and `gradle dependencies` output (benchmarks/corpus/jvm-dotnet)."""

    def names(self, rows):
        return {(r['name'], r['version'], r['scope']) for r in rows}

    def test_maven_text_json_and_console_output_agree(self):
        text, _ = self.collect('dependency-tree.txt', (CORPUS / 'maven' / 'dependency-tree.txt').read_text(encoding='utf-8'))
        data, _ = self.collect('dependency-tree.json', (CORPUS / 'maven' / 'dependency-tree.json').read_text(encoding='utf-8'))
        console, _ = self.collect('dependency-tree.txt', (CORPUS / 'maven' / 'mvn-console-output.log').read_text(encoding='utf-8'))
        self.assertEqual(self.names(text), self.names(data))
        self.assertEqual(self.names(text), self.names(console))
        self.assertEqual(len(text), 9)                  # the project itself is not a dependency
        self.assertIn(('org.apache.logging.log4j:log4j-core', '2.14.1', 'runtime'), self.names(text))
        self.assertIn(('junit:junit', '4.12', 'development'), self.names(text))
        self.assertTrue(all(r['ecosystem'] == 'Maven' and r['evidence_kind'] == 'build_tool_resolution' for r in text))

    def test_maven_omitted_entries_are_not_counted(self):
        tree = ('com.example:demo:jar:1.0\n'
                '+- a:b:jar:1.0:compile\n'
                '|  \\- (c:d:jar:1.0:compile - omitted for conflict with 2.0)\n'
                '\\- c:d:jar:2.0:compile\n')
        rows, gaps = self.collect('dependency-tree.txt', tree)
        self.assertEqual(self.names(rows), {('a:b', '1.0', 'runtime'), ('c:d', '2.0', 'runtime')})
        self.assertEqual(gaps, [])

    def test_gradle_uses_the_resolved_version_and_only_classpaths(self):
        rows, gaps = self.collect('gradle-dependencies.txt',
                                  (CORPUS / 'gradle' / 'gradle-dependencies.txt').read_text(encoding='utf-8'))
        names = self.names(rows)
        self.assertEqual(gaps, [])
        # `guava:30.0-jre -> 31.1-jre`: what the build ships is 31.1-jre.
        self.assertIn(('com.google.guava:guava', '31.1-jre', 'runtime'), names)
        self.assertNotIn('30.0-jre', {r['version'] for r in rows if r['name'] == 'com.google.guava:guava'})
        # A BOM-managed dependency with no requested version.
        self.assertIn(('com.fasterxml.jackson.core:jackson-databind', '2.13.0', 'runtime'), names)
        # annotationProcessor is not a classpath the application ships with.
        self.assertNotIn('org.projectlombok:lombok', {r['name'] for r in rows})
        # testRuntimeClasspath repeats the runtime ones; they stay runtime.
        self.assertIn(('org.apache.logging.log4j:log4j-core', '2.14.1', 'runtime'), names)
        self.assertIn(('junit:junit', '4.12', 'development'), names)
        self.assertEqual(len(rows), len({(r['name'], r['version']) for r in rows}))

    def test_gradle_constraints_unresolved_and_project_entries_are_skipped(self):
        report = ('runtimeClasspath - Runtime classpath.\n'
                  '+--- project :core\n'
                  '+--- x:y:1.0 (c)\n'
                  '+--- x:z:2.0 (n)\n'
                  '+--- x:w:{strictly 1.0} -> 1.0\n'
                  '\\--- x:v:3.0 (*)\n')
        rows, gaps = self.collect('gradle-dependencies.txt', report)
        self.assertEqual(self.names(rows), {('x:w', '1.0', 'runtime'), ('x:v', '3.0', 'runtime')})

    def test_nuget_lock_skips_projects_and_repeats_across_frameworks(self):
        rows, gaps = self.collect('packages.lock.json', (CORPUS / 'nuget' / 'packages.lock.json').read_text(encoding='utf-8'))
        self.assertEqual({(r['ecosystem'], r['name'], r['version']) for r in rows},
                         {('NuGet', 'Newtonsoft.Json', '12.0.1'), ('NuGet', 'System.Text.Encodings.Web', '4.5.0')})
        self.assertEqual(gaps, [])

    def test_build_scripts_are_covered_when_resolved_output_sits_next_to_them(self):
        maven = inventory.collect(CORPUS / 'maven')
        self.assertEqual(maven['gaps'], [])
        self.assertEqual({m['path']: m['state'] for m in maven['manifests']}['pom.xml'], 'covered_by_resolved_output')
        gradle = inventory.collect(CORPUS / 'gradle')
        self.assertEqual(gradle['gaps'], [])

    def test_a_project_file_without_a_nuget_lock_is_a_named_gap(self):
        data = inventory.collect(CORPUS / 'nuget')
        self.assertEqual(data['gaps'], [{'path': 'lib/Lib.csproj', 'reason': 'nuget_lockfile_missing'}])


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


class YarnLockTests(ParserBase):
    """yarn.lock used to be listed as unsupported, so every Yarn project's npm
    packages went unchecked. Both the classic and the Berry format are read now."""
    CLASSIC = '# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n# yarn lockfile v1\n\n\n"@babel/code-frame@^7.0.0", "@babel/code-frame@^7.10.4":\n  version "7.12.13"\n  resolved "https://registry.yarnpkg.com/@babel/code-frame/-/code-frame-7.12.13.tgz#dcfc826beef65e75c50e21d3837d7d95798dd658"\n  integrity sha512-HV1Cm0Q3ZrpCR93tkWOYiuYIgLxZXZFVG2VgK+MBWjUqZTundupbfx2aXarXuw5Ko5aMcjtJgbSs4vUGBS5v6g==\n  dependencies:\n    "@babel/highlight" "^7.12.13"\n\nlodash@4.17.4, lodash@^4.17.0:\n  version "4.17.4"\n  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.4.tgz#78203a4d1c328ae1d86dca6460e369b57f4055ae"\n\n"string-width-cjs@npm:string-width@^4.2.0":\n  version "4.2.3"\n  resolved "https://registry.yarnpkg.com/string-width/-/string-width-4.2.3.tgz#269c7117d27b05ad2e536830a8ec895ef9c6d010"\n\nmy-fork@user/repo:\n  version "1.0.0"\n  resolved "https://codeload.github.com/user/repo/tar.gz/abc123"\n'
    BERRY = '# This file is generated by running "yarn install" inside your project.\n\n__metadata:\n  version: 6\n  cacheKey: 8\n\n"lodash@npm:^4.17.0, lodash@npm:4.17.4":\n  version: 4.17.4\n  resolution: "lodash@npm:4.17.4"\n  checksum: 1234\n  languageName: node\n  linkType: hard\n\n"@types/node@npm:*":\n  version: 18.0.0\n  resolution: "@types/node@npm:18.0.0"\n\n"resolve@patch:resolve@^1.20.0#~builtin<compat/resolve>":\n  version: 1.22.1\n  resolution: "resolve@patch:resolve@npm%3A1.22.1#~builtin<compat/resolve>::version=1.22.1&hash=07638b"\n\n"app@workspace:.":\n  version: 0.0.0-use.local\n  resolution: "app@workspace:."\n'

    def test_classic_lock_gives_exact_versions_and_resolves_aliases(self):
        rows, gaps = self.collect('yarn.lock', self.CLASSIC)
        found = {(r['name'], r['version']) for r in rows}
        self.assertEqual(found, {('@babel/code-frame', '7.12.13'), ('lodash', '4.17.4'), ('string-width', '4.2.3')})
        self.assertTrue(all(r['ecosystem'] == 'npm' and r['scope'] == 'unknown' for r in rows))

    def test_a_git_source_is_a_gap_not_a_registry_version(self):
        rows, gaps = self.collect('yarn.lock', self.CLASSIC)
        self.assertNotIn('my-fork', {r['name'] for r in rows})
        self.assertEqual([g['reason'] for g in gaps], ['yarn_non_registry_source'])

    def test_berry_lock_reads_npm_and_patched_entries_and_skips_workspaces(self):
        rows, gaps = self.collect('yarn.lock', self.BERRY)
        self.assertEqual({(r['name'], r['version']) for r in rows},
                         {('lodash', '4.17.4'), ('@types/node', '18.0.0'), ('resolve', '1.22.1')})
        self.assertEqual([g['reason'] for g in gaps], ['yarn_non_registry_source'])

    def test_package_json_beside_a_yarn_lock_is_not_a_missing_lock(self):
        root = self.write('yarn.lock', self.CLASSIC)
        (root / 'package.json').write_text('{}', encoding='utf-8')
        data = inventory.collect(root)
        self.assertNotIn('npm_lockfile_missing', {g['reason'] for g in data['gaps']})
        self.assertEqual(data['manifests'][0]['state'], 'partial')


class PnpmLockTests(ParserBase):
    V5 = 'lockfileVersion: 5.4\npackages:\n  /lodash/4.17.4:\n    resolution: {integrity: sha512-abc}\n    dev: false\n  /@babel/core/7.12.3_supports-color@5.5.0:\n    resolution: {integrity: sha512-abc}\n    dev: true\n'
    V6 = "lockfileVersion: '6.0'\npackages:\n  /lodash@4.17.4:\n    resolution: {integrity: sha512-abc}\n    dev: false\n  /@babel/core@7.12.3(supports-color@5.5.0):\n    resolution: {integrity: sha512-abc}\n    dev: true\n  github.com/user/repo/abc:\n    resolution: {tarball: https://codeload.github.com/user/repo/tar.gz/abc}\n    name: repo\n    version: 1.0.0\n"
    V9 = "lockfileVersion: '9.0'\npackages:\n  lodash@4.17.4:\n    resolution: {integrity: sha512-abc}\n  '@babel/core@7.12.3':\n    resolution: {integrity: sha512-abc}\nsnapshots:\n  lodash@4.17.4: {}\n"

    def test_all_three_key_formats_give_the_same_packages(self):
        for text in (self.V5, self.V6, self.V9):
            rows, _ = self.collect('pnpm-lock.yaml', text)
            with self.subTest(version=text.splitlines()[0]):
                self.assertEqual({(r['name'], r['version']) for r in rows},
                                 {('lodash', '4.17.4'), ('@babel/core', '7.12.3')})

    def test_dev_flag_becomes_scope_and_peer_suffix_is_not_the_version(self):
        rows, _ = self.collect('pnpm-lock.yaml', self.V6)
        found = {r['name']: r for r in rows}
        self.assertEqual(found['@babel/core']['version'], '7.12.3')
        self.assertEqual(found['@babel/core']['scope'], 'development')
        self.assertEqual(found['lodash']['scope'], 'runtime_or_optional')

    def test_tarball_or_git_resolution_is_a_gap(self):
        rows, gaps = self.collect('pnpm-lock.yaml', self.V6)
        self.assertNotIn('repo', {r['name'] for r in rows})
        self.assertEqual([g['reason'] for g in gaps], ['pnpm_non_registry_source'])

    def test_a_multi_document_lock_is_read_whole(self):
        # pnpm 9/10 can write two YAML documents into one file; vite's lock gave
        # 0 of 1414 packages before this.
        text = self.V9 + '---\nlockfileVersion: \'9.0\'\npackages:\n  react@18.3.1:\n    resolution: {integrity: sha512-x}\n'
        rows, gaps = self.collect('pnpm-lock.yaml', text)
        self.assertEqual({r['name'] for r in rows}, {'lodash', '@babel/core', 'react'})
        self.assertEqual(gaps, [])

    def test_broken_yaml_is_an_invalid_manifest_not_a_crash(self):
        _, gaps = self.collect('pnpm-lock.yaml', 'lockfileVersion: 9.0\npackages: [\n')
        self.assertEqual([g['reason'] for g in gaps], ['invalid_manifest'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
