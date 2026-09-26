"""Fix suggestions (zanjir/fixes.py): target versions, ready diffs, and nothing secret in them."""
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from zanjir import fixes

CORPUS = Path(__file__).resolve().parents[1] / 'benchmarks' / 'corpus'


def finding(ecosystem, name, version, advisory, fixed, manifest='requirements.txt'):
    return {'package': {'ecosystem': ecosystem, 'name': name, 'version': version}, 'advisory_id': advisory,
            'fixed_versions': fixed, 'occurrences': [{'manifest': manifest}]}


class VersionTests(unittest.TestCase):
    def test_ordering_across_ecosystems(self):
        ordered = ['1.0.0-rc1', '1.0.0', '1.0.1', '1.2', '1.10', '2.0.0-beta', '2.0.0']
        self.assertEqual(sorted(reversed(ordered), key=fixes.version_key), ordered)
        self.assertLess(fixes.version_key('2.10.5-r1'), fixes.version_key('2.10.7-r0'))
        self.assertLess(fixes.version_key('30.0-jre'), fixes.version_key('31.1-jre'))
        self.assertEqual(fixes.version_key('v1.2.3'), fixes.version_key('1.2.3'))

    def test_the_fix_on_the_current_branch_is_chosen(self):
        # log4j-core 2.14.1: OSV lists 2.12.2 (the 2.12 branch) and 2.15.0.
        self.assertEqual(fixes.next_fix('2.14.1', ['2.12.2', '2.15.0', '2.3.1']), '2.15.0')
        self.assertIsNone(fixes.next_fix('3.0.0', ['2.15.0']))


class DependencyPlanTests(unittest.TestCase):
    def test_the_target_fixes_every_advisory_of_the_package(self):
        plan = fixes.dependency_plan([finding('PyPI', 'jinja2', '2.10', 'GHSA-1', ['2.10.1']),
                                      finding('PyPI', 'jinja2', '2.10', 'GHSA-2', ['2.11.3'])])
        row = plan['packages'][0]
        self.assertEqual((row['upgrade_to'], row['major_upgrade'], row['target_check']), ('2.11.3', False, 'not_checked'))
        self.assertEqual(row['command'], "pip install 'jinja2==2.11.3'")

    def test_an_advisory_without_a_fix_is_named(self):
        row = fixes.dependency_plan([finding('npm', 'lodash', '4.17.4', 'GHSA-x', [])])['packages'][0]
        self.assertIsNone(row['upgrade_to'])
        self.assertEqual(row['without_fix'], ['GHSA-x'])

    def test_a_target_still_affected_moves_to_the_next_fix(self):
        calls = []

        def query(packages):
            calls.append(packages[0]['version'])
            key = ('Maven', 'org.apache.logging.log4j:log4j-core', packages[0]['version'])
            if key[2] == '2.15.0':        # CVE-2021-45046 was fixed only in 2.16.0
                return ({key: ['GHSA-7rjr']}, {'GHSA-7rjr': {'affected': [{'ranges': [{'events': [{'fixed': '2.16.0'}]}]}]}}, [], [])
            return ({key: []}, {}, [], [])
        row = fixes.dependency_plan([finding('Maven', 'org.apache.logging.log4j:log4j-core', '2.14.1', 'CVE-2021-44228',
                                             ['2.15.0', '2.12.2'], 'pom.xml')], {}, query)['packages'][0]
        self.assertEqual((row['upgrade_to'], row['target_check']), ('2.16.0', 'clean'))
        self.assertEqual(calls, ['2.15.0', '2.16.0'])

    def test_an_unreachable_feed_is_said_not_guessed(self):
        def query(packages):
            return ({}, {}, [{'reason': 'osv_query_incomplete'}], [])
        row = fixes.dependency_plan([finding('PyPI', 'x', '1.0', 'A', ['1.1'])], {}, query)['packages'][0]
        self.assertEqual((row['upgrade_to'], row['target_check']), ('1.1', 'unavailable'))

    def test_a_major_jump_is_flagged(self):
        row = fixes.dependency_plan([finding('npm', 'minimist', '0.0.8', 'A', ['1.2.6'], 'package-lock.json')])['packages'][0]
        self.assertTrue(row['major_upgrade'])
        self.assertEqual(row['command'], 'npm install minimist@1.2.6')

    def diffs(self, ecosystem, name, old, new, path, text):
        plan = fixes.dependency_plan([finding(ecosystem, name, old, 'A', [new], path)], {path: text})
        return plan['packages'][0]['diffs']

    def test_diffs_for_every_manifest_that_pins_literally(self):
        cases = [
            ('PyPI', 'Jinja2', '2.10', '2.11.3', 'requirements.txt', 'flask==1.0\njinja2 == 2.10  # pinned\n',
             '+jinja2 == 2.11.3  # pinned'),
            ('PyPI', 'django', '3.2.1', '3.2.25', 'pyproject.toml', '[project]\ndependencies = ["django==3.2.1", "x>=1"]\n',
             '+dependencies = ["django==3.2.25", "x>=1"]'),
            ('Go', 'golang.org/x/net', '0.7.0', '0.17.0', 'go.mod', 'module m\n\nrequire (\n\tgolang.org/x/net v0.7.0\n)\n',
             '+\tgolang.org/x/net v0.17.0'),
            ('Maven', 'com.fasterxml.jackson.core:jackson-databind', '2.9.8', '2.9.10.8', 'pom.xml',
             '<project><dependencies><dependency>\n<groupId>com.fasterxml.jackson.core</groupId>\n'
             '<artifactId>jackson-databind</artifactId>\n<version>2.9.8</version>\n</dependency></dependencies></project>\n',
             '+<version>2.9.10.8</version>'),
            ('Maven', 'com.google.guava:guava', '30.0-jre', '32.0.0-jre', 'build.gradle',
             "dependencies {\n  implementation 'com.google.guava:guava:30.0-jre'\n}\n",
             "+  implementation 'com.google.guava:guava:32.0.0-jre'"),
            ('NuGet', 'Newtonsoft.Json', '12.0.1', '13.0.1', 'src/App.csproj',
             '<Project>\n  <ItemGroup><PackageReference Include="Newtonsoft.Json" Version="12.0.1" /></ItemGroup>\n</Project>\n',
             '+  <ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.1" /></ItemGroup>'),
        ]
        for ecosystem, name, old, new, path, text, expected in cases:
            with self.subTest(path=path):
                found = self.diffs(ecosystem, name, old, new, path, text)
                self.assertEqual(len(found), 1)
                self.assertIn(expected, found[0]['diff'])
                self.assertTrue(found[0]['diff'].startswith('--- a/' + path))

    def test_a_range_or_another_package_is_left_alone(self):
        self.assertEqual(self.diffs('PyPI', 'jinja2', '2.10', '2.11.3', 'requirements.txt', 'jinja2>=2.10\njinja2-time==2.10\n'), [])
        self.assertEqual(self.diffs('Maven', 'a:b', '1.0', '2.0', 'pom.xml',
                                    '<dependency><groupId>a</groupId><artifactId>c</artifactId><version>1.0</version></dependency>'), [])

    def test_the_diff_applies_with_patch(self):
        if not shutil.which('patch'):
            self.skipTest('patch yo‘q')
        folder = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, folder, True)
        (folder / 'requirements.txt').write_text('flask==1.0\njinja2==2.10\n', encoding='utf-8')
        diff = self.diffs('PyPI', 'jinja2', '2.10', '2.11.3', 'requirements.txt',
                          (folder / 'requirements.txt').read_text(encoding='utf-8'))[0]['diff']
        subprocess.run(['patch', '-p1', '-s'], input=diff, text=True, cwd=folder, check=True)
        self.assertEqual((folder / 'requirements.txt').read_text(encoding='utf-8'), 'flask==1.0\njinja2==2.11.3\n')


class SecretTests(unittest.TestCase):
    def test_secret_values_in_context_lines_are_masked(self):
        before = 'services:\n  db:\n    environment:\n      POSTGRES_PASSWORD: hunter2secret\n    privileged: true\n'
        after = before.replace('privileged: true', 'privileged: false')
        diff = fixes.unified('docker-compose.yml', before, after)
        self.assertNotIn('hunter2secret', diff)
        self.assertIn('POSTGRES_PASSWORD: ***', diff)
        self.assertIn('qo‘lda qo‘llang', diff)


class ImagePlanTests(unittest.TestCase):
    def test_os_packages_become_one_run_line_and_eosl_is_said(self):
        report = {'os': {'Family': 'alpine', 'Name': '3.12.1', 'EOSL': True}, 'findings': [
            {'package': 'busybox', 'version': '1.31.1-r19', 'fixed_version': '1.31.1-r20', 'type': 'alpine'},
            {'package': 'busybox', 'version': '1.31.1-r19', 'fixed_version': '1.31.1-r22', 'type': 'alpine'},
            {'package': 'zlib', 'version': '1.2.11-r3', 'fixed_version': '1.2.12-r0', 'type': 'alpine'},
            {'package': 'pip', 'version': '20.3.1', 'fixed_version': '21.1', 'type': 'python-pkg'},
            {'package': 'musl', 'version': '1.1.24-r10', 'fixed_version': '', 'type': 'alpine'}]}
        plan = fixes.image_plan(report)
        self.assertEqual(plan['dockerfile_snippet'], 'RUN apk add --no-cache --upgrade busybox zlib')
        self.assertEqual(plan['os_packages'][0]['to'], '1.31.1-r22')
        self.assertEqual(plan['language_packages'][0]['command'], 'pip install --no-cache-dir pip==21.1')
        self.assertTrue(plan['language_packages'][0]['major_upgrade'])
        self.assertIn('EOSL', plan['base_image_note'])

    def test_debian_and_rhel_commands(self):
        for family, start in (('debian', 'RUN apt-get update'), ('rocky', 'RUN (dnf -y upgrade')):
            plan = fixes.image_plan({'os': {'Family': family}, 'findings': [
                {'package': 'openssl', 'version': '1', 'fixed_version': '2', 'type': family}]})
            self.assertTrue(plan['dockerfile_snippet'].startswith(start))


class ConfigDiffTests(unittest.TestCase):
    """Applied with `patch` and rescanned in benchmarks (check `fixes`); here the edits themselves."""

    def test_dockerfile_user_goes_before_the_command(self):
        edited = fixes._dockerfile_user('FROM alpine\nRUN x\nCMD ["run"]\n')
        self.assertEqual(edited, 'FROM alpine\nRUN x\nUSER 10001\nCMD ["run"]\n')
        self.assertEqual(fixes._dockerfile_user('FROM a\nUSER root\n'), 'FROM a\nUSER 10001\n')
        self.assertIsNone(fixes._dockerfile_user('FROM a\nUSER app\n'))

    def test_compose_block_and_inline_lists(self):
        text = ('services:\n  api:\n    ports:\n      - "8080:80"\n      - 127.0.0.1:9000:9000\n'
                '    volumes: ["/var/run/docker.sock:/var/run/docker.sock", "data:/data"]\n  other:\n    ports: ["1:1"]\n')
        edits = fixes.compose_edits('api')
        text = edits['RP-001'](text)
        text = edits['RP-007'](text)
        self.assertIn('- "127.0.0.1:8080:80"', text)
        self.assertIn('- 127.0.0.1:9000:9000', text)
        self.assertIn('volumes: ["data:/data"]', text)
        self.assertIn('ports: ["1:1"]', text)            # another service is untouched

    def test_nginx_headers_are_repeated_where_inheritance_breaks(self):
        conf = ('server {\n  add_header X-Frame-Options DENY;\n  add_header X-Content-Type-Options nosniff;\n'
                '  location /a/ {\n    add_header Cache-Control no-store;\n  }\n  location /b/ {\n    proxy_pass http://x;\n  }\n}\n')
        edited = fixes._repeat_headers(conf)
        block_a = edited.split('location /a/')[1].split('}')[0]
        self.assertIn('X-Frame-Options', block_a)
        self.assertIn('X-Content-Type-Options', block_a)
        self.assertNotIn('X-Frame-Options', edited.split('location /b/')[1])


if __name__ == '__main__':
    unittest.main()
