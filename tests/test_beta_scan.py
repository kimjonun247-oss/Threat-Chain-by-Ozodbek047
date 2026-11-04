"""First-scan speed and memory safety on large projects (PLAN.md 2.1, 2.2).

  - Semgrep leaves out vendored, generated and minified files; Gitleaks still
    reads them, and the choice is reported, never silent.
  - The official pack is handed over without the rules for languages the
    project has no file in -- and a file's findings must not change because of it.
  - Workers follow free memory; the count and a memory limit can be set.
  - A scanner that runs out of memory costs a split and a retry on one worker,
    not the scan.
"""
import os
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from zanjir import scanners, triage
from test_architecture import FakeScanner, Workspace


class SkipTests(Workspace):
    def setUp(self):
        super().setUp()
        self.put('app.py', 'eval(x)\n')
        self.put('third_party/lib.py', 'eval(y)\n')
        self.put('site-packages/pkg/mod.py', 'eval(z)\n')
        self.put('dist/app.js', 'eval(a)\n')
        self.put('static/app.min.js', 'eval(b)\n')
        self.put('static/bundle.js', 'var a=1;' * 400 + 'eval(c)\n')        # minified by content
        self.put('static/readable.js', 'eval(d)\n' + 'var a = 1;\n' * 300)
        self.tool = FakeScanner()
        self.shown = []
        tool = self.tool

        def record(command, cwd, env, timeout, cancel=None, **low):
            if 'dir' in command:
                self.shown.append(('gitleaks', sorted(p.relative_to(Path(cwd) / 'source').as_posix()
                                                      for p in (Path(cwd) / 'source').rglob('*') if p.is_file())))
            return tool(command, cwd, env, timeout, cancel, **low)
        for patcher in (patch.object(scanners, 'RUNS', self.tmp / 'runs'),
                        patch.object(scanners, 'target_root', return_value=self.source),
                        patch.object(scanners, 'version', return_value='1.2.3'),
                        patch.object(scanners, 'run_tool', record),
                        patch.object(scanners, 'history_secrets', return_value=({'state': 'not_applicable'}, [])),
                        patch.object(triage, 'record_scan', return_value=False)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def scan(self, **kwargs):
        self.tool.runs.clear()
        self.shown.clear()
        return scanners.start('demo', background=False, **kwargs)

    def test_a_semgrep_skips_vendored_generated_and_minified_files(self):
        report = self.scan()
        self.assertEqual(report['state'], 'completed', report)
        semgrep_saw = sorted(path for run in self.tool.runs for path in run)
        self.assertEqual(semgrep_saw, ['app.py', 'static/readable.js'])
        skipped = report['coverage']['semgrep_skipped']
        self.assertEqual({k: skipped[k] for k in ('vendored', 'generated', 'minified')},
                         {'vendored': 2, 'generated': 2, 'minified': 1})
        self.assertIn(scanners.SCAN_ALL_VARIABLE, skipped['note'])
        self.assertEqual(sorted(f['path'] for f in report['findings']), ['app.py', 'static/readable.js'])

    def test_b_gitleaks_still_reads_the_skipped_files(self):
        self.scan()
        gitleaks = dict(self.shown)['gitleaks']
        for name in ('third_party/lib.py', 'dist/app.js', 'static/app.min.js', 'static/bundle.js'):
            self.assertIn(name, gitleaks)

    def test_c_the_switch_scans_everything_and_the_cache_follows_it(self):
        self.scan()
        with patch.dict(os.environ, {scanners.SCAN_ALL_VARIABLE: '1'}):
            everything = self.scan()
        self.assertEqual(len(everything['findings']), 7)
        self.assertNotIn('semgrep_skipped', everything['coverage'])
        # Only the files that were skipped before had to be scanned now.
        self.assertEqual(sorted(path for run in self.tool.runs for path in run),
                         ['dist/app.js', 'site-packages/pkg/mod.py', 'static/app.min.js', 'static/bundle.js',
                          'third_party/lib.py'])
        # And back: the stored results of the skipped files must not leak into the report.
        again = self.scan()
        self.assertEqual(sorted(f['path'] for f in again['findings']), ['app.py', 'static/readable.js'])
        self.assertEqual(self.tool.runs, [])

    def test_d_minified_needs_long_lines_in_a_js_or_css_file(self):
        long_line = b'x' * 12000
        self.assertTrue(scanners.looks_minified('a.js', long_line))
        self.assertTrue(scanners.looks_minified('a.css', b'a{b:c}' * 1000))
        self.assertFalse(scanners.looks_minified('a.py', long_line), 'a long-lined Python file is still source')
        self.assertFalse(scanners.looks_minified('a.js', b'var a = 1;\n' * 1000))
        self.assertFalse(scanners.looks_minified('a.js', b'x' * 1000), 'small files are not judged')


PACK = ('rules:\n'
        '- id: py-rule\n  languages:\n  - python\n  message: m\n  severity: ERROR\n  pattern: eval(...)\n'
        '- patterns:\n  - pattern: x\n  id: js-ts-rule\n  languages:\n  - javascript\n  - typescript\n  message: m\n  severity: ERROR\n'
        '- id: tf-rule\n  languages:\n  - hcl\n  message: "a b"\n  severity: ERROR\n  pattern: x\n'
        '- id: generic-rule\n  languages:\n  - generic\n  message: m\n  severity: ERROR\n  pattern: x\n'
        '- id: unknown-language\n  languages:\n  - cobol\n  message: m\n  severity: ERROR\n  pattern: x\n')


class LanguageFilterTests(Workspace):
    def pack(self, text):
        path = self.tmp / 'pack.yml'
        path.write_bytes(text.encode('utf-8'))
        return path

    def ids(self, path):
        from vendor import yaml
        return [rule['id'] for rule in yaml.safe_load(Path(path).read_text(encoding='utf-8'))['rules']]

    def test_a_rules_for_absent_languages_are_left_out_and_nothing_else(self):
        out, counts = scanners.filtered_rules(self.pack(PACK), {'python'}, self.tmp)
        self.assertEqual(self.ids(out), ['py-rule', 'generic-rule', 'unknown-language'])
        self.assertEqual((counts['rules'], counts['used']), (5, 3))

    def test_b_a_rule_is_kept_when_any_of_its_languages_is_present(self):
        out, _ = scanners.filtered_rules(self.pack(PACK), {'js'}, self.tmp)
        self.assertIn('js-ts-rule', self.ids(out))

    def test_c_windows_line_ends_survive_byte_for_byte(self):
        crlf = PACK.replace('\n', '\r\n')
        out, _ = scanners.filtered_rules(self.pack(crlf), {'python', 'js', 'hcl'}, self.tmp)
        self.assertEqual(out, self.tmp / 'pack.yml', 'every rule applies: the pack itself is used')
        out, _ = scanners.filtered_rules(self.pack(crlf), {'hcl'}, self.tmp)
        self.assertNotIn(b'\r\r\n', out.read_bytes())
        self.assertEqual(self.ids(out), ['tf-rule', 'generic-rule', 'unknown-language'])

    def test_d_an_unexpected_layout_disables_filtering(self):
        for text in ('rules: [{id: a, languages: [python]}]\n',                         # flow style
                     'rules:\n- id: a\n  languages: [python]\n',                       # inline list
                     'rules:\n- id: a\n  message: m\n',                                 # no languages
                     '# comment\nrules:\n- id: a\n  languages:\n  - python\n'):
            path = self.pack(text)
            self.assertEqual(scanners.filtered_rules(path, set(), self.tmp), (path, None), text)

    def test_e_project_families_by_suffix_and_name(self):
        self.assertEqual(scanners.project_families(['a/b.py', 'web/x.tsx', 'infra/main.tf', 'Dockerfile', 'README']),
                         {'python', 'js', 'hcl', 'dockerfile'})

    def test_f_the_installed_pack_splits_into_exactly_its_rules(self):
        pack = scanners.merged_rules()
        if not pack.is_file():
            self.skipTest('rasmiy paket o‘rnatilmagan')
        from vendor import yaml
        blocks, nl = scanners.rule_blocks(pack)
        self.assertEqual(('rules:' + nl + ''.join(text for text, _ in blocks)).encode('utf-8'), pack.read_bytes())
        rules = yaml.safe_load(pack.read_text(encoding='utf-8'))['rules']
        self.assertEqual([[str(x).lower() for x in r['languages']] for r in rules], [langs for _, langs in blocks])


class WorkerAndMemoryTests(unittest.TestCase):
    def test_a_free_memory_limits_small_projects_too(self):
        with patch.object(scanners, 'available_memory_mb', return_value=1000):
            self.assertEqual(scanners.semgrep_jobs(1, registry=True), 1)
            self.assertEqual(scanners.semgrep_jobs(1, registry=False), 2)
        with patch.object(scanners, 'available_memory_mb', return_value=64000):
            self.assertEqual(scanners.semgrep_jobs(1), 2)

    def test_b_the_worker_count_can_be_set(self):
        with patch.dict(os.environ, {scanners.JOBS_VARIABLE: '5'}):
            self.assertEqual(scanners.semgrep_jobs(1), 5)
        with patch.dict(os.environ, {scanners.JOBS_VARIABLE: 'many'}), \
                patch.object(scanners, 'available_memory_mb', return_value=64000):
            self.assertEqual(scanners.semgrep_jobs(1), 2)

    def test_c_the_memory_limit_reaches_semgrep_only_when_set(self):
        self.assertNotIn('--max-memory', scanners.tool_commands(Path('unused'))['semgrep'])
        with patch.dict(os.environ, {scanners.MAX_MEMORY_VARIABLE: '1500'}):
            command = scanners.tool_commands(Path('unused'))['semgrep']
        self.assertEqual(command[command.index('--max-memory') + 1], '1500')
        self.assertEqual(command[-1], 'source')

    def test_d_out_of_memory_is_recognised(self):
        def done(code, err=''):
            return subprocess.CompletedProcess(['x'], code, '', err)
        self.assertTrue(scanners.out_of_memory(done(137)))
        self.assertTrue(scanners.out_of_memory(done(0xC0000017)))
        self.assertTrue(scanners.out_of_memory(done(2, 'Fatal error: exception Out_of_memory')))
        self.assertFalse(scanners.out_of_memory(done(0, 'Out_of_memory in a file name')))
        self.assertFalse(scanners.out_of_memory(done(2, 'invalid rule')))

    def test_e_fewer_jobs(self):
        self.assertEqual(scanners.fewer_jobs(['s', '--jobs', '4', 'source']), ['s', '--jobs', '1', 'source'])
        self.assertEqual(scanners.fewer_jobs(['s', 'source']), ['s', 'source'])


class OutOfMemoryScanTests(Workspace):
    """A part that exhausts memory is split and retried on one worker."""

    def setUp(self):
        super().setUp()
        for name in ('a.py', 'b.py', 'c.py', 'd.py'):
            self.put(name, 'eval(x)\n')
        self.tool = FakeScanner()
        self.jobs = []
        tool = self.tool

        def hungry(command, cwd, env, timeout, cancel=None, **low):
            if 'dir' not in command:
                files = list((Path(cwd) / 'source').rglob('*.py'))
                jobs = command[command.index('--jobs') + 1]
                self.jobs.append((len(files), jobs))
                if len(files) > 2:                                       # too much at once
                    return subprocess.CompletedProcess(command, 2, '', 'Fatal error: exception Out_of_memory')
            return tool(command, cwd, env, timeout, cancel, **low)
        for patcher in (patch.object(scanners, 'RUNS', self.tmp / 'runs'),
                        patch.object(scanners, 'target_root', return_value=self.source),
                        patch.object(scanners, 'version', return_value='1.2.3'),
                        patch.object(scanners, 'run_tool', hungry),
                        patch.object(scanners, 'available_memory_mb', return_value=64000),
                        patch.object(scanners, 'history_secrets', return_value=({'state': 'not_applicable'}, [])),
                        patch.object(triage, 'record_scan', return_value=False)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_a_the_scan_finishes_with_every_file(self):
        report = scanners.start('demo', background=False)
        semgrep = report['tools']['semgrep']
        self.assertEqual((report['state'], semgrep['state'], semgrep['files_scanned']), ('completed', 'completed', 4), report)
        self.assertEqual(semgrep['memory_retries'], 1)
        self.assertEqual(len(report['findings']), 4)
        self.assertEqual(self.jobs, [(4, '2'), (2, '1'), (2, '1')])

    def test_b_a_single_file_that_never_fits_is_reported_unscanned_not_clean(self):
        def always(command, cwd, env, timeout, cancel=None, **low):
            if 'dir' not in command:
                return subprocess.CompletedProcess(command, 0xC0000017, '', '')
            return self.tool(command, cwd, env, timeout, cancel, **low)
        with patch.object(scanners, 'run_tool', always):
            report = scanners.start('demo', background=False)
        self.assertEqual(report['tools']['semgrep']['state'], 'failed')
        self.assertNotEqual(report['state'], 'completed')


if __name__ == '__main__':
    unittest.main()
