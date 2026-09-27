"""Guard rails for the command-line scripts at the repository root.

These scripts had no test coverage at all, and that is exactly how five of them
broke without anyone noticing:

  - check_all.py and validate_pipeline.py stopped working when a field was added
    to pipeline.validate(), because nothing tied their payloads to it.
  - validate_pipeline.py imported zanjir.lab long after that module was renamed
    to zanjir.httptest; every test file was updated, this script was not.
  - verify_pilot_api.py asserted a mode string and a version number that the
    application had since moved past.

The tests below are deliberately cheap -- they import, they inspect, they never
run a scan -- so that they stay fast enough to live in the default suite while
still catching that whole class of drift.
"""
import ast
import importlib
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
from isolation import isolate_triage

ROOT = Path(__file__).resolve().parents[1]

# Every script a person is expected to run directly.
SCRIPTS = ('app', 'bundle_crapi', 'check_all', 'check_dependencies', 'check_image', 'check_web',
           'ci_gate', 'pilot', 'pilot_evidence', 'pilot_tls', 'scan_code', 'setup_nuclei',
           'setup_semgrep_rules', 'setup_tools', 'validate_pilot', 'validate_pipeline',
           'validate_web', 'verify_pilot_api', 'setup_all', 'verify_platform', 'setup_scanners', 'setup_pmd')

# Scripts that build a pipeline selection and hand it to pipeline.start().
PIPELINE_CLIENTS = ('check_all', 'ci_gate')


def source(name):
    return (ROOT / (name + '.py')).read_text(encoding='utf-8')


class ImportTests(unittest.TestCase):
    """A stale import is invisible until someone runs the script."""

    def test_every_script_imports(self):
        for name in SCRIPTS:
            with self.subTest(script=name):
                try:
                    importlib.import_module(name)
                except Exception as error:                      # noqa: BLE001 - report any import failure
                    self.fail(f'{name}.py import qilinmadi: {type(error).__name__}: {error}')

    def test_no_script_imports_a_module_that_does_not_exist(self):
        # Catches the zanjir.lab -> zanjir.httptest rename directly, including in
        # scripts whose import sits behind a function call.
        for name in SCRIPTS:
            tree = ast.parse(source(name), filename=name + '.py')
            for node in ast.walk(tree):
                modules = []
                if isinstance(node, ast.Import):
                    modules = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    modules = [node.module]
                for module in modules:
                    if not module.startswith('zanjir'):
                        continue
                    with self.subTest(script=name, module=module):
                        self.assertTrue((ROOT / Path(module.replace('.', '/') + '.py')).is_file()
                                        or (ROOT / module.replace('.', '/')).is_dir(),
                                        f'{name}.py `{module}` ni import qiladi, lekin bunday modul yo‘q.')


class HelpTests(unittest.TestCase):
    """--help must work: it is the first thing anyone runs, and it exercises argparse."""

    def test_every_script_answers_help_without_doing_any_work(self):
        for name in SCRIPTS:
            with self.subTest(script=name):
                done = subprocess.run([sys.executable, str(ROOT / (name + '.py')), '--help'],
                                      cwd=ROOT, capture_output=True, text=True, timeout=120)
                self.assertEqual(done.returncode, 0, f'{name}.py --help exit={done.returncode}: {done.stderr[-300:]}')
                self.assertIn('usage', done.stdout.lower())


class PipelinePayloadTests(unittest.TestCase):
    """The regression that hit check_all.py and validate_pipeline.py twice."""
    def setUp(self):
        isolate_triage(self)


    def capture(self, module_name, argv):
        """Run a script's main() with pipeline.start() intercepted, returning the payload."""
        from zanjir import pipeline
        module = importlib.import_module(module_name)
        seen = {}

        def fake_start(payload, background=True):
            seen['payload'] = payload
            raise SystemExit(0)                                  # stop before any scanning happens

        with patch.object(pipeline, 'start', fake_start), patch.object(sys, 'argv', argv):
            with self.assertRaises(SystemExit):
                module.main()
        return seen.get('payload')

    def test_each_pipeline_client_sends_exactly_the_fields_validate_requires(self):
        from zanjir import pipeline
        expected = set(pipeline.SELECTION_FIELDS) | {'online'}
        for name in PIPELINE_CLIENTS:
            with self.subTest(script=name):
                payload = self.capture(name, [name + '.py'])
                self.assertIsNotNone(payload, f'{name}.py pipeline.start() ni chaqirmadi.')
                self.assertEqual(set(payload), expected,
                                 f'{name}.py yuborgan maydonlar pipeline.validate() talabidan farq qiladi.')

    def test_each_pipeline_client_offers_a_flag_for_every_selection_field(self):
        # A field with no flag cannot be chosen from the command line at all.
        for name in PIPELINE_CLIENTS:
            text = source(name)
            for field in ('target', 'web_target', 'image_target', 'repository_target'):
                with self.subTest(script=name, field=field):
                    self.assertIn('--' + field.replace('_', '-'), text)

    def test_a_json_selection_literal_in_any_script_carries_the_full_field_set(self):
        """Covers scripts that post the selection as JSON instead of calling start()."""
        from zanjir import pipeline
        expected = set(pipeline.SELECTION_FIELDS) | {'online'}
        for name in SCRIPTS:
            for node in ast.walk(ast.parse(source(name), filename=name + '.py')):
                if not isinstance(node, ast.Dict):
                    continue
                keys = {k.value for k in node.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)}
                # Only look at dicts that are clearly a pipeline selection.
                if 'web_target' not in keys or 'online' not in keys:
                    continue
                with self.subTest(script=name, line=node.lineno):
                    self.assertEqual(keys, expected,
                                     f'{name}.py:{node.lineno} dagi tanlov pipeline.validate() talabiga mos emas.')


class StaleConstantTests(unittest.TestCase):
    """verify_pilot_api.py asserted a version and a mode the application had left behind."""

    def test_no_script_hardcodes_a_version_that_disagrees_with_the_application(self):
        from zanjir import readiness
        current = readiness.status()['version']
        older = {'0.1.0', '0.2.0', '0.3.0', '0.4.0', '0.5.0'} - {current}
        for name in SCRIPTS:
            text = source(name)
            for stale in older:
                with self.subTest(script=name, version=stale):
                    self.assertNotIn(f"'{stale}'", text,
                                     f'{name}.py `{stale}` versiyasini qattiq yozgan; joriy versiya {current}.')

    def test_no_script_still_refers_to_the_retired_pilot_mode_name(self):
        # Renamed in 0.6 when the offline mode was removed.
        for name in SCRIPTS:
            with self.subTest(script=name):
                self.assertNotIn('local_single_user_pilot', source(name))

    def test_the_health_endpoint_and_readiness_agree_on_the_version(self):
        from zanjir import readiness
        declared = [line for line in source('app').splitlines() if '"/api/health"' in line or "'/api/health'" in line]
        self.assertTrue(declared, '/api/health marshruti topilmadi.')
        text = source('app')
        start = text.index('/api/health')
        window = text[start:start + 400]
        self.assertIn(f'"{readiness.status()["version"]}"', window,
                      '/api/health readiness bilan bir xil versiyani qaytarmaydi.')


class CodeFingerprintTests(unittest.TestCase):
    """A running server keeps the code it loaded; the dashboard must be able to say so."""

    def test_the_two_fingerprints_agree_inside_one_process(self):
        import app
        from zanjir import readiness
        self.assertEqual(app.CODE_FINGERPRINT, readiness.code_fingerprint())

    def test_the_fingerprint_changes_when_a_source_file_changes(self):
        from zanjir import readiness
        target = ROOT / 'zanjir/taxonomy.py'
        original = target.read_bytes()
        before = readiness.code_fingerprint()
        try:
            target.write_bytes(original + b'\n# fingerprint test\n')
            self.assertNotEqual(before, readiness.code_fingerprint())
        finally:
            target.write_bytes(original)
        self.assertEqual(before, readiness.code_fingerprint())


class OutputContractTests(unittest.TestCase):
    """Scripts whose stdout is meant to be parsed must not mix prose into it."""

    JSON_ON_STDOUT = ('check_all', 'ci_gate', 'scan_code', 'check_dependencies', 'check_image', 'check_web')

    def test_only_json_reaches_stdout(self):
        """Anything printed without file= must be json.dumps(...).

        `script > out.json` has to produce a parseable file, so a progress line
        on stdout is a defect even though it looks harmless to a human reader.
        """
        def is_json_dumps(node):
            return (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == 'dumps')

        for name in self.JSON_ON_STDOUT:
            tree = ast.parse(source(name), filename=name + '.py')
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'print'):
                    continue
                if any(kw.arg == 'file' for kw in node.keywords):
                    continue                                     # explicitly redirected, fine
                first = node.args[0] if node.args else None
                with self.subTest(script=name, line=node.lineno):
                    self.assertTrue(first is not None and is_json_dumps(first),
                                    f'{name}.py:{node.lineno} stdout ga JSON bo‘lmagan narsa chiqaradi; '
                                    'odam uchun matnga file=sys.stderr qo‘shing.')

    def test_stdout_of_a_real_run_parses_as_json(self):
        """The contract above, checked by running the script's real printing path.

        The scan itself is stubbed, and so is the target lookup: the target used
        to be resolved for real, so the test passed only on the machine where
        'validation-osv-control' happened to be registered. An earlier version of this test ran the CLI
        for real and so wrote a genuine report into dependency-runs/ on every
        suite run -- test data mixing into the evidence store, the same mistake
        that once pushed crAPI's real reports out of the listing.
        """
        import contextlib
        import io
        import tempfile
        from zanjir import dependencies, scanners
        module = importlib.import_module('check_dependencies')
        fake = {'id': '20260101T000000-abcdef12', 'target': 'validation-osv-control', 'state': 'completed',
                'count': 2, 'priority_counts': {'P1': 0}, 'progress': 'tugadi'}
        stdout, stderr = io.StringIO(), io.StringIO()
        with tempfile.TemporaryDirectory() as temp, \
             patch.object(dependencies, 'RUNS', Path(temp)), \
             patch.object(dependencies, 'start', return_value=fake) as start, \
             patch.object(scanners, 'check_target', return_value=None), \
             patch.object(sys, 'argv', ['check_dependencies.py', '--target', 'validation-osv-control']), \
             contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as caught:
                module.main()
        self.assertEqual(caught.exception.code, 0)
        start.assert_called_once()
        try:
            self.assertEqual(json.loads(stdout.getvalue())['id'], fake['id'])
        except ValueError as error:
            self.fail(f'stdout JSON emas ({error}); birinchi satr: {stdout.getvalue().splitlines()[:1]}')
        self.assertIn('Tekshiruv boshlandi', stderr.getvalue())


if __name__ == '__main__':
    unittest.main(verbosity=2)
