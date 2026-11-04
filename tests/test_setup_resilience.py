"""Tool installation survives a stale Semgrep venv and says why a step failed (CI, 2026-11-04).

The first CI run that got past the unit tests failed in "Vositalarni o'rnatish"
on Linux: setup_scanners.py stopped after 0.6 s and the log showed only
"Gitleaks 8.30.1 mavjud; xeshi mos." next to BAJARILMADI.

  - setup_all kept `stdout or stderr`, so any step that printed a line before
    failing lost its error message. A failed step now prints its stderr.
  - A Semgrep venv restored from the CI tools cache points at the Python that
    built it; once the runner's Python moves to another patch release the
    interpreter link dangles, `python -m venv` leaves a dangling link as it is,
    and pip fails at once. A venv whose interpreter does not start is now
    removed and built again. (The same happens on a server after a Python upgrade.)
"""
import importlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from zanjir.engine import ROOT

sys.path.insert(0, str(ROOT))
setup_all = importlib.import_module('setup_all')
setup_scanners = importlib.import_module('setup_scanners')


class StepOutputTests(unittest.TestCase):
    STEP = {'key': 'scanners', 'script': 'setup_scanners.py', 'supports_force': False}

    def run_with(self, returncode, stdout, stderr):
        done = subprocess.CompletedProcess(['x'], returncode, stdout, stderr)
        with patch.object(setup_all.subprocess, 'run', return_value=done):
            return setup_all.run(self.STEP, False)

    def test_a_a_failed_step_shows_its_error_not_its_last_success_line(self):
        row = self.run_with(1, 'Gitleaks 8.30.1 mavjud; xeshi mos.\n',
                            'semgrep: o‘rnatilmadi — Semgrep pip bilan o‘rnatilmadi va uv topilmadi (FileNotFoundError).\n')
        self.assertFalse(row['ok'])
        self.assertIn('Semgrep pip bilan o‘rnatilmadi', row['output'][0])

    def test_b_a_successful_step_still_shows_one_line(self):
        row = self.run_with(0, 'line one\nSemgrep 1.177.0 mavjud.\n', '')
        self.assertEqual(row['output'], ['Semgrep 1.177.0 mavjud.'])

    def test_c_a_failure_with_nothing_on_stderr_shows_stdout(self):
        row = self.run_with(1, 'first\nwhat went wrong\n', '')
        self.assertEqual(row['output'][-1], 'what went wrong')


class StaleVenvTests(unittest.TestCase):
    def setUp(self):
        self.tools = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tools, True)
        for name in ('TOOLS', 'ROOT'):             # the success message is relative to ROOT
            patcher = patch.object(setup_scanners, name, self.tools)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.venv, self.python, _ = setup_scanners.semgrep_paths()
        self.python.parent.mkdir(parents=True)
        # An interpreter that cannot start: garbage bytes where python(.exe) should be.
        self.python.write_bytes(b'not an executable')
        (self.venv / 'stale-marker').write_text('from the old Python', encoding='utf-8')

    def test_a_an_interpreter_that_cannot_start_is_detected(self):
        self.assertFalse(setup_scanners.interpreter_runs(self.python))
        self.assertTrue(setup_scanners.interpreter_runs(Path(sys.executable)))

    def test_b_a_broken_venv_is_rebuilt_from_scratch(self):
        seen = {}

        def fake_install(venv, python):
            seen['stale_left'] = (venv / 'stale-marker').exists()
            python.parent.mkdir(parents=True, exist_ok=True)
            python.write_bytes(b'fresh')
        with patch.object(setup_scanners, '_venv_pip_install', fake_install), \
                patch.object(setup_scanners, 'installed_semgrep',
                             side_effect=lambda python: setup_scanners.SEMGREP_VERSION
                             if python.read_bytes() == b'fresh' else None), \
                patch.object(setup_scanners, 'write_json'):
            message = setup_scanners.install_semgrep()
        self.assertFalse(seen['stale_left'], 'the broken venv must be removed before it is built again')
        self.assertIn(setup_scanners.SEMGREP_VERSION, message)

    def test_c_a_working_venv_is_kept_for_an_upgrade(self):
        # A venv whose interpreter runs but holds another Semgrep version is upgraded in place.
        seen = {}
        with patch.object(setup_scanners, 'interpreter_runs', return_value=True), \
                patch.object(setup_scanners, '_venv_pip_install',
                             lambda venv, python: seen.setdefault('kept', (venv / 'stale-marker').exists())), \
                patch.object(setup_scanners, 'installed_semgrep', side_effect=[None, setup_scanners.SEMGREP_VERSION]), \
                patch.object(setup_scanners, 'write_json'):
            setup_scanners.install_semgrep()
        self.assertTrue(seen['kept'])


if __name__ == '__main__':
    unittest.main()
