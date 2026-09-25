"""Platform branching, checked in both directions from one machine.

The whole .tools/ tree originally shipped Windows-only binaries and nothing on
macOS or Linux could run at all. The fix put a branch in four consumers and two
installers -- six places that must agree on where a binary lives, or a scan
fails with OSError on whichever platform nobody happened to be using.

These tests cannot run a Windows binary on macOS. What they can do, and do, is
re-evaluate each branch under a mocked sys.platform and assert that the
consumer's expected path and the installer's chosen destination still describe
the same file. That is the part that silently drifts.
"""
import importlib
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

PLATFORMS = {'win32': 'Windows', 'darwin': 'macOS', 'linux': 'Linux'}


def on_platform(module_name, platform_name, extract, machine='arm64'):
    """Read something from a module as if it had started on another platform.

    The value is extracted while the module is still in that state on purpose:
    importlib.reload() mutates the module object in place, so holding on to it
    and reading later would report whichever platform was loaded last.
    """
    with patch.object(sys, 'platform', platform_name), \
         patch('platform.machine', lambda: machine):
        return extract(importlib.reload(importlib.import_module(module_name)))


def archive_name(module):
    return getattr(module, 'ARCHIVE', None) or module.ARCHIVE_NAME


def destination(module, tool):
    base = Path(module.ROOT) / '.tools' / tool
    return (base / module.SUBDIR if module.SUBDIR else base) / module.BINARY_NAME


class ConsumerPathTests(unittest.TestCase):
    """Where each scanner looks for its binary."""

    @classmethod
    def tearDownClass(cls):
        # Leave every module reloaded for the real platform again.
        for name in ('zanjir.images', 'zanjir.webscan', 'zanjir.scanners'):
            importlib.reload(importlib.import_module(name))

    def test_trivy_path_follows_the_platform(self):
        self.assertEqual(on_platform('zanjir.images', 'win32', lambda m: m.BINARY.name), 'trivy.exe')
        for platform_name in ('darwin', 'linux'):
            with self.subTest(platform=PLATFORMS[platform_name]):
                path = on_platform('zanjir.images', platform_name, lambda m: m.BINARY)
                self.assertEqual(path.name, 'trivy')
                self.assertIn('posix', path.parts)

    def test_nuclei_path_follows_the_platform(self):
        self.assertEqual(on_platform('zanjir.webscan', 'win32', lambda m: m.BINARY.name), 'nuclei.exe')
        for platform_name in ('darwin', 'linux'):
            with self.subTest(platform=PLATFORMS[platform_name]):
                path = on_platform('zanjir.webscan', platform_name, lambda m: m.BINARY)
                self.assertEqual(path.name, 'nuclei')
                self.assertIn('posix', path.parts)

    def test_semgrep_and_gitleaks_paths_follow_the_platform(self):
        names = lambda m: (m.semgrep_exe().name, m.semgrep_bin_dir().name, m.gitleaks_exe().name)
        self.assertEqual(on_platform('zanjir.scanners', 'win32', names),
                         ('semgrep.exe', 'Scripts', 'gitleaks.exe'))
        self.assertEqual(on_platform('zanjir.scanners', 'linux', names),
                         ('semgrep', 'bin', 'gitleaks'))

    def test_the_windows_layout_never_uses_the_posix_folder(self):
        # The two builds live side by side; mixing them would overwrite provenance.
        parts = on_platform('zanjir.scanners', 'win32',
                            lambda m: m.semgrep_exe().parts + m.gitleaks_exe().parts)
        self.assertNotIn('posix', parts)


class InstallerAgreementTests(unittest.TestCase):
    """The installer's destination must be the file the scanner later looks for."""

    @classmethod
    def tearDownClass(cls):
        for name in ('zanjir.images', 'zanjir.webscan', 'setup_tools', 'setup_nuclei'):
            importlib.reload(importlib.import_module(name))

    def test_trivy_installer_and_scanner_agree_on_every_platform(self):
        for platform_name in PLATFORMS:
            with self.subTest(platform=PLATFORMS[platform_name]):
                installed = on_platform('setup_tools', platform_name, lambda m: destination(m, 'trivy'))
                expected = on_platform('zanjir.images', platform_name, lambda m: m.BINARY)
                self.assertEqual(installed, expected)

    def test_nuclei_installer_and_scanner_agree_on_every_platform(self):
        for platform_name in PLATFORMS:
            with self.subTest(platform=PLATFORMS[platform_name]):
                installed = on_platform('setup_nuclei', platform_name, lambda m: destination(m, 'nuclei'))
                expected = on_platform('zanjir.webscan', platform_name, lambda m: m.BINARY)
                self.assertEqual(installed, expected)

    def test_each_platform_downloads_a_different_archive(self):
        for module_name in ('setup_tools', 'setup_nuclei'):
            names = {on_platform(module_name, p, archive_name) for p in PLATFORMS}
            with self.subTest(installer=module_name):
                self.assertEqual(len(names), len(PLATFORMS))

    def test_processor_architecture_selects_a_different_archive(self):
        # An arm64 machine must not be handed an amd64 build.
        for module_name in ('setup_tools', 'setup_nuclei'):
            arm = on_platform(module_name, 'linux', archive_name, machine='aarch64')
            intel = on_platform(module_name, 'linux', archive_name, machine='x86_64')
            with self.subTest(installer=module_name):
                self.assertNotEqual(arm, intel)


class SocketPathLimitTests(unittest.TestCase):
    """macOS caps a Unix socket path at 104 bytes, other systems at 108."""

    @classmethod
    def tearDownClass(cls):
        importlib.reload(importlib.import_module('zanjir.scanners'))

    def test_the_darwin_limit_is_the_stricter_one(self):
        source = (Path(__file__).resolve().parents[1] / 'zanjir/scanners.py').read_text(encoding='utf-8')
        self.assertIn("limit=104 if sys.platform=='darwin' else 108", source)

    def test_an_over_long_temporary_path_is_refused_rather_than_failing_mid_scan(self):
        from zanjir import scanners
        with patch('tempfile.gettempdir', lambda: '/' + 'x' * 120):
            with self.assertRaises((ValueError, OSError)):
                with scanners.scanner_environment(Path('/tmp')):
                    pass


class ImageFailureReasonTests(unittest.TestCase):
    """Trivy's log stays local, so its cause has to be lifted into the report.

    "tool.log ni tekshiring" is not an action when the log is a file the web
    interface never shows -- and a real crAPI image hit exactly this path by
    exceeding Trivy's own ten-minute budget.
    """

    def log(self, text):
        path = Path(__import__('tempfile').mkdtemp()) / 'tool.log'
        self.addCleanup(__import__('shutil').rmtree, path.parent, True)
        path.write_text(text, encoding='utf-8')
        return path

    def test_trivys_own_timeout_is_named_and_not_called_a_clean_result(self):
        from zanjir import images
        reason = images.failure_reason(self.log(
            'FATAL\trun error: image scan error: scan failed: context deadline exceeded\n'))
        self.assertIn('vaqt byudjetidan', reason)
        self.assertIn('toza natija emas', reason)

    def test_each_known_cause_maps_to_its_own_message(self):
        from zanjir import images
        for needle, expected in images.FAILURE_HINTS:
            with self.subTest(cause=needle):
                self.assertEqual(images.failure_reason(self.log(f'FATAL {needle} here')), expected)

    def test_an_unrecognised_failure_falls_back_without_claiming_success(self):
        from zanjir import images
        reason = images.failure_reason(self.log('FATAL something entirely new\n'))
        self.assertEqual(reason, images.GENERIC_FAILURE)
        self.assertIn('toza natija emas', reason)

    def test_every_failure_type_reaches_the_report_with_a_reason(self):
        """A report that only says "failed" gives the operator nothing to act on.

        The real crapi-identity scan hit the outer deadline -- a TimeoutError,
        not a ValueError -- and landed in the report with message: null.
        """
        import inspect
        from zanjir import images
        body = inspect.getsource(images.execute)
        self.assertIn('ValueError, TimeoutError', body)
        # The else-branch must exist, so an unexpected type still gets wording.
        self.assertIn("kutilmagan xato", body)

    def test_the_outer_deadline_names_the_cause_when_the_log_shows_one(self):
        # A run this project killed must not be described as if Trivy had
        # reported the failure itself, and "just retry" is wrong when the Java
        # database never finished downloading and so was never cached.
        from zanjir import images
        java = images.failure_reason(
            self.log('INFO\t[javadb] Downloading Java DB...\n'), images.DEADLINE_FAILURE)
        self.assertIn('trivy-java-db', java)
        self.assertIn('qayta urinish odatda yordam bermaydi', java)

    def test_the_deadline_falls_back_to_its_own_wording_for_an_unknown_cause(self):
        from zanjir import images
        reason = images.failure_reason(self.log('INFO nothing notable\n'), images.DEADLINE_FAILURE)
        self.assertEqual(reason, images.DEADLINE_FAILURE)
        self.assertIn('umumiy vaqt chegarasidan', reason)
        self.assertIn('toza natija emas', reason)

    def test_a_missing_log_still_returns_a_failure_message(self):
        from zanjir import images
        self.assertEqual(images.failure_reason(Path('/no/such/tool.log')), images.GENERIC_FAILURE)


class VendoredWindowsBuildTests(unittest.TestCase):
    """What can actually be verified about the Windows side from another machine.

    Running a Windows binary here is impossible and nothing below pretends
    otherwise. What is checkable is that the files the Windows code path points
    at exist and really are Windows executables -- which is what broke before:
    the tree shipped Windows-only builds and the POSIX paths pointed at nothing.
    """

    def windows_paths(self):
        return {
            'semgrep': on_platform('zanjir.scanners', 'win32', lambda m: m.semgrep_exe()),
            'gitleaks': on_platform('zanjir.scanners', 'win32', lambda m: m.gitleaks_exe()),
            'trivy': on_platform('zanjir.images', 'win32', lambda m: m.BINARY),
            'nuclei': on_platform('zanjir.webscan', 'win32', lambda m: m.BINARY),
        }

    @classmethod
    def tearDownClass(cls):
        for name in ('zanjir.images', 'zanjir.webscan', 'zanjir.scanners'):
            importlib.reload(importlib.import_module(name))

    def test_each_windows_path_points_at_a_file_that_exists(self):
        for tool, path in self.windows_paths().items():
            with self.subTest(tool=tool):
                if not path.exists():
                    self.skipTest(f'{tool} uchun Windows binari bu nusxada vendorlanmagan')
                self.assertTrue(path.is_file(), f'{tool}: {path} fayl emas')

    def test_each_vendored_windows_binary_really_is_a_windows_executable(self):
        # PE files start with "MZ"; a POSIX build copied into the Windows path
        # would pass an existence check and fail only on a Windows machine.
        for tool, path in self.windows_paths().items():
            with self.subTest(tool=tool):
                if not path.is_file():
                    self.skipTest(f'{tool} uchun Windows binari bu nusxada vendorlanmagan')
                self.assertEqual(path.read_bytes()[:2], b'MZ',
                                 f'{tool}: {path} Windows bajariladigan fayli emas')

    def test_the_posix_build_is_not_the_same_file_as_the_windows_one(self):
        posix = on_platform('zanjir.scanners', 'linux', lambda m: m.gitleaks_exe())
        windows = self.windows_paths()['gitleaks']
        self.assertNotEqual(posix, windows)


if __name__ == '__main__':
    unittest.main(verbosity=2)


class NewModulePortabilityTests(unittest.TestCase):
    """B5-B7 modules, checked for the assumptions that only fail on Windows.

    Every one of these was a real defect once: a POSIX-only path in a git flag
    meant remote scanning could never have worked on Windows, and nothing in the
    suite would have said so, because the suite runs here.
    """

    MODULES = ('remote_source.py', 'settings.py', 'iac.py', 'sbom.py',
               'findings_index.py', 'triage.py', 'baseline.py', 'chains.py')

    def source(self, name):
        from zanjir.engine import ROOT
        return (ROOT / 'zanjir' / name).read_text(encoding='utf-8')

    def test_a_no_module_hardcodes_a_posix_only_path(self):
        import re
        for name in self.MODULES:
            body = self.source(name)
            for match in re.finditer(r"['\"](/dev/null|/tmp/|/etc/|/var/)", body):
                line = body.count('\n', 0, match.start()) + 1
                self.fail(f'{name}:{line} — {match.group(1)} Windows’da mavjud emas')

    def test_b_paths_are_built_with_pathlib_not_string_concatenation(self):
        import re
        for name in self.MODULES:
            body = self.source(name)
            self.assertIsNone(re.search(r"\+\s*['\"]/[a-z]", body), f'{name}: qo‘lda "/" bilan yo‘l qurilgan')

    def test_c_the_clone_disables_hooks_with_a_real_directory(self):
        from zanjir import remote_source
        # The comment above the line may still name /dev/null to explain why it
        # is not used; what must not contain it is the flag git receives.
        body = self.source('remote_source.py')
        self.assertIn("core.hooksPath={hooks}", body)
        command_lines = [line for line in body.splitlines()
                         if 'hooksPath' in line and not line.strip().startswith('#')]
        self.assertTrue(command_lines)
        for line in command_lines:
            self.assertNotIn('/dev/null', line)
        self.assertEqual(remote_source.CLONE_TIMEOUT, 600)

    def test_d_the_settings_file_tolerates_a_platform_without_chmod(self):
        """Windows ACLs make os.chmod a no-op or an error; it must not fail the write."""
        body = self.source('settings.py')
        self.assertIn('except OSError', body)
        self.assertIn('os.replace', body, 'atomik yozuv yo‘q')

    def test_e_the_iac_scanner_uses_the_same_binary_as_the_image_scanner(self):
        """A second hardcoded trivy path would drift from the Windows layout."""
        from zanjir import iac, images
        self.assertIn('images.BINARY', self.source('iac.py'))
        self.assertTrue(str(images.BINARY).endswith(('trivy', 'trivy.exe')))
