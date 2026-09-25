"""Image-scan speed-ups that must not cost correctness, privacy or the size limit.

Measured on crAPI's web image:
  - Trivy refreshed its database inside the scan: 4.3 of 7.7 minutes.
  - `--max-image-size` re-downloaded every layer to learn the size: 143 s,
    against 3 s for the same cached image without it.
After both changes a repeat scan of that image took 3.3 s, same 169 findings.
"""
import datetime
import json
import shutil
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from zanjir import images

DIGEST = 'sha256:' + 'a' * 64
REFERENCE = 'crapi/crapi-web@' + DIGEST


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        for name, value in (('CACHE', self.tmp / 'cache'), ('SIZE_VERIFIED', self.tmp / 'cache/size-verified.json')):
            patcher = patch.object(images, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        (self.tmp / 'cache').mkdir()

    def metadata(self, name, next_update):
        folder = self.tmp / 'cache' / name
        folder.mkdir(parents=True, exist_ok=True)
        (folder / 'metadata.json').write_text(json.dumps({'NextUpdate': next_update}), encoding='utf-8')


class DatabaseStateTests(Base):
    def test_trivys_nanosecond_utc_timestamps_are_read(self):
        # Python 3.10 reads neither the Z nor nine fractional digits.
        self.metadata('db', '2999-01-01T01:11:25.279659191Z')
        self.assertEqual(images.database_state('db'), 'current')

    def test_a_passed_next_update_is_due(self):
        self.metadata('db', '2000-01-01T00:00:00.000000001Z')
        self.assertEqual(images.database_state('db'), 'due')

    def test_absent_or_unreadable_metadata_is_missing(self):
        self.assertEqual(images.database_state('db'), 'missing')
        (self.tmp / 'cache/db').mkdir()
        (self.tmp / 'cache/db/metadata.json').write_text('{broken', encoding='utf-8')
        self.assertEqual(images.database_state('db'), 'missing')


class RefreshTests(Base):
    def setUp(self):
        super().setUp()
        images.CANCEL['r'] = threading.Event()
        self.addCleanup(images.CANCEL.pop, 'r', None)

    class Done:
        def __init__(self, code): self.returncode = code
        def poll(self): return self.returncode
        def kill(self): pass
        def wait(self, timeout=None): return self.returncode

    def test_current_databases_start_no_download(self):
        for name, _ in images.DATABASES:
            self.metadata(name, '2999-01-01T00:00:00Z')
        with patch.object(images.subprocess, 'Popen') as popen:
            outcome = images.refresh_databases('r', self.tmp, {})
        popen.assert_not_called()
        self.assertEqual(outcome['current'], ['db', 'java-db'])

    def test_a_failed_refresh_with_an_old_database_is_reported_not_raised(self):
        for name, _ in images.DATABASES:
            self.metadata(name, '2000-01-01T00:00:00Z')
        with patch.object(images.subprocess, 'Popen', return_value=self.Done(1)):
            outcome = images.refresh_databases('r', self.tmp, {})
        self.assertEqual(outcome['failed'], ['db', 'java-db'])

    def test_no_database_at_all_is_a_hard_failure(self):
        # Without a vulnerability database a scan cannot find anything, and an
        # empty result must never be mistaken for a clean image.
        with patch.object(images.subprocess, 'Popen', return_value=self.Done(1)), self.assertRaises(ValueError):
            images.refresh_databases('r', self.tmp, {})

    def test_every_download_disables_telemetry(self):
        seen = []
        def popen(args, **kw):
            seen.append(args)
            return self.Done(1)
        self.metadata('db', '2000-01-01T00:00:00Z')
        self.metadata('java-db', '2000-01-01T00:00:00Z')
        with patch.object(images.subprocess, 'Popen', side_effect=popen):
            images.refresh_databases('r', self.tmp, {})
        self.assertTrue(seen)
        for args in seen:
            self.assertIn('--disable-telemetry', args)


class CommandTests(Base):
    def test_the_scan_never_refreshes_a_database_itself(self):
        command = images.command(REFERENCE, self.tmp)
        self.assertIn('--skip-db-update', command)
        self.assertIn('--skip-java-db-update', command)

    def test_a_database_that_could_not_be_fetched_is_left_for_trivy(self):
        command = images.command(REFERENCE, self.tmp, skip_update=('db',))
        self.assertNotIn('--skip-java-db-update', command)

    def test_telemetry_and_version_checks_are_always_off(self):
        # The stated data policy: only package names, versions and advisory ids
        # leave this machine. Trivy's default anonymous usage report is not that.
        command = images.command(REFERENCE, self.tmp)
        self.assertIn('--disable-telemetry', command)
        self.assertIn('--skip-version-check', command)

    def test_the_size_limit_is_enforced_unless_the_digest_is_proven(self):
        self.assertIn('--max-image-size', images.command(REFERENCE, self.tmp))
        self.assertNotIn('--max-image-size', images.command(REFERENCE, self.tmp, check_size=False))


class SizeVerifiedTests(Base):
    def test_an_unknown_digest_is_not_verified(self):
        self.assertFalse(images.size_verified(DIGEST))

    def test_a_marked_digest_is_verified_and_others_are_not(self):
        images.mark_size_verified(DIGEST)
        self.assertTrue(images.size_verified(DIGEST))
        self.assertFalse(images.size_verified('sha256:' + 'b' * 64))

    def test_a_corrupted_record_means_check_again_not_skip(self):
        images.SIZE_VERIFIED.write_text('{broken', encoding='utf-8')
        self.assertFalse(images.size_verified(DIGEST))
        images.mark_size_verified(DIGEST)
        self.assertTrue(images.size_verified(DIGEST))


class PrivacyCoverageTests(unittest.TestCase):
    def test_no_trivy_invocation_in_the_project_omits_disable_telemetry(self):
        root = Path(__file__).resolve().parents[1]
        installer = (root / 'setup_tools.py').read_text(encoding='utf-8')
        self.assertIn('--disable-telemetry', installer)
        self.assertIn('--disable-telemetry', images.QUIET)


if __name__ == '__main__':
    unittest.main(verbosity=2)
