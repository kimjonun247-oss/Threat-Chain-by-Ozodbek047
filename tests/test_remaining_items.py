"""Coverage for the last open items: Apex via PMD, a raised image-size limit,
the disk guard, and keeping superseded control reports out of the listing."""
import json
import shutil
import tempfile
import collections
import unittest
from pathlib import Path
from unittest.mock import patch

from zanjir import images, scanners, taxonomy
from isolation import isolate_triage

PMD_OUTPUT = {'files': [{'filename': None, 'violations': [
    {'rule': 'ApexSOQLInjection', 'beginline': 7, 'priority': 3,
     'description': "Avoid untrusted variable 'customerName' in query"},
    {'rule': 'ApexBadCrypto', 'beginline': 2, 'priority': 1, 'description': 'x'}]}],
    'processingErrors': []}


class ApexTests(unittest.TestCase):
    def setUp(self):
        isolate_triage(self)
        self.source = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.source, True)
        (self.source / 'classes').mkdir()
        self.cls = self.source / 'classes/Account.cls'
        self.cls.write_text('public class Account {}', encoding='utf-8')

    def normalized(self):
        data = json.loads(json.dumps(PMD_OUTPUT))
        data['files'][0]['filename'] = str(self.cls)
        return scanners.normalize('pmd', data, self.source)

    def test_apex_is_detected_only_when_present(self):
        self.assertTrue(scanners.has_apex(self.source))
        empty = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, empty, True)
        (empty / 'a.py').write_text('x=1', encoding='utf-8')
        self.assertFalse(scanners.has_apex(empty))

    def test_pmd_joins_the_scan_only_for_apex_and_only_when_installed(self):
        with patch.object(scanners, 'pmd_exe', lambda: self.cls):   # any existing file stands in
            self.assertIn('pmd', scanners.tool_commands(self.source, apex=True))
            self.assertNotIn('pmd', scanners.tool_commands(self.source, apex=False))
        with patch.object(scanners, 'pmd_exe', lambda: self.source / 'absent'):
            self.assertNotIn('pmd', scanners.tool_commands(self.source, apex=True))

    def test_violations_become_findings_with_cwe_owasp_and_severity(self):
        rows = {f['rule_id']: f for f in self.normalized()}
        self.assertEqual(rows['ApexSOQLInjection']['cwe_ids'], ['CWE-89'])
        self.assertEqual([o['code'] for o in rows['ApexSOQLInjection']['owasp_top10_2025']], ['A05'])
        self.assertEqual(rows['ApexSOQLInjection']['severity'], 'WARNING')
        self.assertEqual(rows['ApexBadCrypto']['severity'], 'ERROR')
        self.assertEqual(rows['ApexSOQLInjection']['path'], 'classes/Account.cls')
        self.assertFalse(rows['ApexSOQLInjection']['verified'])

    def test_the_report_carries_fixed_wording_not_names_from_the_scanned_code(self):
        # PMD's own description may quote identifiers from the project.
        finding = next(f for f in self.normalized() if f['rule_id'] == 'ApexSOQLInjection')
        self.assertNotIn('customerName', finding['message'])
        self.assertEqual(finding['message'], scanners.PMD_MESSAGES['ApexSOQLInjection'])

    def test_every_apex_security_rule_has_a_cwe_and_a_message(self):
        for rule in scanners.PMD_MESSAGES:
            with self.subTest(rule=rule):
                self.assertTrue(taxonomy.tag_static('pmd', rule)['cwe_ids'])

    def test_malformed_pmd_output_is_an_error_not_an_empty_result(self):
        with self.assertRaises(ValueError):
            scanners.normalize('pmd', {'nope': []}, self.source)


class SizeLimitTests(unittest.TestCase):
    def setUp(self):
        isolate_triage(self)
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        patcher = patch.object(images, 'SIZE_VERIFIED', self.tmp / 'v.json')
        patcher.start()
        self.addCleanup(patcher.stop)
        self.digest = 'sha256:' + 'd' * 64

    def test_sizes_parse_and_nonsense_is_refused(self):
        self.assertEqual(images.size_bytes('1GB'), 1024 ** 3)
        self.assertEqual(images.size_bytes('512mb'), 512 * 1024 ** 2)
        for bad in ('', 'big', '-1GB', '1TB', None):
            with self.subTest(value=bad), self.assertRaises(ValueError):
                images.size_bytes(bad)

    def test_a_digest_verified_under_a_raised_limit_does_not_bypass_the_default(self):
        images.mark_size_verified(self.digest, '2GB')
        self.assertTrue(images.size_verified(self.digest, '2GB'))
        self.assertFalse(images.size_verified(self.digest, '1GB'))

    def test_the_strictest_proven_limit_is_kept(self):
        images.mark_size_verified(self.digest, '1GB')
        images.mark_size_verified(self.digest, '2GB')
        self.assertTrue(images.size_verified(self.digest, '1GB'))

    def test_a_limit_above_the_ceiling_is_refused_before_anything_starts(self):
        target = {'id': 'x', 'reference': 'a/b@sha256:' + 'e' * 64}
        with patch.object(images, 'targets', return_value=[target]), self.assertRaises(ValueError) as caught:
            images.start('x', background=False, size_limit='5GB')
        self.assertIn(images.SIZE_CEILING, str(caught.exception))
        self.assertFalse(images.LOCK.locked())

    def test_a_raised_limit_is_stated_in_the_report_itself(self):
        target = {'id': 'x', 'reference': 'a/b@sha256:' + 'e' * 64}
        with patch.object(images, 'targets', return_value=[target]), patch.object(images, 'RUNS', self.tmp), \
             patch.object(images, 'ensure_disk'), patch.object(images, 'execute', side_effect=lambda rid: images.read(rid)):
            report = images.start('x', background=False, size_limit='2GB')
            images.LOCK.release()
        self.assertEqual(report['size_limit'], '2GB')
        self.assertTrue(report['size_limit_raised'])
        self.assertIn('operator', report['scope'])


class TimeBudgetTests(unittest.TestCase):
    def test_the_default_budget_is_unchanged(self):
        self.assertEqual(images.time_budget_minutes('1GB'), 10)
        self.assertEqual(images.time_budget_minutes('512MB'), 10)

    def test_a_raised_limit_brings_proportionally_more_time(self):
        self.assertEqual(images.time_budget_minutes('2GB'), 20)
        self.assertEqual(images.time_budget_minutes('4GB'), 40)

    def test_the_budget_reaches_the_trivy_command(self):
        command = images.command('a/b@sha256:' + 'e' * 64, Path('/tmp'), limit='2GB')
        self.assertEqual(command[command.index('--timeout') + 1], '20m')


class DiskGuardTests(unittest.TestCase):
    def test_a_scan_the_disk_cannot_hold_is_refused_with_the_numbers(self):
        usage = type('U', (), {'free': 500 * 1024 ** 2})()
        with patch.object(images.shutil, 'disk_usage', return_value=usage), self.assertRaises(ValueError) as caught:
            images.ensure_disk('1GB')
        self.assertIn('0.5 GB', str(caught.exception))
        self.assertIn('toza natija emas', str(caught.exception))

    def test_enough_space_passes(self):
        usage = type('U', (), {'free': 10 * 1024 ** 3})()
        with patch.object(images.shutil, 'disk_usage', return_value=usage):
            images.ensure_disk('2GB')


class ControlArchiveTests(unittest.TestCase):
    def test_only_the_superseded_pair_moves_and_nothing_is_deleted(self):
        import validate_pilot
        from zanjir import dependencies
        runs = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, runs, True)
        for rid in ('20260101T000000-aaaaaaaa', '20260101T000000-bbbbbbbb', '20260102T000000-cccccccc'):
            (runs / rid).mkdir()
            (runs / rid / 'report.json').write_text('{}', encoding='utf-8')
        with patch.object(dependencies, 'RUNS', runs):
            validate_pilot.archive_superseded_pair(
                {'before': '20260101T000000-aaaaaaaa', 'after': '20260101T000000-bbbbbbbb'},
                keep={'20260102T000000-cccccccc'})
        self.assertEqual(sorted(p.name for p in (runs / '_archive').iterdir()),
                         ['20260101T000000-aaaaaaaa', '20260101T000000-bbbbbbbb'])
        self.assertTrue((runs / '20260102T000000-cccccccc').is_dir())

    def test_a_pair_still_in_use_is_never_moved(self):
        import validate_pilot
        from zanjir import dependencies
        runs = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, runs, True)
        (runs / '20260101T000000-aaaaaaaa').mkdir()
        with patch.object(dependencies, 'RUNS', runs):
            validate_pilot.archive_superseded_pair({'before': '20260101T000000-aaaaaaaa'},
                                                   keep={'20260101T000000-aaaaaaaa'})
        self.assertTrue((runs / '20260101T000000-aaaaaaaa').is_dir())

    def test_archived_folders_never_appear_in_the_listing(self):
        from zanjir import run_index
        runs = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, runs, True)
        (runs / '_archive' / '20260101T000000-aaaaaaaa').mkdir(parents=True)
        self.assertEqual(run_index.rows(runs, ('id',), lambda rid: run_index.read(runs, rid, 'x')), [])


class OwaspCoverageTests(unittest.TestCase):
    """Every member of the ten OWASP Top 10:2025 categories is mapped.

    The map used to mirror only the members that had been confirmed one at a
    time, which left seven weaknesses (CWE-61 and the six Injection members
    CWE-80/83/86/91/103/104) showing as a bare CWE id with no category. The
    counts below are MITRE's own, read off cwe.mitre.org/data/definitions/
    1436..1445; a category that loses a member fails here instead of quietly
    dropping findings out of the OWASP chart.
    """

    MEMBERS = {'A01': 40, 'A02': 16, 'A03': 6, 'A04': 32, 'A05': 37,
               'A06': 39, 'A07': 36, 'A08': 14, 'A09': 5, 'A10': 24}

    def test_a_every_category_has_its_full_membership(self):
        counts = collections.Counter(taxonomy.CWE_TO_OWASP.values())
        self.assertEqual(dict(counts), self.MEMBERS)
        self.assertEqual(sum(self.MEMBERS.values()), len(taxonomy.CWE_TO_OWASP))

    def test_b_the_categories_themselves_are_never_mapped_as_members(self):
        """CWE-1436..1445 are the categories and CWE-1450 is the parent view."""
        for number in list(range(1436, 1446)) + [1450]:
            self.assertIsNone(taxonomy.CWE_TO_OWASP.get(number), number)

    def test_c_the_seven_late_additions_classify(self):
        for number, code in ((61, 'A01'), (80, 'A05'), (83, 'A05'), (86, 'A05'),
                             (91, 'A05'), (103, 'A05'), (104, 'A05')):
            self.assertEqual(taxonomy.classify([f'CWE-{number}'])[0]['code'], code, number)

    def test_d_an_unmapped_cwe_is_never_guessed_into_a_category(self):
        # CWE-400 and CWE-1333 are members of no 2025 category; they stay blank.
        self.assertEqual(taxonomy.classify(['CWE-400', 'CWE-1333']), [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
