"""A project reached through an unresolved path is still scanned (CI, 2026-11-03).

scanners.snapshot checked every directory with Path(current).resolve() against a
source root it never resolved itself. Any root whose written form differs from
its resolved form -- a Windows 8.3 short name (C:\\Users\\RUNNER~1\\...), macOS's
/var -> /private/var, a junction or a symlinked project folder -- made every
directory look outside the project, and the whole scan failed with "Manba yo'li
loyiha chegarasidan chiqdi". It surfaced as the only CI failure on Windows and
macOS (Ubuntu's /tmp has no such alias). The root is now resolved once; links
inside the tree are still never followed.
"""
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

from zanjir import scanners


def directory_link(target, link):
    """A link to a directory without admin rights: a junction on Windows, a symlink elsewhere."""
    if sys.platform.startswith('win'):
        import _winapi
        _winapi.CreateJunction(str(target), str(link))
    else:
        os.symlink(target, link, target_is_directory=True)


class UnresolvedRootTests(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.base, True)
        self.real = self.base / 'project'
        (self.real / 'pkg').mkdir(parents=True)
        (self.real / 'a.py').write_text('eval(x)\n', encoding='utf-8')
        (self.real / 'pkg' / 'b.py').write_text('y = 2\n', encoding='utf-8')
        self.link = self.base / 'via-link'
        try:
            directory_link(self.real, self.link)
        except (OSError, ImportError, AttributeError) as error:
            self.skipTest(f'directory link unavailable here: {error}')
        self.assertNotEqual(str(self.link.resolve()), str(self.link))

    def test_a_a_project_reached_through_a_link_is_snapshotted(self):
        coverage = scanners.snapshot(self.link, self.base / 'out')
        self.assertEqual(coverage['files'], 2)
        self.assertEqual(sorted(entry['path'] for entry in coverage['manifest']), ['a.py', 'pkg/b.py'])

    def test_b_the_same_project_by_either_path_gives_the_same_snapshot(self):
        through_link = scanners.snapshot(self.link, self.base / 'out1')
        direct = scanners.snapshot(self.real, self.base / 'out2')
        self.assertEqual(through_link['snapshot_sha256'], direct['snapshot_sha256'])

    def test_c_a_link_inside_the_tree_is_still_not_followed(self):
        outside = self.base / 'outside'
        outside.mkdir()
        (outside / 'secret.py').write_text('KEY = 1\n', encoding='utf-8')
        directory_link(outside, self.real / 'escape')
        coverage = scanners.snapshot(self.link, self.base / 'out3')
        self.assertNotIn('escape/secret.py', [entry['path'] for entry in coverage['manifest']])


if __name__ == '__main__':
    unittest.main()
