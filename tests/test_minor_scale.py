"""Smaller large-project defects (shortcomings review 2026-11-02).

  - fixes.read_manifests walked the repository a second time and stopped silently
    at 200 files, so a monorepo lost every fix diff past the 200th lockfile. It now
    reads the inventory's own manifest list (plus NuGet project files), bounded
    by bytes -- and finds the same files the walk found.
  - Kubernetes: a third workload with the same name and kind received the same
    id as the second, merging two workloads into one service.
"""
import shutil
import tempfile
import unittest
from pathlib import Path

from zanjir import fixes, inventory
from zanjir.repository import scan_repository

CORPUS = Path(__file__).resolve().parents[1] / 'benchmarks' / 'corpus'


def from_inventory(root):
    collected = inventory.collect(root)
    return fixes.read_manifests(root, paths=[m['path'] for m in collected['manifests']]
                                + collected.get('project_files', []))


class ManifestReadTests(unittest.TestCase):
    def test_a_the_inventory_list_finds_what_the_walk_found(self):
        for name in ('jvm-dotnet', 'sast', 'iac', 'compose'):
            root = CORPUS / name
            walked = fixes.read_manifests(root)
            listed = from_inventory(root)
            self.assertEqual(sorted(listed), sorted(walked), name)

    def test_b_more_than_two_hundred_manifests_are_all_read(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        for n in range(250):
            folder = root / f'svc{n:03}'
            folder.mkdir()
            (folder / 'requirements.txt').write_text(f'pkg{n}==1.0\n', encoding='utf-8')
        self.assertEqual(len(fixes.read_manifests(root)), 200)          # the old walk's silent cut
        self.assertEqual(len(from_inventory(root)), 250)


WORKLOAD = '''apiVersion: apps/v1
kind: Deployment
metadata: {name: web}
spec:
  template:
    metadata: {labels: {app: web}}
    spec:
      containers: [{name: c, image: IMAGE}]
'''


class WorkloadIdTests(unittest.TestCase):
    def test_three_workloads_with_one_name_get_three_ids(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        for n, overlay in enumerate(('dev', 'staging', 'prod')):
            folder = root / 'k8s' / overlay
            folder.mkdir(parents=True)
            (folder / 'web.yaml').write_text(WORKLOAD.replace('IMAGE', f'nginx:1.{n}'), encoding='utf-8')
        report = scan_repository(root, 'k8s')
        ids = [service['id'] for service in report['services']]
        self.assertEqual(len(ids), 3)
        self.assertEqual(len(set(ids)), 3, ids)
        self.assertEqual(ids[:2], ['web', 'web:deployment'])           # the first two keep their old ids


if __name__ == '__main__':
    unittest.main()
