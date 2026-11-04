"""Hard limits end a stage with what was collected, not with nothing (shortcomings review 2026-11-02, LP#12).

The dependency inventory raised ValueError past 100 000 walked files, its
manifest bytes/count bound or its package bound; the Kubernetes reader past
MAX_DOCUMENTS. Each failed the whole stage -- zero CVE results for a large
monorepo. Now the walk stops at the bound, a `*_limit` gap names it, the stage is
partial, and the CI gate treats it as incomplete (what lay past the bound was
never checked).
"""
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from zanjir import ci_gate, inventory, kubernetes
from zanjir.repository import scan_repository


class InventoryLimitTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        for n in range(6):
            folder = self.root / f'svc{n}'
            folder.mkdir()
            (folder / 'requirements.txt').write_text(f'pkg{n}==1.0.{n}\n', encoding='utf-8')

    def reasons(self, collected):
        return [gap['reason'] for gap in collected['gaps']]

    def test_a_the_file_walk_bound_keeps_what_it_found(self):
        with mock.patch.object(inventory, 'MAX_WALK_FILES', 3):
            collected = inventory.collect(self.root)
        self.assertIn('file_walk_limit', self.reasons(collected))
        self.assertEqual(len(collected['packages']), 3)

    def test_b_the_manifest_bound_keeps_what_it_found(self):
        with mock.patch.object(inventory, 'MAX_MANIFESTS', 2):
            collected = inventory.collect(self.root)
        self.assertIn('manifest_limit', self.reasons(collected))
        self.assertEqual(len(collected['manifests']), 2)

    def test_c_the_package_bound_keeps_what_it_found(self):
        with mock.patch.object(inventory, 'MAX_PACKAGES', 2):
            collected = inventory.collect(self.root)
        self.assertIn('package_limit', self.reasons(collected))
        self.assertGreaterEqual(len(collected['packages']), 2)

    def test_d_the_gate_calls_a_bounded_inventory_incomplete(self):
        with mock.patch.object(inventory, 'MAX_MANIFESTS', 2):
            collected = inventory.collect(self.root)
        stage = {'kind': 'dependencies', 'state': 'partial',
                 'report': {'coverage': {k: v for k, v in collected.items() if k != 'packages'},
                            'feeds': {'kev': {'state': 'available'}}}}
        verdict, reason = ci_gate.classify_stage(stage)
        self.assertEqual(verdict, 'incomplete')
        self.assertIn('manifest_limit', reason)

    def test_e_an_ordinary_gap_still_passes_as_a_gap(self):
        stage = {'kind': 'dependencies', 'state': 'partial',
                 'report': {'coverage': {'gaps': [{'path': 'a/package.json', 'reason': 'npm_lockfile_missing'}]},
                            'feeds': {'kev': {'state': 'available'}}}}
        self.assertEqual(ci_gate.classify_stage(stage)[0], 'gap')


POD = '''apiVersion: apps/v1
kind: Deployment
metadata: {name: NAME}
spec:
  template:
    metadata: {labels: {app: NAME}}
    spec:
      containers: [{name: c, image: nginx}]
'''


class KubernetesLimitTests(unittest.TestCase):
    def test_documents_past_the_bound_are_not_reached_not_fatal(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        (root / 'k8s').mkdir()
        for n in range(5):
            (root / 'k8s' / f'w{n}.yaml').write_text(POD.replace('NAME', f'w{n}'), encoding='utf-8')
        with mock.patch.object(kubernetes, 'MAX_DOCUMENTS', 3):
            report = scan_repository(root, 'k8s')
        self.assertEqual(report['summary']['services'], 3)
        self.assertGreaterEqual(report['coverage_gaps']['not_reached'], 2)


if __name__ == '__main__':
    unittest.main()
