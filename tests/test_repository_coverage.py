"""Repository / Kubernetes inputs that were not read (shortcomings review 2026-11-02, LP#2).

The repository stage was always 'completed': manifests past MAX_FILES, Helm
templates, unreadable files and failed includes were only sentences in
`unknowns`, so their workloads were missing from every chain while the stage,
the assessment and the CI gate all said "finished". Now the report counts them
(`coverage_gaps`), the stage is 'partial', and the gate tells a coverage gap
(not read -> passes, recorded) from a check that never happened (never reached
-> exit 2).
"""
import shutil
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from zanjir import ci_gate, kubernetes, pipeline, repo_store
from zanjir.repository import scan_repository

POD = '''apiVersion: apps/v1
kind: Deployment
metadata: {name: web}
spec:
  template:
    metadata: {labels: {app: web}}
    spec:
      containers: [{name: web, image: nginx}]
'''


class CountTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.root, True)
        (self.root / 'k8s').mkdir()
        (self.root / 'k8s' / 'web.yaml').write_text(POD, encoding='utf-8')

    def test_a_a_clean_folder_has_no_gaps(self):
        report = scan_repository(self.root, 'k8s')
        self.assertEqual(report['coverage_gaps'], {'unread': 0, 'not_reached': 0})

    def test_b_a_helm_template_is_counted_as_unread(self):
        (self.root / 'k8s' / 'chart.yaml').write_text('replicas: {{ .Values.replicas }}\n', encoding='utf-8')
        report = scan_repository(self.root, 'k8s')
        self.assertEqual(report['coverage_gaps']['unread'], 1)
        self.assertEqual(report['coverage_gaps']['not_reached'], 0)

    def test_c_manifests_past_the_cap_are_counted_as_not_reached(self):
        for n in range(4):
            (self.root / 'k8s' / f'extra-{n}.yaml').write_text(POD.replace('name: web}', f'name: web{n}}}'),
                                                               encoding='utf-8')
        with mock.patch.object(kubernetes, 'MAX_FILES', 2):
            report = scan_repository(self.root, 'k8s')
        self.assertEqual(report['coverage_gaps']['not_reached'], 3)


class StageStateTests(unittest.TestCase):
    def stage_state(self, gaps):
        child = {'id': 'r1', 'summary': {'findings': 0}, 'findings': [], 'coverage_gaps': gaps}
        commits = []
        with mock.patch.object(repo_store, 'scan_profile', return_value=child):
            pipeline.run_stage({'kind': 'repository', 'target': 't'}, threading.Event(),
                               lambda stage, **fields: commits.append(fields))
        return commits[-1]['state'], {'kind': 'repository', 'state': commits[-1]['state'], 'report': child}

    def test_a_no_gaps_is_completed(self):
        state, stage = self.stage_state({'unread': 0, 'not_reached': 0})
        self.assertEqual(state, 'completed')
        self.assertEqual(ci_gate.classify_stage(stage)[0], 'finished')

    def test_b_an_unread_input_is_a_gap_the_gate_passes(self):
        state, stage = self.stage_state({'unread': 2, 'not_reached': 0})
        self.assertEqual(state, 'partial')
        self.assertEqual(ci_gate.classify_stage(stage)[0], 'gap')

    def test_c_an_input_never_reached_stops_the_gate(self):
        state, stage = self.stage_state({'unread': 0, 'not_reached': 500})
        self.assertEqual(state, 'partial')
        self.assertEqual(ci_gate.classify_stage(stage)[0], 'incomplete')

    def test_d_an_old_report_without_the_field_is_completed(self):
        state, _ = self.stage_state(None)
        self.assertEqual(state, 'completed')


if __name__ == '__main__':
    unittest.main()
