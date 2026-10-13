"""Kubernetes manifests read into the same report a Compose file produces.

The property that matters is the last class: a manifest report feeds the chain
rules unchanged, so "reachable from outside + a critical CVE in its image" is
found for a cluster deployment exactly as it is for a Compose one.
"""
import tempfile
import unittest
from pathlib import Path

from zanjir import chains, kubernetes, pipeline, portfolio, repo_store, repository
from zanjir.repository import scan_repository

WEB = '''apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: shop
spec:
  template:
    metadata:
      labels: {app: web}
    spec:
      containers:
        - name: web
          image: registry.example.com/shop/web:1.4
          env:
            - {name: DEBUG, value: "true"}
---
apiVersion: v1
kind: Service
metadata: {name: web, namespace: shop}
spec:
  type: LoadBalancer
  selector: {app: web}
  ports:
    - {port: 80, targetPort: 8080}
'''
DATABASE = '''apiVersion: apps/v1
kind: StatefulSet
metadata: {name: db, namespace: shop}
spec:
  template:
    metadata:
      labels: {app: db}
    spec:
      containers:
        - {name: db, image: "postgres:16"}
---
apiVersion: v1
kind: Service
metadata: {name: db, namespace: shop}
spec:
  selector: {app: db}
  ports: [{port: 5432}]
'''
POLICY = '''apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: db-only-from-web, namespace: shop}
spec:
  podSelector:
    matchLabels: {app: db}
  policyTypes: [Ingress]
  ingress:
    - from:
        - podSelector: {matchLabels: {app: web}}
'''
AGENT = '''apiVersion: apps/v1
kind: DaemonSet
metadata: {name: agent}
spec:
  template:
    metadata:
      labels: {app: agent}
    spec:
      hostPID: true
      containers:
        - name: agent
          image: example/agent:2
          securityContext:
            privileged: true
          ports:
            - {containerPort: 9100, hostPort: 9100}
      volumes:
        - name: runtime
          hostPath: {path: /run/containerd/containerd.sock}
'''
INTERNAL = '''apiVersion: apps/v1
kind: Deployment
metadata: {name: worker, namespace: shop}
spec:
  template:
    metadata:
      labels: {app: worker}
    spec:
      containers:
        - name: worker
          image: example/worker:1
          securityContext: {privileged: true}
---
apiVersion: v1
kind: Service
metadata: {name: worker, namespace: shop}
spec:
  selector: {app: worker}
  ports: [{port: 9000}]
'''
INGRESS = '''apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {name: api, namespace: shop}
spec:
  rules:
    - host: api.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service: {name: worker, port: {number: 9000}}
'''


class Manifests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(__import__('shutil').rmtree, self.root, True)

    def put(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')

    def scan(self, path='k8s'):
        return scan_repository(self.root, path)

    def rules(self, report):
        return {(f['rule_id'], f['service_id']) for f in report['findings']}


class DetectionTests(Manifests):
    def test_a_a_folder_or_a_manifest_file_is_kubernetes_and_compose_is_not(self):
        self.put('k8s/web.yaml', WEB)
        self.put('docker-compose.yml', 'services:\n  web:\n    image: x\n')
        self.assertTrue(kubernetes.applies(self.root, 'k8s'))
        self.assertTrue(kubernetes.applies(self.root, 'k8s/web.yaml'))
        self.assertFalse(kubernetes.applies(self.root, 'docker-compose.yml'))
        self.assertFalse(kubernetes.applies(self.root, '../outside'))
        self.assertEqual(scan_repository(self.root, 'docker-compose.yml').get('platform'), None)

    def test_b_a_folder_without_workloads_is_an_error_not_an_empty_report(self):
        self.put('k8s/svc.yaml', 'apiVersion: v1\nkind: ConfigMap\nmetadata: {name: c}\n')
        with self.assertRaises(ValueError):
            self.scan()

    def test_c_env_files_and_proxy_bindings_do_not_apply(self):
        self.put('k8s/web.yaml', WEB)
        with self.assertRaises(ValueError):
            scan_repository(self.root, 'k8s', env_file='.env')


class ExposureTests(Manifests):
    def test_a_a_loadbalancer_service_makes_its_workload_reachable(self):
        self.put('k8s/web.yaml', WEB)
        report = self.scan()
        web = report['services'][0]
        self.assertEqual((web['id'], web['image'], web['networks']), ('shop/web', 'registry.example.com/shop/web:1.4', ['shop']))
        self.assertEqual([(p['published'], p['target'], p['scope'], p['via']) for p in web['ports']],
                         [('80', 8080, 'all_interfaces', 'LoadBalancer')])
        self.assertEqual(self.rules(report), {('RP-001', 'shop/web'), ('RP-006', 'shop/web')})
        self.assertEqual(report['platform'], 'kubernetes')

    def test_b_a_clusterip_service_does_not(self):
        self.put('k8s/worker.yaml', INTERNAL)
        report = self.scan()
        self.assertEqual(report['services'][0]['ports'], [])
        self.assertEqual(report['findings'], [], 'privileged but unreachable: RP-008 is about the combination')

    def test_c_an_ingress_makes_a_clusterip_service_reachable(self):
        self.put('k8s/worker.yaml', INTERNAL)
        self.put('k8s/ingress.yaml', INGRESS)
        report = self.scan()
        self.assertEqual(report['services'][0]['ports'][0]['via'], 'Ingress')
        self.assertEqual(self.rules(report), {('RP-001', 'shop/worker'), ('RP-008', 'shop/worker')})

    def test_d_host_ports_host_namespaces_and_the_runtime_socket(self):
        self.put('k8s/agent.yaml', AGENT)
        report = self.scan()
        self.assertEqual(self.rules(report), {('RP-001', 'agent'), ('RP-007', 'agent'), ('RP-008', 'agent')})
        levels = {f['rule_id']: f['level'] for f in report['findings']}
        self.assertEqual((levels['RP-007'], levels['RP-008']), ('error', 'error'))

    def test_e_a_selector_must_match_within_the_same_namespace(self):
        self.put('k8s/web.yaml', WEB.replace('selector: {app: web}', 'selector: {app: other}'))
        self.assertEqual(self.scan()['services'][0]['ports'], [])
        self.put('k8s/web.yaml', WEB.replace('metadata: {name: web, namespace: shop}', 'metadata: {name: web, namespace: other}'))
        self.assertEqual(self.scan()['services'][0]['ports'], [])


class DatastoreTests(Manifests):
    def test_a_a_database_beside_a_reachable_workload_with_no_policy(self):
        self.put('k8s/web.yaml', WEB)
        self.put('k8s/db.yaml', DATABASE)
        report = self.scan()
        self.assertIn(('RP-005', 'shop/db'), self.rules(report))
        finding = next(f for f in report['findings'] if f['rule_id'] == 'RP-005')
        self.assertIn('NetworkPolicy', finding['detail'])

    def test_b_a_network_policy_selecting_it_removes_the_finding(self):
        self.put('k8s/web.yaml', WEB)
        self.put('k8s/db.yaml', DATABASE)
        self.put('k8s/policy.yaml', POLICY)
        self.assertNotIn(('RP-005', 'shop/db'), self.rules(self.scan()))

    def test_c_a_policy_for_other_pods_or_another_namespace_does_not(self):
        self.put('k8s/web.yaml', WEB)
        self.put('k8s/db.yaml', DATABASE)
        self.put('k8s/policy.yaml', POLICY.replace('matchLabels: {app: db}', 'matchLabels: {app: cache}'))
        self.assertIn(('RP-005', 'shop/db'), self.rules(self.scan()))
        self.put('k8s/policy.yaml', POLICY.replace('namespace: shop', 'namespace: other'))
        self.assertIn(('RP-005', 'shop/db'), self.rules(self.scan()))

    def test_d_no_reachable_workload_no_finding(self):
        self.put('k8s/db.yaml', DATABASE)
        self.assertEqual(self.scan()['findings'], [])


class HonestyTests(Manifests):
    def test_a_a_helm_template_is_listed_as_unread_not_skipped_silently(self):
        self.put('k8s/web.yaml', WEB)
        self.put('k8s/templates/deploy.yaml', 'apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: {{ .Release.Name }}\n')
        report = self.scan()
        self.assertTrue(any('templates/deploy.yaml' in note and 'render' in note for note in report['unknowns']))
        self.assertEqual([f['path'] for f in report['files']], ['k8s/web.yaml'])

    def test_b_a_broken_file_does_not_stop_the_others(self):
        self.put('k8s/web.yaml', WEB)
        self.put('k8s/broken.yaml', 'apiVersion: v1\nkind: [unclosed\n')
        report = self.scan()
        self.assertEqual(len(report['services']), 1)
        self.assertTrue(any('broken.yaml' in note for note in report['unknowns']))

    def test_c_evidence_points_at_the_manifest_and_line(self):
        self.put('k8s/web.yaml', WEB)
        report = self.scan()
        workload = next(e for e in report['evidence'] if e['label'] == 'Workload')
        route = next(e for e in report['evidence'] if e['label'] == 'Tashqi kirish yo‘li')
        self.assertEqual((workload['path'], workload['line']), ('k8s/web.yaml', 1))
        self.assertEqual((route['path'], route['line']), ('k8s/web.yaml', 17))
        self.assertIn('klasterga so‘rov yuborilmadi', ' '.join(report['limits']))

    def test_d_the_report_has_the_keys_every_consumer_of_a_compose_report_reads(self):
        self.put('k8s/web.yaml', WEB)
        report = self.scan()
        compose = Path(tempfile.mkdtemp())
        self.addCleanup(__import__('shutil').rmtree, compose, True)
        (compose / 'c.yml').write_text('services:\n  web:\n    image: x\n    ports: ["80:80"]\n', encoding='utf-8')
        reference = scan_repository(compose, 'c.yml')
        self.assertEqual(set(reference) - set(report), set())
        self.assertEqual(set(reference['summary']) - set(report['summary']), set())
        self.assertEqual(set(reference['fix_plan']) - set(report['fix_plan']), set())
        self.assertEqual(set(reference['findings'][0]) - set(report['findings'][0]), set())
        self.assertTrue(repository.sarif(report)['runs'][0]['results'])
        self.assertEqual(repo_store.compare_reports(report, report)['added'], [])

    def test_e_the_same_manifests_give_the_same_identities(self):
        self.put('k8s/web.yaml', WEB)
        self.put('k8s/db.yaml', DATABASE)
        first, second = self.scan(), self.scan()
        self.assertEqual(sorted(f['fingerprint'] for f in first['findings']),
                         sorted(f['fingerprint'] for f in second['findings']))
        self.assertEqual(first['input_sha256'], second['input_sha256'])


class ChainTests(Manifests):
    """The reason this module exists."""

    def test_a_a_reachable_workload_chains_with_a_critical_cve_in_its_image(self):
        self.put('k8s/web.yaml', WEB)
        self.put('k8s/worker.yaml', INTERNAL)
        report = self.scan()
        image_report = {'state': 'completed', 'reference': 'registry.example.com/shop/web:1.4', 'kev': {'state': 'available'},
                        'findings': [{'package': 'libssl3', 'version': '3.0.1', 'advisory_id': 'CVE-2026-0001',
                                      'severity': 'CRITICAL', 'fixed_version': '3.0.9', 'known_exploited': True}]}
        targets = [{'id': 'shop-web', 'reference': 'registry.example.com/shop/web@sha256:' + 'a' * 64},
                   {'id': 'shop-worker', 'reference': 'example/worker:1'}]
        linked = portfolio.link_images({'images': ['shop-web', 'shop-worker']}, report['services'], targets=targets)
        self.assertEqual(linked['links']['shop-web']['service'], 'shop/web')
        result = chains.correlate_all({'repository': report}, links=linked['links'],
                                      image_reports={'shop-web': image_report, 'shop-worker': image_report})
        found = {(f['rule_id'], f['service_id']) for f in result['findings']}
        # web: reachable + exploited CVE (SX-002), and debug on with a fix available (SX-003).
        self.assertEqual(found, {('SX-002', 'shop/web'), ('SX-003', 'shop/web')})
        # worker runs the same vulnerable image but nothing reaches it: no chain.
        self.assertIn('CVE-2026-0001', pipeline.markdown({'id': 'x', 'state': 'completed', 'created_at': 't', 'limits': '',
                                                          'stages': [], 'chain_findings': result['findings']}))

    def test_b_registration_accepts_a_manifest_folder_in_the_compose_field(self):
        self.put('k8s/web.yaml', WEB)
        profiles = Path(tempfile.mkdtemp())
        self.addCleanup(__import__('shutil').rmtree, profiles, True)
        from unittest.mock import patch
        with patch.object(repo_store, 'LOCAL_PROFILES', profiles):
            registered = repo_store.register_project('shop', self.root, 'k8s')
        self.assertEqual(registered['services'], 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
