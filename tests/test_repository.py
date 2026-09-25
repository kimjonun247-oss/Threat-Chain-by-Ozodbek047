import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from zanjir.repository import parse_yaml, port_mapping, interpolate, dotenv, nginx_routes, scan_repository, sarif
from zanjir.repo_store import compare_reports, profile_for, read_reviews, save_review, save_report
from zanjir.engine import ROOT, canonical, digest


class ParserTests(unittest.TestCase):
    def test_commented_ports_are_not_published(self):
        value, _=parse_yaml('services:\n  app:\n    image: demo\n    # ports:\n    #   - "80:80"\n')
        self.assertNotIn('ports',value['services']['app'])

    def test_duplicate_keys_rejected(self):
        with self.assertRaises(ValueError):
            parse_yaml('services:\n  app: {}\n  app: {}\n')

    def test_aliases_and_executable_tags_rejected(self):
        for text in ['a: &a [1]\nb: *a','!!python/object/apply:os.system [echo]']:
            with self.subTest(text=text),self.assertRaises(Exception):
                parse_yaml(text)

    def test_deep_yaml_rejected_before_construction(self):
        with self.assertRaises(ValueError):
            parse_yaml('['*60+'0'+']'*60)

    def test_port_scopes_ipv4_ipv6_and_long_form(self):
        cases=[('127.0.0.1:80:8080','loopback'),('[::1]:80:8080','loopback'),('0.0.0.0:80:8080','all_interfaces'),
               ('80:8080','default_interfaces'),(8080,'default_interfaces'),({'host_ip':'127.0.0.1','published':80,'target':8080},'loopback')]
        for value,scope in cases:
            with self.subTest(value=value):
                self.assertEqual(port_mapping(value)['scope'],scope)

    def test_unsupported_port_range_not_guessed(self):
        with self.assertRaises(ValueError):
            port_mapping('8000-8005:8000-8005')

    def test_interpolation_uses_explicit_values_not_process_env(self):
        errors=[]
        self.assertEqual(interpolate('${IP:-127.0.0.1}:80:80',{},errors,'port'),'127.0.0.1:80:80')
        self.assertEqual(interpolate('${IP:-127.0.0.1}',{'IP':'0.0.0.0'},errors,'port'),'0.0.0.0')
        self.assertIn('UNRESOLVED_',interpolate('${UNKNOWN}',{},errors,'port'))
        self.assertTrue(errors)

    def test_dotenv_literal_and_duplicate_validation(self):
        self.assertEqual(dotenv('IP="127.0.0.1"\nTLS=true # note'),{'IP':'127.0.0.1','TLS':'true'})
        with self.assertRaises(ValueError):dotenv('IP=a\nIP=b')
        with self.assertRaises(ValueError):dotenv('VALUE=${OTHER}')

    def test_nested_nginx_directives_and_inheritance(self):
        routes,_=nginx_routes('server { listen 443 ssl; proxy_ssl_verify off; location /api/ { proxy_pass https://${TARGET}; } }',{'TARGET':'backend:8443'})
        self.assertEqual(routes[0]['verify'],'off')
        self.assertEqual(routes[0]['target'],'backend')
        self.assertEqual(routes[0]['target_port'],8443)
        self.assertEqual(routes[0]['location'],'/api/')

    def test_http_proxy_not_confused_with_https(self):
        routes,_=nginx_routes('server { location /api/ { proxy_ssl_verify off; proxy_pass http://backend:80; } }',{})
        self.assertEqual(routes[0]['scheme'],'http')

    def test_trust_headers_are_captured_case_insensitively(self):
        routes,_=nginx_routes('server { location /api/ { proxy_set_header X-User $remote_user; proxy_set_header Host $host; '
                              'proxy_pass http://backend:80; } }',{})
        self.assertEqual(routes[0]['trust_headers'],['X-User'])


class RepositoryTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory()
        self.root=Path(self.directory.name)
        self.compose='services:\n  proxy:\n    image: nginx\n    ports: ["127.0.0.1:8080:80"]\n    depends_on: [backend]\n  backend:\n    image: demo\n    ports: ["127.0.0.1:8443:443"]\n'
        (self.root/'compose.yml').write_text(self.compose)
        (self.root/'nginx.conf').write_text('server { listen 80; location /api/ { proxy_pass https://backend:443; proxy_ssl_verify off; } }')
        self.bindings=[{'service_id':'proxy','path':'nginx.conf'}]

    def tearDown(self):self.directory.cleanup()

    def scan(self):return scan_repository(self.root,'compose.yml',bindings=self.bindings)

    def test_config_correlation_without_runtime_claim(self):
        report=self.scan()
        self.assertEqual({f['rule_id'] for f in report['findings']},{'RP-002','RP-003'})
        self.assertEqual(report['summary']['runtime_confirmed'],0)
        self.assertTrue(all(not f['runtime_verified'] for f in report['findings']))

    def test_gateway_trust_header_forgeable_via_parallel_direct_path(self):
        # Individually plausible: the gateway correctly forwards caller identity,
        # and ops correctly exposed the backend port for debugging. Combined,
        # anyone can forge the trust header by skipping the gateway entirely.
        (self.root/'nginx.conf').write_text('server { listen 80; location /api/ { proxy_set_header X-User $remote_user; '
                                             'proxy_pass https://backend:443; proxy_ssl_verify on; } }')
        report=self.scan()
        self.assertIn('RP-004',{f['rule_id'] for f in report['findings']})
        rp004=next(f for f in report['findings'] if f['rule_id']=='RP-004')
        self.assertEqual(rp004['service_id'],'backend')
        self.assertFalse(rp004['runtime_verified'])
        self.assertEqual(rp004['cwe_ids'],['CWE-290'])
        self.assertEqual(rp004['owasp_top10_2025'][0]['code'],'A07')
        self.assertEqual(rp004['level'],'error')

    def test_no_trust_header_means_no_bypass_chain_finding(self):
        # RP-003 (parallel path) alone, with no forwarded identity header, is
        # not an authentication-bypass chain -- RP-004 must not fire for it.
        self.assertNotIn('RP-004',{f['rule_id'] for f in self.scan()['findings']})

    def test_flat_network_lets_exposed_service_reach_internal_datastore(self):
        # Individually plausible: publishing "web" to the host is normal, and
        # relying on Compose's implicit default network is normal too. Combined
        # with no network segmentation, a compromised "web" can reach "db"
        # directly over Docker's internal DNS -- no gateway or app auth in the way.
        (self.root/'compose.yml').write_text('services:\n  web:\n    image: myorg/web:latest\n    ports: ["0.0.0.0:8080:80"]\n  db:\n    image: postgres:14\n')
        report=scan_repository(self.root,'compose.yml')
        self.assertIn('RP-005',{f['rule_id'] for f in report['findings']})
        rp005=next(f for f in report['findings'] if f['rule_id']=='RP-005')
        self.assertEqual(rp005['service_id'],'db')
        self.assertFalse(rp005['runtime_verified'])
        self.assertEqual(rp005['cwe_ids'],['CWE-668'])
        self.assertEqual(rp005['owasp_top10_2025'][0]['code'],'A01')
        self.assertEqual(rp005['level'],'warning')

    def test_network_segmentation_prevents_flat_network_finding(self):
        (self.root/'compose.yml').write_text('services:\n  web:\n    image: myorg/web:latest\n    ports: ["0.0.0.0:8080:80"]\n    networks: [front]\n  db:\n    image: postgres:14\n    networks: [back]\n')
        report=scan_repository(self.root,'compose.yml')
        self.assertNotIn('RP-005',{f['rule_id'] for f in report['findings']})

    def test_unrecognized_internal_image_is_not_guessed_as_datastore(self):
        (self.root/'compose.yml').write_text('services:\n  web:\n    image: myorg/web:latest\n    ports: ["0.0.0.0:8080:80"]\n  worker:\n    image: myorg/worker:latest\n')
        report=scan_repository(self.root,'compose.yml')
        self.assertNotIn('RP-005',{f['rule_id'] for f in report['findings']})

    def test_loopback_only_exposure_does_not_trigger_flat_network_finding(self):
        # Matches the real crAPI sample: every host port is loopback-bound, so
        # there is no externally reachable entry point to pivot from.
        (self.root/'compose.yml').write_text('services:\n  web:\n    image: myorg/web:latest\n    ports: ["127.0.0.1:8080:80"]\n  db:\n    image: postgres:14\n')
        report=scan_repository(self.root,'compose.yml')
        self.assertNotIn('RP-005',{f['rule_id'] for f in report['findings']})

    def test_debug_env_var_on_exposed_port_is_flagged(self):
        # Individually plausible: DEBUG=true is normal for local development,
        # and publishing the port is a separate, ordinary ops decision. Combined,
        # the exposed port now serves whatever the debug mode turns on (verbose
        # errors, an interactive console, extra routes) to the outside world.
        (self.root/'compose.yml').write_text('services:\n  web:\n    image: myorg/web:latest\n    ports: ["0.0.0.0:8080:80"]\n    environment:\n      DEBUG: "true"\n')
        report=scan_repository(self.root,'compose.yml')
        self.assertIn('RP-006',{f['rule_id'] for f in report['findings']})
        rp006=next(f for f in report['findings'] if f['rule_id']=='RP-006')
        self.assertEqual(rp006['service_id'],'web')
        self.assertFalse(rp006['runtime_verified'])
        self.assertEqual(rp006['cwe_ids'],['CWE-489'])
        self.assertEqual(rp006['owasp_top10_2025'][0]['code'],'A02')

    def test_debug_env_var_on_loopback_only_port_is_not_flagged(self):
        (self.root/'compose.yml').write_text('services:\n  web:\n    image: myorg/web:latest\n    ports: ["127.0.0.1:8080:80"]\n    environment:\n      DEBUG: "true"\n')
        report=scan_repository(self.root,'compose.yml')
        self.assertNotIn('RP-006',{f['rule_id'] for f in report['findings']})

    def test_production_env_value_on_exposed_port_is_not_flagged(self):
        (self.root/'compose.yml').write_text('services:\n  web:\n    image: myorg/web:latest\n    ports: ["0.0.0.0:8080:80"]\n    environment:\n      NODE_ENV: "production"\n')
        report=scan_repository(self.root,'compose.yml')
        self.assertNotIn('RP-006',{f['rule_id'] for f in report['findings']})

    def test_docker_socket_mount_on_exposed_port_is_flagged(self):
        # Individually plausible: some tools (CI runners, monitoring UIs)
        # legitimately need the Docker socket, and publishing a port is a
        # separate ops choice. Combined, compromising the exposed service
        # hands the attacker daemon-equivalent control of the whole host.
        (self.root/'compose.yml').write_text('services:\n  web:\n    image: myorg/web:latest\n    ports: ["0.0.0.0:8080:80"]\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n')
        report=scan_repository(self.root,'compose.yml')
        self.assertIn('RP-007',{f['rule_id'] for f in report['findings']})
        rp007=next(f for f in report['findings'] if f['rule_id']=='RP-007')
        self.assertEqual(rp007['service_id'],'web')
        self.assertEqual(rp007['cwe_ids'],['CWE-269'])
        self.assertEqual(rp007['owasp_top10_2025'][0]['code'],'A06')
        self.assertEqual(rp007['level'],'error')

    def test_docker_socket_mount_on_loopback_only_port_is_not_flagged(self):
        (self.root/'compose.yml').write_text('services:\n  web:\n    image: myorg/web:latest\n    ports: ["127.0.0.1:8080:80"]\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n')
        report=scan_repository(self.root,'compose.yml')
        self.assertNotIn('RP-007',{f['rule_id'] for f in report['findings']})

    def test_unrelated_volume_mount_is_not_guessed_as_docker_socket(self):
        (self.root/'compose.yml').write_text('services:\n  web:\n    image: myorg/web:latest\n    ports: ["0.0.0.0:8080:80"]\n    volumes:\n      - ./data:/data\n')
        report=scan_repository(self.root,'compose.yml')
        self.assertNotIn('RP-007',{f['rule_id'] for f in report['findings']})

    def test_privileged_container_on_exposed_port_is_flagged(self):
        (self.root/'compose.yml').write_text('services:\n  web:\n    image: myorg/web:latest\n    ports: ["0.0.0.0:8080:80"]\n    privileged: true\n')
        report=scan_repository(self.root,'compose.yml')
        self.assertIn('RP-008',{f['rule_id'] for f in report['findings']})
        rp008=next(f for f in report['findings'] if f['rule_id']=='RP-008')
        self.assertEqual(rp008['service_id'],'web')
        self.assertEqual(rp008['cwe_ids'],['CWE-269'])
        self.assertEqual(rp008['owasp_top10_2025'][0]['code'],'A06')

    def test_dangerous_cap_add_on_exposed_port_is_flagged(self):
        (self.root/'compose.yml').write_text('services:\n  web:\n    image: myorg/web:latest\n    ports: ["0.0.0.0:8080:80"]\n    cap_add: ["SYS_ADMIN"]\n')
        report=scan_repository(self.root,'compose.yml')
        self.assertIn('RP-008',{f['rule_id'] for f in report['findings']})

    def test_routine_cap_add_is_not_flagged(self):
        (self.root/'compose.yml').write_text('services:\n  web:\n    image: myorg/web:latest\n    ports: ["0.0.0.0:8080:80"]\n    cap_add: ["NET_BIND_SERVICE"]\n')
        report=scan_repository(self.root,'compose.yml')
        self.assertNotIn('RP-008',{f['rule_id'] for f in report['findings']})

    def test_privileged_container_on_loopback_only_port_is_not_flagged(self):
        (self.root/'compose.yml').write_text('services:\n  web:\n    image: myorg/web:latest\n    ports: ["127.0.0.1:8080:80"]\n    privileged: true\n')
        report=scan_repository(self.root,'compose.yml')
        self.assertNotIn('RP-008',{f['rule_id'] for f in report['findings']})

    def test_fix_tls_removes_only_matching_static_finding(self):
        before=self.scan()
        (self.root/'nginx.conf').write_text('server { location /api/ { proxy_pass https://backend:443; proxy_ssl_verify on; } }')
        after=self.scan()
        diff=compare_reports(before,after)
        self.assertEqual(len(diff['absent']),1)
        self.assertEqual(len(diff['unchanged']),1)
        self.assertNotEqual(before['input_sha256'],after['input_sha256'])

    def test_depends_on_does_not_create_network_edge(self):
        report=scan_repository(self.root,'compose.yml')
        self.assertEqual(report['edges'],[])

    def test_disjoint_networks_do_not_prove_reachability(self):
        (self.root/'compose.yml').write_text('services:\n  proxy:\n    networks: [front]\n  backend:\n    networks: [back]\n')
        report=self.scan()
        self.assertEqual(report['edges'][0]['reachability'],'unknown')

    def test_repository_python_is_never_imported(self):
        (self.root/'setup.py').write_text("raise RuntimeError('must not execute')")
        (self.root/'app.py').write_text("raise RuntimeError('must not execute')")
        report=self.scan()
        self.assertEqual(len(report['files']),2)

    def test_path_escape_rejected(self):
        with self.assertRaises(ValueError):scan_repository(self.root,'../outside.yml')
        report=scan_repository(self.root,'compose.yml',bindings=[{'service_id':'proxy','path':'../outside.conf'}])
        self.assertTrue(report['unknowns'])

    def test_includes_not_silently_ignored(self):
        (self.root/'nginx.conf').write_text('include other.conf; server { location /api { proxy_pass https://backend; } }')
        self.assertTrue(self.scan()['unknowns'])

    def test_input_fingerprint_does_not_depend_on_clock(self):
        a,b=self.scan(),self.scan()
        self.assertEqual(a['input_sha256'],b['input_sha256'])
        self.assertEqual([f['fingerprint'] for f in a['findings']],[f['fingerprint'] for f in b['findings']])

    def test_sarif_contains_real_source_locations(self):
        report=self.scan()
        output=sarif(report)
        self.assertEqual(output['version'],'2.1.0')
        self.assertEqual(len(output['runs'][0]['results']),2)
        for result in output['runs'][0]['results']:
            location=result['locations'][0]['physicalLocation']
            self.assertGreaterEqual(location['region']['startLine'],1)
            self.assertTrue((self.root/location['artifactLocation']['uri']).exists())

    def test_review_requires_owner_reason_and_is_snapshot_scoped(self):
        report=self.scan()
        store=self.root/'reports'
        with patch('zanjir.repo_store.REPO_RUNS',store):
            save_report(report,output_dir=store)
            payload={'report_id':report['id'],'fingerprint':report['findings'][0]['fingerprint'],'status':'investigating','owner':'','note':''}
            with self.assertRaises(ValueError):save_review(payload)
            payload.update(owner='AX test',note='Dalillar tekshirilmoqda')
            save_review(payload)
            reviews=read_reviews()
            self.assertIn(report['input_sha256']+':'+payload['fingerprint'],reviews)
            payload['status']='resolved'
            with self.assertRaises(ValueError):save_review(payload)

    def test_different_profiles_cannot_be_compared(self):
        before=self.scan()
        after=copy.deepcopy(before)
        after['profile']['compose']='other.yml'
        with self.assertRaises(ValueError):compare_reports(before,after)


class PinnedSourceTest(unittest.TestCase):
    def test_real_crapi_source_snapshot(self):
        profile=profile_for('crapi')
        root=ROOT/profile['root']
        provenance=json.loads((root/'zanjir-provenance.json').read_text())
        report=scan_repository(root,profile['compose'],profile['env_file'],profile['bindings'],provenance)
        self.assertEqual(provenance['commit'],'700f03d12a392d9e408260b4beae72ed02a4a1a4')
        self.assertEqual(report['summary'],{'services':10,'published_ports':5,'loopback_ports':5,'proxy_routes':12,'findings':6,'runtime_confirmed':0})
        self.assertEqual(sum(f['rule_id']=='RP-002' for f in report['findings']),5)
        self.assertEqual(sum(f['rule_id']=='RP-003' for f in report['findings']),1)
        self.assertFalse(any(f['rule_id']=='RP-001' for f in report['findings']))
        self.assertEqual(report['unknowns'],[])
        for evidence in report['evidence']:
            if evidence['path']=='profile.json':continue
            self.assertLessEqual(evidence['line'],len((root/evidence['path']).read_text().splitlines()))


if __name__=='__main__':unittest.main(verbosity=2)
