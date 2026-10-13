"""Regressions found by reading the project as a large repository would hit it.

Each class is one confirmed defect: a false positive that turns a gate red on
ordinary configuration, a finding that was silently missed, or a limit that made
a big project produce nothing. See MUAMMOLAR.md, section G.
"""
import json
import tempfile
import unittest
from pathlib import Path

from zanjir import advisories, baseline, chains, ci_gate, findings, pathclass, pipeline, repository, scanners
from zanjir.engine import ROOT, skip_directory
from zanjir.repository import nginx_checks, nginx_routes, nginx_tree, parse_yaml, scan_repository


class OccurrenceIdentityTests(unittest.TestCase):
    """G1: equal fields used to mean one identity for several findings."""

    VALUES = {'rule_id': 'python.sqli', 'path': 'app/db.py', 'context': '    cursor.execute(query)'}

    def rows(self, lines):
        return [{'tool': 'semgrep', 'line': line, 'fingerprint': findings.fingerprint('semgrep', self.VALUES)}
                for line in lines]

    def separate(self, rows):
        findings.separate(rows, lambda r: r['tool'], lambda r: self.VALUES)
        return rows

    def test_a_first_occurrence_keeps_the_identity_it_always_had(self):
        rows = self.separate(self.rows([10, 40]))
        self.assertEqual(rows[0]['fingerprint'], findings.fingerprint('semgrep', self.VALUES))
        self.assertNotEqual(rows[0]['fingerprint'], rows[1]['fingerprint'])

    def test_b_a_single_finding_is_untouched(self):
        rows = self.rows([10])
        self.assertEqual(findings.separate(rows, lambda r: 'semgrep', lambda r: self.VALUES), 0)

    def test_c_identities_follow_file_order_not_scanner_order(self):
        forward = self.separate(self.rows([10, 40, 90]))
        backward = self.separate(self.rows([90, 40, 10]))
        self.assertEqual({r['line']: r['fingerprint'] for r in forward},
                         {r['line']: r['fingerprint'] for r in backward})

    def test_d_a_second_identical_sink_is_new_to_the_baseline(self):
        before = {'state': 'completed', 'findings': self.separate(self.rows([10]))}
        after = {'state': 'completed', 'findings': self.separate(self.rows([10, 40]))}
        self.assertEqual(baseline.diff(before, after)['counts'], {'new': 1, 'gone': 0, 'unchanged': 1})

    def test_e_the_code_scanner_applies_it(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp).resolve()
            (source / 'a.py').write_text('x = 1\nos.system(cmd)\ny = 2\nos.system(cmd)\n', encoding='utf-8')
            data = {'results': [{'check_id': 'r.cmd', 'path': 'a.py', 'start': {'line': line}, 'extra': {}}
                                for line in (2, 4)]}
            rows = scanners.normalize('semgrep', data, source)
        self.assertEqual(len({r['fingerprint'] for r in rows}), 2)
        self.assertNotIn('_identity', rows[0])


class NginxPrecisionTests(unittest.TestCase):
    """G2, G3: ordinary reverse-proxy lines reported at `error` level."""

    def rules(self, text):
        return [(i['rule'], i['value']) for i in nginx_checks(nginx_tree(text, {}))]

    def test_a_forwarding_the_request_path_to_a_fixed_host_is_not_ssrf(self):
        for value in ('http://backend:8080$request_uri', 'http://app/$uri$is_args$args', 'http://api$uri?$args'):
            with self.subTest(value=value):
                self.assertEqual(self.rules('server { location / { proxy_pass %s; } }' % value), [])

    def test_b_a_client_chosen_upstream_host_still_is(self):
        for value in ('http://$http_x_upstream/v1', 'http://$arg_target', '$http_x_target', 'https://$host:8443/x'):
            with self.subTest(value=value):
                self.assertEqual(self.rules('server { location /fetch { proxy_pass %s; } }' % value),
                                 [('RP-010', value)])

    def headers(self, line):
        routes, _ = nginx_routes('server { location / { %s proxy_pass http://api:80; } }' % line, {})
        return routes[0]['trust_headers']

    def test_c_relaying_or_clearing_a_header_asserts_no_identity(self):
        self.assertEqual(self.headers('proxy_set_header Authorization $http_authorization;'), [])
        self.assertEqual(self.headers('proxy_set_header X-User "";'), [])

    def test_d_a_value_the_gateway_computes_does(self):
        self.assertEqual(self.headers('proxy_set_header X-User $remote_user;'), ['X-User'])
        self.assertEqual(self.headers('proxy_set_header X-Role admin;'), ['X-Role'])
        # A header relayed under another name is the gateway vouching for it.
        self.assertEqual(self.headers('proxy_set_header X-User $http_x_forwarded_user;'), ['X-User'])


class DatastoreImageTests(unittest.TestCase):
    """G4: RP-005 matched a data store name anywhere in the image string."""

    def test_a_data_stores_are_recognised_however_they_are_published(self):
        for image in ('postgres:16', 'bitnami/postgresql:15', 'mongo', 'redis:7-alpine',
                      'docker.io/library/mysql:8', 'registry.example.com:5000/team/redis@sha256:' + 'a' * 64,
                      'confluentinc/cp-kafka:7.5.0', 'mcr.microsoft.com/mssql/server:2022-latest',
                      'docker.elastic.co/elasticsearch/elasticsearch:8.12.0', 'amazon/dynamodb-local'):
            with self.subTest(image=image):
                self.assertTrue(repository.DATASTORE_IMAGE.search(image))

    def test_b_companions_and_lookalikes_are_not(self):
        for image in ('prom/postgres-exporter', 'mongo-express', 'provectuslabs/kafka-ui', 'redis/redisinsight',
                      'chromatic/web', 'mycorp/netcdf-tools', 'dpage/pgadmin4', 'oliver006/redis_exporter',
                      'myorg/worker:latest', ''):
            with self.subTest(image=image):
                self.assertFalse(repository.DATASTORE_IMAGE.search(image))

    def compose(self, root, extra=''):
        (root / 'compose.yml').write_text(
            'services:\n  web:\n    image: myorg/web\n    ports: ["8080:80"]\n'
            + extra + '  db:\n    image: postgres:16\n', encoding='utf-8')
        report = scan_repository(root, 'compose.yml')
        return next(f for f in report['findings'] if f['rule_id'] == 'RP-005')

    def test_c_exposing_one_more_service_does_not_rename_the_finding(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            before = self.compose(root)
            after = self.compose(root, '  admin:\n    image: myorg/admin\n    ports: ["9090:90"]\n')
        self.assertEqual(before['fingerprint'], after['fingerprint'])
        self.assertIn('admin', after['detail'])


class ComposeAnchorTests(unittest.TestCase):
    """G5: a Compose file using anchors was refused outright."""

    TEXT = ('x-defaults: &defaults\n  restart: always\n  ports: ["8080:80"]\n  environment:\n    DEBUG: "true"\n'
            'services:\n  web:\n    <<: *defaults\n    image: myorg/web\n'
            '  internal:\n    <<: *defaults\n    image: myorg/internal\n    ports: ["127.0.0.1:9000:90"]\n')

    def test_a_merged_keys_are_read_and_own_keys_win(self):
        document, _ = parse_yaml(self.TEXT)
        self.assertEqual(document['services']['web']['ports'], ['8080:80'])
        self.assertEqual(document['services']['internal']['ports'], ['127.0.0.1:9000:90'])
        self.assertNotIn('<<', document['services']['web'])

    def test_b_the_rules_see_what_the_anchor_contributed(self):
        with tempfile.TemporaryDirectory() as temp:
            (Path(temp) / 'compose.yml').write_text(self.TEXT, encoding='utf-8')
            report = scan_repository(Path(temp), 'compose.yml')
        by_rule = {(f['rule_id'], f['service_id']) for f in report['findings']}
        self.assertIn(('RP-001', 'web'), by_rule)
        self.assertIn(('RP-006', 'web'), by_rule)
        self.assertNotIn(('RP-001', 'internal'), by_rule)

    def test_c_a_key_written_twice_is_still_an_error(self):
        with self.assertRaises(ValueError):
            parse_yaml('a: &a {x: 1}\nb:\n  <<: *a\n  y: 1\n  y: 2\n')

    def test_d_a_self_referencing_anchor_is_refused_not_followed(self):
        with self.assertRaises(ValueError):
            parse_yaml('a: &a\n  b: *a\n')

    def test_e_an_alias_bomb_stops_at_the_node_limit(self):
        levels = ['a0: &a0 [x, x, x, x, x, x, x, x, x, x]']
        levels += [f'a{n}: &a{n} [{", ".join(["*a%d" % (n - 1)] * 10)}]' for n in range(1, 8)]
        with self.assertRaises(ValueError):
            parse_yaml('\n'.join(levels) + '\n')


def exposed(sid, context):
    return {'id': sid, 'build_context': context, 'ports': [{'scope': 'all_interfaces', 'published': '80', 'target': 80}]}


def secret(path, mark='f'):
    return {'tool': 'gitleaks', 'rule_id': 'aws-access-token', 'path': path, 'line': 3, 'fingerprint': mark * 24}


class ChainScopeTests(unittest.TestCase):
    """G6, G7: `build: .` never chained; a test fixture always did."""

    def test_a_the_repository_root_as_build_context_matches_its_files(self):
        rows = chains.correlate({'findings': [secret('src/config.py')]}, {'services': [exposed('web', '.')]})
        self.assertEqual([(r['service_id'], r['evidence']['gitleaks_path']) for r in rows], [('web', 'src/config.py')])

    def test_b_a_subdirectory_context_is_still_a_boundary(self):
        self.assertTrue(chains.inside('api/app.py', 'api'))
        self.assertTrue(chains.inside('api', 'api'))
        self.assertFalse(chains.inside('api-admin/app.py', 'api'))
        self.assertFalse(chains.inside('', '.'))

    def test_c_a_secret_in_a_fixture_builds_no_chain_and_is_reported_as_a_gap(self):
        code = {'findings': [secret('api/tests/fixtures/fake.py', 'e'), secret('api/settings.py')]}
        repo = {'services': [exposed('api', 'api')], 'findings': []}
        result = chains.correlate_all({'code': code, 'repository': repo})
        self.assertEqual([r['evidence']['gitleaks_path'] for r in result['findings']], ['api/settings.py'])
        gap = next(g for g in result['gaps'] if g['kind'] == 'outside_shipped_code')
        self.assertEqual(gap['count'], 1)

    def test_d_the_scanner_recorded_class_is_what_decides(self):
        row = {**secret('api/settings.py'), 'path_class': 'test'}
        self.assertEqual(chains.correlate({'findings': [row]}, {'services': [exposed('api', 'api')]}), [])


class PathClassTests(unittest.TestCase):
    def test_a_known_layouts(self):
        cases = {'app/settings.py': 'prod', 'tests/fixtures/key.py': 'test', 'src/test/java/A.java': 'test',
                 'src/main/java/UserTest.java': 'test', 'api/handler_test.go': 'test', 'web/a.spec.ts': 'test',
                 'web/static/app.min.js': 'generated', 'proto/user_pb2.py': 'generated', 'docs/setup.py': 'docs',
                 'README.md': 'docs', '.env.example': 'example', 'examples/demo.py': 'example',
                 'vendor/lib/x.go': 'vendored', 'third_party/zlib/z.c': 'vendored'}
        for path, expected in cases.items():
            with self.subTest(path=path):
                self.assertEqual(pathclass.classify(path), expected)

    def test_b_ordinary_names_are_not_mistaken(self):
        # Lower-casing the name made `Latest.java` end in "test.java".
        for path in ('src/main/java/Latest.java', 'build/tool.py', 'internal/target/run.go', 'app/contest.py',
                     'src/manifest.ts', '', None):
            with self.subTest(path=path):
                self.assertEqual(pathclass.classify(path), 'prod')

    def test_c_the_code_scanner_records_it(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp).resolve()
            (source / 'tests').mkdir()
            (source / 'tests' / 'test_a.py').write_text('eval(x)\n', encoding='utf-8')
            data = {'results': [{'check_id': 'r.eval', 'path': 'tests/test_a.py', 'start': {'line': 1}, 'extra': {}}]}
            self.assertEqual(scanners.normalize('semgrep', data, source)[0]['path_class'], 'test')


class MarkdownChainTests(unittest.TestCase):
    """G8: the assessment export raised KeyError for every chain but SX-001."""

    def report(self, chain):
        return {'id': '20260101T000000-aaaaaaaa', 'state': 'completed', 'created_at': 't', 'limits': '',
                'stages': [], 'chain_findings': chain}

    def test_every_chain_rule_exports(self):
        code = {'findings': [secret('api/settings.py'),
                             {'tool': 'semgrep', 'rule_id': 'sqli', 'path': 'api/db.py', 'line': 9, 'severity': 'ERROR',
                              'cwe_ids': ['CWE-89'], 'fingerprint': 'a' * 24}]}
        repo = {'services': [exposed('api', 'api')], 'findings': [{'rule_id': 'RP-007', 'service_id': 'api'}]}
        image = {'state': 'completed', 'reference': 'x', 'kev': {'state': 'available'}, 'os': {'EOSL': True, 'Name': '3.10'},
                 'findings': [{'package': 'libssl3', 'version': '1', 'advisory_id': 'CVE-2026-1', 'severity': 'CRITICAL',
                               'fixed_version': '2'}]}
        result = chains.correlate_all({'code': code, 'repository': repo}, links={'img': {'service': 'api', 'how': 'name'}},
                                      image_reports={'img': image})
        rules = {f['rule_id'] for f in result['findings']}
        self.assertTrue({'SX-001', 'SX-002', 'SX-004', 'SX-005', 'SX-007'} <= rules, rules)
        text = pipeline.markdown(self.report(result['findings']))
        for rule in rules:
            self.assertIn(rule, text)
        self.assertIn('CVE-2026-1', text)


class DirectorySkipTests(unittest.TestCase):
    """G9: a user's own `profiles/` or `runs/` directory was never scanned."""

    def test_a_application_folders_are_skipped_only_in_the_application(self):
        self.assertTrue(skip_directory(ROOT, 'profiles'))
        self.assertTrue(skip_directory(str(ROOT), 'scanner-runs'))
        self.assertFalse(skip_directory(ROOT / 'web', 'profiles'))

    def test_b_generic_folders_are_skipped_everywhere(self):
        for name in ('.git', 'node_modules', 'vendor', '__pycache__'):
            self.assertTrue(skip_directory('/somewhere/else', name))

    def test_c_a_project_directory_with_such_a_name_is_scanned(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp).resolve() / 'src'
            for name in ('profiles', 'runs', 'pilot', 'app', 'node_modules'):
                (source / name).mkdir(parents=True)
                (source / name / 'views.py').write_text('x = 1\n', encoding='utf-8')
            coverage = scanners.snapshot(source, Path(temp).resolve() / 'out')
        self.assertEqual(sorted(e['path'] for e in coverage['manifest']),
                         ['app/views.py', 'pilot/views.py', 'profiles/views.py', 'runs/views.py'])
        self.assertEqual(coverage['skipped']['excluded'], 1)


class SameToolDuplicateTests(unittest.TestCase):
    """G10: a local rule and a registry rule for one weakness counted twice."""

    def row(self, mark, rule, cwe):
        return {'tool': 'semgrep', 'rule_id': rule, 'path': 'a.py', 'line': 4, 'fingerprint': mark * 24, 'cwe_ids': cwe}

    def test_a_two_rules_for_one_weakness_are_linked(self):
        rows = [self.row('a', 'zanjir.python.eval', ['CWE-95']), self.row('b', 'python.lang.eval-detected', ['CWE-95'])]
        self.assertEqual(baseline.link_duplicates(rows), 1)
        # The primary is the first rule id in order, on every run.
        self.assertEqual(rows[0]['duplicate_of'], 'b' * 24)
        self.assertNotIn('duplicate_of', rows[1])

    def test_b_two_rules_for_different_weaknesses_stay_apart(self):
        rows = [self.row('a', 'r.eval', ['CWE-95']), self.row('b', 'r.sqli', ['CWE-89'])]
        self.assertEqual(baseline.link_duplicates(rows), 0)


def assessment(code_findings):
    return {'id': '20260101T000000-aaaaaaaa', 'state': 'completed', 'selection': {},
            'stages': [{'kind': 'code', 'target': 'demo', 'state': 'completed',
                        'report': {'state': 'completed', 'findings': code_findings}}]}


class ProdOnlyGateTests(unittest.TestCase):
    """G11: opt-in, so the default gate counts exactly what it counted."""

    ROWS = [{**secret('app/settings.py', 'a')}, {**secret('tests/fixtures/key.py', 'b')},
            {**secret('docs/setup.md', 'c'), 'path_class': 'docs'}]

    def test_a_default_is_unchanged(self):
        result = ci_gate.evaluate(assessment(self.ROWS))
        self.assertEqual(result['count'], 3)
        self.assertNotIn('outside_shipped_code', result)

    def test_b_prod_only_counts_shipped_code_and_says_what_it_left_out(self):
        result = ci_gate.evaluate(assessment(self.ROWS), prod_only=True)
        self.assertEqual(result['count'], 1)
        self.assertEqual(result['outside_shipped_code'], 2)
        self.assertEqual(result['total'], 3)
        self.assertEqual(result['hits'][0]['subject'], 'app/settings.py')


class CvssSeverityTests(unittest.TestCase):
    """G12: an advisory with only a CVSS vector stayed UNKNOWN, outside every gate."""

    def test_a_base_scores_match_the_published_calculator(self):
        cases = {'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H': 9.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H': 10.0,
                 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N': 6.1, 'CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N': 1.8,
                 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H': 8.8, 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N': 5.9}
        for vector, score in cases.items():
            with self.subTest(vector=vector):
                self.assertEqual(advisories.cvss3_base(vector), score)

    def test_b_what_is_not_a_v3_vector_gives_nothing(self):
        for vector in ('CVSS:4.0/AV:N/AC:L', 'junk', '', None, 'CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'):
            self.assertIsNone(advisories.cvss3_base(vector))

    def record(self, **extra):
        return {'id': 'GO-2026-0001', 'aliases': ['CVE-2026-0001'], 'summary': 's',
                'affected': [{'package': {'ecosystem': 'Go', 'name': 'example.com/mod'}, 'ranges': []}], **extra}

    def normalize(self, record):
        package = {'ecosystem': 'Go', 'name': 'example.com/mod', 'version': '1.0.0', 'manifest': 'go.mod'}
        key = ('Go', 'example.com/mod', '1.0.0')
        return advisories.normalize([package], {key: [record['id']]}, {record['id']: record}, {}, True)[0]

    def test_c_a_vector_only_advisory_gets_its_severity(self):
        vector = [{'type': 'CVSS_V3', 'score': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}]
        finding = self.normalize(self.record(severity=vector))
        self.assertEqual((finding['severity'], finding['priority']), ('CRITICAL', 'P1'))

    def test_d_the_database_word_still_wins_and_nothing_is_invented(self):
        vector = [{'type': 'CVSS_V3', 'score': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}]
        self.assertEqual(self.normalize(self.record(severity=vector, database_specific={'severity': 'LOW'}))['severity'], 'LOW')
        self.assertEqual(self.normalize(self.record())['severity'], 'UNKNOWN')


class TimeBudgetTests(unittest.TestCase):
    """G13: limits written for 50 MB applied unchanged to ten times that."""

    def test_a_a_project_inside_the_original_budget_runs_as_before(self):
        self.assertEqual(scanners.scan_scale(0), 1)
        self.assertEqual(scanners.scan_scale(scanners.BASE_BYTES), 1)
        command = scanners.tool_commands(Path('unused'))
        self.assertEqual(command['semgrep'][command['semgrep'].index('--jobs') + 1], '2')
        self.assertEqual(command['gitleaks'][-1], '180')

    def test_b_a_larger_snapshot_gets_proportionally_more(self):
        self.assertEqual(scanners.scan_scale(scanners.BASE_BYTES + 1), 2)
        self.assertEqual(scanners.scan_scale(scanners.MAX_TOTAL), 10)
        self.assertEqual(scanners.scan_scale(10 ** 12), scanners.MAX_SCALE)
        self.assertEqual(scanners.tool_commands(Path('unused'), scale=10)['gitleaks'][-1], '1800')


if __name__ == '__main__':
    unittest.main(verbosity=2)
