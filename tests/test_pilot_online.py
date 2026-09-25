import http.client
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from app import Handler
from zanjir import advisories, dependencies, inventory, images, repo_store
from zanjir.httptest import listener
from isolation import isolate_triage


class ImageTests(unittest.TestCase):
    def setUp(self):
        isolate_triage(self)

    def test_urls_and_shell_text_are_rejected(self):
        """What a reference may never be.

        Tags and non-Docker-Hub registries were rejected here until B6; both are
        now accepted on purpose, because an image that cannot be named cannot be
        scanned. What stays rejected is anything that is not a reference at all:
        a URL, shell punctuation, or a value that would reach Trivy as a flag.
        """
        for ref in ('https://example.org/image', 'alpine;whoami', '-x@sha256:' + 'a' * 64,
                    'alpine@sha256:qisqa', 'alpine:TEG!', 'a b', ''):
            with self.assertRaises(ValueError, msg=ref):
                images.command(ref, Path('work'))
        command = images.command('alpine@sha256:' + 'a' * 64, Path('work'))
        self.assertIn('remote', command)
        self.assertNotIn('--insecure', command)
        self.assertEqual(command[command.index('--scanners') + 1], 'vuln')

    def test_a_tag_and_a_private_registry_are_accepted_and_normalised(self):
        """B6: both are allowed, and the canonical form is what reaches Trivy."""
        self.assertEqual(images.command('alpine:3.20', Path('work'))[-1], 'docker.io/library/alpine:3.20')
        self.assertEqual(images.command('registry.example.com:5000/team/app:1.0', Path('work'))[-1],
                         'registry.example.com:5000/team/app:1.0')
        self.assertEqual(images.command('alpine', Path('work'))[-1], 'docker.io/library/alpine:latest')

    def test_normalization_redacts_image_config_and_preserves_distinct_packages(self):
        data={'ArtifactType':'container_image','Metadata':{'ImageConfig':{'Env':['SECRET=do-not-export']},'OS':{'Family':'alpine'}},
              'Results':[{'Target':'image','Class':'os-pkgs','Type':'alpine','Packages':[{'Name':'a'},{'Name':'b'}],
                          'Vulnerabilities':[{'PkgName':'a','InstalledVersion':'1.0','VulnerabilityID':'CVE-2025-11111','Severity':'HIGH'},
                                             {'PkgName':'b','InstalledVersion':'1.0','VulnerabilityID':'CVE-2025-11111','Severity':'HIGH'}]}]}
        report=images.normalize(data)
        self.assertEqual(report['count'],2)
        self.assertEqual(report['coverage'][0]['packages'],2)
        self.assertNotIn('SECRET',json.dumps(report))
        self.assertTrue(all(f['state']=='image_advisory_match' for f in report['findings']))

    def test_missing_result_is_not_a_clean_scan(self):
        for data in ({},{'ArtifactType':'filesystem','Results':[]},{'ArtifactType':'container_image','Results':None}):
            with self.assertRaises(ValueError): images.normalize(data)

    def test_missing_binary_fails_and_releases_job_lock(self):
        with tempfile.TemporaryDirectory() as temp:
            base=Path(temp)
            with patch.object(images,'RUNS',base/'runs'),patch.object(images,'BINARY',base/'not-installed/trivy.exe'),patch.object(images,'targets',return_value=[{'id':'demo','reference':'alpine@sha256:'+'a'*64}]):
                report=images.start('demo',background=False)
                self.assertEqual(report['state'],'failed')
                self.assertFalse(images.LOCK.locked())
                self.assertFalse((base/'runs'/report['id']/'raw.json').exists())

    def test_public_profile_registration_is_exclusive(self):
        with tempfile.TemporaryDirectory() as temp,patch.object(images,'PROFILES',Path(temp)):
            images.register('example','alpine@sha256:'+'a'*64)
            with self.assertRaises(FileExistsError): images.register('example','alpine@sha256:'+'a'*64)
            with self.assertRaises(ValueError): images.register('pilot-abc','alpine@sha256:'+'a'*64)


class OnlineReliabilityTests(unittest.TestCase):
    def setUp(self):
        isolate_triage(self)

    def test_alias_is_not_invented_as_a_direct_matched_record(self):
        package=inventory.package('npm','lodash','4.17.21','package-lock.json','node_modules/lodash')
        key=('npm','lodash','4.17.21')
        record={'id':'GHSA-new-1111-2222','aliases':['CVE-2021-23337','CVE-2026-4800','GHSA-old-1111-2222'],'affected':[]}
        row=advisories.normalize([package],{key:[record['id']]},{record['id']:record},{},True)[0]
        self.assertEqual(row['matched_advisory_ids'],[record['id']])
        self.assertEqual(row['advisory_id'],record['id'])
        self.assertNotIn('GHSA-old-1111-2222',row['matched_advisory_ids'])

    def test_python_continuation_keeps_original_line_evidence(self):
        text='one==1.0 \\\n --hash=sha256:'+'a'*64+'\ntwo==2.0\n'
        rows,gaps=inventory.parse_requirements(text,'requirements.txt')
        self.assertFalse(gaps)
        self.assertEqual([r['locator'] for r in rows],['line:1','line:3'])

    def test_unresolved_npm_tag_is_not_sent_as_exact_version(self):
        rows,gaps=inventory.parse_npm(json.dumps({'lockfileVersion':3,'packages':{'node_modules/a':{'version':'latest'}}}),'package-lock.json')
        self.assertFalse(rows);self.assertTrue(gaps)

    def test_history_orders_subsecond_scans_by_actual_timestamp(self):
        with tempfile.TemporaryDirectory() as temp,patch.object(dependencies,'RUNS',Path(temp)):
            for rid,stamp in [('20260101T000000-ffffffff','.100'),('20260101T000000-00000000','.200')]:
                repo_store.write_json(Path(temp)/rid/'report.json',{'id':rid,'target':'demo','created_at':'2026-01-01T00:00:00'+stamp,'state':'completed'})
            self.assertEqual(dependencies.history()[0]['id'],'20260101T000000-00000000')

    def test_read_failure_does_not_leave_dependency_job_locked(self):
        rid='20260101T000000-12345678'
        dependencies.LOCK.acquire()
        with patch.object(dependencies,'read',side_effect=ValueError('missing')):
            self.assertIsNone(dependencies.execute(rid))
        self.assertFalse(dependencies.LOCK.locked())

    def test_api_rejects_image_urls_without_explicit_registered_target_and_online(self):
        with listener(Handler) as url:
            connection=http.client.HTTPConnection('127.0.0.1',int(url.rsplit(':',1)[1]),timeout=5)
            with patch.object(images,'start') as start:
                for payload in ({'target':'demo'},{'target':'demo','online':False},{'target':'demo','online':1},{'target':'demo','online':True,'url':'http://x'}):
                    connection.request('POST','/api/images/scan',json.dumps(payload),{'Content-Type':'application/json'})
                    response=connection.getresponse();response.read();self.assertEqual(response.status,400)
                start.assert_not_called()
            connection.request('GET','/api/readiness')
            response=connection.getresponse();data=json.loads(response.read())
            self.assertEqual(response.status,200);self.assertEqual(data['mode'],'online_evidence_based_pilot')
            self.assertIn("frame-ancestors 'none'",response.getheader('Content-Security-Policy'))
            connection.close()


if __name__=='__main__':unittest.main()
