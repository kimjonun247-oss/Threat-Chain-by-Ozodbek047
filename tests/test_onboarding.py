"""Registration boundaries and isolation between projects with identical source."""
import contextlib
import http.client
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from app import Handler, main
from zanjir import repo_store as store
from zanjir.httptest import listener
from isolation import isolate_triage


class OnboardingTests(unittest.TestCase):
    def setUp(self):
        isolate_triage(self)
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)/'source'
        self.root.mkdir()
        (self.root/'compose.yml').write_text('services:\n  web:\n    image: nginx\n    ports: ["8080:80"]\n')
        (self.root/'setup.py').write_text("raise RuntimeError('repository must never execute')")
        self.profiles=Path(self.temp.name)/'profiles'
        self.reports=Path(self.temp.name)/'reports'
        for key,value in [('LOCAL_PROFILES',self.profiles),('REPO_RUNS',self.reports)]:
            patcher=patch.object(store,key,value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def register(self,pid='pilot-one',**kwargs):
        return store.register_project(pid,self.root,'compose.yml',**kwargs)

    def test_registration_and_scan_preserve_source(self):
        before={p.name:p.read_bytes() for p in self.root.iterdir()}
        result=self.register(name='Test project',owner='AX')
        report=store.scan_profile(result['id'])
        self.assertEqual(report['profile_id'],'pilot-one')
        self.assertEqual(report['summary']['runtime_confirmed'],0)
        self.assertEqual({p.name:p.read_bytes() for p in self.root.iterdir()},before)
        self.assertEqual(store.get_report(report['id']),report)

    def test_listing_contains_no_absolute_source_root(self):
        self.register()
        listed=store.list_profiles()
        # Bundled samples come from ALLOWED_PROFILES rather than a hardcoded set,
        # so adding one does not break a test that is really about path leakage.
        self.assertEqual({p['id'] for p in listed}, set(store.ALLOWED_PROFILES) | {'pilot-one'})
        self.assertNotIn(str(self.root),json.dumps(listed))
        self.assertTrue(all('root' not in p and 'registered_root' not in p for p in listed))

    def test_reserved_duplicate_and_traversal_ids_rejected(self):
        self.register()
        saved=(self.profiles/'pilot-one.json').read_bytes()
        for pid in ['crapi','pilot-one','../escape','UPPER','x']:
            with self.subTest(pid=pid),self.assertRaises(ValueError):self.register(pid)
        self.assertEqual((self.profiles/'pilot-one.json').read_bytes(),saved)

    def test_missing_root_and_source_escape_rejected(self):
        with self.assertRaises(ValueError):
            store.register_project('missing',self.root/'missing','compose.yml')
        for compose in ['../compose.yml',str(self.root/'compose.yml')]:
            with self.subTest(compose=compose),self.assertRaises(ValueError):
                store.register_project('outside',self.root,compose)
        with self.assertRaises(ValueError):self.register(bindings=[{'path':'../proxy.conf'}])
        self.assertFalse(self.profiles.exists())

    def test_invalid_mapping_and_credential_override_rejected(self):
        (self.root/'proxy.conf').write_text('server {}')
        for bindings in [{},'invalid',[{'service_id':'web','path':'proxy.conf','template_variables':{'TOKEN':'demo'}}]]:
            with self.subTest(bindings=bindings),self.assertRaises(ValueError):self.register(bindings=bindings)
        self.assertFalse(self.profiles.exists())

    def test_mutated_registration_root_rejected(self):
        self.register()
        path=self.profiles/'pilot-one.json'
        profile=json.loads(path.read_text())
        profile['root']=str(self.root.parent)
        path.write_text(json.dumps(profile))
        with self.assertRaises(ValueError):store.scan_profile('pilot-one')

    def test_project_filters_and_review_isolation(self):
        self.register('pilot-one')
        self.register('pilot-two')
        first=store.scan_profile('pilot-one')
        second=store.scan_profile('pilot-two')
        self.assertNotEqual(first['input_sha256'],second['input_sha256'])
        fingerprint=first['findings'][0]['fingerprint']
        self.assertEqual(fingerprint,second['findings'][0]['fingerprint'])
        store.save_review({'report_id':first['id'],'fingerprint':fingerprint,'status':'investigating','owner':'AX','note':'Review first project only'})
        self.assertNotIn(second['input_sha256']+':'+fingerprint,store.read_reviews())
        self.assertEqual([r['id'] for r in store.list_reports('pilot-one')],[first['id']])
        self.assertEqual([r['id'] for r in store.list_reports('pilot-two')],[second['id']])
        with self.assertRaises(ValueError):store.compare_reports(first,second)

    def test_cli_registers_source_for_followup_scan(self):
        args=['app.py','--register-project','cli-pilot','--repo',str(self.root),'--compose','compose.yml','--name','CLI Pilot']
        with patch('sys.argv',args),contextlib.redirect_stdout(io.StringIO()) as stdout:
            main()
        self.assertEqual(json.loads(stdout.getvalue())['id'],'cli-pilot')
        self.assertEqual(store.scan_profile('cli-pilot')['summary']['services'],1)

    def test_browser_lists_profiles_but_cannot_register_paths(self):
        self.register()
        with listener(Handler) as url:
            port=int(url.rsplit(':',1)[1])
            def request(method,path,payload=None):
                connection=http.client.HTTPConnection('127.0.0.1',port,timeout=10)
                try:
                    connection.request(method,path,body=json.dumps(payload) if payload is not None else None,headers={'Content-Type':'application/json'})
                    response=connection.getresponse()
                    return response.status,json.loads(response.read())
                finally:connection.close()
            status,profiles=request('GET','/api/repository/profiles')
            self.assertEqual(status,200)
            self.assertIn('pilot-one',{p['id'] for p in profiles})
            self.assertEqual(request('POST','/api/repository/register',{'root':str(self.root)})[0],404)
            self.assertEqual(request('POST','/api/repository/scan',{'profile_id':'unknown-project'})[0],400)
            self.assertEqual(request('POST','/api/repository/scan',{'profile_id':'pilot-one','root':str(self.root)})[0],400)
            status,report=request('POST','/api/repository/scan',{'profile_id':'pilot-one'})
            self.assertEqual(status,200)
            status,listed=request('GET','/api/repository/reports?profile_id=pilot-one')
            self.assertEqual(status,200)
            self.assertEqual([r['id'] for r in listed],[report['id']])
            self.assertEqual(request('GET','/api/repository/reports?profile_id=unknown-project')[0],400)


if __name__=='__main__':unittest.main(verbosity=2)
