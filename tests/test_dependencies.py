import http.client
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from app import Handler
from zanjir import inventory as inv, advisories as adv, dependencies as dep, code_targets, scanners
from zanjir.httptest import listener
from isolation import isolate_triage

META={'retrieved_at':'2026-09-13T00:00:00+00:00','cache':'network','url':adv.OSV}


def fixture():
    return inv.package('PyPI','demo-pkg','1.0.0','requirements.txt','line:1')


def advisory(vid='GHSA-demo-1111-2222',aliases=None):
    return {'id':vid,'aliases':aliases or ['CVE-2025-12345'],'summary':'Synthetic vulnerable package',
            'database_specific':{'severity':'HIGH'},'affected':[{'package':{'ecosystem':'PyPI','name':'demo-pkg'},'ranges':[{'type':'ECOSYSTEM','events':[{'introduced':'0'},{'fixed':'1.0.1'}]}]}]}


class InventoryTests(unittest.TestCase):
    def test_large_npm_lock_is_included_and_scripts_are_not_executed(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            data={'lockfileVersion':3,'packages':{'':{'scripts':{'install':'do not run'}},'node_modules/demo':{'version':'1.2.3'}},'padding':'x'*(1024*1024+10)}
            (root/'package-lock.json').write_text(json.dumps(data))
            (root/'setup.py').write_text('raise Exception("must not run")')
            report=inv.collect(root)
            self.assertEqual(report['unique_packages'],1)
            self.assertGreater(report['manifests'][0]['bytes'],1024*1024)
            self.assertEqual(report['packages'][0]['version'],'1.2.3')

    def test_npm_v1_nested_and_v3_alias_packages(self):
        rows,_=inv.parse_npm(json.dumps({'lockfileVersion':1,'dependencies':{'a':{'version':'1.0.0','dependencies':{'a':{'version':'2.0.0'}}}}}),'package-lock.json')
        self.assertEqual({r['version'] for r in rows},{'1.0.0','2.0.0'})
        rows,_=inv.parse_npm(json.dumps({'lockfileVersion':3,'packages':{'node_modules/alias':{'name':'actual','version':'1.0.0'}}}),'package-lock.json')
        self.assertEqual(rows[0]['name'],'actual')

    def test_python_ranges_urls_directives_and_markers_are_not_guessed(self):
        rows,gaps=inv.parse_requirements('Django==4.0.0\nrequests>=2\n-r hidden.txt\nfoo @ https://secret.invalid/pkg\nbar==1.2; python_version < "3.12"\n','requirements.txt')
        self.assertEqual([r['name'] for r in rows],['django','bar'])
        self.assertEqual(rows[1]['scope'],'conditional')
        self.assertEqual(len(gaps),3)
        self.assertNotIn('secret.invalid',json.dumps(gaps))

    def test_go_sum_is_not_a_resolved_inventory_and_replace_is_unknown(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'go.sum').write_text('example.com/a v1.0.0 hash')
            self.assertEqual(inv.collect(root)['unique_packages'],0)
        rows,gaps=inv.parse_go('require example.com/a v1.0.0\nreplace example.com/a => ../local','go.mod')
        self.assertEqual(rows,[]);self.assertTrue(gaps)
        rows,gaps=inv.parse_go('module x\nrequire (\n example.com/a v1.2.3 // indirect\n)\n','go.mod')
        self.assertEqual(rows[0]['version'],'v1.2.3')

    def test_unsupported_and_missing_lock_are_visible(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'pyproject.toml').write_text('[project]');(root/'package.json').write_text('{}')
            report=inv.collect(root)
            # An unsupported manifest names what would fix it rather than
            # reporting the bare 'unsupported_manifest'. Since B8 a pyproject is
            # read for exact pins, so an empty [project] is "no dependencies
            # declared" -- a different and more accurate statement than the old
            # "no lock file".
            self.assertEqual({g['reason'] for g in report['gaps']},
                             {'python_pyproject_no_dependencies','npm_lockfile_missing'})


class AdvisoryTests(unittest.TestCase):
    def test_batch_pagination_and_only_minimal_metadata_sent(self):
        calls=[]
        def fetcher(url,payload=None,salt=''):
            calls.append((url,payload))
            if url.endswith('querybatch'):
                self.assertEqual(set(payload['queries'][0]['package']),{'name','ecosystem'})
                self.assertNotIn('requirements.txt',json.dumps(payload))
                if 'page_token' not in payload['queries'][0]:return {'results':[{'vulns':[{'id':'GHSA-demo-1111-2222'}],'next_page_token':'next'}]},META
                return {'results':[{'vulns':[{'id':'PYSEC-2025-1'}]}]},META
            vid=url.rsplit('/',1)[1];return advisory(vid),META
        matches,details,errors,_=adv.query_packages([fixture()],fetcher)
        self.assertEqual(len(next(iter(matches.values()))),2);self.assertFalse(errors)
        self.assertEqual(len(details),2)

    def test_query_failure_cannot_be_reported_as_clean(self):
        def unavailable(*args,**kwargs):raise adv.FeedError('test')
        matches,_,errors,_=adv.query_packages([fixture()],unavailable)
        self.assertEqual(matches,{});self.assertEqual(len(errors),1)

    def test_response_length_mismatch_and_bad_ids_are_not_trusted(self):
        for response in ({'results':[]},{'results':[{'vulns':[{'id':'../../private'}]}]}):
            _,_,errors,_=adv.query_packages([fixture()],lambda *a,**kw:(response,META))
            self.assertTrue(errors)

    def test_aliases_merge_but_versions_and_occurrences_remain(self):
        p=fixture();p2={**p,'manifest':'service-b/requirements.txt','id':'different'}
        key=(p['ecosystem'],p['name'],p['version']);a=advisory();b=advisory('PYSEC-2025-1')
        rows=adv.normalize([p,p2],{key:[a['id'],b['id']]},{a['id']:a,b['id']:b},{},True)
        self.assertEqual(len(rows),1);self.assertEqual(len(rows[0]['occurrences']),2)
        self.assertEqual(rows[0]['fixed_versions'],['1.0.1']);self.assertEqual(rows[0]['priority'],'P2')
        self.assertEqual(rows[0]['state'],'advisory_match')

    def test_kev_unknown_and_withdrawn_records(self):
        p=fixture();key=(p['ecosystem'],p['name'],p['version']);record=advisory()
        rows=adv.normalize([p],{key:[record['id']]},{record['id']:record},{},False)
        self.assertIsNone(rows[0]['known_exploited'])
        rows=adv.normalize([p],{key:[record['id']]},{record['id']:record},{'CVE-2025-12345':{}},True)
        self.assertEqual(rows[0]['priority'],'P1')
        record['withdrawn']='2025-01-01'
        self.assertEqual(adv.normalize([p],{key:[record['id']]},{record['id']:record},{},True),[])

    def test_arbitrary_network_endpoint_rejected(self):
        for url in ('http://api.osv.dev/v1/querybatch','https://evil.invalid/','https://api.osv.dev/v1/vulns/../secret'):
            with self.assertRaises(adv.FeedError):adv.fetch(url)


class DependencyJobTests(unittest.TestCase):
    def setUp(self):
        isolate_triage(self)

    def test_scan_always_queries_advisories_online(self):
        with tempfile.TemporaryDirectory() as temp:
            base=Path(temp);root=base/'repo';root.mkdir();(root/'requirements.txt').write_text('demo-pkg==1.0.0')
            with patch.object(dep,'RUNS',base/'runs'),patch.object(scanners,'target_root',return_value=root),\
                 patch.object(adv,'query_packages',return_value=({},{},[],[])) as query,\
                 patch.object(adv,'kev_catalog',return_value=({},{'state':'available'})):
                report=dep.start('test',False)
            query.assert_called_once()
            self.assertEqual(report['state'],'completed');self.assertFalse(dep.LOCK.locked())

    def test_partial_state_retains_valid_results_and_review_requires_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            base=Path(temp);root=base/'repo';root.mkdir();(root/'requirements.txt').write_text('demo-pkg==1.0.0\nother>=2')
            p=fixture();key=(p['ecosystem'],p['name'],p['version']);a=advisory()
            with patch.object(dep,'RUNS',base/'runs'),patch.object(scanners,'target_root',return_value=root),patch.object(adv,'query_packages',return_value=({key:[a['id']]},{a['id']:a},[],[META])),patch.object(adv,'kev_catalog',return_value=({}, {'state':'available'})),patch.object(adv,'enrich',side_effect=lambda findings,progress=None:findings):
                report=dep.start('test',False)
                self.assertEqual(report['state'],'partial');self.assertEqual(report['count'],1)
                self.assertFalse(report['findings'][0]['verified'])
                payload={'report_id':report['id'],'finding_id':report['findings'][0]['id'],'status':'fix_planned','owner':'Tester','note':'Synthetic test'}
                dep.review(payload);self.assertEqual(len(dep.reviews(report['id'])),1)
                with self.assertRaises(ValueError):dep.review({**payload,'finding_id':'missing'})
                with self.assertRaises(ValueError):dep.review({**payload,'note':''})

    def test_comparison_requires_same_target_and_keeps_absence_distinct(self):
        base={'id':'a','target':'one','state':'completed','findings':[{'id':'x'}],'inventory_sha256':'old'}
        after={**base,'id':'b','findings':[],'inventory_sha256':'new'}
        result=dep.compare(base,after)
        self.assertEqual(result['absent'],['x']);self.assertTrue(result['inventory_changed'])
        with self.assertRaises(ValueError):dep.compare(base,{**after,'target':'two'})

    def test_registered_source_does_not_require_compose(self):
        with tempfile.TemporaryDirectory() as temp,patch.object(code_targets,'PROFILES',Path(temp)/'profiles'):
            code_targets.register('example',temp,'Example')
            self.assertEqual(scanners.target_root('example'),Path(temp).resolve())
            with self.assertRaises(ValueError):code_targets.register('example',temp)

    def test_api_rejects_invalid_or_unregistered_targets(self):
        with listener(Handler) as url:
            connection=http.client.HTTPConnection('127.0.0.1',int(url.rsplit(':',1)[1]),timeout=5)
            for payload in ({'target':'C:/private'},{'target':'crapi-full','online':True},{'target':123},{}):
                connection.request('POST','/api/dependencies/scan',json.dumps(payload),{'Content-Type':'application/json'})
                response=connection.getresponse();response.read();self.assertEqual(response.status,400)
            connection.close()


if __name__=='__main__':unittest.main()
