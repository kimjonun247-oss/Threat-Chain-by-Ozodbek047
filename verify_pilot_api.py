"""Read-only localhost check: persisted evidence must equal API downloads."""
import argparse
import http.client
import json
import re
from html.parser import HTMLParser
from zanjir.engine import ROOT
from zanjir import dependencies, images, repo_store, webscan, pipeline, readiness


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--port',type=int,default=8765)
    args=parser.parse_args()
    connection=http.client.HTTPConnection('127.0.0.1',args.port,timeout=15)
    def get(path,headers=None):
        connection.request('GET',path,headers=headers or {})
        response=connection.getresponse();raw=response.read()
        return response.status,raw,dict(response.getheaders())
    checks={}
    class Assets(HTMLParser):
        def __init__(self):super().__init__();self.ids=[];self.assets=[]
        def handle_starttag(self,tag,attrs):
            attrs=dict(attrs)
            if 'id' in attrs:self.ids.append(attrs['id'])
            if tag=='script' and attrs.get('src'):self.assets.append(attrs['src'])
            if tag=='link' and attrs.get('href','').startswith('/'):self.assets.append(attrs['href'])
    page=Assets();page.feed((ROOT/'dist/index.html').read_text(encoding='utf-8'))
    checks['unique_html_ids']=len(page.ids)==len(set(page.ids))
    checks['local_assets_exist']=all((ROOT/'dist'/path.lstrip('/')).is_file() for path in page.assets)
    bindings=set(re.findall(r"\$\('([a-z][a-z0-9-]*)'\)",(ROOT/'dist/web-pilot.js').read_text(encoding='utf-8')))
    checks['new_control_bindings_exist']=bindings<=set(page.ids)
    status,raw,headers=get('/api/health')
    # Versiya bu yerda qattiq yozilmaydi: 0.5 -> 0.6 ko‘tarilganda aynan shu tekshiruv
    # jimgina eskirib qolgan edi. Endi /api/health va readiness bir-biriga mos kelishi tekshiriladi.
    health=json.loads(raw) if status==200 else {}
    checks['health']=status==200 and health.get('ok') is True and health.get('version')==readiness.status()['version']
    checks['csp']="frame-ancestors 'none'" in headers.get('Content-Security-Policy','')
    status,raw,_=get('/')
    checks['served_html_matches_disk']=status==200 and raw==(ROOT/'dist/index.html').read_bytes()
    for path in page.assets:
        status,raw,headers=get(path)
        mime=headers.get('Content-Type','').split(';',1)[0]
        expected={'js':{'text/javascript','application/javascript'},'css':{'text/css'}}.get(path.rsplit('.',1)[-1])
        checks['served_asset:'+path]=status==200 and raw==(ROOT/'dist'/path.lstrip('/')).read_bytes() and (expected is None or mime in expected)
    status,raw,_=get('/api/readiness')
    # 0.6 da offline rejim olib tashlanganda rejim nomi o‘zgargan; readiness.py va
    # tests/test_pilot_online.py yangi qiymatda, bu skript esa eskisida qolib ketgan edi.
    checks['readiness']=status==200 and json.loads(raw)['mode']=='online_evidence_based_pilot'
    status,raw,_=get('/api/web/control-evidence')
    checks['web_control_evidence']=status==200 and json.loads(raw).get('passed') is True
    report=dependencies.read(dependencies.history('crapi-full')[0]['id'])
    rid=report['id']
    status,raw,_=get('/api/dependencies/reports/'+rid+'/download')
    checks['dependency_download_matches_disk']=status==200 and json.loads(raw)==report
    status,raw,_=get('/api/dependencies/reports/'+rid+'/inventory')
    checks['inventory_download_matches_disk']=status==200 and json.loads(raw)==dependencies.read_inventory(rid)
    status,raw,_=get('/api/dependencies/reports/'+rid+'/markdown')
    checks['markdown_matches_report']=status==200 and raw.decode('utf-8')==dependencies.markdown(report)
    image=images.read(images.history()[0]['id'])
    status,raw,_=get('/api/images/reports/'+image['id']+'/download')
    checks['image_download_matches_disk']=status==200 and json.loads(raw)==image
    checks['image_config_not_exported']='ImageConfig' not in raw.decode('utf-8')
    status,_,_=get('/api/readiness',{'Origin':'https://untrusted.invalid'})
    checks['cross_origin_rejected']=status==403
    status,_,_=get('/api/dependencies/reports/invalid/download')
    checks['invalid_report_rejected']=status==404
    control=json.loads((ROOT/'validation-runs/osv-control/result.json').read_text(encoding='utf-8'))
    status,raw,_=get('/api/dependencies/reports/'+control['after']+'/reviews')
    checks['review_readback']=status==200 and json.loads(raw)==dependencies.reviews(control['after'])
    for prefix,module in (('/api/web',webscan),('/api/assessments',pipeline)):
        latest=module.history()
        checks[prefix+'_has_report']=bool(latest)
        if latest:
            row=module.read(latest[0]['id'])
            status,raw,_=get(prefix+'/reports/'+row['id']+'/download')
            checks[prefix+'_download_matches_disk']=status==200 and json.loads(raw)==row
            status,raw,_=get(prefix+'/reports/'+row['id']+'/markdown')
            checks[prefix+'_markdown_matches_disk']=status==200 and raw.decode('utf-8')==module.markdown(row)
    connection.close()
    result={'created_at':dependencies.now(),'checks':checks,'passed':all(checks.values()),
            'dependency_report':rid,'image_report':image['id'],'osv_control_passed':control['passed'],
            'scope':'Local API, export consistency and request boundary checks. Not a full penetration test.'}
    repo_store.write_json(ROOT/'validation-runs/api-check.json',result)
    print(json.dumps(result,ensure_ascii=False,indent=2))
    raise SystemExit(0 if result['passed'] else 1)


if __name__=='__main__':main()
