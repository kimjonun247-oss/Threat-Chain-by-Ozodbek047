"""Exercise real API -> background assessment -> real Nuclei -> safe export."""
import argparse
import http.client
import json
import time
from unittest.mock import patch
from app import Handler
from validate_web import fixture, DEMO_SECRET
from zanjir import pipeline, webscan, repo_store
from zanjir.httptest import listener


def main():
    root=webscan.ROOT/'validation-runs/pipeline-control'
    with fixture() as (url, calls), patch.object(pipeline,'RUNS',root/'assessments'), patch.object(webscan,'RUNS',root/'web'):
        target={'id':'control-web','url':url,'owner':'Zanjir synthetic control','authorized_at':webscan.now(),'allow_private':True}
        with patch.object(webscan,'target_for',return_value=target), listener(Handler) as server:
            c=http.client.HTTPConnection('127.0.0.1',int(server.rsplit(':',1)[1]),timeout=10)
            c.request('POST','/api/assessments/scan',json.dumps({'target':'','repository_target':'','web_target':'control-web','image_target':'','online':True}),{'Content-Type':'application/json'})
            response=c.getresponse();data=json.loads(response.read());assert response.status==202,data
            rid=data['id'];deadline=time.monotonic()+90
            while True:
                c.request('GET','/api/assessments/reports/'+rid)
                response=c.getresponse();report=json.loads(response.read());assert response.status==200,report
                if report['state'] not in {'queued','running'}:break
                assert time.monotonic()<deadline,'Pipeline timeout'
                time.sleep(0.1)
            assert report['state']=='completed',report
            web=next(s for s in report['stages'] if s['kind']=='web')
            assert web['report']['tool']['version']=='3.11.1'
            assert sum(f['tool']=='Nuclei' for f in web['report']['findings'])==6
            c.request('GET','/api/assessments/reports/'+rid+'/download')
            response=c.getresponse();raw=response.read();assert response.status==200
            assert json.loads(raw)==pipeline.read(rid)
            assert DEMO_SECRET not in raw.decode()
            c.close()
            result={'passed':True,'assessment_id':rid,'web_report':web['report_id'],'requests':len(calls),
                    'nuclei_matches':6,'secret_redacted':True,'scope':'Synthetic localhost through real API, jobs, Nuclei and JSON download.'}
    repo_store.write_json(root/'result.json',result)
    print(json.dumps(result,ensure_ascii=False,indent=2))


if __name__=='__main__':
    argparse.ArgumentParser(description='Sun’iy nishonda to‘liq quvurni uchidan-uchigacha tekshirish').parse_args()
    main()
