"""Collect a bounded configuration snapshot from the local crAPI pilot.

This captures on-disk configuration in a running container, not worker memory
or proof that an attacker can intercept a connection.
"""
import argparse
import datetime
import hashlib
import json
import re
import subprocess
import uuid

import pilot
from zanjir import repo_store
from zanjir.repository import nginx_routes


def inspect_container(prefix, container_id):
    template='{"id":{{json .Id}},"image_id":{{json .Image}},"running":{{json .State.Running}},"started_at":{{json .State.StartedAt}},"project":{{json (index .Config.Labels "com.docker.compose.project")}},"service":{{json (index .Config.Labels "com.docker.compose.service")}}}'
    return json.loads(pilot.run(prefix+['inspect','--type','container','--format',template,container_id]))


def require_target(info, expected_image_id):
    if (info.get('project')!=pilot.PROJECT or info.get('service')!='crapi-web'
            or info.get('running') is not True or info.get('image_id')!=expected_image_id):
        raise ValueError('Konteyner lokal crAPI pilotining saqlangan web image nusxasiga mos emas.')


def identity_observation(config_text):
    try:
        routes,includes=nginx_routes(config_text,{})
    except ValueError as error:
        return {'state':'analysis_unknown','reason':str(error),'routes':[]}
    selected=[route for route in routes if route['location']=='/identity/' and str(route['listen'])=='443']
    if includes or len(selected)!=1:
        return {'state':'analysis_unknown','reason':'Yo‘l yagona emas, topilmadi yoki qo‘shimcha include bor.','routes':selected}
    route=selected[0]
    observed=(route['scheme']=='https' and route['verify']=='off'
              and route['target']=='crapi-identity' and route['target_port']==8080)
    return {'state':'explicit_tls_verification_disabled_observed' if observed else 'needs_review',
            'routes':selected,'scope':'On-disk server listening on 443, location /identity/; not a traffic test.'}


def capture():
    pilot.prepare()
    locked=pilot.locked_config()
    prefix=pilot.docker_prefix()
    cid=pilot.run(pilot.compose(prefix,True)+['ps','-q','crapi-web'])
    if not re.fullmatch(r'[0-9a-f]{12,64}',cid):
        raise ValueError('Bitta ishlayotgan crapi-web konteyneri topilmadi.')
    digest=locked['services']['crapi-web']['image']
    image_id=pilot.run(prefix+['image','inspect','--format','{{.Id}}',digest])
    before=inspect_container(prefix,cid)
    require_target(before,image_id)
    print('crAPI web konfiguratsiyasi o‘qilmoqda. Xizmat qayta ishga tushirilmaydi.',flush=True)
    dump=pilot.run(prefix+['exec',cid,'openresty','-T'],timeout=30)
    config=pilot.run(prefix+['exec',cid,'cat','/etc/nginx/conf.d/default.conf'])
    after=inspect_container(prefix,cid)
    if before!=after:
        raise ValueError('Tekshiruv paytida konteyner holati o‘zgardi; natijani qayta olish kerak.')
    marker='# configuration file /etc/nginx/conf.d/default.conf:'
    if marker not in dump:
        raise ValueError('Olingan default.conf Nginx konfiguratsiya ro‘yxatida topilmadi.')
    dumped_default=dump.split(marker,1)[1].split('\n# configuration file ',1)[0].strip()
    if dumped_default!=config.strip():
        raise ValueError('Konfiguratsiya nusxalari mos emas; tekshiruvni qayta bajarish kerak.')
    source_report=repo_store.scan_profile('crapi')
    observation=identity_observation(config)
    now=datetime.datetime.now(datetime.timezone.utc)
    run_id=now.strftime('%Y%m%dT%H%M%S')+'-'+uuid.uuid4().hex[:8]
    folder=pilot.PILOT/'evidence'/run_id
    folder.mkdir(parents=True)
    files={'nginx-dump.txt':dump,'default.conf':config}
    hashes={}
    for name,content in files.items():
        raw=content.encode('utf-8')
        (folder/name).write_bytes(raw)
        hashes[name]=hashlib.sha256(raw).hexdigest()
    report={'id':run_id,'checked_at':now.isoformat(),'state':'configuration_snapshot_collected',
            'container':before,'locked_image':digest,'files_sha256':hashes,
            'source_report_id':source_report['id'],'source_commit':pilot.COMMIT,
            'source_image_equivalence':'not_proven','observation':observation,
            'security_test':'not_run','runtime_verified':False,
            'limits':['Nginx -T reads on-disk configuration; loaded worker configuration is not proven.',
                      'No interception, untrusted-certificate, trusted-certificate or remediation test has run.',
                      'The source snapshot and prebuilt image may differ; route evidence is kept separate.']}
    pilot.write_json(folder/'report.json',report)
    found=observation['state']=='explicit_tls_verification_disabled_observed'
    description=('Konteyner faylida /identity/ HTTPS yo‘li uchun sertifikat tekshiruvi aniq o‘chirilgan.'
                 if found else 'Tanlangan sozlama avtomatik tasdiqlanmadi; konfiguratsiya qo‘lda ko‘rib chiqilishi kerak.')
    (folder/'report.md').write_text(
        '# crAPI: birinchi konfiguratsiya dalili\n\n'+description+'\n\n'
        'Bu hali hujum amalga oshishi yoki noto‘g‘ri sertifikat qabul qilinishining isboti emas. '
        'Olingan nusxa konteyner diskidagi sozlama; ishlayotgan Nginx xotirasidagi sozlama bilan tengligi isbotlanmagan.\n\n'
        f'- Tekshiruv vaqti (UTC): {report["checked_at"]}\n- Manba hisoboti: {source_report["id"]}\n'
        f'- Image: `{digest}`\n- Natija: `{observation["state"]}`\n\n'
        'Keyingi bosqich: alohida muhitda ishonchsiz sertifikat, tuzatilgan sozlama va ishonchli sertifikat bilan uchta nazorat.\n',encoding='utf-8')
    pilot.write_json(pilot.PILOT/'runtime'/'latest-evidence.json',
                     {'id':run_id,'report':str(folder/'report.json'),'observation':observation['state'],'security_test':'not_run'})
    return {'state':report['state'],'observation':observation['state'],'report':str(folder/'report.md'),'security_test':'not_run'}


def main():
    try:
        print(json.dumps(capture(),indent=2,ensure_ascii=False))
        return 0
    except (OSError,RuntimeError,ValueError,KeyError,subprocess.TimeoutExpired) as error:
        failure={'checked_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),
                 'state':'not_completed','action':'collect_evidence','message':str(error),'security_test':'not_run'}
        pilot.write_json(pilot.PILOT/'runtime'/'evidence-error.json',failure)
        print(json.dumps(failure,ensure_ascii=False))
        return 2


if __name__=='__main__':
    argparse.ArgumentParser(description='crAPI web konfiguratsiyasidan dalil yig‘ish').parse_args()
    raise SystemExit(main())
