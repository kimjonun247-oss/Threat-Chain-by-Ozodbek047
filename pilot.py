"""Explicit Docker pilot lifecycle, separate from the read-only repository scanner."""
from __future__ import annotations
import argparse
import copy
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
import urllib.request

from zanjir.engine import ROOT
from zanjir.repository import dotenv, interpolate, parse_yaml

PILOT=ROOT/'pilot'
PROJECT='zanjir-crapi-pilot'
COMMIT='700f03d12a392d9e408260b4beae72ed02a4a1a4'


def write_json(path,data):
    path.parent.mkdir(parents=True,exist_ok=True)
    temp=path.with_suffix('.tmp')
    temp.write_text(json.dumps(data,indent=2,ensure_ascii=False),encoding='utf-8')
    os.replace(temp,path)


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def create_config(source):
    """Resolve only the bundled environment; never import caller shell variables."""
    config,_=parse_yaml((source/'docker-compose.yml').read_text(encoding='utf-8'))
    values=dotenv((source/'.env').read_text(encoding='utf-8'))
    unknowns=[]
    def resolve(value):
        if isinstance(value,str):return interpolate(value,values,unknowns,'pilot')
        if isinstance(value,list):return [resolve(v) for v in value]
        if isinstance(value,dict):return {k:resolve(v) for k,v in value.items()}
        return value
    config=resolve(config)
    if unknowns:raise ValueError('Pilot konfiguratsiyasida aniqlanmagan qiymat bor.')
    # Own project names and an internal network, no production network attachment.
    for service in config['services'].values():
        service.pop('container_name',None)
        service.pop('ports',None)
        service['networks']=['default']
    config['services']['crapi-web']['ports']=['127.0.0.1:18888:80','127.0.0.1:18443:443']
    config['services']['mailhog']['ports']=['127.0.0.1:18025:8025']
    config['services']['crapi-identity']['volumes']=[{'type':'bind','source':'./keys','target':'/app/keys','read_only':True}]
    config['networks']={'default':{'internal':True}}
    return config


def prepare():
    source=PILOT/'upstream'
    manifest=json.loads((source/'provenance.json').read_text(encoding='utf-8'))
    if manifest['commit']!=COMMIT or any(sha(source/name)!=value for name,value in manifest['files'].items()):
        raise ValueError('Pilot manba fayllari saqlangan nusxaga mos emas.')
    config=create_config(source)
    folder=PILOT/'runtime'
    target=folder/'compose.json'
    if target.exists() and json.loads(target.read_text())!=config:
        raise ValueError('Tayyor konfiguratsiya o‘zgargan; avtomatik ustiga yozilmaydi.')
    write_json(target,config)
    (folder/'keys').mkdir(exist_ok=True)
    key=folder/'keys'/'jwks.json'
    if key.exists() and key.read_bytes()!=(source/'keys'/'jwks.json').read_bytes():
        raise ValueError('Pilot kalit fayli o‘zgargan; avtomatik ustiga yozilmaydi.')
    if not key.exists():shutil.copyfile(source/'keys'/'jwks.json',key)
    write_json(folder/'preparation.json',{'source_commit':COMMIT,'compose_sha256':sha(target),
        'services':len(config['services']),'state':'prepared_not_started','runtime_verified':False,
        'changes':['dedicated project','internal network','loopback ports 18888,18443,18025','read-only demo keys'],
        'note':'Prebuilt image identity is recorded after pull; image/source commit equivalence is not assumed.'})
    return {'state':'prepared_not_started','services':len(config['services']),'runtime_verified':False}


def run(command,timeout=20,live=False):
    env={k:v for k,v in os.environ.items() if not k.startswith(('DOCKER_','COMPOSE_'))}
    result=subprocess.run(command,cwd=PILOT/'runtime',env=env,capture_output=not live,text=True,encoding='utf-8',errors='replace',timeout=timeout)
    if result.returncode:
        raise RuntimeError((result.stderr or '').strip()[-1600:] or (result.stdout or '').strip()[-1600:] or 'Docker amali bajarilmadi; oynadagi xato matnini tekshiring.')
    return (result.stdout or '').strip()


def docker_prefix():
    executable=shutil.which('docker')
    if not executable:
        candidates=[]
        local_app_data=os.environ.get('LOCALAPPDATA')
        if local_app_data:
            candidates.append(Path(local_app_data)/'Programs/DockerDesktop/resources/bin/docker.exe')
        candidates.append(Path(os.environ.get('ProgramFiles','C:/Program Files'))/'Docker/Docker/resources/bin/docker.exe')
        executable=next((str(candidate) for candidate in candidates if candidate.is_file()),None)
    if not executable:raise RuntimeError('Docker topilmadi. Docker Desktop va WSL 2 kerak.')
    # The active context's name varies by setup (Docker Desktop, colima,
    # OrbStack, native Linux) -- ask the CLI which one is current rather than
    # guessing a fixed name per OS.
    context=run([executable,'context','show']).strip()
    info=json.loads(run([executable,'context','inspect',context]))
    host=info[0]['Endpoints']['docker']['Host']
    if not host.startswith(('npipe://','unix://')):
        raise RuntimeError('Pilot faqat lokal Docker bilan ishlaydi; masofaviy endpoint rad etildi.')
    return [executable,'--context',context]


def check():
    state={'checked_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'runtime_verified':False,'security_test':'not_run'}
    try:
        prefix=docker_prefix()
        info=json.loads(run(prefix+['info','--format','{{json .}}']))
        if info.get('OSType')!='linux':raise RuntimeError('Docker Linux konteynerlar rejimida bo‘lishi kerak.')
        version=run(prefix+['compose','version','--short'])
        state.update(state='engine_ready',compose_version=version,message='Docker tayyor. Ilova hali tekshirilmagan.')
    except (RuntimeError,OSError,ValueError,subprocess.TimeoutExpired) as error:
        state.update(state='environment_required',message=str(error))
    write_json(PILOT/'runtime'/'environment.json',state)
    return state


def access_config():
    # Only browser-facing services join the ingress bridge; backend stays internal.
    return {'services':{sid:{'networks':['default','local_access']} for sid in ('crapi-web','mailhog')},
            'networks':{'local_access':{'driver':'bridge','internal':False}}}


def compose(prefix,locked=False):
    command=prefix+['compose','--project-name',PROJECT,'-f',str(PILOT/'runtime'/('compose.lock.json' if locked else 'compose.json'))]
    overlay=PILOT/'runtime'/'compose.access.json'
    if locked and overlay.exists():
        if json.loads(overlay.read_text(encoding='utf-8'))!=access_config():
            raise ValueError('Mahalliy kirish konfiguratsiyasi o‘zgargan; amal to‘xtatildi.')
        command+=['-f',str(overlay)]
    return command


def http_readiness(attempts=1):
    # Do not send localhost checks through caller HTTP proxies.
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    checks=[]
    for attempt in range(attempts):
        checks=[]
        for url in ('http://127.0.0.1:18888/','http://127.0.0.1:18025/'):
            try:
                with opener.open(url,timeout=5) as response:
                    body=response.read(512)
                    checks.append({'url':url,'status':response.status,'responding':response.status==200 and bool(body)})
            except OSError as error:
                checks.append({'url':url,'responding':False,'error':str(error)})
        if all(item['responding'] for item in checks):break
        if attempt+1<attempts:time.sleep(2)
    report={'checked_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'checks':checks,'ready':all(item['responding'] for item in checks),
            'security_test':'not_run','note':'HTTP availability only; no vulnerability verification.'}
    write_json(PILOT/'runtime'/'http-readiness.json',report)
    return report


def lock_images(config,inspector):
    result=copy.deepcopy(config)
    identities={}
    for sid,service in result['services'].items():
        tag=service['image']
        info=inspector(tag)
        repo=tag.rsplit(':',1)[0]
        digest=next((d for d in info.get('RepoDigests',[]) if d.startswith(repo+'@sha256:')),None)
        if not digest or not re.fullmatch(r'.+@sha256:[0-9a-f]{64}',digest):
            raise ValueError(f'{sid}: yuklangan image digest olinmadi.')
        service['image']=digest
        identities[sid]={'requested':tag,'resolved':digest,'image_id':info['Id']}
    return result,identities


def locked_config():
    base=json.loads((PILOT/'runtime'/'compose.json').read_text())
    path=PILOT/'runtime'/'compose.lock.json'
    if not path.exists():raise ValueError('Avval pull bosqichi kerak: image nusxalari hali qayd qilinmagan.')
    locked=json.loads(path.read_text())
    expected=copy.deepcopy(base)
    if set(locked['services'])!=set(base['services']):raise ValueError('Image lock qamrovi mos emas.')
    for sid,service in locked['services'].items():
        image=service['image']
        repository=base['services'][sid]['image'].rsplit(':',1)[0]
        if not re.fullmatch(re.escape(repository)+r'@sha256:[0-9a-f]{64}',image):
            raise ValueError('Image digest noto‘g‘ri.')
        expected['services'][sid]['image']=image
    if locked!=expected:raise ValueError('Image lock ichidagi pilot sozlamalari o‘zgargan.')
    return locked


def lifecycle(action):
    prepare()
    if action=='check':return check()
    prefix=docker_prefix()
    if action=='pull':
        if check()['state']!='engine_ready':raise RuntimeError('Docker Linux engine hali tayyor emas.')
        run(compose(prefix)+['config','--quiet'])
        print('crAPI image fayllari yuklanmoqda. Bu bosqich internet va disk joyi talab qiladi.',flush=True)
        run(compose(prefix)+['pull'],timeout=1800,live=True)
        config=json.loads((PILOT/'runtime'/'compose.json').read_text())
        locked,identities=lock_images(config,lambda tag:json.loads(run(prefix+['image','inspect',tag]))[0])
        write_json(PILOT/'runtime'/'compose.lock.json',locked)
        write_json(PILOT/'runtime'/'images.json',identities)
        return {'state':'images_locked','services':len(identities),'runtime_verified':False}
    locked_config()
    if action=='repair-access':
        overlay=PILOT/'runtime'/'compose.access.json'
        if overlay.exists() and json.loads(overlay.read_text(encoding='utf-8'))!=access_config():
            raise ValueError('Mahalliy kirish fayli o‘zgargan; ustiga yozilmaydi.')
        write_json(overlay,access_config())
        command=compose(prefix,True)
        run(command+['config','--quiet'])
        print('Mahalliy kirish tuzatilmoqda. Image qayta yuklanmaydi; faqat web va mailhog yangilanadi.',flush=True)
        run(command+['up','-d','--pull','never','--no-build','--no-deps','--wait','--wait-timeout','180','crapi-web','mailhog'],timeout=210,live=True)
    elif action=='start':
        run(compose(prefix,True)+['up','-d','--pull','never','--no-build','--wait','--wait-timeout','180'],timeout=210,live=True)
    elif action=='stop':
        run(compose(prefix,True)+['down'],timeout=120)
        return {'state':'stopped','volumes':'retained','runtime_verified':False}
    raw=run(compose(prefix,True)+['ps','--all','--format','json'])
    rows=json.loads(raw) if raw.startswith('[') else [json.loads(line) for line in raw.splitlines() if line.strip()]
    services=[{k:r.get(k) for k in ('Service','State','Health','ExitCode')} for r in rows]
    expected=set(locked_config()['services'])
    ready={s['Service'] for s in services if s['State']=='running' and s['Health'] in ('healthy','',None)}
    http=http_readiness(attempts=3 if action in ('start','repair-access') else 1)
    state={'checked_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'state':('services_running' if http['ready'] else 'http_not_ready') if ready==expected else 'services_not_ready','services':services,
        'http_ready':http['ready'],'http_checks':http['checks'],
        'security_test':'not_run','runtime_verified':False,
        'note':'Container readiness is not vulnerability confirmation.'}
    write_json(PILOT/'runtime'/'status.json',state)
    return state


def main():
    parser=argparse.ArgumentParser(description='Zanjir crAPI ajratilgan lokal pilot')
    parser.add_argument('action',choices=['prepare','check','pull','start','status','stop','repair-access'])
    args=parser.parse_args()
    try:
        result=prepare() if args.action=='prepare' else lifecycle(args.action)
        print(json.dumps(result,indent=2,ensure_ascii=False))
        return 2 if result['state'] in {'environment_required','services_not_ready','http_not_ready'} else 0
    except (OSError,RuntimeError,ValueError,KeyError,subprocess.TimeoutExpired) as error:
        failure={'state':'not_completed','action':args.action,'message':str(error),'runtime_verified':False,'security_test':'not_run'}
        write_json(PILOT/'runtime'/'last-error.json',failure)
        print(json.dumps(failure,ensure_ascii=False))
        return 2


if __name__=='__main__':raise SystemExit(main())
