from __future__ import annotations
import copy
import threading
import json
import os
import re
import uuid
import time
from pathlib import Path
from .engine import ROOT, canonical, digest, DATA
from .repository import scan_repository, safe_read

REPO_RUNS=DATA/'repository-runs'
# Profiles that ship with the application: their root is a path inside this
# folder, checked for containment rather than against a registered_root.
ALLOWED_PROFILES={'crapi','chain-demo'}
LOCAL_PROFILES=DATA/'profiles'/'local'
PROFILE_ID=re.compile(r'^[a-z][a-z0-9_-]{1,39}$')
REPORT_ID=re.compile(r'^\d{8}T\d{6}-[0-9a-f]{8}$')


_MEMO={}
_MEMO_LOCK=threading.Lock()


def folder_signature(*folders):
    """What a listing of these folders depends on: names, sizes and mtimes.

    One stat per file -- far cheaper than reading and parsing every JSON profile,
    which the dashboard did 3436 times per request. A write through write_json()
    renames a temp file into place, so it always changes the signature.
    """
    signature=[]
    for folder in folders:
        try:
            with os.scandir(folder) as entries:
                signature.append((str(folder),tuple(sorted((e.name,e.stat().st_mtime_ns,e.stat().st_size)
                                                         for e in entries if e.is_file()))))
        except OSError:
            signature.append((str(folder),None))
    return tuple(signature)


def memo(key,signature,compute):
    """compute() once per signature; callers get their own copy to mutate."""
    with _MEMO_LOCK:
        hit=_MEMO.get(key)
    if hit is not None and hit[0]==signature:
        return copy.deepcopy(hit[1])
    value=compute()
    with _MEMO_LOCK:
        _MEMO[key]=(signature,value)
    return copy.deepcopy(value)


def profile_for(profile_id):
    if not isinstance(profile_id,str) or not PROFILE_ID.fullmatch(profile_id):
        raise ValueError('Noma’lum repository profili.')
    path=ROOT/'profiles'/f'{profile_id}.json' if profile_id in ALLOWED_PROFILES else LOCAL_PROFILES/f'{profile_id}.json'
    try:
        stat=path.stat()
    except OSError:
        raise ValueError('Loyiha ro‘yxatdan o‘tkazilmagan.') from None
    if not path.is_file():
        raise ValueError('Loyiha ro‘yxatdan o‘tkazilmagan.')
    return memo(('profile',str(path)),(stat.st_mtime_ns,stat.st_size),
                lambda:json.loads(path.read_text(encoding='utf-8')))


def list_profiles():
    return memo(('list_profiles',str(LOCAL_PROFILES)),folder_signature(ROOT/'profiles',LOCAL_PROFILES),_list_profiles)


def _list_profiles():
    ids=sorted(ALLOWED_PROFILES)
    if LOCAL_PROFILES.exists():
        ids += [p.stem for p in sorted(LOCAL_PROFILES.glob('*.json')) if PROFILE_ID.fullmatch(p.stem) and p.stem not in ALLOWED_PROFILES]
    result=[]
    for pid in ids:
        try:
            p=profile_for(pid)
            result.append({'id':pid,'name':p['name'],'compose':p['compose'],'env_file':p.get('env_file'),
                           'proxy_bindings':len(p.get('bindings',[])), 'mode':'bundled_sample' if pid in ALLOWED_PROFILES else 'registered_local',
                           'owner':p.get('owner',''), 'scope':'Compose + berilgan Nginx fayllari; faqat o‘qish'})
        except (ValueError,KeyError,OSError):
            continue
    return result


def register_project(profile_id, root, compose, env_file=None, bindings=None, name=None, owner=''):
    """Explicit local CLI onboarding, never available as an arbitrary-path browser API."""
    # A code target with the same id is allowed: one project, several stages,
    # grouped by id in the portfolio. It used to be refused with a message about
    # the crapi name that had nothing to do with the real reason.
    if not isinstance(profile_id,str) or not PROFILE_ID.fullmatch(profile_id):
        raise ValueError('Loyiha ID: 2–40 ta kichik lotin harfi, raqam, _ yoki - (harf bilan boshlansin).')
    if profile_id in ALLOWED_PROFILES|{'crapi-full'}:
        raise ValueError(f'“{profile_id}” ID namuna loyiha uchun band; boshqa ID tanlang.')
    path=LOCAL_PROFILES/f'{profile_id}.json'
    if path.exists():
        raise ValueError('Bu loyiha ID allaqachon mavjud; boshqa ID tanlang.')
    source=Path(root).resolve()
    if not source.is_dir():
        raise ValueError('Loyiha papkasi mavjud emas.')
    if not isinstance(name or profile_id,str) or not isinstance(owner,str) or len(name or profile_id)>120 or len(owner)>120:
        raise ValueError('Loyiha nomi/mas’ul 120 belgidan oshmasin.')
    bindings=[] if bindings is None else bindings
    if not isinstance(bindings,list):
        raise ValueError('Proxy binding JSON massiv bo‘lishi kerak.')
    for binding in bindings:
        if not isinstance(binding,dict):
            raise ValueError('Proxy mapping noto‘g‘ri.')
        safe_read(source,binding.get('path'))
    # A Compose file is validated now (fail fast on a bad one), but it is optional:
    # a project without one still registers, and the code, dependency and IaC
    # stages read the source root directly. Only the repository and chain layers
    # need Compose, and they say so when it is absent.
    preview=scan_repository(source,compose,env_file,bindings) if compose else None
    profile={'id':profile_id,'name':name or profile_id,'root':str(source),'registered_root':str(source),
             'compose':compose,'env_file':env_file,'bindings':bindings,'owner':owner,'mode':'registered_local'}
    # Credentials must not be persisted in profile template overrides.
    if re.search(r'(?i)(password|secret|token|api_key|authorization)',json.dumps(bindings)):
        raise ValueError('Proxy mappingga credential kiritmang; faqat target va protokol kabi qiymatlar kerak.')
    LOCAL_PROFILES.mkdir(parents=True,exist_ok=True)
    with path.open('x',encoding='utf-8') as file:
        json.dump(profile,file,ensure_ascii=False,indent=2)
    return {'id':profile_id,'name':profile['name'],
            'services':preview['summary']['services'] if preview else [],
            'unknowns':preview['unknowns'] if preview else [],'mode':'registered_local'}


def write_json(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    temp=path.with_name(path.name+'.'+uuid.uuid4().hex+'.tmp')
    try:
        temp.write_text(json.dumps(value,indent=2,ensure_ascii=False),encoding='utf-8')
        # Windows readers can briefly hold the destination without delete-sharing.
        # Keep atomic replacement; never truncate a report visible to another reader.
        for attempt in range(6):
            try:
                os.replace(temp,path)
                break
            except PermissionError:
                if attempt == 5:
                    raise
                time.sleep(0.02 * (attempt + 1))
    finally:
        if temp.exists():temp.unlink()
    # Keep the run index current without re-walking the folder (run_index.written).
    from . import run_index
    run_index.written(path,value)


def read_json(path):
    """Bounded retry for Windows sharing conflicts with a replacing writer."""
    for attempt in range(6):
        try:
            return json.loads(path.read_text(encoding='utf-8'))
        except PermissionError:
            if attempt == 5:
                raise
            time.sleep(0.02 * (attempt + 1))


def save_report(report, output_dir=None):
    folder=Path(output_dir) if output_dir else REPO_RUNS
    report['report_sha256']=digest(canonical(report))
    write_json(folder/(report['id']+'.json'),report)
    return report


def scan_profile(profile_id):
    profile=profile_for(profile_id)
    source=(ROOT/profile['root']).resolve()
    if profile_id in ALLOWED_PROFILES:
        if not source.is_relative_to(ROOT):
            raise ValueError('Namuna loyiha chegarasidan tashqarida.')
        provenance=json.loads((source/'zanjir-provenance.json').read_text(encoding='utf-8'))
    else:
        if profile.get('mode')!='registered_local' or str(source)!=profile.get('registered_root'):
            raise ValueError('Ro‘yxatdan o‘tgan papka yo‘li o‘zgargan; qayta ro‘yxatdan o‘tkazing.')
        provenance={'repository':profile['name'],'commit':None,'source_type':'registered_local',
                    'note':'Commit avtomatik olinmagan. Aniq o‘qilgan fayllar xeshlari hisobotda saqlanadi.'}
    if not profile.get('compose'):
        raise ValueError('Bu loyiha docker-compose.yml’siz ro‘yxatga olingan; Repository qatlami Compose faylini talab '
                         'qiladi. Loyihada compose bo‘lsa, uni compose fayli bilan qayta ro‘yxatga oling — aks holda '
                         'faqat Kod, CVE va IaC skanlaridan foydalaning.')
    report=scan_repository(source,profile['compose'],profile.get('env_file'),profile.get('bindings'),provenance)
    report['profile_id']=profile_id
    report['profile_name']=profile['name']
    report['input_sha256']=digest(canonical({'profile_id':profile_id,'input_sha256':report['input_sha256']}))
    saved=save_report(report)
    from . import triage
    # Record what this completed scan saw before handing the report back, so the
    # SLA has a first-seen date to count from. Then return the same enriched view
    # get_report() would return -- a freshly scanned report and a reloaded one
    # must not differ.
    triage.observe(triage.scope_for('repository',profile_id),saved.get('findings') or [],saved.get('created_at'))
    return get_report(saved['id'])


def get_report(report_id):
    if not isinstance(report_id,str) or not REPORT_ID.fullmatch(report_id):
        raise ValueError('Noto‘g‘ri hisobot identifikatori.')
    path=REPO_RUNS/(report_id+'.json')
    if not path.is_file():
        raise ValueError('Hisobot topilmadi.')
    report=json.loads(path.read_text(encoding='utf-8'))
    # Imported here because triage writes through this module; a module-level
    # import would be a cycle.
    from . import triage
    return triage.attach('repository',report.get('profile_id'),report)


def list_reports(profile_id=None,limit=30):
    if profile_id is not None:
        profile_for(profile_id)
    from . import run_index
    # Reports sit flat as <id>.json next to reviews.json; get_report() rejects any
    # name that is not a report id, so those files never enter the index.
    rows=run_index.rows(REPO_RUNS,('id','profile_id','created_at','repository','summary','input_sha256'),
                        get_report,limit=10**6,flat=True)
    if profile_id is not None:
        rows=[row for row in rows if row.get('profile_id')==profile_id]
    return rows[:limit]


def read_reviews():
    path=REPO_RUNS/'reviews.json'
    return json.loads(path.read_text(encoding='utf-8')) if path.exists() else {}


def save_review(payload):
    import datetime
    allowed={'report_id','fingerprint','status','owner','note'}
    if not isinstance(payload,dict) or set(payload)!=allowed or not all(isinstance(v,str) for v in payload.values()):
        raise ValueError('Review maydonlari noto‘g‘ri.')
    if payload['status'] not in {'new','investigating','accepted_risk','false_positive'}:
        raise ValueError('Review holati noto‘g‘ri.')
    if len(payload['owner'])>120 or len(payload['note'])>1000:
        raise ValueError('Review matni juda uzun.')
    if payload['status']!='new' and (not payload['owner'].strip() or not payload['note'].strip()):
        raise ValueError('Qaror uchun mas’ul va asos kerak.')
    report=get_report(payload['report_id'])
    if not any(f['fingerprint']==payload['fingerprint'] for f in report['findings']):
        raise ValueError('Topilma ushbu hisobotga tegishli emas.')
    # Bind manual review to the exact input snapshot. A new source revision needs renewed review.
    key=report['input_sha256']+':'+payload['fingerprint']
    reviews=read_reviews()
    reviews[key]={**payload,'updated_at':datetime.datetime.now(datetime.timezone.utc).isoformat()}
    write_json(REPO_RUNS/'reviews.json',reviews)
    return reviews[key]


def compare_reports(before,after):
    left={f['fingerprint']:f for f in before['findings']}
    right={f['fingerprint']:f for f in after['findings']}
    if before.get('profile_id')!=after.get('profile_id') or before['profile']!=after['profile']:
        raise ValueError('Turli profil/qamrovdagi hisobotlarni solishtirib bo‘lmaydi.')
    return {'before':before['id'],'after':after['id'],'added':sorted(right.keys()-left.keys()),
            'absent':sorted(left.keys()-right.keys()),'unchanged':sorted(left.keys()&right.keys()),
            'caution':'Yo‘qolgan topilma faqat joriy statik qamrovda ko‘rinmaydi; avtomatik ravishda tuzatilgan deb hisoblanmaydi.',
            'coverage_changed':before.get('unknowns')!=after.get('unknowns') or {f['path'] for f in before['files']}!={f['path'] for f in after['files']}}


def remove_project(profile_id):
    """Drop a registered Compose profile. Bundled samples stay; reports stay."""
    if not isinstance(profile_id,str) or not PROFILE_ID.fullmatch(profile_id) or profile_id in ALLOWED_PROFILES:
        raise ValueError('Bu repository profilini o‘chirib bo‘lmaydi.')
    path=LOCAL_PROFILES/f'{profile_id}.json'
    if not path.is_file():
        raise ValueError('Bunday ro‘yxatdagi repository profili yo‘q.')
    path.unlink()
    return {'id':profile_id,'removed':True,'note':'Manba papkasiga tegilmadi; oldingi hisobotlar tarixda qoldi.'}
