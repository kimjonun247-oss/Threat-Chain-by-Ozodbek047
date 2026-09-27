"""Dependency jobs, scoped review and exports for a local single-user pilot."""
import collections
import datetime
import json
from pathlib import Path
import threading
import uuid
from .engine import ROOT, DATA
from . import inventory, advisories, scanners, repo_store, run_index, triage, fixes
from . import verification as verification_mod

RUNS=DATA/'dependency-runs'
LOCK=threading.Lock()
REVIEW_LOCK=threading.Lock()
CANCEL={}


def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()


def read(rid):
    report=run_index.read(RUNS,rid,'Hisobot topilmadi.')
    return triage.attach('dependencies',report.get('target'),report)


def history(target=None,limit=30):
    # Filtering happens after the cache so one cache serves every target.
    rows=run_index.rows(RUNS,('id','target','created_at','state','count','inventory_sha256'),read,limit=10**6)
    if target:rows=[row for row in rows if row.get('target')==target]
    return rows[:limit]


def execute(rid):
    report=None;folder=RUNS/rid
    def save():repo_store.write_json(folder/'report.json',report)
    def progress(message):
        if CANCEL[rid].is_set():raise InterruptedError('Tekshiruv bekor qilindi.')
        report['progress']=message;save()
    try:
        report=read(rid)
        report['state']='running';progress('Kutubxona ro‘yxati yig‘ilmoqda')
        # A remote repository is cloned for this scan only and removed after the
        # inventory is read; the manifests are copied into inventory.json first.
        with scanners.source_for(report['target']) as (root,provenance):
            collected=inventory.collect(root)
            manifest_texts=fixes.read_manifests(root)
        report['source']=provenance
        repo_store.write_json(folder/'inventory.json',collected)
        report.update(inventory_sha256=collected['sha256'],coverage={k:v for k,v in collected.items() if k!='packages'})
        if not collected['packages']:
            report.update(state='no_supported_packages',progress='Qo‘llanadigan aniq versiyali paket topilmadi')
        else:
            progress('OSV bazasi bilan solishtirilmoqda')
            matches,details,errors,provenance=advisories.query_packages(collected['packages'],progress=progress)
            progress('CISA KEV ustuvorlik ma’lumotlari olinmoqda')
            kev,kev_meta=advisories.kev_catalog()
            findings=advisories.normalize(collected['packages'],matches,details,kev,kev_meta['state']=='available')
            advisories.enrich(findings,progress=progress)
            progress('Tuzatish rejasi: maqsad versiyalar OSV’da qayta tekshirilmoqda')
            report['fix_plan']=fixes.dependency_plan(findings,manifest_texts,advisories.query_packages)
            report.update(findings=findings,count=len(findings),query_errors=errors,
                          feeds={'osv':{'checked_packages':len(matches),'requested_packages':collected['unique_packages'],
                                        'responses':len(provenance),'oldest_retrieved_at':min((p['retrieved_at'] for p in provenance),default=None),
                                        'cache_ttl_hours':24},'kev':kev_meta},
                          priority_counts=dict(collections.Counter(row['priority'] for row in findings)),
                          verification_summary=verification_mod.summarize(findings))
            repo_store.write_json(folder/'feed-provenance.json',provenance)
            report['state']='partial' if errors or collected['gaps'] or kev_meta['state']!='available' else 'completed'
            report['progress']='Tekshiruv tugadi; qamrovdagi cheklovlarni ko‘ring' if report['state']=='partial' else 'Belgilangan qamrovda tekshiruv tugadi'
    except InterruptedError:report.update(state='cancelled',progress='Bekor qilindi; qisman ma’lumot xavfsizlik xulosasi emas')
    except Exception as error:
        if report is not None:
            report.update(state='failed',error_type=type(error).__name__,progress='Tekshiruv tugallanmadi; bu toza natija emas')
            if isinstance(error,PermissionError):report['message']='Windows faylga kirishni rad etdi. Hisobot papkasi ruxsatlarini va parallel jarayonlarni tekshiring.'
            if isinstance(error,ValueError):report['message']=str(error)[:300]
    finally:
        try:
            if report is not None:
                report['finished_at']=now();save();triage.record_scan('dependencies',report)
        finally:CANCEL.pop(rid,None);LOCK.release()
    return report


def start(target,background=True):
    scanners.check_target(target)
    if not LOCK.acquire(blocking=False):raise ValueError('Boshqa kutubxona tekshiruvi davom etmoqda.')
    rid=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S')+'-'+uuid.uuid4().hex[:8]
    CANCEL[rid]=threading.Event()
    try:
        repo_store.write_json(RUNS/rid/'report.json',{'schema_version':1,'id':rid,'target':target,'created_at':now(),
                             'state':'queued','count':0,'findings':[],
                             'limits':'OSV/NVD/CISA KEV paket/versiya mosligi amaliy hujum tasdig‘i emas. Qamrov, conditional/dev paketlar va ishlayotgan tizimga moslik qo‘lda tekshiriladi.',
                             'data_policy':'OSV, NVD va EPSS ga faqat paket nomi, ecosystem, versiya yoki CVE ID yuboriladi. Kod, fayl yo‘li, token yuborilmaydi. Bu tekshiruv doim internetga ulangan holda ishlaydi; offline/faqat-inventar rejim mavjud emas.'})
    except Exception:CANCEL.pop(rid,None);LOCK.release();raise
    if background:
        threading.Thread(target=execute,args=(rid,),daemon=True).start()
        return {'id':rid,'state':'queued'}
    return execute(rid)


def cancel(rid):
    read(rid)
    if rid not in CANCEL:raise ValueError('Bu jarayon ushbu serverda ishlamayapti.')
    CANCEL[rid].set()
    return {'id':rid,'state':'cancellation_requested'}


def read_inventory(rid):
    read(rid)
    try:return json.loads((RUNS/rid/'inventory.json').read_text(encoding='utf-8'))
    except (OSError,ValueError):raise ValueError('Inventar hali tayyor emas.') from None


def reviews(rid):
    report=read(rid)
    try:data=json.loads((RUNS/rid/'reviews.json').read_text(encoding='utf-8'))
    except FileNotFoundError:return {}
    except (OSError,ValueError):raise ValueError('Review faylini o‘qib bo‘lmadi.') from None
    if not isinstance(data,dict):raise ValueError('Review formati noto‘g‘ri.')
    if data.get('inventory_sha256')!=report.get('inventory_sha256'):return {}
    return data.get('findings',{})


def review(payload):
    if not isinstance(payload,dict) or set(payload)!={'report_id','finding_id','status','owner','note'} or not all(isinstance(v,str) for v in payload.values()):
        raise ValueError('Review maydonlari noto‘g‘ri.')
    if payload['status'] not in {'investigating','accepted_risk','false_positive','fix_planned'}:raise ValueError('Review holati noto‘g‘ri.')
    if not 1<=len(payload['owner'].strip())<=120 or not 1<=len(payload['note'].strip())<=1000:
        raise ValueError('Qaror uchun mas’ul (120 gacha) va asos (1000 gacha) kerak.')
    report=read(payload['report_id'])
    if not any(row['id']==payload['finding_id'] for row in report['findings']):raise ValueError('Topilma ushbu hisobotga tegishli emas.')
    row={key:payload[key] for key in ('status','owner','note')};row['updated_at']=now()
    with REVIEW_LOCK:
        current=reviews(report['id']);current[payload['finding_id']]=row
        audit_id=uuid.uuid4().hex
        repo_store.write_json(RUNS/report['id']/'review-events'/(audit_id+'.json'),
                             {'event_id':audit_id,'finding_id':payload['finding_id'],'inventory_sha256':report['inventory_sha256'],**row})
        repo_store.write_json(RUNS/report['id']/'reviews.json',{'inventory_sha256':report['inventory_sha256'],'findings':current})
    return row


def compare(before,after):
    if before['target']!=after['target']:
        raise ValueError('Bir xil loyihaning ikkita hisoboti kerak.')
    if before['state'] not in {'completed','partial'} or after['state'] not in {'completed','partial'}:
        raise ValueError('Faqat tugagan hisobotlarni solishtirish mumkin.')
    left={row['id'] for row in before['findings']};right={row['id'] for row in after['findings']}
    return {'before':before['id'],'after':after['id'],'added':sorted(right-left),'absent':sorted(left-right),'unchanged':sorted(left&right),
            'inventory_changed':before.get('inventory_sha256')!=after.get('inventory_sha256'),
            'coverage_incomplete':before['state']=='partial' or after['state']=='partial',
            'note':'Joriy hisobotda yo‘qlik tuzatish tasdig‘i emas: paket versiyasi, qamrov yoki bazadagi ma’lumot o‘zgargan bo‘lishi mumkin.'}


def markdown(report):
    def cell(value):return str(value).replace('|','\\|').replace('\n',' ').replace('\r',' ')
    verification=verification_mod.summarize(report.get('findings',[]))
    lines=['# Zanjir — kutubxonalar tekshiruvi','',f"Loyiha: {cell(report['target'])}",f"Hisobot: {report['id']}",
           f"Vaqt: {report['created_at']}",f"Holat: {report['state']}",'',report['limits'],'',
           f"Tasdiqlash: {verification['confirmed_by_evidence']} dalil bilan tasdiqlangan / "
           f"{verification['manual_review_required']} qo‘lda tekshirish talab qiladi (jami {verification['total']}).",'',
           '| Ustuvorlik | Paket | Versiya | Zaiflik | Og‘irlik | CWE | OWASP Top 10 | EPSS | Tuzatilgan versiyalar |',
           '|---|---|---|---|---|---|---|---|---|']
    for row in report['findings']:
        owasp=', '.join(o['code'] for o in row.get('owasp_top10_2025') or []) or '—'
        epss=f"{row['epss']['epss']*100:.1f}%" if row.get('epss') else '—'
        lines.append('| '+' | '.join(cell(v) for v in (row['priority'],row['package']['name'],row['package']['version'],row['advisory_id'],row['severity'],
                     ', '.join(row.get('cwe_ids') or []) or '—',owasp,epss,', '.join(row['fixed_versions']) or 'Manbada yo‘q'))+' |')
    lines+=['','Qamrov: '+cell(report.get('coverage',{}).get('scope','Inventar tayyor emas')),
            'Qamrov bo‘shliqlari: '+str(len(report.get('coverage',{}).get('gaps',[]))),
            'So‘rov xatolari: '+str(len(report.get('query_errors',[]))),
            'KEV holati: '+str(report.get('feeds',{}).get('kev',{}).get('state','Tekshirilmagan'))]
    return '\n'.join(lines)+'\n'
