"""Read-only OSV matching and CISA KEV enrichment. Never send source or credentials."""
from concurrent.futures import ThreadPoolExecutor, as_completed
import datetime
import hashlib
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from .engine import ROOT
from . import nettrust, repo_store, taxonomy, threatfeeds, findings as findings_mod

_SSL_CONTEXT = nettrust.ssl_context()

CACHE=ROOT/'advisory-cache'
OSV='https://api.osv.dev/v1/'
KEV='https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json'
ADVISORY_ID=re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.:-]{1,159}$')
TTL=24*60*60
ADVISORY_DETAIL_LIMIT=50000


def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()


class FeedError(ValueError):pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):raise FeedError('unexpected_feed_redirect')


def fetch(url,payload=None,salt=''):
    if not (url in (OSV+'querybatch',KEV) or url.startswith(OSV+'vulns/') and ADVISORY_ID.fullmatch(url[len(OSV+'vulns/'):])):
        raise FeedError('feed_url_not_allowed')
    request_bytes=json.dumps(payload,separators=(',',':')).encode() if payload is not None else None
    key=hashlib.sha256((url+json.dumps(payload,sort_keys=True)+salt).encode()).hexdigest()
    path=CACHE/(key+'.json')
    try:
        cached=json.loads(path.read_text(encoding='utf-8'))
        age=time.time()-cached['stored_at']
        if 0<=age<TTL:return cached['data'],{'retrieved_at':cached['retrieved_at'],'cache':'fresh','url':url}
    except (OSError,ValueError,TypeError,KeyError):pass
    request=urllib.request.Request(url,data=request_bytes,headers={'Content-Type':'application/json','Accept':'application/json','User-Agent':'Zanjir/0.4'})
    # Ambient proxy settings are not used unless the operator opts in
    # (THREATCHAIN_USE_PROXY, see nettrust); user auth headers never are.
    opener=urllib.request.build_opener(nettrust.proxy_handler(),NoRedirect(),urllib.request.HTTPSHandler(context=_SSL_CONTEXT))
    for attempt in range(2):
        try:
            with opener.open(request,timeout=20) as response:
                raw=response.read(8*1024*1024+1)
                if len(raw)>8*1024*1024:raise FeedError('feed_response_too_large')
                data=json.loads(raw)
            stamp=now()
            repo_store.write_json(path,{'stored_at':time.time(),'retrieved_at':stamp,'data':data})
            return data,{'retrieved_at':stamp,'cache':'network','url':url}
        except urllib.error.HTTPError as error:
            if attempt==0 and error.code in {429,500,502,503,504}:time.sleep(1);continue
            raise FeedError('feed_http_'+str(error.code)) from None
        except (urllib.error.URLError,TimeoutError,OSError,json.JSONDecodeError):
            if attempt==0:time.sleep(1);continue
            raise FeedError('feed_unavailable_or_invalid_json') from None


def query_packages(packages,fetcher=fetch,progress=None):
    keys=sorted({(p['ecosystem'],p['name'],p['version']) for p in packages})
    matches={};errors=[];provenance=[];modified={}
    for start in range(0,len(keys),50):
        pending=[(key,None,[]) for key in keys[start:start+50]]
        for page in range(20):
            if not pending:break
            queries=[{'package':{'ecosystem':key[0],'name':key[1]},'version':key[2],**({'page_token':token} if token else {})} for key,token,_ in pending]
            try:
                data,meta=fetcher(OSV+'querybatch',{'queries':queries});provenance.append(meta)
                values=data.get('results')
                if not isinstance(values,list) or len(values)!=len(pending):raise FeedError('osv_batch_shape_invalid')
                following=[]
                for (key,token,previous),value in zip(pending,values):
                    if not isinstance(value,dict):raise FeedError('osv_result_invalid')
                    vulns=value.get('vulns',[])
                    if not isinstance(vulns,list):raise FeedError('osv_vulns_invalid')
                    ids=[]
                    for vuln in vulns:
                        vid=vuln.get('id') if isinstance(vuln,dict) else None
                        if not isinstance(vid,str) or not ADVISORY_ID.fullmatch(vid):raise FeedError('osv_id_invalid')
                        ids.append(vid);modified[vid]=str(vuln.get('modified',''))
                    collected=list(dict.fromkeys(previous+ids))
                    next_token=value.get('next_page_token')
                    if next_token:
                        if not isinstance(next_token,str) or len(next_token)>4096 or next_token==token:raise FeedError('osv_pagination_invalid')
                        following.append((key,next_token,collected))
                    else:matches[key]=collected
                pending=following
            except (FeedError,AttributeError,TypeError):
                errors.extend({'package':list(key),'reason':'osv_query_incomplete'} for key,_,_ in pending)
                pending=[];break
        if pending:errors.extend({'package':list(key),'reason':'osv_pagination_limit'} for key,_,_ in pending)
        if progress:progress('OSV: '+str(min(start+50,len(keys)))+'/'+str(len(keys))+' paket tekshirildi')
    ids=sorted({vid for values in matches.values() for vid in values});details={}
    # Every matched advisory is fetched: a finding without its record has no
    # severity, so cutting the list at 1 500 (alphabetically) left thousands of
    # vulnerable packages of a large project out of the report. Records are
    # cached for a day, so only the first scan pays for them.
    if len(ids)>ADVISORY_DETAIL_LIMIT:
        errors.append({'reason':'advisory_detail_limit','skipped':len(ids)-ADVISORY_DETAIL_LIMIT});ids=ids[:ADVISORY_DETAIL_LIMIT]
    def detail(vid):
        data,meta=fetcher(OSV+'vulns/'+vid,salt=modified.get(vid,''))
        if not isinstance(data,dict) or data.get('id')!=vid:raise FeedError('advisory_id_mismatch')
        return vid,data,meta
    pool=ThreadPoolExecutor(max_workers=8)
    try:
        futures={pool.submit(detail,vid):vid for vid in ids}
        for completed,future in enumerate(as_completed(futures),1):
            try:
                vid,data,meta=future.result();details[vid]=data;provenance.append(meta)
            except (FeedError,OSError,ValueError,TypeError):errors.append({'advisory':futures[future],'reason':'advisory_detail_unavailable'})
            if progress:progress('Zaiflik tavsiflari: '+str(completed)+'/'+str(len(ids)))
    finally:
        pool.shutdown(wait=True,cancel_futures=True)
    return matches,details,errors,provenance


def kev_catalog(fetcher=fetch):
    try:
        doc,meta=fetcher(KEV)
        if not isinstance(doc,dict) or not isinstance(doc.get('vulnerabilities'),list):raise FeedError('kev_invalid')
        rows={row['cveID']:row for row in doc['vulnerabilities'] if isinstance(row,dict) and re.fullmatch(r'CVE-\d{4}-\d{4,}',str(row.get('cveID','')))}
        if not rows:raise FeedError('kev_empty')
        return rows,{'state':'available','catalog_version':str(doc.get('catalogVersion','')),'date_released':str(doc.get('dateReleased','')),**meta}
    except (FeedError,TypeError,KeyError):return {},{'state':'unavailable','url':KEV}


CVSS3={'AV':{'N':0.85,'A':0.62,'L':0.55,'P':0.2},'AC':{'L':0.77,'H':0.44},'UI':{'N':0.85,'R':0.62},
       'C':{'H':0.56,'L':0.22,'N':0.0},'I':{'H':0.56,'L':0.22,'N':0.0},'A':{'H':0.56,'L':0.22,'N':0.0}}
CVSS3_PR={'U':{'N':0.85,'L':0.62,'H':0.27},'C':{'N':0.85,'L':0.68,'H':0.5}}


def cvss3_base(vector):
    """CVSS v3.x base score from its vector string, or None when it is not one.

    The published formula (FIRST, CVSS v3.1 section 7.1), nothing estimated.
    """
    parts=dict(item.split(':',1) for item in str(vector or '').split('/') if ':' in item)
    if not str(parts.get('CVSS','')).startswith('3'):return None
    try:
        scope=parts['S'];privileges=CVSS3_PR[scope][parts['PR']]
        weight={key:CVSS3[key][parts[key]] for key in CVSS3}
    except KeyError:return None
    iss=1-(1-weight['C'])*(1-weight['I'])*(1-weight['A'])
    impact=6.42*iss if scope=='U' else 7.52*(iss-0.029)-3.25*(iss-0.02)**15
    if impact<=0:return 0.0
    exploitability=8.22*weight['AV']*weight['AC']*privileges*weight['UI']
    raw=min(impact+exploitability,10) if scope=='U' else min(1.08*(impact+exploitability),10)
    scaled=round(raw*100000)
    return scaled/100000.0 if scaled%10000==0 else (scaled//10000+1)/10.0


def cvss_rating(record):
    """A severity word from the record's own CVSS v3 vector, or None.

    GitHub advisories carry `database_specific.severity`; Go, RustSec and PyPA
    records often carry only the vector. Reading nothing there left real
    criticals `UNKNOWN`, which no gate counts.
    """
    best=None
    for entry in record.get('severity') or []:
        if isinstance(entry,dict) and str(entry.get('type','')).upper()=='CVSS_V3':
            score=cvss3_base(entry.get('score'))
            if score is not None and (best is None or score>best):best=score
    if best is None or best<=0:return None
    return 'CRITICAL' if best>=9 else 'HIGH' if best>=7 else 'MEDIUM' if best>=4 else 'LOW'


def clean_text(value,limit=1500):
    return ''.join(c for c in str(value or '') if c.isprintable() or c in '\n\t')[:limit]


def normalize(packages,matches,details,kev,kev_available):
    occurrences={}
    for row in packages:occurrences.setdefault((row['ecosystem'],row['name'],row['version']),[]).append(row)
    findings=[]
    for key,ids in matches.items():
        # Join aliases within this exact component/version, never across assets.
        groups=[]
        for vid in ids:
            record=details.get(vid)
            if not record or record.get('withdrawn'):continue
            aliases={vid}|{x for x in record.get('aliases',[]) if isinstance(x,str) and ADVISORY_ID.fullmatch(x)}
            touching=[g for g in groups if g['aliases']&aliases]
            group={'aliases':aliases,'records':[record]}
            for old in touching:
                group['aliases']|=old['aliases'];group['records']+=old['records'];groups.remove(old)
            groups.append(group)
        for group in groups:
            aliases=sorted(group['aliases']);cves=[v for v in aliases if re.fullmatch(r'CVE-\d{4}-\d{4,}',v)]
            records=group['records'];matched_ids=sorted(r['id'] for r in records)
            # A newer advisory can alias an older CVE but have a different affected range.
            # Preserve exactly which records OSV matched, rather than label every alias a direct match.
            primary=cves[0] if len(cves)==1 else matched_ids[0]
            fixed=set();ratings=[];references=[];cwe_ids=set()
            for record in records:
                severity=str(record.get('database_specific',{}).get('severity','UNKNOWN')).upper()
                if severity in {'CRITICAL','HIGH','MODERATE','MEDIUM','LOW'}:ratings.append('MEDIUM' if severity=='MODERATE' else severity)
                else:
                    computed=cvss_rating(record)
                    if computed:ratings.append(computed)
                for raw_cwe in record.get('database_specific',{}).get('cwe_ids') or []:
                    match=re.fullmatch(r'CWE-(\d+)',str(raw_cwe))
                    if match:cwe_ids.add(int(match.group(1)))
                for affected in record.get('affected',[]):
                    pkg=affected.get('package',{})
                    if pkg.get('ecosystem')!=key[0] or pkg.get('name','').lower().replace('_','-')!=key[1].lower().replace('_','-'):continue
                    for interval in affected.get('ranges',[]):
                        for event in interval.get('events',[]):
                            if isinstance(event.get('fixed'),str):fixed.add(clean_text(event['fixed'],120))
                references.append('https://osv.dev/vulnerability/'+record['id'])
            rank={'UNKNOWN':0,'LOW':1,'MEDIUM':2,'HIGH':3,'CRITICAL':4}
            severity=max(ratings,key=lambda v:rank[v]) if ratings else 'UNKNOWN'
            exploited=any(cve in kev for cve in cves)
            priority='P1' if exploited or severity=='CRITICAL' else 'P2' if severity=='HIGH' else 'P3' if severity in {'MEDIUM','LOW'} else 'REVIEW'
            finding={'id':hashlib.sha256(json.dumps([list(key),primary]).encode()).hexdigest()[:24],
                     # `id` keeps its own value and its own field list: the saved
                     # reviews are keyed by it. `fingerprint` is the shared identity
                     # every scanner now carries -- it leaves the version out, so a
                     # dependency bump does not present the same advisory as new.
                     'fingerprint':findings_mod.fingerprint('dependencies',
                                                            {'ecosystem':key[0],'package':key[1],'advisory_id':primary}),
                     'family':'dependency','package':{'ecosystem':key[0],'name':key[1],'version':key[2]},
                     'advisory_id':primary,'aliases':aliases,'matched_advisory_ids':matched_ids,'severity':severity,'priority':priority,
                     'alias_note':'Aliases manbadagi bog‘langan identifikatorlar; har bir alias ushbu versiyaga alohida mos kelishi tekshirilmagan.',
                     'priority_reason':'KEV: real hujumlarda ishlatilishi ma’lum' if exploited else 'Manba og‘irlik bahosi; tizimga amaliy ta’sir hali baholanmagan',
                     'known_exploited':exploited if kev_available else None,
                     'state':'advisory_match','summary':clean_text(next((r.get('summary') for r in records if r.get('summary')),primary)),
                     'fixed_versions':sorted(fixed),'references':sorted(set(references)),
                     'occurrences':occurrences[key],'cwe_ids':sorted(f'CWE-{c}' for c in cwe_ids),
                     'primary_cve':next((v for v in cves),None),'epss':None,
                     'verified':False,
                     'verification_note':'OSV/CISA KEV/NVD ma’lumoti bilan paket-versiya darajasida statik moslik; nishonda amalda ishlatilishi yoki ekspluatatsiya qilinishi tekshirilmagan. Mutaxassis qo‘lda ko‘rib chiqishi shart.',
                     'remediation':'Manbada ko‘rsatilgan tuzatilgan versiya shoxini tekshiring, yangilang va funksional sinov hamda qayta skan bajaring.' if fixed else 'Ushbu javobda tuzatilgan versiya ko‘rsatilmagan. Ishlab chiqaruvchi tavsiyasi va vaqtinchalik chorani tekshiring.'}
            findings.append(finding)
    return sorted(findings,key=lambda f:({'P1':0,'P2':1,'P3':2,'REVIEW':3}[f['priority']],f['package']['name'],f['advisory_id']))


def enrich(findings,progress=None,nvd_budget=threatfeeds.NVD_BUDGET_DEFAULT):
    """Fill CWE gaps via a bounded NVD lookup, attach OWASP Top 10 tags and EPSS scores.

    Mutates and returns findings. Best-effort: any feed failure leaves a finding
    with fewer tags, never raises, and never marks a static match as verified.
    """
    missing=sorted({f['primary_cve'] for f in findings if not f['cwe_ids'] and f.get('primary_cve') and re.fullmatch(r'CVE-\d{4}-\d{4,}',f['primary_cve'])})
    if missing:
        if progress:progress('NVD orqali qo‘shimcha CWE qidirilmoqda (cheklangan so‘rov)')
        fetched=threatfeeds.enrich_cwe(missing,budget=nvd_budget)
        for f in findings:
            if not f['cwe_ids'] and f.get('primary_cve') in fetched:
                f['cwe_ids']=sorted(f'CWE-{c}' for c in fetched[f['primary_cve']])
    all_cves=sorted({alias for f in findings for alias in f['aliases'] if re.fullmatch(r'CVE-\d{4}-\d{4,}',alias)})
    if all_cves:
        if progress:progress('EPSS ekspluatatsiya ehtimoli olinmoqda')
        try:scores=threatfeeds.epss_scores(all_cves)
        except Exception:scores={}
    else:scores={}
    for f in findings:
        f['owasp_top10_2025']=taxonomy.classify(f['cwe_ids'])
        best=None
        for alias in f['aliases']:
            row=scores.get(alias)
            if row and (best is None or row['epss']>best['epss']):best=row
        f['epss']=best
    return findings
