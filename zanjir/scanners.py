"""Local, bounded source scanning; never execute project code or persist snippets."""
import datetime
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import uuid

from vendor import yaml

from .engine import ROOT, DATA
from . import priority, repo_store, code_targets, taxonomy, custom_rules, run_index, baseline, findings as findings_mod, triage, verification as verification_mod

TOOLS=ROOT/'.tools'
RUNS=DATA/'scanner-runs'
RULES=ROOT/'scanner-rules'
# Vendored tools are bundled per platform: a Windows build (gitleaks.exe, a
# Scripts/ venv) and a POSIX build (a plain binary, a bin/ venv) live side by
# side under the same .tools/<tool> folder so neither platform's copy is disturbed.
# Functions (not constants) so they always reflect the current TOOLS value --
# tests patch TOOLS to point at a fixture directory.
IS_WINDOWS=sys.platform.startswith('win')


def semgrep_bin_dir():
    return TOOLS/'semgrep'/('Scripts' if IS_WINDOWS else 'posix/bin')


def semgrep_exe():
    return semgrep_bin_dir()/('semgrep.exe' if IS_WINDOWS else 'semgrep')


def gitleaks_exe():
    return TOOLS/'gitleaks'/('gitleaks.exe' if IS_WINDOWS else 'gitleaks')


def pmd_exe():
    """PMD's launcher, installed by setup_pmd.py. Optional: only Apex needs it."""
    return TOOLS/'pmd'/'bin'/('pmd.bat' if IS_WINDOWS else 'pmd')


APEX_SUFFIXES=('.cls','.trigger')
# PMD fills some rule messages with names from the scanned code. As with the
# Semgrep pack, the report carries fixed wording per rule instead, so nothing
# from the project can reach a downloadable report through this field.
PMD_MESSAGES={
    'ApexBadCrypto':'Shifrlash kaliti yoki IV kodda qattiq yozilgan.',
    'ApexCRUDViolation':'Ma’lumotga yozish/o‘qishdan oldin CRUD/FLS ruxsati tekshirilmagan.',
    'ApexDangerousMethods':'Xavfli metod chaqirilgan (masalan, sozlamalarni o‘zgartirish yoki debug chiqishi).',
    'ApexInsecureEndpoint':'Tashqi manzilga shifrlanmagan HTTP orqali murojaat.',
    'ApexOpenRedirect':'Foydalanuvchi bergan manzilga tekshiruvsiz yo‘naltirish (open redirect).',
    'ApexSharingViolations':'DML/SOQL bajaradigan klassda sharing modeli e’lon qilinmagan.',
    'ApexSOQLInjection':'Tekshirilmagan qiymat dinamik SOQL/DML so‘roviga qo‘shilgan (SOQL injection).',
    'ApexSuggestUsingNamedCred':'Autentifikatsiya ma’lumoti kodda; Named Credentials ishlatilmagan.',
    'ApexXSSFromEscapeFalse':'Chiqishda escape o‘chirilgan (XSS).',
    'ApexXSSFromURLParam':'URL parametri tekshiruvsiz sahifaga chiqarilgan (XSS).',
}


def has_apex(source):
    """PMD starts a JVM, so it runs only when the snapshot actually holds Apex."""
    for path in Path(source).rglob('*'):
        if path.suffix in APEX_SUFFIXES and path.is_file():
            return True
    return False


def semgrep_registry():
    """Official semgrep-rules pack installed by setup_semgrep_rules.py.

    Optional on purpose: without it the scan still runs on this project's own
    seven local rules, so an installation that never fetched the pack keeps
    working exactly as before.
    """
    return RULES/'semgrep-registry'


def merged_rules():
    """The whole pack as one file, which is how Semgrep reads it fastest.

    Semgrep's own profiling on this pack: 36s of `config_time` reading 1327
    separate files against 6s reading one, for byte-identical findings (checked
    on both the bundled sample and crAPI). The individual files stay on disk and
    remain what the manifest hashes.
    """
    return RULES/'semgrep-merged.yml'


def registry_manifest(cached=False):
    """Manifest of the installed pack, or None when it is not installed.

    cached=True (status views only) reuses the last full verification while no
    rule file's size or mtime has changed; hashing 1327 files on every dashboard
    request was a third of its time. A scan always verifies every hash.
    """
    if cached:
        # The manifest and the merged file are what an install or a re-install
        # rewrites, and the merged file is what a scan actually loads; walking
        # 1327 rule files for a status line cost 45 ms per dashboard request.
        root=semgrep_registry()
        signature=(repo_store.folder_signature(root),repo_store.folder_signature(merged_rules().parent))
        return repo_store.memo(('registry_manifest',str(root)),signature,registry_manifest)
    return _verify_registry_manifest()


def _verify_registry_manifest():
    """Full check: every rule file against its recorded SHA-256.

    Raises ValueError when the manifest is present but a rule file on disk no
    longer matches its recorded SHA-256: rules decide what a scan can find, so a
    silently edited rule file would silently shrink coverage.
    """
    path=semgrep_registry()/'manifest.json'
    if not path.is_file():
        # Rule files without a manifest means an install was interrupted. Reading
        # that as "no pack installed" would quietly drop a scan back to seven
        # local rules while everything still looked healthy.
        if semgrep_registry().is_dir() and any(semgrep_registry().glob('*/')):
            raise ValueError('Semgrep qoida paketi chala o‘rnatilgan (manifest yo‘q). '
                             'python3 setup_semgrep_rules.py --force bilan qayta o‘rnating.')
        return None
    try:manifest=json.loads(path.read_text(encoding='utf-8'))
    except ValueError:raise ValueError('Semgrep qoida manifesti o‘qilmadi.')
    for entry in manifest.get('entries',[]):
        rule=semgrep_registry()/entry['file']
        if not rule.is_file():raise ValueError('Semgrep qoida fayli yo‘q: '+entry['file'])
        if hashlib.sha256(rule.read_bytes()).hexdigest()!=entry['sha256']:
            raise ValueError('Semgrep qoida fayli o‘zgargan: '+entry['file'])
    merged=manifest.get('merged')
    if merged:
        # The merged file is what the scan actually loads, so it is hashed too --
        # editing it alone would change results without touching any source file.
        path=merged_rules()
        if not path.is_file():raise ValueError('Birlashtirilgan qoida fayli yo‘q: '+merged['file'])
        if hashlib.sha256(path.read_bytes()).hexdigest()!=merged['sha256']:
            raise ValueError('Birlashtirilgan qoida fayli o‘zgargan: '+merged['file'])
    return manifest
LOCK=threading.Lock()
ID=run_index.RUN_ID  # one definition shared by every scanner
EXCLUDED={'.git','.tools','.venv','venv','node_modules','vendor','__pycache__','scanner-runs','dependency-runs','image-runs','web-runs','assessment-runs','validation-runs','advisory-cache','repository-runs','runs','pilot','profiles'}
IGNORE_FILES={'.semgrepignore','.gitleaksignore','.gitleaks.toml'}
MAX_FILE=1024*1024
MAX_TOTAL=50*1024*1024


def write(path,data):
    repo_store.write_json(path,data)


def crapi_root():
    """Bundled copy first, so the demo keeps working when only this folder is moved.

    Order: explicit ZANJIR_CRAPI_ROOT, a copy inside the application folder,
    then the historical sibling checkout next to the application folder.
    """
    override=os.environ.get('ZANJIR_CRAPI_ROOT','').strip()
    # An explicit choice must not silently scan a different repository if missing.
    if override:
        return Path(override)
    candidates=[ROOT/'work/repositories/crapi-stable']
    candidates.append(ROOT.parents[1]/'work/repositories/crapi-stable')
    for candidate in candidates:
        try:
            if candidate.is_dir():return candidate
        except OSError:continue
    return candidates[-1]


def bundled_code_samples():
    """Bundled samples offered as source targets, keyed by id.

    crAPI is excluded because it already appears as 'crapi-full', which resolves
    through crapi_root() and its ZANJIR_CRAPI_ROOT override. The rest -- today
    only the synthetic chain demo -- live inside this folder, so a source scan of
    them needs no registration: without this, the cross-scanner chain (SX-001)
    could not be shown at all, since the bundled crAPI compose has no `build:`.
    """
    return {p['id']:p for p in repo_store.list_profiles()
            if p['mode']=='bundled_sample' and p['id']!='crapi'}


def targets():
    result=[{'id':'crapi-full','name':'OWASP crAPI · to‘liq manba nusxasi','available':crapi_root().is_dir()}]
    for pid,profile in sorted(bundled_code_samples().items()):
        result.append({'id':pid,'name':profile['name'],
                       'available':(ROOT/repo_store.profile_for(pid)['root']).is_dir()})
    code_ids={p['id'] for p in code_targets.profiles()}
    for profile in repo_store.list_profiles():
        # A Compose profile may share its id with a code registration; the code
        # registration (listed below) is then the source of truth for the root.
        if profile['mode']=='registered_local' and profile['id'] not in code_ids:
            result.append({'id':profile['id'],'name':profile['name'],'available':True})
    existing={row['id'] for row in result}
    # A remote repository has no local directory to test, so "available" means
    # "registered": whether the clone will succeed is only knowable at scan time,
    # and the scan says so plainly if it does not.
    result.extend({'id':p['id'],'name':p['name'],
                   'available':True if p.get('source')=='remote_git' else Path(p.get('root','')).is_dir(),
                   **({'source':'remote_git','url':p['url'],'ref':p.get('ref','')} if p.get('source')=='remote_git' else {})}
                  for p in code_targets.profiles() if p['id'] not in existing)
    return result


def target_root(target):
    if target=='crapi-full':path=crapi_root()
    elif target in bundled_code_samples():
        # A bundled root is stored relative to the application folder and has no
        # registered_root to compare against; containment is the check instead.
        path=(ROOT/repo_store.profile_for(target)['root']).resolve()
        if not path.is_relative_to(ROOT):raise ValueError('Namuna loyiha chegarasidan tashqarida.')
    elif remote_profile(target) is not None:
        # Only source_for() may resolve a remote repository (it clones and cleans
        # up). Reaching here used to raise KeyError('root') and crash callers.
        raise ValueError('Bu masofaviy git loyihasi; lokal papkasi yo‘q — skan vaqtida vaqtinchalik klonlanadi.')
    else:
        if target not in {item['id'] for item in targets()}:raise ValueError('Noma’lum loyiha.')
        profile=next((p for p in code_targets.profiles() if p['id']==target),None) or repo_store.profile_for(target)
        path=Path(profile['root'])
        if path.resolve()!=Path(profile['registered_root']).resolve():raise ValueError('Loyiha ro‘yxatidagi manba yo‘li o‘zgargan.')
    if not path.is_dir():
        # 'crapi-full' is the CLI default, and on a fresh clone its source is not
        # there (work/ is never committed). Name what can be scanned instead of
        # leaving the operator with a bare "folder missing".
        hint=''
        if target=='crapi-full':
            ready=[row['id'] for row in targets() if row.get('available') and row['id']!='crapi-full']
            hint=(' crAPI manbasi work/repositories/crapi-stable da yo‘q (yoki ZANJIR_CRAPI_ROOT o‘rnatilmagan).'
                  +(' Mavjud nishonlar: '+', '.join(ready)+' — --target bilan tanlang.' if ready else
                    ' O‘z loyihangizni --register <id> --repo <papka> bilan ro‘yxatga oling.'))
        raise ValueError('Loyihaning to‘liq manba papkasi mavjud emas.'+hint)
    return path.resolve()


def remote_profile(target):
    """The registration of a remote repository, or None for a local target."""
    return next((row for row in code_targets.profiles()
                 if row['id']==target and row.get('source')=='remote_git'),None)


def check_target(target):
    """Validate a target without fetching anything.

    target_root() cannot do this for a remote repository: it would have to clone
    first, and a pipeline that is only checking its own selection must not pull
    a repository over the network to find out whether the id is known.
    """
    if remote_profile(target) is not None:
        return
    target_root(target)


@contextmanager
def source_for(target):
    """Yield (path, provenance) for a local or a remote target.

    A remote repository is cloned into a temporary directory for the duration of
    the scan and removed afterwards, whether the scan succeeded or not.
    """
    profile=remote_profile(target)
    if profile is None:
        root=target_root(target)
        yield root,{'source_type':'local_directory','root':root.name,
                    'execution':'faqat o‘qish; hech qanday kod bajarilmaydi'}
        return
    from . import remote_source
    path,provenance=remote_source.clone(profile['url'],profile.get('ref',''))
    try:
        yield path,provenance
    finally:
        shutil.rmtree(path.parent,ignore_errors=True)


def environment(work,temp=None):
    env={k.upper():v for k,v in os.environ.items() if k.upper() in {'SYSTEMROOT','WINDIR','COMSPEC','PATH','PATHEXT','NUMBER_OF_PROCESSORS'}}
    home=work/'home'
    home.mkdir(exist_ok=True)
    temporary=temp if temp is not None else home
    # The Semgrep wrapper appends Scripts to PATH; an older global pysemgrep
    # would otherwise win when its native frontend invokes the Python frontend.
    env['PATH']=str(semgrep_bin_dir())+os.pathsep+env.get('PATH','')
    env.update(HOME=str(home),USERPROFILE=str(home),APPDATA=str(home),LOCALAPPDATA=str(home),TEMP=str(temporary),TMP=str(temporary),
               PYTHONUTF8='1',PYTHONIOENCODING='utf-8',SEMGREP_SEND_METRICS='off',SEMGREP_ENABLE_VERSION_CHECK='0',
               SEMGREP_SETTINGS_FILE=str(home/'semgrep-settings.yml'),OTEL_SDK_DISABLED='true',NO_COLOR='1')
    return env


@contextmanager
def scanner_environment(work):
    # OCaml's socketpair emulation (used on Windows) and real Unix domain
    # sockets (used by semgrep-core's IPC on macOS/Linux) both address through
    # a sun_path buffer capped at 108 bytes on Linux/Windows and 104 on macOS
    # -- TEMP plus a socket name must fit. Keep settings in the isolated work
    # folder, but scratch files in a short, unique OS temp directory. Only
    # this child-process environment is changed.
    parent=Path(tempfile.gettempdir()).resolve()
    with tempfile.TemporaryDirectory(prefix='zsg-',dir=parent) as temporary:
        path=Path(temporary).resolve()
        if path.parent!=parent:raise ValueError('Vaqtinchalik papka chegarasi noto‘g‘ri.')
        limit=104 if sys.platform=='darwin' else 108
        if len(str(path).encode('utf-8'))+30>=limit:
            raise ValueError('Vaqtinchalik papka yo‘li Semgrep uchun juda uzun.')
        yield environment(work,path)


def snapshot(source,destination):
    destination.mkdir()
    entries=[]
    skipped={'excluded':0,'links':0,'binary':0,'large':0}
    total=0
    def linked(path):
        info=path.lstat()
        return stat.S_ISLNK(info.st_mode) or bool(getattr(info,'st_file_attributes',0)&getattr(stat,'FILE_ATTRIBUTE_REPARSE_POINT',1024))
    for current,dirs,files in os.walk(source,followlinks=False):
        allowed=[]
        for name in sorted(dirs):
            path=Path(current)/name
            if name in EXCLUDED:skipped['excluded']+=1
            elif linked(path):skipped['links']+=1
            else:allowed.append(name)
        dirs[:]=allowed
        for name in sorted(files):
            path=Path(current)/name
            if name in IGNORE_FILES:skipped['excluded']+=1;continue
            if linked(path):skipped['links']+=1;continue
            if not path.resolve().is_relative_to(source):raise ValueError('Manba yo‘li loyiha chegarasidan chiqdi.')
            if path.stat().st_size>MAX_FILE:skipped['large']+=1;continue
            raw=path.read_bytes()
            if b'\0' in raw:skipped['binary']+=1;continue
            total+=len(raw)
            if total>MAX_TOTAL or len(entries)>=10000:raise ValueError('Loyiha 50 MB yoki 10000 fayl chegarasidan oshdi.')
            relative=path.relative_to(source)
            target=destination/relative
            target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes(raw)
            entries.append({'path':relative.as_posix(),'sha256':hashlib.sha256(raw).hexdigest()})
    if not entries:raise ValueError('Tekshiriladigan matn fayli topilmadi.')
    digest=hashlib.sha256(json.dumps(entries,sort_keys=True).encode()).hexdigest()
    return {'files':len(entries),'bytes':total,'snapshot_sha256':digest,'skipped':skipped,'manifest':entries,
            'scope':'Joriy matn fayllari (vendor/node_modules, binar va 1 MB dan katta fayllar kiritilmagan). Git tarixidagi sirlar Gitleaks bilan alohida tekshiriladi (.git bo‘lsa).'}


def tool_commands(work,registry=False,local=None,apex=False):
    # Semgrep accepts repeated --config: this project's own rules always run, the
    # official pack and the operator's own rules are layered on top only when
    # they exist. The pack is handed over as one merged file when the installer
    # produced it -- same rules, same findings, a fraction of the start-up cost.
    semgrep_config=['--config',str(RULES/'semgrep.yml')]
    if registry:semgrep_config+=['--config',str(merged_rules() if merged_rules().is_file() else semgrep_registry())]
    if local:semgrep_config+=['--config',str(local)]
    return {
        'semgrep':[str(semgrep_exe()),'scan',*semgrep_config,
                   '--metrics','off','--disable-version-check','--disable-nosem','--no-rewrite-rule-ids','--no-git-ignore','--json','--quiet','--jobs','2','--timeout','10','--max-target-bytes',str(MAX_FILE),'source'],
        'gitleaks':[str(gitleaks_exe()),'dir','source','--config',str(RULES/'gitleaks.toml'),
                    '--report-format','json','--report-path','-','--redact=100','--no-banner','--no-color','--ignore-gitleaks-allow',
                    '--gitleaks-ignore-path',str(RULES/'empty.ignore'),'--max-target-megabytes','1','--timeout','180'],
        # Apex only: OSS Semgrep cannot parse it, PMD's security ruleset can.
        **({'pmd':[str(pmd_exe()),'check','--dir','source','--rulesets','category/apex/security.xml',
                   '--format','json','--no-progress','--no-cache','--no-fail-on-violation']}
           if apex and pmd_exe().is_file() else {})}


HISTORY_COMMITS=2000


def history_secrets(source,current,env,work):
    """Secrets that are gone from the working tree but still in git history.

    The snapshot deliberately leaves .git out, so a token committed and then
    deleted in the next commit was never reported -- yet anyone with a clone can
    still read it. Gitleaks' own `git` mode reads the history (`git log -p`; no
    repository code or hook runs). Only what the working-tree scan did not
    already report is added. Returns (summary, findings).
    """
    if not (Path(source)/'.git').exists():
        return {'state':'not_applicable','note':'Manbada .git yo‘q (yoki sayoz klon) — git tarixi tekshirilmadi.'},[]
    if not gitleaks_exe().is_file():
        return {'state':'failed','note':'Gitleaks o‘rnatilmagan.'},[]
    command=[str(gitleaks_exe()),'git',str(source),'--config',str(RULES/'gitleaks.toml'),'--log-opts',f'--all --max-count={HISTORY_COMMITS}',
             '--report-format','json','--report-path','-','--redact=100','--no-banner','--no-color','--ignore-gitleaks-allow',
             '--max-target-megabytes','1','--timeout','180']
    history_env={**env,'GIT_CONFIG_COUNT':'1','GIT_CONFIG_KEY_0':'safe.directory','GIT_CONFIG_VALUE_0':str(source),
                 'GIT_TERMINAL_PROMPT':'0'}
    try:
        run_command,low=priority.gentle(command)
        process=subprocess.run(run_command,cwd=work,env=history_env,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=240,**low)
        if process.returncode not in (0,1):raise ValueError('gitleaks git kodi '+str(process.returncode))
        rows=json.loads(process.stdout or '[]')
        if not isinstance(rows,list):raise ValueError('gitleaks git natijasi noto‘g‘ri')
    except (OSError,ValueError,subprocess.TimeoutExpired) as error:
        return {'state':'failed','note':'Git tarixini o‘qib bo‘lmadi ('+type(error).__name__+').'},[]
    present={(f['path'],f['rule_id']) for f in current if f.get('tool')=='gitleaks'}
    found=[];seen=set()
    for row in rows:
        try:
            path=str(row['File']).replace('\\','/');rule=str(row['RuleID']);line=int(row['StartLine']);commit=str(row['Commit'])
        except (KeyError,TypeError,ValueError):continue
        if not path or path.startswith('/') or '..' in Path(path).parts or not re.fullmatch(r'[A-Za-z0-9_.-]{1,220}',rule) \
                or not re.fullmatch(r'[0-9a-f]{7,64}',commit):continue
        if (path,rule) in present:continue
        identity=findings_mod.fingerprint('gitleaks',{'rule_id':rule,'path':path,'column':int(row.get('StartColumn') or 0),
                                                      'entropy':row.get('Entropy')})
        if identity in seen:continue
        seen.add(identity)
        tags=taxonomy.tag_static('gitleaks',rule)
        found.append({'tool':'gitleaks','rule_id':rule,'path':path,'line':max(1,line),'fingerprint':identity,
                      'message':(f'Git tarixida qolgan sir (commit {commit[:12]}). Hozirgi fayllarda yo‘q, lekin repozitoriy '
                                 'nusxasi bor har kim uni o‘qiy oladi. Sirni bekor qiling (rotate) va tarixni tozalang.'),
                      'severity':None,'state':'unverified_static','secret_value':'hidden',
                      'history':{'commit':commit[:12],'date':str(row.get('Date') or '')[:25]},
                      'cwe_ids':tags['cwe_ids'],'owasp_top10_2025':tags['owasp_top10_2025'],'verified':False,
                      'verification_note':'Git tarixidagi statik moslik; sir hali amalda ekanini tekshiring.'})
    return {'state':'completed','commits_limit':HISTORY_COMMITS,'count':len(found),
            'note':'Faqat hozirgi fayllarda ko‘rinmaydigan tarixiy sirlar qo‘shildi.'},found


def path_in_snapshot(value,source):
    raw=str(value).replace('\\','/')
    path=Path(raw)
    if path.is_absolute():
        try:raw=path.resolve().relative_to(source.resolve()).as_posix()
        except ValueError:raise ValueError('Skaner natijasida tashqi fayl yo‘li bor.')
    elif raw.startswith('source/'):raw=raw[7:]
    if not raw or '..' in Path(raw).parts or ':' in raw:raise ValueError('Skaner natijasida noto‘g‘ri yo‘l bor.')
    if not (source/raw).is_file():raise ValueError('Natijadagi fayl manba nusxasida topilmadi.')
    return raw


def local_rule_count():
    """How many rules scanner-rules/semgrep.yml holds -- counted, never hard-coded."""
    try:
        text=(RULES/'semgrep.yml').read_text(encoding='utf-8')
    except OSError:
        return 0
    return len(re.findall(r'(?m)^  - id: ',text))


def rule_set_label(tool,manifest,own=0):
    if tool=='pmd':return 'PMD category/apex/security.xml (10 ta Apex xavfsizlik qoidasi)'
    if tool!='semgrep':return 'Gitleaks ichki qoidalari'
    parts=[f'ThreatChain {local_rule_count()} lokal qoida']
    if manifest:parts.append(f'{manifest["rules"]} rasmiy semgrep-rules qoidasi ({len(manifest["languages"])} til)')
    if own:parts.append(f'{own} ta o‘zingiz yozgan qoida')
    return ' + '.join(parts)


def error_kinds(errors):
    """Semgrep error counts grouped by kind, so a coverage gap stays legible.

    A bare error number cannot be acted on; "these files could not be parsed" and
    "this rule needs an engine we do not have" are different problems.
    """
    counts={}
    for item in errors:
        kind=item.get('type') if isinstance(item,dict) else None
        kind=kind if isinstance(kind,str) else 'Boshqa'
        counts[kind]=counts.get(kind,0)+1
    return dict(sorted(counts.items(),key=lambda pair:(-pair[1],pair[0])))


MAX_LISTED_FILES=40


def error_files(errors,source):
    """Unparsed files, grouped into categories an operator can act on.

    The stage still reports `partial` -- a file Semgrep could not read is a real
    coverage gap and is never presented as clean. What changes here is that the
    gap says which files and what to do about them. On any repository shipping a
    Helm chart the whole count is one known cause: everything under a chart's
    templates/ directory is a Go template, not YAML, so no YAML parser can read
    it. The remedy is to render the chart and scan the output, which a bare
    number like "36 xato" does not convey.
    """
    groups={}
    for item in errors:
        if not isinstance(item,dict):continue
        raw=str(item.get('path') or '').replace('\\','/')
        relative=raw.split('source/',1)[1] if 'source/' in raw else raw.rsplit('/',1)[-1]
        category='other'
        if '/templates/' in '/'+relative:
            try:
                if '{{' in (source/relative).read_text(encoding='utf-8',errors='replace')[:20000]:
                    category='helm_template'
            except OSError:
                pass
        group=groups.setdefault(category,{'files':[],'count':0})
        group['count']+=1
        if len(group['files'])<MAX_LISTED_FILES and relative not in group['files']:
            group['files'].append(relative)
    actions={'helm_template':'Bu fayllar Helm (Go) shabloni, YAML emas — hech bir YAML tahlilchisi ularni o‘qiy olmaydi. '
                             'Qamrovga kiritish uchun `helm template` bilan render qilib, natijani alohida loyiha sifatida tekshiring.',
             'other':'Fayl sintaksisi qo‘llanadigan tillarga mos kelmadi. Fayl turini va kodlanishini tekshiring.'}
    return {name:{**group,'files':sorted(group['files']),'action':actions[name]}
            for name,group in sorted(groups.items(),key=lambda pair:-pair[1]['count'])}


_MESSAGES={}


def clean_message(value):
    """One-line, bounded, control-character-free rule wording."""
    text=' '.join(str(value or '').split())
    text=''.join(ch for ch in text if ch.isprintable())
    return text[:400] if text else None


def registry_messages(manifest):
    """rule_id -> that rule's own wording, read from the SHA-verified rule files.

    Deliberately NOT taken from Semgrep's own output: Semgrep interpolates the
    matched source text into `extra.message` (for example the matched function
    name or a literal argument), which would carry scanned content -- possibly a
    real secret -- into a downloadable report. The rule file's text is fixed and
    contains only the rule author's wording, so nothing from the scanned project
    can reach the report through this field.
    """
    if not manifest:return {}
    key=manifest.get('commit')
    if key in _MESSAGES:return _MESSAGES[key]
    messages={}
    for entry in manifest.get('entries',[]):
        try:parsed=yaml.safe_load((semgrep_registry()/entry['file']).read_text(encoding='utf-8'))
        except (OSError,UnicodeDecodeError,yaml.YAMLError):continue
        for rule in (parsed or {}).get('rules') or []:
            if isinstance(rule,dict) and rule.get('id') and rule.get('message'):
                messages.setdefault(str(rule['id']),clean_message(rule['message']))
    _MESSAGES[key]=messages
    return messages


def local_messages():
    """This project's own rules keep their own wording too (scanner-rules/semgrep.yml).

    Every local finding used to carry one generic sentence ("Koddagi xavfli amal
    yoki TLS sozlamasi...") in the report and in SARIF, so a SQL injection and a
    weak hash read the same. Same reasoning as registry_messages(): the text comes
    from the fixed rule file, never from Semgrep's interpolated output.
    """
    try:
        parsed=yaml.safe_load((RULES/'semgrep.yml').read_text(encoding='utf-8'))
    except (OSError,UnicodeDecodeError,yaml.YAMLError):
        return {}
    return {str(rule['id']):clean_message(rule['message']) for rule in (parsed or {}).get('rules') or []
            if isinstance(rule,dict) and rule.get('id') and rule.get('message')}


RULE_META_KEYS=('confidence','impact','likelihood','subcategory')


def rule_meta(meta):
    """The rule author's own confidence/impact/likelihood/subcategory, when given.

    The CI gate uses them: a registry rule marked WARNING but with MEDIUM/HIGH
    confidence for an injection class is a real finding, while `audit` rules with
    LOW confidence are leads for a human. Values are plain words from the rule
    file, so nothing from the scanned project passes through here.
    """
    result={}
    for key in RULE_META_KEYS:
        value=meta.get(key)
        if isinstance(value,list):value=value[0] if value else None
        if isinstance(value,str) and re.fullmatch(r'[A-Za-z_-]{1,20}',value):result[key]=value.lower()
    return result


def pmd_rows(data):
    """Flatten PMD's files[].violations[] into one row per violation."""
    if not isinstance(data,dict) or not isinstance(data.get('files'),list):
        raise ValueError('PMD JSON natijasi noto‘g‘ri.')
    rows=[]
    for entry in data['files']:
        for violation in entry.get('violations') or []:
            rows.append({**violation,'filename':entry.get('filename')})
    return rows


# PMD priority 1 (highest) .. 5 mapped onto the ERROR/WARNING/INFO scale the
# rest of the report, the SARIF export and the CI gate already understand.
PMD_SEVERITY={1:'ERROR',2:'ERROR',3:'WARNING',4:'INFO',5:'INFO'}


def source_line(source,path,line):
    """The text of one line of the snapshot, for the finding's stable identity.

    Read from the snapshot rather than taken from the scanner's own output
    because only semgrep reports a snippet: pmd reports none and gitleaks
    redacts its own. path_in_snapshot() has already proved the file is inside
    the snapshot, so this cannot read outside it. A file that cannot be read
    yields an empty context -- the fingerprint then rests on rule and path
    alone, which is weaker but never wrong.
    """
    try:
        with (source/path).open('r',encoding='utf-8',errors='replace') as handle:
            for number,text in enumerate(handle,1):
                if number==line:return text
                if number>line:break
    except OSError:
        pass
    return ''


def normalize(tool,data,source,messages=None):
    if tool=='pmd':rows=pmd_rows(data)
    else:rows=data.get('results') if tool=='semgrep' and isinstance(data,dict) else data
    if not isinstance(rows,list):raise ValueError('Skaner JSON natijasi noto‘g‘ri.')
    result=[]
    for row in rows:
        severity=None;meta_fields={}
        if tool=='semgrep':
            rule=str(row['check_id']);path=path_in_snapshot(row['path'],source);line=int(row['start']['line'])
            extra=row.get('extra') if isinstance(row.get('extra'),dict) else {}
            meta=extra.get('metadata') if isinstance(extra.get('metadata'),dict) else {}
            # Official rules carry their own CWE list, explanation and severity; this
            # project's own seven rules do not, so they keep the RULE_CWE table and the
            # generic wording. The OWASP category is derived from the CWE either way --
            # never read from the upstream rule's own `owasp` field.
            tags=taxonomy.tag_from_metadata(meta.get('cwe')) or taxonomy.tag_static(tool,rule)
            message=(messages or {}).get(rule) or 'Koddagi xavfli amal yoki TLS sozlamasi. Ma’lumot oqimi va amaliy ta’sirini tekshiring.'
            level=str(extra.get('severity') or '').upper()
            severity=level if level in ('ERROR','WARNING','INFO') else None
            meta_fields=rule_meta(meta)
        elif tool=='pmd':
            rule=str(row['rule']);path=path_in_snapshot(row['filename'],source);line=int(row['beginline'])
            message=PMD_MESSAGES.get(rule) or 'Apex xavfsizlik qoidasi mos keldi. Ma’lumot oqimini tekshiring.'
            tags=taxonomy.tag_static(tool,rule)
            severity=PMD_SEVERITY.get(row.get('priority'))
        else:
            rule=str(row['RuleID']);path=path_in_snapshot(row['File'],source);line=int(row['StartLine'])
            message='Maxfiy qiymatga o‘xshash matn topildi. Bu demo qiymatmi yoki amaldagi sir ekanini tekshiring.'
            tags=taxonomy.tag_static(tool,rule)
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,220}',rule) or line<1:raise ValueError('Natija identifikatori noto‘g‘ri.')
        if tool=='gitleaks':
            # The redacted secret gives nothing to hash; column and entropy come
            # from it without revealing it. See zanjir/findings.py.
            identity=findings_mod.fingerprint(tool,{'rule_id':rule,'path':path,
                                                    'column':int(row.get('StartColumn') or 0),
                                                    'entropy':row.get('Entropy')})
        else:
            identity=findings_mod.fingerprint(tool,{'rule_id':rule,'path':path,
                                                    'context':source_line(source,path,line)})
        result.append({'tool':tool,'rule_id':rule,'path':path,'line':line,'fingerprint':identity,'message':message,'severity':severity,
                       'state':'unverified_static','secret_value':'hidden' if tool=='gitleaks' else None,
                       'cwe_ids':tags['cwe_ids'],'owasp_top10_2025':tags['owasp_top10_2025'],
                       'verified':False,'verification_note':'Statik kod naqshi mosligi; ma’lumot oqimi, ishga tushirish sharti va amaliy ta’siri tekshirilmagan. Mutaxassis qo‘lda ko‘rib chiqishi shart.',
                       **({'rule_meta':meta_fields} if meta_fields else {})})
    return result


def version(tool,command,env,work):
    args=command[:1]+(['--version'] if tool in ('semgrep','pmd') else ['version'])
    process=subprocess.run(args,cwd=work,env=env,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=30)
    if 'CertOpenSystemStore returned NULL' in process.stderr:raise RuntimeError('windows_certificate_store')
    if process.returncode!=0:raise ValueError('Skaner versiyasini tekshirib bo‘lmadi.')
    match=re.search(r'\b\d+\.\d+\.\d+\b',process.stdout)
    if not match:raise ValueError('Skaner versiyasi aniqlanmadi.')
    return match.group()


def read_report(rid):
    report=run_index.read(RUNS,rid,'Hisobot topilmadi.')
    # Triage is applied here rather than stored in report.json: a decision made
    # after the scan has to show on the scan it applies to, and the evidence file
    # must stay exactly as the scanners produced it.
    return triage.attach('code',report.get('target'),report)


def history(limit=30):
    return run_index.rows(RUNS,('id','target','created_at','state','count'),read_report,limit=limit)


def pilot_summary():
    try:
        from pilot_tls import evaluate
        base=ROOT/'pilot'
        latest=json.loads((base/'runtime/latest-tls-test.json').read_text(encoding='utf-8'))
        rid=latest['id']
        if not ID.fullmatch(rid):raise ValueError('Invalid ID')
        folder=base/'tls-runs'/rid
        report=json.loads((folder/'report.json').read_text(encoding='utf-8'))
        manifest=json.loads((folder/'manifest.json').read_text(encoding='utf-8'))
        for name in ('manifest.json','nginx-error.log'):
            if hashlib.sha256((folder/name).read_bytes()).hexdigest()!=report['artifacts_sha256'][name]:raise ValueError('Changed evidence')
        for name in ('nginx.conf','trusted-ca.crt','good.crt','bad.crt'):
            if hashlib.sha256((folder/'inputs'/name).read_bytes()).hexdigest()!=manifest['input_sha256'][name]:raise ValueError('Changed inputs')
        controls=evaluate(report['responses'],(folder/'nginx-error.log').read_text(encoding='utf-8'),manifest['nonce'])
        return {'state':'controlled_test_confirmed' if controls['passed'] else 'needs_review','id':rid,
                'finished_at':report['finished_at'],'checks':controls['checks'],
                'scope':'crAPI web image nusxasida alohida TLS tajribasi. Asl crAPI hujum yo‘li tasdiqlanmagan va tuzatish qo‘llanmagan.'}
    except (OSError,ValueError,KeyError,TypeError):
        return {'state':'no_verified_result','checks':{},'scope':'Tekshirilgan amaliy TLS natijasi mavjud emas.'}


def execute(target,rid):
    folder=RUNS/rid
    report=read_report(rid)
    report.update(state='running',tools={},findings=[])
    write(folder/'report.json',report)
    try:
      with source_for(target) as (source,provenance):
        report['source']=provenance
        write(folder/'report.json',report)
        # Temporary copies and scanner output never enter the downloadable report.
        with tempfile.TemporaryDirectory(prefix='work-',dir=folder) as temp, scanner_environment(Path(temp).resolve()) as env:
            work=Path(temp).resolve()
            if not work.is_relative_to(folder.resolve()):raise ValueError('Vaqtinchalik papka chegarasi noto‘g‘ri.')
            coverage=snapshot(source,work/'source')
            write(folder/'snapshot-manifest.json',coverage.pop('manifest'))
            report['coverage']=coverage
            manifest=registry_manifest()
            messages={**local_messages(),**registry_messages(manifest)}
            local=custom_rules.active()
            if local:messages={**messages,**custom_rules.messages()}
            for tool,command in tool_commands(work,registry=bool(manifest),local=local,apex=has_apex(work/'source')).items():
                stage='version'
                process=None
                try:
                    tool_version=version(tool,command,env,work)
                    stage='scan'
                    # The official pack raises the rule count from 7 to ~1300, so the
                    # scan legitimately takes minutes rather than seconds.
                    limit=900 if (tool=='semgrep' and manifest) else 240
                    run_command,low=priority.gentle(command)
                    process=subprocess.run(run_command,cwd=work,env=env,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=limit,**low)
                    # Semgrep scan (without --error): findings exit 0. Gitleaks: findings exit 1.
                    allowed=(0,) if tool in ('semgrep','pmd') else (0,1)
                    if process.returncode not in allowed:raise ValueError('Skaner xato bilan tugadi (kod '+str(process.returncode)+').')
                    stage='parse_json'
                    data=json.loads(process.stdout)
                    stage='normalize'
                    findings=normalize(tool,data,work/'source',messages)
                    if tool=='gitleaks' and ((process.returncode==1)!=bool(findings)):raise ValueError('Gitleaks exit kodi va natija mos emas.')
                    errors=len(data.get('errors',[])) if tool=='semgrep' else len(data.get('processingErrors') or []) if tool=='pmd' else 0
                    report['tools'][tool]={'state':'partial' if errors else 'completed','version':tool_version,'count':len(findings),'errors':errors,
                        'rule_set':rule_set_label(tool,manifest,custom_rules.summary()['rules'] if local else 0),
                        'rules_sha256':hashlib.sha256((TOOLS/'pmd/provenance.json' if tool=='pmd' else RULES/('semgrep.yml' if tool=='semgrep' else 'gitleaks.toml')).read_bytes()).hexdigest()}
                    if tool=='semgrep':
                        if manifest:report['tools'][tool]['rule_pack']={'source':manifest['source'],'commit':manifest['commit'],
                            'rules':manifest['rules'],'files':manifest['files'],'languages':manifest['languages']}
                        report['tools'][tool]['error_kinds']=error_kinds(data.get('errors',[]))
                        report['tools'][tool]['error_files']=error_files(data.get('errors',[]),work/'source')
                    report['findings']+=findings
                except (OSError,ValueError,RuntimeError,KeyError,TypeError,subprocess.TimeoutExpired) as error:
                    report['tools'][tool]={'state':'failed','count':0,'message':'Tekshiruv tugallanmadi. O‘rnatish, qoidalar yoki bajarish cheklovini tekshiring.','error_type':type(error).__name__}
                    report['tools'][tool]['failure_stage']=stage
                    if process is not None:report['tools'][tool]['exit_code']=process.returncode
                    if str(error)=='windows_certificate_store':
                        report['tools'][tool].update(diagnostic_code='windows_certificate_store',message='Bu ish muhitida Windows sertifikat omboriga kirib bo‘lmadi. SCAN-CODE.cmd faylini Windows’da ochib tekshiring.')
                report['count']=len(report['findings']);report['verification_summary']=verification_mod.summarize(report['findings'])
                # Two scanners on one line is one issue reported twice; they are
                # linked, never merged, so no evidence is lost. See baseline.py.
                report['duplicates']=baseline.link_duplicates(report['findings'])
                write(folder/'report.json',report)
            states=[item['state'] for item in report['tools'].values()]
            report['state']='completed' if all(s=='completed' for s in states) else 'failed' if all(s=='failed' for s in states) else 'partial'
            # Kept out of report['tools'] on purpose: a project without .git is
            # not a partial scan, and the tool states above decide the stage.
            report['history_scan'],extra=history_secrets(source,report['findings'],env,work)
            if extra:
                report['findings']+=extra
                report['count']=len(report['findings']);report['verification_summary']=verification_mod.summarize(report['findings'])
            write(folder/'report.json',report)
    except (OSError,ValueError) as error:
        report.update(state='failed',message=str(error))
    finally:
        report['finished_at']=datetime.datetime.now(datetime.timezone.utc).isoformat()
        write(folder/'report.json',report)
        triage.record_scan('code',report)
        LOCK.release()
    return report


def diagnose_semgrep(rid):
    """Only synthetic input is used: raw diagnostic output cannot quote project code."""
    read_report(rid)
    folder=RUNS/rid
    result={'scope':'Synthetic demo only; no repository files scanned.','steps':[]}
    with tempfile.TemporaryDirectory(prefix='diagnostic-',dir=folder) as temp, scanner_environment(Path(temp).resolve()) as env:
        work=Path(temp).resolve()
        if not work.is_relative_to(folder.resolve()):raise ValueError('Diagnostika papkasi chegarasi noto‘g‘ri.')
        source=work/'source';source.mkdir()
        (source/'demo.py').write_text('import os\nos.system(user_input)\neval(user_input)\n',encoding='utf-8')
        command=tool_commands(work)['semgrep']
        # Quiet mode hid the cause of the native CLI's "missing output" error.
        # Compare the full rule set with one known Python pattern, all synthetic.
        debug_command=[arg for arg in command if arg!='--quiet']
        debug_command.insert(2,'--debug')
        minimal=work/'diagnostic-rule.yml'
        minimal.write_text('rules:\n  - id: diagnostic.eval\n    languages: [python]\n    severity: WARNING\n    message: Synthetic diagnostic\n    pattern: eval(...)\n',encoding='utf-8')
        minimal_command=debug_command.copy()
        minimal_command[minimal_command.index('--config')+1]=str(minimal)
        steps=[('version',command[:1]+['--version']),('synthetic_scan_debug',debug_command),
               ('minimal_json_debug',minimal_command),
               ('minimal_text_debug',[arg for arg in minimal_command if arg!='--json'])]
        result['environment']={'temp_utf8_bytes':len(env['TEMP'].encode('utf-8')),
                               'semgrep_scripts':str(semgrep_bin_dir())}
        for name,args in steps:
            try:
                process=subprocess.run(args,cwd=work,env=env,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=60)
                result['steps'].append({'step':name,'exit_code':process.returncode,'stdout':process.stdout[:64000],'stderr':process.stderr[:64000]})
            except (OSError,subprocess.TimeoutExpired) as error:
                result['steps'].append({'step':name,'error_type':type(error).__name__})
            # Preserve completed steps even if the user closes the launcher early.
            write(folder/'semgrep-diagnostic-debug.json',result)
        write(folder/'semgrep-diagnostic-debug.json',result)
    return result


def start(target,background=True):
    check_target(target)
    if not LOCK.acquire(blocking=False):raise ValueError('Boshqa kod tekshiruvi davom etmoqda.')
    rid=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S')+'-'+uuid.uuid4().hex[:8]
    try:write(RUNS/rid/'report.json',{'id':rid,'target':target,'created_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'state':'queued','count':0,'findings':[],'tools':{},'verification':'unverified_static',
                'limits':'Topilmalar qo‘lda tekshiriladi. Maxfiy qiymat va kod parchasi hisobotga kiritilmaydi. Bu amaliy hujum tasdig‘i emas.'})
    except Exception:LOCK.release();raise
    if background:
        threading.Thread(target=execute,args=(target,rid),daemon=True).start()
        return {'id':rid,'state':'queued'}
    return execute(target,rid)
