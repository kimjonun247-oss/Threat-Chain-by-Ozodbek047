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
import time
import uuid

from vendor import yaml

from .engine import ROOT, DATA, skip_directory, available_memory_mb
from . import pathclass, priority, repo_store, scan_cache, code_targets, taxonomy, custom_rules, run_index, baseline, findings as findings_mod, triage, verification as verification_mod

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
class ScanSlots:
    """Which projects are being scanned, and whether one more may start.

    This was a single lock: one code scan on the whole installation, whichever
    project it was for. A project is still never scanned twice at once, but two
    different projects may now run side by side, up to the operator's
    `max_parallel_scans` setting. Its default is 1, so an installation that
    never changed it behaves exactly as before.
    """

    def __init__(self):
        self._guard=threading.Lock()
        self.active=set()

    @staticmethod
    def capacity():
        try:
            from . import settings
            return max(1,min(4,int(settings.read().get('max_parallel_scans',1))))
        except (OSError,ValueError,TypeError):
            return 1

    def acquire(self,key='*',blocking=False):
        with self._guard:
            if key in self.active or len(self.active)>=self.capacity():return False
            self.active.add(key);return True

    def release(self,key='*'):
        with self._guard:self.active.discard(key)

    def locked(self,key=None):
        """With a key: is that project running. Without: is there no free slot."""
        with self._guard:
            return key in self.active if key is not None else len(self.active)>=self.capacity()


LOCK=ScanSlots()
CANCEL={}
ID=run_index.RUN_ID  # one definition shared by every scanner
EXCLUDED={'.git','.tools','.venv','venv','node_modules','vendor','__pycache__','scanner-runs','dependency-runs','image-runs','web-runs','assessment-runs','validation-runs','advisory-cache','repository-runs','runs','pilot','profiles'}
IGNORE_FILES={'.semgrepignore','.gitleaksignore','.gitleaks.toml'}
MAX_FILE=1024*1024
MAX_TOTAL=500*1024*1024


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
    # The historical sibling checkout sits two levels above the application
    # folder. In a container the app lives at /app, which has no grandparent, so
    # guard the index -- otherwise readiness and every target listing raise
    # IndexError. ROOT/'work/...' above still covers the in-folder copy.
    if len(ROOT.parents)>=2:
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
        remote_source.remove(path.parent)


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


MAX_FILES=100000
# Windows refuses a path of 260 characters or more unless long paths are enabled
# system-wide. The snapshot lives under the run folder, which adds its own
# length to every file, so a path that is fine in the project can be too long in
# the copy. One such file used to fail the whole scan with FileNotFoundError.
WINDOWS_PATH_LIMIT=259
UTF16_BOMS=(b'\xff\xfe',b'\xfe\xff')
SCAN_ALL_VARIABLE='THREATCHAIN_SCAN_ALL_CODE'
MINIFIED_SUFFIXES=('.js','.mjs','.cjs','.css')


def looks_minified(key,raw):
    """A JavaScript/CSS file written for machines: very long lines, almost no line breaks.

    Only by content and only for these suffixes -- a long-lined Python data file is
    still somebody's source. Average line over 300 characters, or one line of 10 000
    or more, in a file of at least 2 KB.
    """
    if len(raw)<2048 or not key.lower().endswith(MINIFIED_SUFFIXES):return False
    lines=raw.count(b'\n')+1
    if len(raw)/lines>300:return True
    return max(map(len,raw.split(b'\n')))>=10000


def semgrep_skip_reason(key,kind):
    """Why Semgrep leaves this file out ('vendored', 'generated', 'minified'), or None.

    Someone else's code (site-packages, third_party, bower_components...) and build
    output are not what a code review of this project can fix; on the 26 503-file
    tree measured 2026-10-13, 1 598 of 1 895 Semgrep findings were in site-packages.
    Their dependencies are judged by the CVE stage, and Gitleaks still reads them
    for secrets. THREATCHAIN_SCAN_ALL_CODE=1 scans everything.
    """
    if os.environ.get(SCAN_ALL_VARIABLE,'').strip().lower() in {'1','true','yes','on'}:return None
    if kind=='minified':return 'minified'
    found=pathclass.classify(key)
    return found if found in ('vendored','generated') else None
PROGRESS_EVERY=500


class Cancelled(Exception):
    """The operator cancelled the scan; raised between files and between tools."""


def _walk(source):
    """(directory, file names) for everything a snapshot would look at, plus what it left out."""
    skipped={'excluded':0,'links':0}
    def linked(path):
        info=os.lstat(path)
        return stat.S_ISLNK(info.st_mode) or bool(getattr(info,'st_file_attributes',0)&getattr(stat,'FILE_ATTRIBUTE_REPARSE_POINT',1024))
    def walk():
        for current,dirs,files in os.walk(source,followlinks=False):
            allowed=[]
            for name in sorted(dirs):
                path=os.path.join(current,name)
                if skip_directory(current,name):skipped['excluded']+=1
                elif linked(path):skipped['links']+=1
                else:allowed.append(name)
            dirs[:]=allowed
            yield current,sorted(files),linked
    return walk(),skipped


def measure(source,sniff=False):
    """Files and bytes a snapshot of `source` would hold, without copying anything.

    Without `sniff` only names and sizes are read, which gives an upper bound: a
    binary file is still counted because telling needs its content. With `sniff`
    the first 4 KB of each file is read to leave binaries out, which is close to
    exact. Returns (files, bytes).
    """
    walker,_=_walk(source)
    files=total=0
    for current,names,linked in walker:
        for name in names:
            if name in IGNORE_FILES:continue
            path=os.path.join(current,name)
            try:
                if linked(path):continue
                size=os.stat(path).st_size
                if size>MAX_FILE:continue
                if sniff:
                    with open(path,'rb') as handle:head=handle.read(4096)
                    if b'\0' in head and not head.startswith(UTF16_BOMS):continue
            except OSError:continue
            files+=1;total+=size
    return files,total


def check_size(source,progress=None):
    """Refuse an oversized project before copying it, and say how big it is.

    The limit used to be noticed only while copying: a project over it was read
    and written for minutes and then thrown away. Names and sizes are counted
    first; only when that upper bound is over a limit is the slower, more exact
    count made. Returns the number of files the copy should expect.
    """
    files,total=measure(source)
    if files>MAX_FILES or total>MAX_TOTAL:
        if progress:progress('Loyiha hajmi o‘lchanmoqda (chegaraga yaqin)')
        files,total=measure(source,sniff=True)
        if files>MAX_FILES or total>MAX_TOTAL:
            raise ValueError(f'Loyiha {MAX_TOTAL//1024**2} MB yoki {MAX_FILES} fayl chegarasidan oshdi: '
                             f'taxminan {files} ta matn fayli, {total//1024**2} MB. Hech narsa nusxalanmadi. '
                             'Loyihani qismlarga bo‘lib (masalan, har xizmatni alohida) ro‘yxatga oling.')
    return files


def snapshot(source,destination,progress=None,cancel=None,cache=None,tools=(),copy_all=True):
    """Describe the project and copy what has to be scanned into `destination`.

    Without a cache every text file is read and copied, as it always was. With
    one (zanjir/scan_cache.py) a file whose size and mtime are unchanged is not
    opened: its hash comes from the cache, and it is copied only when one of
    `tools` has no stored result for that exact content (or `copy_all` asks for
    everything, as the whole-program analysis does). The manifest, the counts
    and the snapshot hash describe the whole project either way; `copied` says
    which files are actually in `destination`.
    """
    expected=check_size(source,progress)
    destination.mkdir()
    entries=[]
    skipped={'excluded':0,'links':0,'binary':0,'large':0}
    extra={'path_too_long':0,'unreadable':0}
    too_long=[];transcoded=0;copied=[];copied_bytes=0;unread=0
    semgrep_skipped={'vendored':0,'generated':0,'minified':0};semgrep_skip=set();semgrep_skip_examples=[]
    needs={tool:[] for tool in tools}
    total=0;seen=0
    walker,counted=_walk(source)
    made=set()
    for current,names,linked in walker:
        # Containment is proved once per directory. Links are never followed
        # (directories and files that are links are skipped above and below), so
        # a file directly inside a contained directory is contained too --
        # resolving every single file cost one extra open per file on Windows.
        if names and not Path(current).resolve().is_relative_to(source):raise ValueError('Manba yo‘li loyiha chegarasidan chiqdi.')
        for name in names:
            seen+=1
            if cancel is not None and cancel.is_set():raise Cancelled('Skan bekor qilindi.')
            if progress and seen%PROGRESS_EVERY==0:
                progress(f'Manba o‘qilmoqda: {len(entries)}/{expected} fayl ({len(copied)} tasi skanga)')
            path=Path(current)/name
            if name in IGNORE_FILES:counted['excluded']+=1;continue
            raw=None
            try:
                if linked(path):counted['links']+=1;continue
                info=path.stat()
                if info.st_size>MAX_FILE:skipped['large']+=1;continue
                relative=path.relative_to(source)
                key=relative.as_posix()
                known=cache.lookup(key,info.st_size,info.st_mtime_ns) if cache is not None else None
                if known is None:
                    raw=path.read_bytes()
                    kind='text'
                    if raw.startswith(UTF16_BOMS):
                        # UTF-16 source (common for Windows-authored .cs/.ps1/.sql) is full
                        # of NUL bytes and was dropped as binary, so it was never scanned.
                        # The copy handed to the scanners is the same text as UTF-8.
                        try:raw=raw.decode('utf-16').encode('utf-8');kind='utf16'
                        except UnicodeDecodeError:kind='binary'
                    if kind!='binary' and b'\0' in raw:kind='binary'
                    if kind=='text' and looks_minified(key,raw):kind='minified'
                    sha=hashlib.sha256(raw).hexdigest() if kind!='binary' else '';size=len(raw)
                else:
                    sha,kind,size=known;unread+=1
                if cache is not None:cache.remember(key,info.st_size,info.st_mtime_ns,sha,kind,size)
                if kind=='binary':skipped['binary']+=1;continue
                if kind=='utf16':transcoded+=1
                # Per tool: one whose last run failed has nothing stored and needs
                # every file, and that must not make the others scan again.
                applies=[t for t in tools if t!='pmd' or key.endswith(APEX_SUFFIXES)]
                reason=semgrep_skip_reason(key,kind) if 'semgrep' in applies else None
                if reason:
                    applies.remove('semgrep');semgrep_skipped[reason]+=1
                    semgrep_skip.add(key)
                    if len(semgrep_skip_examples)<MAX_LISTED_FILES:semgrep_skip_examples.append(key)
                wanted=applies if copy_all or cache is None else [t for t in applies if not cache.has(key,sha,[t])]
                need=copy_all or cache is None or bool(wanted)
                target=destination/relative
                if need and IS_WINDOWS and len(str(target))>=WINDOWS_PATH_LIMIT:
                    extra['path_too_long']+=1
                    if len(too_long)<MAX_LISTED_FILES:too_long.append(key)
                    continue
                if total+size>MAX_TOTAL or len(entries)>=MAX_FILES:raise ValueError(f'Loyiha {MAX_TOTAL//1024**2} MB yoki {MAX_FILES} fayl chegarasidan oshdi.')
                if need:
                    if raw is None:
                        raw=path.read_bytes()
                        if kind=='utf16':raw=raw.decode('utf-16').encode('utf-8')
                    if target.parent not in made:
                        target.parent.mkdir(parents=True,exist_ok=True);made.add(target.parent)
                    target.write_bytes(raw)
                    copied.append(key);copied_bytes+=len(raw)
                    for tool in wanted:needs[tool].append(key)
            except (OSError,UnicodeDecodeError):
                extra['unreadable']+=1;continue
            total+=size
            entries.append({'path':key,'sha256':sha})
    skipped['excluded']=counted['excluded'];skipped['links']=counted['links']
    # Only named when they happened, so a project without them reports exactly
    # the four counts it always did.
    skipped.update({key:value for key,value in extra.items() if value})
    if not entries:raise ValueError('Tekshiriladigan matn fayli topilmadi.')
    digest=hashlib.sha256(json.dumps(entries,sort_keys=True).encode()).hexdigest()
    result={'files':len(entries),'bytes':total,'snapshot_sha256':digest,'skipped':skipped,'manifest':entries,
            'copied':copied,'copied_bytes':copied_bytes,'unread':unread,'needs':needs,
            'scope':'Joriy matn fayllari (vendor/node_modules, binar va 1 MB dan katta fayllar kiritilmagan). Git tarixidagi sirlar Gitleaks bilan alohida tekshiriladi (.git bo‘lsa).'}
    if transcoded:result['transcoded_utf16']=transcoded
    result['tool_skip']={'semgrep':semgrep_skip}
    if semgrep_skip:
        result['semgrep_skipped']={**{k:v for k,v in semgrep_skipped.items() if v},'examples':semgrep_skip_examples,
            'note':('Semgrep bu fayllarni tekshirmadi: boshqa birovning kodi (vendor), build natijasi yoki minify qilingan fayl. '
                    'Gitleaks ularni ham sirlar uchun tekshiradi. Hammasini Semgrep bilan tekshirish: '+SCAN_ALL_VARIABLE+'=1.')}
    if too_long:
        result['path_too_long']={'files':too_long,'count':extra['path_too_long'],
                                 'action':('Bu fayllarning skan nusxasidagi yo‘li Windows’ning 260 belgilik chegarasidan oshadi va ular '
                                           'tekshirilmadi. THREATCHAIN_DATA_DIR ni qisqa yo‘lga (masalan C:\\tc) ko‘chiring yoki '
                                           'Windows’da uzun yo‘llarni yoqing (LongPathsEnabled).')}
    return result


BASE_BYTES=50*1024*1024
MAX_SCALE=16


def scan_scale(size):
    """How many times the original 50 MB budget a snapshot is, from 1 to 16.

    Every time limit was written for a 50 MB project. A snapshot ten times that
    size with the same fifteen minutes does not finish: the tool is killed and
    the stage reports nothing at all. Limits and worker count now grow with the
    snapshot; a project inside the original budget runs exactly as before.
    """
    return max(1,min(MAX_SCALE,-(-int(size)//BASE_BYTES)))


WORKER_MEMORY_MB=750
LOCAL_WORKER_MEMORY_MB=200
JOBS_VARIABLE='THREATCHAIN_SEMGREP_JOBS'
MAX_MEMORY_VARIABLE='THREATCHAIN_SEMGREP_MAX_MEMORY'


def env_int(name,low,high):
    """A whole number from the environment within [low, high], or None when unset or not a number."""
    try:value=int(str(os.environ.get(name,'')).strip())
    except ValueError:return None
    return max(low,min(high,value))


def semgrep_jobs(scale,registry=True):
    """Semgrep workers for a snapshot of this scale.

    Two for a project inside the original budget, up to half the cores for a
    larger one -- but never more than free memory can hold, small projects
    included. Measured 2026-10-13 with Semgrep's own `max_memory_bytes`: two
    workers with the full registry pack peaked at 1.5 GB on 167 stdlib files
    (~750 MB each); with the seven local rules a worker stays near 130 MB. Two
    full-pack workers on a machine with 1 GB free is how a scan runs the machine
    out of memory. THREATCHAIN_SEMGREP_JOBS overrides the count (1-32).
    """
    forced=env_int(JOBS_VARIABLE,1,32)
    if forced:return forced
    wanted=2 if scale<=1 else max(2,min(8,(os.cpu_count() or 2)//2))
    free=available_memory_mb()
    if free is not None:wanted=max(1,min(wanted,free//(WORKER_MEMORY_MB if registry else LOCAL_WORKER_MEMORY_MB)))
    return wanted


def semgrep_memory_limit():
    """Semgrep's own per-file memory limit in MB (`--max-memory`), or None for its default (none).

    Set THREATCHAIN_SEMGREP_MAX_MEMORY on a small machine: a file that needs more
    is then reported as that file's error instead of the whole run being killed
    by the system. Not set by default, because a limit derived from the memory
    free at that moment would make the same file pass on one scan and fail on
    the next.
    """
    value=env_int(MAX_MEMORY_VARIABLE,0,1024*1024)
    return value or None


# Semgrep language name -> a family of file extensions. JavaScript and TypeScript
# share one family on purpose (rules list either or both). A language missing from
# this table is never filtered out.
LANGUAGE_FAMILY={'python':'python','py':'python','python2':'python','python3':'python',
                 'javascript':'js','js':'js','typescript':'js','ts':'js','vue':'js',
                 'java':'java','kotlin':'kotlin','kt':'kotlin','scala':'scala','go':'go','golang':'go',
                 'ruby':'ruby','rb':'ruby','php':'php','csharp':'csharp','c#':'csharp','cs':'csharp',
                 'c':'c','cpp':'c','c++':'c','rust':'rust','swift':'swift',
                 'hcl':'hcl','terraform':'hcl','tf':'hcl','yaml':'yaml','json':'json',
                 'solidity':'solidity','sol':'solidity','ocaml':'ocaml','elixir':'elixir','ex':'elixir',
                 'lua':'lua','html':'html','xml':'xml','apex':'apex','clojure':'clojure','dart':'dart',
                 'julia':'julia','r':'r','scheme':'scheme','jsonnet':'jsonnet',
                 'dockerfile':'dockerfile','docker':'dockerfile'}
FAMILY_SUFFIXES={'python':('.py','.pyi','.pyw'),
                 'js':('.js','.jsx','.mjs','.cjs','.ts','.tsx','.mts','.cts','.vue'),
                 'java':('.java',),'kotlin':('.kt','.kts'),'scala':('.scala','.sc'),'go':('.go',),
                 'ruby':('.rb','.rake','.gemspec','.ru','gemfile','rakefile'),
                 'php':('.php','.phtml','.php3','.php4','.php5','.php7','.phps','.inc'),
                 'csharp':('.cs',),'c':('.c','.h','.cc','.cpp','.cxx','.c++','.hh','.hpp','.hxx','.h++','.ino'),
                 'rust':('.rs',),'swift':('.swift',),'hcl':('.tf','.hcl','.tfvars'),'yaml':('.yml','.yaml'),
                 'json':('.json',),'solidity':('.sol',),'ocaml':('.ml','.mli'),'elixir':('.ex','.exs'),
                 'lua':('.lua',),'html':('.html','.htm'),'xml':('.xml',),'apex':('.cls','.trigger'),
                 'clojure':('.clj','.cljs','.cljc','.edn'),'dart':('.dart',),'julia':('.jl',),'r':('.r',),
                 'scheme':('.scm','.ss'),'jsonnet':('.jsonnet','.libsonnet'),
                 'dockerfile':('dockerfile','.dockerfile','containerfile')}


def project_families(paths):
    """The language families present in these snapshot-relative paths."""
    found=set()
    for key in paths:
        name=str(key).rsplit('/',1)[-1].lower()
        for family,suffixes in FAMILY_SUFFIXES.items():
            if family not in found and name.endswith(suffixes):found.add(family)
    return found


_RULE_BLOCKS={}


def rule_blocks(path):
    """The merged pack as ([(rule text, languages)], newline), or None when its layout is not the expected one.

    The pack is written by setup_semgrep_rules.py with yaml.safe_dump: `rules:`,
    then one block per rule starting with `- ` in the first column, exactly one
    `id:` and one `languages:` key two spaces in, the languages a block list.
    Reading 2 MB of YAML with a parser costs more than it saves, so the text is
    cut at those lines -- and anything that does not look exactly like that
    disables filtering instead of guessing.
    """
    try:raw=Path(path).read_bytes()
    except OSError:return None
    digest=hashlib.sha256(raw).hexdigest()
    if digest in _RULE_BLOCKS:return _RULE_BLOCKS[digest]
    text=raw.decode('utf-8','replace');result=None
    # Written with write_text, so CRLF on Windows and LF elsewhere.
    nl='\r\n' if text.startswith('rules:\r\n') else '\n'
    if text.startswith('rules:'+nl) and text.endswith(nl):
        blocks=[];current=None
        # Split on the newline only: str.splitlines() also breaks on \x0c,
        # and the like, which can sit inside a rule's message.
        for line in (piece+nl for piece in text[len('rules:'+nl):-len(nl)].split(nl)):
            if line.startswith('- '):
                if current is not None:blocks.append(current)
                current=[line]
            elif current is None:break
            else:current.append(line)
        else:
            if current is not None:blocks.append(current)
            parsed=[]
            for block in blocks:
                # The first key of a rule is written after the `- ` (usually `id`, not always).
                keys=['  '+block[0][2:],*block[1:]]
                if sum(line.startswith('  id: ') for line in keys)!=1:break
                marks=[i for i,line in enumerate(keys) if line=='  languages:'+nl]
                if len(marks)!=1:break
                languages=[]
                for line in keys[marks[0]+1:]:
                    if not line.startswith('  - '):break
                    languages.append(line[4:].strip().strip('\'"').lower())
                if not languages:break
                parsed.append((''.join(block),languages))
            else:
                result=(parsed,nl) if parsed else None
    _RULE_BLOCKS.clear();_RULE_BLOCKS[digest]=result
    return result


def filtered_rules(pack,families,folder):
    """The pack without rules for languages this project has no file in.

    Semgrep applies a rule only to files of its languages, so dropping a rule
    whose every language is absent from the project cannot change any file's
    result -- it only removes start-up and per-file prefilter work. Measured on
    167 stdlib files: start-up 36 s with all 1 343 rules, 15 s with the 370 that
    apply to Python; scan 167 s -> 140 s with 2 workers. Generic/regex rules,
    languages missing from LANGUAGE_FAMILY and an unexpected pack layout all
    keep the full pack. Returns the path to hand to Semgrep and the rule counts.
    """
    found=rule_blocks(pack)
    if found is None:return pack,None
    blocks,nl=found
    keep=[text for text,languages in blocks
          if any(LANGUAGE_FAMILY.get(language) is None or LANGUAGE_FAMILY[language] in families for language in languages)]
    if len(keep)==len(blocks):return pack,{'rules':len(blocks),'used':len(blocks)}
    out=Path(folder)/'semgrep-rules-for-project.yml'
    out.write_bytes(('rules:'+nl+''.join(keep) if keep else 'rules: []'+nl).encode('utf-8'))
    return out,{'rules':len(blocks),'used':len(keep),'languages':sorted(families)}


def tool_commands(work,registry=False,local=None,apex=False,scale=1,families=None,used=None):
    # Semgrep accepts repeated --config: this project's own rules always run, the
    # official pack and the operator's own rules are layered on top only when
    # they exist. The pack is handed over as one merged file when the installer
    # produced it -- same rules, same findings, a fraction of the start-up cost --
    # and, when the project's languages are known, without the rules for
    # languages it has no file in (filtered_rules).
    semgrep_config=['--config',str(RULES/'semgrep.yml')]
    if registry:
        pack=merged_rules() if merged_rules().is_file() else semgrep_registry()
        if families is not None and pack.is_file():
            pack,counts=filtered_rules(pack,families,work)
            if used is not None and counts:used.update(counts)
        semgrep_config+=['--config',str(pack)]
    if local:semgrep_config+=['--config',str(local)]
    limit=semgrep_memory_limit()
    return {
        'semgrep':[str(semgrep_exe()),'scan',*semgrep_config,
                   '--metrics','off','--disable-version-check','--disable-nosem','--no-rewrite-rule-ids','--no-git-ignore','--json','--quiet','--jobs',str(semgrep_jobs(scale,registry)),'--timeout','10','--max-target-bytes',str(MAX_FILE),
                   *(['--max-memory',str(limit)] if limit else []),'source'],
        'gitleaks':[str(gitleaks_exe()),'dir','source','--config',str(RULES/'gitleaks.toml'),
                    '--report-format','json','--report-path','-','--redact=100','--no-banner','--no-color','--ignore-gitleaks-allow',
                    '--gitleaks-ignore-path',str(RULES/'empty.ignore'),'--max-target-megabytes','1','--timeout',str(180*scale)],
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
        found.append({'tool':'gitleaks','rule_id':rule,'path':path,'path_class':pathclass.classify(path),'line':max(1,line),'fingerprint':identity,
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


_LINES={'source':None,'files':{}}
LINE_CACHE_FILES=256


def source_line(source,path,line):
    """One line of a snapshot file, read through a small per-snapshot cache.

    A scan with fifty thousand findings reopened its files fifty thousand times
    (41 s measured); the lines of the files being normalised are now kept for
    that one normalize() call, at most 256 files at a time.
    """
    cache=_LINES
    if cache['source']!=str(source):cache.update(source=str(source),files={})
    lines=cache['files'].get(path)
    if lines is None:
        try:
            with (source/path).open('r',encoding='utf-8',errors='replace') as handle:lines=handle.readlines()
        except OSError:lines=[]
        if len(cache['files'])>=LINE_CACHE_FILES:cache['files'].clear()
        cache['files'][path]=lines
    return lines[line-1] if 0<line<=len(lines) else ''


def source_snippet(target,path,line,span=3):
    """A few source lines around `line` of `path`, for the finding detail panel.

    Read from the live registered source -- the scan snapshot is gone by now --
    so a file edited since the scan shows its current lines, and the caller says
    so. The path is validated against the target's own root and never read
    outside it; a missing, oversized or unreadable file yields no snippet rather
    than an error, and secrets are never passed here (gitleaks redacts its own)."""
    try:
        root=target_root(target)
        line=int(line)
    except (TypeError,ValueError,OSError):
        return None
    raw=str(path or '').replace('\\','/')
    if not raw or raw.startswith('/') or '..' in Path(raw).parts or ':' in raw:
        return None
    file=root/raw
    try:
        if not file.resolve().is_relative_to(root.resolve()) or not file.is_file() or file.stat().st_size>2_000_000:
            return None
        rows,lo,hi=[],max(1,line-span),line+span
        with file.open('r',encoding='utf-8',errors='replace') as handle:
            for number,text in enumerate(handle,1):
                if number<lo:continue
                if number>hi:break
                # Safety net: mask any long unbroken key-like token (an API key,
                # hash or base64 blob) so an incidental secret on a line never
                # reaches the panel. Normal code -- keywords, short names, SQL with
                # spaces -- is untouched; detail() skips secret findings outright.
                safe=re.sub(r'[A-Za-z0-9+/=_.\-]{24,}',lambda m:m.group()[:4]+'***',text.rstrip('\n'))
                rows.append({'n':number,'text':safe[:300],'hit':number==line})
        return rows or None
    except OSError:
        return None


def checked_paths(source):
    """path_in_snapshot() for one snapshot, remembering each answer.

    The check stats the file. A scan reports many findings per file, and on
    Windows fifty thousand of those stats were most of the time normalising took.
    A path that fails the check is never remembered, so it fails every time.
    """
    known={}
    def check(value):
        key=str(value)
        if key not in known:known[key]=path_in_snapshot(value,source)
        return known[key]
    return check


def line_contexts(tool,data,source,check=None):
    """(path, line) -> identity context for every semgrep/pmd result, one read per file.

    Results do not arrive grouped by file, so a per-file cache alone still
    reopened files constantly (41 s for 50 000 results over 1 000 files). The
    lines each file needs are collected first and every file is then read once,
    keeping only those lines -- already reduced to what the fingerprint uses.
    Anything this cannot resolve is simply absent, and normalize() reads that
    line the slow way and reports any real problem itself.
    """
    if tool=='gitleaks':return {}
    try:rows=pmd_rows(data) if tool=='pmd' else data.get('results')
    except (ValueError,AttributeError):return {}
    wanted={}
    check=check or checked_paths(source)
    for row in rows if isinstance(rows,list) else []:
        try:
            if tool=='pmd':path=check(row['filename']);line=int(row['beginline'])
            else:path=check(row['path']);line=int(row['start']['line'])
        except (KeyError,TypeError,ValueError):continue
        wanted.setdefault(path,set()).add(line)
    found={}
    for path,lines in wanted.items():
        last=max(lines)
        try:
            with (source/path).open('r',encoding='utf-8',errors='replace') as handle:
                for number,text in enumerate(handle,1):
                    if number in lines:found[(path,number)]=findings_mod.context(text)
                    if number>=last:break
        except OSError:continue
        for line in lines:found.setdefault((path,line),'')
    return found


def normalize(tool,data,source,messages=None):
    # The line cache lives for one normalisation: the same path can hold other
    # text on the next scan.
    _LINES.update(source=None,files={})
    check=checked_paths(source)
    contexts=line_contexts(tool,data,source,check)
    if tool=='pmd':rows=pmd_rows(data)
    else:rows=data.get('results') if tool=='semgrep' and isinstance(data,dict) else data
    if not isinstance(rows,list):raise ValueError('Skaner JSON natijasi noto‘g‘ri.')
    result=[]
    for row in rows:
        severity=None;meta_fields={}
        if tool=='semgrep':
            rule=str(row['check_id']);path=check(row['path']);line=int(row['start']['line'])
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
            rule=str(row['rule']);path=check(row['filename']);line=int(row['beginline'])
            message=PMD_MESSAGES.get(rule) or 'Apex xavfsizlik qoidasi mos keldi. Ma’lumot oqimini tekshiring.'
            tags=taxonomy.tag_static(tool,rule)
            severity=PMD_SEVERITY.get(row.get('priority'))
        else:
            rule=str(row['RuleID']);path=check(row['File']);line=int(row['StartLine'])
            message='Maxfiy qiymatga o‘xshash matn topildi. Bu demo qiymatmi yoki amaldagi sir ekanini tekshiring.'
            tags=taxonomy.tag_static(tool,rule)
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,220}',rule) or line<1:raise ValueError('Natija identifikatori noto‘g‘ri.')
        if tool=='gitleaks':
            # The redacted secret gives nothing to hash; column and entropy come
            # from it without revealing it. See zanjir/findings.py.
            values={'rule_id':rule,'path':path,'column':int(row.get('StartColumn') or 0),'entropy':row.get('Entropy')}
        else:
            known=contexts.get((path,line))
            values={'rule_id':rule,'path':path,'context':known if known is not None else source_line(source,path,line)}
        identity=findings_mod.fingerprint(tool,values)
        result.append({'_identity':values,'tool':tool,'rule_id':rule,'path':path,'path_class':pathclass.classify(path),'line':line,'fingerprint':identity,'message':message,'severity':severity,
                       'state':'unverified_static','secret_value':'hidden' if tool=='gitleaks' else None,
                       'cwe_ids':tags['cwe_ids'],'owasp_top10_2025':tags['owasp_top10_2025'],
                       'verified':False,'verification_note':'Statik kod naqshi mosligi; ma’lumot oqimi, ishga tushirish sharti va amaliy ta’siri tekshirilmagan. Mutaxassis qo‘lda ko‘rib chiqishi shart.',
                       **({'rule_meta':meta_fields} if meta_fields else {})})
    # Equal fields are not one finding: the same call on two lines of one file
    # gets its own identity from the second occurrence on (zanjir/findings.py).
    findings_mod.separate(result,lambda item:item['tool'],lambda item:item['_identity'])
    for item in result:del item['_identity']
    return result


_PINNED={}


def pinned_version(tool):
    """The version setup_scanners.py installs, read from that file (never imported)."""
    if not _PINNED:
        try:text=(ROOT/'setup_scanners.py').read_text(encoding='utf-8')
        except OSError:text=''
        for name in ('semgrep','gitleaks'):
            match=re.search(rf"(?m)^{name.upper()}_VERSION\s*=\s*'([0-9.]+)'",text)
            _PINNED[name]=match.group(1) if match else None
    return _PINNED.get(tool)


def version_note(tool,found):
    """A sentence when the installed tool is not the version this project was tested with.

    An older Gitleaks rejects the flags the scan passes and exits 126; the
    report said only "the scan did not finish", with nothing pointing at the
    binary. The note names both versions and the command that installs the
    right one.
    """
    wanted=pinned_version(tool)
    if not wanted or not found or found==wanted:return None
    return (f'O‘rnatilgan {tool} {found}, loyiha esa {wanted} bilan sinalgan. Farqli versiya buyruq bayroqlarini '
            'tanimasligi yoki boshqa natija berishi mumkin. To‘g‘ri versiya: python3 setup_scanners.py --force')


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


def read_view(rid):
    """The report as a screen needs it: every field, the worst findings of a large one.

    A small report is returned whole. A large one comes from its page view and
    says so in `message`, which the screen already shows -- so a shortened table
    is never mistaken for the whole result.
    """
    view=run_index.view(RUNS,rid)
    if view is None:return read_report(rid)
    note=(f'Bu sahifada {view["findings_total"]} ta topilmadan eng jiddiy {view["findings_shown"]} tasi ko‘rsatilgan. '
          'Hammasi: “Topilmalar” bo‘limi (filtr va qidiruv bilan) yoki JSON hisobot.')
    view['message']=(str(view['message'])+' ' if view.get('message') else '')+note
    return triage.attach('code',view.get('target'),view)


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


def kill_tree(process):
    """Stop a scanner and the workers it started."""
    try:
        if IS_WINDOWS:
            subprocess.run(['taskkill','/PID',str(process.pid),'/T','/F'],capture_output=True,timeout=30)
        else:
            import signal
            try:os.killpg(os.getpgid(process.pid),signal.SIGKILL)
            except (OSError,ProcessLookupError):process.kill()
    except (OSError,subprocess.SubprocessError):
        pass
    try:process.wait(10)
    except (OSError,subprocess.SubprocessError):pass


class MemoryExhausted(RuntimeError):
    """A scanner process ran out of memory: the part is split and retried, not the scan failed."""


# 137 / -9: killed by the Linux OOM killer (SIGKILL). 0xC0000017 STATUS_NO_MEMORY and
# 0xC00000FD stack overflow on Windows. OCaml (semgrep-core) prints Out_of_memory.
OOM_EXIT_CODES={137,-9,0xC0000017,0xC00000FD,-1073741801,-1073741571}
OOM_TEXT=re.compile(r'out[ _]of[ _]memory|MemoryError|cannot allocate memory|std::bad_alloc|Stack_overflow',re.I)


def out_of_memory(process):
    """True when a finished scanner process says, by exit code or message, that memory ran out."""
    if process.returncode in OOM_EXIT_CODES:return True
    if process.returncode==0:return False
    return bool(OOM_TEXT.search((process.stderr or '')[-20000:]))


def fewer_jobs(command):
    """The same command with one Semgrep worker: after running out of memory, half the part on N workers can do it again."""
    if '--jobs' not in command:return command
    i=command.index('--jobs')
    return [*command[:i+1],'1',*command[i+2:]]


def run_tool(command,cwd,env,timeout,cancel=None,**low):
    """Run one scanner to the end, to its time limit, or until cancelled.

    Output goes to files instead of pipes held in memory (a large project's
    Semgrep JSON is tens of megabytes), and the process is watched rather than
    waited on: a cancellation used to take effect only between tools, so a
    Semgrep run with hours of budget left kept running after "cancel".
    """
    with tempfile.TemporaryFile(dir=cwd) as out,tempfile.TemporaryFile(dir=cwd) as err:
        extra={} if IS_WINDOWS else {'start_new_session':True}
        process=subprocess.Popen(command,cwd=cwd,env=env,stdout=out,stderr=err,stdin=subprocess.DEVNULL,**extra,**low)
        deadline=time.monotonic()+timeout
        while True:
            try:
                process.wait(0.5);break
            except subprocess.TimeoutExpired:
                pass
            if cancel is not None and cancel.is_set():
                kill_tree(process);raise Cancelled('Skan bekor qilindi.')
            if time.monotonic()>deadline:
                kill_tree(process);raise subprocess.TimeoutExpired(command,timeout)
        out.seek(0);err.seek(0)
        return subprocess.CompletedProcess(command,process.returncode,out.read().decode('utf-8','replace'),
                                           err.read().decode('utf-8','replace'))


BATCH_FILES=4000
BATCH_BYTES=48*1024*1024


def batches(work,paths):
    """The files one tool has to scan, split into parts it is run on one at a time.

    One run over a whole large project is all or nothing: measured with the
    official rule pack on 26 503 files, Semgrep was still working after an hour,
    and a time limit or a cancellation at that point would have thrown every
    result away. Each part's findings are stored the moment that part ends, so
    an interrupted scan loses one part and the next scan continues after it.
    A small project is a single part and runs exactly as before. Returns
    [(paths, bytes), ...] in a fixed order.
    """
    parts=[];part=[];size=0
    for key in sorted(paths):
        try:length=os.path.getsize(work/'source'/key)
        except OSError:length=0
        if part and (len(part)>=BATCH_FILES or size+length>BATCH_BYTES):
            parts.append((part,size));part=[];size=0
        part.append(key);size+=length
    if part:parts.append((part,size))
    return parts


MAX_SPLITS=4


def part_bytes(work,paths):
    total=0
    for key in paths:
        try:total+=os.path.getsize(work/'source'/key)
        except OSError:pass
    return total


class PacedLimit:
    """Time limit for one part, learned from the parts that already finished.

    A fixed limit per part was too short with the full rule pack: a 4 000-file
    part needed ~10 minutes, the larger ones more than the 15 allowed, two timed
    out in a row and 3 351 files were never scanned. The first part gets the
    size-based budget; after that a part gets three times what the measured pace
    predicts for its file count, never less than the size-based budget and never
    more than MAX_PART_SECONDS.
    """

    def __init__(self,base):
        self.base=base;self.files=0;self.seconds=0.0

    def observe(self,part,seconds):
        self.files+=len(part);self.seconds+=max(0.0,seconds)

    def limit(self,part,size):
        floor=self.base*scan_scale(size)
        if not self.files:return floor
        predicted=self.seconds/self.files*len(part)
        return int(min(MAX_PART_SECONDS,max(floor,3*predicted)))


MAX_PART_SECONDS=4*60*60


def tool_folder(work,tool,mine,copied,number=None):
    """The folder to run `tool` in: its `source` holds exactly the files it must scan.

    Usually that is every copied file and the tool runs in the work folder. When
    it needs fewer -- another tool had nothing stored and pulled in more, or
    this is one part of a large scan -- it gets a folder of its own with links
    to just its files (a copy where links are not possible), so it does not
    rescan what it already has results for.
    """
    if mine==copied and number is None:return work
    folder=work/('only-'+tool if number is None else f'part-{tool}-{number}')
    made=set()
    for key in sorted(mine):
        target=folder/'source'/key
        if target.parent not in made:
            target.parent.mkdir(parents=True,exist_ok=True);made.add(target.parent)
        try:os.link(work/'source'/key,target)
        except OSError:shutil.copyfile(work/'source'/key,target)
    return folder


CACHE_FORMAT=1
FULL_SCAN_VARIABLE='THREATCHAIN_FULL_SCAN'


def cache_folder():
    """Beside the run folder, so a relocated or test RUNS gets its own cache."""
    return RUNS.parent/'scan-cache'


def full_scan_requested():
    return os.environ.get(FULL_SCAN_VARIABLE,'').strip().lower() in {'1','true','yes','on'}


def tool_context(tool,tool_version,manifest,local):
    """Everything that decides what `tool` reports for a given file's content."""
    def sha(path):
        try:return hashlib.sha256(Path(path).read_bytes()).hexdigest()
        except OSError:return 'missing'
    parts=[CACHE_FORMAT,tool,tool_version or '',MAX_FILE]
    if tool=='semgrep':
        parts+=[sha(RULES/'semgrep.yml'),(manifest or {}).get('commit'),((manifest or {}).get('merged') or {}).get('sha256'),
                sha(local) if local and Path(local).is_file() else str(local or '')]
        if local and Path(local).is_dir():
            parts+=sorted((item.name,sha(item)) for item in Path(local).rglob('*') if item.is_file())
    elif tool=='gitleaks':parts.append(sha(RULES/'gitleaks.toml'))
    else:parts.append(sha(TOOLS/'pmd/provenance.json'))
    return hashlib.sha256(json.dumps(parts,sort_keys=True,default=str).encode()).hexdigest()


def error_relative(item):
    """Snapshot-relative path of one scanner error entry, or None when it names no file."""
    if not isinstance(item,dict):return None
    raw=str(item.get('path') or item.get('filename') or '').replace('\\','/')
    if not raw:return None
    if raw.startswith('source/'):return raw[7:]
    return raw.split('/source/',1)[1] if '/source/' in raw else None


def merge_results(tool,fresh,fresh_errors,entries,scanned,cache,skip=frozenset()):
    """One tool's findings for the whole project: this run's for the files it
    scanned, the stored ones for the files it did not.

    Returns (findings, errors, reused file count, rows to store or None). The
    rows are None when an error names no file: it cannot be filed under a file,
    so nothing from this run is stored and the next scan looks again.
    """
    by_path={};errors_by_path={};storable=True
    for finding in fresh:by_path.setdefault(finding['path'],[]).append(finding)
    for item in fresh_errors:
        relative=error_relative(item)
        if relative is None:storable=False
        else:errors_by_path.setdefault(relative,[]).append({'type':item.get('type') if isinstance(item.get('type'),str) else None,
                                                             'path':'source/'+relative})
    findings=list(fresh);errors=list(fresh_errors);reused=0
    if cache is not None:
        for entry in entries:
            path=entry['path']
            if path in scanned or path in skip or (tool=='pmd' and not path.endswith(APEX_SUFFIXES)):continue
            stored=cache.get(tool,path,entry['sha256'])
            if stored is None:continue
            findings+=stored[0];errors+=stored[1];reused+=1
        findings.sort(key=lambda f:(f.get('path') or '',f.get('line') or 0,str(f.get('rule_id'))))
    sha_of={entry['path']:entry['sha256'] for entry in entries}
    rows=[(path,sha_of[path],by_path.get(path,[]),errors_by_path.get(path,[])) for path in scanned
          if path in sha_of and (tool!='pmd' or path.endswith(APEX_SUFFIXES))] if storable else None
    return findings,errors,reused,rows


def execute(target,rid,full=False):
    folder=RUNS/rid
    cancel=CANCEL.setdefault(rid,threading.Event())
    report=read_report(rid)
    report.update(state='running',tools={},findings=[])
    write(folder/'report.json',report)
    cache=None
    # Where a first scan's wall time goes, so a slow one on a large project can be
    # explained: reading files, loading rules, running scanners, everything else.
    timing={};_t_total=time.perf_counter()
    try:
      with source_for(target) as (source,provenance):
        report['source']=provenance
        write(folder/'report.json',report)
        # Temporary copies and scanner output never enter the downloadable report.
        with tempfile.TemporaryDirectory(prefix='work-',dir=folder) as temp, scanner_environment(Path(temp).resolve()) as env:
            work=Path(temp).resolve()
            if not work.is_relative_to(folder.resolve()):raise ValueError('Vaqtinchalik papka chegarasi noto‘g‘ri.')
            def progress(text):
                report['progress']=text
                write(folder/'report.json',report)
            manifest=registry_manifest()
            messages={**local_messages(),**registry_messages(manifest)}
            local=custom_rules.active()
            if local:messages={**messages,**custom_rules.messages()}
            from . import deep_analysis
            deep=deep_analysis.enabled()
            # Tool versions first: they are part of what a stored result is valid for.
            versions={};version_errors={}
            for tool,command in tool_commands(work,registry=bool(manifest),local=local).items():
                try:versions[tool]=version(tool,command,env,work)
                except (OSError,ValueError,RuntimeError,subprocess.TimeoutExpired) as error:version_errors[tool]=error
            contexts={tool:tool_context(tool,found,manifest,local) for tool,found in versions.items()}
            if pmd_exe().is_file():contexts['pmd']=tool_context('pmd','',manifest,local)
            full=full or full_scan_requested()
            if not full:
                cache=scan_cache.open_cache(cache_folder(),target)
                if cache is not None:cache.load(contexts)
            progress('Manba o‘lchanmoqda va o‘qilmoqda')
            _t=time.perf_counter()
            coverage=snapshot(source,work/'source',progress=progress,cancel=cancel,cache=cache,
                              tools=list(contexts),copy_all=deep or cache is None)
            timing['files_s']=round(time.perf_counter()-_t,2)
            entries=coverage.pop('manifest');scanned=set(coverage.pop('copied'));scanned_bytes=coverage.pop('copied_bytes')
            tool_skip=coverage.pop('tool_skip',{})
            if cache is not None:cache.save_files()
            unread=coverage.pop('unread');needs=coverage.pop('needs')
            write(folder/'snapshot-manifest.json',entries)
            # Files a partial clone never downloaded are as unscanned as the large
            # files the snapshot skipped, and are counted with them.
            coverage['skipped']['large']+=(provenance.get('partial_clone') or {}).get('large_files_not_downloaded',0)
            # How much of this result was computed now and how much was taken from
            # the previous scan of identical content -- stated, never implied.
            coverage['incremental']={'mode':'incremental' if cache is not None else 'full','files_scanned':len(scanned),
                                     'files_reused':coverage['files']-len(scanned),'files_not_reopened':unread}
            report['coverage']=coverage
            scale=scan_scale(scanned_bytes)
            if scale>1:coverage['time_budget_scale']=scale
            apex=any(entry['path'].endswith(APEX_SUFFIXES) for entry in entries)
            rules_used={}
            families=project_families(entry['path'] for entry in entries if entry['path'] not in tool_skip.get('semgrep',()))
            _t=time.perf_counter()
            command_set=tool_commands(work,registry=bool(manifest),local=local,apex=apex,scale=scale,families=families,used=rules_used)
            timing['rules_s']=round(time.perf_counter()-_t,2)
            _t_scan=time.perf_counter()
            for tool,command in command_set.items():
                stage='version'
                process=None
                tool_version=versions.get(tool)
                if cancel.is_set():raise Cancelled('Skan bekor qilindi.')
                mine=set(needs.get(tool,())) if tool in needs else {path for path in scanned if tool!='pmd' or path.endswith(APEX_SUFFIXES)}
                progress(f'{tool}: tekshiruv bajarilmoqda ({len(mine)} fayl, {coverage["files"]-len(mine)} tasi oldingi skandan)')
                try:
                    if tool in version_errors:raise version_errors[tool]
                    if tool_version is None:tool_version=version(tool,command,env,work)
                    stage='scan'
                    fresh=[];fresh_errors=[];done=set();failed_parts=0;in_a_row=0;first_error=None;memory_retries=0
                    # The official pack raises the rule count from 7 to ~1300, so the
                    # scan legitimately takes minutes rather than seconds.
                    base=900 if (tool=='semgrep' and manifest) else 240
                    run_command,low=priority.gentle(command)
                    queue=[(part,size,0) for part,size in batches(work,mine)]
                    pace=PacedLimit(base)
                    number=0
                    while queue:
                        part,size,depth=queue.pop(0)
                        number+=1
                        if cancel.is_set():raise Cancelled('Skan bekor qilindi.')
                        many=number>1 or bool(queue)
                        if many:progress(f'{tool}: {number}-qism, {len(queue)} navbatda ({len(done)}/{len(mine)} fayl tekshirildi)')
                        where=tool_folder(work,tool,set(part),scanned,number if many else None)
                        started=time.monotonic()
                        try:
                            stage='scan'
                            process=run_tool(run_command,where,env,pace.limit(part,size),cancel,**low)
                            # Semgrep scan (without --error): findings exit 0. Gitleaks: findings exit 1.
                            allowed=(0,) if tool in ('semgrep','pmd') else (0,1)
                            # Only a non-allowed exit is examined: gitleaks exit 1 means
                            # findings, not a failure, and must not be read as out-of-memory.
                            if process.returncode not in allowed:
                                if out_of_memory(process):raise MemoryExhausted(f'{tool}: xotira yetmadi (kod {process.returncode}).')
                                raise ValueError('Skaner xato bilan tugadi (kod '+str(process.returncode)+').')
                            stage='parse_json'
                            data=json.loads(process.stdout)
                            stage='normalize'
                            found=normalize(tool,data,where/'source',messages)
                            if tool=='gitleaks' and ((process.returncode==1)!=bool(found)):raise ValueError('Gitleaks exit kodi va natija mos emas.')
                            found_errors=list(data.get('errors') or []) if tool=='semgrep' else list(data.get('processingErrors') or []) if tool=='pmd' else []
                        except (subprocess.TimeoutExpired,MemoryExhausted) as error:
                            if first_error is None:first_error=error
                            # Out of memory: the rest of this tool's run uses one worker,
                            # since N workers on half the files can exhaust it again.
                            if isinstance(error,MemoryExhausted):
                                run_command=fewer_jobs(run_command);memory_retries+=1
                            # Too slow or too big as a whole: split it and try each half, so
                            # a few heavy files cost their own part, not their neighbours'. Not
                            # counted as a failure until a part can no longer be split.
                            if len(part)>1 and depth<MAX_SPLITS:
                                half=len(part)//2
                                queue[:0]=[(part[:half],part_bytes(work,part[:half]),depth+1),
                                           (part[half:],part_bytes(work,part[half:]),depth+1)]
                                continue
                            failed_parts+=1;in_a_row+=1
                            if in_a_row>=3:break
                            continue
                        except (OSError,ValueError,KeyError,TypeError) as error:
                            # A part that did not finish. The rest still run, unless three in
                            # a row say the tool is not working. If nothing finishes at all
                            # the tool is judged below, once it is known whether the cache
                            # can still answer for the other files.
                            if first_error is None:first_error=error
                            failed_parts+=1;in_a_row+=1
                            if in_a_row>=3:break
                            continue
                        finally:
                            if where!=work:shutil.rmtree(where,ignore_errors=True)
                        pace.observe(part,time.monotonic()-started)
                        in_a_row=0
                        fresh+=found;fresh_errors+=found_errors;done|=set(part)
                        # Stored now, not when the whole tool has finished.
                        rows=merge_results(tool,found,found_errors,entries,set(part),None)[3]
                        if cache is not None and rows is not None and tool in contexts:cache.store(contexts[tool],tool,rows)
                    unscanned=len(mine)-len(done)
                    findings,all_errors,reused,_=merge_results(tool,fresh,fresh_errors,entries,mine,cache,tool_skip.get(tool,frozenset()))
                    # Nothing finished this run AND the cache has nothing for the other
                    # files: the tool itself is not working, reported as a failure with
                    # its diagnostic. But when an earlier scan's results are cached for
                    # files this run did not need (a rescan where only the newly-added or
                    # previously-timed-out files failed), those stay -- dropping them was
                    # a real regression: a rescan turned 23k cached findings into zero.
                    if not done and not reused and first_error is not None:
                        raise first_error
                    errors=len(all_errors)
                    report['tools'][tool]={'state':'partial' if errors or unscanned else 'completed','version':tool_version,'count':len(findings),'errors':errors,
                        'rule_set':rule_set_label(tool,manifest,custom_rules.summary()['rules'] if local else 0),
                        'rules_sha256':hashlib.sha256((TOOLS/'pmd/provenance.json' if tool=='pmd' else RULES/('semgrep.yml' if tool=='semgrep' else 'gitleaks.toml')).read_bytes()).hexdigest(),
                        'files_scanned':len(done),'files_reused':reused}
                    # Distinct files the tool could not read: when that is every file it
                    # was given, nothing was checked and the gate must not read it as clean.
                    unreadable={error_relative(item) for item in all_errors}-{None}
                    if unreadable:report['tools'][tool]['files_with_errors']=len(unreadable)
                    if memory_retries:report['tools'][tool]['memory_retries']=memory_retries
                    if tool=='semgrep' and rules_used:report['tools'][tool]['rules_used']=dict(rules_used)
                    if unscanned:
                        # Not a coverage gap: these files were never looked at. The gate
                        # and the baseline treat the scan as unfinished (ci_gate.classify_stage);
                        # what did finish is stored, so the next scan starts from here.
                        report['tools'][tool].update(files_unscanned=unscanned,
                            message=(f'{unscanned} ta fayl tekshirilmadi: {failed_parts} ta qism vaqt chegarasida tugamadi yoki xato berdi. '
                                     'Tugagan qismlar natijasi saqlangan — skanni qayta ishga tushirsangiz, qolgan fayllardan davom etadi.'))
                    note=version_note(tool,tool_version)
                    if note:report['tools'][tool]['version_note']=note
                    if tool=='semgrep':
                        if manifest:report['tools'][tool]['rule_pack']={'source':manifest['source'],'commit':manifest['commit'],
                            'rules':manifest['rules'],'files':manifest['files'],'languages':manifest['languages']}
                        report['tools'][tool]['error_kinds']=error_kinds(all_errors)
                        report['tools'][tool]['error_files']=error_files(all_errors,source)
                    report['findings']+=findings
                except (OSError,ValueError,RuntimeError,KeyError,TypeError,subprocess.TimeoutExpired) as error:
                    report['tools'][tool]={'state':'failed','count':0,'message':'Tekshiruv tugallanmadi. O‘rnatish, qoidalar yoki bajarish cheklovini tekshiring.','error_type':type(error).__name__}
                    report['tools'][tool]['failure_stage']=stage
                    note=version_note(tool,tool_version)
                    if note:report['tools'][tool].update(version=tool_version,version_note=note,message=note)
                    if process is not None:report['tools'][tool]['exit_code']=process.returncode
                    if str(error)=='windows_certificate_store':
                        report['tools'][tool].update(diagnostic_code='windows_certificate_store',message='Bu ish muhitida Windows sertifikat omboriga kirib bo‘lmadi. SCAN-CODE.cmd faylini Windows’da ochib tekshiring.')
                report['count']=len(report['findings']);report['verification_summary']=verification_mod.summarize(report['findings'])
                # Two scanners on one line is one issue reported twice; they are
                # linked, never merged, so no evidence is lost. See baseline.py.
                report['duplicates']=baseline.link_duplicates(report['findings'])
                write(folder/'report.json',report)
            timing['scan_s']=round(time.perf_counter()-_t_scan,2)
            if cache is not None:cache.finish()
            # Optional deep analysis (CodeQL, inter-file taint): opt-in in settings,
            # it runs on the same snapshot and counts like any other tool. It follows
            # data across files, so it always sees the whole project, never a part.
            if deep:
                report['progress']='CodeQL: fayllararo ma’lumot oqimi tahlili (bir necha daqiqa)'
                write(folder/'report.json',report)
                record,deep_findings=deep_analysis.run(work/'source',work,env)
                report['tools']['codeql']=record
                report['findings']+=deep_findings
                report['count']=len(report['findings']);report['verification_summary']=verification_mod.summarize(report['findings'])
                report['duplicates']=baseline.link_duplicates(report['findings'])
            timing['total_s']=round(time.perf_counter()-_t_total,2)
            # Everything not in a named phase: tool versions, cache load, optional
            # deep analysis, history secrets, finalising the report.
            timing['other_s']=round(max(0.0,timing['total_s']-timing.get('files_s',0.0)
                                        -timing.get('rules_s',0.0)-timing.get('scan_s',0.0)),2)
            report['timing']=timing
            states=[item['state'] for item in report['tools'].values()]
            report['state']='completed' if all(s=='completed' for s in states) else 'failed' if all(s=='failed' for s in states) else 'partial'
            # Kept out of report['tools'] on purpose: a project without .git is
            # not a partial scan, and the tool states above decide the stage.
            report['history_scan'],extra=history_secrets(source,report['findings'],env,work)
            if extra:
                report['findings']+=extra
                report['count']=len(report['findings']);report['verification_summary']=verification_mod.summarize(report['findings'])
            write(folder/'report.json',report)
    except Cancelled:
        # What the finished tools found stays in the report; the state says the
        # scan did not run to the end, so nothing reads it as a clean result.
        report.update(state='cancelled',message='Skan bekor qilindi; tugagan vositalar natijasi saqlangan, qolganlari bajarilmadi.')
    except Exception as error:  # noqa: BLE001 -- any failure marks the scan failed rather than leaving it 'running'; dependencies.py, iac.py and images.py do the same
        report.update(state='failed',error_type=type(error).__name__)
        if isinstance(error,(OSError,ValueError)):report['message']=str(error)[:300]
    finally:
        if cache is not None:cache.close()
        report['finished_at']=datetime.datetime.now(datetime.timezone.utc).isoformat()
        report.pop('progress',None)
        write(folder/'report.json',report)
        triage.record_scan('code',report)
        CANCEL.pop(rid,None)
        LOCK.release(target)
    return report


def cancel(rid):
    """Ask a running code scan to stop.

    It stops while copying the source and between tools. A tool that is already
    running is not killed -- it ends within its own time limit -- so the answer
    says the stop may not be immediate.
    """
    read_report(rid)
    event=CANCEL.get(rid)
    if event is None:raise ValueError('Jarayon ushbu serverda ishlamayapti.')
    event.set()
    return {'id':rid,'state':'cancellation_requested',
            'message':'Bekor qilish so‘raldi. Ishlab turgan vosita o‘z vaqt chegarasida tugaydi; keyingisi boshlanmaydi.'}


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


def start(target,background=True,full=False):
    check_target(target)
    if not LOCK.acquire(target):
        raise ValueError('Bu loyiha hozir tekshirilmoqda.' if LOCK.locked(target) else 'Boshqa kod tekshiruvi davom etmoqda.')
    rid=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S')+'-'+uuid.uuid4().hex[:8]
    CANCEL[rid]=threading.Event()
    try:write(RUNS/rid/'report.json',{'id':rid,'target':target,'created_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'state':'queued','count':0,'findings':[],'tools':{},'verification':'unverified_static','pid':os.getpid(),
                'limits':'Topilmalar qo‘lda tekshiriladi. Maxfiy qiymat va kod parchasi hisobotga kiritilmaydi. Bu amaliy hujum tasdig‘i emas.'})
    except Exception:CANCEL.pop(rid,None);LOCK.release(target);raise
    if background:
        threading.Thread(target=execute,args=(target,rid,full),daemon=True).start()
        return {'id':rid,'state':'queued'}
    return execute(target,rid,full)
