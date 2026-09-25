"""Bounded dependency evidence collection. Never resolve/install/run repository code."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

EXCLUDED={'.git','.tools','.venv','venv','node_modules','vendor','__pycache__','scanner-runs','dependency-runs','image-runs','web-runs','assessment-runs','validation-runs','advisory-cache','repository-runs','runs','pilot','profiles'}
MAX_MANIFEST=16*1024*1024
MAX_TOTAL=64*1024*1024
MAX_PACKAGES=12000
try:
    import tomllib
except ModuleNotFoundError:           # Python 3.10 has no tomllib
    tomllib = None

# Formats that state an exact version for every package. Anything whose version
# has to be resolved by running a build tool stays out: this module never runs
# repository code, so it would have to guess, and a guessed version produces
# advisory matches that look like evidence but are not.
SUPPORTED={'package-lock.json','npm-shrinkwrap.json','go.mod',
           'Pipfile.lock','composer.lock','Gemfile.lock','gradle.lockfile'}
TOML_SUPPORTED={'poetry.lock','uv.lock','Cargo.lock'}
UNSUPPORTED={'yarn.lock','pnpm-lock.yaml','packages.lock.json','pom.xml',
             'build.gradle','build.gradle.kts'}
# An unsupported manifest is a dead end unless the operator is told how to turn
# it into one of the formats above.
UNSUPPORTED_HINTS={
    'build.gradle':'gradle_lockfile_missing','build.gradle.kts':'gradle_lockfile_missing',
    'pom.xml':'maven_lockfile_missing',
    'yarn.lock':'yarn_lock_unsupported','pnpm-lock.yaml':'pnpm_lock_unsupported',
    'packages.lock.json':'nuget_lock_unsupported',
}


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode()).hexdigest()


def linked(path):
    info=path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info,'st_file_attributes',0)&getattr(stat,'FILE_ATTRIBUTE_REPARSE_POINT',1024))


def package(ecosystem,name,version,path,locator,scope='unknown',evidence_kind=None):
    if not isinstance(name,str) or not isinstance(version,str) or not name or not version:
        raise ValueError('Paket nomi yoki versiyasi yo‘q.')
    if ecosystem=='PyPI':name=re.sub(r'[-_.]+','-',name).lower()
    if len(name)>240 or len(version)>120 or not re.fullmatch(r'[A-Za-z0-9@_./+!:-]+',name) or not re.fullmatch(r'[A-Za-z0-9_.+!:-]+',version):
        raise ValueError('Aniq paket nomi/versiyasi o‘qilmadi.')
    if any(marker in version for marker in ('://','file:','npm:','workspace:')):
        raise ValueError('Paket versiyasi hal qilinmagan.')
    if ecosystem=='npm' and not re.fullmatch(r'v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?',version):
        raise ValueError('npm lock ichida aniq semver kerak.')
    # A version declared in a source manifest and one pinned by a lock file are
    # different kinds of evidence; the caller says which, so a lock-derived PyPI
    # package is not labelled as if a human had written the pin.
    return {'ecosystem':ecosystem,'name':name,'version':version,'manifest':path,'locator':locator,'scope':scope,
            'evidence_kind':evidence_kind or ('declared_exact_version' if ecosystem in {'Go','PyPI'} else 'lockfile_version'),
            'id':digest([path,ecosystem,name,version,locator])[:24]}


def parse_npm(text,path):
    doc=json.loads(text);rows=[];gaps=[]
    if not isinstance(doc,dict) or doc.get('lockfileVersion') not in (1,2,3):
        raise ValueError('npm lockfile versiyasi qo‘llanmaydi.')
    def add(entry,location,name):
        if not isinstance(entry,dict):raise ValueError('npm paket formati noto‘g‘ri.')
        if entry.get('link'):
            gaps.append({'path':path,'reason':'npm_workspace_link_unresolved','locator':location});return
        try:
            rows.append(package('npm',entry.get('name') or name,entry.get('version'),path,location,
                                'development' if entry.get('dev') else 'runtime_or_optional'))
        except ValueError:gaps.append({'path':path,'reason':'npm_version_unresolved','locator':location})
    if doc['lockfileVersion']>=2:
        if not isinstance(doc.get('packages'),dict):raise ValueError('npm packages ro‘yxati yo‘q.')
        for location,entry in doc['packages'].items():
            if not location:continue
            if 'node_modules/' not in location:
                gaps.append({'path':path,'reason':'npm_workspace_unresolved','locator':location});continue
            add(entry,location,location.rsplit('node_modules/',1)[1])
    else:
        stack=[(doc.get('dependencies',{}),'dependencies',0)]
        while stack:
            entries,prefix,depth=stack.pop()
            if not isinstance(entries,dict) or depth>50:raise ValueError('npm dependency daraxti noto‘g‘ri yoki juda chuqur.')
            for name,entry in entries.items():
                location=prefix+'/'+name;add(entry,location,name)
                if isinstance(entry,dict) and entry.get('dependencies'):stack.append((entry['dependencies'],location+'/dependencies',depth+1))
    return rows,gaps


def parse_requirements(text,path):
    rows=[];gaps=[]
    # Markers are not evaluated: their environment is not known from source alone.
    lines=[];pending='';first=1
    for number,physical in enumerate(text.splitlines(),1):
        if not pending:first=number
        if physical.rstrip().endswith('\\'):
            pending+=physical.rstrip()[:-1]+' ';continue
        lines.append((first,pending+physical));pending=''
    if pending:lines.append((first,pending+'\\'))
    for index,line in lines:
        line=line.strip()
        if not line or line.startswith('#'):continue
        line=line.split(' #',1)[0].strip()
        match=re.fullmatch(r'([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[[A-Za-z0-9_,.-]+\])?\s*==\s*([A-Za-z0-9][A-Za-z0-9_.+!-]*)(?:\s+--hash=sha256:[a-fA-F0-9]{64})*(?:\s*;\s*(.+))?',line)
        if not match:
            gaps.append({'path':path,'line':index,'reason':'python_not_exact_pin_or_unsupported_directive'});continue
        rows.append(package('PyPI',match[1],match[2],path,'line:'+str(index),
                            'conditional' if match[3] else 'declared'))
    return rows,gaps


PIN = re.compile(r'([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[[A-Za-z0-9_,.-]+\])?\s*==\s*([A-Za-z0-9][A-Za-z0-9_.+!-]*)\s*$')


def parse_pyproject(text,path):
    """Exact pins declared in pyproject.toml; everything else stays a gap.

    pyproject was refused outright until now, because a dependency there may be
    a range, a marker or a value a build backend computes -- and resolving those
    would mean running the project's own build tooling, which this scanner never
    does. But a line that already says `flask==2.3.2` needs no resolution: it is
    as exact as a lock file. So exact pins are read, and every other line is
    reported as a gap with its own reason rather than the whole file being one.

    Only the standard `[project]` tables are read. A tool-specific table
    (poetry, pdm, hatch) has its own syntax for the same idea, and each of those
    projects has a real lock file that is already supported.
    """
    if tomllib is None:
        return [],[{'path':path,'reason':'toml_lock_needs_python_311'}]
    try:
        document=tomllib.loads(text)
    except Exception:
        return [],[{'path':path,'reason':'toml_unreadable'}]
    project=document.get('project') if isinstance(document.get('project'),dict) else {}
    entries=[]
    for value in project.get('dependencies') or []:
        entries.append(('dependencies',value))
    optional=project.get('optional-dependencies')
    if isinstance(optional,dict):
        for group,values in optional.items():
            for value in values or []:
                entries.append((f'optional-dependencies.{group}',value))
    rows=[];gaps=[]
    for where,value in entries:
        if not isinstance(value,str):
            gaps.append({'path':path,'reason':'python_not_exact_pin_or_unsupported_directive'});continue
        head=value.split(';',1)[0].strip()          # markers are not evaluated
        conditional=';' in value
        match=PIN.fullmatch(head)
        if not match:
            gaps.append({'path':path,'reason':'python_pyproject_not_exact_pin'});continue
        rows.append(package('PyPI',match[1],match[2],path,where,
                            'conditional' if conditional else 'declared'))
    if not rows and not gaps:
        gaps.append({'path':path,'reason':'python_pyproject_no_dependencies'})
    return rows,gaps


def parse_go(text,path):
    rows=[];gaps=[];in_require=False
    if re.search(r'(?m)^\s*(replace|exclude)\b',text):
        return [],[{'path':path,'reason':'go_replace_or_exclude_requires_resolved_inventory'}]
    for index,line in enumerate(text.splitlines(),1):
        line=line.split('//',1)[0].strip()
        if line=='require (':in_require=True;continue
        if in_require and line==')':in_require=False;continue
        value=line[8:].strip() if line.startswith('require ') else line if in_require else ''
        if not value:continue
        match=re.fullmatch(r'([^\s]+)\s+(v[^\s]+)',value)
        if match:rows.append(package('Go',match[1],match[2],path,'line:'+str(index),'declared'))
        else:gaps.append({'path':path,'line':index,'reason':'go_requirement_unresolved'})
    return rows,gaps


def parse_pipfile_lock(text,path):
    """Pipfile.lock: every entry carries an exact `==` pin."""
    doc=json.loads(text);rows=[];gaps=[]
    if not isinstance(doc,dict):raise ValueError('Pipfile.lock formati noto‘g‘ri.')
    for section,scope in (('default','runtime'),('develop','development')):
        entries=doc.get(section) or {}
        if not isinstance(entries,dict):raise ValueError('Pipfile.lock bo‘limi noto‘g‘ri.')
        for name,entry in entries.items():
            version=(entry or {}).get('version') if isinstance(entry,dict) else None
            if not isinstance(version,str) or not version.startswith('=='):
                # A VCS or path requirement has no released version to match against.
                gaps.append({'path':path,'reason':'python_lock_entry_not_versioned','locator':section+':'+str(name)});continue
            try:rows.append(package('PyPI',name,version[2:],path,section+':'+name,scope,'lockfile_version'))
            except ValueError:gaps.append({'path':path,'reason':'python_lock_entry_unresolved','locator':section+':'+str(name)})
    return rows,gaps


def parse_toml_packages(text,path,ecosystem,scope='locked'):
    """poetry.lock, uv.lock and Cargo.lock all use `[[package]]` with name+version."""
    if tomllib is None:
        raise ValueError('TOML lock fayllari uchun Python 3.11+ kerak.')
    doc=tomllib.loads(text);rows=[];gaps=[]
    entries=doc.get('package')
    if not isinstance(entries,list):raise ValueError('TOML lock ichida package ro‘yxati yo‘q.')
    for index,entry in enumerate(entries):
        if not isinstance(entry,dict):raise ValueError('TOML lock yozuvi noto‘g‘ri.')
        name,version=entry.get('name'),entry.get('version')
        locator='package['+str(index)+']'
        if not isinstance(name,str) or not isinstance(version,str):
            gaps.append({'path':path,'reason':'lock_entry_not_versioned','locator':locator});continue
        try:rows.append(package(ecosystem,name,version,path,locator,scope,'lockfile_version'))
        except ValueError:gaps.append({'path':path,'reason':'lock_entry_unresolved','locator':locator})
    return rows,gaps


def parse_gemfile_lock(text,path):
    """Gemfile.lock: only the four-space `specs:` rows carry a resolved version.

    Deeper rows are that gem's own constraints (`rails (>= 6.0)`), not versions,
    so indentation is what separates a fact from a requirement here.
    """
    rows=[];gaps=[];in_specs=False
    for index,line in enumerate(text.splitlines(),1):
        stripped=line.strip()
        if stripped=='specs:':in_specs=True;continue
        if stripped and not line.startswith(' '):in_specs=False;continue
        if not in_specs:continue
        match=re.fullmatch(r' {4}([A-Za-z0-9_.-]+) \(([^()]+)\)',line)
        if not match:continue
        try:rows.append(package('RubyGems',match[1],match[2],path,'line:'+str(index),'locked','lockfile_version'))
        except ValueError:gaps.append({'path':path,'line':index,'reason':'rubygems_version_unresolved'})
    return rows,gaps


def parse_composer_lock(text,path):
    doc=json.loads(text);rows=[];gaps=[]
    if not isinstance(doc,dict):raise ValueError('composer.lock formati noto‘g‘ri.')
    for section,scope in (('packages','runtime'),('packages-dev','development')):
        entries=doc.get(section) or []
        if not isinstance(entries,list):raise ValueError('composer.lock bo‘limi noto‘g‘ri.')
        for entry in entries:
            name=(entry or {}).get('name') if isinstance(entry,dict) else None
            version=(entry or {}).get('version') if isinstance(entry,dict) else None
            if not isinstance(name,str) or not isinstance(version,str):
                gaps.append({'path':path,'reason':'composer_entry_not_versioned'});continue
            # Packagist tags are commonly written `v1.2.3`; advisories use `1.2.3`.
            if re.fullmatch(r'v\d.*',version):version=version[1:]
            try:rows.append(package('Packagist',name,version,path,name,scope,'lockfile_version'))
            except ValueError:gaps.append({'path':path,'reason':'composer_entry_unresolved','locator':name})
    return rows,gaps


def parse_gradle_lockfile(text,path):
    """gradle.lockfile: `group:artifact:version=configurations`, one per line."""
    rows=[];gaps=[]
    for index,line in enumerate(text.splitlines(),1):
        line=line.strip()
        if not line or line.startswith('#') or line.startswith('empty='):continue
        coordinate=line.split('=',1)[0]
        parts=coordinate.split(':')
        if len(parts)!=3:
            gaps.append({'path':path,'line':index,'reason':'gradle_coordinate_unresolved'});continue
        group,artifact,version=parts
        try:rows.append(package('Maven',group+':'+artifact,version,path,'line:'+str(index),'locked','lockfile_version'))
        except ValueError:gaps.append({'path':path,'line':index,'reason':'gradle_coordinate_unresolved'})
    return rows,gaps


def parser_for(name,is_python):
    if is_python:return parse_requirements
    if name=='pyproject.toml':return parse_pyproject
    if name=='go.mod':return parse_go
    if name=='Pipfile.lock':return parse_pipfile_lock
    if name=='Gemfile.lock':return parse_gemfile_lock
    if name=='composer.lock':return parse_composer_lock
    if name=='gradle.lockfile':return parse_gradle_lockfile
    if name in ('poetry.lock','uv.lock'):
        return lambda text,path:parse_toml_packages(text,path,'PyPI')
    if name=='Cargo.lock':
        return lambda text,path:parse_toml_packages(text,path,'crates.io')
    return parse_npm


def collect(root):
    root=Path(root).resolve();manifests=[];rows=[];gaps=[];total=0;seen=0;excluded=0
    if not root.is_dir():raise ValueError('Loyiha papkasi topilmadi.')
    for current,dirs,files in os.walk(root,followlinks=False):
        allowed=[]
        for name in sorted(dirs):
            path=Path(current)/name
            if name in EXCLUDED:excluded+=1
            elif linked(path):gaps.append({'path':path.relative_to(root).as_posix(),'reason':'linked_directory_skipped'})
            else:allowed.append(name)
        dirs[:]=allowed
        for name in sorted(files):
            seen+=1
            if seen>100000:raise ValueError('Loyiha 100000 fayl chegarasidan oshdi.')
            is_python=bool(re.fullmatch(r'requirements(?:[-_.][A-Za-z0-9_.-]+)?\.txt',name))
            if name not in SUPPORTED|TOML_SUPPORTED|UNSUPPORTED|{'package.json','pyproject.toml'} and not is_python:continue
            file=Path(current)/name;relative=file.relative_to(root).as_posix()
            if linked(file):gaps.append({'path':relative,'reason':'linked_manifest_skipped'});continue
            if not file.resolve().is_relative_to(root):raise ValueError('Manifest loyiha chegarasidan chiqdi.')
            if name=='package.json':
                if not any((file.parent/lock).is_file() for lock in ('package-lock.json','npm-shrinkwrap.json','yarn.lock','pnpm-lock.yaml')):
                    gaps.append({'path':relative,'reason':'npm_lockfile_missing'})
                continue
            if file.stat().st_size>MAX_MANIFEST:
                gaps.append({'path':relative,'reason':'manifest_over_16mb'});continue
            raw=file.read_bytes();total+=len(raw)
            if total>MAX_TOTAL or len(manifests)>=500:raise ValueError('Manifestlar 64 MB yoki 500 fayl chegarasidan oshdi.')
            item={'path':relative,'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'state':'unsupported'}
            manifests.append(item)
            if name in UNSUPPORTED:
                gaps.append({'path':relative,'reason':UNSUPPORTED_HINTS.get(name,'unsupported_manifest')});continue
            if name=='pyproject.toml' and tomllib is None:
                gaps.append({'path':relative,'reason':'toml_lock_needs_python_311'});continue
            if name in TOML_SUPPORTED and tomllib is None:
                gaps.append({'path':relative,'reason':'toml_lock_needs_python_311'});continue
            try:
                text=raw.decode('utf-8-sig')
                found,missing=parser_for(name,is_python)(text,relative)
                rows.extend(found);gaps.extend(missing);item.update(state='partial' if missing else 'parsed',packages=len(found))
            except (ValueError,TypeError,KeyError,RecursionError):
                item['state']='invalid';gaps.append({'path':relative,'reason':'invalid_manifest'})
            if len(rows)>MAX_PACKAGES:raise ValueError('12000 paket nusxasi chegarasidan oshdi.')
    rows.sort(key=lambda p:(p['manifest'],p['ecosystem'],p['name'],p['version'],p['locator']))
    return {'schema_version':1,'packages':rows,'manifests':manifests,'gaps':gaps,
            'sha256':digest(manifests),'unique_packages':len({(p['ecosystem'],p['name'],p['version']) for p in rows}),
            'occurrences':len(rows),'excluded_directories':excluded,
            'scope':('npm lock v1–v3, Python == pins va Pipfile/poetry/uv lock, Go require, '
                     'Gradle lockfile (Maven), Gemfile.lock (RubyGems), composer.lock (Packagist), '
                     'Cargo.lock (crates.io). Faqat aniq versiya yozilgan formatlar o‘qiladi — versiyani '
                     'hal qilish uchun build vositasini ishga tushirish kerak bo‘lgan fayllar (pom.xml, '
                     'build.gradle) qamrovga kirmaydi va bo‘shliq sifatida ko‘rsatiladi. '
                     'pyproject.toml dan faqat aniq pinlangan (`==`) qatorlar o‘qiladi; diapazon va '
                     'marker bilan yozilganlari bo‘shliq bo‘lib qoladi. '
                     'Tranzitiv bog‘liqliklar va ishlayotgan muhitning to‘liq inventari kafolatlanmaydi. '
                     'Repository kodi bajarilmadi.')}
