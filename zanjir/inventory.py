"""Bounded dependency evidence collection. Never resolve/install/run repository code."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import urllib.parse

from vendor import yaml

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
# Build-tool output is accepted where the build tool itself resolved every
# version: `mvn dependency:tree` (text or JSON) and `gradle dependencies`. The
# operator runs the build tool; this module still never does.
BUILD_TOOL_OUTPUT={'dependency-tree.txt','dependency-tree.json','gradle-dependencies.txt'}
SUPPORTED={'package-lock.json','npm-shrinkwrap.json','yarn.lock','pnpm-lock.yaml','go.mod',
           'Pipfile.lock','composer.lock','Gemfile.lock','gradle.lockfile','packages.lock.json'}|BUILD_TOOL_OUTPUT
TOML_SUPPORTED={'poetry.lock','uv.lock','Cargo.lock'}
UNSUPPORTED={'pom.xml','build.gradle','build.gradle.kts'}
# An unsupported manifest is a dead end unless the operator is told how to turn
# it into one of the formats above.
UNSUPPORTED_HINTS={
    'build.gradle':'gradle_lockfile_missing','build.gradle.kts':'gradle_lockfile_missing',
    'pom.xml':'maven_lockfile_missing',
}
# A build script next to a file that states its resolved versions is covered.
RESOLVED_BY={
    'pom.xml':('dependency-tree.txt','dependency-tree.json'),
    'build.gradle':('gradle.lockfile','gradle-dependencies.txt','dependency-tree.txt'),
    'build.gradle.kts':('gradle.lockfile','gradle-dependencies.txt','dependency-tree.txt'),
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


YARN_ENTRY=re.compile(r'^(?P<key>[^\s#][^\n]*):\s*$')
YARN_FIELD=re.compile(r'^  (?P<field>version|resolution|resolved):?\s+"?(?P<value>[^"\n]*)"?\s*$')


def yarn_descriptor_name(descriptor):
    """Package name from a yarn v1 descriptor like `lodash@^4`, `@scope/pkg@~1`
    or an alias `alias@npm:real@^2` (whose installed package is `real`)."""
    descriptor=descriptor.strip().strip('"')
    if '@npm:' in descriptor:
        descriptor=descriptor.split('@npm:',1)[1]
    at=descriptor.find('@',1)
    return descriptor[:at] if at>0 else descriptor


def parse_yarn_lock(text,path):
    """yarn.lock, classic (v1) and Berry (v2+), read line by line.

    Both formats give every entry an exact `version`. Yarn records no dev flag,
    so scope stays 'unknown'. What is not a registry package -- a git or file
    source, a workspace, a link/portal -- is a named gap, never a guess.
    """
    rows=[];gaps=[];berry='__metadata:' in text
    entries=[];current=None
    for number,line in enumerate(text.splitlines(),1):
        if not line.strip() or line.lstrip().startswith('#'):continue
        head=YARN_ENTRY.match(line)
        if head and not line.startswith(' '):
            current={'key':head.group('key'),'line':number,'fields':{}};entries.append(current);continue
        field=YARN_FIELD.match(line)
        if field and current is not None:
            current['fields'].setdefault(field.group('field'),field.group('value').strip())
    if not entries:raise ValueError('yarn.lock yozuvlari topilmadi.')
    for entry in entries:
        key=entry['key'];fields=entry['fields'];locator='line:'+str(entry['line'])
        if key=='__metadata':continue
        version=fields.get('version')
        if berry:
            resolution=fields.get('resolution','')
            match=re.fullmatch(r'(?P<name>(?:@[^/@]+/)?[^@]+)@npm:(?P<version>[^#]+)',resolution)
            patched=re.fullmatch(r'(?P<name>(?:@[^/@]+/)?[^@]+)@patch:.*?@npm%3A(?P<version>[^#]+)#.*',resolution)
            if match or patched:
                found=match or patched
                name,version=found.group('name'),urllib.parse.unquote(found.group('version'))
            else:
                gaps.append({'path':path,'reason':'yarn_non_registry_source','locator':locator});continue
        else:
            resolved=fields.get('resolved','')
            # A registry tarball always has the /-/<name>-<version>.tgz shape; a
            # git, codeload or file source does not, and its "version" is only
            # what that checkout's package.json claims.
            if resolved and not re.fullmatch(r'https?://\S+/-/[^/\s]+\.tgz(?:#\S*)?',resolved):
                gaps.append({'path':path,'reason':'yarn_non_registry_source','locator':locator});continue
            name=yarn_descriptor_name(key.split(', ')[0])
        try:rows.append(package('npm',name,version,path,locator,'unknown','lockfile_version'))
        except ValueError:gaps.append({'path':path,'reason':'yarn_version_unresolved','locator':locator})
    return rows,gaps


def pnpm_key(key,major):
    """(name, version) from a pnpm `packages` key of lockfile v5, v6 or v9."""
    text=re.sub(r'\(.*\)$','',key.lstrip('/'))
    if major<6:
        name,_,version=text.rpartition('/')
        return name,version.split('_',1)[0]
    at=text.find('@',1)
    if at<0:raise ValueError('pnpm kaliti noto‘g‘ri.')
    return text[:at],text[at+1:]


def parse_pnpm_lock(text,path):
    """pnpm-lock.yaml v5.x, v6.x and v9.x. Only registry packages are read; a
    tarball, git or directory resolution is a named gap."""
    # pnpm 9/10 may write several YAML documents into one file (the first holds
    # config dependencies, the second the project itself). Reading only one
    # document failed the whole file: vite's lockfile gave 0 of 1414 packages.
    try:
        docs=[doc for doc in yaml.safe_load_all(text) if doc is not None]
    except yaml.YAMLError as error:
        raise ValueError('pnpm-lock.yaml o‘qilmadi: '+str(getattr(error,'problem',error))[:120]) from None
    if not docs or not all(isinstance(doc,dict) for doc in docs):raise ValueError('pnpm-lock.yaml formati noto‘g‘ri.')
    entries=[]
    for doc in docs:
        try:major=int(float(str(doc.get('lockfileVersion','')).strip("'\"")))
        except ValueError:raise ValueError('pnpm lockfileVersion o‘qilmadi.') from None
        if major<5 or major>9:raise ValueError('pnpm lockfile versiyasi qo‘llanmaydi.')
        packages=doc.get('packages') or {}
        if not isinstance(packages,dict):raise ValueError('pnpm packages ro‘yxati noto‘g‘ri.')
        entries+=[(key,entry,major) for key,entry in packages.items()]
    rows=[];gaps=[]
    for key,entry,major in entries:
        entry=entry if isinstance(entry,dict) else {}
        resolution=entry.get('resolution') or {}
        if isinstance(resolution,dict) and ({'tarball','repo','directory','commit'}&set(resolution)) \
                and 'integrity' not in resolution:
            gaps.append({'path':path,'reason':'pnpm_non_registry_source','locator':str(key)});continue
        try:
            name,version=pnpm_key(str(key),major)
            name=entry.get('name') or name
            version=str(entry.get('version') or version)
            scope={True:'development',False:'runtime_or_optional'}.get(entry.get('dev'),'unknown')
            rows.append(package('npm',name,version,path,str(key),scope,'lockfile_version'))
        except ValueError:
            gaps.append({'path':path,'reason':'pnpm_version_unresolved','locator':str(key)})
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


def registry_source(ecosystem,source):
    """True when a poetry/uv/Cargo lock entry comes from a package registry."""
    if ecosystem=='crates.io':
        return isinstance(source,str) and source.startswith(('registry+','sparse+'))
    if source is None:
        return True                       # poetry: no source table means PyPI
    if isinstance(source,dict):
        kind=source.get('type')
        if kind is not None:              # poetry: legacy/explicit = another index
            return kind in {'legacy','explicit','pypi'}
        return 'registry' in source       # uv: {registry=...} vs editable/virtual/git/path/url
    return False


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
        if not registry_source(ecosystem,entry.get('source')):
            # The project's own workspace members, path and git dependencies are
            # not the registry release of that name and version; matching them
            # against crates.io/PyPI advisories would attach someone else's CVEs.
            # ripgrep's lock has 11 such crates out of 63.
            gaps.append({'path':path,'reason':'lock_entry_local_or_git','locator':locator});continue
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


def parse_nuget_lock(text,path):
    """packages.lock.json (NuGet, RestorePackagesWithLockFile): resolved per target framework."""
    doc=json.loads(text);rows=[];gaps=[];seen=set()
    if not isinstance(doc,dict) or doc.get('version') not in (1,2) or not isinstance(doc.get('dependencies'),dict):
        raise ValueError('packages.lock.json formati noto‘g‘ri.')
    for framework,entries in sorted(doc['dependencies'].items()):
        if not isinstance(entries,dict):raise ValueError('packages.lock.json bo‘limi noto‘g‘ri.')
        for name,entry in sorted(entries.items()):
            if not isinstance(entry,dict):
                gaps.append({'path':path,'reason':'nuget_entry_unresolved','locator':name});continue
            # A project reference is this repository's own code, not a NuGet release.
            if entry.get('type')=='Project':continue
            version=entry.get('resolved')
            if not isinstance(version,str):
                gaps.append({'path':path,'reason':'nuget_entry_unresolved','locator':name});continue
            if (name.lower(),version) in seen:continue      # the same package under several frameworks
            seen.add((name.lower(),version))
            try:rows.append(package('NuGet',name,version,path,framework+'/'+name,'locked','lockfile_version'))
            except ValueError:gaps.append({'path':path,'reason':'nuget_entry_unresolved','locator':name})
    return rows,gaps


MAVEN_SCOPE={'test':'development','provided':'runtime','compile':'runtime','runtime':'runtime','system':'runtime','import':'runtime'}


def maven_coordinate(text):
    """`g:a:type[:classifier]:version:scope` -> (name, version, scope) or None."""
    parts=text.split(':')
    if len(parts)==5:group,artifact,_,version,scope=parts
    elif len(parts)==6:group,artifact,_,_,version,scope=parts
    else:return None
    return group+':'+artifact,version,MAVEN_SCOPE.get(scope,'unknown')


def parse_maven_tree_json(text,path):
    """`mvn dependency:tree -DoutputType=json`: the project is the root, dependencies its children."""
    doc=json.loads(text);rows=[];gaps=[];seen=set()
    if not isinstance(doc,dict) or 'artifactId' not in doc:raise ValueError('dependency-tree.json formati noto‘g‘ri.')
    stack=[(child,1) for child in reversed(doc.get('children') or [])]
    while stack:
        node,depth=stack.pop()
        if not isinstance(node,dict):continue
        stack.extend((child,depth+1) for child in reversed(node.get('children') or []))
        group,artifact,version=node.get('groupId'),node.get('artifactId'),node.get('version')
        if not all(isinstance(v,str) and v for v in (group,artifact,version)):
            gaps.append({'path':path,'reason':'maven_tree_entry_unresolved'});continue
        name=group+':'+artifact;scope=MAVEN_SCOPE.get(node.get('scope') or 'compile','unknown')
        if (name,version,scope) in seen:continue
        seen.add((name,version,scope))
        try:rows.append(package('Maven',name,version,path,name,scope,'build_tool_resolution'))
        except ValueError:gaps.append({'path':path,'reason':'maven_tree_entry_unresolved','locator':name})
    return rows,gaps


TREE_LINE=re.compile(r'^(?:\[INFO\] )?([| ]*)(\+-|\\-|\+---|\\---) (.*)$')


def parse_dependency_tree(text,path):
    """Text output of `mvn dependency:tree` or `gradle dependencies`, told apart by the tree marks.

    Maven: `+- g:a:jar:1.0:compile`. Gradle: `+--- g:a:1.0 -> 1.2 (*)`, where the
    version after `->` is the one the build actually resolved. Entries the tool
    itself marks as not on the classpath -- Maven's `(... omitted for conflict)`,
    Gradle's `(n)` not resolved and `(c)` constraint -- are left out, and
    project references are this repository's own modules.
    """
    rows={};gaps=[];scope_now='runtime'
    # A Gradle report lists every configuration, alphabetically: annotationProcessor
    # comes before compileClasspath. Only *Classpath configurations are what the
    # build compiles against or ships, so when the report has them, nothing
    # outside them counts -- from the first line on.
    gradle_filter=bool(re.search(r'(?m)^[A-Za-z][A-Za-z0-9]*Classpath(?: - .*)?$',text));wanted=not gradle_filter
    for index,raw in enumerate(text.splitlines(),1):
        line=raw.rstrip()
        header=re.match(r'^([A-Za-z][A-Za-z0-9]*)(?: - .*)?$',line)
        if header and header.group(1).endswith('Classpath'):
            scope_now='development' if 'test' in header.group(1).lower() else 'runtime'
            wanted=True
            continue
        if header and gradle_filter:
            wanted=False                      # annotationProcessor, kapt, ...: not shipped
            continue
        match=TREE_LINE.match(line)
        if not match:continue
        if gradle_filter and not wanted:continue
        marker,body=match.group(2),match.group(3).strip()
        locator='line:'+str(index)
        if marker in ('+-','\\-'):                                   # Maven
            if body.startswith('('):continue                           # omitted duplicate/conflict
            found=maven_coordinate(body.split()[0])
            if not found:
                gaps.append({'path':path,'line':index,'reason':'maven_tree_entry_unresolved'});continue
            name,version,scope=found
        else:                                                          # Gradle
            if body.startswith('project ') or body.endswith(('(n)','(c)')) or 'FAILED' in body:continue
            body=re.sub(r'\s+\([*c n]\)$','',body)
            requested,_,resolved=body.partition(' -> ')
            parts=requested.split(':')
            if len(parts)<2:
                gaps.append({'path':path,'line':index,'reason':'gradle_tree_entry_unresolved'});continue
            name=parts[0]+':'+parts[1]
            version=(resolved or (parts[2] if len(parts)>2 else '')).strip()
            if not version or version.startswith('{') or ' ' in version:
                gaps.append({'path':path,'line':index,'reason':'gradle_tree_entry_unresolved','locator':name});continue
            scope=scope_now
        # One row per package. testRuntimeClasspath repeats every runtime
        # dependency; what ships is decided by the runtime appearance.
        known=rows.get((name,version))
        if known is not None:
            if scope=='runtime':known['scope']='runtime'
            continue
        try:rows[(name,version)]=package('Maven',name,version,path,locator,scope,'build_tool_resolution')
        except ValueError:gaps.append({'path':path,'line':index,'reason':'maven_tree_entry_unresolved','locator':name})
    if not rows and not gaps:raise ValueError('Bog‘liqlik daraxti topilmadi.')
    return list(rows.values()),gaps


def parser_for(name,is_python):
    if is_python:return parse_requirements
    if name=='pyproject.toml':return parse_pyproject
    if name=='go.mod':return parse_go
    if name=='Pipfile.lock':return parse_pipfile_lock
    if name=='Gemfile.lock':return parse_gemfile_lock
    if name=='composer.lock':return parse_composer_lock
    if name=='gradle.lockfile':return parse_gradle_lockfile
    if name=='packages.lock.json':return parse_nuget_lock
    if name=='dependency-tree.json':return parse_maven_tree_json
    if name in ('dependency-tree.txt','gradle-dependencies.txt'):return parse_dependency_tree
    if name in ('poetry.lock','uv.lock'):
        return lambda text,path:parse_toml_packages(text,path,'PyPI')
    if name=='yarn.lock':return parse_yarn_lock
    if name=='pnpm-lock.yaml':return parse_pnpm_lock
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
            if name.endswith(('.csproj','.fsproj','.vbproj')):
                # NuGet resolves versions at restore time; only its lock file states them.
                if not (Path(current)/'packages.lock.json').is_file():
                    gaps.append({'path':(Path(current)/name).relative_to(root).as_posix(),'reason':'nuget_lockfile_missing'})
                continue
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
                if any((file.parent/resolved).is_file() for resolved in RESOLVED_BY.get(name,())):
                    item['state']='covered_by_resolved_output';continue
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
            'scope':('npm lock v1–v3, yarn.lock (v1 va Berry), pnpm-lock.yaml (v5–v9), Python == pins va Pipfile/poetry/uv lock, Go require, '
                     'Gradle lockfile (Maven), Gemfile.lock (RubyGems), composer.lock (Packagist), '
                     'Cargo.lock (crates.io), packages.lock.json (NuGet), `mvn dependency:tree` natijasi '
                     '(dependency-tree.txt/.json) va `gradle dependencies` natijasi (gradle-dependencies.txt). '
                     'Faqat aniq versiya yozilgan formatlar o‘qiladi — pom.xml, build.gradle va .csproj yonida '
                     'shunday fayl bo‘lmasa, ular bo‘shliq sifatida ko‘rsatiladi (buyruq bilan). '
                     'pyproject.toml dan faqat aniq pinlangan (`==`) qatorlar o‘qiladi; diapazon va '
                     'marker bilan yozilganlari bo‘shliq bo‘lib qoladi. '
                     'Tranzitiv bog‘liqliklar va ishlayotgan muhitning to‘liq inventari kafolatlanmaydi. '
                     'Repository kodi bajarilmadi.')}
