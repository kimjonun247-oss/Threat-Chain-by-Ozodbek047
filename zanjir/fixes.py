"""Fix suggestions: which version to move to, and a ready diff where one is safe.

The data was already in every report -- OSV's fixed versions, Trivy's fixed
package versions, the exact Dockerfile/Compose/Kubernetes line a check fired
on -- but each finding said only "update" or "fix the configuration". This
module turns it into something an engineer can apply:

  - **Dependencies**: per package, the lowest version that fixes every matched
    advisory (for each advisory: the smallest fixed version above the current
    one; then the highest of those). The proposed version is queried against
    OSV again: when it is itself affected, the next fix is tried (at most three
    rounds) and the plan says whether the target came back clean. A unified
    diff is produced for manifests that pin the version literally
    (requirements*.txt, pyproject.toml, go.mod, pom.xml, *.csproj,
    build.gradle); every ecosystem gets the command that does it.
  - **Images**: the OS packages with fixes, as one ready `RUN apk|apt-get|dnf`
    line for the Dockerfile, language packages as their install command, and a
    note when the base OS is past end of support.
  - **IaC and Compose/Nginx**: a unified diff for checks whose fix is one
    deterministic edit (non-root USER, --no-install-recommends, privileged /
    host namespaces off, port bound to loopback, docker.sock removed,
    proxy_ssl_verify on ...). Checks that need a human decision (which base
    tag, which health command) get the explanation, not a guess.

Nothing is applied. A diff is a proposal next to its finding; the major
version jumps are marked, because an upgrade that fixes a CVE can still break
the build.
"""
import difflib
import re

PRE_RELEASE = {'a', 'alpha', 'b', 'beta', 'rc', 'c', 'pre', 'preview', 'dev', 'snapshot', 'm', 'cr', 'ea'}
MAX_ROUNDS = 3


# ---- versions ------------------------------------------------------------------
def version_key(value):
    """A sort key good enough across semver, PEP 440, Maven and distro versions."""
    text = str(value or '').strip()
    text = re.sub(r'^[vV](?=\d)', '', text).split('+')[0]
    key = []
    for part in re.findall(r'\d+|[A-Za-z]+', text):
        if part.isdigit():
            key.append((1, int(part), ''))
        else:
            word = part.lower()
            key.append((0 if word in PRE_RELEASE else 2, 0, word))
    # A release sorts after its own pre-releases and before its patch levels.
    key.append((1, -1, ''))
    return key


def major(value):
    match = re.search(r'\d+', str(value or ''))
    return int(match.group()) if match else None


def next_fix(current, fixed_versions):
    """The smallest fixed version above `current`, or None."""
    above = [v for v in fixed_versions if version_key(v) > version_key(current)]
    return min(above, key=version_key) if above else None


# ---- dependencies -----------------------------------------------------------------
COMMANDS = {
    'npm': 'npm install {name}@{version}',
    'PyPI': "pip install '{name}=={version}'",
    'Go': 'go get {name}@v{version}',
    'Maven': '<version>{version}</version>  ({name})',
    'NuGet': 'dotnet add package {name} --version {version}',
    'Packagist': 'composer require {name}:^{version}',
    'crates.io': 'cargo update -p {name} --precise {version}',
    'RubyGems': 'bundle update {name} --conservative',
}
TRANSITIVE_NOTE = {
    'npm': 'Tranzitiv bo‘lsa: package.json `overrides` (npm) / `resolutions` (yarn) / `pnpm.overrides`.',
    'Maven': 'Tranzitiv bo‘lsa: <dependencyManagement> ichida versiyani belgilang.',
    'PyPI': 'Tranzitiv bo‘lsa: constraints faylida yoki to‘g‘ridan-to‘g‘ri pin bilan belgilang.',
}


def command_for(ecosystem, name, version, lockfiles=()):
    if ecosystem == 'npm' and any(path.endswith('yarn.lock') for path in lockfiles):
        return f'yarn add {name}@{version}'
    if ecosystem == 'npm' and any(path.endswith('pnpm-lock.yaml') for path in lockfiles):
        return f'pnpm add {name}@{version}'
    if ecosystem == 'PyPI' and any(path.endswith('poetry.lock') for path in lockfiles):
        return f'poetry add {name}@^{version}'
    template = COMMANDS.get(ecosystem)
    return template.format(name=name, version=re.sub(r'^v', '', version)) if template else None


def pep503(name):
    return re.sub(r'[-_.]+', '-', name).lower()


def edit_manifest(path, text, ecosystem, name, old, new):
    """The manifest text with `name` moved from `old` to `new`, or None when it is not pinned there."""
    base = path.rsplit('/', 1)[-1]
    lines = text.splitlines(keepends=True)
    changed = False
    if ecosystem == 'PyPI' and re.fullmatch(r'requirements(?:[-_.][A-Za-z0-9_.-]+)?\.txt', base):
        for i, line in enumerate(lines):
            match = re.match(r'^(\s*)([A-Za-z0-9][A-Za-z0-9._-]*)(\s*(?:\[[^\]]*\])?\s*==\s*)([^\s;#]+)(.*)$', line.rstrip('\r\n'))
            if match and pep503(match.group(2)) == pep503(name) and match.group(4) == old:
                ending = line[len(line.rstrip('\r\n')):]
                lines[i] = match.group(1) + match.group(2) + match.group(3) + new + match.group(5) + ending
                changed = True
    elif ecosystem == 'PyPI' and base == 'pyproject.toml':
        pattern = re.compile(r'(["\'])(' + re.escape(name) + r')(\s*(?:\[[^\]]*\])?\s*==\s*)' + re.escape(old) + r'(\1|[;\s])', re.I)
        for i, line in enumerate(lines):
            updated = pattern.sub(lambda m: m.group(1) + m.group(2) + m.group(3) + new + m.group(4), line)
            changed |= updated != line
            lines[i] = updated
    elif ecosystem == 'Go' and base == 'go.mod':
        pattern = re.compile(r'^(\s*(?:require\s+)?' + re.escape(name) + r'\s+)v?' + re.escape(old.lstrip('v')) + r'(\b.*)$')
        for i, line in enumerate(lines):
            body = line.rstrip('\r\n')
            match = pattern.match(body)
            if match:
                lines[i] = match.group(1) + 'v' + new.lstrip('v') + match.group(2) + line[len(body):]
                changed = True
    elif ecosystem == 'Maven' and base == 'pom.xml' and ':' in name:
        group, artifact = name.split(':', 1)
        block = re.compile(r'<dependency>(?:(?!</dependency>).)*?</dependency>', re.S)

        def bump(match):
            nonlocal changed
            chunk = match.group(0)
            if f'<groupId>{group}</groupId>' in chunk and f'<artifactId>{artifact}</artifactId>' in chunk \
                    and f'<version>{old}</version>' in chunk:
                changed = True
                return chunk.replace(f'<version>{old}</version>', f'<version>{new}</version>')
            return chunk
        edited = block.sub(bump, text)
        return edited if changed else None
    elif ecosystem == 'Maven' and base in ('build.gradle', 'build.gradle.kts'):
        pattern = re.compile(r'(["\'])' + re.escape(name) + ':' + re.escape(old) + r'(["\':@])')
        edited = pattern.sub(lambda m: m.group(1) + name + ':' + new + m.group(2), text)
        return edited if edited != text else None
    elif ecosystem == 'NuGet' and base.endswith(('.csproj', '.fsproj', '.vbproj')):
        pattern = re.compile(r'(<PackageReference\s+Include="' + re.escape(name) + r'"\s+Version=")' + re.escape(old) + '"', re.I)
        edited = pattern.sub(lambda m: m.group(1) + new + '"', text)
        return edited if edited != text else None
    return ''.join(lines) if changed else None


# A diff carries lines of the project's own files into the report. Reports never
# hold secret values, so any line that assigns something secret-looking keeps
# its key and loses its value -- such a hunk is then applied by hand.
SECRET_LINE = re.compile(r'(?i)^([+\- ]\s*-?\s*["\']?[\w.-]*(?:pass(?:word)?|secret|token|api[_-]?key|private[_-]?key|'
                         r'credential|auth)[\w.-]*["\']?\s*[:=]\s*)(["\']?)[^\s"\'#]+')


def redact(diff):
    lines, hidden = [], 0
    for line in diff.splitlines(keepends=True):
        if not line.startswith(('---', '+++', '@@')):
            masked = SECRET_LINE.sub(lambda m: m.group(1) + m.group(2) + '***', line)
            hidden += masked != line
            line = masked
        lines.append(line)
    return ''.join(lines), hidden


def unified(path, before, after, context=2):
    diff = ''.join(difflib.unified_diff(before.splitlines(keepends=True), after.splitlines(keepends=True),
                                        fromfile='a/' + path, tofile='b/' + path, n=context))
    text, hidden = redact(diff)
    return text + ('# (maxfiy qiymatli qatorlar *** bilan yashirildi — bu bo‘lakni qo‘lda qo‘llang)\n' if hidden else '')


def dependency_plan(findings, manifests=None, query=None):
    """Per-package upgrade plan for dependency findings.

    `manifests`: {relative path: text} of manifests that may pin versions
    literally (read while the source was available). `query`: OSV lookup
    (advisories.query_packages); None skips the re-check of proposed versions.
    """
    manifests = manifests or {}
    packages = {}
    for finding in findings:
        package = finding.get('package') or {}
        key = (package.get('ecosystem'), package.get('name'), package.get('version'))
        if not all(key):
            continue
        entry = packages.setdefault(key, {'advisories': [], 'fixes': [], 'unfixed': [],
                                          'manifests': sorted({o.get('manifest') for o in finding.get('occurrences') or []
                                                               if o.get('manifest')})})
        entry['advisories'].append(finding['advisory_id'])
        step = next_fix(key[2], finding.get('fixed_versions') or [])
        (entry['fixes'] if step else entry['unfixed']).append((finding['advisory_id'], step))
    plan = []
    for (ecosystem, name, version), entry in sorted(packages.items(), key=lambda item: (item[0][0], item[0][1].lower())):
        target = max((step for _, step in entry['fixes']), key=version_key, default=None)
        row = {'ecosystem': ecosystem, 'name': name, 'current': version, 'upgrade_to': target,
               'advisories': sorted(set(entry['advisories'])),
               'without_fix': sorted({advisory for advisory, _ in entry['unfixed']}),
               'major_upgrade': bool(target and major(target) is not None and major(version) is not None
                                     and major(target) > major(version)),
               'target_check': 'not_checked', 'diffs': [], 'command': None,
               'transitive_note': TRANSITIVE_NOTE.get(ecosystem)}
        if target and query is not None:
            row['upgrade_to'], row['target_check'], row['still_affected_by'] = recheck(query, ecosystem, name, target)
            target = row['upgrade_to']
            row['major_upgrade'] = bool(major(target) is not None and major(version) is not None and major(target) > major(version))
        if target:
            row['command'] = command_for(ecosystem, name, target, entry['manifests'])
            for path, text in sorted(manifests.items()):
                edited = edit_manifest(path, text, ecosystem, name, version, target)
                if edited is not None and edited != text:
                    row['diffs'].append({'path': path, 'diff': unified(path, text, edited)})
        plan.append(row)
    return {'packages': plan,
            'summary': {'packages': len(plan), 'with_target': sum(bool(p['upgrade_to']) for p in plan),
                        'target_clean': sum(p['target_check'] == 'clean' for p in plan),
                        'with_diff': sum(bool(p['diffs']) for p in plan),
                        'major_upgrades': sum(p['major_upgrade'] for p in plan)},
            'note': ('Tavsiya: har bir advisory uchun joriy versiyadan katta eng kichik tuzatilgan versiya, ulardan eng '
                     'kattasi. Maqsad versiya OSV’da qayta tekshirilgan (target_check). Major versiya o‘zgarishi mos '
                     'kelmaslikka olib kelishi mumkin — yangilashdan keyin testlar va qayta skan shart.')}


def recheck(query, ecosystem, name, target):
    """(version, 'clean'|'still_affected'|'unavailable', advisories) after up to MAX_ROUNDS OSV look-ups."""
    remaining = []
    for _ in range(MAX_ROUNDS):
        try:
            matches, details, errors, _ = query([{'ecosystem': ecosystem, 'name': name, 'version': target}])
        except Exception:                            # noqa: BLE001 -- a feed outage must not break the report
            return target, 'unavailable', []
        if errors and not matches:
            return target, 'unavailable', []
        ids = [vid for vid in matches.get((ecosystem, name, target), []) if not (details.get(vid) or {}).get('withdrawn')]
        if not ids:
            return target, 'clean', []
        remaining = sorted(ids)
        fixes = []
        for vid in ids:
            fixed = set()
            for affected in (details.get(vid) or {}).get('affected') or []:
                for interval in affected.get('ranges') or []:
                    fixed |= {e['fixed'] for e in interval.get('events') or [] if isinstance(e.get('fixed'), str)}
            step = next_fix(target, fixed)
            if step:
                fixes.append(step)
        if not fixes:
            break
        target = max(fixes, key=version_key)
    return target, 'still_affected', remaining


# ---- images ----------------------------------------------------------------------
RHEL = {'redhat', 'centos', 'rocky', 'alma', 'almalinux', 'amazon', 'fedora', 'oracle', 'photon', 'cbl-mariner', 'azurelinux'}
LANGUAGE = {'python-pkg': "pip install --no-cache-dir {spec}", 'node-pkg': 'npm install {spec}',
            'gobinary': 'go get {spec}', 'jar': '<version> {spec}', 'gemspec': 'gem install {spec}'}


def image_plan(report):
    findings = report.get('findings') or []
    family = str((report.get('os') or {}).get('Family') or '').lower()
    upgrades, language = {}, {}
    for finding in findings:
        package, version, fixed = finding.get('package'), finding.get('version'), finding.get('fixed_version')
        if not package or not fixed:
            continue
        # Trivy writes several fixed versions as "1.2.3, 1.3.1": the one above the current version.
        step = next_fix(version, [v.strip() for v in str(fixed).split(',') if v.strip()]) or str(fixed).split(',')[0].strip()
        bucket = upgrades if finding.get('type') == family or finding.get('type') in RHEL | {'alpine', 'debian', 'ubuntu'} else language
        known = bucket.get((finding.get('type'), package))
        if known is None or version_key(step) > version_key(known['to']):
            bucket[(finding.get('type'), package)] = {'package': package, 'from': version, 'to': step}
    os_rows = sorted(upgrades.values(), key=lambda r: r['package'])
    snippet = None
    names = ' '.join(r['package'] for r in os_rows)
    if os_rows and family == 'alpine':
        snippet = f'RUN apk add --no-cache --upgrade {names}'
    elif os_rows and family in ('debian', 'ubuntu'):
        snippet = ('RUN apt-get update && apt-get install -y --no-install-recommends --only-upgrade '
                   f'{names} && rm -rf /var/lib/apt/lists/*')
    elif os_rows and family in RHEL:
        snippet = f'RUN (dnf -y upgrade {names} || yum -y update {names}) && (dnf clean all || yum clean all)'
    language_rows = []
    for (kind, package), row in sorted(language.items()):
        template = LANGUAGE.get(kind)
        spec = f'{package}=={row["to"]}' if kind == 'python-pkg' else f'{package}@{row["to"]}'
        language_rows.append({**row, 'type': kind, 'command': template.format(spec=spec) if template else None,
                              'major_upgrade': bool(major(row['to']) is not None and major(row['from']) is not None
                                                    and major(row['to']) > major(row['from']))})
    eosl = bool((report.get('os') or {}).get('EOSL'))
    return {'os_family': family, 'os_packages': os_rows, 'dockerfile_snippet': snippet,
            'language_packages': language_rows,
            'base_image_note': (f"{family} {(report.get('os') or {}).get('Name', '')} qo‘llab-quvvatlash muddati tugagan (EOSL): "
                                'paketlarni yangilash vaqtinchalik chora; base image’ni qo‘llab-quvvatlanadigan relizga '
                                'ko‘chiring va qayta skan qiling.') if eosl else None,
            'note': ('Dockerfile’da FROM qatoridan keyin qo‘shing va image’ni qayta yig‘ing. Image ichidagi paketlar '
                     'yangilanadi; ilova kodi va base tag o‘zgarmaydi.') if snippet else None,
            'summary': {'os_packages': len(os_rows), 'language_packages': len(language_rows), 'eosl': eosl}}


# ---- IaC ---------------------------------------------------------------------------
def _dockerfile_user(text):
    lines = text.splitlines(keepends=True)
    users = [i for i, l in enumerate(lines) if re.match(r'\s*USER\s', l, re.I)]
    if users and re.match(r'\s*USER\s+(root|0)(\s|:|$)', lines[users[-1]], re.I):
        lines[users[-1]] = re.sub(r'(?i)(USER\s+)\S+', r'\g<1>10001', lines[users[-1]], count=1)
        return ''.join(lines)
    if users:
        return None
    finals = [i for i, l in enumerate(lines) if re.match(r'\s*(CMD|ENTRYPOINT)\s', l, re.I)]
    at = finals[0] if finals else len(lines)
    if lines and not lines[-1].endswith('\n') and at == len(lines):
        lines[-1] += '\n'
    lines.insert(at, 'USER 10001\n')
    return ''.join(lines)


def _no_recommends(text):
    edited = re.sub(r'(apt-get\s+(?:-\S+\s+)*install)(?![^\n&;|]*--no-install-recommends)', r'\1 --no-install-recommends', text)
    return edited if edited != text else None


def _yaml_flag(key, value_from, value_to):
    pattern = re.compile(r'^(\s*' + key + r':\s*)' + value_from + r'(\s*(?:#.*)?)$', re.M)

    def edit(text):
        edited = pattern.sub(lambda m: m.group(1) + value_to + m.group(2), text)
        return edited if edited != text else None
    return edit


IAC_EDITS = {
    'DS-0002': (_dockerfile_user, 'Konteyner root emas foydalanuvchi (UID 10001) bilan ishlaydi. Ilova yozadigan '
                                  'papkalar shu UID uchun yozish mumkin bo‘lishini tekshiring.'),
    'DS-0029': (_no_recommends, 'Keraksiz tavsiya etilgan paketlar o‘rnatilmaydi (kichikroq hujum yuzasi).'),
    'KSV-0017': (_yaml_flag('privileged', 'true', 'false'), 'Konteyner imtiyozli rejimdan chiqariladi.'),
    'KSV-0001': (_yaml_flag('allowPrivilegeEscalation', 'true', 'false'), 'Imtiyozni oshirish taqiqlanadi.'),
    'KSV-0009': (_yaml_flag('hostNetwork', 'true', 'false'), 'Pod host tarmoq nomlar fazosidan ajratiladi.'),
    'KSV-0010': (_yaml_flag('hostPID', 'true', 'false'), 'Pod host PID nomlar fazosidan ajratiladi.'),
    'KSV-0008': (_yaml_flag('hostIPC', 'true', 'false'), 'Pod host IPC nomlar fazosidan ajratiladi.'),
    'KSV-0012': (_yaml_flag('runAsNonRoot', 'false', 'true'), 'Konteyner root sifatida ishga tushmaydi.'),
    'KSV-0014': (_yaml_flag('readOnlyRootFilesystem', 'false', 'true'), 'Root fayl tizimi faqat o‘qish uchun.'),
}
IAC_ADVICE = {
    'DS-0001': '`:latest` o‘rniga aniq versiya yoki digest yozing (qaysi versiya — jamoa qarori, avtomatik taklif qilinmaydi).',
    'DS-0026': 'HEALTHCHECK qo‘shing; buyruq ilovaga bog‘liq (masalan `HEALTHCHECK CMD curl -fsS http://localhost:8080/health || exit 1`).',
}


def file_plan(findings, read_file, edits, advice, path_of=lambda f: f.get('path')):
    """Group the deterministic edits per file, apply them in sequence, return one diff per file."""
    by_file, notes = {}, []
    for finding in findings:
        rule, path = finding.get('rule_id'), path_of(finding)
        if rule in edits and path:
            by_file.setdefault(path, [])
            if rule not in by_file[path]:
                by_file[path].append(rule)
        elif rule in advice:
            notes.append({'rule_id': rule, 'path': path, 'advice': advice[rule]})
    files = []
    for path, rules in sorted(by_file.items()):
        try:
            original = read_file(path)
        except (OSError, ValueError, UnicodeDecodeError):
            continue
        text, applied = original, []
        for rule in rules:
            edited = edits[rule][0](text)
            if edited is not None and edited != text:
                text = edited
                applied.append({'rule_id': rule, 'why': edits[rule][1]})
        if applied:
            files.append({'path': path, 'rules': applied, 'diff': unified(path, original, text)})
    return {'files': files, 'advice': notes,
            'summary': {'files_with_diff': len(files), 'rules_fixed': sum(len(f['rules']) for f in files),
                        'advice_only': len(notes)},
            'note': 'Diff avtomatik qo‘llanmaydi. Qo‘llagach, qayta skan qiling.'}


def iac_plan(findings, root):
    from pathlib import Path
    base = Path(root).resolve()

    def read_file(path):
        target = (base / path).resolve()
        if not target.is_relative_to(base) or target.stat().st_size > 1024 * 1024:
            raise ValueError('path')
        return target.read_text(encoding='utf-8')
    return file_plan(findings, read_file, IAC_EDITS, IAC_ADVICE)


# ---- Compose / Nginx (repository stage) -----------------------------------------------
DANGEROUS_CAPS = ('SYS_ADMIN', 'SYS_PTRACE', 'NET_ADMIN', 'SYS_MODULE', 'DAC_READ_SEARCH', 'ALL')


def _inline_items(value):
    return [item.strip() for item in value.split(',') if item.strip()]


def _edit_list(body, key, edit_item):
    """Apply edit_item(raw) -> new raw | None (drop) to both `key: [a, b]` and block `- a` lists."""
    def inline(match):
        items = [edit_item(item) for item in _inline_items(match.group(2))]
        return match.group(1) + '[' + ', '.join(item for item in items if item is not None) + ']' + match.group(3)
    body = re.sub(r'(?m)^(\s*' + key + r':\s*)\[([^\]\n]*)\](.*)$', inline, body)
    block = re.search(r'(?m)^(?P<indent>\s*)' + key + r':\s*\n(?P<items>(?:(?P=indent)\s+-.*\n)+)', body)
    if block:
        lines = []
        for line in block.group('items').splitlines(keepends=True):
            item = re.match(r'^(\s*-\s*)(.*?)(\s*)$', line.rstrip('\n'))
            edited = edit_item(item.group(2))
            if edited is not None:
                lines.append(item.group(1) + edited + item.group(3) + '\n')
        body = body[:block.start('items')] + ''.join(lines) + body[block.end('items'):]
    return body


def _unquote(raw):
    quote = raw[:1] if raw[:1] in '"\'' and raw[-1:] == raw[:1] else ''
    return quote, raw[1:-1] if quote else raw


def compose_edits(service):
    """Edits for one service's block in a Compose file."""

    def within_service(text, transform):
        # The service block: from "  <service>:" to the next line at the same indent.
        match = re.search(r'(?m)^(?P<indent>[ \t]*)' + re.escape(service) + r':[ \t]*\n(?P<body>(?:(?P=indent)[ \t]+.*\n|[ \t]*\n)*)', text)
        if not match:
            return None
        body = match.group('body')
        edited = transform(body)
        if edited is None or edited == body:
            return None
        return text[:match.start('body')] + edited + text[match.end('body'):]

    def loopback(raw):
        quote, value = _unquote(raw)
        if re.fullmatch(r'(?:0\.0\.0\.0:)?\d+(?:-\d+)?:\d+(?:-\d+)?(?:/(?:tcp|udp))?', value):
            return quote + '127.0.0.1:' + re.sub(r'^0\.0\.0\.0:', '', value) + quote
        return raw

    def no_socket(raw):
        return None if _unquote(raw)[1].startswith('/var/run/docker.sock') else raw

    def safe_cap(raw):
        return None if _unquote(raw)[1].upper() in DANGEROUS_CAPS else raw

    def ports(text):
        return within_service(text, lambda body: _edit_list(body, 'ports', loopback))

    def no_host_ports(text):
        # Behind a proxy the service needs no host port at all; a loopback port
        # would still be a second way in that skips the proxy's checks.
        def fix(body):
            body = re.sub(r'(?m)^\s*ports:\s*\[[^\]\n]*\].*\n', '', body)
            return re.sub(r'(?m)^(?P<indent>\s*)ports:\s*\n(?:(?P=indent)\s+-.*\n)+', '', body)
        return within_service(text, fix)

    def socket(text):
        return within_service(text, lambda body: _edit_list(body, 'volumes', no_socket))

    def unprivileged(text):
        def fix(body):
            body = re.sub(r'(?m)^(\s*privileged:\s*)true\b', r'\1false', body)
            return _edit_list(body, 'cap_add', safe_cap)
        return within_service(text, fix)

    def debug_off(text):
        def fix(body):
            body = re.sub(r'(?mi)^(\s*-?\s*["\']?(?:DEBUG|FLASK_DEBUG|DJANGO_DEBUG|APP_DEBUG)["\']?\s*[:=]\s*["\']?)(true|1|yes|on)\b',
                          lambda m: m.group(1) + ('false' if m.group(2).isalpha() else '0'), body)
            return re.sub(r'(?mi)^(\s*-?\s*["\']?(?:NODE_ENV|FLASK_ENV|APP_ENV|RAILS_ENV)["\']?\s*[:=]\s*["\']?)development\b',
                          r'\1production', body)
        return within_service(text, fix)
    return {'RP-001': ports, 'RP-003': no_host_ports, 'RP-004': no_host_ports, 'RP-007': socket,
            'RP-008': unprivileged, 'RP-006': debug_off}


COMPOSE_WHY = {'RP-001': 'Port faqat lokal interfeysga (127.0.0.1) bog‘lanadi; tashqi kirish kerak bo‘lsa proxy orqali.',
               'RP-003': 'Proxy ortidagi xizmatning host porti olib tashlanadi: kirish faqat proxy orqali.',
               'RP-004': 'Ishonch sarlavhasini soxtalashtirish yo‘li yopiladi: backend’ning host porti olib tashlanadi.',
               'RP-007': 'Docker socket konteynerga ulanmaydi (host ustidan to‘liq nazorat yo‘li yopiladi).',
               'RP-008': 'privileged o‘chiriladi va xavfli capability’lar olib tashlanadi.',
               'RP-006': 'Debug/development rejimi o‘chiriladi.'}
def _changed(text, edited):
    return edited if edited != text else None


def _alias_slash(text):
    # `location /static { alias /var/www/static/; }` -> `location /static/ {`
    pattern = re.compile(r'(location\s+)(/[^\s{;]*[^/\s{;])(\s*\{[^{}]*?\balias\s+[^;{}]*/\s*;)')
    return _changed(text, pattern.sub(lambda m: m.group(1) + m.group(2) + '/' + m.group(3), text))


def _repeat_headers(text):
    """Copy server-level add_header lines into every location block that sets its own.

    nginx inherits add_header only when a block sets none; one Cache-Control in
    a location silently drops X-Frame-Options & co. for that path.
    """
    lines = text.splitlines(keepends=True)
    depth, outer, blocks, current = 0, [], [], None
    for index, line in enumerate(lines):
        code = line.split('#', 1)[0]
        if depth == 1 and re.match(r'\s*add_header\s', code):
            outer.append(line.strip())
        if re.match(r'\s*location\b', code) and '{' in code and depth == 1:
            current = {'start': index, 'headers': [], 'indent': None}
        elif current is not None and re.match(r'\s*add_header\s', code):
            current['headers'].append(line.strip())
            current['indent'] = re.match(r'\s*', line).group()
        depth += code.count('{') - code.count('}')
        if current is not None and depth == 1:
            if current['headers']:
                blocks.append(current)
            current = None
    inserted = 0
    for block in blocks:
        names = {h.split()[1].lower() for h in block['headers'] if len(h.split()) > 1}
        missing = [h for h in outer if len(h.split()) > 1 and h.split()[1].lower() not in names]
        if missing:
            at = block['start'] + 1 + inserted
            lines[at:at] = [block['indent'] + h + '\n' for h in missing]
            inserted += len(missing)
    return _changed(text, ''.join(lines))


NGINX_EDITS = {
    'RP-002': (lambda text: _changed(text, re.sub(r'(?m)^(\s*proxy_ssl_verify\s+)off\s*;', r'\1on;', text)),
               'Upstream TLS sertifikati tekshiriladi (proxy_ssl_trusted_certificate ham kerak bo‘ladi).'),
    'RP-009': (_alias_slash, 'location prefiksi `/` bilan tugaydi — `/static../` bilan alias ildizidan chiqib bo‘lmaydi.'),
    'RP-011': (_repeat_headers, 'Server darajasidagi xavfsizlik sarlavhalari o‘z add_header’i bor blokda ham takrorlanadi.'),
}
REPOSITORY_ADVICE = {
    'RP-005': 'Ochiq xizmat va ma’lumotlar bazasini alohida Compose tarmoqlariga ajrating (faqat kerakli xizmat ikkalasiga ulanadi).',
    'RP-010': 'proxy_pass manzilini so‘rovdagi o‘zgaruvchidan qurmang: ruxsat etilgan upstream’lar ro‘yxati (map) yoki qat’iy manzil ishlating.',
}


def repository_plan(report, read_file):
    """Diffs for the Compose file and nginx configs of a repository report."""
    compose = (report.get('profile') or {}).get('compose')
    evidence = {row.get('id'): row for row in report.get('evidence') or []}
    # A proxy/gateway is published on purpose: binding it to loopback would take
    # the site offline. It gets advice, not a diff.
    proxies = {edge.get('from') for edge in report.get('edges') or []}
    files, advice = {}, []
    for finding in report.get('findings') or []:
        rule, service = finding.get('rule_id'), finding.get('service_id')
        if rule in ('RP-001', 'RP-003') and service in proxies:
            advice.append({'rule_id': rule, 'service_id': service,
                           'advice': 'Bu xizmat proxy/gateway — ochiq bo‘lishi kutilgan. Portni saqlang, lekin TLS, '
                                     'autentifikatsiya va firewall qoidasini tekshiring; kerak bo‘lmasa 127.0.0.1 ga bog‘lang.'})
            continue
        if rule in COMPOSE_WHY and compose and service:
            if (rule, service) not in files.setdefault(compose, []):
                files[compose].append((rule, service))
        elif rule in NGINX_EDITS:
            # The nginx file is the one the finding's evidence points into.
            paths = [(evidence.get(eid) or {}).get('path') for eid in finding.get('evidence_ids') or []]
            read_files = {row.get('path') for row in report.get('files') or []}
            path = next((p for p in paths if p and p != compose and p in read_files), None)
            if path and (rule, None) not in files.setdefault(path, []):
                files[path].append((rule, None))
        elif rule in REPOSITORY_ADVICE:
            advice.append({'rule_id': rule, 'service_id': service, 'advice': REPOSITORY_ADVICE[rule]})
    result = []
    for path, items in sorted(files.items()):
        try:
            original = read_file(path)
        except (OSError, ValueError, UnicodeDecodeError):
            continue
        text, applied = original, []
        for rule, service in items:
            edit = compose_edits(service)[rule] if service else NGINX_EDITS[rule][0]
            edited = edit(text)
            if edited is not None and edited != text:
                text = edited
                applied.append({'rule_id': rule, 'service_id': service,
                                'why': COMPOSE_WHY.get(rule) or NGINX_EDITS[rule][1]})
        if applied:
            result.append({'path': path, 'rules': applied, 'diff': unified(path, original, text)})
    return {'files': result, 'advice': advice,
            'summary': {'files_with_diff': len(result), 'rules_fixed': sum(len(f['rules']) for f in result),
                        'advice_only': len(advice)},
            'note': 'Diff avtomatik qo‘llanmaydi. Tashqi kirish haqiqatan kerak bo‘lsa, portni proxy orqali oching.'}


# Manifests whose versions a diff can move. Read while the source is at hand
# (a remote clone is deleted right after the inventory).
DIFFABLE = re.compile(r'^(requirements(?:[-_.][A-Za-z0-9_.-]+)?\.txt|pyproject\.toml|go\.mod|pom\.xml|'
                      r'build\.gradle(?:\.kts)?|.+\.(?:cs|fs|vb)proj)$')


def read_manifests(root, limit=200, max_bytes=512 * 1024):
    import os
    from pathlib import Path
    from .inventory import EXCLUDED
    base = Path(root).resolve()
    found = {}
    for current, dirs, files in os.walk(base, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in EXCLUDED and not os.path.islink(os.path.join(current, d)))
        for name in sorted(files):
            if not DIFFABLE.match(name):
                continue
            path = Path(current) / name
            try:
                if path.is_symlink() or path.stat().st_size > max_bytes or not path.resolve().is_relative_to(base):
                    continue
                found[path.relative_to(base).as_posix()] = path.read_text(encoding='utf-8')
            except (OSError, UnicodeDecodeError):
                continue
            if len(found) >= limit:
                return found
    return found
