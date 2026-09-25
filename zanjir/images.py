"""Pinned public image scanning. Download and inspect layers; never run them."""
import collections
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import re
import subprocess
import sys
import threading
import uuid
from .engine import ROOT
from . import repo_store, scanners, taxonomy, run_index, findings as findings_mod, triage
from . import verification as verification_mod

RUNS = ROOT / 'image-runs'
PROFILES = ROOT / 'profiles/images'
CACHE = ROOT / '.tools/trivy/cache'
# Windows keeps the original .tools/trivy/trivy.exe; every other platform uses
# the vendored posix/ build installed by setup_tools.py.
BINARY = ROOT / '.tools/trivy/trivy.exe' if sys.platform.startswith('win') else ROOT / '.tools/trivy/posix/trivy'
LOCK = threading.Lock()
CANCEL = {}
# An image reference, taken apart instead of matched by one large regex: the
# pieces are what the report has to record separately (which registry, which
# repository, was it pinned to a digest or was it a tag that can move).
REGISTRY_HOST = re.compile(r'^(?=.*[.:]|localhost$)[A-Za-z0-9][A-Za-z0-9.-]*(?::\d{1,5})?$')
REPOSITORY_SEGMENT = re.compile(r'^[a-z0-9]+(?:[._-][a-z0-9]+)*$')
TAG = re.compile(r'^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$')
DIGEST = re.compile(r'^sha256:[a-f0-9]{64}$')
# Kept for the callers and tests written before B6; a digest-pinned Docker Hub
# reference still matches it exactly as it always did.
REFERENCE = re.compile(r'^(?:docker\.io/)?(?:[a-z0-9][a-z0-9_-]*/)?[a-z0-9][a-z0-9._-]*@sha256:[a-f0-9]{64}$')
DEFAULT_REGISTRY = 'docker.io'


def parse_reference(value):
    """Split an image reference into registry, repository and tag/digest.

    Accepts what a person actually types: `nginx`, `nginx:1.27`,
    `crapi/crapi-web@sha256:...`, `registry.example.com:5000/team/app:1.0`.

    A tag is accepted but never treated as equivalent to a digest: a tag can be
    moved to different content tomorrow, so the report records which kind was
    asked for and, after the scan, which digest it actually resolved to.
    """
    text = str(value or '').strip()
    if not text or len(text) > 512 or any(c.isspace() for c in text) or '//' in text:
        raise ValueError('Image manzili bo‘sh yoki noto‘g‘ri.')
    if '://' in text:
        raise ValueError('Image manzili URL emas; `registry/repo:teg` yoki `repo@sha256:...` ko‘rinishida yozing.')
    digest = ''
    if '@' in text:
        text, _, digest = text.partition('@')
        if not DIGEST.fullmatch(digest):
            raise ValueError('Digest `sha256:` va 64 ta hex belgidan iborat bo‘lishi kerak.')
    head, _, rest = text.partition('/')
    if rest and REGISTRY_HOST.fullmatch(head):
        registry, repository = head, rest
    else:
        registry, repository = DEFAULT_REGISTRY, text
    tag = ''
    last = repository.rsplit('/', 1)[-1]
    if ':' in last:
        repository, _, tag = repository.rpartition(':')
        if not TAG.fullmatch(tag):
            raise ValueError('Teg noto‘g‘ri: harf/raqamdan boshlanib, 128 belgigacha bo‘lsin.')
    segments = repository.split('/')
    if not 1 <= len(segments) <= 6 or not all(REPOSITORY_SEGMENT.fullmatch(part) for part in segments):
        raise ValueError('Repozitoriy nomi noto‘g‘ri: kichik harf, raqam va . _ - belgilari.')
    if registry == DEFAULT_REGISTRY and len(segments) == 1:
        repository = 'library/' + repository          # docker.io/nginx == docker.io/library/nginx
    if not digest and not tag:
        tag = 'latest'
    canonical = f'{registry}/{repository}' + (f'@{digest}' if digest else f':{tag}')
    return {'registry': registry, 'repository': repository, 'tag': tag, 'digest': digest,
            'canonical': canonical, 'kind': 'digest' if digest else 'tag',
            'pinned': bool(digest)}


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def targets():
    rows = []
    try:
        pinned = json.loads((ROOT / 'pilot/runtime/images.json').read_text(encoding='utf-8'))
        for service, value in pinned.items():
            ref = value.get('resolved', '')
            if REFERENCE.fullmatch(ref):
                rows.append({'id': 'pilot-' + service, 'name': 'crAPI · ' + service, 'reference': ref})
    except (OSError, ValueError, AttributeError):
        pass
    for path in sorted(PROFILES.glob('*.json')):
        try:
            row = json.loads(path.read_text(encoding='utf-8'))
            if row['id'] != path.stem or not repo_store.PROFILE_ID.fullmatch(row['id']):
                continue
            parsed = parse_reference(row['reference'])
            rows.append({**row, 'registry': parsed['registry'], 'pinned': parsed['pinned'],
                         'kind': parsed['kind'], 'auth': row.get('auth', 'none')})
        except (OSError, ValueError, KeyError, TypeError):
            continue
    return rows


AUTH_MODES = ('none', 'environment', 'docker-config')


def credential_slug(host):
    """Registry host -> the suffix of the environment variables that hold its login."""
    return ''.join(c if c.isalnum() else '_' for c in str(host or '')).upper()


def credential_names(host):
    slug = credential_slug(host)
    return f'THREATCHAIN_REGISTRY_{slug}_USERNAME', f'THREATCHAIN_REGISTRY_{slug}_PASSWORD'


def registry_credentials(host, mode):
    """Environment for one scan, plus what the report may say about it.

    Nothing is stored and nothing is echoed. Two modes, both requiring a
    deliberate act outside the browser:

      environment   - the operator exported THREATCHAIN_REGISTRY_<HOST>_USERNAME
                      and _PASSWORD before starting the server. They are handed
                      to Trivy as TRIVY_USERNAME/TRIVY_PASSWORD for this one
                      subprocess and never written anywhere.
      docker-config - Trivy is pointed at the operator's real ~/.docker, so an
                      existing `docker login` is reused. The default is an empty
                      HOME precisely so this cannot happen by accident.

    The variables are per host on purpose: one exported password must not be
    offered to every registry an image reference happens to name.
    """
    if mode not in AUTH_MODES:
        raise ValueError('auth qiymati: ' + ', '.join(AUTH_MODES))
    if mode == 'none':
        return {}, {'mode': 'none', 'credentials_present': False,
                    'note': 'Ochiq registry; hech qanday kirish ma’lumoti ishlatilmadi.'}
    if mode == 'docker-config':
        config = Path.home() / '.docker'
        return ({'DOCKER_CONFIG': str(config)} if config.is_dir() else {}), {
            'mode': 'docker-config', 'credentials_present': config.is_dir(),
            'path': str(config) if config.is_dir() else None,
            'note': ('Operatorning mavjud `docker login` seansi ishlatildi. Parol bu loyihada saqlanmaydi '
                     'va hisobotga yozilmaydi.' if config.is_dir() else
                     '~/.docker topilmadi; anonim urinish qilinadi.')}
    user_var, password_var = credential_names(host)
    user, password = os.environ.get(user_var, ''), os.environ.get(password_var, '')
    if not user or not password:
        raise ValueError(f'{host} uchun kirish ma’lumoti topilmadi. Serverni ishga tushirishdan oldin '
                         f'{user_var} va {password_var} muhit o‘zgaruvchilarini o‘rnating.')
    return {'TRIVY_USERNAME': user, 'TRIVY_PASSWORD': password}, {
        'mode': 'environment', 'credentials_present': True,
        'variables': [user_var, password_var],
        'note': ('Kirish ma’lumoti faqat shu jarayonning muhitidan olindi. Qiymatlar hech qayerda '
                 'saqlanmaydi va hisobotda faqat o‘zgaruvchi nomi ko‘rinadi.')}


def register(target, reference, name=None, auth='none'):
    if not repo_store.PROFILE_ID.fullmatch(target) or target.startswith('pilot-'):
        raise ValueError('Image ID 2–40 belgili bo‘lsin; pilot- nomlari band.')
    parsed = parse_reference(reference)          # raises with the exact reason
    if auth not in AUTH_MODES:
        raise ValueError('auth qiymati: ' + ', '.join(AUTH_MODES))
    if not isinstance(name or target, str) or len(name or target) > 120:
        raise ValueError('Image nomi 120 belgidan oshmasin.')
    PROFILES.mkdir(parents=True, exist_ok=True)
    row = {'id': target, 'name': name or target, 'reference': parsed['canonical'],
           'registry': parsed['registry'], 'kind': parsed['kind'], 'pinned': parsed['pinned'],
           'auth': auth}
    if not parsed['pinned']:
        row['pin_note'] = ('Teg bilan ro‘yxatga olindi. Teg boshqa mazmunga ko‘chishi mumkin, shuning uchun '
                           'har bir skan aynan qaysi digest tekshirilganini hisobotda yozadi.')
    with (PROFILES / (target + '.json')).open('x', encoding='utf-8') as file:
        json.dump(row, file, ensure_ascii=False, indent=2)
    return row


def read(rid):
    report = run_index.read(RUNS, rid, 'Image hisoboti topilmadi.')
    return triage.attach('images', report.get('target'), report)


def history(limit=30):
    return run_index.rows(RUNS, ('id', 'target', 'reference', 'created_at', 'state', 'count'), read, limit=limit)


def enrich(findings):
    """Add CISA KEV and FIRST EPSS to the CVEs Trivy reported.

    Trivy gives a severity but says nothing about whether a CVE is actually
    being exploited. The dependency scanner has had that context since 0.6 and
    the image scanner had not, which left the SX-002 chain (an exposed service
    running an image with a known-exploited CVE) unable to ask the question.

    Both feeds are optional and their failure is recorded rather than hidden:
    `known_exploited: None` means "not checked", never "not exploited". Nothing
    here can fail the scan -- an image report is still evidence without them.
    """
    from . import advisories, threatfeeds
    cves = sorted({f['advisory_id'] for f in findings
                   if re.fullmatch(r'CVE-\d{4}-\d{4,}', str(f.get('advisory_id') or ''))})
    kev, kev_meta = advisories.kev_catalog() if cves else ({}, {'state': 'not_needed'})
    scores = threatfeeds.epss_scores(cves) if cves else {}
    available = kev_meta.get('state') == 'available'
    for finding in findings:
        advisory = finding.get('advisory_id')
        # A finding whose advisory is not a CVE (a Trivy vendor id, say) was never
        # looked up, so it stays None. Saying False would claim it was checked.
        checked = available and advisory in set(cves)
        finding['known_exploited'] = (advisory in kev) if checked else None
        finding['kev_added_on'] = str((kev.get(advisory) or {}).get('dateAdded', '')) or None if checked else None
        finding['epss'] = scores.get(advisory)
    return {'kev': kev_meta,
            'epss': {'state': 'available' if scores else 'unavailable', 'scored': len(scores), 'requested': len(cves)},
            'known_exploited_count': sum(1 for f in findings if f.get('known_exploited')) if available else None,
            'threat_context_note': ('CISA KEV va EPSS qo‘shildi. known_exploited: null — tekshirilmagan '
                                    'degani, "ekspluatatsiya qilinmaydi" degani emas.')}


def normalize(data, target=''):
    if data.get('ArtifactType') != 'container_image' or not isinstance(data.get('Results'), list):
        raise ValueError('Trivy image natijasi yoki qamrovi noto‘g‘ri.')
    findings = {}
    scopes = []
    packages = []
    for result in data['Results']:
        if not isinstance(result, dict):
            raise ValueError('Trivy natija formati noto‘g‘ri.')
        scope = {key: str(result.get(key, ''))[:500] for key in ('Target', 'Class', 'Type')}
        scope['packages'] = len(result.get('Packages') or [])
        scopes.append(scope)
        # Kept so an SBOM can be produced from the same evidence as the findings,
        # without downloading and scanning the image a second time. Only the
        # fields an SBOM needs are stored: Trivy also reports a maintainer email
        # and the installed file list, and neither belongs in an exported report.
        for package in result.get('Packages') or []:
            if not isinstance(package, dict) or not str(package.get('Name', '')).strip():
                continue
            identifier = package.get('Identifier') if isinstance(package.get('Identifier'), dict) else {}
            packages.append({'name': str(package.get('Name', ''))[:300],
                             'version': str(package.get('Version', ''))[:200],
                             'purl': str(identifier.get('PURL', ''))[:500],
                             'type': scope['Type'], 'target': scope['Target'],
                             'licenses': sorted({str(l)[:120] for l in (package.get('Licenses') or [])})[:20]})
        for row in result.get('Vulnerabilities') or []:
            package = str(row.get('PkgName', ''))[:300]
            version = str(row.get('InstalledVersion', ''))[:200]
            advisory = str(row.get('VulnerabilityID', ''))[:200]
            key = (scope['Target'], package, version, advisory)
            cwe_ids = sorted({str(c)[:20] for c in (row.get('CweIDs') or []) if re.fullmatch(r'CWE-\d+', str(c))})
            findings[key] = {
                'id': hashlib.sha256(json.dumps(key).encode()).hexdigest()[:24],
                # `id` stays as it was. `fingerprint` swaps Trivy's scan target
                # (a layer path, which changes between builds) for the registered
                # image id, so the same CVE in two different images is two
                # findings and a rebuild is not a new one.
                'fingerprint': findings_mod.fingerprint('images',
                                                        {'image_target': target, 'package': package,
                                                         'advisory_id': advisory}),
                'package': package, 'version': version, 'advisory_id': advisory,
                'severity': str(row.get('Severity', 'UNKNOWN'))[:30],
                'fixed_version': str(row.get('FixedVersion', ''))[:500],
                'title': str(row.get('Title', ''))[:2000], 'target': scope['Target'],
                'type': scope['Type'], 'state': 'image_advisory_match',
                'source': str((row.get('DataSource') or {}).get('Name', ''))[:200],
                'cwe_ids': cwe_ids, 'owasp_top10_2025': taxonomy.classify(cwe_ids),
                'verified': False,
                'verification_note': 'Trivy image qatlamidagi paket-versiya darajasida statik moslik; image ishga tushirilmagan, amaliy ta’sir tekshirilmagan. Mutaxassis qo‘lda ko‘rib chiqishi shart.',
            }
    order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'UNKNOWN': 4}
    values = sorted(findings.values(), key=lambda row: (order.get(row['severity'], 4), row['package'], row['advisory_id']))
    metadata = data.get('Metadata') or {}
    return {'findings': values, 'count': len(values), 'coverage': scopes,
            'packages': sorted(packages, key=lambda row: (row['target'], row['name'], row['version'])),
            'os': metadata.get('OS'), 'image_id': metadata.get('ImageID'),
            'repo_digests': metadata.get('RepoDigests') or [],
            'severity_counts': dict(collections.Counter(row['severity'] for row in values)),
            'verification_summary': verification_mod.summarize(values)}


GENERIC_FAILURE = 'Trivy yakunlanmadi. Hisobot papkasidagi tool.log ni tekshiring; bu toza natija emas.'
DEADLINE_FAILURE = ('Tekshiruv umumiy vaqt chegarasidan oshdi va to‘xtatildi (chegara hisobotdagi time_budget_minutes). Bu toza natija emas: '
                    'image tekshirilmagan holicha qoldi. Katta image yoki sekin tarmoq sabab bo‘lishi mumkin.')
# Trivy's own wording -> what the operator can actually do about it. The log
# stays local (it can carry registry metadata), so the cause has to be lifted
# out of it: "tool.log ni tekshiring" is not an action when the log is a file
# the web interface never shows.
FAILURE_HINTS = (
    # Checked before the generic timeout: a Java image makes Trivy fetch a
    # separate, large Java database, and a run killed mid-download leaves nothing
    # cached -- so "just retry" is the wrong advice for this one.
    ('[javadb] Downloading',
     'Trivy Java zaiflik bazasini (trivy-java-db) yuklayotganda vaqt tugadi. Baza yuklanib '
     'ulgurmagani uchun keshga ham tushmagan — oddiy qayta urinish odatda yordam bermaydi. '
     'Bu toza natija emas: image tekshirilmagan holicha qoldi. Avval kichikroq Java image’ni '
     'tekshirib bazani keshga tushiring yoki tarmoq tezligini oshiring.'),
    ('context deadline exceeded',
     'Trivy vaqt byudjetidan oshdi (hisobotdagi time_budget_minutes) — image juda katta yoki registrdan yuklash sekin. '
     'Bu toza natija emas: image tekshirilmagan holicha qoldi. Tarmoqni tekshirib qayta urinib ko‘ring.'),
    # Trivy's real wording, taken from an actual failing run rather than guessed:
    # "uncompressed layers size 1.37GB exceeds maximum allowed size 1GB".
    ('exceeds maximum allowed size',
     'Image qatlamlarining ochilgan hajmi 1 GB chegarasidan oshdi va tekshirilmadi. '
     'Bu toza natija emas. Chegara bu pilotning ongli cheklovi — aniq hajm hisobot '
     'papkasidagi tool.log da yozilgan.'),
    ('MANIFEST_UNKNOWN',
     'Registrda bunday digest topilmadi. Image manzili va digestni tekshiring.'),
    ('UNAUTHORIZED',
     'Registr kirishni rad etdi. Faqat public image qo‘llanadi; private registry qabul qilinmaydi.'),
    ('no such host',
     'Registrga ulanib bo‘lmadi (DNS). Internet ulanishini tekshiring.'),
)


def failure_reason(log_path, default=GENERIC_FAILURE):
    """A specific, actionable reason pulled out of Trivy's local log.

    `default` is what to say when the log names no known cause -- the outer
    deadline passes its own wording, so a run this project killed is never
    described as if Trivy had reported the failure itself.
    """
    try:
        text = log_path.read_text(encoding='utf-8', errors='replace')[-20000:]
    except OSError:
        return default
    for needle, message in FAILURE_HINTS:
        if needle.lower() in text.lower():
            return message
    return default


DATABASES = (('db', '--download-db-only'), ('java-db', '--download-java-db-only'))
DB_REFRESH_SECONDS = 900
# Trivy sends anonymous usage data to Aqua and checks for new versions unless
# told not to. The project's stated data policy is that only package names,
# versions and advisory ids leave this machine, so both are switched off on
# every invocation. Semgrep (--metrics off) and Nuclei (-duc) already were.
QUIET = ('--disable-telemetry', '--skip-version-check')
SIZE_LIMIT = '1GB'
# An operator may raise the limit for one scan, never past this ceiling: the
# bound exists so a single scan cannot fill the disk or run for an hour.
SIZE_CEILING = '4GB'
SIZE_VERIFIED = CACHE / 'size-verified.json'
# Free space a scan needs on top of the image itself: Trivy's temporary layer
# files plus report and cache writes.
DISK_MARGIN_BYTES = 1024 ** 3


def size_bytes(value):
    """'1GB' / '512MB' -> bytes. Anything else is refused rather than guessed."""
    match = re.fullmatch(r'(\d+(?:\.\d+)?)(MB|GB)', str(value or '').strip().upper())
    if not match:
        raise ValueError('Hajm chegarasi `1GB` yoki `512MB` ko‘rinishida bo‘lishi kerak.')
    return int(float(match[1]) * (1024 ** 2 if match[2] == 'MB' else 1024 ** 3))


def size_verified(digest, limit=SIZE_LIMIT):
    """True once this digest has passed a size check at least as strict as `limit`.

    `--max-image-size` makes Trivy download every layer to learn the
    uncompressed size, bypassing its layer cache: measured on crAPI's web image,
    143 s with the flag against 3 s without it for an image already cached. A
    digest is content-addressed and cannot change, so one proven within a limit
    stays within it. The comparison matters: a digest verified under a raised
    2 GB limit proves nothing about the default 1 GB one, so it is re-checked.
    """
    try:
        entry = json.loads(SIZE_VERIFIED.read_text(encoding='utf-8')).get(digest)
        return bool(entry) and size_bytes(entry.get('limit')) <= size_bytes(limit)
    except (OSError, ValueError, TypeError, AttributeError):
        return False


def mark_size_verified(digest, limit=SIZE_LIMIT):
    try:
        known = json.loads(SIZE_VERIFIED.read_text(encoding='utf-8'))
        if not isinstance(known, dict):
            known = {}
    except (OSError, ValueError):
        known = {}
    previous = known.get(digest)
    # Keep the strictest limit ever proven; a looser one adds no information.
    try:
        if previous and size_bytes(previous.get('limit')) <= size_bytes(limit):
            return
    except (ValueError, AttributeError):
        pass
    known[digest] = {'limit': limit, 'verified_at': now()}
    try:
        repo_store.write_json(SIZE_VERIFIED, known)
    except OSError:
        pass  # Losing this only costs the next scan its speed-up.


def ensure_disk(limit):
    """Refuse to start a scan the disk cannot hold.

    Measured on this machine: 3.4 GB free on a 99 %-full disk. A scan that runs
    out of space midway fails in a way that looks like a network or Trivy error;
    saying so up front is both faster and honest.
    """
    free = shutil.disk_usage(ROOT).free
    needed = size_bytes(limit) + DISK_MARGIN_BYTES
    if free < needed:
        raise ValueError(f'Diskda joy yetarli emas: {free / 1024 ** 3:.1f} GB bo‘sh, bu tekshiruv uchun '
                         f'kamida {needed / 1024 ** 3:.1f} GB kerak ({limit} image + 1 GB zaxira). '
                         'Joy bo‘shating; bu toza natija emas, tekshiruv boshlanmadi.')


def _parse_time(value):
    """Trivy writes nanosecond timestamps with a trailing Z; Python 3.10 reads neither."""
    text = str(value).replace('Z', '+00:00')
    match = re.fullmatch(r'(.*T\d\d:\d\d:\d\d)(?:\.(\d+))?(.*)', text)
    if match and match[2]:
        text = f'{match[1]}.{match[2][:6]}{match[3]}'
    return datetime.datetime.fromisoformat(text)


def database_state(name, now=None):
    """'current', 'due' or 'missing' for one Trivy database, by Trivy's own NextUpdate."""
    try:
        meta = json.loads((CACHE / name / 'metadata.json').read_text(encoding='utf-8'))
        next_update = _parse_time(meta['NextUpdate'])
    except (OSError, ValueError, KeyError, TypeError):
        return 'missing'
    return 'current' if next_update > (now or datetime.datetime.now(datetime.timezone.utc)) else 'due'


def refresh_databases(rid, folder, env):
    """Bring Trivy's databases up to date *before* the scan, as its own step.

    Left to itself Trivy refreshes a database inside the scan whenever its own
    NextUpdate has passed -- about once a day for the vulnerability DB. Measured
    on crAPI's web image: 4.3 of 7.7 minutes went to that refresh, inside the
    scan's time budget. The same cause made a Java image fail outright earlier,
    and warming the databases at install time only helps until the next
    NextUpdate. Doing it here keeps Trivy's own freshness policy while the scan
    budget is spent on the image.

    A refresh that fails is not hidden: the scan continues on the previous
    database, and the report says so and is marked partial.
    """
    outcome = {'refreshed': [], 'failed': [], 'current': []}
    for name, flag in DATABASES:
        state = database_state(name)
        if state == 'current':
            outcome['current'].append(name)
            continue
        with (folder / 'db-refresh.log').open('ab') as log:
            process = subprocess.Popen([str(BINARY), 'image', flag, '--cache-dir', str(CACHE), '--no-progress', *QUIET],
                                       cwd=folder, env=env, stdout=log, stderr=subprocess.STDOUT,
                                       stdin=subprocess.DEVNULL)
            deadline = datetime.datetime.now().timestamp() + DB_REFRESH_SECONDS
            while process.poll() is None:
                if CANCEL[rid].wait(0.5):
                    process.kill()
                    raise InterruptedError('Image tekshiruvi bekor qilindi.')
                if datetime.datetime.now().timestamp() > deadline:
                    process.kill()
                    process.wait(timeout=10)
                    break
        if process.returncode == 0 and database_state(name) != 'missing':
            outcome['refreshed'].append(name)
        else:
            outcome['failed'].append(name)
    if 'db' in outcome['failed'] and database_state('db') == 'missing':
        raise ValueError('Zaiflik bazasi yo‘q va uni yuklab bo‘lmadi. Internet ulanishini tekshiring; '
                         'bazasiz tekshiruv natija bermaydi.')
    return outcome


def time_budget_minutes(limit):
    """Ten minutes per gigabyte of allowed image, never less than the default ten.

    Measured: a 1.37 GB image did not finish downloading from Docker Hub inside
    Trivy's fixed ten-minute budget. When an operator deliberately raises the
    size limit, the time a larger image needs has to come with it; the default
    1 GB scan keeps exactly the budget it always had.
    """
    return 10 * max(1, -(-size_bytes(limit) // 1024 ** 3))


def command(reference, folder, skip_update=('db', 'java-db'), check_size=True, limit=SIZE_LIMIT):
    # parse_reference() normalises and validates; a digest-pinned Docker Hub
    # reference comes out exactly as the old code produced it.
    reference = parse_reference(reference)['canonical']
    # The databases were refreshed as a separate step; the scan itself must not
    # stop to download them again.
    skip = (['--skip-db-update'] if 'db' in skip_update else []) + \
           (['--skip-java-db-update'] if 'java-db' in skip_update else [])
    return [str(BINARY), 'image', '--image-src', 'remote', '--platform', 'linux/amd64',
            '--scanners', 'vuln', '--format', 'json', '--list-all-pkgs', '--no-progress',
            '--cache-dir', str(CACHE), '--config', str(folder / 'config.yaml'),
            '--ignorefile', str(folder / 'empty.ignore'), '--timeout', f'{time_budget_minutes(limit)}m', *skip, *QUIET,
            *(['--max-image-size', limit] if check_size else []),
            '--output', str(folder / 'raw.json'), reference]


def execute(rid):
    report = None
    process = None
    folder = RUNS / rid
    raw = folder / 'raw.json'
    try:
        report = read(rid)
        def save():
            repo_store.write_json(folder / 'report.json', report)
        report.update(state='running', progress='Zaiflik bazasi va image qatlamlari olinmoqda; image ishga tushirilmaydi')
        save()
        provenance = json.loads((BINARY.parent / 'provenance.json').read_text(encoding='utf-8'))
        binary_hash = hashlib.sha256(BINARY.read_bytes()).hexdigest()
        if binary_hash != provenance.get('binary_sha256'):
            raise ValueError('Trivy binary xeshi o‘zgargan. setup_tools.py bilan tekshiring.')
        report['tool'] = {'name': 'Trivy', 'version': provenance['version'], 'binary_sha256': binary_hash}
        (folder / 'config.yaml').write_text('{}\n', encoding='utf-8')
        (folder / 'empty.ignore').write_text('', encoding='utf-8')
        home = folder / 'home'
        home.mkdir(exist_ok=True)
        env = {k: v for k, v in os.environ.items() if k.upper() in {'SYSTEMROOT', 'WINDIR', 'COMSPEC', 'PATH', 'PATHEXT'}}
        # DOCKER_CONFIG points at an empty home by default: the operator's real
        # registry logins must not be handed to whatever registry an image
        # reference happens to name. registry_credentials() overrides it only
        # when the target was registered as needing authentication.
        env.update(HOME=str(home), USERPROFILE=str(home), APPDATA=str(home), LOCALAPPDATA=str(home),
                   TEMP=str(home), TMP=str(home), DOCKER_CONFIG=str(home), NO_COLOR='1')
        profile = next((row for row in targets() if row['id'] == report['target']), {})
        secrets, auth_meta = registry_credentials(parse_reference(report['reference'])['registry'],
                                                  profile.get('auth', 'none'))
        env.update(secrets)
        report['progress'] = 'Zaiflik bazasi tekshirilmoqda; eskirgan bo‘lsa alohida yangilanadi'
        save()
        refresh = refresh_databases(rid, folder, env)
        report['database_refresh'] = refresh
        # In-scan updates are skipped only for databases actually on disk: a Java
        # DB that could not be fetched is left for Trivy to try on its own.
        skip = tuple(name for name, _ in DATABASES if database_state(name) != 'missing')
        parsed = parse_reference(report['reference'])
        limit = report.get('size_limit') or SIZE_LIMIT
        digest = parsed['digest']
        # A tag names content that can change, so nothing about it can be cached:
        # the size is always measured again, and the digest it resolved to is
        # written into the report afterwards.
        check_size = True if not digest else not size_verified(digest, limit)
        report['size_check'] = ('enforced' if check_size else 'previously_verified_digest') \
            if digest else 'enforced_tag_not_pinned'
        report['reference_kind'] = parsed['kind']
        report['registry'] = {'host': parsed['registry'], **auth_meta}
        report['time_budget_minutes'] = time_budget_minutes(limit)
        report['progress'] = 'Image qatlamlari olinmoqda; image ishga tushirilmaydi'
        save()
        # Logs may contain registry metadata. Keep them local, never in API exports.
        with (folder / 'tool.log').open('wb') as log:
            process = subprocess.Popen(command(report['reference'], folder, skip, check_size, limit), cwd=folder, env=env,
                                       stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
            deadline = datetime.datetime.now().timestamp() + time_budget_minutes(limit) * 60 + 60
            while process.poll() is None:
                if CANCEL[rid].wait(0.5):
                    raise InterruptedError('Image tekshiruvi bekor qilindi.')
                if datetime.datetime.now().timestamp() > deadline:
                    raise TimeoutError(failure_reason(folder / 'tool.log', DEADLINE_FAILURE))
            if process.returncode != 0:
                raise ValueError(failure_reason(folder / 'tool.log'))
        if raw.stat().st_size > 64 * 1024 * 1024:
            raise ValueError('Trivy hisoboti 64 MB chegarasidan oshdi.')
        report.update(normalize(json.loads(raw.read_text(encoding='utf-8')), report['target']))
        report.update(enrich(report['findings']))
        # A tag is a name, not content. Record which digest it actually resolved
        # to, so a later report can be compared with this one and so a moved tag
        # is visible instead of silent.
        resolved = next((str(d).rsplit('@', 1)[-1] for d in report.get('repo_digests') or []
                         if '@sha256:' in str(d)), digest)
        report['resolved_digest'] = resolved or None
        if not digest and resolved:
            report['pin_hint'] = (f'Bu skan `{parsed["repository"]}:{parsed["tag"]}` tegini tekshirdi va u '
                                  f'{resolved} digestiga yechildi. Takrorlanadigan natija uchun image’ni '
                                  f'digest bilan ro‘yxatga oling.')
        if check_size and (digest or resolved):
            # Trivy exited 0 with --max-image-size set: that digest is proven
            # within the limit, and a digest cannot change. For a tag scan the
            # digest it resolved to is what gets marked -- never the tag.
            mark_size_verified(digest or resolved, limit)
        try:
            db = json.loads((CACHE / 'db/metadata.json').read_text(encoding='utf-8'))
            report['database'] = {k: db.get(k) for k in ('Version', 'UpdatedAt', 'NextUpdate', 'DownloadedAt')}
        except (OSError, ValueError):
            report['database'] = None
        stale = refresh['failed']
        report['state'] = 'completed' if report['coverage'] and report['database'] and not stale else 'partial'
        if stale:
            # Findings from an out-of-date database can miss recent CVEs; the scan
            # is kept but never presented as complete.
            report['message'] = ('Zaiflik bazasi yangilanmadi (' + ', '.join(stale) + '); tekshiruv oldingi baza bilan '
                                 'bajarildi va so‘nggi CVE’lar tushib qolgan bo‘lishi mumkin.')
        report['progress'] = 'Image tahlili tugadi; amaliy ta’sirini mutaxassis tekshiradi'
    except InterruptedError:
        if report is not None: report.update(state='cancelled', progress='Image tekshiruvi bekor qilindi')
    except Exception as error:
        if report is not None:
            report.update(state='failed', error_type=type(error).__name__, progress='Image tekshiruvi tugallanmadi')
            # Every failure gets a reason. A report that only says "failed" leaves
            # the operator with nothing to act on -- the real crapi-identity scan
            # hit the outer deadline (a TimeoutError, not a ValueError) and landed
            # in the report with message: null and no explanation at all.
            if isinstance(error, (ValueError, TimeoutError)):
                report['message'] = str(error)[:400]
            else:
                report['message'] = ('Image tekshiruvi kutilmagan xato bilan to‘xtadi '
                                     f'({type(error).__name__}). Bu toza natija emas; qayta urinib ko‘ring.')
    finally:
        try:
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=10)
        finally:
            try:
                # ImageConfig may contain environment values; never expose it in API reports.
                if raw.exists(): raw.unlink()
                if report is not None:
                    report['finished_at'] = now()
                    repo_store.write_json(folder / 'report.json', report)
                    triage.record_scan('images', report)
            finally:
                CANCEL.pop(rid, None)
                LOCK.release()
    return report


def start(target, background=True, size_limit=None):
    row = next((row for row in targets() if row['id'] == target), None)
    if row is None: raise ValueError('Image oldindan ro‘yxatdan o‘tkazilishi kerak.')
    limit = (size_limit or SIZE_LIMIT).strip().upper()
    if size_bytes(limit) > size_bytes(SIZE_CEILING):
        raise ValueError(f'Hajm chegarasi {SIZE_CEILING} dan oshmasligi kerak.')
    ensure_disk(limit)
    if not LOCK.acquire(blocking=False): raise ValueError('Boshqa image tekshiruvi davom etmoqda.')
    rid = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S') + '-' + uuid.uuid4().hex[:8]
    CANCEL[rid] = threading.Event()
    try:
        repo_store.write_json(RUNS / rid / 'report.json', {
            'schema_version': 1, 'id': rid, 'target': target, 'reference': row['reference'],
            'created_at': now(), 'state': 'queued', 'findings': [], 'count': 0,
            'size_limit': limit,
            # A raised limit is the operator's explicit decision and is stated in
            # the report itself, not only in a command history somewhere.
            'size_limit_raised': limit != SIZE_LIMIT,
            'scope': f'Public Docker Hub image, linux/amd64, {limit} gacha'
                     + (' (standart 1 GB chegarasi operator tomonidan ushbu tekshiruv uchun oshirilgan)' if limit != SIZE_LIMIT else '')
                     + '. OS va aniqlangan til paketlari. Jarayon ishga tushirilmaydi.',
            'limits': 'Image topilmasi amaliy hujum tasdig‘i emas. Image digest ishlayotgan deploy va source commit bilan alohida bog‘lanadi. Qamrovga kirmagan paketlar bo‘lishi mumkin.',
            'data_policy': 'Public registry image va zaiflik bazalari yuklanadi. Lokal kod va Docker login ma’lumotlari yuborilmaydi.'})
    except Exception:
        CANCEL.pop(rid, None); LOCK.release(); raise
    if background:
        threading.Thread(target=execute, args=(rid,), daemon=True).start()
        return {'id': rid, 'state': 'queued'}
    return execute(rid)


def cancel(rid):
    read(rid)
    if rid not in CANCEL: raise ValueError('Bu image jarayoni ushbu serverda ishlamayapti.')
    CANCEL[rid].set()
    return {'id': rid, 'state': 'cancellation_requested'}
