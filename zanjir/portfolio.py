"""Portfolio view: many projects, five stages each, over time.

Two honesty rules shape this whole module, and they are the reason it looks
different from a typical multi-project dashboard:

  1. No blended score, here or anywhere. A project is never reduced to one
     number or one colour. Each stage keeps its own count, its own state and its
     own scan time, because a Trivy count and a Nuclei count measure different
     things and adding them would invent a quantity that does not exist.

  2. "Never scanned" is not "clean". The matrix distinguishes three states that
     a single number would flatten together: a stage that was scanned and found
     nothing, a stage that was scanned and did not finish (`partial`/`failed`),
     and a stage that was never scanned at all. The third is the one a portfolio
     view exists to surface -- an untested project looks best on any dashboard
     that only counts findings.

A count falling between two scans is likewise not proof of a fix: coverage may
have shrunk instead. `trend()` therefore carries state alongside every count and
never reports a direction of travel on its own.

Grouping: a project's target id can differ per stage (the bundled crAPI sample
is registered as `crapi-full` for code, `crapi` for Compose, `pilot-crapi` for
web and one id per image). So a project is an explicit grouping, either bundled
below, registered by the operator, or derived from an exact id match -- which is
what `app.py --register-project` produces, since it registers one id into the
code, dependency and repository registries at once. Ids are never matched by
fuzzy resemblance.
"""
import datetime
import json
import re

from .engine import ROOT, DATA
from . import repo_store, code_targets, scanners, dependencies, iac, images, webscan

PROFILES = DATA / 'profiles/portfolio'
ID = re.compile(r'^[a-z0-9][a-z0-9._-]{2,64}$')
INTERPOLATION = re.compile(r'\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*')
STAGES = ('code', 'repository', 'dependencies', 'iac', 'images', 'web')
STAGE_TITLES = {'code': 'Kod va sirlar', 'repository': 'Repository (Compose)',
                'dependencies': 'CVE va kutubxonalar', 'iac': 'Konfiguratsiya (IaC)',
                'images': 'Docker image', 'web': 'Sayt va API'}
# Only 'images' takes a list: one project legitimately ships many containers.
MULTI = {'images'}

# The bundled crAPI sample, grouped in code for the same reason crapi_root() is:
# it ships with the application and its per-stage ids are historical.
BUNDLED = {'crapi': {'name': 'OWASP crAPI · to‘liq namuna', 'owner': 'Bundled sample', 'bundled': True,
                     'stages': {'code': 'crapi-full', 'repository': 'crapi', 'dependencies': 'crapi-full',
                                'web': 'pilot-crapi',
                                'images': ['pilot-crapi-identity', 'pilot-crapi-community', 'pilot-crapi-workshop',
                                           'pilot-crapi-chatbot', 'pilot-crapi-web', 'pilot-postgresdb',
                                           'pilot-mongodb', 'pilot-chromadb', 'pilot-mailhog']}}}


def registered_targets():
    """Target ids each stage currently knows about."""
    # One scanners.targets() call, not three: it walks every registry.
    sources = {t['id'] for t in scanners.targets() if t.get('available')}
    return {
        'code': set(sources),
        'repository': {p['id'] for p in repo_store.list_profiles()},
        'dependencies': sources | {p['id'] for p in code_targets.profiles()},
        # The IaC stage reads the same registered project roots the code scanner does.
        'iac': set(sources),
        'images': {t['id'] for t in images.targets()},
        'web': {t['id'] for t in webscan.targets()},
    }


def histories():
    """Latest-first scan rows per stage, normalised to the same few fields."""
    rows = {stage: [] for stage in STAGES}
    # Every row, not the 30 the UI lists show. With the 30-row window a target
    # whose last scan had scrolled out -- crAPI's workshop image, once there were
    # 36 image reports -- was reported as never scanned, which is exactly the
    # kind of false statement this view exists to prevent. The run index makes
    # reading all of them cheap.
    everything = 10 ** 6
    for stage, source in (('code', scanners), ('dependencies', dependencies), ('images', images),
                          ('web', webscan), ('iac', iac)):
        for row in source.history(limit=everything):
            rows[stage].append({'id': row.get('id'), 'target': row.get('target'), 'created_at': row.get('created_at'),
                                'state': row.get('state'), 'count': row.get('count')})
    for row in repo_store.list_reports(limit=everything):
        summary = row.get('summary') or {}
        rows['repository'].append({'id': row.get('id'), 'target': row.get('profile_id'), 'created_at': row.get('created_at'),
                                   # Repository scans are synchronous and either produce a report or raise.
                                   'state': 'completed', 'count': summary.get('findings')})
    for stage in rows:
        rows[stage].sort(key=lambda item: item.get('created_at') or '', reverse=True)
    return rows


def normalise(stages):
    """Accept {stage: id} / {stage: [ids]} and return {stage: [ids]} for known stages only."""
    if not isinstance(stages, dict):
        raise ValueError('`stages` obyekt bo‘lishi kerak.')
    unknown = sorted(set(stages) - set(STAGES))
    if unknown:
        raise ValueError('Noma’lum bosqich: ' + ', '.join(unknown))
    result = {}
    for stage, value in stages.items():
        ids = value if isinstance(value, list) else [value]
        # An images entry may name the Compose service it belongs to:
        #   {"id": "pilot-crapi-identity", "service": "crapi-identity"}
        # Only the id is kept here so every existing consumer keeps seeing a
        # plain list; the mapping is read separately by image_services().
        ids = [str(i.get('id', '')) if isinstance(i, dict) else str(i) for i in ids]
        ids = [i for i in ids if i.strip()]
        if len(ids) > 1 and stage not in MULTI:
            raise ValueError(f'`{stage}` bosqichida faqat bitta nishon bo‘lishi mumkin.')
        if len(ids) > 40:
            raise ValueError(f'`{stage}` bosqichida 40 tadan ko‘p nishon bo‘lmasligi kerak.')
        if ids:
            result[stage] = ids
    if not result:
        raise ValueError('Kamida bitta bosqichga nishon bog‘lang.')
    return result


def image_services(stages):
    """image target id -> the Compose service the operator said it belongs to.

    Only explicit statements land here. An image with no `service` is matched
    later by its own name against the Compose file, and when that fails it is
    reported as unlinked rather than guessed into a service.
    """
    links = {}
    if not isinstance(stages, dict):
        return links
    for entry in stages.get('images') or []:
        if isinstance(entry, dict) and str(entry.get('id', '')).strip() and str(entry.get('service', '')).strip():
            links[str(entry['id'])] = str(entry['service'])
    return links


def repository_name(reference):
    """The part of an image reference that survives a tag or digest change.

    `crapi/crapi-web:${VERSION:-latest}` and `crapi/crapi-web@sha256:b27d...`
    are the same image; a registry host and a `docker.io/library/` prefix are
    dropped so a Compose file and a registered target still meet.
    """
    name = str(reference or '').strip().split('@', 1)[0]
    # Compose interpolation first: `crapi/crapi-web:${VERSION:-latest}` carries
    # colons inside the default value, so cutting the tag before removing it
    # leaves `crapi/crapi-web:${VERSION` and nothing ever matches.
    name = INTERPOLATION.sub('', name)
    head, _, last = name.rpartition('/')
    # A colon in a registry host:port is not a tag; only the final path segment
    # can carry one.
    last = last.split(':', 1)[0]
    name = f'{head}/{last}' if head else last
    for prefix in ('docker.io/', 'index.docker.io/', 'registry-1.docker.io/'):
        name = name.removeprefix(prefix)
    name = name.removeprefix('library/')
    return name.strip('/').lower()


def link_images(stages, services, targets=None):
    """Match a project's image targets to the Compose services they run.

    Returns the links plus both kinds of gap, because a chain rule that quietly
    skipped an unmatched image would look like "no finding" instead of
    "not checked".
    """
    declared = image_services(stages)
    rows = {t['id']: t for t in (targets if targets is not None else images.targets())}
    wanted = [i for i in (stages.get('images') if isinstance(stages, dict) else None) or []
              if (i if isinstance(i, str) else i.get('id')) in rows] or list(rows)
    by_name = {}
    for service in services or []:
        name = repository_name(service.get('image'))
        if name:
            by_name.setdefault(name, []).append(service['id'])
    links, unlinked, ambiguous = {}, [], []
    for identifier in [i if isinstance(i, str) else str(i.get('id', '')) for i in wanted]:
        row = rows.get(identifier)
        if row is None:
            continue
        if identifier in declared:
            links[identifier] = {'service': declared[identifier], 'how': 'declared'}
            continue
        candidates = by_name.get(repository_name(row.get('reference')), [])
        if len(candidates) == 1:
            links[identifier] = {'service': candidates[0], 'how': 'image_name'}
        elif len(candidates) > 1:
            # Two services from one image: which one is exposed is not knowable
            # from the image alone, so the operator is asked instead of guessed at.
            ambiguous.append({'image': identifier, 'services': sorted(candidates)})
        else:
            unlinked.append(identifier)
    return {'links': links, 'unlinked': sorted(unlinked), 'ambiguous': ambiguous}


def defined():
    """Operator-registered groupings, newest definition wins over a bundled one."""
    result = {}
    if PROFILES.is_dir():
        for path in sorted(PROFILES.glob('*.json')):
            if not ID.fullmatch(path.stem):
                continue
            try:
                row = json.loads(path.read_text(encoding='utf-8'))
                if row.get('id') == path.stem:
                    result[path.stem] = {'name': row.get('name') or path.stem, 'owner': row.get('owner', ''),
                                         'bundled': False, 'stages': normalise(row.get('stages') or {})}
            except (OSError, ValueError):
                continue
    return result


def claimed(groups):
    """Every target id already belonging to a group, so nothing is listed twice."""
    used = set(groups)
    for meta in groups.values():
        for ids in meta['stages'].values():
            used.update(ids)
    return used


def derived(taken):
    """Projects implied by one id registered into several stages at once.

    This is exactly what `app.py --register-project` produces, so a project
    added that way appears here without any further configuration. An id known
    to only one stage (an image or a web target registered on its own) is a
    project too, marked `single_stage`: leaving it out made a scanned image such
    as alpine or a web target simply absent from the portfolio, which reads as
    "nothing to see" rather than "only one layer is checked".
    """
    registry = registered_targets()
    groups = {}
    for identifier in sorted(set().union(*registry.values())):
        if identifier in taken:
            continue
        stages = {stage: [identifier] for stage, ids in registry.items() if identifier in ids}
        if not stages:
            continue
        name = next((p['name'] for p in repo_store.list_profiles() if p['id'] == identifier),
                    next((t['name'] for t in scanners.targets() if t['id'] == identifier), identifier))
        groups[identifier] = {'name': name, 'owner': '', 'bundled': False, 'derived': True, 'stages': stages,
                              'single_stage': len(stages) == 1}
    return groups


def projects():
    groups = {identifier: {**meta, 'stages': normalise(meta['stages'])} for identifier, meta in BUNDLED.items()}
    groups.update(defined())                 # an explicit definition replaces the bundled one
    groups.update(derived(claimed(groups)))  # only ids no group already covers
    return groups


def unknown_targets(meta, registry=None):
    """Ids a grouping names that no registry knows about.

    A bundled grouping lists crAPI's nine image ids by name. If one is renamed or
    removed, the group would quietly cover less than it claims and the portfolio
    would look healthier than it is -- so the mismatch is surfaced instead.
    """
    registry = registry or registered_targets()
    missing = []
    for stage, ids in meta['stages'].items():
        missing += [i for i in ids if i not in registry[stage]]
    # One id can be named by several stages (crapi-full is both the code and the
    # dependency target); listing it twice read as two missing targets.
    return sorted(set(missing))


def stage_state(rows, targets):
    """Latest scan across this stage's targets, or an explicit never-scanned marker."""
    relevant = [r for r in rows if r.get('target') in targets]
    if not relevant:
        return {'targets': targets, 'scanned': False, 'state': 'never_scanned', 'count': None,
                'last_scan': None, 'report_id': None, 'scanned_targets': 0}
    latest = relevant[0]
    # For a multi-target stage the honest total is over each target's own latest
    # scan, not over every scan ever run.
    newest = {}
    for row in relevant:
        newest.setdefault(row['target'], row)
    counts = [r['count'] for r in newest.values() if isinstance(r.get('count'), int)]
    states = {r.get('state') for r in newest.values()}
    # "Has a scan record" is not "has a result": a target whose latest scan failed
    # or was cancelled would otherwise be counted towards full coverage and the
    # row would read 9/9 while one image was never actually analysed.
    # 'no_supported_packages' finished: the dependency stage read the project and
    # found no lockfile. It stays visible as its own state, not as "unfinished".
    incomplete = sorted(t for t, r in newest.items() if r.get('state') not in {'completed', 'no_supported_packages'})
    return {'targets': targets, 'scanned': True,
            'state': 'partial' if states & {'partial', 'failed', 'cancelled'} else latest.get('state'),
            'count': sum(counts) if counts else None,
            'last_scan': latest.get('created_at'), 'report_id': latest.get('id'),
            'scanned_targets': len(newest) - len(incomplete), 'attempted_targets': len(newest),
            'incomplete_targets': incomplete, 'unscanned_targets': sorted(set(targets) - set(newest))}


def overview():
    rows = histories()
    known = registered_targets()
    result = []
    for identifier, meta in sorted(projects().items(), key=lambda item: item[1]['name'].lower()):
        stages = {}
        for stage in STAGES:
            targets = meta['stages'].get(stage) or []
            stages[stage] = stage_state(rows[stage], targets) if targets else {
                'targets': [], 'scanned': False, 'state': 'not_registered', 'count': None,
                'last_scan': None, 'report_id': None, 'scanned_targets': 0}
        scanned = [s for s in stages.values() if s['scanned']]
        result.append({'id': identifier, 'name': meta['name'], 'owner': meta.get('owner', ''),
                       'bundled': meta.get('bundled', False), 'derived': meta.get('derived', False),
                       'single_stage': meta.get('single_stage', False),
                       'stages': stages, 'unknown_targets': unknown_targets(meta, known),
                       'gaps': [stage for stage in STAGES if stages[stage]['state'] in ('never_scanned', 'not_registered')],
                       'last_scan': max((s['last_scan'] for s in scanned), default=None)})
    return {'projects': result, 'stages': [{'key': s, 'title': STAGE_TITLES[s]} for s in STAGES],
            'generated_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'note': ('Har bir bosqich o‘z soni va holati bilan alohida turadi; ular qo‘shilib umumiy '
                     'ball chiqarilmaydi. "Tekshirilmagan" — "toza" degani emas.')}


def trend(project_id, stage, limit=20):
    """Chronological scans of one stage, oldest first.

    Every point carries its own state. A falling count can mean a fix, or it can
    mean a scan that covered less -- so the two are never separated here, and no
    direction of travel is reported.
    """
    meta = projects().get(project_id)
    if not meta:
        raise ValueError('Bunday loyiha yo‘q.')
    if stage not in STAGES:
        raise ValueError('Bunday bosqich yo‘q.')
    targets = meta['stages'].get(stage) or []
    if not targets:
        raise ValueError('Bu bosqich loyihaga bog‘lanmagan.')
    if not isinstance(limit, int) or not 1 <= limit <= 200:
        raise ValueError('limit 1 va 200 orasida bo‘lishi kerak.')
    rows = [r for r in histories()[stage] if r.get('target') in targets]
    points = list(reversed(rows[:limit]))
    return {'project': project_id, 'stage': stage, 'title': STAGE_TITLES[stage], 'targets': targets,
            'points': points,
            'note': ('Sonning kamayishi tuzatish dalili emas — qamrov qisqargan bo‘lishi ham mumkin. '
                     'Har bir nuqtaning holatini va hisobotdagi qamrovni tekshiring.')}


def path_for(identifier):
    if not isinstance(identifier, str) or not ID.fullmatch(identifier):
        raise ValueError('Loyiha ID kichik harf, raqam, nuqta, tire va pastki chiziqdan iborat 3–65 belgi bo‘lishi kerak.')
    path = (PROFILES / (identifier + '.json')).resolve()
    if path.parent != PROFILES.resolve():
        raise ValueError('Fayl yo‘li chegaradan chiqdi.')
    return path


def register(identifier, name, stages, owner=''):
    path = path_for(identifier)
    if not isinstance(name, str) or not 1 <= len(name.strip()) <= 120:
        raise ValueError('Loyiha nomi 1–120 belgi bo‘lishi kerak.')
    if not isinstance(owner, str) or len(owner) > 120:
        raise ValueError('Mas’ul nomi 120 belgidan oshmasligi kerak.')
    stages = normalise(stages)
    known = registered_targets()
    for stage, ids in stages.items():
        missing = sorted(set(ids) - known[stage])
        if missing:
            raise ValueError(f'`{stage}` bosqichida ro‘yxatdan o‘tmagan nishon: ' + ', '.join(missing))
    PROFILES.mkdir(parents=True, exist_ok=True)
    repo_store.write_json(path, {'id': identifier, 'name': name.strip(), 'owner': owner.strip(), 'stages': stages})
    return {'id': identifier, 'name': name.strip(), 'owner': owner.strip(), 'stages': stages}


def remove(identifier):
    path = path_for(identifier)
    if not path.is_file():
        raise ValueError('Bunday loyiha ta’rifi yo‘q. Bundled va avtomatik guruhlar o‘chirilmaydi.')
    path.unlink()
    return {'id': identifier, 'deleted': True}
