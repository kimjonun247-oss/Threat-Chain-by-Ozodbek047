"""API endpoint inventory for the web scan.

The web scan is black-box: it only sees what an HTTP client sees. On an internal
server, though, the full list of API endpoints is knowable -- an application
publishes an OpenAPI/Swagger description, and a copy often lives in the source
repository. The single Nuclei template probes three default spec URLs; this
module widens that in two ways:

  1. **More live spec URLs** than the three defaults, so a spec served at a
     non-default path is still found.
  2. **Spec files committed in the registered source repository**, read from
     disk, so the full documented surface is known even when the running app
     exposes no spec at all.

From any spec it reads the documented paths, then -- inside the same bounded,
GET-only, same-origin, rate-limited envelope as the rest of the scan -- asks one
question of each static (non-parameterised) endpoint: does it answer an
*unauthenticated* GET with a success status? A documented endpoint reachable
without credentials is reported for review: it may be public by design, or a
missing authorisation check. This reads; it never POSTs, never guesses path
parameters, and never exercises an endpoint.

The design principles are unchanged: GET only, same origin, bounded by the
collector's own budget/window/deadline, evidence-based (every reported endpoint
was actually reached), and no combined score.
"""
import json
from pathlib import Path

from vendor import yaml

# Live spec URLs to try, beyond the three the Nuclei template already covers.
# Each is a conventional publication path for an OpenAPI/Swagger document.
NUCLEI_SPEC_PATHS = ('/openapi.json', '/swagger.json', '/v3/api-docs')
EXTRA_SPEC_PATHS = (
    '/openapi.yaml', '/openapi.yml', '/swagger.yaml', '/swagger.yml',
    '/api-docs', '/api/openapi.json', '/api/swagger.json', '/api/v1/openapi.json',
    '/v2/api-docs', '/swagger/v1/swagger.json', '/docs/openapi.json',
    '/redoc/openapi.json', '/api-docs/swagger.json', '/swagger/doc.json',
)
# Repository file names (stem) that hold an API description. Matched case-folded
# against the stem; the suffix must be a parsable JSON/YAML extension below.
SPEC_STEMS = ('openapi', 'swagger', 'api-docs', 'apidocs', 'api_spec', 'api-spec')
SPEC_SUFFIXES = ('.json', '.yaml', '.yml')

# Bounds. The scan is a pilot against a cooperating target, not a crawler.
MAX_PROBE = 24              # documented endpoints actively reached per scan
MAX_REPO_SPEC_FILES = 20    # spec files parsed from the repository
MAX_REPO_WALK_ENTRIES = 50000
MAX_SPEC_FILE_BYTES = 2_000_000
MAX_LISTED = 60             # endpoints named in a finding's evidence


def parse_spec(text):
    """Return the parsed document only when it is really an OpenAPI/Swagger spec.

    The body is the target's or the repository's, never ours, so any parse error
    means 'not a spec', not a scan failure.
    """
    if not isinstance(text, str) or not text.strip():
        return None
    try:
        document = json.loads(text) if text.lstrip()[:1] in '{[' else yaml.safe_load(text)
    except (ValueError, yaml.YAMLError, RecursionError):
        return None
    if not isinstance(document, dict):
        return None
    has_version = bool(document.get('openapi') or document.get('swagger'))
    if has_version and isinstance(document.get('paths'), dict):
        return document
    return None


def spec_get_paths(spec):
    """The documented paths that expose a GET operation.

    OpenAPI keys each path to a map of lower-case HTTP methods. A path with no
    GET is left out: this module only ever sends GET, so it would never reach it.
    """
    result = set()
    paths = spec.get('paths')
    if not isinstance(paths, dict):
        return result
    for path, operations in paths.items():
        if not isinstance(path, str) or not path.startswith('/'):
            continue
        if isinstance(operations, dict) and ('get' in operations or not any(
                m in operations for m in ('post', 'put', 'patch', 'delete', 'head', 'options'))):
            result.add(path)
    return result


def discover_repo(source_root):
    """Parse every API-description file found under the registered source root.

    Returns a list of (relative_path, spec). The walk is bounded, each file is
    size-capped, and only files whose name looks like a spec are opened -- this
    never reads arbitrary repository content.
    """
    root = Path(source_root)
    found, seen = [], 0
    try:
        if not root.is_dir():
            return found
        for path in root.rglob('*'):
            seen += 1
            if seen > MAX_REPO_WALK_ENTRIES or len(found) >= MAX_REPO_SPEC_FILES:
                break
            if not path.is_file():
                continue
            if path.suffix.lower() not in SPEC_SUFFIXES:
                continue
            if not any(stem in path.stem.lower() for stem in SPEC_STEMS):
                continue
            try:
                if path.stat().st_size > MAX_SPEC_FILE_BYTES:
                    continue
                spec = parse_spec(path.read_text(encoding='utf-8', errors='replace'))
            except OSError:
                continue
            if spec is not None:
                try:
                    label = str(path.relative_to(root))
                except ValueError:
                    label = path.name
                found.append((label, spec))
    except OSError:
        return found
    return found


def _probe(collector, path):
    """One bounded GET against a documented endpoint; status, or None if the
    request could not be made (budget, window, scope, deadline, target error).
    The collector enforces every safety rule; this only asks it to try one GET."""
    try:
        collector.allow(path)
        status, _, _ = collector.fetch(path)
        return status
    except Exception:  # noqa: BLE001 -- any collector limit or target error == "not reached"
        return None


def inventory_findings(collector, finding, source_root=None, authenticated=False):
    """Build the API inventory and the findings it supports.

    Returns (findings, inventory) where inventory is a transparency record for
    the report. `finding` is webscan.finding, injected to avoid a circular import.
    """
    specs = []  # (origin, label, spec)
    for live_path in NUCLEI_SPEC_PATHS + EXTRA_SPEC_PATHS:
        status = None
        body = None
        try:
            collector.allow(live_path)
            status, _, body = collector.fetch(live_path)
        except Exception:  # noqa: BLE001
            continue
        if status in (200, 206) and body is not None:
            spec = parse_spec(body.decode('utf-8', 'replace'))
            if spec is not None:
                specs.append(('live', live_path, spec))
    if source_root:
        for label, spec in discover_repo(source_root):
            specs.append(('repo', label, spec))

    documented = {}  # endpoint path -> set("origin:label")
    for origin, label, spec in specs:
        for endpoint in spec_get_paths(spec):
            documented.setdefault(endpoint, set()).add(f'{origin}:{label}')

    inventory = {
        'spec_sources': [{'origin': o, 'label': l, 'endpoints': len(spec_get_paths(s))}
                         for o, l, s in specs],
        'documented_endpoints': len(documented),
        'authenticated_scan': bool(authenticated),
    }
    findings = []
    if not specs:
        return findings, inventory

    # A spec served live at a path the Nuclei template does not cover is itself
    # worth noting: the operator may not know it is published there.
    extra_live = sorted({label for origin, label, _ in specs
                         if origin == 'live' and label not in NUCLEI_SPEC_PATHS})
    for label in extra_live:
        findings.append(finding(
            'api-spec-exposed',
            'API sxemasi standart bo‘lmagan manzilda ochiq',
            'LOW', label,
            f'API spetsifikatsiyasi {label} manzilida oshkor (Nuclei standart 3 manzilidan tashqari).',
            'Agar sxema ommaviy bo‘lishi shart bo‘lmasa, uni autentifikatsiya ortiga oling yoki olib tashlang.'))

    # Actively reach the static documented endpoints and record which answer a
    # GET. Parameterised paths ({id}) are inventoried but never probed -- a
    # guessed id could touch real data, and this module never guesses.
    static = sorted(p for p in documented if '{' not in p and '}' not in p)
    parameterised = sorted(p for p in documented if '{' in p or '}' in p)
    reached, probed = [], 0
    for endpoint in static:
        if probed >= MAX_PROBE:
            break
        status = _probe(collector, endpoint)
        probed += 1
        if status is not None:
            inventory.setdefault('probed', {})[endpoint] = status
            if 200 <= status < 300:
                reached.append(endpoint)

    inventory['probed_count'] = probed
    inventory['parameterised_skipped'] = len(parameterised)

    # The cross-reference the operator asked for: documented endpoints that an
    # UNAUTHENTICATED client reaches. When the scan carries credentials this
    # cannot be claimed, so it is reported only for an unauthenticated scan.
    if reached and not authenticated:
        listed = reached[:MAX_LISTED]
        more = '' if len(reached) <= MAX_LISTED else f' (+{len(reached) - MAX_LISTED} boshqa)'
        sources = sorted({s.split(':', 1)[0] for e in reached for s in documented.get(e, [])})
        evidence = (f'{len(reached)} ta hujjatlangan endpoint autentifikatsiyasiz GET so‘roviga '
                    f'muvaffaqiyatli (2xx) javob berdi. Manba: {", ".join(sources)}. '
                    f'Endpoint(lar): {", ".join(listed)}{more}.')
        findings.append(finding(
            'api-endpoint-unauthenticated',
            f'Hujjatlangan API endpoint(lar) autentifikatsiyasiz ochiq ({len(reached)} ta)',
            'MEDIUM', listed[0],
            evidence,
            'Har bir endpoint ommaviy bo‘lishi kerakmi tekshiring; bo‘lmasa autentifikatsiya/avtorizatsiya qo‘shing.'))

    return findings, inventory
