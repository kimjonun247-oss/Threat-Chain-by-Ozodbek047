"""One list of every finding, from every scanner, for one screen.

Until now a finding could only be seen inside the report that produced it. Six
scanners meant six screens, and no way to ask "what is open and overdue across
this project" -- which is the question an operator actually has. This module
answers it by reading the newest report of every stage and flattening them into
one row shape.

Four rules keep the flattening honest:

  1. **Nothing is merged or recomputed.** A row carries the values its own
     scanner produced. The only added fields are the ones this project already
     computes elsewhere: the triage view, the SLA date and the project name.
  2. **A stage that was never scanned is reported as such.** `coverage` lists
     every registered target and whether a report exists, so an empty table
     means "nothing found in what was scanned", never "nothing to find".
  3. **No score.** Counts are grouped by severity, stage and status; they are
     never combined. The same rule the portfolio has always followed.
  4. **The newest report wins, and its state travels with the row.** A finding
     that came from a `partial` scan says so, because partial coverage is not a
     clean result.
"""
import re

from . import triage

# CWE numbers whose whole point is a secret sitting in the source: a hard-coded
# credential, password, key or token. A snippet of such a line would re-expose
# the very value the scanner flagged, so the panel never shows source for them.
SECRET_CWES = frozenset({256, 257, 258, 259, 260, 261, 312, 319, 321, 322,
                         323, 324, 522, 540, 547, 798})
# Backstop for secret rules that carry no CWE (many semgrep/gitleaks secret
# rules). Matched against the rule id, title and message, word-ish boundaries.
SECRET_WORDS = re.compile(
    r'(?i)(?:secret|password|passwd|credential|api[_-]?key|private[_-]?key'
    r'|access[_-]?key|auth[_-]?token|\btoken\b|\bkey\b)')


def _is_secret_finding(finding):
    """True when a finding's source line is likely to contain a secret value."""
    for cwe in finding.get('cwe_ids') or []:
        match = re.search(r'(\d+)', str(cwe))
        if match and int(match.group(1)) in SECRET_CWES:
            return True
    blob = ' '.join(str(finding.get(k) or '') for k in ('rule_id', 'title', 'message'))
    return bool(SECRET_WORDS.search(blob))

# Stage -> how to read its newest reports. Imported lazily inside functions:
# these modules import triage, which this one uses.
STAGES = ('code', 'dependencies', 'iac', 'images', 'web', 'repository')
# States whose findings are read into the board.
USABLE = ('completed', 'partial')
# States that mean "this target was scanned and the scan reached a conclusion,
# there is simply nothing in the table from it". Reporting these as never
# scanned would be the same false statement the portfolio view exists to
# prevent, only in the other direction: it turns a real result into a gap.
CONCLUDED = ('no_supported_packages',)
# Kept for callers that read it: the board no longer cuts a report short. Rows
# live in a table on disk (zanjir/findings_store.py), so a report of any size
# is read once when it appears and paged by the database afterwards.
PER_REPORT = 10 ** 9
CACHE_TTL = 4.0


def sources():
    from . import dependencies, iac, images, repo_store, scanners, webscan
    return {
        'code': (scanners.read_report, scanners.history, 'target'),
        'dependencies': (dependencies.read, lambda limit: dependencies.history(None, limit), 'target'),
        'iac': (iac.read, iac.history, 'target'),
        'images': (images.read, images.history, 'target'),
        'web': (webscan.read, webscan.history, 'target'),
        # The repository scanner is synchronous: it either produces a report or
        # raises, so its rows carry no `state`. That absence means completed
        # here, and only here.
        'repository': (repo_store.get_report, lambda limit: repo_store.list_reports(limit=limit), 'profile_id'),
    }


def project_of(stage, target):
    try:
        return triage.scope_for(stage, target)
    except (OSError, ValueError):
        return ''


def subject(stage, finding):
    """The one thing a reader needs to identify where a finding lives."""
    package = finding.get('package')
    if isinstance(package, dict):
        return f"{package.get('name')} {package.get('version')}".strip()
    if stage == 'images' and package:
        return f"{package} {finding.get('version') or ''}".strip()
    if finding.get('path'):
        return finding['path'] + (f":{finding['line']}" if finding.get('line') else '')
    return finding.get('service_id') or ''


def title_of(stage, finding):
    return (finding.get('title') or finding.get('summary') or finding.get('message')
            or finding.get('detail') or finding.get('advisory_id') or finding.get('rule_id') or '')


def row(stage, report, finding, project):
    view = finding.get('triage') or {}
    epss = finding.get('epss') or {}
    return {
        'fingerprint': finding.get('fingerprint'),
        'stage': stage, 'project': project, 'target': report.get('target') or report.get('profile_id') or '',
        'report_id': report.get('id'), 'report_state': report.get('state', 'completed'),
        'rule_id': finding.get('rule_id') or finding.get('advisory_id') or '',
        'title': str(title_of(stage, finding))[:400],
        'subject': str(subject(stage, finding))[:300],
        'severity': finding.get('severity') or finding.get('level') or '',
        'severity_scale': triage.severity_of(finding),
        'cwe_ids': finding.get('cwe_ids') or [],
        'owasp': [o['code'] for o in finding.get('owasp_top10_2025') or []],
        'known_exploited': finding.get('known_exploited'),
        'epss': epss.get('epss'), 'epss_percentile': epss.get('percentile'),
        'advisory_id': finding.get('advisory_id') or '',
        'fixed_version': finding.get('fixed_version') or '',
        'verified': bool(finding.get('verified')),
        'tool': finding.get('tool') or '',
        'duplicate_of': finding.get('duplicate_of'),
        'escalates': finding.get('escalates'),
        'status': view.get('status'), 'owner': view.get('owner'),
        'open': view.get('open', True), 'suppressed': bool(view.get('suppressed')),
        'stale': bool(view.get('stale')),
        'first_seen': view.get('first_seen'), 'last_seen': view.get('last_seen'),
        'sla': view.get('sla'),
        'overdue': bool((view.get('sla') or {}).get('overdue')),
    }


def collect():
    """Every row of the board plus its coverage list.

    The board itself is searched through search(); this returns the whole list
    for the few callers that want it, and reads it from the same table.
    """
    from . import findings_store
    return findings_store.everything(_self())


def _self():
    import sys
    return sys.modules[__name__]


def chain_rows(stage):
    """Cross-scanner chain findings, which live on the assessment, not a stage."""
    if stage != 'repository':
        return []
    from . import pipeline
    rows = []
    try:
        for entry in pipeline.history(limit=30):
            if entry.get('state') not in USABLE:
                continue
            report = pipeline.read(entry['id'])
            target = next((s.get('target') for s in report.get('stages') or []
                           if s.get('kind') == 'repository' and s.get('target')), '')
            project = project_of('repository', target) if target else ''
            for finding in report.get('chain_findings') or []:
                rows.append({**row('chain', {'id': report['id'], 'state': report.get('state'), 'target': target},
                                   finding, project),
                             'rule_id': finding.get('rule_id'), 'subject': finding.get('service_id') or ''})
            if rows:
                break                     # the newest assessment that produced chains
    except (OSError, ValueError, KeyError):
        pass
    return rows


def registered(stage):
    from . import portfolio
    try:
        return portfolio.registered_targets().get(stage, set())
    except (OSError, ValueError):
        return set()


# The filters the board accepts and the facets it counts. The filtering,
# ordering and counting themselves are SQL now (zanjir/findings_store.py): one
# definition, so the table and its chips cannot disagree. Sorted worst-first:
# severity, then overdue, then known-exploited, then how long a finding has
# been open -- an order, never a composite number.
FILTERS = ('stage', 'project', 'target', 'severity', 'owasp', 'status', 'state')
FACET_KEYS = ('severity', 'stage', 'project', 'owasp', 'status')


def search(query='', filters=None, offset=0, limit=50):
    from . import findings_store
    offset = max(0, int(offset))
    limit = max(1, min(int(limit), 200))
    data = findings_store.search(_self(), query, filters, offset, limit)
    facets = data['facets']
    # An active value must always have a chip, even when it now counts zero.
    for name in FACET_KEYS:
        chosen = (filters or {}).get(name)
        if chosen and chosen not in facets[name]:
            facets[name][chosen] = 0
    facets['note'] = ('Bu sonlar filtr uchun; ular qo‘shilib umumiy ball chiqarilmaydi. Turli skanerlarning '
                      'topilmalari turli narsani o‘lchaydi.')
    unscanned = [c for c in data['coverage'] if c.get('outcome') == 'never_scanned']
    incomplete = [c for c in data['coverage'] if c.get('outcome') == 'incomplete']
    return {
        'total': data['total'], 'offset': offset, 'limit': limit,
        'rows': data['rows'],
        'facets': facets,
        'coverage': {'scanned': [c for c in data['coverage'] if c['scanned']],
                     'unscanned': unscanned,
                     'incomplete': incomplete,
                     'truncated': [],
                     'note': ('Tekshirilmagan nishon toza degani emas. Quyidagi nishonlar uchun hech qanday '
                              'natija yo‘q va ular bu jadvalda umuman ko‘rinmaydi.') if unscanned else None,
                     'incomplete_note': ('Bu nishonlarda skan boshlangan, lekin natija bermadi '
                                         '(tugallanmagan yoki bekor qilingan). Ular ham toza emas.')
                                        if incomplete else None},
    }


def detail(fingerprint):
    """One finding with its full original record, for the side panel."""
    from . import findings_store
    found = findings_store.detail(_self(), fingerprint)
    if found is None:
        raise ValueError('Bunday topilma joriy hisobotlarda yo‘q.')
    item, original, related = found
    events = []
    try:
        if item['project']:
            events = [e for e in triage.events(item['project']) if e.get('fingerprint') == fingerprint]
    except (OSError, ValueError):
        events = []
    # The exact source lines the code scanners flagged, read from the live source
    # so the operator sees what was found without leaving the panel. Only code
    # findings, and never a secret finding -- gitleaks, or any rule (semgrep
    # included) whose line holds the credential it flagged. source_snippet also
    # masks long key-like tokens, but the surest fix is to not read the line.
    # snippet_state tells the panel why there is no snippet, so a deliberately
    # withheld secret is never mislabelled as a read error:
    #   'secret'      -- withheld on purpose (the line holds the credential)
    #   'unavailable' -- a code line was expected but could not be read
    #   None          -- not a code finding; no snippet is expected at all
    snippet, snippet_state = None, None
    if item['stage'] == 'code' and original:
        if original.get('tool') == 'gitleaks' or _is_secret_finding(original):
            snippet_state = 'secret'
        elif original.get('path') and original.get('line'):
            try:
                from . import scanners
                snippet = scanners.source_snippet(item['target'], original['path'], original['line'])
            except (OSError, ValueError):
                snippet = None
            snippet_state = 'unavailable' if snippet is None else None
    return {'row': item, 'finding': original, 'events': events, 'related': related,
            'snippet': snippet, 'snippet_state': snippet_state}


def triage_changed(scope, fingerprints):
    """A decision was stored: bring its rows up to date without rebuilding."""
    from . import findings_store
    findings_store.decided(scope, fingerprints)


def invalidate():
    """Forget the board; the next search rebuilds it from the reports."""
    from . import findings_store
    findings_store.forget()
