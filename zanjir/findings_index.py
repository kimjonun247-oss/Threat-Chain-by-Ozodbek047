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
import threading
import time

from . import triage

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
# One request reads at most this many findings from one report. An image report
# can carry seven thousand rows; the table pages through them and the cap keeps
# a single dashboard load from parsing everything ever scanned.
PER_REPORT = 5000
CACHE_TTL = 4.0
_CACHE = {'at': 0.0, 'value': None}
_LOCK = threading.Lock()


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
    """Newest usable report per (stage, target), flattened. Cached briefly."""
    with _LOCK:
        if _CACHE['value'] is not None and time.monotonic() - _CACHE['at'] < CACHE_TTL:
            return _CACHE['value']
    rows, coverage, truncated = [], [], []
    for stage, (read, history, field) in sources().items():
        try:
            listed = history(10 ** 6)
        except (OSError, ValueError):
            listed = []
        newest = {}
        last_attempt = {}
        for entry in listed:                      # newest first
            target = entry.get(field) or entry.get('target')
            state = entry.get('state', 'completed' if stage == 'repository' else None)
            if not target:
                continue
            if target not in last_attempt:
                last_attempt[target] = {**entry, 'state': state}
            if target not in newest and state in USABLE:
                newest[target] = entry
        for target in sorted(registered(stage)):
            entry = newest.get(target)
            if entry is None:
                last = last_attempt.get(target)
                # A scan that ran and concluded is not an unscanned target, and a
                # scan that failed is not one either -- each gets its own word.
                concluded = last is not None and last.get('state') in CONCLUDED
                coverage.append({'stage': stage, 'target': target, 'scanned': concluded,
                                 'state': (last or {}).get('state'),
                                 'report_id': (last or {}).get('id'),
                                 'outcome': ('concluded_no_findings' if concluded else
                                             'incomplete' if last is not None else 'never_scanned'),
                                 'findings': 0})
                continue
            try:
                report = read(entry['id'])
            except (OSError, ValueError):
                continue
            project = project_of(stage, target)
            found = report.get('findings') or []
            if len(found) > PER_REPORT:
                truncated.append({'stage': stage, 'target': target, 'total': len(found), 'shown': PER_REPORT})
                found = found[:PER_REPORT]
            rows += [row(stage, report, finding, project) for finding in found]
            coverage.append({'stage': stage, 'target': target, 'scanned': True,
                             'state': report.get('state', 'completed'), 'report_id': report.get('id'),
                             'created_at': report.get('created_at'), 'findings': len(report.get('findings') or [])})
        rows += chain_rows(stage)
    value = {'rows': rows, 'coverage': coverage, 'truncated': truncated}
    with _LOCK:
        _CACHE.update(at=time.monotonic(), value=value)
    return value


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


def matches(item, query):
    if not query:
        return True
    haystack = ' '.join(str(item.get(key) or '') for key in
                        ('rule_id', 'title', 'subject', 'target', 'project', 'advisory_id', 'tool')).lower()
    return all(word in haystack for word in query.lower().split())


FILTERS = {
    'stage': lambda item, value: item['stage'] == value,
    'project': lambda item, value: item['project'] == value,
    'target': lambda item, value: item['target'] == value,
    'severity': lambda item, value: (item['severity_scale'] or 'UNRATED') == value,
    'owasp': lambda item, value: value in item['owasp'],
    'status': lambda item, value: (item['status'] or 'untriaged') == value,
    'state': lambda item, value: {'open': item['open'], 'closed': not item['open'],
                                  'overdue': item['overdue'], 'kev': item['known_exploited'] is True,
                                  'verified': item['verified'],
                                  'duplicate': bool(item['duplicate_of'])}.get(value, True),
}
# Sorted worst-first by default: severity, then whether it is overdue, then how
# long it has been open. No weighting, no composite number -- just an order.
RANK = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, None: 4}


def sort_key(item):
    return (RANK.get(item['severity_scale'], 4), 0 if item['overdue'] else 1,
            0 if item['known_exploited'] else 1, str(item.get('first_seen') or '9999'),
            item['stage'], item['rule_id'])


FACET_KEYS = {
    'severity': lambda i: i['severity_scale'] or 'UNRATED',
    'stage': lambda i: i['stage'],
    'project': lambda i: i['project'] or '—',
    'owasp': lambda i: i['owasp'] or ['—'],
    'status': lambda i: i['status'] or 'untriaged',
}


def apply_filters(rows, filters, skip=None):
    for key, value in (filters or {}).items():
        if not value or key == skip:
            continue
        rule = FILTERS.get(key)
        if rule:
            rows = [item for item in rows if rule(item, value)]
    return rows


def facets(rows, filters=None):
    """Counts the table offers as filters. Never added together.

    Each facet is counted over the rows left by every *other* filter, which is
    what makes the chips still usable after a filter narrows the table to
    nothing -- counting them over the final result set would erase the very
    chip you need to click to get back.
    """
    def tally(key, source):
        counts = {}
        for item in source:
            value = key(item)
            for one in (value if isinstance(value, list) else [value]):
                counts[one] = counts.get(one, 0) + 1
        return dict(sorted(counts.items(), key=lambda pair: (-pair[1], str(pair[0]))))
    result = {name: tally(key, apply_filters(rows, filters, skip=name))
              for name, key in FACET_KEYS.items()}
    # An active value must always have a chip, even when it now counts zero.
    for name in FACET_KEYS:
        chosen = (filters or {}).get(name)
        if chosen and chosen not in result[name]:
            result[name][chosen] = 0
    result['note'] = ('Bu sonlar filtr uchun; ular qo‘shilib umumiy ball chiqarilmaydi. Turli skanerlarning '
                      'topilmalari turli narsani o‘lchaydi.')
    return result


def search(query='', filters=None, offset=0, limit=50):
    data = collect()
    searched = [item for item in data['rows'] if matches(item, query)]
    rows = apply_filters(searched, filters)
    rows.sort(key=sort_key)
    offset = max(0, int(offset))
    limit = max(1, min(int(limit), 200))
    unscanned = [c for c in data['coverage'] if c.get('outcome') == 'never_scanned']
    incomplete = [c for c in data['coverage'] if c.get('outcome') == 'incomplete']
    return {
        'total': len(rows), 'offset': offset, 'limit': limit,
        'rows': rows[offset:offset + limit],
        'facets': facets(searched, filters),
        'coverage': {'scanned': [c for c in data['coverage'] if c['scanned']],
                     'unscanned': unscanned,
                     'incomplete': incomplete,
                     'truncated': data['truncated'],
                     'note': ('Tekshirilmagan nishon toza degani emas. Quyidagi nishonlar uchun hech qanday '
                              'natija yo‘q va ular bu jadvalda umuman ko‘rinmaydi.') if unscanned else None,
                     'incomplete_note': ('Bu nishonlarda skan boshlangan, lekin natija bermadi '
                                         '(tugallanmagan yoki bekor qilingan). Ular ham toza emas.')
                                        if incomplete else None},
    }


def detail(fingerprint):
    """One finding with its full original record, for the side panel."""
    data = collect()
    item = next((i for i in data['rows'] if i['fingerprint'] == fingerprint), None)
    if item is None:
        raise ValueError('Bunday topilma joriy hisobotlarda yo‘q.')
    read = sources().get(item['stage'], (None,))[0]
    original, events = None, []
    try:
        if read and item['report_id']:
            report = read(item['report_id'])
            original = next((f for f in report.get('findings') or []
                             if f.get('fingerprint') == fingerprint), None)
    except (OSError, ValueError):
        original = None
    try:
        if item['project']:
            events = [e for e in triage.events(item['project']) if e.get('fingerprint') == fingerprint]
    except (OSError, ValueError):
        events = []
    related = [i for i in data['rows']
               if i['fingerprint'] != fingerprint and
               (i.get('duplicate_of') == fingerprint or i.get('escalates') == fingerprint
                or (item.get('duplicate_of') and i['fingerprint'] == item['duplicate_of'])
                or (item.get('escalates') and i['fingerprint'] == item['escalates']))]
    return {'row': item, 'finding': original, 'events': events, 'related': related}


def invalidate():
    with _LOCK:
        _CACHE.update(at=0.0, value=None)
