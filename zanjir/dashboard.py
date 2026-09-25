"""Everything the overview screen needs, in one request.

The dashboard used to be assembled from four separate calls and rendered as
paragraphs. Four calls meant four chances for one slow feed to hold up the whole
page, and paragraphs meant the numbers a reader actually wants -- how many
critical findings, which layers were never scanned -- were buried in prose.

Two rules from the rest of the project apply unchanged:

  - **Counts are never combined.** Severity, stage and status are three separate
    tallies. There is no total "score" here and no weighting between scanners,
    because a Trivy count and a Nuclei count do not measure the same thing.
  - **Coverage is part of the answer.** A chart drawn only from what was found
    would make an unscanned project look like a clean one, so the unscanned and
    incomplete targets are returned beside the totals and the screen draws them.
"""
import datetime

from . import findings_index, portfolio, readiness, triage

STAGES = ('code', 'repository', 'dependencies', 'iac', 'images', 'web')
SEVERITY_ORDER = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNRATED')
RECENT = 8
TREND = 12


def recent_scans(limit=RECENT):
    """The last few scans across every stage, newest first."""
    from . import dependencies, iac, images, repo_store, scanners, webscan
    sources = (('code', scanners.history, 'target'), ('dependencies', lambda n: dependencies.history(None, n), 'target'),
               ('iac', iac.history, 'target'), ('images', images.history, 'target'),
               ('web', webscan.history, 'target'),
               ('repository', lambda n: repo_store.list_reports(limit=n), 'profile_id'))
    rows = []
    for stage, history, field in sources:
        try:
            for entry in history(limit):
                rows.append({'stage': stage, 'target': entry.get(field) or entry.get('target') or '',
                             'id': entry.get('id'), 'created_at': entry.get('created_at'),
                             'state': entry.get('state', 'completed' if stage == 'repository' else ''),
                             'count': entry.get('count', (entry.get('summary') or {}).get('findings'))})
        except (OSError, ValueError, KeyError):
            continue
    rows.sort(key=lambda row: str(row.get('created_at') or ''), reverse=True)
    return rows[:limit]


def trend(limit=TREND):
    """Findings per completed code scan, oldest first.

    One stage only, and the state of every point travels with it: a falling
    count can mean a fix or a scan that covered less, and this module never
    decides which.
    """
    from . import scanners
    points = []
    try:
        for entry in scanners.history(limit=200):
            if entry.get('state') in ('completed', 'partial'):
                points.append({'at': entry.get('created_at'), 'count': entry.get('count') or 0,
                               'state': entry.get('state'), 'target': entry.get('target')})
    except (OSError, ValueError):
        return []
    return list(reversed(points[:limit]))


def severity_by_stage():
    """Severity counts per scanner, for the stacked bar on the overview.

    Read from the board's own cached rows, so the bar and the table can never
    disagree. Still three separate tallies: a stage's five numbers are drawn
    side by side, never added into one bar of "risk".
    """
    rows = findings_index.collect()['rows']
    table = {stage: dict.fromkeys(SEVERITY_ORDER, 0) for stage in STAGES + ('chain',)}
    for item in rows:
        bucket = table.get(item['stage'])
        if bucket is None:
            continue
        bucket[item.get('severity_scale') or 'UNRATED'] += 1
    return [{'stage': stage, 'counts': counts, 'total': sum(counts.values())}
            for stage, counts in table.items() if sum(counts.values())]


def last_assessment():
    """The newest "Umumiy tekshiruv" run, as a row per stage.

    The overview screen shows it so the result of the one action that runs
    every scanner at once is visible without opening its own section. Each
    stage keeps its own state and its own count -- a partial run is reported as
    partial, never folded into the total.
    """
    from . import pipeline
    try:
        listed = pipeline.history(limit=1)
        if not listed:
            return None
        report = pipeline.read(listed[0]['id'])
    except (OSError, ValueError, KeyError):
        return None
    stages = [{'kind': stage.get('kind'), 'target': stage.get('target') or '',
               'state': stage.get('state'), 'count': stage.get('count')}
              for stage in report.get('stages') or []]
    return {'id': report.get('id'), 'created_at': report.get('created_at'),
            'state': report.get('state'), 'stages': stages,
            'chain_findings': len(report.get('chain_findings') or []),
            'chain_gaps': len(report.get('chain_gaps') or [])}


def overview():
    board = findings_index.search(limit=1)
    facets = board['facets']
    coverage = board['coverage']
    health = readiness.status()
    projects = portfolio.overview()['projects']

    severity = {name: facets['severity'].get(name, 0) for name in SEVERITY_ORDER}
    stages = {stage: facets['stage'].get(stage, 0) for stage in STAGES + ('chain',)}
    overdue = 0
    decided = 0
    for project in projects:
        try:
            summary = triage.overview(project['id'])
        except (OSError, ValueError):
            continue
        overdue += summary.get('overdue', 0)
        decided += len(summary.get('decisions') or [])

    gaps = sum(len(project.get('gaps') or []) for project in projects)
    return {
        'generated_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'system': {
            'version': health['version'], 'python': health['python'],
            'free_disk_gb': health['free_disk_gb'], 'disk_warning': health.get('disk_warning'),
            'code_fingerprint': health['code_fingerprint'],
            'tools': [{'name': tool['name'], 'installed': tool['installed']} for tool in health['tools']],
            'rules': {'semgrep': (health['semgrep_rule_pack'] or {}).get('rules'),
                      'languages': len((health['semgrep_rule_pack'] or {}).get('languages') or []),
                      'custom': (health.get('custom_rules') or {}).get('rules', 0),
                      'chain': 11, 'cross_scanner': 3},
            'nvd_key': health['nvd_api_key']['present'],
        },
        'totals': {
            'findings': board['total'], 'severity': severity, 'stages': stages,
            'owasp': facets['owasp'], 'status': facets['status'],
            'triaged': decided, 'overdue': overdue,
            'note': ('Sonlar qo‘shilmaydi va umumiy ball chiqarilmaydi: har bir skaner boshqa narsani '
                     'o‘lchaydi.'),
        },
        'coverage': {
            'scanned': len(coverage['scanned']), 'unscanned': len(coverage['unscanned']),
            'incomplete': len(coverage.get('incomplete') or []),
            'unscanned_targets': [{'stage': c['stage'], 'target': c['target']} for c in coverage['unscanned']],
            'truncated': coverage['truncated'],
        },
        'projects': [{'id': p['id'], 'name': p['name'], 'gaps': len(p.get('gaps') or []),
                      'stages': {stage: p['stages'][stage]['state'] for stage in STAGES}}
                     for p in projects],
        'project_gaps': gaps,
        'recent': recent_scans(),
        'severity_by_stage': severity_by_stage(),
        'last_assessment': last_assessment(),
        'trend': trend(),
    }
