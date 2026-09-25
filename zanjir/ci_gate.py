"""Pass/fail evaluation for CI pipelines.

Deliberately does not compute any blended score: this project never claims
an overall security percentage (see README), and a CI gate stays just as
honest -- it fails on concrete, named conditions, not an opaque number.

"Gate-relevant" findings are:
  - code: every Gitleaks match (a literal secret in tracked source is never
    acceptable to merge, whatever else the scan found) and Semgrep findings the
    rule's own author marked ERROR. Semgrep WARNING/INFO are deliberately left
    out -- on a real repository they number in the hundreds and a gate that
    always fails is a gate nobody reads.
  - repository (Compose/Nginx) findings at level == 'error' (e.g. RP-004, RP-007, RP-008 --
    the chain rules whose direct consequence is auth bypass or host-level compromise)
  - dependencies / images / iac findings with severity CRITICAL or HIGH
  - web findings with severity HIGH
  - any cross-scanner chain finding (SX-001 and future SX-00X) -- these are
    already the rare, deliberately-flagged combination of two independently
    unremarkable facts, so any one of them is worth a human's attention

Since B3 the gate can also judge only what a change *introduced*, against a
baseline scan (see zanjir/baseline.py), and can be told to ignore findings a
person has closed. Both are opt-in: without the new flags the gate counts
exactly what it counted before.

Two rules keep the baseline mode from passing a build it did not really check:

  - A gate-relevant finding with no fingerprint is always counted. It cannot be
    matched against the baseline, so it cannot be shown to be old, and the gate
    never guesses in the direction of passing.
  - A missing or unusable baseline is an error, not a pass. Comparing against
    nothing would let a first run through with anything in it.
"""
from . import baseline as baseline_mod
from .pipeline import FINISHED_STAGE_STATES

SEVERE = {'CRITICAL', 'HIGH'}
# What --fail-on accepts. 'any' is what the gate has always done.
FAIL_MODES = ('any', 'new', 'new-high', 'new-critical')
NEW_ONLY = {'new': None, 'new-high': {'CRITICAL', 'HIGH'}, 'new-critical': {'CRITICAL'}}


def hit(stage, finding, rule_id, subject, detail):
    """One gate-relevant finding, with what the baseline and triage filters need."""
    from . import triage
    return {'stage': stage, 'rule_id': rule_id, 'subject': subject, 'detail': detail,
            'fingerprint': finding.get('fingerprint'),
            'severity': finding.get('severity') or finding.get('level') or '',
            'severity_scale': triage.severity_of(finding)}


def gate_relevant(report):
    hits = []
    for stage in report.get('stages', []):
        child = stage.get('report')
        if not child:
            continue
        kind = stage['kind']
        for f in child.get('findings') or []:
            if kind == 'code':
                if f.get('tool') == 'gitleaks' or str(f.get('severity', '')).upper() == 'ERROR':
                    hits.append(hit(kind, f, f.get('rule_id'), f.get('path'),
                                    'Gitleaks' if f.get('tool') == 'gitleaks' else 'Semgrep ERROR'))
            elif kind == 'repository' and f.get('level') == 'error':
                hits.append(hit(kind, f, f.get('rule_id'), f.get('service_id'), f.get('title')))
            elif kind in ('dependencies', 'images') and str(f.get('severity', '')).upper() in SEVERE:
                subject = f['package']['name'] if isinstance(f.get('package'), dict) else f.get('package')
                hits.append(hit(kind, f, f.get('advisory_id'), subject, f.get('severity')))
            elif kind == 'iac' and str(f.get('severity', '')).upper() in SEVERE:
                # Same bar as the dependency and image stages: a CRITICAL/HIGH
                # misconfiguration in a Dockerfile or manifest decides what the
                # container may do, so it is gate-relevant; MEDIUM/LOW are not,
                # for the same reason Semgrep WARNING is not.
                hits.append(hit(kind, f, f.get('rule_id'), f.get('path'), f.get('title')))
            elif kind == 'web' and str(f.get('severity', '')).upper() == 'HIGH':
                hits.append(hit(kind, f, f.get('rule_id'), f.get('path'), f.get('title')))
    for f in report.get('chain_findings') or []:
        hits.append(hit('chain', f, f.get('rule_id'), f.get('service_id'), f.get('title')))
    return hits


def incomplete_stages(report):
    """Selected stages that did not finish -- a failed, partial or cancelled run.

    'no_supported_packages' (see pipeline.FINISHED_STAGE_STATES) is a finished
    dependency stage that found no lockfile: a coverage gap the report states
    plainly, not a scan that broke half way.

    A partial dependency stage is one where OSV could not be reached for some
    packages; counting its findings and passing would turn "the advisory database
    was down" into "no known vulnerabilities". The gate therefore treats such a
    run like a scan that did not finish (exit 2), unless the operator opts in.
    """
    return [{'kind': s['kind'], 'target': s['target'], 'state': s.get('state')}
            for s in report.get('stages', [])
            if s.get('target') and s.get('state') not in FINISHED_STAGE_STATES]


def evaluate(report, allow=0, baseline=None, fail_on='any', respect_triage=False):
    """Judge one assessment.

    Called with no new arguments it behaves exactly as it always has: count every
    gate-relevant finding and compare with `allow`.

    `baseline` is a previous assessment report. `fail_on` in NEW_ONLY then counts
    only what this run introduced, optionally narrowed by severity. Findings a
    person closed are dropped when `respect_triage` is set.
    """
    if fail_on not in FAIL_MODES:
        raise ValueError('--fail-on qiymati noto‘g‘ri: ' + ', '.join(FAIL_MODES))
    hits = gate_relevant(report)
    result = {'fail_on': fail_on, 'allow': allow, 'total': len(hits),
              'respect_triage': bool(respect_triage), 'baseline': None, 'notes': []}
    if respect_triage:
        closed = baseline_mod.suppressed(report)
        kept = [h for h in hits if h['fingerprint'] not in closed]
        result['suppressed_by_triage'] = len(hits) - len(kept)
        result['notes'].append('Odam tomonidan yopilgan (false_positive / accepted_risk) topilmalar '
                               'sanalmadi. Bu ularning tuzatilgani emas.')
        hits = kept
    if fail_on == 'any':
        return {**result, 'passed': len(hits) <= allow, 'count': len(hits), 'hits': hits}
    if not isinstance(baseline, dict):
        raise ValueError('--fail-on new* uchun asos skan kerak; asossiz o‘tkazib yuborilmaydi.')
    comparison = baseline_mod.diff(baseline, report)
    introduced = {row['fingerprint'] for row in comparison['new']}
    wanted = NEW_ONLY[fail_on]
    counted = []
    for row in hits:
        if row['fingerprint'] is None:
            # Cannot be matched against the baseline, so it cannot be shown to be
            # old. Counted, and said out loud rather than dropped.
            counted.append({**row, 'why': 'identifikatorsiz'})
            continue
        if row['fingerprint'] not in introduced:
            continue
        if wanted is not None and row['severity_scale'] not in wanted:
            continue
        counted.append({**row, 'why': 'yangi'})
    result['baseline'] = {'id': comparison['before'], 'state': comparison['before_state'],
                          'counts': comparison['counts'], 'warnings': comparison['warnings']}
    result['notes'] += comparison['warnings']
    result['notes'].append(comparison['note'])
    return {**result, 'passed': len(counted) <= allow, 'count': len(counted), 'hits': counted}
