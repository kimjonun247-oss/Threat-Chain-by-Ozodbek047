"""Pass/fail evaluation for CI pipelines.

Deliberately does not compute any blended score: this project never claims
an overall security percentage (see README), and a CI gate stays just as
honest -- it fails on concrete, named conditions, not an opaque number.

"Gate-relevant" findings are:
  - code: every Gitleaks match, including secrets found only in git history (a
    literal secret is never acceptable to merge, whatever else the scan found);
    Semgrep/PMD findings marked ERROR; and WARNING findings of a high-impact
    weakness class (injection, deserialization, XXE, SSRF, traversal, XSS) whose
    rule author rates their confidence MEDIUM/HIGH -- see code_gate_reason().
    Audit rules and LOW confidence stay out: on a real repository they number in
    the hundreds and a gate that always fails is a gate nobody reads.
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


# Weakness classes where one confirmed instance is remote code execution, data
# theft or a full auth bypass: injection of every kind, deserialization, XXE,
# SSRF, path traversal/inclusion, XSS.
HIGH_IMPACT_CWES = {22, 23, 73, 77, 78, 79, 89, 90, 91, 94, 95, 96, 98, 502, 611, 643, 917, 918, 1336}


def cwe_numbers(finding):
    numbers = set()
    for value in finding.get('cwe_ids') or []:
        try:
            numbers.add(int(str(value).upper().replace('CWE-', '')))
        except ValueError:
            continue
    return numbers


def code_gate_reason(finding):
    """Why a code finding stops the build, or '' when it does not.

    Semgrep's severity alone missed most of what matters: in the 30-case
    benchmark 27 vulnerabilities were found but only 16 were ERROR -- Java
    deserialization, Go SQL injection, Python XSS/SSTI and PMD's SOQL injection
    were all WARNING. A high-impact CWE now counts when the rule author rates
    their own confidence MEDIUM or HIGH (registry rules carry that metadata);
    `audit` rules and LOW confidence stay leads for a human, so the gate does
    not turn red on every `subprocess` call. PMD's security rules have no
    confidence field and are specific enough to count on their CWE alone.
    """
    tool = finding.get('tool')
    if tool == 'gitleaks':
        return 'Gitleaks'
    severity = str(finding.get('severity', '')).upper()
    if severity == 'ERROR':
        return f'{"PMD" if tool == "pmd" else "Semgrep"} ERROR'
    if severity == 'INFO' or not (cwe_numbers(finding) & HIGH_IMPACT_CWES):
        return ''
    if tool == 'pmd':
        return 'PMD xavfsizlik qoidasi · yuqori ta’sirli CWE'
    meta = finding.get('rule_meta') or {}
    if meta.get('subcategory') == 'audit' or meta.get('confidence') not in ('medium', 'high'):
        return ''
    return f'Semgrep · yuqori ta’sirli CWE · ishonch {meta["confidence"].upper()}'


def gate_relevant(report):
    hits = []
    for stage in report.get('stages', []):
        child = stage.get('report')
        if not child:
            continue
        kind = stage['kind']
        for f in child.get('findings') or []:
            if kind == 'code':
                why = code_gate_reason(f)
                if why:
                    hits.append(hit(kind, f, f.get('rule_id'), f.get('path'), why))
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


def classify_stage(stage):
    """('finished' | 'gap' | 'incomplete', reason) for one selected stage.

    A scanner reports `partial` for two different things, and the gate must not
    treat them alike:

    - a coverage gap: the scan ran to the end but some input could not be read
      (a Dockerfile Semgrep has no parser for, an unsupported manifest, a page
      that answered 500). Real repositories almost always have one; failing the
      build on it made the gate exit 2 on DVWA and on any site with an error page.
    - an incomplete scan: the check itself did not happen (a tool failed, OSV was
      unreachable, the web target could not be fully requested, the image had no
      coverage or a stale database). Passing then would turn "not checked" into
      "clean", so the gate stops with exit 2.
    """
    state = stage.get('state')
    child = stage.get('report') or {}
    if state in FINISHED_STAGE_STATES:
        return 'finished', ''
    if state != 'partial' or not child:
        return 'incomplete', f'holat: {state}'
    kind = stage.get('kind')
    if kind == 'code':
        failed = sorted(name for name, tool in (child.get('tools') or {}).items() if tool.get('state') == 'failed')
        if failed:
            return 'incomplete', 'skaner ishlamadi: ' + ', '.join(failed)
        return 'gap', 'ayrim fayllarni skaner o‘qiy olmadi (qamrov bo‘shlig‘i)'
    if kind == 'dependencies':
        kev = ((child.get('feeds') or {}).get('kev') or {}).get('state')
        if child.get('query_errors'):
            return 'incomplete', f"{len(child['query_errors'])} ta paket OSV’da tekshirilmadi"
        if kev not in (None, 'available'):
            return 'incomplete', 'CISA KEV ro‘yxati olinmadi'
        return 'gap', 'qo‘llanmaydigan manifest yoki lockfile yo‘q (qamrov bo‘shlig‘i)'
    if kind == 'web':
        coverage = child.get('coverage') or {}
        if child.get('errors') or coverage.get('unvisited_paths') or coverage.get('truncated_responses') \
                or not child.get('tool'):
            return 'incomplete', 'nishonning bir qismi so‘ralmadi yoki Nuclei ishlamadi'
        return 'gap', 'odatdan tashqari javoblar (5xx, 401/403, yo‘naltirish) — qamrov bo‘shlig‘i'
    return 'incomplete', f'{kind} bosqichi to‘liq tugamadi'


def incomplete_stages(report):
    """Selected stages whose check did not actually happen -- see classify_stage.

    A partial dependency stage because OSV could not be reached is here; a stage
    that ran to the end with an unreadable file is a gap (coverage_gaps), shown
    but not blocking.
    """
    rows = []
    for s in report.get('stages', []):
        if s.get('target') and classify_stage(s)[0] == 'incomplete':
            rows.append({'kind': s['kind'], 'target': s['target'], 'state': s.get('state'),
                         'reason': classify_stage(s)[1]})
    return rows


def coverage_gaps(report):
    return [{'kind': s['kind'], 'target': s['target'], 'reason': classify_stage(s)[1]}
            for s in report.get('stages', []) if s.get('target') and classify_stage(s)[0] == 'gap']


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
