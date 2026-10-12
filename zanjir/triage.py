"""What a human decided about a finding, kept across rescans.

Two review mechanisms already existed and both had the same flaw: the decision
was stored against a *report*. `dependency-runs/<id>/reviews.json` is keyed by a
finding id that a later scan recomputes, and the repository store binds a review
to one source snapshot on purpose. So the next scan produced a fresh report with
no decisions on it, and the operator started over. Code, image and web findings
had no review at all.

This module stores a decision against the pair (project, fingerprint) instead.
The fingerprint is stable across rescans (see zanjir/findings.py), so the
decision is too. Three things shape the design:

  1. **A decision is never inferred.** A status is set by a person, with an owner
     and a reason; nothing here marks a finding fixed because it stopped
     appearing. A finding can vanish because coverage shrank, and that is not a
     fix -- the same rule the comparison views already state.
  2. **The audit trail is append-only.** Every change writes its own event file.
     The current state is a convenience view that can be rebuilt from the events.
  3. **An SLA is a date, never a score.** Each open finding gets a due date from
     its severity, and overdue ones are counted. The counts are never combined
     into a percentage or a grade -- the same rule that keeps the portfolio from
     inventing a security score.

Statuses and SLA defaults follow DefectDojo (BSD-3-Clause): its finding states
and its default remediation windows of 7/30/90/120 days for critical/high/
medium/low. No DefectDojo code is used.
"""
import datetime
import json
import os
import re
import threading
import time
import uuid

from .engine import ROOT, DATA
from . import repo_store

TRIAGE = DATA / 'profiles/triage'
SCOPE = re.compile(r'^[a-z0-9_][a-z0-9._-]{1,80}$')
LOCK = threading.Lock()
# attach() runs on every report read, and the grouping it needs is built from
# five registries. Recomputing that per read made a history listing quadratic,
# so it is memoised for a few seconds. A grouping registered in the last few
# seconds is simply not used yet; no decision is lost, it is only filed under
# the target's own scope until the cache turns over.
_GROUPS = {'at': 0.0, 'value': None}
GROUP_TTL = 5.0

STATUSES = ('investigating', 'confirmed', 'fix_planned', 'false_positive', 'accepted_risk', 'fixed')
# Statuses that take a finding out of the open list. `fixed` is separate from the
# two suppressing ones because a fix is expected to be confirmed by a rescan,
# while a false positive and an accepted risk are decisions about the finding
# itself and stay in force until someone changes them.
SUPPRESSING = ('false_positive', 'accepted_risk')
CLOSED = SUPPRESSING + ('fixed',)

# DefectDojo's default remediation windows, in days.
SLA_DAYS = {'CRITICAL': 7, 'HIGH': 30, 'MEDIUM': 90, 'LOW': 120}
# Each scanner rates findings on its own scale. Mapping them onto one scale is
# needed for an SLA and for nothing else; it never produces a combined number.
# UNKNOWN is deliberately absent: a finding nobody has rated gets no deadline
# rather than an invented one.
SEVERITY_SCALE = {
    'CRITICAL': 'CRITICAL',
    'HIGH': 'HIGH', 'ERROR': 'HIGH',
    'MEDIUM': 'MEDIUM', 'WARNING': 'MEDIUM',
    'LOW': 'LOW', 'INFO': 'LOW', 'NOTE': 'LOW', 'INFORMATIONAL': 'LOW',
}


def now():
    return datetime.datetime.now(datetime.timezone.utc)


def parse_time(value):
    try:
        moment = datetime.datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=datetime.timezone.utc)


def severity_of(finding):
    """The one severity scale, or None when the scanner did not rate the finding.

    Repository findings carry a SARIF `level` rather than a severity; both are
    read here so every stage lands on the same scale.
    """
    raw = finding.get('severity') or finding.get('level') or ''
    return SEVERITY_SCALE.get(str(raw).upper())


def scope_for(stage, target):
    """The project a scan belongs to, or a per-target scope when it belongs to none.

    Grouping comes from portfolio.py, which already maps one project onto its
    per-stage target ids (crAPI is `crapi-full` for code and `crapi` for Compose).
    A target no grouping claims gets its own scope rather than being guessed into
    a neighbouring project.
    """
    # Imported here, not at module level: portfolio reads every scanner module,
    # and those modules call attach() -- importing it at the top would make the
    # cycle scanners -> triage -> portfolio -> scanners.
    target = str(target or '')
    if not target:
        raise ValueError('Nishon ko‘rsatilmagan.')
    for identifier, meta in groups().items():
        if target in (meta.get('stages') or {}).get(stage, []):
            return identifier
    scope = '_' + target
    if not SCOPE.fullmatch(scope):
        raise ValueError('Nishon identifikatori noto‘g‘ri.')
    return scope


def groups():
    from . import portfolio      # see _GROUPS above for why this import is local
    if _GROUPS['value'] is None or time.monotonic() - _GROUPS['at'] > GROUP_TTL:
        try:
            _GROUPS['value'] = portfolio.projects()
        except (OSError, ValueError):
            _GROUPS['value'] = {}      # a broken grouping must not block a decision
        _GROUPS['at'] = time.monotonic()
    return _GROUPS['value']


def folder(scope):
    if not SCOPE.fullmatch(str(scope or '')):
        raise ValueError('Loyiha identifikatori noto‘g‘ri.')
    return TRIAGE / scope


# Decisions and the first/last-seen ledger live in SEPARATE files. They used to
# share decisions.json, and `write()` wrote the whole thing: a CLI scan's
# observe() (which touches only `seen`) running at the same time as the server's
# decide_many() (which touches only `decisions`) each read the combined file and
# wrote it back, so whichever finished last erased the other's change -- and when
# observe won, it erased a human's triage decision. Splitting the files makes the
# two writers touch disjoint files, so neither can clobber the other. decisions
# come only from the server UI, seen from either, so the dangerous case (a lost
# decision) cannot happen once they are apart. Within one process LOCK still
# serialises; across processes the atomic replace is now per-file.
def _load(path):
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        raise ValueError('Triage faylini o‘qib bo‘lmadi.') from None
    if not isinstance(data, dict):
        raise ValueError('Triage fayli formati noto‘g‘ri.')
    return data


def read(scope):
    """The stored state of one project: decisions plus the first/last-seen ledger.

    Reads the split files, falling back to a legacy combined decisions.json for
    `seen` until the next write of each kind moves it into seen.json.
    """
    base = folder(scope)
    combined = _load(base / 'decisions.json') or {}
    seen_file = _load(base / 'seen.json')
    decisions = combined.get('decisions')
    seen = seen_file.get('seen') if seen_file is not None else combined.get('seen')
    if not isinstance(decisions, dict):
        decisions = {}
    if not isinstance(seen, dict):
        seen = {}
    return {'scope': scope, 'decisions': decisions, 'seen': seen}


def _write_decisions(scope, decisions):
    repo_store.write_json(folder(scope) / 'decisions.json', {'scope': scope, 'decisions': decisions})


def _write_seen(scope, seen):
    repo_store.write_json(folder(scope) / 'seen.json', {'scope': scope, 'seen': seen})


def _ensure_seen_split(scope, data):
    """Before decisions.json is rewritten without its legacy `seen`, make sure
    that `seen` is already safe in seen.json -- otherwise the one-time migration
    would drop it."""
    if data.get('seen') and not (folder(scope) / 'seen.json').exists():
        _write_seen(scope, data['seen'])


def event(scope, record):
    """Append-only audit entry. Written before the state file, so a crash between
    the two leaves the trail ahead of the view rather than behind it."""
    identifier = uuid.uuid4().hex
    repo_store.write_json(folder(scope) / 'review-events' / (identifier + '.json'), {'event_id': identifier, **record})
    return identifier


def events(scope):
    directory = folder(scope) / 'review-events'
    rows = []
    for path in sorted(directory.glob('*.json')) if directory.is_dir() else []:
        try:
            rows.append(json.loads(path.read_text(encoding='utf-8')))
        except (OSError, ValueError):
            continue
    return sorted(rows, key=lambda row: str(row.get('updated_at') or ''))


def count_events(scope):
    """How many events the trail holds, without opening any of them.

    The audit trail is one append-only file per event and grows without bound;
    overview() needs only its size, so it counts names rather than parsing every
    file (which readLoad did, turning a count into O(events) JSON reads)."""
    directory = folder(scope) / 'review-events'
    try:
        with os.scandir(directory) as entries:
            return sum(1 for entry in entries if entry.name.endswith('.json') and entry.is_file())
    except OSError:
        return 0


def _decision_record(status, owner, note, bound_to, stage, target):
    """Validate a decision's shared fields and build the stored record. Every
    field is required because an unexplained status is what makes a triage list
    untrustworthy a month later."""
    if status not in STATUSES:
        raise ValueError('Triage holati noto‘g‘ri: ' + ', '.join(STATUSES))
    if not isinstance(owner, str) or not 1 <= len(owner.strip()) <= 120:
        raise ValueError('Qaror uchun mas’ul kerak (120 belgigacha).')
    if not isinstance(note, str) or not 1 <= len(note.strip()) <= 1000:
        raise ValueError('Qaror uchun asos kerak (1000 belgigacha).')
    return {'status': status, 'owner': owner.strip(), 'note': note.strip(),
            'updated_at': now().isoformat(), 'bound_to': bound_to or None,
            'stage': str(stage or '')[:40], 'target': str(target or '')[:120]}


def decide(scope, fingerprint, status, owner, note, bound_to=None, stage='', target=''):
    """Record one decision."""
    return decide_many(scope, [fingerprint], status, owner, note, bound_to, stage, target)[fingerprint]


def decide_many(scope, fingerprints, status, owner, note, bound_to=None, stage='', target=''):
    """Record decisions for one or many findings in a SINGLE decisions-file write,
    so a bulk of 200 does not rewrite (and re-read) the whole file 200 times."""
    base = _decision_record(status, owner, note, bound_to, stage, target)
    # Validate the whole batch before writing anything. An invalid fingerprint
    # found mid-loop used to raise after earlier findings had already written
    # their append-only event files, leaving the audit trail ahead of a
    # decisions file that was never written -- orphan events for a decision the
    # state never records. All-or-nothing instead.
    unique = list(dict.fromkeys(fingerprints))
    for fingerprint in unique:
        if not re.fullmatch(r'[0-9a-f]{24}', str(fingerprint or '')):
            raise ValueError('Topilma identifikatori noto‘g‘ri.')
    records = {}
    with LOCK:
        data = read(scope)
        _ensure_seen_split(scope, data)   # keep legacy `seen` before dropping it from decisions.json
        for fingerprint in unique:
            record = dict(base)
            event(scope, {'scope': scope, 'fingerprint': fingerprint, **record})
            data['decisions'][fingerprint] = record
            records[fingerprint] = record
        _write_decisions(scope, data['decisions'])   # one write for the whole batch, not one per finding
    # The findings board caches its flattened view for a few seconds; a decision
    # taken from that screen has to show on it immediately.
    try:
        from . import findings_index
        findings_index.invalidate()
    except ImportError:
        pass
    return records


def observe(scope, findings, at=None):
    """Record that these findings were seen in a completed scan.

    first_seen is what an SLA counts from, so it is written once and never moved
    forward. last_seen moves on every scan. Nothing here changes a decision.
    """
    moment = (at or now().isoformat())
    changed = False
    with LOCK:
        data = read(scope)
        for finding in findings or []:
            fingerprint = finding.get('fingerprint')
            if not fingerprint:
                continue
            entry = data['seen'].get(fingerprint)
            severity = severity_of(finding)
            if entry is None:
                data['seen'][fingerprint] = {'first_seen': moment, 'last_seen': moment, 'severity': severity}
                changed = True
            else:
                if entry.get('last_seen') != moment or entry.get('severity') != severity:
                    changed = True
                entry['last_seen'] = moment
                entry['severity'] = severity
        if changed:
            _write_seen(scope, data['seen'])
    return changed


def record_scan(stage, report):
    """Record what a finished scan saw. Called from each scanner's `finally`.

    Only a scan that produced results counts: a failed or cancelled run has not
    established that anything is still present, and letting it set first_seen
    would start an SLA clock from a scan that proved nothing. Never raises --
    a triage bookkeeping problem must not turn a finished scan into a failed one.
    """
    try:
        if not isinstance(report, dict) or report.get('state') not in ('completed', 'partial'):
            return False
        scope = scope_for(stage, report.get('target') or report.get('profile_id'))
        return observe(scope, report.get('findings') or [], report.get('created_at'))
    except (OSError, ValueError, KeyError, TypeError):
        return False


def sla(severity, first_seen, at=None):
    """Due date for one open finding. Returns None when there is nothing to count
    from -- an unrated severity or an unknown first-seen date."""
    days = SLA_DAYS.get(severity or '')
    start = parse_time(first_seen)
    if not days or start is None:
        return None
    due = start + datetime.timedelta(days=days)
    moment = at or now()
    remaining = (due - moment).days
    return {'days': days, 'due': due.isoformat(), 'overdue': moment > due, 'days_remaining': remaining}


def decorate(finding, data, at=None):
    """The triage view of one finding: decision, first/last seen, SLA."""
    fingerprint = finding.get('fingerprint')
    if not fingerprint:
        return None
    decision = (data['decisions'] or {}).get(fingerprint)
    seen = (data['seen'] or {}).get(fingerprint) or {}
    severity = severity_of(finding)
    stale = bool(decision and decision.get('bound_to') and decision['bound_to'] != finding.get('_snapshot'))
    open_now = not decision or decision['status'] not in CLOSED or stale
    return {
        'status': None if stale else (decision or {}).get('status'),
        'owner': None if stale else (decision or {}).get('owner'),
        'note': None if stale else (decision or {}).get('note'),
        'updated_at': None if stale else (decision or {}).get('updated_at'),
        # A decision bound to one source snapshot (the repository reviews have
        # always worked this way) does not carry over to a changed source.
        'stale': stale,
        'stale_note': ('Bu qaror boshqa manba holatiga bog‘langan edi; manba o‘zgargani uchun '
                       'qaytadan ko‘rib chiqilishi kerak.') if stale else None,
        'first_seen': seen.get('first_seen'), 'last_seen': seen.get('last_seen'),
        'severity_scale': severity, 'open': open_now,
        'suppressed': bool(decision and not stale and decision['status'] in SUPPRESSING),
        'sla': sla(severity, seen.get('first_seen'), at) if open_now else None,
    }


def summarize(findings, at=None):
    counts = {status: 0 for status in STATUSES}
    summary = {'total': len(findings or []), 'untriaged': 0, 'open': 0, 'suppressed': 0,
               'overdue': 0, 'no_fingerprint': 0, 'by_status': counts,
               'note': ('Bu sonlar qo‘shilib bitta ball chiqarilmaydi. "suppressed" — odam '
                        'tomonidan yopilgan topilmalar soni, hal qilingan xavf o‘lchovi emas.')}
    for finding in findings or []:
        view = finding.get('triage')
        if view is None:
            summary['no_fingerprint'] += 1
            continue
        if view['status']:
            counts[view['status']] += 1
        else:
            summary['untriaged'] += 1
        summary['open'] += bool(view['open'])
        summary['suppressed'] += bool(view['suppressed'])
        summary['overdue'] += bool((view.get('sla') or {}).get('overdue'))
    return summary


def attach(stage, target, report, at=None):
    """Add `triage` to every finding of a report and a `triage_summary` beside them.

    Called when a report is read rather than when it is written: a decision made
    after the scan must show on the scan it applies to. The stored report.json is
    never modified, which keeps the evidence and the opinions about it apart.
    """
    if not isinstance(report, dict) or not isinstance(report.get('findings'), list):
        return report
    try:
        scope = scope_for(stage, target)
        data = read(scope)
    except (OSError, ValueError):
        return report                     # triage is an overlay; it never blocks a report
    snapshot = report.get('input_sha256')
    findings = []
    for finding in report['findings']:
        findings.append({**finding, 'triage': decorate({**finding, '_snapshot': snapshot}, data, at)})
    return {**report, 'findings': findings, 'triage_scope': scope,
            'triage_summary': summarize(findings, at)}


def readers():
    """stage -> (read one report, the field naming its target).

    Imported lazily for the same reason scope_for() is: these modules import
    this one.
    """
    from . import dependencies, iac, images, repo_store as store, scanners, webscan
    return {'code': (scanners.read_report, 'target'), 'dependencies': (dependencies.read, 'target'),
            'images': (images.read, 'target'), 'web': (webscan.read, 'target'),
            'iac': (iac.read, 'target'), 'repository': (store.get_report, 'profile_id')}


def locate(stage, report_id):
    """The report a decision is being made against, plus its scope.

    A decision always names the report it was made from. That is not
    bookkeeping: it is what lets the server check the fingerprint actually
    exists before storing an opinion about it, so a typo becomes an error
    instead of a decision nobody can ever see again.
    """
    entry = readers().get(str(stage or ''))
    if entry is None:
        raise ValueError('Bosqich noto‘g‘ri: ' + ', '.join(sorted(readers())))
    reader, field = entry
    report = reader(report_id)
    target = report.get(field)
    return report, scope_for(stage, target), target


def apply(payload):
    """One or many decisions from one report. Returns the stored records."""
    allowed = {'stage', 'report_id', 'status', 'owner', 'note'}
    if not isinstance(payload, dict) or not allowed <= set(payload) <= allowed | {'fingerprint', 'fingerprints'}:
        raise ValueError('stage, report_id, status, owner, note va fingerprint(lar) kerak.')
    single = payload.get('fingerprint')
    many = payload.get('fingerprints')
    if (single is None) == (many is None):
        raise ValueError('Aynan bittasi kerak: fingerprint yoki fingerprints.')
    wanted = [single] if single is not None else many
    if not isinstance(wanted, list) or not 1 <= len(wanted) <= 200 or not all(isinstance(v, str) for v in wanted):
        raise ValueError('fingerprints — 1 dan 200 gacha satrdan iborat ro‘yxat bo‘lsin.')
    report, scope, target = locate(payload['stage'], payload['report_id'])
    present = {f.get('fingerprint') for f in report.get('findings') or []}
    missing = sorted(set(wanted) - present)
    if missing:
        raise ValueError(f'Bu hisobotda yo‘q topilma(lar): {", ".join(missing[:3])}')
    # Repository reviews have always been bound to one source snapshot, and that
    # is kept: a decision about a file does not carry over to a changed file.
    bound = report.get('input_sha256') if payload['stage'] == 'repository' else None
    records = decide_many(scope, wanted, payload['status'], payload['owner'],
                          payload['note'], bound, payload['stage'], target)
    return {'scope': scope, 'stage': payload['stage'], 'target': target,
            'report_id': report.get('id'), 'decisions': records}


def overview(scope, at=None):
    """Everything stored for one project, for the API and (in B7) one screen."""
    data = read(scope)
    rows = []
    for fingerprint, decision in sorted(data['decisions'].items()):
        seen = data['seen'].get(fingerprint) or {}
        severity = seen.get('severity')
        rows.append({'fingerprint': fingerprint, **decision,
                     'first_seen': seen.get('first_seen'), 'last_seen': seen.get('last_seen'),
                     'severity_scale': severity,
                     'sla': sla(severity, seen.get('first_seen'), at) if decision['status'] not in CLOSED else None})
    open_rows = [r for r in rows if r['status'] not in CLOSED]
    return {'scope': scope, 'decisions': rows, 'seen': len(data['seen']), 'events': count_events(scope),
            'sla_days': dict(SLA_DAYS),
            'overdue': sum(1 for r in open_rows if (r['sla'] or {}).get('overdue')),
            'note': ('Qarorlar loyiha va topilma identifikatori bo‘yicha saqlanadi, hisobot bo‘yicha emas — '
                     'shuning uchun ular qayta skanlardan keyin ham qoladi. Muddatlar ball emas.')}


# -- migration of the two review stores that existed before this module --------
#
# Neither old store is deleted or rewritten. Each source file keeps working for
# the endpoints that already read it, and a sibling marker records what was
# imported, so running the migration twice imports nothing twice and removing
# the marker re-runs it. An existing decision is never overwritten: the triage
# store is the newer opinion by definition.

MARKER = 'reviews.migrated.json'
# 'new' in the old repository store meant "not yet reviewed"; it has no
# counterpart here, because an untriaged finding is simply one with no decision.
OLD_STATUS = {'investigating': 'investigating', 'accepted_risk': 'accepted_risk',
              'false_positive': 'false_positive', 'fix_planned': 'fix_planned'}


def _import(scope, fingerprint, row, bound_to, stage, target, imported, dry_run):
    status = OLD_STATUS.get(str(row.get('status') or ''))
    if not status:
        return 'skipped_status'
    owner = str(row.get('owner') or '').strip() or 'migratsiya'
    note = str(row.get('note') or '').strip() or 'Eski review’dan ko‘chirildi; asos yozilmagan edi.'
    if fingerprint in read(scope)['decisions']:
        return 'already_present'
    if not dry_run:
        decide(scope, fingerprint, status, owner, note, bound_to, stage, target)
    imported.append({'scope': scope, 'fingerprint': fingerprint, 'status': status, 'stage': stage})
    return 'imported'


def migrate(dry_run=False):
    """Import the per-report reviews into the project-scoped store."""
    from . import dependencies, findings as findings_mod, repo_store as store
    imported, notes = [], []

    reviews = store.REPO_RUNS / 'reviews.json'
    if reviews.is_file() and not (store.REPO_RUNS / MARKER).is_file():
        try:
            data = json.loads(reviews.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            data = {}
            notes.append('repository/reviews.json o‘qilmadi')
        for key, row in (data or {}).items():
            snapshot, _, fingerprint = str(key).partition(':')
            try:
                report = store.get_report(str(row.get('report_id') or ''))
                target = report.get('profile_id')
                _import(scope_for('repository', target), fingerprint, row, snapshot,
                        'repository', target, imported, dry_run)
            except (OSError, ValueError):
                notes.append(f'repository: {fingerprint[:12]} uchun hisobot topilmadi')
        if not dry_run:
            repo_store_write(store.REPO_RUNS / MARKER, imported, 'repository-runs/reviews.json')

    for path in sorted(dependencies.RUNS.rglob('reviews.json')):
        if (path.parent / MARKER).is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding='utf-8'))
            report = json.loads((path.parent / 'report.json').read_text(encoding='utf-8'))
        except (OSError, ValueError):
            notes.append(f'{path.parent.name}: review yoki hisobot o‘qilmadi')
            continue
        target = report.get('target')
        # Reports written before B1 carry no fingerprint, so it is recomputed
        # from the fields it is made of -- all of which the old report already has.
        identity = {}
        for finding in report.get('findings') or []:
            package = finding.get('package') or {}
            try:
                identity[finding.get('id')] = finding.get('fingerprint') or findings_mod.fingerprint(
                    'dependencies', {'ecosystem': package.get('ecosystem'), 'package': package.get('name'),
                                     'advisory_id': finding.get('advisory_id')})
            except ValueError:
                continue
        try:
            scope = scope_for('dependencies', target)
        except ValueError:
            notes.append(f'{path.parent.name}: nishon aniqlanmadi')
            continue
        found = []
        for finding_id, row in (data.get('findings') or {}).items():
            fingerprint = identity.get(finding_id)
            if not fingerprint:
                notes.append(f'{path.parent.name}: {str(finding_id)[:12]} hisobotda yo‘q')
                continue
            _import(scope, fingerprint, row, None, 'dependencies', target, found, dry_run)
        imported += found
        if not dry_run:
            repo_store_write(path.parent / MARKER, found, path.name)
    return {'imported': imported, 'count': len(imported), 'notes': notes, 'dry_run': bool(dry_run)}


def repo_store_write(path, imported, source):
    repo_store.write_json(path, {'migrated_at': now().isoformat(), 'source': source,
                                 'imported': imported,
                                 'note': ('Manba fayl o‘zgartirilmadi va o‘chirilmadi. Bu belgini o‘chirsangiz '
                                          'migratsiya qayta ishlaydi; mavjud qaror hech qachon qayta yozilmaydi.')})

