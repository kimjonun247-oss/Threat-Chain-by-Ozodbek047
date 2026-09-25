"""What changed since the last scan, and what a CI gate should do about it.

`ci_gate.py` counts every gate-relevant finding in the current run. On a project
that already has a hundred of them that gate fails on day one, someone adds
`continue-on-error`, and it never speaks again. A gate that is switched off is
worse than no gate, because the pipeline still shows a step named "security".

So the useful question is not "how many findings are there" but "what did this
change introduce". Answering it needs three things, and all three carry the same
honesty rules the rest of the project uses:

  1. **A comparison by identity, not by count.** Findings are matched on the
     fingerprint from zanjir/findings.py, so an unrelated edit above a finding
     does not make it look new.
  2. **A baseline must have covered at least as much.** Comparing against a scan
     that covered less would present previously-unscanned findings as newly
     introduced. A baseline is therefore a `completed` scan, and when the current
     run covered less than the baseline that is reported, not smoothed over.
  3. **A finding that disappeared is not a fixed finding.** It can vanish because
     coverage shrank, a package moved, or a file stopped being scanned. `gone` is
     reported as `gone` and nothing here ever calls it fixed -- the same rule the
     existing comparison views already state.
"""
from . import triage

class NoBaseline(ValueError):
    """There is no completed earlier scan to compare against.

    A subclass of ValueError so every existing caller keeps catching it, but
    distinguishable on purpose: for the CI gate this is a hard stop (a build was
    never compared and must not pass), while for a report screen it is the normal
    state of a first scan and is shown as a sentence, not as an error.
    """


STAGES = ('code', 'dependencies', 'images', 'web', 'repository', 'iac')
# A scan that did not finish proves nothing about what it did not reach, so it
# can never serve as the thing a later scan is measured against.
BASELINE_STATES = ('completed',)


def modules():
    """stage -> (read one report, list history rows). Imported lazily: these
    modules import triage, which imports this one's callers."""
    from . import dependencies, iac, images, repo_store, scanners, webscan
    return {
        'code': (scanners.read_report, scanners.history),
        'iac': (iac.read, iac.history),
        'dependencies': (dependencies.read, lambda limit=10 ** 6: dependencies.history(None, limit)),
        'images': (images.read, images.history),
        'web': (webscan.read, webscan.history),
        'repository': (repo_store.get_report, lambda limit=10 ** 6: repo_store.list_reports(limit=limit)),
    }


def rows(report):
    """Every finding of a report as (stage, finding), for one stage or an assessment.

    An assessment carries its stage reports inside it plus the cross-scanner
    chain findings, which belong to no single stage and get the name 'chain'.
    """
    if not isinstance(report, dict):
        return []
    found = []
    if isinstance(report.get('stages'), list):
        for stage in report['stages']:
            child = stage.get('report')
            if isinstance(child, dict):
                found += [(stage.get('kind'), f) for f in child.get('findings') or []]
        found += [('chain', f) for f in report.get('chain_findings') or []]
        return found
    return [(report.get('stage') or '', f) for f in report.get('findings') or []]


def index(report):
    """fingerprint -> the finding, for one report. Findings with no fingerprint
    are counted separately: they cannot take part in a comparison at all."""
    known, unidentified = {}, 0
    for stage, finding in rows(report):
        fingerprint = finding.get('fingerprint')
        if not fingerprint:
            unidentified += 1
            continue
        known.setdefault(fingerprint, {'stage': stage, 'finding': finding})
    return known, unidentified


def suppressed(report):
    """Fingerprints a person has closed as a false positive or an accepted risk.

    Read from the report's own attached triage view, so a decision that is stale
    (bound to a source snapshot that changed) does not silently suppress.
    """
    closed = set()
    for _, finding in rows(report):
        view = finding.get('triage') or {}
        if view.get('suppressed'):
            closed.add(finding.get('fingerprint'))
    closed.discard(None)
    return closed


def state_of(report):
    return str((report or {}).get('state') or '')


def diff(before, after):
    """What `after` has that `before` did not, and the other way round."""
    old, old_blind = index(before)
    new, new_blind = index(after)
    added = sorted(set(new) - set(old))
    gone = sorted(set(old) - set(new))
    warnings = []
    if state_of(before) not in BASELINE_STATES:
        warnings.append(f'Asos skan holati "{state_of(before) or "noma’lum"}" — u to‘liq qamrovni isbotlamaydi, '
                        'shuning uchun "yangi" ro‘yxati ishonchli emas.')
    if state_of(after) not in BASELINE_STATES and state_of(before) in BASELINE_STATES:
        warnings.append(f'Joriy skan holati "{state_of(after) or "noma’lum"}" — asosdan kamroq qamrab olgan '
                        'bo‘lishi mumkin; yo‘qolgan topilmalar tuzatilgan degani emas.')
    if old_blind or new_blind:
        warnings.append(f'Identifikatorsiz topilma: asosda {old_blind}, joriyda {new_blind} ta — ular '
                        'solishtirishda qatnashmaydi (B1 dan oldingi hisobot).')
    return {
        'before': (before or {}).get('id'), 'after': (after or {}).get('id'),
        'before_state': state_of(before), 'after_state': state_of(after),
        'new': [{'fingerprint': f, **summary(new[f])} for f in added],
        'gone': [{'fingerprint': f, **summary(old[f])} for f in gone],
        'unchanged': sorted(set(new) & set(old)),
        'counts': {'new': len(added), 'gone': len(gone), 'unchanged': len(set(new) & set(old))},
        'warnings': warnings,
        'note': ('Yo‘qolgan topilma tuzatilgan degani emas: qamrov qisqargan, fayl ko‘chgan yoki paket '
                 'o‘zgargan bo‘lishi mumkin. Bu modul hech qachon "tuzatildi" demaydi.'),
    }


def summary(entry):
    """The few fields a diff row needs, whatever stage the finding came from."""
    finding, stage = entry['finding'], entry['stage']
    package = finding.get('package')
    subject = (package.get('name') if isinstance(package, dict) else package) or \
        finding.get('path') or finding.get('service_id') or ''
    return {'stage': stage, 'rule_id': finding.get('rule_id') or finding.get('advisory_id') or '',
            'severity': finding.get('severity') or finding.get('level') or '',
            'severity_scale': triage.severity_of(finding), 'subject': str(subject)[:300],
            'title': str(finding.get('title') or finding.get('message') or '')[:300]}


def history_rows(stage, limit=10 ** 6):
    entry = modules().get(stage)
    if entry is None:
        raise ValueError('Bosqich noto‘g‘ri: ' + ', '.join(sorted(modules())))
    return entry[1](limit)


def read_report(stage, report_id):
    entry = modules().get(stage)
    if entry is None:
        raise ValueError('Bosqich noto‘g‘ri: ' + ', '.join(sorted(modules())))
    return entry[0](report_id)


def target_of(row, stage):
    return row.get('profile_id') if stage == 'repository' else row.get('target')


def since_last_green(stage, target, before_id=None):
    """The newest completed scan of this target, older than `before_id`.

    Returns None when there is none. The caller decides what to do about that --
    the CI gate refuses to run rather than passing a build it never compared.
    """
    rows_seen = history_rows(stage)
    started = before_id is None
    for row in rows_seen:                      # newest first
        if not started:
            started = row.get('id') == before_id
            continue
        if row.get('id') == before_id or target_of(row, stage) != target:
            continue
        if str(row.get('state') or '') in BASELINE_STATES:
            return row.get('id')
    return None


def last_green_assessment(selection, before_id=None):
    """The newest completed assessment that scanned the same selection."""
    from . import pipeline
    started = before_id is None
    for row in pipeline.history(limit=10 ** 6):
        if not started:
            started = row.get('id') == before_id
            continue
        if row.get('id') == before_id:
            continue
        if row.get('state') in BASELINE_STATES and (row.get('selection') or {}) == dict(selection or {}):
            return row.get('id')
    return None


def compare(stage, report_id, baseline_id=None):
    """Compare one report with its baseline, resolving 'last-green' when asked.

    'assessment' is handled apart from the five scanner stages: an assessment is
    not identified by a target but by the selection of stages it ran, and only a
    run of the same selection is a fair comparison.
    """
    if stage == 'assessment':
        from . import pipeline
        current = pipeline.read(report_id)
        resolved = baseline_id if baseline_id and baseline_id != 'last-green' else \
            last_green_assessment(current.get('selection'), report_id)
        if not resolved:
            raise NoBaseline('Bir xil tanlovdagi tugagan (completed) oldingi umumiy tekshiruv topilmadi. '
                             'Birinchi skanning solishtiradigan asosi bo‘lmaydi.')
        before = pipeline.read(resolved)
        if (before.get('selection') or {}) != (current.get('selection') or {}):
            raise ValueError('Asos skan boshqa tanlov bilan bajarilgan; solishtirib bo‘lmaydi.')
        return {'stage': stage, 'target': '', **diff(before, current)}
    current = read_report(stage, report_id)
    target = target_of(current, stage)
    resolved = baseline_id if baseline_id and baseline_id != 'last-green' else \
        since_last_green(stage, target, report_id)
    if not resolved:
        raise NoBaseline(f'{target} uchun tugagan (completed) oldingi skan topilmadi. '
                         'Birinchi skanning solishtiradigan asosi bo‘lmaydi.')
    before = read_report(stage, resolved)
    if target_of(before, stage) != target:
        raise ValueError('Asos skan boshqa nishonga tegishli.')
    return {'stage': stage, 'target': target, **diff(before, current)}


# -- cross-scanner duplicates --------------------------------------------------
#
# Two scanners can report the same line. The bundled sample shows it exactly:
# Semgrep's `detected-stripe-api-key` and Gitleaks' `stripe-access-token` both
# fire on app/config.py:7, and a reader sees two findings where there is one
# secret.
#
# They are linked, never merged. Merging would throw away one scanner's evidence
# -- and the two are not redundant: Gitleaks proves the string matches a known
# credential format, Semgrep proves it sits in a call that uses it. So the later
# one gets `duplicate_of` pointing at the first, both stay in the report, and it
# is presentation that may collapse them.
#
# Only findings in the same file at the same line are linked, and only inside one
# code scan. A CVE in a lockfile and the same CVE in an image are *not* linked:
# they are two different exposures that get fixed in two different places.
DUPLICATE_ORDER = ('gitleaks', 'semgrep', 'pmd')


def link_duplicates(findings):
    """Add `duplicate_of` to code findings that share a file and line.

    The primary is chosen by DUPLICATE_ORDER and then by rule id, so the same
    scan always names the same primary. Returns the number of links made.
    """
    groups = {}
    for finding in findings or []:
        if finding.get('path') and finding.get('line'):
            groups.setdefault((finding['path'], finding['line']), []).append(finding)
    linked = 0
    for members in groups.values():
        if len(members) < 2 or len({f.get('tool') for f in members}) < 2:
            continue
        order = sorted(members, key=lambda f: (DUPLICATE_ORDER.index(f['tool']) if f.get('tool') in DUPLICATE_ORDER
                                               else len(DUPLICATE_ORDER), str(f.get('rule_id'))))
        primary = order[0]
        for member in order[1:]:
            if member.get('fingerprint') and primary.get('fingerprint'):
                member['duplicate_of'] = primary['fingerprint']
                linked += 1
    return linked


def compare_optional(stage, report_id, baseline_id=None):
    """compare(), but "there is no baseline yet" is an answer rather than a failure.

    The HTTP layer uses this: a first scan having nothing to compare with is the
    normal state of a first scan, and reporting it as a client error would put a
    red line in the console of a perfectly healthy page. Bad input still raises.
    """
    try:
        return {'available': True, **compare(stage, report_id, baseline_id)}
    except NoBaseline as error:
        return {'available': False, 'stage': stage, 'after': report_id, 'reason': str(error)}

