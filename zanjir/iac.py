"""Infrastructure-as-code misconfiguration scanning with Trivy's `config` mode.

The gap this closes: a Dockerfile, a Kubernetes manifest or a Terraform file is
configuration that decides what a container is allowed to do, and until now
nothing in this project read any of them. The Compose analyser (repository.py)
covers Compose and Nginx with its own chain rules; everything else was simply
unscanned -- and an unscanned layer looks exactly like a clean one on a
dashboard, which is the failure this project exists to avoid.

Trivy is already installed and needs no new dependency, so `trivy config` is
what runs here. Three things shape the module:

  1. **Opt-in.** `iac` is a sixth pipeline stage that nobody gets by accident.
     A run that does not select it behaves exactly as it did before.
  2. **The same read-only snapshot the code scanner uses.** Nothing is executed,
     symlinks are not followed, binaries and oversized files are skipped, and
     the project directory is never written to.
  3. **CWE is looked up, never guessed.** Trivy's checks carry no CWE, so this
     module maps the ones whose weakness is unambiguous (CHECK_CWE below) and
     leaves the rest with the check id alone. An unmapped check is shown as
     itself rather than filed under a category nobody verified.
"""
import datetime
import json
import re
import subprocess
import tempfile
import threading
import uuid
from pathlib import Path

from .engine import ROOT, DATA
from . import images, priority, repo_store, run_index, scanners, taxonomy, triage, fixes
from . import findings as findings_mod
from . import verification as verification_mod

RUNS = DATA / 'iac-runs'
LOCK = threading.Lock()
CANCEL = {}
TIMEOUT = 600
# Trivy check id -> the CWE its own description names. Only checks whose weakness
# is unambiguous are listed; anything else keeps its id and no CWE, because a
# guessed category is worse than an honest blank (the same rule taxonomy.py uses).
CHECK_CWE = {
    # Dockerfile (builtin.dockerfile.DSxxx)
    'DS-0001': [250],    # ":latest" tag -- unverifiable provenance
    'DS-0002': [250],    # runs as root: Execution with Unnecessary Privileges
    'DS-0004': [250],    # COPY --chown root
    'DS-0005': [250],    # ADD instead of COPY (silent extraction)
    'DS-0013': [250],    # RUN using sudo
    'DS-0015': [1357],   # missing package version pin
    'DS-0017': [1357],   # update without install
    'DS-0031': [250],    # root user in final stage
    # Kubernetes (builtin.kubernetes.KSVxxx)
    'KSV-0001': [250], 'KSV0001': [250],     # allowPrivilegeEscalation
    'KSV-0003': [250], 'KSV0003': [250],     # default capabilities not dropped
    'KSV-0012': [250], 'KSV0012': [250],     # runAsNonRoot not set
    'KSV-0017': [250], 'KSV0017': [250],     # privileged container
    'KSV-0020': [250], 'KSV0020': [250],     # runs with low user id
    'KSV-0023': [552], 'KSV0023': [552],     # hostPath volume mounted
    'KSV-0028': [552], 'KSV0028': [552],     # writable host mount
    'KSV-0037': [284], 'KSV0037': [284],     # default namespace
    'KSV-0041': [284], 'KSV0041': [284],     # can manage secrets
    'KSV-0109': [522], 'KSV0109': [522],     # ConfigMap holds a secret
}
# Trivy's own severities, mapped onto the SARIF levels the gate and export use.
LEVELS = {'CRITICAL': 'error', 'HIGH': 'error', 'MEDIUM': 'warning', 'LOW': 'note', 'UNKNOWN': 'note'}
LIMITS = ('Trivy `config` rejimi: Dockerfile, Kubernetes, Terraform, CloudFormation, Helm va ARM '
          'fayllari statik tekshiriladi. Compose va Nginx uchun alohida Repository bosqichi ishlaydi. '
          'Hech bir fayl bajarilmaydi; topilmalar amalda ekspluatatsiya qilinishi tekshirilmagan.')


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def targets():
    """The same registered projects the code scanner offers."""
    return scanners.targets()


def read(rid):
    report = run_index.read(RUNS, rid, 'IaC hisoboti topilmadi.')
    return triage.attach('iac', report.get('target'), report)


def history(limit=30):
    return run_index.rows(RUNS, ('id', 'target', 'created_at', 'state', 'count'), read, limit=limit)


def command(folder, output):
    """The same binary and the same telemetry flags the image scanner uses."""
    return [str(images.BINARY), 'config', '--format', 'json', '--output', str(output),
            *images.QUIET, '--quiet', str(folder)]


def normalize(data, source):
    """One row per failing check, with the file and line Trivy could point at."""
    if not isinstance(data, dict) or not isinstance(data.get('Results'), list):
        raise ValueError('Trivy config natijasi noto‘g‘ri.')
    rows = []
    scanned = []
    for result in data['Results']:
        if not isinstance(result, dict):
            raise ValueError('Trivy config natija formati noto‘g‘ri.')
        target = str(result.get('Target', ''))[:500]
        misconfigurations = result.get('Misconfigurations') or []
        scanned.append({'path': target, 'type': str(result.get('Type', ''))[:80],
                        'checks': len(misconfigurations)})
        for row in misconfigurations:
            if not isinstance(row, dict) or str(row.get('Status', '')).upper() != 'FAIL':
                continue          # Trivy also reports PASS/EXCEPTION rows; only failures are findings
            check = str(row.get('ID', ''))[:60]
            cause = row.get('CauseMetadata') if isinstance(row.get('CauseMetadata'), dict) else {}
            line = cause.get('StartLine')
            severity = str(row.get('Severity', 'UNKNOWN')).upper()
            cwes = sorted(CHECK_CWE.get(check, []))
            path = scanners.path_in_snapshot(target, source) if (source / target).is_file() else target
            rows.append({
                'tool': 'trivy-config', 'rule_id': check, 'check_type': str(row.get('Type', ''))[:120],
                'title': str(row.get('Title', ''))[:300], 'message': str(row.get('Message', ''))[:1000],
                'remediation': str(row.get('Resolution', ''))[:1000],
                'path': path, 'line': int(line) if isinstance(line, int) and line > 0 else None,
                'provider': str(cause.get('Provider', ''))[:80], 'service': str(cause.get('Service', ''))[:80],
                'severity': severity if severity in LEVELS else 'UNKNOWN',
                'level': LEVELS.get(severity, 'note'),
                'reference': str(row.get('PrimaryURL', ''))[:300],
                'cwe_ids': [f'CWE-{c}' for c in cwes],
                'owasp_top10_2025': taxonomy.classify(cwes),
                'fingerprint': findings_mod.fingerprint('iac', {'rule_id': check, 'path': path,
                                                                'provider': cause.get('Provider') or ''}),
                'state': 'unverified_static', 'verified': False,
                'verification_note': ('Konfiguratsiya fayli statik tekshirildi; fayl bajarilmagan va bu sozlama '
                                      'amalda qanday ta’sir qilishi tasdiqlanmagan. Mutaxassis ko‘rib chiqishi shart.'),
            })
    untagged = sorted({r['rule_id'] for r in rows if not r['cwe_ids']})
    return {'findings': rows, 'count': len(rows), 'coverage': scanned,
            'untagged_checks': untagged,
            'untagged_note': ('Bu tekshiruvlar uchun CWE xaritada yo‘q; ular o‘z ID si bilan ko‘rsatiladi va '
                              'hech qanday OWASP toifasiga taxmin qilinmaydi.') if untagged else None}


def execute(rid, target, event):
    folder = RUNS / rid
    report = read_raw(rid)
    process = None
    try:
        report.update(state='running', progress='Konfiguratsiya fayllari nusxalanmoqda')
        repo_store.write_json(folder / 'report.json', report)
        # A remote repository is cloned here and removed when the block exits,
        # whether the scan succeeded or not.
        with scanners.source_for(target) as (source, provenance), \
                tempfile.TemporaryDirectory() as work:
            report['source'] = provenance
            repo_store.write_json(folder / 'report.json', report)
            work = Path(work)
            # The scanners' own snapshot: read-only, no symlinks, no binaries,
            # bounded in size -- the project folder is never touched.
            manifest = scanners.snapshot(source, work / 'source')
            report['coverage_scope'] = manifest['scope']
            report['snapshot_sha256'] = manifest['snapshot_sha256']
            report['files'] = manifest['files']
            report['progress'] = 'Trivy config tekshiruvi bajarilmoqda'
            repo_store.write_json(folder / 'report.json', report)
            output = work / 'iac.json'
            with (folder / 'tool.log').open('wb') as log:
                run_command, low = priority.gentle(command(work / 'source', output))
                process = subprocess.Popen(run_command, cwd=work,
                                           env=scanners.environment(work), stdout=log,
                                           stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, **low)
                deadline = datetime.datetime.now().timestamp() + TIMEOUT
                while process.poll() is None:
                    if event.wait(0.5):
                        raise InterruptedError('IaC tekshiruvi bekor qilindi.')
                    if datetime.datetime.now().timestamp() > deadline:
                        raise TimeoutError('Trivy config vaqt chegarasidan oshdi.')
            if process.returncode != 0:
                raise ValueError('Trivy config bajarilmadi; tool.log faylini tekshiring.')
            report.update(normalize(json.loads(output.read_text(encoding='utf-8')), work / 'source'))
            # Diffs are made from the snapshot while it still exists (zanjir/fixes.py).
            report['fix_plan'] = fixes.iac_plan(report['findings'], work / 'source')
        report['verification_summary'] = verification_mod.summarize(report['findings'])
        report['severity_counts'] = {level: sum(1 for f in report['findings'] if f['severity'] == level)
                                     for level in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN')}
        report['tool'] = {'name': 'trivy config', 'version': trivy_version()}
        report['state'] = 'completed'
        report['progress'] = 'Konfiguratsiya tekshiruvi tugadi'
    except InterruptedError:
        report.update(state='cancelled', progress='IaC tekshiruvi bekor qilindi')
    except Exception as error:
        report.update(state='failed', error_type=type(error).__name__,
                      progress='IaC tekshiruvi tugallanmadi; bu toza natija emas')
        if isinstance(error, (ValueError, TimeoutError)):
            report['message'] = str(error)[:400]
    finally:
        if process is not None and process.poll() is None:
            process.kill()
        report['finished_at'] = now()
        try:
            repo_store.write_json(folder / 'report.json', report)
            triage.record_scan('iac', report)
        finally:
            CANCEL.pop(rid, None)
            LOCK.release()
    return report


def trivy_version():
    try:
        done = subprocess.run([str(images.BINARY), 'version', '--format', 'json'],
                              capture_output=True, text=True, timeout=30)
        data = json.loads(done.stdout)
        # A non-dict payload (a future Trivy, or an error on stdout) would make
        # .get() raise AttributeError, which the except below does not catch.
        return str(data.get('Version', '') if isinstance(data, dict) else '')[:40]
    except (OSError, ValueError, subprocess.SubprocessError):
        return ''


def read_raw(rid):
    return run_index.read(RUNS, rid, 'IaC hisoboti topilmadi.')


def start(target, background=True):
    if not isinstance(target, str) or target not in {t['id'] for t in targets() if t.get('available')}:
        raise ValueError('Ro‘yxatdan o‘tgan loyiha ID kerak.')
    scanners.check_target(target)
    if not images.BINARY.is_file():
        raise ValueError('Trivy o‘rnatilmagan; `python3 setup_tools.py` ni bajaring.')
    if not LOCK.acquire(blocking=False):
        raise ValueError('Boshqa IaC tekshiruvi davom etmoqda.')
    rid = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S') + '-' + uuid.uuid4().hex[:8]
    event = threading.Event()
    try:
        repo_store.write_json(RUNS / rid / 'report.json',
                              {'id': rid, 'target': target, 'created_at': now(), 'state': 'queued',
                               'count': 0, 'findings': [], 'limits': LIMITS,
                               'progress': 'Navbatda'})
        CANCEL[rid] = event
        if background:
            threading.Thread(target=execute, args=(rid, target, event), daemon=True).start()
            return {'id': rid, 'state': 'queued'}
    except Exception:
        CANCEL.pop(rid, None)
        LOCK.release()
        raise
    return execute(rid, target, event)


def cancel(rid):
    event = CANCEL.get(rid)
    if event is None:
        raise ValueError('Bu jarayon shu serverda ishlamayapti.')
    event.set()
    return {'id': rid, 'state': 'cancelling'}


def markdown(report):
    def cell(value):
        return str(value).replace('|', '\\|').replace('\n', ' ').replace('\r', ' ')
    lines = ['# ThreatChain — konfiguratsiya (IaC) tekshiruvi', '',
             f"Loyiha: {cell(report.get('target'))}", f"Hisobot: {report['id']}",
             f"Vaqt: {report['created_at']}", f"Holat: {report['state']}", '',
             report.get('limits', ''), '',
             '| Tekshiruv | Og‘irlik | Fayl | CWE / OWASP | Sarlavha |',
             '|---|---|---|---|---|']
    for finding in report.get('findings') or []:
        owasp = ', '.join(o['code'] for o in finding.get('owasp_top10_2025') or [])
        location = finding.get('path') + (f":{finding['line']}" if finding.get('line') else '')
        lines.append(f"| {cell(finding['rule_id'])} | {cell(finding['severity'])} | {cell(location)} | "
                     f"{cell(', '.join(finding.get('cwe_ids') or []) + (' ' + owasp if owasp else '') or '—')} | "
                     f"{cell(finding.get('title'))} |")
    if report.get('untagged_checks'):
        lines += ['', 'CWE xaritasida yo‘q tekshiruvlar: ' + ', '.join(report['untagged_checks']),
                  report.get('untagged_note') or '']
    return '\n'.join(lines) + '\n'
