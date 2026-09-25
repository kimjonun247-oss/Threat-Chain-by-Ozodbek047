"""One pilot run links independent, redacted scanner evidence; no security score."""
import datetime
import hashlib
import json
import threading
import uuid
from .engine import ROOT
from . import scanners, dependencies, iac, images, webscan, repo_store, chains, portfolio, sarif_export, run_index, triage
from . import verification as verification_mod

RUNS = ROOT / 'assessment-runs'
LOCK = threading.Lock()
CANCEL = {}
# The selection a caller must supply, as one source of truth. Every CLI that
# starts a pipeline builds its payload from these names, and a test asserts they
# still line up: adding a field here previously broke check_all.py and
# validate_pipeline.py silently, because nothing tied the two together.
SELECTION_FIELDS = ('target', 'web_target', 'image_target', 'repository_target')
# `iac_target` is optional on purpose. Adding it to SELECTION_FIELDS would make
# it required -- validate() rejects a payload whose keys do not match exactly --
# and every existing caller, including the browser, would start failing. An
# optional field keeps every payload written before B5 working unchanged.
OPTIONAL_FIELDS = ('iac_target',)
MODULES = {'code': scanners, 'dependencies': dependencies, 'web': webscan, 'images': images, 'iac': iac}
LIMITS = ('Lokal bir foydalanuvchili pilot. Har bir skaner o‘z qamrovi va o‘z vaqtida olingan daliliga ega. '
          'Kod, image va URL aynan bir deployga tegishliligini operator tekshiradi. '
          'Tugamagan, o‘tkazib yuborilgan yoki qisman skan toza natija emas. AI ishlatilmaydi.')


def read(rid):
    report = run_index.read(RUNS, rid, 'Umumiy tekshiruv hisoboti topilmadi.')
    return attach_triage(report)


def attach_triage(report):
    """Apply triage to every stage report embedded in an assessment.

    A stage report inside an assessment is a snapshot taken when the scan ran, so
    it never carries decisions of its own; they are applied on read exactly as
    they are for a standalone report.
    """
    if not isinstance(report, dict) or not isinstance(report.get('stages'), list):
        return report
    stages = []
    for stage in report['stages']:
        child = stage.get('report')
        if isinstance(child, dict) and isinstance(child.get('findings'), list):
            stage = {**stage, 'report': triage.attach(stage.get('kind'), stage.get('target'), child)}
        stages.append(stage)
    chain = report.get('chain_findings')
    if isinstance(chain, list) and chain:
        # A chain finding belongs to the project, not to one stage; the code
        # stage's target is what names that project.
        target = next((s.get('target') for s in report['stages'] if s.get('kind') == 'code' and s.get('target')), None)
        if target:
            chain = triage.attach('code', target, {'findings': chain})['findings']
        report = {**report, 'chain_findings': chain}
    return {**report, 'stages': stages}


def history(limit=30):
    return run_index.rows(RUNS, ('id', 'created_at', 'state', 'selection'), read, limit=limit)


def validate(payload):
    fields = SELECTION_FIELDS
    if not isinstance(payload, dict) or set(payload) - set(OPTIONAL_FIELDS) != set(fields) | {'online'}:
        raise ValueError('target, web_target, image_target, repository_target va online maydonlari kerak '
                         '(iac_target ixtiyoriy).')
    fields = SELECTION_FIELDS + tuple(f for f in OPTIONAL_FIELDS if f in payload)
    if not all(isinstance(payload[k], str) for k in fields) or type(payload['online']) is not bool:
        raise ValueError('Tanlov formati noto‘g‘ri.')
    if not any(payload[k] for k in fields):
        raise ValueError('Kamida bitta manba yoki nishonni tanlang.')
    if payload['target']:
        scanners.target_root(payload['target'])
    if payload['web_target']:
        webscan.target_for(payload['web_target'])
    if payload['image_target'] and payload['image_target'] not in {t['id'] for t in images.targets()}:
        raise ValueError('Image ro‘yxatda yo‘q.')
    if payload['repository_target']:
        repo_store.profile_for(payload['repository_target'])
    if payload.get('iac_target'):
        scanners.target_root(payload['iac_target'])
    if (payload['web_target'] or payload['image_target']) and not payload['online']:
        raise ValueError('Web/image uchun online rejimni belgilang.')


# Stages that only read the project's own files or fetch public data. `web` is
# left out on purpose: it sends real requests to a target, so it must stay
# cancellable before its first request.
PASSIVE_STAGES = ('code', 'repository', 'dependencies', 'images', 'iac')


def _digest(child):
    return hashlib.sha256(json.dumps(child, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def run_stage(stage, event, commit):
    """Run one stage to completion and record its result through `commit`."""
    kind, target = stage['kind'], stage['target']
    if kind == 'repository':
        # Pure local YAML/Nginx parsing -- synchronous, no external tool.
        commit(stage, state='running')
        child = repo_store.scan_profile(target)
        commit(stage, report_id=child['id'], state='completed', count=child['summary']['findings'], report=child,
               report_sha256=_digest(child), verification=verification_mod.summarize(child.get('findings', [])))
        return
    module = MODULES[kind]
    job = module.start(target)
    commit(stage, report_id=job['id'], state='running')
    cancelled_child = False
    read_failures = 0
    while True:
        try:
            child = module.read_report(job['id']) if kind == 'code' else module.read(job['id'])
            read_failures = 0
        except ValueError:
            read_failures += 1
            if read_failures >= 3:
                raise
            threading.Event().wait(0.4)
            continue
        if child['state'] not in {'queued', 'running'}:
            break
        if event.is_set() and kind != 'code' and not cancelled_child:
            try:
                module.cancel(job['id'])
            except ValueError:
                pass  # Child may have completed between read and cancel.
            cancelled_child = True
        # Code scanners have a bounded timeout; cancellation waits for this stage.
        threading.Event().wait(0.4)
    commit(stage, state=child['state'], count=child.get('count', 0), report=child,
           report_sha256=_digest(child), verification=verification_mod.summarize(child.get('findings', [])))


def stage_report(report, kind):
    """A completed stage's report, or None. A stage that did not finish is not
    evidence, so a chain rule never rests on one."""
    stage = next((s for s in report['stages'] if s['kind'] == kind), None)
    return stage.get('report') if stage and stage['state'] == 'completed' else None


def correlate_stages(report):
    """Run every cross-scanner chain over this assessment's finished stages.

    The image stage takes one target per run, so the images available here are
    that one plus -- when the project grouping names more -- the latest completed
    scan of each. That is what makes SX-002 useful in practice: an assessment
    that scanned one image still sees the rest of the project's images, and says
    so in the evidence.
    """
    repository = stage_report(report, 'repository')
    images_by_target = {}
    if repository:
        images_by_target = project_images(report, repository)
    linked = image_links(repository, images_by_target)
    return chains.correlate_all({'code': stage_report(report, 'code'), 'repository': repository},
                                links=linked.get('links'), image_reports=images_by_target,
                                ambiguous=linked.get('ambiguous'))


def project_images(report, repository):
    """The image reports this assessment may reason about, newest first.

    The one this run scanned always counts. The others come from the project
    grouping: the newest report of each that produced results, because saying
    nothing about an image the operator registered would be the quieter, worse
    answer.

    A `partial` image report counts. Unlike a baseline -- where partial coverage
    would make a later scan look like it introduced findings -- a partial image
    scan can only miss CVEs, never invent them, so every chain it does support is
    real. What it may have missed is reported as a gap by chains.image_chains().
    """
    found = {}
    scanned = stage_report(report, 'images')
    if scanned and scanned.get('target'):
        found[scanned['target']] = scanned
    try:
        target = next((s['target'] for s in report['stages'] if s['kind'] == 'repository' and s['target']), None)
        meta = next((m for m in portfolio.projects().values()
                     if target in (m.get('stages') or {}).get('repository', [])), None)
        history = images.history(limit=10 ** 6)          # newest first
        for identifier in (meta or {}).get('stages', {}).get('images', []):
            if identifier in found:
                continue
            row = next((r for r in history
                        if r.get('target') == identifier and r.get('state') in ('completed', 'partial')), None)
            if row:
                found[identifier] = images.read(row['id'])
    except (OSError, ValueError, KeyError):
        pass          # a broken grouping must not fail a finished assessment
    return found


def image_links(repository, images_by_target):
    if not repository or not images_by_target:
        return {}
    try:
        return portfolio.link_images({'images': sorted(images_by_target)}, repository.get('services') or [],
                                     targets=[{'id': t, 'reference': r.get('reference')}
                                              for t, r in images_by_target.items()])
    except (OSError, ValueError, KeyError):
        return {}


def execute(rid, event):
    report = read(rid)
    path = RUNS / rid / 'report.json'
    report['state'] = 'running'
    selection = report['selection']
    requested = [('code', selection['target']), ('repository', selection['repository_target']),
                 ('dependencies', selection['target']), ('iac', selection.get('iac_target', '')),
                 ('web', selection['web_target']), ('images', selection['image_target'])]
    # Stage rows keep their fixed order in the report whatever order they run in.
    for kind, target in requested:
        report['stages'].append({'kind': kind, 'target': target, 'state': 'not_selected'})
    write_lock = threading.Lock()

    def commit(stage=None, **fields):
        # Stages finish on different threads; every mutation and every write of the
        # shared report goes through one lock, or json.dumps could meet a dict that
        # another thread is changing.
        with write_lock:
            if stage is not None:
                stage.update(fields)
            running = [s['kind'] for s in report['stages'] if s['state'] == 'running']
            report['progress'] = ', '.join(running) if running else report.get('progress')
            repo_store.write_json(path, report)

    def run(stage):
        if event.is_set():
            commit(stage, state='cancelled')
            return
        try:
            run_stage(stage, event, commit)
        except (OSError, ValueError, KeyError, TypeError) as error:
            commit(stage, state='failed', message='Bosqich bajarilmadi; alohida skaner holatini tekshiring.',
                   error_type=type(error).__name__)

    try:
        commit()
        selected_rows = [s for s in report['stages'] if s['target']]
        # Passive stages read local files or fetch public data, so they run side by
        # side: measured on crAPI, code is CPU-bound while the image stage spent
        # most of its time pulling layers from Docker Hub.
        passive = [s for s in selected_rows if s['kind'] in PASSIVE_STAGES]
        workers = [threading.Thread(target=run, args=(s,), daemon=True) for s in passive]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join()
        # The web stage sends real requests to someone's system. It runs last and
        # alone so a cancellation during the passive stages still guarantees that
        # not a single request reaches the target.
        for stage in selected_rows:
            if stage['kind'] not in PASSIVE_STAGES:
                run(stage)
        selected = [s for s in report['stages'] if s['target']]
        report['state'] = ('cancelled' if event.is_set() else 'completed' if all(s['state'] == 'completed' for s in selected)
                           else 'failed' if all(s['state'] == 'failed' for s in selected) else 'partial')
        chain = correlate_stages(report)
        chain_findings = chain['findings']
        report['chain_findings'] = chain_findings
        # What could not be checked is stored beside what was: an image that
        # could not be linked to a service, or a stage nobody selected, must not
        # be indistinguishable from "nothing found".
        report['chain_gaps'] = chain['gaps']
        verification_lists = [s['verification'] for s in report['stages'] if 'verification' in s]
        if chain_findings:
            verification_lists.append(verification_mod.summarize(chain_findings))
        report['verification_summary'] = verification_mod.summarize_many(verification_lists) if verification_lists else verification_mod.summarize([])
    except Exception as error:
        report.update(state='failed', error_type=type(error).__name__)
    finally:
        report['finished_at'] = webscan.now()
        report['progress'] = 'Jarayon yakunlandi; har bir bosqich holatini ko‘ring.'
        try:
            repo_store.write_json(path, report)
        finally:
            CANCEL.pop(rid, None)
            LOCK.release()
    return report


def start(payload, background=True):
    validate(payload)
    if not LOCK.acquire(blocking=False):
        raise ValueError('Umumiy tekshiruv davom etmoqda.')
    rid = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S') + '-' + uuid.uuid4().hex[:8]
    event = threading.Event()
    try:
        repo_store.write_json(RUNS / rid / 'report.json', {'id': rid, 'created_at': webscan.now(), 'state': 'queued',
                             'selection': dict(payload), 'stages': [], 'limits': LIMITS})
        CANCEL[rid] = event
        if background:
            threading.Thread(target=execute, args=(rid, event), daemon=True).start()
            return {'id': rid, 'state': 'queued'}
    except Exception:
        CANCEL.pop(rid, None)
        LOCK.release()
        raise
    return execute(rid, event)


def cancel(rid):
    read(rid)
    if rid not in CANCEL:
        raise ValueError('Jarayon ushbu serverda ishlamayapti.')
    CANCEL[rid].set()
    return {'id': rid, 'state': 'cancellation_requested', 'message': 'Joriy kod bosqichi tugashi kutilishi mumkin; keyingi bosqichlar boshlanmaydi.'}


STAGE_TITLES = {'code': 'Kod va sirlar (Semgrep + Gitleaks)', 'repository': 'Repository (Compose/Nginx)',
                'dependencies': 'CVE va kutubxonalar (OSV + CISA KEV)',
                'iac': 'Konfiguratsiya / IaC (Trivy config)',
                'web': 'Sayt va API (Nuclei + HTTP)', 'images': 'Docker image (Trivy)'}
STAGE_LIMIT = 40


def stage_rows(kind, findings):
    if kind == 'code':
        return ('Vosita', 'Qoida', 'Fayl:Qator', 'Xabar'), [
            (f['tool'], f['rule_id'], f['path'] + ':' + str(f['line']), f['message']) for f in findings]
    if kind == 'repository':
        return ('Qoida', 'Xizmat', 'Sarlavha', 'Daraja'), [
            (f['rule_id'], f['service_id'], f['title'], f['level']) for f in findings]
    if kind == 'dependencies':
        return ('Ustuvorlik', 'Paket', 'Versiya', 'Zaiflik', 'Og‘irlik'), [
            (f['priority'], f['package']['name'], f['package']['version'], f['advisory_id'], f['severity']) for f in findings]
    if kind == 'web':
        return ('Vosita', 'Og‘irlik', 'Yo‘l', 'Topilma'), [
            (f['tool'], f['severity'], f['path'], f['title']) for f in findings]
    if kind == 'images':
        return ('Paket', 'Versiya', 'Zaiflik', 'Og‘irlik'), [
            (f['package'], f['version'], f['advisory_id'], f['severity']) for f in findings]
    if kind == 'iac':
        return ('Tekshiruv', 'Og‘irlik', 'Fayl', 'Sarlavha'), [
            (f['rule_id'], f['severity'],
             f['path'] + (':' + str(f['line']) if f.get('line') else ''), f['title']) for f in findings]
    return (), []


def sarif(report):
    return sarif_export.build(report)


def markdown(report):
    def cell(value):
        return str(value).replace('|', '\\|').replace('\n', ' ').replace('\r', ' ')
    lines = ['# Zanjir — umumiy pilot hisoboti', '', 'Hisobot: ' + report['id'], 'Holat: ' + report['state'],
             'Boshlangan: ' + report['created_at'], '', report['limits'], '', '| Bosqich | Nishon | Holat | Topilma / moslik | Dalil ID |',
             '|---|---|---|---|---|']
    for s in report['stages']:
        lines.append('| ' + ' | '.join(cell(s.get(k, '—')) for k in ('kind', 'target', 'state', 'count', 'report_id')) + ' |')
    for s in report['stages']:
        findings = (s.get('report') or {}).get('findings') or []
        if not findings:
            continue
        headers, rows = stage_rows(s['kind'], findings)
        if not rows:
            continue
        lines += ['', '## ' + STAGE_TITLES.get(s['kind'], s['kind']) + ' — ' + s['target'],
                  '| ' + ' | '.join(headers) + ' |', '|' + '---|' * len(headers)]
        for row in rows[:STAGE_LIMIT]:
            lines.append('| ' + ' | '.join(cell(v) for v in row) + ' |')
        if len(rows) > STAGE_LIMIT:
            lines.append('')
            lines.append(f'... va yana {len(rows) - STAGE_LIMIT} ta topilma. To‘liq ro‘yxat uchun shu bosqichning alohida hisobotini (Dalil ID: {s.get("report_id", "—")}) oching.')
    chain_findings = report.get('chain_findings') or []
    if chain_findings:
        lines += ['', '## Cross-skaner zanjiri — sir + tarmoq ochiqligi (SX-001)',
                  '| Xizmat | Manba katalogi | Gitleaks qoidasi | Fayl:Qator |', '|---|---|---|---|']
        for f in chain_findings:
            ev = f['evidence']
            lines.append('| ' + ' | '.join(cell(v) for v in (
                f['service_id'], ev['build_context'], ev['gitleaks_rule_id'], ev['gitleaks_path'] + ':' + str(ev['gitleaks_line']))) + ' |')
    lines += ['', 'To‘liq redaktlangan dalillar JSON eksportidagi stages/report bo‘limlarida.',
              'Bu sonlarni qo‘shib xavfsizlik foizi yoki tasdiqlangan hujumlar soni chiqarilmaydi.']
    return '\n'.join(lines) + '\n'
