"""Scan queue, schedules and change notifications.

Each scanner still runs one scan of its kind at a time (its own LOCK). Before
this module a second request was simply refused ("Boshqa ... davom etmoqda"),
and nothing ran unless someone pressed a button. Now:

  - **Queue.** A request becomes a job. The worker starts it as soon as its
    scanner is free and the parallel limit allows (default one scan at a time
    for the whole machine: the host running scans is someone's workstation).
    The same kind+target is never queued twice.
  - **Schedules.** "every weekday at 02:30 +05:00": the worker enqueues a job
    when a scheduled time has passed. A time missed while the server was down
    is run once when it comes back (within a day), not once per missed day.
  - **Web permission windows** are respected: a web job outside its target's
    window waits until the window opens instead of failing (webscan.permission).
  - **Notifications.** When a job's result differs from the previous scan of the
    same target, zanjir.notify tells the configured channels.

State lives in DATA/jobs/ (queue.json, schedule-state.json) and
DATA/profiles/schedules/<id>.json, written atomically like everything else.
Jobs survive a restart: a job that was running when the server stopped is
marked `interrupted` (its report says what happened), queued ones stay queued.
"""
import datetime
import threading
import time
import uuid

from . import repo_store, scan_window, settings
from .engine import DATA

JOBS = DATA / 'jobs'
QUEUE = JOBS / 'queue.json'
STATE = JOBS / 'schedule-state.json'
SCHEDULES = DATA / 'profiles/schedules'
KEEP = 500                      # finished jobs kept in the queue file
TICK = 2.0
POLL = 2.0                      # seconds between reads of a running job's report
BUSY_RETRY = 20                 # seconds before trying a job whose scanner was busy
CATCH_UP = datetime.timedelta(hours=24)
KINDS = ('code', 'dependencies', 'images', 'iac', 'web', 'assessment')
ACTIVE = ('queued', 'waiting', 'running')
FINAL = ('completed', 'partial', 'failed', 'cancelled', 'no_supported_packages', 'interrupted')
NOTIFY = ('on_change', 'always', 'never')

_LOCK = threading.RLock()
_WORKER = {'thread': None, 'stop': threading.Event(), 'running': {}}


def now():
    return datetime.datetime.now(datetime.timezone.utc)


def modules():
    from . import dependencies, iac, images, pipeline, scanners, webscan
    return {'code': scanners, 'dependencies': dependencies, 'images': images, 'iac': iac,
            'web': webscan, 'assessment': pipeline}


def reader(kind):
    module = modules()[kind]
    return getattr(module, 'read_report', None) or module.read


# ---- persistence ------------------------------------------------------------
def load():
    try:
        data = repo_store.read_json(QUEUE)
    except (OSError, ValueError):
        return []
    return data if isinstance(data, list) else []


def save(jobs):
    active = [job for job in jobs if job['state'] in ACTIVE]
    finished = [job for job in jobs if job['state'] not in ACTIVE][-KEEP:]
    JOBS.mkdir(parents=True, exist_ok=True)
    repo_store.write_json(QUEUE, finished + active)


def update(job_id, **fields):
    with _LOCK:
        jobs = load()
        for job in jobs:
            if job['id'] == job_id:
                job.update(fields)
                save(jobs)
                return job
    return None


# ---- queue ------------------------------------------------------------------
def check(kind, target, payload):
    """Refuse a job that could never run, now rather than at 2 a.m."""
    if kind not in KINDS:
        raise ValueError('Skan turi: ' + ', '.join(KINDS))
    if kind == 'assessment':
        if not isinstance(payload, dict):
            raise ValueError('Umumiy tekshiruv uchun tanlov (payload) kerak.')
        modules()['assessment'].validate(payload)
        return
    if not isinstance(target, str) or not target:
        raise ValueError('Nishon ID kerak.')
    module = modules()[kind]
    if kind == 'web':
        module.target_for(target)
    elif kind == 'images':
        if target not in {row['id'] for row in module.targets()}:
            raise ValueError('Image ro‘yxatda yo‘q.')
    elif kind == 'iac':
        if target not in {row['id'] for row in module.targets() if row.get('available')}:
            raise ValueError('IaC uchun ro‘yxatdagi loyiha ID kerak.')
    else:
        modules()['code'].check_target(target)


def enqueue(kind, target=None, payload=None, source='manual', schedule_id=None, notify='never', requested_by=None):
    check(kind, target, payload)
    if notify not in NOTIFY:
        raise ValueError('notify: ' + ', '.join(NOTIFY))
    with _LOCK:
        jobs = load()
        for job in jobs:
            if job['state'] in ('queued', 'waiting') and job['kind'] == kind and job.get('target') == target \
                    and job.get('payload') == payload:
                return {**job, 'duplicate': True}
        job = {'id': now().strftime('%Y%m%dT%H%M%S') + '-' + uuid.uuid4().hex[:8], 'kind': kind,
               'target': target, 'payload': payload, 'source': source, 'schedule_id': schedule_id,
               'notify': notify, 'state': 'queued', 'created_at': now().isoformat(), 'not_before': None,
               'report_id': None, 'message': 'Navbatda', 'attempts': 0,
               'requested_by': requested_by or ('scheduler' if source == 'schedule' else None)}
        jobs.append(job)
        save(jobs)
    wake()
    return job


def cancel(job_id):
    with _LOCK:
        jobs = load()
        job = next((j for j in jobs if j['id'] == job_id), None)
        if job is None:
            raise ValueError('Bunday navbat yozuvi yo‘q.')
        if job['state'] in ('queued', 'waiting'):
            job.update(state='cancelled', finished_at=now().isoformat(), message='Boshlanishidan oldin bekor qilindi.')
            save(jobs)
            return job
        if job['state'] != 'running' or not job.get('report_id'):
            raise ValueError('Bu yozuv allaqachon tugagan.')
    modules()[job['kind']].cancel(job['report_id'])
    return {**job, 'message': 'Bekor qilish so‘raldi.'}


def listing():
    jobs = load()
    return {'jobs': list(reversed(jobs))[:200], 'schedules': schedules(),
            'max_parallel': max_parallel(), 'worker_running': bool(_WORKER['thread'] and _WORKER['thread'].is_alive()),
            'note': ('Bir turdagi skan bir vaqtda bittadan ishlaydi; qolganlari navbatda kutadi. Web nishon ruxsat '
                     'oynasidan tashqarida bo‘lsa, ish oyna ochilguncha "waiting" holatida turadi.')}


def max_parallel():
    value = settings.read().get('max_parallel_scans', 1)
    return value if type(value) is int and 1 <= value <= 4 else 1


# ---- schedules ---------------------------------------------------------------
def schedules():
    rows = []
    for path in sorted(SCHEDULES.glob('*.json')) if SCHEDULES.is_dir() else []:
        try:
            row = repo_store.read_json(path)
        except (OSError, ValueError):
            continue
        if isinstance(row, dict) and row.get('id') == path.stem:
            rows.append({**row, 'next_run': next_run(row)})
    return rows


def normalise_schedule(data):
    allowed = {'id', 'kind', 'target', 'payload', 'days', 'at', 'timezone', 'notify', 'enabled'}
    if not isinstance(data, dict) or not set(data) <= allowed or not {'id', 'kind', 'at'} <= set(data):
        raise ValueError('Jadval maydonlari: ' + ', '.join(sorted(allowed)) + ' (id, kind, at majburiy).')
    if not isinstance(data['id'], str) or not repo_store.PROFILE_ID.fullmatch(data['id']):
        raise ValueError('Jadval ID: 2–40 belgi (harf, raqam, tire).')
    if not scan_window.CLOCK.fullmatch(str(data['at'])):
        raise ValueError('at: "HH:MM" (24 soat).')
    zone = str(data.get('timezone') or 'UTC')
    scan_window.timezone(zone)
    notify = data.get('notify', 'on_change')
    if notify not in NOTIFY:
        raise ValueError('notify: ' + ', '.join(NOTIFY))
    if type(data.get('enabled', True)) is not bool:
        raise ValueError('enabled: true yoki false.')
    check(data['kind'], data.get('target'), data.get('payload'))
    return {'id': data['id'], 'kind': data['kind'], 'target': data.get('target'), 'payload': data.get('payload'),
            'days': scan_window.parse_days(data.get('days') or list(scan_window.DAYS)), 'at': data['at'],
            'timezone': zone, 'notify': notify, 'enabled': data.get('enabled', True)}


def save_schedule(data):
    row = normalise_schedule(data)
    path = SCHEDULES / (row['id'] + '.json')
    try:
        row['created_at'] = repo_store.read_json(path).get('created_at') or now().isoformat()
    except (OSError, ValueError):
        row['created_at'] = now().isoformat()
    SCHEDULES.mkdir(parents=True, exist_ok=True)
    repo_store.write_json(path, row)
    wake()
    return {**row, 'next_run': next_run(row)}


def remove_schedule(schedule_id):
    path = SCHEDULES / (str(schedule_id) + '.json')
    if not repo_store.PROFILE_ID.fullmatch(str(schedule_id)) or not path.is_file():
        raise ValueError('Bunday jadval yo‘q.')
    path.unlink()
    return {'id': schedule_id, 'removed': True}


def _occurrences(row, around):
    zone = scan_window.timezone(row['timezone'])
    local = around.astimezone(zone)
    hours, minutes = map(int, row['at'].split(':'))
    for offset in range(-8, 9):
        day = local.date() + datetime.timedelta(days=offset)
        if scan_window.DAYS[day.weekday()] in row['days']:
            yield datetime.datetime.combine(day, datetime.time(hours, minutes), zone)


def last_due(row, at):
    return max((moment for moment in _occurrences(row, at) if moment <= at), default=None)


def next_run(row, at=None):
    at = at or now()
    if not row.get('enabled', True):
        return None
    upcoming = min((moment for moment in _occurrences(row, at) if moment > at), default=None)
    return upcoming.isoformat() if upcoming else None


def fire_due(at=None):
    """Enqueue every schedule whose time has come since it last fired. Returns the new jobs."""
    at = at or now()
    try:
        state = repo_store.read_json(STATE)
    except (OSError, ValueError):
        state = {}
    fired = []
    for row in schedules():
        if not row.get('enabled', True):
            continue
        due = last_due(row, at)
        if due is None or at - due > CATCH_UP:
            continue
        created = datetime.datetime.fromisoformat(row.get('created_at') or at.isoformat())
        last = state.get(row['id'])
        if due < created or (last and datetime.datetime.fromisoformat(last) >= due):
            continue
        try:
            fired.append(enqueue(row['kind'], row.get('target'), row.get('payload'), source='schedule',
                                 schedule_id=row['id'], notify=row.get('notify', 'on_change')))
        except ValueError as error:
            fired.append({'schedule_id': row['id'], 'state': 'failed', 'message': str(error)})
        state[row['id']] = due.isoformat()
    if fired:
        JOBS.mkdir(parents=True, exist_ok=True)
        repo_store.write_json(STATE, state)
    return fired


# ---- worker -------------------------------------------------------------------
def start_scan(job):
    """Hand the job to its scanner; returns the report id."""
    module = modules()[job['kind']]
    if job['kind'] == 'assessment':
        return module.start(job['payload'])['id']
    return module.start(job['target'])['id']


def busy(kind):
    return modules()[kind].LOCK.locked()


def finish(job, report):
    """Record the outcome and notify when the result changed."""
    fields = {'state': report.get('state') or 'failed', 'finished_at': now().isoformat(),
              'message': report.get('message') or report.get('progress') or ''}
    if job.get('notify') in ('on_change', 'always') and job['kind'] != 'assessment':
        from . import notify
        try:
            delta = notify.change(job['kind'], report)
            fields['change'] = {'changed': delta['changed'], 'first': delta['first'], 'counts': delta['counts'],
                                'previous_state': delta['before_state']}
            if delta['changed'] or job['notify'] == 'always':
                fields['notifications'] = notify.deliver(notify.event_for(job, report, delta))
        except (OSError, ValueError, KeyError) as error:
            fields['notifications'] = [{'channel': 'all', 'ok': False, 'error': type(error).__name__}]
    update(job['id'], **fields)


def run(job):
    kind = job['kind']
    try:
        rid = start_scan(job)
    except ValueError as error:
        retry_at = getattr(error, 'retry_at', None)
        if retry_at is not None:
            update(job['id'], state='waiting', not_before=retry_at.isoformat(), message=str(error))
        elif busy(kind) or 'davom etmoqda' in str(error):
            later = now() + datetime.timedelta(seconds=BUSY_RETRY)
            update(job['id'], state='queued', not_before=later.isoformat(), message='Skaner band; qayta uriniladi.')
        else:
            update(job['id'], state='failed', finished_at=now().isoformat(), message=str(error)[:300])
        return
    update(job['id'], state='running', report_id=rid, started_at=now().isoformat(), message='Ishlayapti')
    read = reader(kind)
    while True:
        try:
            report = read(rid)
        except (OSError, ValueError):
            report = {'state': 'failed', 'message': 'Hisobotni o‘qib bo‘lmadi.'}
            break
        if report.get('state') not in ('queued', 'running'):
            break
        if _WORKER['stop'].wait(POLL):
            return
    finish(job, report)


def tick():
    """One pass: fire schedules, start whatever may start. Returns the jobs started."""
    fire_due()
    started = []
    with _LOCK:
        jobs = load()
        running = _WORKER['running']
        for job_id, thread in list(running.items()):
            if not thread.is_alive():
                running.pop(job_id)
        busy_kinds = {job['kind'] for job in jobs if job['state'] == 'running'}
        for job in jobs:
            if len(running) >= max_parallel():
                break
            if job['state'] not in ('queued', 'waiting') or job['kind'] in busy_kinds or job['id'] in running:
                continue
            if job.get('not_before') and datetime.datetime.fromisoformat(job['not_before']) > now():
                continue
            if busy(job['kind']):
                continue                      # a manual scan of this kind is running
            job['attempts'] = job.get('attempts', 0) + 1
            job['state'] = 'running'          # claimed; run() records the report id
            thread = threading.Thread(target=run, args=(dict(job),), daemon=True, name='job-' + job['id'])
            running[job['id']] = thread
            busy_kinds.add(job['kind'])
            started.append(job)
        if started:
            save(jobs)
    for job in started:
        _WORKER['running'][job['id']].start()
    return started


def recover():
    """After a restart: a job that was running when the process ended cannot be resumed."""
    with _LOCK:
        jobs = load()
        changed = False
        for job in jobs:
            if job['state'] == 'running':
                job.update(state='interrupted', finished_at=now().isoformat(),
                           message='Server to‘xtagan paytda ishlayotgan edi; hisobotda holati ko‘rsatilgan.')
                changed = True
        if changed:
            save(jobs)


_WAKE = threading.Event()


def wake():
    _WAKE.set()


def loop():
    while not _WORKER['stop'].is_set():
        try:
            tick()
        except Exception:                    # noqa: BLE001 -- the worker must outlive one bad job
            import traceback
            traceback.print_exc()
        _WAKE.wait(TICK)
        _WAKE.clear()


def start_worker():
    if _WORKER['thread'] and _WORKER['thread'].is_alive():
        return
    recover()
    _WORKER['stop'].clear()
    _WORKER['thread'] = threading.Thread(target=loop, daemon=True, name='threatchain-jobs')
    _WORKER['thread'].start()


def stop_worker(timeout=5):
    _WORKER['stop'].set()
    wake()
    if _WORKER['thread']:
        _WORKER['thread'].join(timeout)
