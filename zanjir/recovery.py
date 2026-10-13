"""Reports left `running` by a process that is gone.

A scan writes `running` when it starts and its real state when it ends. If the
process dies in between -- the server is stopped, the machine restarts, the
task is killed -- nothing ever writes the end: the report said `running` for
good, the dashboard showed a scan that would never finish, and the copy of the
source it was working on stayed on disk.

This runs when the server starts. It does not guess: a report is closed only
when the process that owned it is provably gone (its recorded pid no longer
exists), or, for a report written before pids were recorded, when it is older
than any scan is allowed to run.
"""
import datetime
import json
import shutil

from .engine import process_alive
from . import repo_store, run_index

STALE_AFTER = datetime.timedelta(hours=6)
MESSAGE = ('Skan tugamasdan jarayon to‘xtagan (server o‘chirilgan yoki qayta ishga tushgan). '
           'Natija to‘liq emas; qayta ishga tushiring.')


def _modules():
    from . import dependencies, iac, images, pipeline, scanners, webscan
    return (scanners, dependencies, images, iac, webscan, pipeline)


def _stale(report, now):
    if report.get('pid'):
        return not process_alive(report['pid'])
    try:
        created = datetime.datetime.fromisoformat(str(report.get('created_at')))
    except ValueError:
        return False
    if created.tzinfo is None:
        created = created.replace(tzinfo=datetime.timezone.utc)
    return now - created > STALE_AFTER


def recover():
    """Close orphaned reports and remove their work folders. Returns what was closed."""
    now = datetime.datetime.now(datetime.timezone.utc)
    closed = []
    for module in _modules():
        runs = module.RUNS
        if not runs.is_dir():
            continue
        for folder in sorted(runs.iterdir()):
            if not folder.is_dir() or not run_index.RUN_ID.fullmatch(folder.name):
                continue
            if folder.name in getattr(module, 'CANCEL', {}):
                continue                         # running in this very process
            view = run_index.status(runs, folder.name)
            path = folder / 'report.json'
            try:
                if view is not None and view.get('state') not in run_index.ACTIVE_STATES:
                    report = None
                else:
                    report = json.loads(path.read_text(encoding='utf-8'))
            except (OSError, ValueError):
                continue
            if report is not None and report.get('state') in run_index.ACTIVE_STATES and _stale(report, now):
                report.update(state='failed', error_type='Interrupted', message=MESSAGE, finished_at=now.isoformat())
                report.pop('progress', None)
                try:
                    repo_store.write_json(path, report)
                    closed.append({'stage': runs.name, 'id': folder.name})
                except OSError:
                    continue
            elif report is not None and report.get('state') in run_index.ACTIVE_STATES:
                continue                         # still owned by a live process: leave its files alone
            # A finished or closed report has no use for a work folder; what is
            # left is a copy of the scanned source from a run that was killed.
            for leftover in folder.glob('work-*'):
                if leftover.is_dir():
                    shutil.rmtree(leftover, ignore_errors=True)
    return closed
