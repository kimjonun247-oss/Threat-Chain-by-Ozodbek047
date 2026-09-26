"""Redirect the stores a completed scan writes to, for one test case.

A test that patched the report folders used to be fully isolated. Since B2 a
finished scan also writes to profiles/triage, and the first suite run after that
change created three real projects there. The suite-wide evidence guard now
watches that folder too, so a forgotten call fails loudly instead of quietly
polluting the store -- this helper is what makes remembering it a single line.
"""
import shutil
import tempfile
from pathlib import Path
from unittest.mock import patch

from zanjir import auth, iac, jobs, triage

# Suite-wide, from the moment any test imports this module: the audit log, the
# user list and the job queue are the operator's, not the tests'. Without this
# every test POST appended to the real audit log (66 lines on the first run),
# and a developer who had created a user locally saw every HTTP test fail 401.
_STATE = Path(tempfile.mkdtemp(prefix='threatchain-test-state-'))
auth.AUDIT = _STATE / 'audit/audit.jsonl'
auth.USERS = _STATE / 'profiles/users.json'
jobs.JOBS = _STATE / 'jobs'
jobs.QUEUE = _STATE / 'jobs/queue.json'
jobs.STATE = _STATE / 'jobs/schedule-state.json'
jobs.SCHEDULES = _STATE / 'profiles/schedules'


def isolate_triage(case):
    """Point the triage store at a temp folder for the lifetime of `case`."""
    folder = Path(tempfile.mkdtemp())
    case.addCleanup(shutil.rmtree, folder, True)
    patcher = patch.object(triage, 'TRIAGE', folder / 'triage')
    patcher.start()
    case.addCleanup(patcher.stop)
    # The project grouping is memoised for a few seconds; a stale entry would
    # make a decision land under the wrong scope in the next test.
    triage._GROUPS.update(at=0.0, value=None)
    case.addCleanup(lambda: triage._GROUPS.update(at=0.0, value=None))
    return folder / 'triage'


def isolate_runs(case, *modules):
    """Point each module's RUNS directory at a temp folder for one test case."""
    folder = Path(tempfile.mkdtemp())
    case.addCleanup(shutil.rmtree, folder, True)
    for module in modules or (iac,):
        patcher = patch.object(module, 'RUNS', folder / module.__name__.rsplit('.', 1)[-1])
        patcher.start()
        case.addCleanup(patcher.stop)
    return folder
