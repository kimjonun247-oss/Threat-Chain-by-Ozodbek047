"""Shared state for the suite-wide "tests never write evidence" check.

Twice a test wrote real reports into the evidence folders: once hundreds of
repository reports that pushed crAPI's genuine evidence out of the listing,
once a dependency report on every run. Each time the individual test looked
harmless. The only reliable guard is to compare the folders before the first
test and after the last one.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# profiles/triage joined this list the day it was created: the very first test
# run after triage was wired wrote three real projects into it, because a test
# that patched the report folders had no reason to know a second store now
# existed. Any folder a scan writes to belongs here.
FOLDERS = ('scanner-runs', 'dependency-runs', 'image-runs', 'web-runs', 'assessment-runs',
           'repository-runs', 'iac-runs', 'profiles/triage')
BASELINE = None


def snapshot():
    found = set()
    for name in FOLDERS:
        folder = ROOT / name
        if not folder.is_dir():
            continue
        for path in folder.rglob('*.json'):
            if path.name != 'index.json':      # the listing cache may legitimately change
                found.add(path.relative_to(ROOT).as_posix())
    return found
