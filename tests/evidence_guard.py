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


def _folders():
    """The seed list plus any `*-runs` evidence directory that exists now.

    The list was not self-maintaining: a new evidence directory stayed invisible
    to the guard until someone remembered to add it (profiles/triage was missed
    once and silently polluted). Auto-discovering `*-runs` closes that gap.
    Audit 2026-10-26 E3.
    """
    names = set(FOLDERS)
    try:
        for child in ROOT.iterdir():
            if child.is_dir() and child.name.endswith('-runs'):
                names.add(child.name)
    except OSError:
        pass
    return sorted(names)


def snapshot():
    found = set()
    for name in _folders():
        folder = ROOT / name
        if not folder.is_dir():
            continue
        for path in folder.rglob('*.json'):
            if path.name != 'index.json':      # the listing cache may legitimately change
                found.add(path.relative_to(ROOT).as_posix())
    return found
