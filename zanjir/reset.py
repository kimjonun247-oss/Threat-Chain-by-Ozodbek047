"""Clear all scan results, so a new target set starts from a clean board.

When one system's scan is finished and the next must not be read together with
it, this removes every stored report (all *-runs) and the triage decisions that
point at them, then drops the cached board. It does NOT touch registered targets,
settings, installed tools or rule packs -- only results. The scan reports are the
only thing deleted; nothing is sent anywhere.
"""
import shutil

from .engine import DATA
from . import findings_index

# Every per-stage report directory, plus the unified assessment reports.
RESULT_DIRS = ('scanner-runs', 'dependency-runs', 'image-runs', 'repository-runs',
               'iac-runs', 'web-runs', 'assessment-runs')
# Triage decisions reference findings by fingerprint; once the reports are gone
# the decisions are orphaned, so they are cleared with them.
DECISION_DIRS = ('profiles/triage',)


def _empty_dir(path):
    """Delete everything inside a directory (the directory itself stays). Returns
    how many entries were removed; unreadable entries are skipped, not fatal."""
    removed = 0
    try:
        children = list(path.iterdir())
    except OSError:
        return 0
    for child in children:
        try:
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child)
            else:
                child.unlink()
            removed += 1
        except OSError:
            pass
    return removed


def clear_results():
    """Remove all scan reports and triage decisions; return a per-directory count."""
    cleared = {}
    for name in RESULT_DIRS + DECISION_DIRS:
        cleared[name] = _empty_dir(DATA / name)
    findings_index.invalidate()
    return {'cleared': cleared, 'total': sum(cleared.values())}
