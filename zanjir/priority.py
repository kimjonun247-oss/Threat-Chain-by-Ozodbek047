"""Run scanners so they do not compete with the operator's own work.

Semgrep, Gitleaks, Trivy and Nuclei are CPU- and disk-heavy, and the assessment
runs several of them side by side. On the operator's machine -- often the same
laptop they are working on, sometimes a shared CI runner -- they now run at a
lower CPU priority (nice 10) and, on Linux, in the idle I/O class, so they take
what is free instead of what is asked for. Results are identical; only the
scheduling changes. THREATCHAIN_NORMAL_PRIORITY=1 turns this off (for example
on a dedicated scan host where speed matters more).
"""
import os
import shutil
import subprocess
import sys

VARIABLE = 'THREATCHAIN_NORMAL_PRIORITY'
NICE = 10


def enabled():
    return os.environ.get(VARIABLE, '').strip().lower() not in {'1', 'true', 'yes', 'on'}


def gentle(command):
    """(command, extra Popen/run keyword arguments) for a low-priority run."""
    command = [str(part) for part in command]
    if not enabled():
        return command, {}
    if sys.platform == 'win32':
        return command, {'creationflags': getattr(subprocess, 'BELOW_NORMAL_PRIORITY_CLASS', 0)}
    prefix = []
    if sys.platform.startswith('linux') and shutil.which('ionice'):
        prefix += [shutil.which('ionice'), '-c', '3']
    if shutil.which('nice'):
        prefix += [shutil.which('nice'), '-n', str(NICE)]
    return prefix + command, {}
