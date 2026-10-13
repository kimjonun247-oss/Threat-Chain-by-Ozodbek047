"""Shared, pure primitives used across every scanner module."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Where reports, registrations and triage decisions live. Defaults to the
# application folder (unchanged behaviour); THREATCHAIN_DATA_DIR moves all of it
# elsewhere -- a separate disk, one data set per team, or a throw-away folder so
# the benchmark suite and CI never touch an operator's real evidence. Tools,
# rules and bundled samples stay in ROOT.
DATA = Path(os.environ.get('THREATCHAIN_DATA_DIR') or ROOT).resolve()


# Directories no scan descends into, wherever they are: version control, virtual
# environments and third-party code that the dependency stage covers instead.
SKIPPED_ANYWHERE = frozenset({'.git', '.venv', 'venv', 'node_modules', 'vendor', '__pycache__'})
# This application's own working folders. They are skipped only as direct
# children of the application folder: `profiles`, `runs` and `pilot` are also
# ordinary names in other people's code (a Django `profiles` app), and skipping
# them everywhere left such a directory unscanned without a word.
SKIPPED_IN_APP = frozenset({'.tools', 'scanner-runs', 'dependency-runs', 'image-runs', 'web-runs',
                            'assessment-runs', 'validation-runs', 'advisory-cache', 'repository-runs',
                            'iac-runs', 'scan-cache', 'findings-board', 'runs', 'pilot', 'profiles', 'jobs', 'audit'})
_APP = os.path.normcase(str(ROOT))
_DATA = os.path.normcase(str(DATA))


def skip_directory(parent, name) -> bool:
    """Whether a walk should leave `parent/name` out."""
    if name in SKIPPED_ANYWHERE:
        return True
    return name in SKIPPED_IN_APP and os.path.normcase(str(parent)) in (_APP, _DATA)


def available_memory_mb():
    """Free physical memory in MB, or None when the platform will not say.

    Standard library only. Used to keep a scan from starting more workers than
    the machine can hold: six Semgrep workers on a laptop with 1 GB free did not
    finish faster, they made the whole machine stop answering.
    """
    try:
        if os.name == 'nt':
            import ctypes

            class Status(ctypes.Structure):
                _fields_ = [('length', ctypes.c_ulong), ('load', ctypes.c_ulong)] + \
                           [(name, ctypes.c_ulonglong) for name in ('total', 'available', 'page_total', 'page_free',
                                                                    'virtual_total', 'virtual_free', 'extended')]
            status = Status()
            status.length = ctypes.sizeof(Status)
            if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
                return None
            return int(status.available // (1024 * 1024))
        with open('/proc/meminfo', encoding='ascii') as handle:
            for line in handle:
                if line.startswith('MemAvailable:'):
                    return int(line.split()[1]) // 1024
    except (OSError, ValueError, AttributeError, ImportError):
        return None
    return None


def process_alive(pid) -> bool:
    """Whether a process id still names a running process. Unknown counts as alive."""
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return True
    if pid <= 0:
        return False
    if os.name == 'nt':
        try:
            import ctypes
            handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)      # QUERY_LIMITED_INFORMATION
            if not handle:
                return False
            code = ctypes.c_ulong()
            ok = ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
            ctypes.windll.kernel32.CloseHandle(handle)
            return bool(ok) and code.value == 259                                # STILL_ACTIVE
        except (OSError, AttributeError, ImportError):
            return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return True


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
