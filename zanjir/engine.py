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


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
