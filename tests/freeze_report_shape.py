"""Re-freeze tests/fixtures/shape-snapshot.json after an intentional shape change.

Run this only when a report format change is deliberate, and say in the commit
which field moved and why. Adding a field never needs this script -- the guard
only fails on a lost or retyped key.

    python3 tests/freeze_report_shape.py
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'tests')]

from test_report_shape import SNAPSHOT, document_shape, fixtures  # noqa: E402


def main():
    snapshot = {path.name: document_shape(json.loads(path.read_text(encoding='utf-8'))) for path in fixtures()}
    SNAPSHOT.write_text(json.dumps(snapshot, ensure_ascii=False, indent=1, sort_keys=True) + '\n', encoding='utf-8')
    print(f'{SNAPSHOT.relative_to(ROOT)}: {len(snapshot)} namuna muzlatildi')


if __name__ == '__main__':
    main()
