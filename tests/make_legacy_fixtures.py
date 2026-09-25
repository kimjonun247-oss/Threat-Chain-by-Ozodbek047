"""Regenerate tests/fixtures/legacy/ from the real evidence folders.

Not a test (the name does not match unittest discovery). Run by hand when a new
report format ships and the frozen set should gain a sample:

    python3 tests/make_legacy_fixtures.py

Why real reports and not hand-written ones: the shapes these fixtures protect
were produced by five scanners over two weeks of real scans, and a hand-written
sample would only ever contain the fields whoever wrote it remembered. The
oldest and the newest report of every stage are taken, because the oldest is the
one most likely to be missing a field that later code assumes is always there.

Three reports per stage are frozen: the oldest, the newest, and the one with the
most findings -- because the first two were often empty, and an export path that
is only ever run over a report with no findings is not really being tested.

Reports are copied with three changes, all recorded in MANIFEST.json:
  - long arrays are cut to the first few entries (an image report is 93 KB and
    7424 findings; its *shape* is what matters here, not its length),
  - absolute paths and owner names are replaced,
  - nothing else. Key names, types and nesting are untouched, which is the whole
    point of the fixture.
"""
import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'tests/fixtures/legacy'
# stage -> (evidence folder, report file inside each run folder or None when flat)
SOURCES = {
    'code': ('scanner-runs', 'report.json'),
    'dependencies': ('dependency-runs', 'report.json'),
    'images': ('image-runs', 'report.json'),
    'web': ('web-runs', 'report.json'),
    'assessment': ('assessment-runs', 'report.json'),
    'repository': ('repository-runs', None),
    'iac': ('iac-runs', 'report.json'),
}
KEEP = 3
# Only these lists are cut. Cutting anything else broke the fixtures once: the
# repository report's `evidence` list is referenced by id from every finding, so
# a shortened copy made repository.sarif() raise KeyError on a report that is
# perfectly valid in production. A fixture that cannot survive its own consumers
# tests nothing, so referential lists stay whole and only the genuinely long,
# self-contained ones (an image report carries 7424 findings) are shortened.
LONG_LISTS = {'findings', 'packages', 'coverage', 'gaps', 'errors', 'suppressed'}
HOME = re.compile(r'/Users/[^/"\\ ]+')
OWNER_KEYS = {'owner', 'authorized_by', 'registered_by'}


def trim(value, key=None):
    """Shorten the long self-contained lists, redact paths and owner names.

    Key names, types and nesting are never touched -- that is what the fixture
    exists to freeze.
    """
    if isinstance(value, dict):
        return {k: ('redacted' if k in OWNER_KEYS and isinstance(v, str) and v.strip() else trim(v, k))
                for k, v in value.items()}
    if isinstance(value, list):
        items = value[:KEEP] if key in LONG_LISTS else value
        return [trim(item, key) for item in items]
    if isinstance(value, str):
        return HOME.sub('/redacted/home', value)
    return value


def runs(folder, name):
    base = ROOT / folder
    if name is None:
        return sorted(p for p in base.glob('*.json') if p.name != 'index.json')
    return sorted(p / name for p in sorted(base.iterdir()) if p.is_dir() and (p / name).is_file())


def main():
    parser = argparse.ArgumentParser(description='Muzlatilgan namunalarni qayta yaratish')
    # Without --only, every stage is re-frozen and the "newest" samples move
    # forward to whatever was scanned last. That is usually not what you want:
    # an older "newest" is a sample of a format an earlier release produced.
    parser.add_argument('--only', action='append', choices=sorted(SOURCES),
                        help='Faqat shu bosqich(lar)ni qayta yaratish')
    args = parser.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    manifest = {}
    manifest_path = OUT / 'MANIFEST.json'
    if args.only and manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    for stage, (folder, name) in SOURCES.items():
        if args.only and stage not in args.only:
            continue
        found = runs(folder, name)
        if not found:
            print(f'{stage}: {folder} bo‘sh — o‘tkazib yuborildi', file=sys.stderr)
            continue
        richest = max(found, key=lambda p: len(json.loads(p.read_text(encoding='utf-8')).get('findings') or []))
        chosen = {'oldest': found[0], 'newest': found[-1]}
        if richest not in chosen.values():
            chosen['richest'] = richest
        for label, path in chosen.items():
            original = json.loads(path.read_text(encoding='utf-8'))
            target = OUT / f'{stage}-{label}.json'
            target.write_text(json.dumps(trim(original), ensure_ascii=False, indent=1) + '\n', encoding='utf-8')
            manifest[target.name] = {
                'stage': stage, 'source': path.relative_to(ROOT).as_posix(),
                'report_id': original.get('id'), 'created_at': original.get('created_at'),
                'state': original.get('state'),
                'changes': [f'{sorted(LONG_LISTS)} lists cut to {KEEP} entries',
                            'absolute home paths replaced', 'owner names replaced'],
            }
            print(f'{target.name} <- {path.relative_to(ROOT)}')
    manifest_path.write_text(json.dumps(dict(sorted(manifest.items())), ensure_ascii=False, indent=1) + '\n',
                             encoding='utf-8')


if __name__ == '__main__':
    main()
