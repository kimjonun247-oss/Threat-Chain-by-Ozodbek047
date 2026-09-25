"""Summary rows for a run folder, without re-parsing every report each time.

Listing 30 rows used to mean opening and parsing every report in the folder.
Measured before this module: dependencies 84 ms over 86 reports, and
portfolio.overview() 89 ms because it calls six such listings. The cost grows
linearly with the number of scans ever run, so an installation used for a year
would spend most of a dashboard load re-reading history.

The cache is *only* a cache. Three rules keep it from becoming a second source
of truth that can drift:

  1. A report is never served from it. Only the small summary rows a listing
     needs are cached; `read()` still opens the report file.
  2. An entry is used only while the report's size and mtime match what was
     recorded. Any edit, any rewrite, and that entry is re-read.
  3. A missing, unreadable or malformed cache is not an error. The folder is
     read directly and the cache is rebuilt, so deleting index.json is always a
     safe repair.
"""
import json
import os
import re

CACHE_NAME = 'index.json'
# Every scanner names its runs the same way; one definition keeps a report id
# that one module accepts from being rejected by another.
RUN_ID = re.compile(r'^\d{8}T\d{6}-[a-f0-9]{8}$')


def read(runs, rid, missing):
    """One run's report, shared by every scanner module.

    Five modules carried a copy of this that differed only in the wording of
    `missing`. The id is validated before any path is built from it, so a
    request can never name a file outside `runs`.
    """
    from . import repo_store
    if not isinstance(rid, str) or not RUN_ID.fullmatch(rid):
        raise ValueError('Hisobot ID noto‘g‘ri.')
    try:
        return repo_store.read_json(runs / rid / 'report.json')
    except (OSError, ValueError):
        raise ValueError(missing) from None


def _load(path):
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return {}
    return data.get('entries') or {} if isinstance(data, dict) else {}


def _save(path, entries):
    """Write atomically; a cache that cannot be written is not worth an error."""
    try:
        temporary = path.with_suffix('.tmp')
        temporary.write_text(json.dumps({'version': 1, 'entries': entries}, ensure_ascii=False),
                             encoding='utf-8')
        os.replace(temporary, path)
    except OSError:
        pass


def rows(runs, fields, read, limit=30, report_name='report.json', flat=False):
    """Newest-first summary rows for every run in `runs`.

    `read(id)` returns the full report and is called only for entries the cache
    cannot answer. `flat` selects folders whose reports sit directly in `runs`
    as `<id>.json` rather than in `<id>/report.json`.
    """
    if not runs.is_dir():
        return []
    cache = _load(runs / CACHE_NAME)
    fresh = {}
    result = []
    changed = False
    for path in sorted(runs.iterdir(), reverse=True):
        identifier = path.stem if flat else path.name
        report_file = path if flat else path / report_name
        if flat and path.suffix != '.json':
            continue
        if flat and path.name == CACHE_NAME:
            continue
        try:
            stat = report_file.stat()
        except OSError:
            continue
        stamp = [int(stat.st_mtime_ns), stat.st_size]
        entry = cache.get(identifier)
        if isinstance(entry, dict) and entry.get('stamp') == stamp and isinstance(entry.get('row'), dict):
            row = entry['row']
        else:
            try:
                report = read(identifier)
            except (ValueError, OSError, KeyError):
                continue
            row = {key: report.get(key) for key in fields}
            changed = True
        fresh[identifier] = {'stamp': stamp, 'row': row}
        result.append(row)
    if changed or len(fresh) != len(cache):
        _save(runs / CACHE_NAME, fresh)
    return sorted(result, key=lambda row: row.get('created_at') or '', reverse=True)[:limit]
