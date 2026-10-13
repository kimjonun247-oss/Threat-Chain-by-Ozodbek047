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
from pathlib import Path

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


# ---- status sidecar ----------------------------------------------------------
# A progress poll needs a state and a sentence. It used to parse the whole
# report to get them -- 2.2 s for a 46 MB report, every few seconds, for every
# open browser tab, and every 0.4 s from the pipeline itself. The few fields a
# poll reads are written beside the report on every write; a missing or
# unreadable sidecar simply sends the caller back to the report.
STATUS_NAME = 'status.json'
STATUS_KEYS = ('id', 'target', 'state', 'progress', 'count', 'message', 'created_at', 'finished_at', 'pid')
ACTIVE_STATES = ('queued', 'running')


def write_status(folder, report):
    view = {key: report[key] for key in STATUS_KEYS if key in report}
    if isinstance(report.get('stages'), list):
        view['stages'] = [{key: stage.get(key) for key in ('kind', 'target', 'state', 'count')}
                          for stage in report['stages'] if isinstance(stage, dict)]
    try:
        temporary = folder / (STATUS_NAME + '.tmp')
        temporary.write_text(json.dumps(view, ensure_ascii=False), encoding='utf-8')
        os.replace(temporary, folder / STATUS_NAME)
    except OSError:
        pass


def status(runs, rid):
    """The sidecar of one run, or None when there is none to trust."""
    if not isinstance(rid, str) or not RUN_ID.fullmatch(rid):
        return None
    try:
        view = json.loads((runs / rid / STATUS_NAME).read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return None
    return view if isinstance(view, dict) and view.get('id') == rid and 'state' in view else None


# ---- page view ---------------------------------------------------------------
# A report screen shows a table that pages 25 rows at a time, and to draw it the
# browser was sent the whole report: 55 MB for 50 000 findings, parsed by the
# server (2.6 s) and again by the page. A report over VIEW_LIMIT findings now
# also gets `view.json`: the same report with its worst VIEW_LIMIT findings and
# the true total. The screen reads that; the full report is still what a
# download, an export, a comparison and the findings board read.
VIEW_NAME = 'view.json'
VIEW_LIMIT = 2000
_VIEW_RANK = {'CRITICAL': 0, 'HIGH': 1, 'ERROR': 1, 'MEDIUM': 2, 'WARNING': 2, 'LOW': 3, 'INFO': 3, 'NOTE': 3}


def write_view(folder, report):
    target = folder / VIEW_NAME
    findings = report.get('findings')
    try:
        if not isinstance(findings, list) or len(findings) <= VIEW_LIMIT:
            if target.exists():
                target.unlink()
            return
        worst = sorted(range(len(findings)), key=lambda n: (
            _VIEW_RANK.get(str(findings[n].get('severity') or findings[n].get('level') or '').upper(), 4), n))
        view = {**report, 'findings': [findings[n] for n in worst[:VIEW_LIMIT]],
                'findings_total': len(findings), 'findings_shown': VIEW_LIMIT}
        temporary = folder / (VIEW_NAME + '.tmp')
        temporary.write_text(json.dumps(view, ensure_ascii=False), encoding='utf-8')
        os.replace(temporary, target)
    except (OSError, AttributeError, TypeError):
        pass


def view(runs, rid):
    """The page view of a large report, or None (small report, or none written)."""
    if not isinstance(rid, str) or not RUN_ID.fullmatch(rid):
        return None
    try:
        data = json.loads((runs / rid / VIEW_NAME).read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) and data.get('id') == rid else None


# ---- comparison view ---------------------------------------------------------
# "What changed since the last scan" needs each finding's identity and a few
# words about it, not its evidence. Comparing two 50 000-finding reports parsed
# 92 MB to use a fraction of it (3.7 s). A large report also gets `compare.json`:
# every finding, reduced to the fields a comparison reads.
COMPARE_NAME = 'compare.json'
COMPARE_KEYS = ('fingerprint', 'rule_id', 'advisory_id', 'severity', 'level', 'package', 'path', 'service_id', 'title')


def write_compare(folder, report):
    target = folder / COMPARE_NAME
    findings = report.get('findings')
    try:
        if not isinstance(findings, list) or len(findings) <= VIEW_LIMIT:
            if target.exists():
                target.unlink()
            return
        slim = []
        for finding in findings:
            row = {key: finding[key] for key in COMPARE_KEYS if finding.get(key) is not None}
            if 'title' not in row and finding.get('message'):
                row['message'] = str(finding['message'])[:300]
            slim.append(row)
        temporary = folder / (COMPARE_NAME + '.tmp')
        temporary.write_text(json.dumps({**report, 'findings': slim}, ensure_ascii=False), encoding='utf-8')
        os.replace(temporary, target)
    except (OSError, AttributeError, TypeError, KeyError):
        pass


def compare_view(runs, rid):
    """The comparison view of a large report, or None."""
    if not isinstance(rid, str) or not RUN_ID.fullmatch(rid):
        return None
    try:
        data = json.loads((runs / rid / COMPARE_NAME).read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) and data.get('id') == rid else None


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


# ---- SQLite index ------------------------------------------------------------
# Measured on a synthetic year of use (60 projects, 6000 reports): the JSON
# cache still stat()ed every report and re-sorted the whole folder on every
# listing -- one dashboard request made 19 listings, 22 000 stat calls, ~380 ms,
# growing linearly with history. The rows now live in `index.sqlite3` inside
# the run folder (so a test's temporary folder gets its own, and deleting the
# file is always a safe repair) and a listing is one ordered, limited query.
# It stays a cache under the same three rules:
#   - new or removed runs are found by listing the folder's names (one scandir,
#     no per-report stat); write_json() drops the row of any report it rewrites,
#     from any process, so it is read again; and every row a normal listing
#     returns is still re-checked against its file's size and mtime;
#   - the first listing of a folder in each process re-checks every row, which
#     catches edits made while nothing was running;
#   - any SQLite problem falls back to the JSON cache below. Nothing breaks.
# A connection is opened per call and closed: nothing stays locked (Windows
# cannot delete an open file) and no server thread leaks a handle.
import sqlite3

DB_NAME = 'index.sqlite3'
VERIFY_LIMIT = 500           # listings up to this size re-check every returned row
_VERIFIED = set()            # (folder, scope) fully re-checked in this process


def _connect(runs):
    connection = sqlite3.connect(str(runs / DB_NAME), timeout=10, isolation_level=None)
    try:
        if connection.execute('PRAGMA user_version').fetchone()[0] != 1:
            connection.execute('CREATE TABLE IF NOT EXISTS runs (scope TEXT, id TEXT, created_at TEXT,'
                               ' mtime_ns INTEGER, size INTEGER, row TEXT, PRIMARY KEY (scope, id))')
            connection.execute('CREATE INDEX IF NOT EXISTS runs_order ON runs (scope, created_at)')
            connection.execute('PRAGMA user_version = 1')
    except BaseException:
        connection.close()
        raise
    return connection


def _file(runs, identifier, report_name, flat):
    return runs / (identifier + '.json') if flat else runs / identifier / report_name


def _identifiers(runs, flat):
    names = set()
    with os.scandir(runs) as entries:
        for entry in entries:
            if flat:
                if entry.name.endswith('.json') and entry.name != CACHE_NAME:
                    names.add(entry.name[:-5])
            elif entry.is_dir():
                names.add(entry.name)
    return names


def _store(connection, scope, identifier, stat, row):
    connection.execute('INSERT OR REPLACE INTO runs VALUES (?,?,?,?,?,?)',
                       (scope, identifier, row.get('created_at') or '', stat.st_mtime_ns, stat.st_size,
                        json.dumps(row, ensure_ascii=False)))


def _refresh(connection, scope, runs, identifier, fields, read, report_name, flat):
    connection.execute('DELETE FROM runs WHERE scope=? AND id=?', (scope, identifier))
    try:
        stat = _file(runs, identifier, report_name, flat).stat()
        report = read(identifier)
    except (ValueError, OSError, KeyError):
        return None             # unreadable: not listed, retried next time
    row = {key: report.get(key) for key in fields}
    _store(connection, scope, identifier, stat, row)
    return row


def _sync(connection, scope, runs, fields, read, report_name, flat):
    """Add new runs, drop removed ones and, once per process, re-check every row."""
    key = (str(runs), scope)
    full = key not in _VERIFIED
    on_disk = _identifiers(runs, flat)
    indexed = {row[0]: (row[1], row[2]) for row in
               connection.execute('SELECT id, mtime_ns, size FROM runs WHERE scope=?', (scope,))}
    work = [identifier for identifier in on_disk if full or identifier not in indexed]
    gone = set(indexed) - on_disk
    if not work and not gone:
        return
    connection.execute('BEGIN IMMEDIATE')
    try:
        for identifier in gone:
            connection.execute('DELETE FROM runs WHERE scope=? AND id=?', (scope, identifier))
        for identifier in work:
            stamp = indexed.get(identifier)
            if stamp is not None:
                try:
                    stat = _file(runs, identifier, report_name, flat).stat()
                except OSError:
                    stat = None
                if stat is not None and (stat.st_mtime_ns, stat.st_size) == stamp:
                    continue
            _refresh(connection, scope, runs, identifier, fields, read, report_name, flat)
        connection.execute('COMMIT')
    except BaseException:
        connection.execute('ROLLBACK')
        raise
    _VERIFIED.add(key)


def _rows_sqlite(runs, fields, read, limit, report_name, flat):
    scope = ','.join(fields)
    connection = _connect(runs)
    try:
        _sync(connection, scope, runs, fields, read, report_name, flat)
        selected = connection.execute('SELECT id, mtime_ns, size, row FROM runs WHERE scope=? '
                                      'ORDER BY created_at DESC, id DESC LIMIT ?',
                                      (scope, max(0, int(limit)))).fetchall()
        result = []
        for identifier, mtime_ns, size, raw in selected:
            row = json.loads(raw)
            if len(selected) <= VERIFY_LIMIT:
                # A report rewritten by something that bypassed write_json().
                try:
                    stat = _file(runs, identifier, report_name, flat).stat()
                    fresh = (stat.st_mtime_ns, stat.st_size) == (mtime_ns, size)
                except OSError:
                    fresh = False
                if not fresh:
                    row = _refresh(connection, scope, runs, identifier, fields, read, report_name, flat)
                    if row is None:
                        continue
            result.append(row)
    finally:
        connection.close()
    return sorted(result, key=lambda row: row.get('created_at') or '', reverse=True)


def written(path, value=None):
    """write_json() hook: forget the index row of a report that was just written.

    The row is not built here from `value`: only the module's own read() knows
    which files are reports (repository-runs also holds reviews.json) and what a
    report looks like once read. Dropping the row makes the next listing, in any
    process, find the id unindexed and read it again. It works across processes
    because it acts on the folder's index file, not on anything held in memory:
    a CLI scan that turns a report from `running` into `completed` is seen by the
    server's next listing, however long that listing is.
    """
    path = Path(path)
    for runs, identifier in ((path.parent.parent, path.parent.name), (path.parent, path.stem)):
        database = runs / DB_NAME
        if not database.is_file():
            continue
        try:
            connection = sqlite3.connect(str(database), timeout=10, isolation_level=None)
            try:
                connection.execute('DELETE FROM runs WHERE id=?', (identifier,))
            finally:
                connection.close()
        except sqlite3.Error:
            pass            # the per-row stamp check and the per-process full check remain


def rows(runs, fields, read, limit=30, report_name='report.json', flat=False):
    """Newest-first summary rows for every run in `runs`.

    `read(id)` returns the full report and is called only for entries the index
    cannot answer. `flat` selects folders whose reports sit directly in `runs`
    as `<id>.json` rather than in `<id>/report.json`.
    """
    if not runs.is_dir():
        return []
    try:
        return _rows_sqlite(runs, fields, read, limit, report_name, flat)
    except sqlite3.DatabaseError:
        # A damaged index file: remove it and rebuild once; it holds nothing else.
        try:
            os.remove(runs / DB_NAME)
            return _rows_sqlite(runs, fields, read, limit, report_name, flat)
        except (sqlite3.Error, OSError):
            pass
    except OSError:
        pass
    return _rows_json(runs, fields, read, limit, report_name, flat)


def _rows_json(runs, fields, read, limit=30, report_name='report.json', flat=False):
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
