"""The findings board as a table on disk instead of a list in memory.

Measured before this module, with three projects of 50 000 findings each: the
board was rebuilt by parsing every report into one Python list -- 10.8 s and
520 MB -- and then every search filtered, sorted and counted that list in
Python. It was rebuilt whenever anything changed anywhere.

Here the same rows live in one SQLite table, and three things follow:

  1. **Only what changed is read.** Each (stage, target) remembers which report
     its rows came from. A new scan of one project replaces that project's rows;
     the other reports are not opened.
  2. **A search is a query.** Filtering, ordering, paging and the facet counts
     are done by SQLite over indexed columns; the server holds one page of rows.
  3. **A triage decision updates rows, it does not rebuild them.** The stored
     finding is re-decorated from the decision file; no report is re-read.

The table is a cache and nothing else. By default it lives in a temporary
folder for the life of the process. The server keeps it in its data directory
instead (persist()), so a restart finds the rows already there and only checks
which reports changed -- building them from nothing took 20 s for 150 000 rows.
A file written by another version of this module is discarded and rebuilt, and
deleting it is always safe.

The honesty rules of findings_index.py are unchanged, because the rows are made
by its own row() and the coverage list by the same walk as before.
"""
import atexit
import json
import shutil
import sqlite3
import tempfile
import threading
import time
from pathlib import Path

from . import triage

# What a search filters, orders and counts by. The two JSON documents of a row
# -- what the API returns and the scanner's original finding -- are kept in a
# table of their own: with them inline every count and every sort dragged a
# kilobyte per row through the cache (6.7 s for a filtered search of 150 000
# rows); kept apart, those queries touch only these narrow columns.
COLUMNS = ('stage', 'target', 'fingerprint', 'project', 'report_id', 'rule_id', 'severity_scale', 'owasp',
           'status', 'open', 'known_exploited', 'verified', 'duplicate_of', 'escalates', 'first_seen',
           'sla_due', 'rank', 'priority', 'haystack', 'snapshot')
RANK = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}


def priority(item):
    """Order within one severity: 0 first, 7 last. Three yes/no questions, most important first:

      4  not known to be reachable from outside (a chain or a web finding is)
      2  not in shipped code (test, docs, example, generated, vendored)
      1  no fixed version to move to (a dependency or image CVE without a fix;
         a code finding counts as fixable -- the fix is a code change)

    Severity still decides first: a CRITICAL in a test file is above a HIGH in
    shipped code, but below every CRITICAL in shipped code. Documented in
    BETA_READINESS.md ("Ustuvorlik tartibi").
    """
    fixable = bool(item.get('fixed_version')) or item.get('stage') not in ('dependencies', 'images')
    return ((0 if item.get('reachable') else 4) + (0 if (item.get('path_class') or 'prod') == 'prod' else 2)
            + (0 if fixable else 1))
SYNC_TTL = 4.0
FORMAT = 4                              # bump when the tables or the stored rows change shape
_STATE = {'folder': None, 'file': None, 'at': 0.0, 'force': True}
_LOCK = threading.RLock()
# One encoder for every stored document: json.dumps() with non-default options
# builds a new encoder per call, which was a quarter of the time a build took.
ENCODE = json.JSONEncoder(ensure_ascii=False, separators=(',', ':')).encode


def _path():
    if _STATE['file'] is not None:
        return _STATE['file']
    if _STATE['folder'] is None:
        folder = Path(tempfile.mkdtemp(prefix='threatchain-board-'))
        atexit.register(shutil.rmtree, folder, True)
        _STATE['folder'] = folder
    return _STATE['folder'] / 'board.sqlite3'


def persist(path):
    """Keep the table in `path` across restarts (the server calls this once).

    What is already there is trusted only as far as its own bookkeeping goes:
    the next search still compares every target's report id and decision file
    with what the rows were built from.
    """
    path = Path(path)
    with _LOCK:
        usable = False
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.is_file():
                db = sqlite3.connect(str(path), timeout=30)
                try:
                    usable = db.execute('PRAGMA user_version').fetchone()[0] == FORMAT
                finally:
                    db.close()
                if not usable:
                    path.unlink()
        except (OSError, sqlite3.Error):
            try:
                path.unlink()
            except OSError:
                return False                # cannot use this location: stay in the temporary folder
            usable = False
        _STATE.update(file=path, force=not usable, at=0.0)
    return True


def connect():
    db = sqlite3.connect(str(_path()), timeout=30, isolation_level=None)
    db.execute('PRAGMA journal_mode=MEMORY')
    db.execute('PRAGMA synchronous=OFF')
    db.execute('PRAGMA cache_size=-65536')              # 64 MB of pages, not the 2 MB default
    db.execute('PRAGMA temp_store=MEMORY')
    db.execute('CREATE TABLE IF NOT EXISTS rows (id INTEGER PRIMARY KEY, stage TEXT, target TEXT, fingerprint TEXT,'
               ' project TEXT, report_id TEXT, rule_id TEXT, severity_scale TEXT, owasp TEXT, status TEXT,'
               ' open INTEGER, known_exploited INTEGER, verified INTEGER, duplicate_of TEXT, escalates TEXT,'
               ' first_seen TEXT, sla_due REAL, rank INTEGER, priority INTEGER, haystack TEXT, snapshot TEXT)')
    db.execute('CREATE TABLE IF NOT EXISTS payload (id INTEGER PRIMARY KEY, data TEXT, finding TEXT)')
    db.execute('CREATE TABLE IF NOT EXISTS sources (stage TEXT, target TEXT, version TEXT, scope TEXT,'
               ' decisions TEXT, coverage TEXT, truncated TEXT, PRIMARY KEY (stage, target))')
    db.execute('CREATE INDEX IF NOT EXISTS rows_pair ON rows (stage, target)')
    db.execute('CREATE INDEX IF NOT EXISTS rows_fingerprint ON rows (fingerprint)')
    db.execute('CREATE INDEX IF NOT EXISTS rows_duplicate ON rows (duplicate_of) WHERE duplicate_of IS NOT NULL')
    db.execute('CREATE INDEX IF NOT EXISTS rows_escalates ON rows (escalates) WHERE escalates IS NOT NULL')
    db.execute(f'PRAGMA user_version = {FORMAT}')
    return db


def remove(db, where, values):
    '''Delete rows and their payloads.'''
    db.execute('DELETE FROM payload WHERE id IN (SELECT id FROM rows WHERE ' + where + ')', values)
    db.execute('DELETE FROM rows WHERE ' + where, values)


def epoch(value):
    moment = triage.parse_time(value)
    return moment.timestamp() if moment is not None else None


def record(item, finding, snapshot):
    """One board row as the tuple of COLUMNS."""
    sla = item.get('sla') or {}
    haystack = ' '.join(str(item.get(key) or '') for key in
                        ('rule_id', 'title', 'subject', 'target', 'project', 'advisory_id', 'tool')).lower()
    kev = item.get('known_exploited')
    return (item['stage'], item['target'], item.get('fingerprint'), item.get('project') or '', item.get('report_id'),
            item.get('rule_id') or '', item.get('severity_scale'), '|' + '|'.join(item.get('owasp') or []) + '|',
            item.get('status'), 1 if item.get('open', True) else 0, None if kev is None else int(bool(kev)),
            int(bool(item.get('verified'))), item.get('duplicate_of'), item.get('escalates'),
            item.get('first_seen'), epoch(sla.get('due')), RANK.get(item.get('severity_scale'), 4), priority(item), haystack,
            snapshot, ENCODE(item), ENCODE(finding))


def insert(db, records):
    '''records: tuples of COLUMNS followed by the two JSON documents.'''
    width = len(COLUMNS)
    statement = 'INSERT INTO rows (id, ' + ', '.join(COLUMNS) + ') VALUES (' + ', '.join('?' * (width + 1)) + ')'
    identifier = db.execute('SELECT COALESCE(MAX(id), 0) FROM rows').fetchone()[0]
    narrow, wide = [], []
    for values in records:
        identifier += 1
        narrow.append((identifier, *values[:width]))
        wide.append((identifier, values[width], values[width + 1]))
        if len(narrow) >= 5000:
            db.executemany(statement, narrow)
            db.executemany('INSERT INTO payload VALUES (?,?,?)', wide)
            narrow, wide = [], []
    if narrow:
        db.executemany(statement, narrow)
        db.executemany('INSERT INTO payload VALUES (?,?,?)', wide)


def decisions_stamp(scope):
    """When the decision file of a scope last changed, as a comparable string."""
    try:
        info = (triage.folder(scope) / 'decisions.json').stat()
        return f'{info.st_mtime_ns}:{info.st_size}'
    except (OSError, ValueError):
        return ''


def forget():
    """Rebuild everything on the next search (a reset, or a test's new world)."""
    with _LOCK:
        _STATE.update(force=True, at=0.0)


def sync(index):
    """Bring the table in line with the reports. `index` is findings_index, whose
    sources(), registered(), row(), project_of() and chain_rows() define the board."""
    with _LOCK:
        force = _STATE['force']
        if not force and time.monotonic() - _STATE['at'] < SYNC_TTL:
            return
        db = connect()
        try:
            db.execute('BEGIN IMMEDIATE')
            try:
                _sync(db, index, force)
                db.execute('COMMIT')
            except BaseException:
                db.execute('ROLLBACK')
                raise
        finally:
            db.close()
        _STATE.update(force=False, at=time.monotonic())


def _sync(db, index, force):
    if force:
        db.execute('DELETE FROM rows')
        db.execute('DELETE FROM payload')
        db.execute('DELETE FROM sources')
    stored = {(stage, target): (version, scope, decisions) for stage, target, version, scope, decisions in
              db.execute('SELECT stage, target, version, scope, decisions FROM sources')}
    wanted = set()
    for stage, (read, history, field) in index.sources().items():
        try:
            listed = history(10 ** 6)
        except (OSError, ValueError):
            listed = []
        newest, last_attempt = {}, {}
        for entry in listed:                      # newest first
            target = entry.get(field) or entry.get('target')
            state = entry.get('state', 'completed' if stage == 'repository' else None)
            if not target:
                continue
            if target not in last_attempt:
                last_attempt[target] = {**entry, 'state': state}
            if target not in newest and state in index.USABLE:
                newest[target] = entry
        for target in sorted(index.registered(stage)):
            pair = (stage, target)
            wanted.add(pair)
            entry = newest.get(target)
            last = last_attempt.get(target)
            version = json.dumps([entry.get('id') if entry else None, (last or {}).get('id'), (last or {}).get('state')])
            old = stored.get(pair)
            if old is not None and old[0] == version:
                _refresh_triage(db, pair, old[1], old[2])
                continue
            remove(db, 'stage=? AND target=?', pair)
            if entry is None:
                # A scan that ran and concluded is not an unscanned target, and a
                # scan that failed is not one either -- each gets its own word.
                concluded = last is not None and last.get('state') in index.CONCLUDED
                coverage = {'stage': stage, 'target': target, 'scanned': concluded,
                            'state': (last or {}).get('state'), 'report_id': (last or {}).get('id'),
                            'outcome': ('concluded_no_findings' if concluded else
                                        'incomplete' if last is not None else 'never_scanned'),
                            'findings': 0}
                _remember(db, pair, version, '', '', coverage)
                continue
            try:
                report = read(entry['id'])
            except (OSError, ValueError):
                db.execute('DELETE FROM sources WHERE stage=? AND target=?', pair)
                continue
            project = index.project_of(stage, target)
            snapshot = report.get('input_sha256')
            found = report.get('findings') or []
            insert(db, (record(index.row(stage, report, finding, project), finding, snapshot) for finding in found))
            coverage = {'stage': stage, 'target': target, 'scanned': True,
                        'state': report.get('state', 'completed'), 'report_id': report.get('id'),
                        'created_at': report.get('created_at'), 'findings': len(found)}
            _remember(db, pair, version, project, decisions_stamp(project) if project else '', coverage)
        if stage == 'repository':
            _sync_chains(db, index, force, stored, wanted)
    for stage, target in set(stored) - wanted:
        remove(db, 'stage=? AND target=?', (stage, target))
        db.execute('DELETE FROM sources WHERE stage=? AND target=?', (stage, target))


def _remember(db, pair, version, scope, decisions, coverage):
    db.execute('INSERT OR REPLACE INTO sources VALUES (?,?,?,?,?,?,?)',
               (*pair, version, scope, decisions, json.dumps(coverage, ensure_ascii=False) if coverage else None, None))


CHAIN_PAIR = ('chain', '*')


def _sync_chains(db, index, force, stored, wanted):
    """Chain findings belong to the newest assessment that produced any."""
    wanted.add(CHAIN_PAIR)
    try:
        from . import pipeline
        version = json.dumps([[row.get('id'), row.get('state')] for row in pipeline.history(limit=30)])
    except (OSError, ValueError):
        version = '[]'
    old = stored.get(CHAIN_PAIR)
    if old is not None and old[0] == version and not force:
        return
    remove(db, 'stage=?', ('chain',))
    rows = index.chain_rows('repository')
    insert(db, (record(item, None, None) for item in rows))
    _remember(db, CHAIN_PAIR, version, '', '', None)


def _refresh_triage(db, pair, scope, known):
    """Re-decorate one target's rows when its project's decisions changed on disk."""
    if not scope:
        return
    current = decisions_stamp(scope)
    if current == (known or ''):
        return
    redecorate(db, scope, pair=pair)
    db.execute('UPDATE sources SET decisions=? WHERE stage=? AND target=?', (current, *pair))


def redecorate(db, scope, pair=None, fingerprints=None):
    """Apply the stored decisions of `scope` to rows already in the table.

    The stored finding is everything triage.decorate() needs, so a decision
    reaches the board without the report it concerns being read again.
    """
    try:
        data = triage.read(scope)
    except (OSError, ValueError):
        return 0
    where, values = ['project=?'], [scope]
    if pair is not None:
        where += ['stage=?', 'target=?']
        values += list(pair)
    if fingerprints is not None:
        prints = list(fingerprints)
        if not prints:
            return 0
        where.append('fingerprint IN (' + ', '.join('?' * len(prints)) + ')')
        values += prints
    changed = 0
    for identifier, snapshot, raw, original in db.execute(
            'SELECT rows.id, snapshot, data, finding FROM rows JOIN payload ON payload.id=rows.id WHERE '
            + ' AND '.join(where), values).fetchall():
        item, finding = json.loads(raw), json.loads(original)
        if not isinstance(finding, dict):
            continue                    # a chain row: it has no stage report of its own
        view = triage.decorate({**finding, '_snapshot': snapshot}, data) or {}
        item.update(status=view.get('status'), owner=view.get('owner'), open=view.get('open', True),
                    suppressed=bool(view.get('suppressed')), stale=bool(view.get('stale')),
                    first_seen=view.get('first_seen'), last_seen=view.get('last_seen'), sla=view.get('sla'),
                    overdue=bool((view.get('sla') or {}).get('overdue')))
        db.execute('UPDATE rows SET status=?, open=?, first_seen=?, sla_due=? WHERE id=?',
                   (item['status'], 1 if item['open'] else 0, item['first_seen'], epoch((item['sla'] or {}).get('due')),
                    identifier))
        db.execute('UPDATE payload SET data=? WHERE id=?', (ENCODE(item), identifier))
        changed += 1
    return changed


def decided(scope, fingerprints):
    """A decision was just stored in this process: update its rows now."""
    with _LOCK:
        if _STATE['force'] or (_STATE['folder'] is None and _STATE['file'] is None):
            return                      # nothing built yet; the next sync reads it all
        db = connect()
        try:
            db.execute('BEGIN IMMEDIATE')
            try:
                redecorate(db, scope, fingerprints=fingerprints)
                db.execute('UPDATE sources SET decisions=? WHERE scope=?', (decisions_stamp(scope), scope))
                db.execute('COMMIT')
            except BaseException:
                db.execute('ROLLBACK')
                raise
        finally:
            db.close()


# -- queries ---------------------------------------------------------------------

def like(word):
    return '%' + word.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_') + '%'


def conditions(query, filters, now, skip=None):
    """(sql, values) for a text query and the board's filters, minus one of them."""
    where, values = [], []
    for word in (query or '').lower().split():
        where.append("haystack LIKE ? ESCAPE '\\'")
        values.append(like(word))
    for key, value in (filters or {}).items():
        if not value or key == skip:
            continue
        if key in ('stage', 'project', 'target'):
            where.append(f'{key}=?')
            values.append(value)
        elif key == 'severity':
            where.append('severity_scale IS NULL' if value == 'UNRATED' else 'severity_scale=?')
            values += [] if value == 'UNRATED' else [value]
        elif key == 'owasp':
            where.append("owasp LIKE ? ESCAPE '\\'")
            values.append(like('|' + value + '|'))
        elif key == 'status':
            where.append('status IS NULL' if value == 'untriaged' else 'status=?')
            values += [] if value == 'untriaged' else [value]
        elif key == 'state':
            clause = {'open': 'open=1', 'closed': 'open=0', 'kev': 'known_exploited=1', 'verified': 'verified=1',
                      'duplicate': "duplicate_of IS NOT NULL AND duplicate_of<>''",
                      'overdue': 'open=1 AND sla_due IS NOT NULL AND sla_due<?'}.get(value)
            if clause:
                where.append('(' + clause + ')')
                values += [now] if value == 'overdue' else []
    return (' WHERE ' + ' AND '.join(where)) if where else '', values


def present(raw, now_moment):
    """A stored row as the API returns it: the SLA is a date, so "overdue" is
    worked out when the row is read, not when it was stored."""
    item = json.loads(raw)
    if item.get('open', True) and item.get('sla'):
        item['sla'] = triage.sla(item.get('severity_scale'), item.get('first_seen'), now_moment)
        item['overdue'] = bool((item['sla'] or {}).get('overdue'))
    return item


FACET_SQL = {'severity': "COALESCE(severity_scale, 'UNRATED')", 'stage': 'stage',
             'project': "CASE WHEN project='' THEN '—' ELSE project END", 'owasp': 'owasp',
             'status': "COALESCE(status, 'untriaged')"}


def search(index, query='', filters=None, offset=0, limit=50):
    sync(index)
    now_moment = triage.now()
    now = now_moment.timestamp()
    db = connect()
    try:
        where, values = conditions(query, filters, now)
        total = db.execute('SELECT COUNT(*) FROM rows' + where, values).fetchone()[0]
        # Worst first: severity, then overdue, then known-exploited, then how long
        # it has been open. No weighting, no composite number -- just an order.
        order = (' ORDER BY rank, CASE WHEN open=1 AND sla_due IS NOT NULL AND sla_due<? THEN 0 ELSE 1 END,'
                 " CASE WHEN known_exploited=1 THEN 0 ELSE 1 END, priority, COALESCE(first_seen, '9999'), stage, rule_id, id"
                 ' LIMIT ? OFFSET ?')
        # The page is chosen on the narrow table; only its rows are then read in full.
        page = [identifier for (identifier,) in
                db.execute('SELECT id FROM rows' + where + order, values + [now, limit, offset])]
        rows = payloads(db, page, now_moment)
        facets = {}
        for name, expression in FACET_SQL.items():
            clause, facet_values = conditions(query, filters, now, skip=name)
            counts = {}
            for value, count in db.execute(f'SELECT {expression}, COUNT(*) FROM rows{clause} GROUP BY 1', facet_values):
                if name == 'owasp':
                    for code in [c for c in str(value).split('|') if c] or ['—']:
                        counts[code] = counts.get(code, 0) + count
                else:
                    counts[value] = counts.get(value, 0) + count
            facets[name] = dict(sorted(counts.items(), key=lambda pair: (-pair[1], str(pair[0]))))
        coverage = _coverage(db, index)
    finally:
        db.close()
    return {'total': total, 'rows': rows, 'facets': facets, 'coverage': coverage}


def _coverage(db, index):
    """One entry per registered target, in the board's fixed stage order."""
    order = {stage: position for position, stage in enumerate(index.STAGES)}
    rows = [json.loads(raw) for (raw,) in db.execute('SELECT coverage FROM sources WHERE coverage IS NOT NULL')]
    return sorted(rows, key=lambda c: (order.get(c['stage'], len(order)), c['target']))


def payloads(db, identifiers, now_moment):
    '''The API rows for these ids, in the order given.'''
    if not identifiers:
        return []
    found = dict(db.execute('SELECT id, data FROM payload WHERE id IN (' + ', '.join('?' * len(identifiers)) + ')',
                            identifiers))
    return [present(found[identifier], now_moment) for identifier in identifiers if identifier in found]


def everything(index):
    """Every row, for the few callers that still want the whole list."""
    sync(index)
    now_moment = triage.now()
    db = connect()
    try:
        rows = [present(raw, now_moment) for (raw,) in db.execute('SELECT data FROM payload ORDER BY id')]
        coverage = _coverage(db, index)
    finally:
        db.close()
    return {'rows': rows, 'coverage': coverage, 'truncated': []}


def tally(index, *columns):
    """Counts grouped by plain columns, e.g. tally(index, 'stage', 'severity_scale')."""
    allowed = {'stage', 'severity_scale', 'project', 'status'}
    if not columns or not set(columns) <= allowed:
        raise ValueError('Guruhlash ustuni noto‘g‘ri.')
    sync(index)
    db = connect()
    try:
        return [tuple(row) for row in
                db.execute(f'SELECT {", ".join(columns)}, COUNT(*) FROM rows GROUP BY {", ".join(columns)}')]
    finally:
        db.close()


def detail(index, fingerprint):
    """(row, original finding, related rows) for one fingerprint, or None."""
    sync(index)
    now_moment = triage.now()
    db = connect()
    try:
        found = db.execute('SELECT data, finding FROM payload WHERE id=(SELECT id FROM rows WHERE fingerprint=?'
                           ' ORDER BY id LIMIT 1)', (fingerprint,)).fetchone()
        if found is None:
            return None
        item, original = present(found[0], now_moment), json.loads(found[1])
        related_where = ['duplicate_of=?', 'escalates=?']
        values = [fingerprint, fingerprint]
        for key in ('duplicate_of', 'escalates'):
            if item.get(key):
                related_where.append('fingerprint=?')
                values.append(item[key])
        related = payloads(db, [identifier for (identifier,) in
                                db.execute('SELECT id FROM rows WHERE fingerprint<>? AND (' + ' OR '.join(related_where)
                                           + ') ORDER BY id', [fingerprint] + values)], now_moment)
    finally:
        db.close()
    return item, original, related
