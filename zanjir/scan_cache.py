"""What an earlier scan already established about a project's files.

Measured on a real 26 499-file tree: a scan took fifteen minutes, nine of them
before any scanner started -- and the cost was not copying the files but opening
each of them for the first time (93 files/s against 1 000 files/s for a file the
system had already read). The next scan of the same tree paid all of it again,
although almost nothing had changed.

Two things are remembered per project, both in one SQLite file:

  files    path -> size, mtime, SHA-256 and kind. A file whose size and mtime are
           unchanged is not opened at all; its hash is taken from here. This is
           the bargain git's own index makes, with the same blind spot: content
           changed without touching size or mtime is not seen. A full scan
           (THREATCHAIN_FULL_SCAN=1, or `full=True`) ignores this table.

  results  (context, tool, path) -> the file's hash and what the tool reported
           for it: findings and unreadable-file errors. The open-source engines
           used here judge one file at a time, so a file with the same content,
           at the same path, under the same rules and the same tool version has
           the same findings. `context` carries rules and version; when either
           changes, nothing matches and everything is scanned again.

It is a cache and only a cache. Deleting the file is always safe, a file that
cannot be opened or read simply means a full scan, and every report still lists
how many files were scanned and how many were taken from here.
"""
import json
import re
import sqlite3

VERSION = 2
NAME = re.compile(r'^[A-Za-z0-9_.-]{1,120}$')


class Cache:
    def __init__(self, folder, target):
        if not NAME.fullmatch(str(target or '')):
            raise ValueError('Kesh uchun nishon nomi yaroqsiz.')
        folder.mkdir(parents=True, exist_ok=True)
        self.path = folder / (target + '.sqlite3')
        self.db = sqlite3.connect(str(self.path), timeout=30, isolation_level=None)
        try:
            if self.db.execute('PRAGMA user_version').fetchone()[0] != VERSION:
                self.db.execute('DROP TABLE IF EXISTS files')
                self.db.execute('DROP TABLE IF EXISTS results')
                self.db.execute('CREATE TABLE files (path TEXT PRIMARY KEY, size INTEGER, mtime_ns INTEGER,'
                                ' sha256 TEXT, kind TEXT, bytes INTEGER)')
                self.db.execute('CREATE TABLE results (context TEXT, tool TEXT, path TEXT, sha256 TEXT,'
                                ' findings TEXT, errors TEXT, PRIMARY KEY (tool, path))')
                self.db.execute(f'PRAGMA user_version = {VERSION}')
            self.files = {row[0]: row[1:] for row in
                          self.db.execute('SELECT path, size, mtime_ns, sha256, kind, bytes FROM files')}
        except BaseException:
            self.db.close()
            raise
        self.current = {}
        self.known = {}                 # (tool, path) -> sha256, for the contexts of this scan

    # -- files ------------------------------------------------------------------
    def lookup(self, path, size, mtime_ns):
        """(sha256, kind, bytes) when the file looks unchanged, else None."""
        row = self.files.get(path)
        return row[2:] if row is not None and row[0] == size and row[1] == mtime_ns else None

    def remember(self, path, size, mtime_ns, sha256, kind, nbytes):
        self.current[path] = (size, mtime_ns, sha256, kind, nbytes)

    # -- results ----------------------------------------------------------------
    def load(self, contexts):
        """Index what is stored for these {tool: context} pairs."""
        self.known = {}
        for tool, context in contexts.items():
            for path, sha256 in self.db.execute('SELECT path, sha256 FROM results WHERE tool=? AND context=?',
                                                (tool, context)):
                self.known[(tool, path)] = sha256

    def has(self, path, sha256, tools):
        return all(self.known.get((tool, path)) == sha256 for tool in tools)

    def get(self, tool, path, sha256):
        """(findings, errors) stored for this exact content, or None."""
        if self.known.get((tool, path)) != sha256:
            return None
        row = self.db.execute('SELECT findings, errors FROM results WHERE tool=? AND path=? AND sha256=?',
                              (tool, path, sha256)).fetchone()
        if row is None:
            return None
        try:
            return json.loads(row[0]), json.loads(row[1])
        except ValueError:
            return None

    def store(self, context, tool, rows):
        """rows: (path, sha256, findings, errors) for every file the tool just scanned."""
        self.db.execute('BEGIN IMMEDIATE')
        try:
            for path, sha256, findings, errors in rows:
                self.db.execute('INSERT OR REPLACE INTO results VALUES (?,?,?,?,?,?)',
                                (context, tool, path, sha256, json.dumps(findings, ensure_ascii=False),
                                 json.dumps(errors, ensure_ascii=False)))
                self.known[(tool, path)] = sha256
            self.db.execute('COMMIT')
        except BaseException:
            self.db.execute('ROLLBACK')
            raise

    def save_files(self):
        """Record what this scan read about the files, before any tool runs.

        The reading is the expensive part of a first scan. Written only at the
        very end, it was lost with a scan that was cancelled or ran out of time
        -- and the next one opened every file again.
        """
        self.db.execute('BEGIN IMMEDIATE')
        try:
            self.db.execute('DELETE FROM files')
            self.db.executemany('INSERT INTO files VALUES (?,?,?,?,?,?)',
                                [(path, *row) for path, row in self.current.items()])
            self.db.execute('COMMIT')
        except BaseException:
            self.db.execute('ROLLBACK')
            raise
        self.files = dict(self.current)

    def finish(self):
        """Keep exactly the files this scan saw; forget results of files that are gone."""
        self.db.execute('BEGIN IMMEDIATE')
        try:
            self.db.execute('DELETE FROM files')
            self.db.executemany('INSERT INTO files VALUES (?,?,?,?,?,?)',
                                [(path, *row) for path, row in self.current.items()])
            self.db.execute('CREATE TEMP TABLE IF NOT EXISTS alive (path TEXT PRIMARY KEY)')
            self.db.execute('DELETE FROM alive')
            self.db.executemany('INSERT OR IGNORE INTO alive VALUES (?)', [(path,) for path in self.current])
            self.db.execute('DELETE FROM results WHERE path NOT IN (SELECT path FROM alive)')
            self.db.execute('COMMIT')
        except BaseException:
            self.db.execute('ROLLBACK')
            raise
        self.files = dict(self.current)

    def close(self):
        try:
            self.db.close()
        except sqlite3.Error:
            pass


def open_cache(folder, target):
    """A usable cache, or None. A damaged file is removed and rebuilt once."""
    for attempt in range(2):
        try:
            return Cache(folder, target)
        except ValueError:
            return None
        except (sqlite3.Error, OSError):
            try:
                (folder / (str(target) + '.sqlite3')).unlink()
            except OSError:
                return None
    return None
