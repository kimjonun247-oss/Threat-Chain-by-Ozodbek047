"""Who may use the dashboard, what each may do, and a record of what they did.

On one workstation the dashboard listens on 127.0.0.1 only and needs no login:
the operating system account is the boundary. A team needs more, and this
module provides it without any new dependency:

  - **Users and roles** (DATA/profiles/users.json, owner-only file):
      viewer   -- read reports, findings, portfolio;
      operator -- viewer + start/cancel scans, queue, register code/image targets, triage;
      admin    -- operator + web target authorisation, settings, notification
                  channels, schedules, custom rules, audit log.
    Passwords are stored as PBKDF2-SHA256 (600 000 iterations, 16-byte salt).
    Users are managed from the command line (app.py --add-user ...), never
    over HTTP: a stolen session cannot create itself a second account.
  - **Sessions**: a random 256-bit token in an HttpOnly, SameSite=Strict cookie
    (Secure over TLS). Only its SHA-256 is kept in memory. 30 minutes idle,
    12 hours at most; a restart logs everyone out.
  - **Login throttling**: after 5 failures for a user or an address, further
    attempts are refused for a growing period (1, 2, 4 ... up to 15 minutes).
  - **Audit log** (DATA/audit/audit.jsonl, append-only): logins, logouts,
    refusals and every state-changing request -- who, role, address, action,
    the ids it named and the HTTP status. Never a password, token or field value
    other than ids.

Login is required when at least one user exists, and the server refuses to
listen beyond loopback without users and without TLS (see app.py).
"""
import collections
import datetime
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import threading
import time

from .engine import DATA

USERS = DATA / 'profiles/users.json'
AUDIT = DATA / 'audit/audit.jsonl'
ROLES = ('viewer', 'operator', 'admin')
ITERATIONS = 600_000
IDLE = 30 * 60
ABSOLUTE = 12 * 3600
MAX_FAILURES = 5
MAX_LOCK = 15 * 60
NAME = re.compile(r'^[a-z0-9][a-z0-9._-]{1,39}$')
COOKIE = 'tc_session'

_SESSIONS = {}          # sha256(token) -> {'user', 'role', 'created', 'seen'}
_FAILURES = {}          # key -> {'count', 'until'}
_LOCK = threading.Lock()


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


# ---- users --------------------------------------------------------------------
def load():
    try:
        data = json.loads(USERS.read_text(encoding='utf-8'))
    except FileNotFoundError:
        return {}
    except (OSError, ValueError):
        raise ValueError('Foydalanuvchilar faylini o‘qib bo‘lmadi.') from None
    return data if isinstance(data, dict) else {}


def save(users):
    USERS.parent.mkdir(parents=True, exist_ok=True)
    temporary = USERS.with_suffix('.tmp')
    temporary.write_text(json.dumps(users, ensure_ascii=False, indent=1) + '\n', encoding='utf-8')
    try:
        os.chmod(temporary, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    os.replace(temporary, USERS)


def enabled():
    """Login is required once any user exists."""
    try:
        return bool(load())
    except ValueError:
        return True                 # an unreadable user file must not open the door


def hash_password(password, salt=None, iterations=ITERATIONS):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)
    return f'pbkdf2_sha256${iterations}${salt.hex()}${digest.hex()}'


_DECOY = {}


def _decoy_hash():
    """A stored-hash string to check an unknown user's password against.

    The login path must cost one PBKDF2 of ITERATIONS work whether or not the
    name exists, or the response time says which names do. Generating the decoy
    per call would make the unknown-user path cost *two* PBKDF2 runs (make the
    decoy, then check against it) while a known user costs one -- a 2x gap an
    attacker can still measure. So the decoy is built once and cached (keyed by
    ITERATIONS, which tests patch), leaving every probe at a single PBKDF2.
    """
    stored = _DECOY.get(ITERATIONS)
    if stored is None:
        stored = hash_password('decoy-password', b'\x00' * 16, ITERATIONS)
        _DECOY[ITERATIONS] = stored
    return stored


def check_password(password, stored):
    try:
        scheme, iterations, salt, digest = stored.split('$')
        if scheme != 'pbkdf2_sha256':
            return False
        candidate = hash_password(password, bytes.fromhex(salt), int(iterations))
    except (ValueError, AttributeError):
        return False
    return hmac.compare_digest(candidate, stored)


def validate_password(password):
    if not isinstance(password, str) or len(password) < 12 or len(password) > 200:
        raise ValueError('Parol 12–200 belgidan iborat bo‘lsin.')
    if len(set(password)) < 6:
        raise ValueError('Parol juda bir xil belgilardan iborat.')


def add_user(name, role, password):
    if not isinstance(name, str) or not NAME.fullmatch(name):
        raise ValueError('Foydalanuvchi nomi: kichik harf, raqam, . _ - (2–40 belgi).')
    if role not in ROLES:
        raise ValueError('Rol: ' + ', '.join(ROLES))
    validate_password(password)
    users = load()
    if name in users:
        raise ValueError('Bunday foydalanuvchi bor. Parolni --set-password bilan o‘zgartiring.')
    users[name] = {'role': role, 'password': hash_password(password), 'created_at': now(), 'disabled': False}
    save(users)
    audit('user_added', user='cli', details={'name': name, 'role': role})
    return {'name': name, 'role': role}


def set_password(name, password):
    validate_password(password)
    users = load()
    if name not in users:
        raise ValueError('Bunday foydalanuvchi yo‘q.')
    users[name]['password'] = hash_password(password)
    save(users)
    drop_sessions(name)
    audit('password_changed', user='cli', details={'name': name})


def set_role(name, role):
    if role not in ROLES:
        raise ValueError('Rol: ' + ', '.join(ROLES))
    users = load()
    if name not in users:
        raise ValueError('Bunday foydalanuvchi yo‘q.')
    users[name]['role'] = role
    save(users)
    drop_sessions(name)
    audit('role_changed', user='cli', details={'name': name, 'role': role})


def remove_user(name):
    users = load()
    if name not in users:
        raise ValueError('Bunday foydalanuvchi yo‘q.')
    remaining_admins = [n for n, u in users.items() if n != name and u.get('role') == 'admin' and not u.get('disabled')]
    if users[name].get('role') == 'admin' and not remaining_admins:
        raise ValueError('Oxirgi admin o‘chirilmaydi.')
    users.pop(name)
    save(users)
    drop_sessions(name)
    audit('user_removed', user='cli', details={'name': name})


def listing():
    return [{'name': name, 'role': row.get('role'), 'created_at': row.get('created_at'),
             'disabled': bool(row.get('disabled'))} for name, row in sorted(load().items())]


# ---- throttling -------------------------------------------------------------------
def _locked(key, at):
    entry = _FAILURES.get(key)
    return entry is not None and entry['until'] > at


def _fail(key, at):
    entry = _FAILURES.setdefault(key, {'count': 0, 'until': 0.0})
    entry['count'] += 1
    if entry['count'] >= MAX_FAILURES:
        entry['until'] = at + min(MAX_LOCK, 60 * 2 ** (entry['count'] - MAX_FAILURES))


# ---- sessions --------------------------------------------------------------------
def _digest(token):
    return hashlib.sha256(token.encode('ascii', 'replace')).hexdigest()


def login(name, password, address):
    """(token, user) on success; ValueError with a deliberately vague reason otherwise."""
    at = time.monotonic()
    keys = ('user:' + str(name)[:40], 'addr:' + str(address))
    with _LOCK:
        if any(_locked(key, at) for key in keys):
            audit('login_throttled', user=str(name)[:40], address=address)
            raise PermissionError('Juda ko‘p urinish. Birozdan keyin qayta urinib ko‘ring.')
    users = load()
    row = users.get(name) if isinstance(name, str) else None
    # The hash is checked even for an unknown user so timing does not tell which
    # names exist: both paths run one PBKDF2 of ITERATIONS work (see _decoy_hash).
    valid = check_password(password if isinstance(password, str) else '',
                           (row or {}).get('password') or _decoy_hash())
    if not row or row.get('disabled') or not valid:
        with _LOCK:
            for key in keys:
                _fail(key, at)
        audit('login_failed', user=str(name)[:40], address=address)
        raise ValueError('Login yoki parol noto‘g‘ri.')
    with _LOCK:
        for key in keys:
            _FAILURES.pop(key, None)
        token = secrets.token_urlsafe(32)
        _SESSIONS[_digest(token)] = {'user': name, 'role': row['role'], 'created': at, 'seen': at}
    audit('login', user=name, role=row['role'], address=address)
    return token, {'name': name, 'role': row['role']}


def session(token):
    """The signed-in user for a cookie value, or None. Refreshes the idle timer."""
    if not token:
        return None
    at = time.monotonic()
    with _LOCK:
        key = _digest(token)
        entry = _SESSIONS.get(key)
        if entry is None:
            return None
        if at - entry['seen'] > IDLE or at - entry['created'] > ABSOLUTE:
            _SESSIONS.pop(key, None)
            return None
        entry['seen'] = at
        return {'name': entry['user'], 'role': entry['role']}


def logout(token):
    with _LOCK:
        entry = _SESSIONS.pop(_digest(token or ''), None)
    return entry


def drop_sessions(name):
    with _LOCK:
        for key in [k for k, v in _SESSIONS.items() if v['user'] == name]:
            _SESSIONS.pop(key, None)


# ---- authorisation ----------------------------------------------------------------
# Registering a web target records someone's permission to send requests to a
# third party's server: that is an authorisation decision, so admin only.
# /api/reset/* wipes every scan result and the triage history with it: that is a
# destruction of the record, heavier than the scans an operator runs, so it is an
# admin decision like the other state-of-the-system changes here.
ADMIN_PATHS = ('/api/settings/', '/api/schedules', '/api/notifications/', '/api/audit', '/api/rules/save',
               '/api/rules/delete', '/api/registry/web', '/api/reset')


def required_role(method, path):
    """The least role that may make this request."""
    if path.startswith(ADMIN_PATHS) and (method == 'POST' or path.startswith('/api/audit')):
        return 'admin'
    if path == '/api/settings/notifications':
        return 'admin'
    return 'operator' if method == 'POST' else 'viewer'


def allowed(user, method, path):
    return user is not None and ROLES.index(user['role']) >= ROLES.index(required_role(method, path))


# ---- audit ----------------------------------------------------------------------------
_AUDIT_LOCK = threading.Lock()
ID_FIELDS = ('id', 'target', 'kind', 'report_id', 'name', 'reference', 'url', 'stage', 'fingerprint', 'status')


def audit(action, user=None, role=None, address=None, path=None, status=None, details=None):
    """Append one line. Fields are fixed; values are ids, never secrets."""
    entry = {'at': now(), 'action': action, 'user': user, 'role': role, 'address': address,
             'path': path, 'status': status}
    if details:
        entry['details'] = details
    line = json.dumps({k: v for k, v in entry.items() if v is not None}, ensure_ascii=False)
    with _AUDIT_LOCK:
        AUDIT.parent.mkdir(parents=True, exist_ok=True)
        with open(AUDIT, 'a', encoding='utf-8') as handle:
            handle.write(line + '\n')


def payload_ids(payload):
    """The identifying fields of a request body -- never secrets or free text."""
    if not isinstance(payload, dict):
        return None
    picked = {}
    for key in ID_FIELDS:
        value = payload.get(key)
        if isinstance(value, (str, int)) and not isinstance(value, bool):
            text = str(value)
            if key == 'url':
                text = re.sub(r'(?i)(https?://)[^/@\s]+@', r'\1***@', text).split('?')[0]
            picked[key] = text[:200]
    fingerprints = payload.get('fingerprints')
    if isinstance(fingerprints, list):
        picked['fingerprints'] = len(fingerprints)
    return picked or None


def read_audit(limit=200):
    # The audit log is append-only and grows without bound; readlines() loaded
    # the whole file into memory on every /api/audit call, so a long-lived team
    # server would read gigabytes to return 200 rows. A deque over the file keeps
    # only the last `want` lines in memory, whatever the file's size.
    want = max(1, min(limit, 2000))
    try:
        with open(AUDIT, encoding='utf-8') as handle:
            lines = list(collections.deque(handle, maxlen=want))
    except FileNotFoundError:
        return []
    rows = []
    for line in reversed(lines):
        try:
            rows.append(json.loads(line))
        except ValueError:
            continue
    return rows
