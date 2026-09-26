"""Scanning a repository that lives somewhere else.

Until now a source project had to be a directory on this machine, so the
scanners could only ever see code someone had already cloned by hand. This
module fetches a remote repository into a temporary directory, hands that
directory to the existing scanners, and deletes it when the scan is done.

Four rules, each of them a deliberate limit rather than an omission:

  1. **Read-only and shallow.** `git clone --depth 1` with no submodules, no
     hooks and no filters. Nothing from the repository is executed -- the
     scanners already copy text files into their own snapshot and run tools
     against that copy.
  2. **No credentials are stored or accepted over HTTP.** A private repository
     works if the operator's own git credential helper or SSH agent already
     works for it. This module never takes a username, a password or a token,
     and never writes one anywhere.
  3. **The clone is temporary and is always removed.** The commit it resolved to
     is recorded, because that -- not the branch name -- is what a later report
     can be compared against.
  4. **The URL is checked before git sees it.** An option-looking value, a
     local path pretending to be a URL, or a scheme git would treat as a command
     is refused, and the reason is stated.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# Only the two transports whose credential handling the operator already
# controls. `file://`, `ext::` and friends are refused: ext:: makes git run an
# arbitrary command, and a file URL is a local path dressed as a remote.
SCHEMES = ('https://', 'ssh://', 'git@')
HOST = re.compile(r'^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(?::\d{1,5})?$')
REF = re.compile(r'^[A-Za-z0-9._/-]{1,200}$')
CLONE_TIMEOUT = 600
MAX_BYTES = 400 * 1024 * 1024


def check_url(url):
    """Refuse anything that is not a plain https/ssh git URL, with the reason."""
    text = str(url or '').strip()
    if not text or len(text) > 500 or any(c.isspace() for c in text):
        raise ValueError('Repozitoriy manzili bo‘sh yoki noto‘g‘ri.')
    if text.startswith('-'):
        raise ValueError('Manzil `-` bilan boshlana olmaydi: u git uchun bayroqqa aylanadi.')
    if not text.startswith(SCHEMES):
        raise ValueError('Faqat https:// yoki ssh:// (yoki git@host:yo‘l) manzillari qo‘llanadi. '
                         'file://, ext:: va boshqa transportlar rad etiladi — ular git’ga buyruq '
                         'bajartirishi yoki lokal yo‘lni masofaviy ko‘rinishida berishi mumkin.')
    if '://' in text:
        scheme, rest = text.split('://', 1)
        authority, _, path = rest.partition('/')
        # An https URL with a login in it would be written into the project's
        # own profile file, which is exactly what this module promises never to
        # do. ssh:// keeps its `git@`, which is a user name, not a secret.
        if '@' in authority and scheme.lower() == 'https':
            raise ValueError('Manzil ichida foydalanuvchi/parol bo‘lishi mumkin emas — u loyiha faylida '
                             'saqlanib qolardi. Git credential helper yoki SSH kaliti ishlating.')
        host = authority.rsplit('@', 1)[-1]
    else:
        _, _, rest = text.partition('@')             # git@host:owner/repo
        host, _, path = rest.partition(':')
    if not host or not HOST.fullmatch(host):
        raise ValueError('Repozitoriy manzilidagi host noto‘g‘ri.')
    if not path.strip('/'):
        raise ValueError('Manzilda repozitoriy yo‘li ko‘rsatilmagan.')
    return text


def check_ref(ref):
    text = str(ref or '').strip()
    if not text:
        return ''
    if text.startswith('-') or not REF.fullmatch(text):
        raise ValueError('Branch/tag nomi noto‘g‘ri.')
    return text


def git():
    path = shutil.which('git')
    if not path:
        raise ValueError('git topilmadi. Masofaviy repozitoriyni tekshirish uchun git o‘rnatilgan bo‘lishi kerak.')
    return path


def environment():
    """A git run that cannot stop to ask a human anything.

    Without these, a private URL makes git block on a credential prompt and the
    scan hangs until the timeout instead of failing with a usable message.
    """
    return {'GIT_TERMINAL_PROMPT': '0', 'GIT_ASKPASS': '', 'SSH_ASKPASS': '',
            'GIT_CONFIG_NOSYSTEM': '1', 'GCM_INTERACTIVE': 'never'}


def directory_bytes(path):
    total = 0
    for item in path.rglob('*'):
        if item.is_file() and not item.is_symlink():
            total += item.stat().st_size
            if total > MAX_BYTES:
                return total
    return total


def clone(url, ref='', into=None):
    """Shallow-clone `url` and return (path, provenance). The caller removes it."""
    import os
    url = check_url(url)
    ref = check_ref(ref)
    # Resolved, because the scanners check that every file they copy stays
    # inside the source root: on macOS /var is a symlink to /private/var, so an
    # unresolved temp path makes that check fail on every remote scan.
    folder = Path(into or tempfile.mkdtemp(prefix='threatchain-clone-')).resolve()
    target = folder / 'source'
    # An empty directory rather than /dev/null: that path does not exist on
    # Windows, so a clone there would have failed on the very first flag. The
    # directory is inside the temp folder and goes away with it.
    hooks = folder / 'no-hooks'
    hooks.mkdir(exist_ok=True)
    command = [git(), '-c', f'core.hooksPath={hooks}', 'clone', '--depth', '1',
               '--no-tags', '--recurse-submodules=no', '--config', 'core.symlinks=false']
    if ref:
        command += ['--branch', ref]
    command += ['--', url, str(target)]
    env = {k: v for k, v in os.environ.items()
           if k.upper() in {'PATH', 'HOME', 'USERPROFILE', 'SYSTEMROOT', 'WINDIR', 'COMSPEC',
                            'SSH_AUTH_SOCK', 'TMPDIR', 'TEMP', 'TMP'}}
    env.update(environment())
    try:
        done = subprocess.run(command, capture_output=True, text=True, encoding='utf-8',
                              errors='replace', timeout=CLONE_TIMEOUT, env=env, cwd=str(folder))
    except subprocess.TimeoutExpired:
        remove(folder)
        raise ValueError(f'Klonlash {CLONE_TIMEOUT} soniyada tugamadi.') from None
    except OSError as error:
        remove(folder)
        raise ValueError(f'Klonlash bajarilmadi: {error}') from None
    if done.returncode != 0:
        remove(folder)
        raise ValueError('Klonlash bajarilmadi: ' + redact(done.stderr or done.stdout)[-300:])
    size = directory_bytes(target)
    if size > MAX_BYTES:
        remove(folder)
        raise ValueError(f'Repozitoriy {MAX_BYTES // 1024 ** 2} MB chegarasidan oshdi.')
    commit = resolve(target, env)
    return target, {
        'source_type': 'remote_git', 'url': redact(url), 'ref': ref or '(standart branch)',
        'commit': commit, 'depth': 1, 'submodules': False, 'bytes': size,
        'execution': 'faqat o‘qish; hook’lar o‘chirilgan, hech qanday kod bajarilmagan',
        'note': ('Vaqtinchalik nusxa: skan tugagach o‘chiriladi. Commit yozib olindi — keyingi '
                 'hisobot aynan shu holat bilan solishtiriladi, branch nomi bilan emas.'),
    }


def remove(folder):
    """Delete a temporary clone, including git's read-only files.

    On Windows git marks .git/objects/pack/*.pack and *.idx read-only, and
    shutil.rmtree(ignore_errors=True) then silently left the whole clone behind
    after every remote scan -- the platform check on a Windows runner found it.
    Clearing the read-only bit and retrying removes it on every OS.
    """
    import stat

    def clear_and_retry(function, path, _):
        try:
            os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
            function(path)
        except OSError:
            pass

    folder = Path(folder)
    if sys.version_info >= (3, 12):
        shutil.rmtree(folder, onexc=clear_and_retry)
    else:
        shutil.rmtree(folder, onerror=clear_and_retry)


def resolve(target, env):
    try:
        done = subprocess.run([git(), '-C', str(target), 'rev-parse', 'HEAD'],
                              capture_output=True, text=True, timeout=60, env=env)
        value = done.stdout.strip()
        return value if re.fullmatch(r'[0-9a-f]{40}', value) else None
    except (OSError, subprocess.SubprocessError, ValueError):
        return None


def redact(text):
    """Strip anything that looks like a credential out of a URL or a git message.

    git puts the remote URL into its own error text, and a URL someone typed may
    carry `https://user:token@host`. Nothing with a password in it reaches a
    report from here.
    """
    return re.sub(r'(?i)(https?://)[^/@\s]+@', r'\1***@', str(text or ''))
