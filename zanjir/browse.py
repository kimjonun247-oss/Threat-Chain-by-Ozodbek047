"""Folder listing for the "Nishon qo‘shish" window's picker.

Typing an absolute path by hand is the one step of registering a project that
the browser could not help with, so this lists the folders under one the
operator is already allowed to give the server.

Two boundaries, both deliberate:

  - **The same gate as registration.** The endpoint answers only when the
    server was started with `--allow-registration`. That flag already lets the
    page hand the server any path to read and index, so listing folder names
    below it grants nothing the flag did not; without it this module is never
    reached.
  - **Names of folders, nothing else.** No file is opened, no file content or
    file name is returned, symlinks are skipped so a link cannot walk out of
    the tree, and the walk stays inside the operator's home directory -- a
    mistyped path enumerates nothing.
"""
import os
from pathlib import Path

COMPOSE = ('docker-compose.yml', 'docker-compose.yaml', 'compose.yml', 'compose.yaml')
LIMIT = 400


def home():
    return Path(os.path.expanduser('~')).resolve()


def compose_in(folder):
    """The compose file this folder carries, if any -- the picker marks those."""
    for name in COMPOSE:
        try:
            if (folder / name).is_file():
                return name
        except OSError:
            continue
    return None


def listing(path=''):
    """Folders directly inside `path` (default: the home directory)."""
    base = home()
    try:
        here = Path(os.path.expanduser(path)).resolve() if path else base
    except (OSError, ValueError):
        raise ValueError('Yo‘lni o‘qib bo‘lmadi.')
    if here != base and base not in here.parents:
        raise ValueError('Faqat uy papkasi ichidagi papkalar ko‘rsatiladi.')
    if not here.is_dir():
        raise ValueError('Bunday papka yo‘q.')
    entries, truncated = [], False
    try:
        children = sorted(here.iterdir(), key=lambda item: item.name.lower())
    except OSError:
        raise ValueError('Papkani o‘qish uchun ruxsat yo‘q.')
    for child in children:
        if child.name.startswith('.'):
            continue
        try:
            if child.is_symlink() or not child.is_dir():
                continue
        except OSError:
            continue
        if len(entries) >= LIMIT:
            truncated = True
            break
        entries.append({'name': child.name, 'path': str(child), 'compose': compose_in(child)})
    return {'path': str(here), 'home': str(base), 'name': here.name or str(here),
            'parent': str(here.parent) if here != base else None,
            'compose': compose_in(here), 'entries': entries, 'truncated': truncated}
