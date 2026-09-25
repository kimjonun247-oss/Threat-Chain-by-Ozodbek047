"""Operator settings that live on this machine and never leave it.

Only one setting so far: the NVD API key. Without it NVD allows five requests
per thirty seconds, so CWE enrichment is slow and partial; with it the limit
rises. It is a rate-limit token for a public API, not a credential to anything
the operator owns, but it is still a key, so three rules apply:

  1. **Never returned.** The API reports whether one is set and the last four
     characters, never the value. Nothing echoes it back into a report.
  2. **Owner-only on disk.** The file is written with mode 0600 where the
     platform supports it.
  3. **The environment wins.** `NVD_API_KEY` in the environment takes priority
     over the stored value, so a CI run cannot be silently overridden by
     whatever someone typed into a browser once.
"""
import json
import os
import stat
import sys

from .engine import ROOT

PATH = ROOT / 'profiles/settings.json'
MAX_KEY = 120


def read():
    try:
        data = json.loads(PATH.read_text(encoding='utf-8'))
    except FileNotFoundError:
        return {}
    except (OSError, ValueError):
        raise ValueError('Sozlamalar faylini o‘qib bo‘lmadi.') from None
    return data if isinstance(data, dict) else {}


def write(data):
    PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary = PATH.with_suffix('.tmp')
    temporary.write_text(json.dumps(data, ensure_ascii=False, indent=1) + '\n', encoding='utf-8')
    try:
        os.chmod(temporary, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass                      # Windows ACLs: the rename still happens
    os.replace(temporary, PATH)


def nvd_key():
    """The key in force: the environment first, then the stored one."""
    return (os.environ.get('NVD_API_KEY', '').strip() or str(read().get('nvd_api_key') or '').strip()) or None


def set_nvd_key(value):
    """Store or clear the key. An empty value clears it."""
    if not isinstance(value, str):
        raise ValueError('Kalit matn bo‘lishi kerak.')
    value = value.strip()
    if len(value) > MAX_KEY:
        raise ValueError(f'Kalit {MAX_KEY} belgidan oshmasin.')
    if value and not value.replace('-', '').isalnum():
        raise ValueError('Kalit faqat harf, raqam va tire’dan iborat bo‘lishi kerak.')
    data = read()
    if value:
        data['nvd_api_key'] = value
    else:
        data.pop('nvd_api_key', None)
    write(data)
    return status()


def status(registration_enabled=False):
    stored = str(read().get('nvd_api_key') or '')
    from_env = bool(os.environ.get('NVD_API_KEY', '').strip())
    key = nvd_key()
    return {
        'nvd_api_key': {
            'present': bool(key),
            'source': 'muhit o‘zgaruvchisi' if from_env else ('saqlangan fayl' if stored else ''),
            # Enough to recognise which key is in place, not enough to use it.
            'masked': ('…' + key[-4:]) if key and len(key) > 4 else ('o‘rnatilgan' if key else ''),
            'stored': bool(stored), 'from_env': from_env,
            'note': ('Kalit profiles/settings.json faylida, faqat egasi o‘qiy oladigan huquq bilan saqlanadi '
                     'va hech qanday hisobotda ko‘rsatilmaydi. Muhit o‘zgaruvchisi ustun turadi.'),
        },
        'registration_enabled': bool(registration_enabled),
        'python': '.'.join(map(str, sys.version_info[:3])),
    }
