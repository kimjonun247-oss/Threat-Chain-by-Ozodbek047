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
import re
import stat
import sys

from .engine import ROOT, DATA

PATH = DATA / 'profiles/settings.json'
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


# ---- notification channels ---------------------------------------------------
# Scheduled scans report a changed result to a webhook, Slack and/or email. A
# Slack incoming-webhook URL and a generic webhook URL carry their own secret in
# the path, and SMTP needs a password, so the same three rules as the NVD key
# apply: never returned (only whether set and a masked tail), owner-only file,
# and THREATCHAIN_SMTP_PASSWORD in the environment wins over a stored password.
EMAIL_FIELDS = {'host', 'port', 'security', 'username', 'password', 'sender', 'recipients'}


def _https_url(value, what, prefix=None):
    from urllib.parse import urlsplit
    text = str(value or '').strip()
    if not text:
        return ''
    parts = urlsplit(text)
    loopback = parts.hostname in ('127.0.0.1', 'localhost', '::1')
    if len(text) > 500 or not parts.hostname or (parts.scheme != 'https' and not (parts.scheme == 'http' and loopback)):
        raise ValueError(f'{what}: https:// manzil kerak (http faqat localhost uchun).')
    if prefix and not text.startswith(prefix):
        raise ValueError(f'{what}: {prefix} bilan boshlanishi kerak.')
    return text


def notifications():
    """The channel configuration in force, secrets included. For zanjir.notify only."""
    config = dict(read().get('notifications') or {})
    email = dict(config.get('email') or {})
    if email:
        email['password'] = os.environ.get('THREATCHAIN_SMTP_PASSWORD', '') or email.get('password', '')
        config['email'] = email
    return config


def set_notifications(payload):
    """Replace the channel configuration. A secret left as None keeps the stored one."""
    if not isinstance(payload, dict) or not set(payload) <= {'webhook_url', 'slack_webhook_url', 'email'}:
        raise ValueError('Maydonlar: webhook_url, slack_webhook_url, email.')
    current = read().get('notifications') or {}
    config = {}
    for key, what, prefix in (('webhook_url', 'Webhook', None),
                              ('slack_webhook_url', 'Slack webhook', 'https://hooks.slack.com/')):
        value = payload.get(key, None)
        value = current.get(key, '') if value is None else _https_url(value, what, prefix)
        if value:
            config[key] = value
    email = payload.get('email', None)
    if email is None:
        email = current.get('email') or None
    elif email:
        if not isinstance(email, dict) or not set(email) <= EMAIL_FIELDS:
            raise ValueError('email: ' + ', '.join(sorted(EMAIL_FIELDS)) + ' maydonlari.')
        host = str(email.get('host') or '').strip()
        port = email.get('port', 587)
        security = email.get('security', 'starttls')
        sender = str(email.get('sender') or '').strip()
        recipients = email.get('recipients') or []
        if isinstance(recipients, str):
            recipients = [part.strip() for part in recipients.split(',') if part.strip()]
        address = lambda text: bool(re.fullmatch(r'[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+', text)) and len(text) <= 200
        if not host or len(host) > 200 or not re.fullmatch(r'[A-Za-z0-9.-]+', host):
            raise ValueError('email.host: SMTP server nomi kerak.')
        if type(port) is not int or not 1 <= port <= 65535 or security not in ('starttls', 'ssl', 'none'):
            raise ValueError('email.port 1–65535, security: starttls | ssl | none.')
        if not address(sender) or not recipients or len(recipients) > 20 or not all(address(r) for r in recipients):
            raise ValueError('email.sender va email.recipients (1–20 ta) to‘g‘ri manzil bo‘lsin.')
        password = email.get('password', None)
        stored = (current.get('email') or {}).get('password', '')
        email = {'host': host, 'port': port, 'security': security,
                 'username': str(email.get('username') or '').strip()[:200], 'sender': sender,
                 'recipients': recipients, 'password': stored if password is None else str(password)[:200]}
    else:
        email = None
    if email:
        config['email'] = email
    data = read()
    if config:
        data['notifications'] = config
    else:
        data.pop('notifications', None)
    write(data)
    return notification_status()


def _mask(value):
    return ('…' + value[-4:]) if value and len(value) > 8 else ('o‘rnatilgan' if value else '')


def notification_status():
    config = read().get('notifications') or {}
    email = config.get('email') or {}
    from_env = bool(os.environ.get('THREATCHAIN_SMTP_PASSWORD', ''))
    return {
        'webhook': {'present': bool(config.get('webhook_url')), 'masked': _mask(config.get('webhook_url', ''))},
        'slack': {'present': bool(config.get('slack_webhook_url')), 'masked': _mask(config.get('slack_webhook_url', ''))},
        'email': ({'present': True, 'host': email['host'], 'port': email['port'], 'security': email['security'],
                   'username': email.get('username', ''), 'sender': email['sender'], 'recipients': email['recipients'],
                   'password_present': bool(email.get('password')) or from_env, 'password_from_env': from_env}
                  if email else {'present': False}),
        'note': 'Webhook/Slack manzili va SMTP paroli hech qachon qaytarilmaydi; THREATCHAIN_SMTP_PASSWORD ustun turadi.',
    }


def set_max_parallel(value):
    """How many queued scans may run at once on this machine (1-4)."""
    if type(value) is not int or not 1 <= value <= 4:
        raise ValueError('max_parallel_scans 1 dan 4 gacha butun son bo‘lsin.')
    data = read()
    data['max_parallel_scans'] = value
    write(data)
    return {'max_parallel_scans': value}
