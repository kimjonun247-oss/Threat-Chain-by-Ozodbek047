"""Words and formats shared by every human-readable report (Markdown exports).

The UI review of 2026-11-04 read the downloaded reports as a reader would and
found raw codes where words belong: `Holat: completed`, stage names `code /
repository`, severities `warning / error`, timestamps with microseconds in UTC,
and three product names in three titles. This module is the one place those
words live; the JSON exports keep their codes, because tools read those.
"""
import datetime

from . import triage

PRODUCT = 'ThreatChain'

# Report and stage states, as one reader-facing word each.
STATE = {
    'completed': 'Tugadi', 'partial': 'Qisman — qamrov to‘liq emas', 'failed': 'Xato bilan tugadi',
    'cancelled': 'Bekor qilindi', 'queued': 'Navbatda', 'running': 'Davom etmoqda',
    'no_supported_packages': 'Versiyali paket fayli topilmadi', 'not_selected': 'Tanlanmagan',
    'skipped': 'O‘tkazib yuborildi', 'never_scanned': 'Hech tekshirilmagan',
    'external_or_interrupted': 'Boshqa oynada boshlangan yoki uzilgan',
}

STAGE = {
    'code': 'Kod va sirlar', 'repository': 'Compose va tarmoq', 'dependencies': 'Kutubxonalar (CVE)',
    'iac': 'Konfiguratsiya (IaC)', 'web': 'Sayt va API', 'images': 'Docker image', 'chain': 'Skanerlararo zanjir',
}

# The one severity scale (triage.SEVERITY_SCALE), in words; unrated stays unrated.
SEVERITY = {'CRITICAL': 'Kritik', 'HIGH': 'Yuqori', 'MEDIUM': 'O‘rta', 'LOW': 'Past'}
UNRATED = 'Baholanmagan'
ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}


def state(value):
    return STATE.get(str(value or ''), str(value or '—'))


def stage(value):
    return STAGE.get(str(value or ''), str(value or '—'))


def severity(finding):
    """The finding's severity on the one scale, in words."""
    return SEVERITY.get(triage.severity_of(finding) or '', UNRATED)


def by_severity(findings):
    """Worst first; the scanner's own order is kept inside one severity."""
    return sorted(findings, key=lambda f: ORDER.get(triage.severity_of(f) or '', len(ORDER)))


def severity_counts(findings):
    """'Kritik 0 · Yuqori 3 · ...' -- counts per severity, never added together."""
    counts = {name: 0 for name in (*SEVERITY.values(), UNRATED)}
    for finding in findings:
        counts[severity(finding)] += 1
    return ' · '.join(f'{name} {count}' for name, count in counts.items())


def when(value):
    """An ISO timestamp as the server's local date and time, with its offset.

    A value that is not a timestamp is returned as it is, so a report from an
    older format still renders.
    """
    moment = triage.parse_time(value)
    if moment is None:
        return str(value or '—')
    local = moment.astimezone()
    offset = local.strftime('%z')
    return local.strftime('%Y-%m-%d %H:%M') + (f' (UTC{offset[:3]}:{offset[3:]})' if offset else '')


def cell(value):
    """A Markdown table cell: no pipe or line break can split the row."""
    return str(value).replace('|', '\\|').replace('\n', ' ').replace('\r', ' ')
