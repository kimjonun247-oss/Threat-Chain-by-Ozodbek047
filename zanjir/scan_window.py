"""When a web target may be scanned, and how many requests a day it accepts.

A production service usually has an agreed quiet period -- nights, weekends --
and a load it will tolerate from a scanner. Both are recorded with the target's
authorisation, next to the owner who gave it:

    "scan_window": {"days": ["mon", "tue", "wed", "thu", "fri"],
                    "start": "22:00", "end": "06:00", "timezone": "+05:00"},
    "daily_request_budget": 300

A window may cross midnight (22:00-06:00 belongs to the day it starts). The
time zone is a fixed UTC offset such as "+05:00", which works everywhere with
the standard library alone; an IANA name ("Asia/Tashkent") is accepted where
the platform has the zone database (Windows needs the tzdata package for that,
so the offset is the portable choice). No window means any time; no budget
means only the per-scan limits apply.
"""
import datetime
import re

DAYS = ('mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun')
CLOCK = re.compile(r'^([01]\d|2[0-3]):([0-5]\d)$')
OFFSET = re.compile(r'^(?:UTC)?([+-])(\d{2}):(\d{2})$')
MAX_BUDGET = 100000


def timezone(name):
    text = str(name or 'UTC').strip()
    if text.upper() in ('UTC', 'Z', '+00:00'):
        return datetime.timezone.utc
    match = OFFSET.fullmatch(text)
    if match:
        sign, hours, minutes = match.groups()
        delta = datetime.timedelta(hours=int(hours), minutes=int(minutes))
        if delta > datetime.timedelta(hours=14):
            raise ValueError('Vaqt zonasi ofseti ±14:00 dan oshmasligi kerak.')
        return datetime.timezone(delta if sign == '+' else -delta)
    try:
        from zoneinfo import ZoneInfo
        return ZoneInfo(text)
    except Exception:
        raise ValueError(f'Vaqt zonasi “{text}” tanilmadi. "+05:00" kabi UTC ofsetini yozing '
                         '(IANA nomi faqat zona bazasi bor tizimda ishlaydi).') from None


NAMES = {**{day: day for day in DAYS},
         **{name: day for name, day in zip(('monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday'), DAYS)}}


def parse_days(value):
    """["mon", "wed"], "mon,wed", "mon-fri" or "fri-mon" -> ordered day names.

    Every token must be a day name or a range of two: a silently shortened
    list ("mon-fri" read as just Monday) would scan on days nobody allowed --
    or never on the ones they did.
    """
    tokens = [part.strip().lower() for part in value.split(',')] if isinstance(value, str) else value
    if not isinstance(tokens, list) or not tokens:
        raise ValueError('scan_window.days: mon, tue, wed, thu, fri, sat, sun (yoki mon-fri) dan tanlang.')
    chosen = set()
    for token in tokens:
        token = str(token).strip().lower()
        first, dash, last = token.partition('-')
        if dash and first in NAMES and last in NAMES:
            index, stop = DAYS.index(NAMES[first]), DAYS.index(NAMES[last])
            while True:
                chosen.add(DAYS[index])
                if index == stop:
                    break
                index = (index + 1) % 7
        elif token in NAMES:
            chosen.add(NAMES[token])
        else:
            raise ValueError(f'scan_window.days: “{token}” kun nomi emas (mon, tue, wed, thu, fri, sat, sun yoki mon-fri).')
    return [day for day in DAYS if day in chosen]


def parse_window(value):
    """Validate and normalise a window; None or {} means "any time"."""
    if value in (None, {}, ''):
        return None
    if not isinstance(value, dict) or not set(value) <= {'days', 'start', 'end', 'timezone'}:
        raise ValueError('scan_window: {"days": [...], "start": "HH:MM", "end": "HH:MM", "timezone": "+05:00"} ko‘rinishida bo‘lsin.')
    days = parse_days(value.get('days') or list(DAYS))
    start, end = str(value.get('start') or ''), str(value.get('end') or '')
    if not CLOCK.fullmatch(start) or not CLOCK.fullmatch(end):
        raise ValueError('scan_window.start va end "HH:MM" (24 soat) ko‘rinishida bo‘lsin.')
    if start == end:
        raise ValueError('scan_window: boshlanish va tugash vaqti bir xil bo‘lmasin (butun kun uchun oynani bermang).')
    zone = str(value.get('timezone') or 'UTC').strip()
    timezone(zone)
    return {'days': days, 'start': start, 'end': end, 'timezone': zone}


def parse_budget(value):
    if value in (None, ''):
        return None
    if type(value) is not int or not 1 <= value <= MAX_BUDGET:
        raise ValueError(f'daily_request_budget 1 dan {MAX_BUDGET} gacha butun son bo‘lsin.')
    return value


def _clock(text):
    hours, minutes = text.split(':')
    return datetime.time(int(hours), int(minutes))


def _instances(window, around):
    """Window occurrences (start, end) whose start date is near `around` (local time)."""
    zone = timezone(window['timezone'])
    local = around.astimezone(zone)
    start_clock, end_clock = _clock(window['start']), _clock(window['end'])
    for offset in range(-1, 9):
        day = local.date() + datetime.timedelta(days=offset)
        if DAYS[day.weekday()] not in window['days']:
            continue
        opens = datetime.datetime.combine(day, start_clock, zone)
        closes = datetime.datetime.combine(day, end_clock, zone)
        if closes <= opens:
            closes += datetime.timedelta(days=1)
        yield opens, closes


def status(window, now=None):
    """{'open', 'closes_at', 'opens_at'} for a normalised window at `now` (aware)."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    if window is None:
        return {'open': True, 'closes_at': None, 'opens_at': None}
    upcoming = None
    for opens, closes in _instances(window, now):
        if opens <= now < closes:
            return {'open': True, 'closes_at': closes, 'opens_at': opens}
        if opens > now and (upcoming is None or opens < upcoming):
            upcoming = opens
    return {'open': False, 'closes_at': None, 'opens_at': upcoming}


def day_start(window, now=None):
    """Midnight of the current day in the window's zone: when the daily budget resets."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    zone = timezone((window or {}).get('timezone') or 'UTC')
    local = now.astimezone(zone)
    return datetime.datetime.combine(local.date(), datetime.time(0, 0), zone)


def describe(window):
    if window is None:
        return 'istalgan vaqtda'
    return f"{', '.join(window['days'])} {window['start']}–{window['end']} ({window['timezone']})"
