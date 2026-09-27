"""Web targets: when they may be scanned and how many requests a day they take."""
import datetime
import json
import shutil
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from zanjir import scan_window as sw
from zanjir import webscan as w
from zanjir.httptest import listener

from test_target_impact import target

UTC = datetime.timezone.utc


def at(text):
    return datetime.datetime.fromisoformat(text)


class WindowTests(unittest.TestCase):
    NIGHTS = sw.parse_window({'days': ['mon', 'tue', 'wed', 'thu', 'fri'], 'start': '22:00', 'end': '06:00',
                              'timezone': '+05:00'})

    def test_a_window_is_normalised(self):
        self.assertEqual(self.NIGHTS['days'], ['mon', 'tue', 'wed', 'thu', 'fri'])
        self.assertEqual(sw.parse_window({'days': 'Sat, sun', 'start': '01:00', 'end': '03:00'})['days'], ['sat', 'sun'])
        self.assertIsNone(sw.parse_window(None))
        self.assertIsNone(sw.parse_window({}))

    def test_day_ranges_and_names(self):
        self.assertEqual(sw.parse_days('mon-fri'), ['mon', 'tue', 'wed', 'thu', 'fri'])
        self.assertEqual(sw.parse_days('fri-mon'), ['mon', 'fri', 'sat', 'sun'])
        self.assertEqual(sw.parse_days(['Saturday', 'sun']), ['sat', 'sun'])
        for bad in ('mon-xyz', 'monx', 'mo', ''):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                sw.parse_days(bad)

    def test_bad_windows_are_refused_with_the_reason(self):
        for bad in ({'start': '25:00', 'end': '01:00'}, {'start': '10:00', 'end': '10:00'},
                    {'days': ['xyz'], 'start': '01:00', 'end': '02:00'}, {'start': '01:00', 'end': '02:00', 'extra': 1},
                    {'start': '01:00', 'end': '02:00', 'timezone': '+15:00'}, 'nightly'):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                sw.parse_window(bad)

    def test_an_unknown_zone_name_suggests_an_offset(self):
        with self.assertRaises(ValueError) as caught:
            sw.parse_window({'start': '01:00', 'end': '02:00', 'timezone': 'Mars/Olympus'})
        self.assertIn('+05:00', str(caught.exception))

    def test_a_window_across_midnight_is_open_on_both_sides(self):
        # Monday 23:00 and Tuesday 03:00 in +05:00 both belong to Monday's window.
        self.assertTrue(sw.status(self.NIGHTS, at('2026-09-28T23:00:00+05:00'))['open'])
        early = sw.status(self.NIGHTS, at('2026-09-29T03:00:00+05:00'))
        self.assertTrue(early['open'])
        self.assertEqual(early['closes_at'], at('2026-09-29T06:00:00+05:00'))

    def test_outside_the_window_the_next_opening_is_given(self):
        noon = sw.status(self.NIGHTS, at('2026-09-29T12:00:00+05:00'))
        self.assertFalse(noon['open'])
        self.assertEqual(noon['opens_at'], at('2026-09-29T22:00:00+05:00'))
        # Friday night's window runs into Saturday; Saturday night has none.
        saturday = sw.status(self.NIGHTS, at('2026-10-03T12:00:00+05:00'))
        self.assertEqual(saturday['opens_at'], at('2026-10-05T22:00:00+05:00'))

    def test_the_offset_is_honoured_not_the_servers_clock(self):
        # 17:30 UTC is 22:30 in +05:00: inside the window.
        self.assertTrue(sw.status(self.NIGHTS, at('2026-09-28T17:30:00+00:00'))['open'])
        self.assertFalse(sw.status(self.NIGHTS, at('2026-09-28T16:30:00+00:00'))['open'])

    def test_budget_values(self):
        self.assertIsNone(sw.parse_budget(None))
        self.assertEqual(sw.parse_budget(300), 300)
        for bad in (0, -1, 1.5, '300', True, sw.MAX_BUDGET + 1):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                sw.parse_budget(bad)


class PermissionTests(unittest.TestCase):
    def setUp(self):
        folder = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, folder, True)
        for name, value in (('RUNS', folder / 'runs'), ('PROFILES', folder / 'profiles')):
            patcher = mock.patch.object(w, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        w.RUNS.mkdir()

    def past_scan(self, rid, created, requests):
        (w.RUNS / rid).mkdir()
        (w.RUNS / rid / 'report.json').write_text(json.dumps({
            'id': rid, 'target': 'shop', 'created_at': created, 'state': 'completed', 'count': 0,
            'impact': {'requests': requests}}), encoding='utf-8')

    def profile(self, **extra):
        return {'id': 'shop', 'url': 'https://shop.example.test', 'owner': 'x', 'allow_private': False, **extra}

    def test_registration_records_window_and_budget_with_the_authorisation(self):
        row = w.register('shop', 'https://shop.example.test', 'Ops lead',
                         scan_window={'days': ['sat'], 'start': '02:00', 'end': '04:00', 'timezone': '+05:00'},
                         daily_request_budget=120)
        stored = json.loads((w.PROFILES / 'shop.json').read_text(encoding='utf-8'))
        self.assertEqual(stored['scan_window'], row['scan_window'])
        self.assertEqual(stored['daily_request_budget'], 120)

    def test_outside_the_window_the_scan_is_refused_with_the_next_opening(self):
        profile = self.profile(scan_window={'days': ['sat'], 'start': '02:00', 'end': '04:00', 'timezone': '+05:00'})
        with self.assertRaises(w.PermissionWindowError) as caught:
            w.permission(profile, at('2026-09-28T12:00:00+05:00'))
        self.assertEqual(caught.exception.retry_at, at('2026-10-03T02:00:00+05:00'))
        self.assertIn('oynasidan tashqarida', str(caught.exception))

    def test_todays_requests_count_against_the_budget_yesterdays_do_not(self):
        self.past_scan('20260928T010000-aaaaaaaa', '2026-09-28T01:00:00+00:00', 40)     # Sep 28, 06:00 +05
        self.past_scan('20260927T100000-bbbbbbbb', '2026-09-27T10:00:00+00:00', 900)    # the day before
        allowed = w.permission(self.profile(daily_request_budget=100), at('2026-09-28T12:00:00+00:00'))
        self.assertEqual((allowed['used_today'], allowed['remaining_today']), (40, 60))

    def test_a_spent_budget_refuses_until_midnight_in_the_targets_zone(self):
        self.past_scan('20260928T010000-aaaaaaaa', '2026-09-28T01:00:00+00:00', 100)
        profile = self.profile(daily_request_budget=100,
                               scan_window={'start': '00:00', 'end': '23:59', 'timezone': '+05:00'})
        with self.assertRaises(w.PermissionWindowError) as caught:
            w.permission(profile, at('2026-09-28T12:00:00+00:00'))
        self.assertEqual(caught.exception.retry_at, at('2026-09-29T00:00:00+05:00'))


class DuringScanTests(unittest.TestCase):
    def collector(self, url, paths):
        profile = {'id': 't', 'url': url, 'owner': 'test', 'authorized_at': w.now(), 'allow_private': True,
                   'rate_delay': 0.5}
        collector = w.Collector(profile, set(paths), threading.Event())
        collector.delay = 0.01
        self.addCleanup(collector.close)
        return collector

    def test_the_budget_stops_the_scan_at_the_last_allowed_request(self):
        handler, seen = target(lambda n: (200, {}, 0))
        with listener(handler) as url:
            collector = self.collector(url, ['/a', '/b', '/c', '/d'])
            collector.request_budget = 2
            collector.fetch('/a')
            collector.fetch('/b')
            with self.assertRaises(ValueError):
                collector.fetch('/c')
        self.assertEqual(seen['requests'], 2)
        self.assertEqual(collector.stopped, 'daily_budget')

    def test_a_window_that_closes_mid_scan_stops_it(self):
        handler, seen = target(lambda n: (200, {}, 0))
        with listener(handler) as url:
            collector = self.collector(url, ['/a', '/b'])
            collector.fetch('/a')
            collector.window_closes = datetime.datetime.now(UTC) - datetime.timedelta(seconds=1)
            with self.assertRaises(ValueError):
                collector.fetch('/b')
        self.assertEqual(seen['requests'], 1)
        self.assertEqual(collector.stopped, 'window_closed')
        self.assertIn('oynasi yopildi', w.STOP_MESSAGES['window_closed'])


if __name__ == '__main__':
    unittest.main()
