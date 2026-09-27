"""Tests for the multi-project portfolio view.

The behaviour worth protecting here is mostly about what the view refuses to do:
never add counts across stages, never present "never scanned" as "clean", and
never group two target ids because they merely look alike.
"""
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from zanjir import portfolio as pf


def row(target, created_at, state='completed', count=0, rid=None):
    return {'id': rid or (created_at + '-x'), 'target': target, 'created_at': created_at,
            'state': state, 'count': count}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        patcher = patch.object(pf, 'PROFILES', self.tmp / 'portfolio')
        patcher.start()
        self.addCleanup(patcher.stop)

    def world(self, registry, history, bundled=None):
        """Patch the five registries, the scan history and the bundled grouping."""
        empty = {stage: [] for stage in pf.STAGES}
        return (patch.object(pf, 'registered_targets', lambda: {s: set(registry.get(s, ())) for s in pf.STAGES}),
                patch.object(pf, 'histories', lambda: {**empty, **history}),
                patch.object(pf, 'BUNDLED', bundled if bundled is not None else {}))

    def overview(self, registry, history, bundled=None):
        a, b, c = self.world(registry, history, bundled)
        with a, b, c:
            return {p['id']: p for p in pf.overview()['projects']}


class StageStateTests(Base):
    def test_a_stage_never_scanned_is_marked_so_and_is_not_a_zero(self):
        state = pf.stage_state([], ['app'])
        self.assertEqual(state['state'], 'never_scanned')
        self.assertIsNone(state['count'])          # not 0 -- nothing was measured
        self.assertFalse(state['scanned'])

    def test_a_completed_scan_with_no_findings_is_distinct_from_never_scanned(self):
        state = pf.stage_state([row('app', '2026-01-01T00:00:00+00:00', count=0)], ['app'])
        self.assertEqual(state['state'], 'completed')
        self.assertEqual(state['count'], 0)
        self.assertTrue(state['scanned'])

    def test_one_incomplete_target_makes_the_whole_stage_partial(self):
        rows = [row('b', '2026-01-02T00:00:00+00:00', state='partial', count=1),
                row('a', '2026-01-01T00:00:00+00:00', state='completed', count=2)]
        self.assertEqual(pf.stage_state(rows, ['a', 'b'])['state'], 'partial')

    def test_a_failed_scan_is_never_reported_as_completed(self):
        rows = [row('a', '2026-01-01T00:00:00+00:00', state='failed', count=0)]
        self.assertEqual(pf.stage_state(rows, ['a'])['state'], 'partial')

    def test_multi_target_total_uses_each_targets_latest_scan_only(self):
        # Three scans of 'a' must not be counted three times.
        rows = [row('a', '2026-01-03T00:00:00+00:00', count=5),
                row('a', '2026-01-02T00:00:00+00:00', count=99),
                row('b', '2026-01-01T00:00:00+00:00', count=2)]
        state = pf.stage_state(rows, ['a', 'b'])
        self.assertEqual(state['count'], 7)
        self.assertEqual(state['scanned_targets'], 2)

    def test_targets_never_scanned_inside_a_scanned_stage_are_named(self):
        rows = [row('a', '2026-01-01T00:00:00+00:00', count=1)]
        state = pf.stage_state(rows, ['a', 'b', 'c'])
        self.assertEqual(state['unscanned_targets'], ['b', 'c'])
        self.assertEqual(state['scanned_targets'], 1)

    def test_a_target_whose_latest_scan_failed_is_not_counted_as_covered(self):
        # Otherwise a stage with one broken image still reads N/N.
        rows = [row('a', '2026-01-02T00:00:00+00:00', state='failed', count=0),
                row('b', '2026-01-01T00:00:00+00:00', state='completed', count=3)]
        state = pf.stage_state(rows, ['a', 'b'])
        self.assertEqual(state['scanned_targets'], 1)
        self.assertEqual(state['attempted_targets'], 2)
        self.assertEqual(state['incomplete_targets'], ['a'])
        self.assertEqual(state['unscanned_targets'], [])

    def test_a_target_never_attempted_and_one_that_failed_are_reported_apart(self):
        rows = [row('a', '2026-01-01T00:00:00+00:00', state='failed', count=0)]
        state = pf.stage_state(rows, ['a', 'b'])
        self.assertEqual(state['incomplete_targets'], ['a'])
        self.assertEqual(state['unscanned_targets'], ['b'])

    def test_all_completed_leaves_both_gap_lists_empty(self):
        rows = [row('a', '2026-01-01T00:00:00+00:00', count=1)]
        state = pf.stage_state(rows, ['a'])
        self.assertEqual(state['incomplete_targets'], [])
        self.assertEqual(state['scanned_targets'], 1)


class GroupingTests(Base):
    def test_an_id_registered_in_two_stages_becomes_a_project(self):
        projects = self.overview({'code': ['app'], 'dependencies': ['app']}, {})
        self.assertIn('app', projects)
        self.assertTrue(projects['app']['derived'])

    def test_an_id_known_to_only_one_stage_is_a_single_stage_project(self):
        # It used to be left out: a scanned image or web target registered on its
        # own was simply absent from the portfolio.
        projects = self.overview({'web': ['lonely']}, {})
        self.assertEqual(sorted(projects), ['lonely'])
        self.assertTrue(projects['lonely']['single_stage'])
        self.assertEqual(projects['lonely']['stages']['web']['targets'], ['lonely'])
        self.assertEqual(projects['lonely']['stages']['code']['state'], 'not_registered')

    def test_ids_are_never_grouped_by_resemblance(self):
        # 'shop' and 'shop-web' are different projects until someone says otherwise.
        projects = self.overview({'code': ['shop'], 'dependencies': ['shop'], 'web': ['shop-web']}, {})
        self.assertEqual(sorted(projects), ['shop', 'shop-web'])
        self.assertEqual(projects['shop']['stages']['web']['targets'], [])
        self.assertFalse(projects['shop']['single_stage'])

    def test_a_bundled_group_claims_its_targets_so_they_are_not_listed_twice(self):
        bundled = {'demo': {'name': 'Demo', 'owner': '', 'bundled': True,
                            'stages': {'code': 'app', 'dependencies': 'app', 'web': 'site'}}}
        projects = self.overview({'code': ['app'], 'dependencies': ['app'], 'web': ['site']}, {}, bundled)
        self.assertEqual(sorted(projects), ['demo'])

    def test_an_explicit_definition_replaces_the_bundled_one_with_the_same_id(self):
        bundled = {'demo': {'name': 'Bundled nomi', 'owner': '', 'bundled': True,
                            'stages': {'code': 'app', 'dependencies': 'app'}}}
        a, b, c = self.world({'code': ['app'], 'dependencies': ['app']}, {}, bundled)
        with a, b, c:
            pf.PROFILES.mkdir(parents=True)
            (pf.PROFILES / 'demo.json').write_text(json.dumps(
                {'id': 'demo', 'name': 'Qo‘lda berilgan nom', 'stages': {'code': 'app'}}), encoding='utf-8')
            projects = {p['id']: p for p in pf.overview()['projects']}
        self.assertEqual(projects['demo']['name'], 'Qo‘lda berilgan nom')
        self.assertFalse(projects['demo']['bundled'])

    def test_gaps_name_every_stage_that_is_unbound_or_unscanned(self):
        history = {'code': [row('app', '2026-01-01T00:00:00+00:00', count=1)]}
        projects = self.overview({'code': ['app'], 'dependencies': ['app']}, history)
        self.assertEqual(projects['app']['stages']['dependencies']['state'], 'never_scanned')
        self.assertEqual(projects['app']['stages']['web']['state'], 'not_registered')
        self.assertEqual(projects['app']['gaps'], ['repository', 'dependencies', 'iac', 'images', 'web'])

    def test_overview_never_emits_a_combined_score_field(self):
        # Checked against the data keys, not the prose: the note deliberately
        # contains the word "ball" to say that no score is produced.
        history = {stage: [row('app', '2026-01-0%d' % (i + 1), count=i + 1)] for i, stage in enumerate(('code', 'dependencies'))}
        projects = self.overview({'code': ['app'], 'dependencies': ['app']}, history)
        keys = set(projects['app']) | {k for stage in projects['app']['stages'].values() for k in stage}
        for word in ('score', 'ball', 'grade', 'rating', 'percent', 'foiz', 'total'):
            self.assertFalse([k for k in keys if word in k.lower()], f'{word} in {sorted(keys)}')
        # Each stage keeps its own count; nothing adds them up.
        self.assertEqual(projects['app']['stages']['code']['count'], 1)
        self.assertEqual(projects['app']['stages']['dependencies']['count'], 2)

    def test_a_target_the_registries_no_longer_know_is_named_not_hidden(self):
        # A bundled group lists crAPI's image ids by name. If one is renamed the
        # group would quietly cover less than it claims, so the gap is surfaced.
        bundled = {'demo': {'name': 'Demo', 'owner': '', 'bundled': True,
                            'stages': {'code': 'app', 'images': ['img-a', 'img-gone']}}}
        projects = self.overview({'code': ['app'], 'images': ['img-a']}, {}, bundled)
        self.assertEqual(projects['demo']['unknown_targets'], ['img-gone'])

    def test_a_group_whose_targets_all_exist_reports_no_mismatch(self):
        bundled = {'demo': {'name': 'Demo', 'owner': '', 'bundled': True,
                            'stages': {'code': 'app', 'images': ['img-a']}}}
        projects = self.overview({'code': ['app'], 'images': ['img-a']}, {}, bundled)
        self.assertEqual(projects['demo']['unknown_targets'], [])


class FullHistoryTests(unittest.TestCase):
    """The portfolio must see every scan, not the 30 rows a UI list shows.

    With the 30-row window, crAPI's workshop image -- scanned, but no longer
    among the newest 30 of 36 image reports -- was reported as never scanned.
    """

    def test_histories_asks_every_source_for_all_rows(self):
        seen = {}
        def recorder(name):
            def history(*args, limit=30, **kw):
                seen[name] = limit
                return []
            return history
        with patch.object(pf.scanners, 'history', recorder('code')), \
             patch.object(pf.dependencies, 'history', recorder('dependencies')), \
             patch.object(pf.images, 'history', recorder('images')), \
             patch.object(pf.webscan, 'history', recorder('web')), \
             patch.object(pf.repo_store, 'list_reports', recorder('repository')):
            pf.histories()
        self.assertEqual(set(seen), {'code', 'dependencies', 'images', 'web', 'repository'})
        for name, limit in seen.items():
            with self.subTest(source=name):
                self.assertGreater(limit, 30)

    def test_a_scan_older_than_the_newest_thirty_still_counts(self):
        rows = [row(f'img-{i}', f'2026-01-{i + 2:02d}T00:00:00+00:00', count=1) for i in range(35)]
        rows.append(row('old-target', '2026-01-01T00:00:00+00:00', count=4))
        rows.sort(key=lambda r: r['created_at'], reverse=True)
        state = pf.stage_state(rows, ['old-target'])
        self.assertEqual(state['state'], 'completed')
        self.assertEqual(state['count'], 4)


class NormaliseTests(unittest.TestCase):
    def test_a_bare_id_and_a_list_are_both_accepted(self):
        self.assertEqual(pf.normalise({'code': 'app'}), {'code': ['app']})
        self.assertEqual(pf.normalise({'images': ['a', 'b']}), {'images': ['a', 'b']})

    def test_only_the_images_stage_may_hold_several_targets(self):
        with self.assertRaises(ValueError):
            pf.normalise({'code': ['a', 'b']})

    def test_an_unknown_stage_is_refused(self):
        with self.assertRaises(ValueError):
            pf.normalise({'kubernetes': 'a'})

    def test_a_grouping_with_no_target_at_all_is_refused(self):
        with self.assertRaises(ValueError):
            pf.normalise({'code': ''})


class RegisterTests(Base):
    def registry(self):
        return patch.object(pf, 'registered_targets',
                            lambda: {'code': {'app'}, 'repository': set(), 'dependencies': {'app'},
                                     'images': {'img-a', 'img-b'}, 'web': {'site'}})

    def test_a_grouping_is_saved_and_read_back(self):
        with self.registry():
            pf.register('my-app', 'Mening ilovam', {'code': 'app', 'images': ['img-a', 'img-b']}, owner='Jamoa')
            groups = pf.defined()
        self.assertEqual(groups['my-app']['stages'], {'code': ['app'], 'images': ['img-a', 'img-b']})
        self.assertEqual(groups['my-app']['owner'], 'Jamoa')

    def test_a_target_no_registry_knows_about_is_refused(self):
        with self.registry(), self.assertRaises(ValueError) as caught:
            pf.register('my-app', 'X', {'code': 'absent'})
        self.assertIn('absent', str(caught.exception))

    def test_an_id_cannot_escape_the_profile_directory(self):
        for identifier in ('../escape', 'a/b', 'Upper', 'ab'):
            with self.assertRaises(ValueError):
                pf.path_for(identifier)

    def test_an_empty_name_is_refused(self):
        with self.registry(), self.assertRaises(ValueError):
            pf.register('my-app', '   ', {'code': 'app'})

    def test_removing_a_grouping_that_was_never_defined_is_an_error(self):
        with self.assertRaises(ValueError):
            pf.remove('bundled-or-derived')

    def test_remove_deletes_only_the_explicit_definition(self):
        with self.registry():
            pf.register('my-app', 'X', {'code': 'app'})
            pf.remove('my-app')
            self.assertEqual(pf.defined(), {})


class TrendTests(Base):
    def history(self):
        return {'code': [row('app', '2026-01-03T00:00:00+00:00', state='partial', count=4),
                         row('app', '2026-01-02T00:00:00+00:00', count=9),
                         row('app', '2026-01-01T00:00:00+00:00', count=7)]}

    def trend(self, *args, **kwargs):
        a, b, c = self.world({'code': ['app'], 'dependencies': ['app']}, self.history())
        with a, b, c:
            return pf.trend(*args, **kwargs)

    def test_points_are_returned_oldest_first(self):
        points = self.trend('app', 'code')['points']
        self.assertEqual([p['count'] for p in points], [7, 9, 4])

    def test_every_point_carries_its_own_state_so_a_drop_is_never_read_alone(self):
        points = self.trend('app', 'code')['points']
        self.assertEqual(points[-1]['state'], 'partial')

    def test_the_result_never_claims_a_direction_of_travel(self):
        blob = json.dumps(self.trend('app', 'code')).lower()
        for word in ('improv', 'yaxshilan', 'better', 'worse', 'trend_direction'):
            self.assertNotIn(word, blob)

    def test_limit_bounds_the_series_and_is_itself_validated(self):
        self.assertEqual(len(self.trend('app', 'code', limit=2)['points']), 2)
        for bad in (0, 500, 'x'):
            with self.assertRaises(ValueError):
                self.trend('app', 'code', limit=bad)

    def test_unknown_project_or_stage_is_an_error_not_an_empty_series(self):
        with self.assertRaises(ValueError):
            self.trend('absent', 'code')
        with self.assertRaises(ValueError):
            self.trend('app', 'kubernetes')

    def test_a_stage_not_bound_to_the_project_is_an_error(self):
        with self.assertRaises(ValueError):
            self.trend('app', 'web')


if __name__ == '__main__':
    unittest.main(verbosity=2)
