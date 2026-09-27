"""The B7 workbench: the findings board, the settings store and the CSP contract.

The screens themselves are verified in a real browser (see REJA.md), but three
things must hold without one, because they are the ones that break silently:
the aggregation the board reads, the boundary on what a browser may register,
and the promise that the pages stay free of inline script and style.
"""
import json
import os
import re
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from isolation import isolate_triage
from zanjir import browse, findings_index, settings
from zanjir.engine import ROOT

DIST = ROOT / 'dist'


def finding(fingerprint, severity='HIGH', **extra):
    return {'fingerprint': fingerprint, 'rule_id': 'r', 'title': 'sarlavha', 'severity': severity,
            'path': 'a.py', 'line': 2, 'cwe_ids': ['CWE-79'],
            'owasp_top10_2025': [{'code': 'A05', 'name': 'A05:2025 – Injection'}], **extra}


def report(rows, rid='20260101T000000-aaaaaaaa', target='app', state='completed'):
    return {'id': rid, 'target': target, 'state': state, 'created_at': '2026-01-01T00:00:00+00:00',
            'findings': list(rows)}


class IndexTests(unittest.TestCase):
    """The board's own logic, over a fixed world."""

    def setUp(self):
        isolate_triage(self)
        findings_index.invalidate()
        self.addCleanup(findings_index.invalidate)
        self.world = {
            'code': (lambda rid: report([finding('a' * 24, 'ERROR'), finding('b' * 24, 'WARNING')]),
                     lambda limit: [{'id': '20260101T000000-aaaaaaaa', 'target': 'app', 'state': 'completed'}],
                     'target'),
            'images': (lambda rid: report([finding('c' * 24, 'CRITICAL', known_exploited=True,
                                                   epss={'epss': 0.9, 'percentile': 0.99},
                                                   package='openssl', version='1.0')],
                                          rid='20260102T000000-bbbbbbbb', target='img', state='partial'),
                       lambda limit: [{'id': '20260102T000000-bbbbbbbb', 'target': 'img', 'state': 'partial'}],
                       'target'),
        }
        patchers = [patch.object(findings_index, 'sources', lambda: self.world),
                    patch.object(findings_index, 'registered',
                                 lambda stage: {'code': {'app'}, 'images': {'img', 'skanerlanmagan'}}.get(stage, set())),
                    patch.object(findings_index, 'chain_rows', lambda stage: []),
                    patch.object(findings_index, 'project_of', lambda stage, target: 'demo')]
        for patcher in patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_a_every_scanner_lands_in_one_list(self):
        result = findings_index.search()
        self.assertEqual(result['total'], 3)
        self.assertEqual({row['stage'] for row in result['rows']}, {'code', 'images'})

    def test_b_worst_first_without_inventing_a_score(self):
        rows = findings_index.search()['rows']
        self.assertEqual([r['severity_scale'] for r in rows], ['CRITICAL', 'HIGH', 'MEDIUM'])
        self.assertNotIn('score', json.dumps(rows))
        self.assertIn('ball chiqarilmaydi', findings_index.search()['facets']['note'])

    def test_c_an_unscanned_target_is_named_not_omitted(self):
        """A target with no report is invisible in the table, so the table has to
        say it exists -- otherwise an empty result reads as "nothing to find"."""
        coverage = findings_index.search()['coverage']
        self.assertEqual([c['target'] for c in coverage['unscanned']], ['skanerlanmagan'])
        self.assertIn('toza degani emas', coverage['note'])

    def test_c2_a_scan_that_concluded_with_nothing_is_not_called_unscanned(self):
        """`no_supported_packages` is a result, not a gap.

        The board reported such a target as "never scanned", which is the same
        false statement the portfolio view exists to prevent, only in the other
        direction: it turned a real conclusion into a gap.
        """
        world = dict(self.world)
        world['dependencies'] = (lambda rid: report([], rid='20260103T000000-cccccccc',
                                                    target='dep', state='no_supported_packages'),
                                 lambda limit: [{'id': '20260103T000000-cccccccc', 'target': 'dep',
                                                 'state': 'no_supported_packages'}],
                                 'target')
        with patch.object(findings_index, 'sources', lambda: world), \
             patch.object(findings_index, 'registered',
                          lambda stage: {'code': {'app'}, 'images': {'img', 'skanerlanmagan'},
                                         'dependencies': {'dep'}}.get(stage, set())):
            findings_index.invalidate()
            coverage = findings_index.search()['coverage']
        self.assertNotIn('dep', [c['target'] for c in coverage['unscanned']])
        concluded = [c for c in coverage['scanned'] if c['target'] == 'dep']
        self.assertEqual(concluded[0]['outcome'], 'concluded_no_findings')
        self.assertEqual(concluded[0]['state'], 'no_supported_packages')

    def test_c3_a_failed_scan_is_incomplete_not_unscanned(self):
        world = dict(self.world)
        world['dependencies'] = (lambda rid: report([], rid='20260103T000000-cccccccc',
                                                    target='dep', state='failed'),
                                 lambda limit: [{'id': '20260103T000000-cccccccc', 'target': 'dep',
                                                 'state': 'failed'}],
                                 'target')
        with patch.object(findings_index, 'sources', lambda: world), \
             patch.object(findings_index, 'registered',
                          lambda stage: {'code': {'app'}, 'images': {'img', 'skanerlanmagan'},
                                         'dependencies': {'dep'}}.get(stage, set())):
            findings_index.invalidate()
            coverage = findings_index.search()['coverage']
        self.assertEqual([c['target'] for c in coverage['incomplete']], ['dep'])
        self.assertNotIn('dep', [c['target'] for c in coverage['unscanned']])
        self.assertIn('toza emas', coverage['incomplete_note'])

    def test_d_a_partial_scan_travels_with_its_rows(self):
        row = next(r for r in findings_index.search()['rows'] if r['stage'] == 'images')
        self.assertEqual(row['report_state'], 'partial')

    def test_e_kev_and_epss_reach_the_row(self):
        row = next(r for r in findings_index.search()['rows'] if r['stage'] == 'images')
        self.assertIs(row['known_exploited'], True)
        self.assertEqual(row['epss'], 0.9)

    def test_f_search_matches_across_the_fields_a_reader_would_type(self):
        self.assertEqual(findings_index.search(query='openssl')['total'], 1)
        self.assertEqual(findings_index.search(query='yo-q-bunday')['total'], 0)

    def test_g_filters_narrow_and_can_be_combined(self):
        self.assertEqual(findings_index.search(filters={'stage': 'code'})['total'], 2)
        self.assertEqual(findings_index.search(filters={'stage': 'code', 'severity': 'HIGH'})['total'], 1)
        self.assertEqual(findings_index.search(filters={'state': 'kev'})['total'], 1)

    def test_h_a_facet_stays_clickable_after_it_filters_to_nothing(self):
        """Counting facets over the final result set would delete the chip you
        need in order to undo the filter."""
        result = findings_index.search(filters={'stage': 'code', 'severity': 'CRITICAL'})
        self.assertEqual(result['total'], 0)
        self.assertIn('CRITICAL', result['facets']['severity'])
        self.assertEqual(result['facets']['severity']['CRITICAL'], 0)
        self.assertEqual(result['facets']['severity']['HIGH'], 1, 'boshqa filtr ichida sanaladi')
        self.assertEqual(result['facets']['stage']['images'], 1)

    def test_i_paging_reports_the_whole_total(self):
        page = findings_index.search(offset=1, limit=1)
        self.assertEqual((page['total'], len(page['rows']), page['offset']), (3, 1, 1))

    def test_j_detail_carries_the_original_record(self):
        detail = findings_index.detail('c' * 24)
        self.assertEqual(detail['row']['stage'], 'images')
        self.assertEqual(detail['finding']['package'], 'openssl')
        self.assertEqual(detail['events'], [])

    def test_k_an_unknown_fingerprint_is_an_error(self):
        with self.assertRaises(ValueError):
            findings_index.detail('f' * 24)


class SettingsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp()).resolve()   # macOS: /var is a symlink to /private/var
        self.addCleanup(shutil.rmtree, self.tmp, True)
        patcher = patch.object(settings, 'PATH', self.tmp / 'settings.json')
        patcher.start()
        self.addCleanup(patcher.stop)
        environ = patch.dict('os.environ', {}, clear=False)
        environ.start()
        self.addCleanup(environ.stop)
        import os
        os.environ.pop('NVD_API_KEY', None)

    def test_a_a_key_is_stored_and_never_returned(self):
        status = settings.set_nvd_key('abcd1234efgh5678')
        self.assertTrue(status['nvd_api_key']['present'])
        self.assertEqual(status['nvd_api_key']['masked'], '…5678')
        self.assertNotIn('abcd1234efgh5678', json.dumps(status))

    @unittest.skipIf(os.name == 'nt', 'Windows: POSIX ruxsat bitlari yo‘q (himoya papkaning ACL ruxsatlariga bog‘liq)')
    def test_b_the_file_is_owner_only(self):
        settings.set_nvd_key('abcd1234')
        import stat as stat_module
        mode = settings.PATH.stat().st_mode
        self.assertFalse(mode & (stat_module.S_IRGRP | stat_module.S_IROTH), 'kalit fayli boshqalarga ochiq')

    def test_c_an_empty_value_clears_it(self):
        settings.set_nvd_key('abcd1234')
        status = settings.set_nvd_key('')
        self.assertFalse(status['nvd_api_key']['present'])
        self.assertIsNone(settings.nvd_key())

    def test_d_a_malformed_key_is_refused(self):
        for bad in ('kalit bilan bo‘sh joy', 'x' * 200, 'a;b', 12345):
            with self.assertRaises(ValueError):
                settings.set_nvd_key(bad)

    def test_e_the_environment_wins_over_the_stored_value(self):
        import os
        settings.set_nvd_key('saqlangan1')
        os.environ['NVD_API_KEY'] = 'muhitdan1'
        try:
            self.assertEqual(settings.nvd_key(), 'muhitdan1')
            self.assertTrue(settings.status()['nvd_api_key']['from_env'])
        finally:
            os.environ.pop('NVD_API_KEY', None)

    def test_f_the_rate_limit_follows_the_key_without_a_restart(self):
        from zanjir import threatfeeds
        self.assertEqual(threatfeeds.min_interval(), 6.5)
        settings.set_nvd_key('abcd1234')
        self.assertEqual(threatfeeds.min_interval(), 0.7)


class FrontendContractTests(unittest.TestCase):
    """The page contract the CSP depends on, checked as text.

    `script-src 'self'; style-src 'self'` means an inline handler or an inline
    style silently does nothing in the browser. That failure is invisible in a
    unit test of the backend and easy to reintroduce, so it is asserted here.
    """

    def files(self, pattern):
        return sorted(DIST.glob(pattern))

    def test_a_no_inline_script_or_style_in_the_page(self):
        html = (DIST / 'index.html').read_text(encoding='utf-8')
        self.assertNotRegex(html, r'<script(?![^>]*\bsrc=)[^>]*>', 'inline <script> CSP tufayli ishlamaydi')
        self.assertNotIn('style="', html, 'inline style CSP tufayli qo‘llanmaydi')
        self.assertNotRegex(html, r'\son(click|load|change|submit)=', 'inline hodisa ishlovchisi')

    def test_b_no_inline_style_written_from_javascript(self):
        for path in self.files('*.js'):
            body = path.read_text(encoding='utf-8')
            self.assertNotRegex(body, r'\.style\.[a-zA-Z]+\s*=', f'{path.name}: .style o‘rniga sinf ishlating')
            self.assertNotRegex(body, r'style="\$\{', f'{path.name}: shablonda inline style')

    def test_c_every_script_the_page_loads_exists_and_parses_as_a_module(self):
        html = (DIST / 'index.html').read_text(encoding='utf-8')
        referenced = re.findall(r'<script src="/([^"]+)"', html)
        self.assertIn('findings.js', referenced)
        for name in referenced:
            path = DIST / name
            self.assertTrue(path.is_file(), name)
            body = path.read_text(encoding='utf-8')
            self.assertEqual(body.count('{') - body.count('}'), 0, f'{name}: qavslar mos emas')

    def test_c2_every_element_the_scripts_reach_for_exists_in_the_page(self):
        """A `$('id')` pointing at a removed element throws on page load.

        That happened when the overview screen moved to dashboard.js: the old
        renderer kept writing into `readiness-result`, which no longer existed,
        and every visit to the code view showed "Cannot set properties of null".
        Nothing in the suite noticed, because the failure is in the browser.
        """
        import re
        html = (DIST / 'index.html').read_text(encoding='utf-8')
        declared = set(re.findall(r'id="([A-Za-z0-9_-]+)"', html))
        for path in self.files('*.js'):
            body = path.read_text(encoding='utf-8')
            # Only literal ids; `$(kind + '-result')` is built at run time.
            for match in re.finditer(r"\$\('([A-Za-z0-9_-]+)'\)", body):
                name = match.group(1)
                if name in declared:
                    continue
                # Ids the scripts create themselves inside innerHTML.
                if re.search(rf'id="{re.escape(name)}"', body):
                    continue
                line = body.count('\n', 0, match.start()) + 1
                self.fail(f'{path.name}:{line} — #{name} sahifada ham, skriptda ham yo‘q')

    def test_c3_every_section_app_js_shows_and_hides_exists(self):
        """`$(name + '-view')` is built at run time, so test_c2 cannot see it.

        Removing the rule editor left 'rules' in that list and every view
        switch then threw "Cannot set properties of null" before it ran.
        """
        html = (DIST / 'index.html').read_text(encoding='utf-8')
        app = (DIST / 'app.js').read_text(encoding='utf-8')
        listed = re.search(r"for \(const item of \[([^\]]+)\]\)", app)
        self.assertIsNotNone(listed, 'view() dagi bo‘limlar ro‘yxati topilmadi')
        for name in re.findall(r"'([a-z]+)'", listed.group(1)):
            self.assertIn(f'id="{name}-view"', html, name)

    def test_d_every_view_in_the_nav_has_a_section(self):
        html = (DIST / 'index.html').read_text(encoding='utf-8')
        for view in re.findall(r'data-view="([a-z]+)"', html):
            self.assertIn(f'id="{view}-view"', html, view)

    def test_e_every_modal_button_has_a_window(self):
        html = (DIST / 'index.html').read_text(encoding='utf-8')
        shell = (DIST / 'shell.js').read_text(encoding='utf-8')
        for name in re.findall(r'data-modal="([a-z]+)"', html):
            self.assertRegex(shell, rf'\b{name}:', f'{name} oynasi shell.js da yo‘q')

    def test_f_the_board_never_computes_a_combined_score(self):
        """The prose says "never a score", so the word itself is allowed; what
        must not appear is a score being computed or read."""
        board = (DIST / 'findings.js').read_text(encoding='utf-8')
        for pattern in (r'\bscore\s*=', r'\.score\b', r'\bscore\('):
            self.assertNotRegex(board, pattern, pattern)
        self.assertIn('xavfsizlik xulosasi emas', board, 'bo‘sh jadval izohi yo‘qolgan')

    def test_g_dark_mode_is_declared_only_with_tokens(self):
        css = (DIST / 'style.css').read_text(encoding='utf-8')
        self.assertIn(':root[data-theme="dark"]', css)
        self.assertIn('--bg:#0b1522', css)

    def test_h_no_heading_colour_is_hardcoded_past_the_theme(self):
        """A literal navy on h2 made every section heading invisible in dark
        mode; headings go through a token like everything else."""
        css = (DIST / 'style.css').read_text(encoding='utf-8')
        # The literal may appear once, as the light theme's token value.
        self.assertEqual(css.count('#0c1930'), 1)
        self.assertIn('--heading:#0c1930', css)
        self.assertIn('--heading:#f2f6fb', css, 'qorong‘u rejim uchun sarlavha rangi yo‘q')

    def test_i_icons_are_one_inline_sprite_with_no_external_request(self):
        html = (DIST / 'index.html').read_text(encoding='utf-8')
        self.assertIn('<svg class="sprite"', html)
        self.assertNotRegex(html, r'<img\s', 'tashqi rasm CSP va offline ishlashga zid')
        import re
        used = set(re.findall(r'href="#(i-[a-z-]+)"', html))
        declared = set(re.findall(r'<symbol id="(i-[a-z-]+)"', html))
        self.assertEqual(used - declared, set(), 'e\u2019lon qilinmagan ikonka ishlatilgan')


class FolderPickerTests(unittest.TestCase):
    """The picker lists folders; it must never become a file reader.

    Registering a project needs an absolute path, and typing one by hand was
    the last step the window could not help with. The listing is therefore
    allowed -- but only inside the home directory, only directory names, and
    only behind the same --allow-registration flag that registration itself
    needs (app.py refuses the route otherwise).
    """

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp()).resolve()   # macOS: /var is a symlink to /private/var
        (self.tmp / 'loyiha').mkdir()
        (self.tmp / 'loyiha' / 'docker-compose.yml').write_text('services: {}\n', encoding='utf-8')
        (self.tmp / '.yashirin').mkdir()
        (self.tmp / 'fayl.txt').write_text('x', encoding='utf-8')
        (self.tmp / 'tashqariga').symlink_to('/etc')
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def listing(self, path=''):
        with patch.object(browse, 'home', lambda: self.tmp):
            return browse.listing(path)

    def test_a_only_folders_are_listed(self):
        names = [entry['name'] for entry in self.listing()['entries']]
        self.assertEqual(names, ['loyiha'], 'fayl, yashirin papka yoki symlink chiqmasligi kerak')

    def test_b_a_compose_file_is_marked_so_the_picker_can_show_it(self):
        self.assertEqual(self.listing()['entries'][0]['compose'], 'docker-compose.yml')
        self.assertEqual(self.listing(str(self.tmp / 'loyiha'))['compose'], 'docker-compose.yml')

    def test_c_the_walk_cannot_leave_the_home_directory(self):
        for outside in ('/etc', '/', str(self.tmp.parent), str(self.tmp / '..' / '..')):
            with self.assertRaises(ValueError, msg=outside):
                self.listing(outside)

    def test_d_the_home_directory_has_no_way_up(self):
        self.assertIsNone(self.listing()['parent'])
        self.assertEqual(self.listing(str(self.tmp / 'loyiha'))['parent'], str(self.tmp))

    def test_e_no_file_name_or_content_is_ever_returned(self):
        blob = json.dumps(self.listing())
        self.assertNotIn('fayl.txt', blob)
        self.assertNotIn('tashqariga', blob)

    def test_f_a_missing_folder_is_a_value_error_not_a_crash(self):
        with self.assertRaises(ValueError):
            self.listing(str(self.tmp / 'yo-q'))

    def test_g_the_route_sits_behind_the_registration_flag(self):
        source = (ROOT / 'app.py').read_text(encoding='utf-8')
        where = source.index("/api/registry/browse")
        self.assertIn('ALLOW_REGISTRATION', source[where:where + 400])


if __name__ == '__main__':
    unittest.main()


class YamlBoundaryTests(unittest.TestCase):
    """Every YAML entry point must convert a parser error into a ValueError.

    This is asserted as a class, not one case at a time, because the same defect
    appeared twice: once in the rule editor (A22) and again in the Compose
    parser, where pointing a registration at a non-YAML file closed the
    connection with no response. `yaml.YAMLError` is not a `ValueError`, so it
    walks straight past the `except ValueError` handlers in app.py.
    """

    BAD = ['\t tab bilan boshlangan', 'ochilgan: [', '%YAML 9.9\n---\na: 1',
           'a:\n\tb: 1', '127.0.0.1\tlocalhost', '"yopilmagan qo‘shtirnoq']

    def assert_value_error(self, call, label):
        from vendor import yaml
        for text in self.BAD:
            with self.subTest(entry=label, text=text[:20]):
                try:
                    call(text)
                except ValueError:
                    pass                    # including the ValueError subclasses used for limits
                except yaml.YAMLError as error:
                    self.fail(f'{label}: yaml.YAMLError o‘tib ketdi — {error}')

    def test_a_compose_parser(self):
        from zanjir import repository
        self.assert_value_error(repository.parse_yaml, 'repository.parse_yaml')

    def test_b_rule_editor(self):
        from zanjir import custom_rules
        self.assert_value_error(custom_rules.parse, 'custom_rules.parse')

    def test_c_nginx_parser(self):
        from zanjir import repository
        self.assert_value_error(lambda text: repository.nginx_tree(text, {}), 'repository.nginx_tree')

    def test_d_the_message_names_the_line(self):
        from zanjir import repository
        with self.assertRaises(ValueError) as caught:
            repository.parse_yaml('yaxshi: qator\n\tyomon: qator')
        self.assertIn('qator', str(caught.exception))

    def test_e_every_yaml_call_in_the_package_sits_inside_a_guard(self):
        """A new call added without a guard is the same defect returning."""
        import re
        from zanjir.engine import ROOT
        for path in sorted((ROOT / 'zanjir').glob('*.py')):
            body = path.read_text(encoding='utf-8')
            for match in re.finditer(r'yaml\.(parse|safe_load|load)\(', body):
                line = body.count('\n', 0, match.start())
                window = '\n'.join(body.splitlines()[max(0, line - 12):line + 14])
                self.assertIn('yaml.YAMLError', window,
                              f'{path.name}:{line + 1} — yaml chaqiruvi qo‘riqlanmagan')
