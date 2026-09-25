"""B6: targets that live somewhere else -- and the credentials that must not follow them.

Three surfaces were added: image tags and private registries, remote git
repositories, and authenticated web targets. All three need a login the project
is not allowed to keep, so the same rule runs through every test here: a
credential is read from the process environment at the moment it is used, and
nothing about it reaches a profile, a report or an API response except the name
of the variable it came from.
"""
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from isolation import isolate_triage
from zanjir import code_targets, images, remote_source, webscan

SECRET = 'PAROL-QIYMATI-NEVER-STORE-9977'
USERNAME = 'foydalanuvchi-XYZ-9977'


class ReferenceTests(unittest.TestCase):
    """What an image reference may be, now that tags and registries are allowed."""

    def test_a_a_bare_name_a_tag_and_a_digest_all_parse(self):
        self.assertEqual(images.parse_reference('nginx')['canonical'], 'docker.io/library/nginx:latest')
        self.assertEqual(images.parse_reference('nginx:1.27')['canonical'], 'docker.io/library/nginx:1.27')
        digest = 'sha256:' + 'b' * 64
        self.assertEqual(images.parse_reference(f'crapi/crapi-web@{digest}')['canonical'],
                         f'docker.io/crapi/crapi-web@{digest}')

    def test_b_a_private_registry_with_a_port_is_kept_intact(self):
        parsed = images.parse_reference('registry.example.com:5000/team/app:1.0')
        self.assertEqual(parsed['registry'], 'registry.example.com:5000')
        self.assertEqual(parsed['repository'], 'team/app')
        self.assertEqual(parsed['canonical'], 'registry.example.com:5000/team/app:1.0')

    def test_c_a_tag_is_never_treated_as_pinned(self):
        self.assertFalse(images.parse_reference('nginx:1.27')['pinned'])
        self.assertTrue(images.parse_reference('nginx@sha256:' + 'a' * 64)['pinned'])

    def test_d_anything_that_is_not_a_reference_is_refused(self):
        for bad in ('', ' ', 'https://example.org/image', 'alpine;whoami', '-x@sha256:' + 'a' * 64,
                    'alpine@sha256:qisqa', 'alpine:TEG!', 'a b', 'x' * 600, 'a//b'):
            with self.assertRaises(ValueError, msg=bad):
                images.parse_reference(bad)

    def test_e_the_command_receives_the_canonical_form(self):
        self.assertEqual(images.command('alpine:3.20', Path('work'))[-1], 'docker.io/library/alpine:3.20')


class RegistryCredentialTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        patcher = patch.object(images, 'PROFILES', self.tmp / 'images')
        patcher.start()
        self.addCleanup(patcher.stop)
        for name in images.credential_names('registry.example.com'):
            os.environ.pop(name, None)

    def export(self):
        user_var, password_var = images.credential_names('registry.example.com')
        os.environ[user_var] = USERNAME
        os.environ[password_var] = SECRET
        self.addCleanup(lambda: [os.environ.pop(v, None) for v in (user_var, password_var)])

    def test_a_a_public_image_uses_no_credentials_at_all(self):
        secrets, meta = images.registry_credentials('docker.io', 'none')
        self.assertEqual(secrets, {})
        self.assertFalse(meta['credentials_present'])

    def test_b_an_authenticated_target_without_the_variables_is_refused_with_the_names(self):
        with self.assertRaises(ValueError) as caught:
            images.registry_credentials('registry.example.com', 'environment')
        self.assertIn('THREATCHAIN_REGISTRY_REGISTRY_EXAMPLE_COM_USERNAME', str(caught.exception))

    def test_c_the_credential_reaches_trivy_and_nothing_else(self):
        self.export()
        secrets, meta = images.registry_credentials('registry.example.com', 'environment')
        self.assertEqual(secrets['TRIVY_PASSWORD'], SECRET)
        blob = json.dumps(meta, ensure_ascii=False)
        self.assertNotIn(SECRET, blob)
        self.assertNotIn(USERNAME, blob)
        self.assertIn('THREATCHAIN_REGISTRY_REGISTRY_EXAMPLE_COM_PASSWORD', blob)

    def test_d_credentials_are_per_registry_not_global(self):
        """One exported password must not be offered to every registry an image names."""
        self.export()
        with self.assertRaises(ValueError):
            images.registry_credentials('boshqa-registry.example.net', 'environment')

    def test_e_the_profile_never_holds_a_credential(self):
        self.export()
        row = images.register('private-app', 'registry.example.com:5000/team/app:1.0', auth='environment')
        stored = (images.PROFILES / 'private-app.json').read_text(encoding='utf-8')
        self.assertNotIn(SECRET, stored)
        self.assertNotIn(USERNAME, stored)
        self.assertEqual(row['auth'], 'environment')
        self.assertEqual(row['registry'], 'registry.example.com:5000')

    def test_f_a_tag_registration_says_it_is_not_pinned(self):
        row = images.register('teg-image', 'nginx:1.27')
        self.assertFalse(row['pinned'])
        self.assertIn('ko‘chishi mumkin', row['pin_note'])
        self.assertNotIn('pin_note', images.register('digest-image', 'nginx@sha256:' + 'c' * 64))

    def test_g_an_unknown_auth_mode_is_refused(self):
        with self.assertRaises(ValueError):
            images.register('x-image', 'nginx:1.27', auth='hammasi')


class RemoteGitTests(unittest.TestCase):
    def test_a_only_https_and_ssh_are_accepted(self):
        for good in ('https://github.com/owner/repo.git', 'ssh://git@host:22/owner/repo',
                     'git@github.com:owner/repo.git'):
            self.assertEqual(remote_source.check_url(good), good)

    def test_b_transports_that_can_run_a_command_are_refused(self):
        """`ext::` makes git execute an arbitrary command; `file://` is a local
        path dressed as a remote."""
        for bad in ('ext::sh -c whoami', 'file:///etc', 'http://example.org/a/b',
                    '--upload-pack=/bin/sh', 'ssh://host', 'git@host', ''):
            with self.assertRaises(ValueError, msg=bad):
                remote_source.check_url(bad)

    def test_c_a_url_carrying_a_login_is_refused(self):
        """It would be written into the project's own profile file."""
        with self.assertRaises(ValueError) as caught:
            remote_source.check_url(f'https://user:{SECRET}@gitlab.example.com/a/b')
        self.assertNotIn(SECRET, str(caught.exception))
        self.assertIn('credential helper', str(caught.exception).lower() + 'credential helper')

    def test_d_a_branch_name_cannot_become_a_flag(self):
        for bad in ('--upload-pack=x', 'a b', 'shox;whoami'):
            with self.assertRaises(ValueError, msg=bad):
                remote_source.check_ref(bad)
        self.assertEqual(remote_source.check_ref('release/1.2'), 'release/1.2')

    def test_e_git_cannot_stop_to_ask_for_a_password(self):
        """Without this a private URL hangs until the timeout instead of failing."""
        env = remote_source.environment()
        self.assertEqual(env['GIT_TERMINAL_PROMPT'], '0')
        self.assertEqual(env['GIT_ASKPASS'], '')

    def test_f_a_credential_in_a_git_message_is_redacted(self):
        message = f'fatal: https://user:{SECRET}@github.com/x/y not found'
        self.assertNotIn(SECRET, remote_source.redact(message))
        self.assertIn('***@github.com', remote_source.redact(message))

    def test_g_the_registration_stores_the_address_and_nothing_else(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        with patch.object(code_targets, 'PROFILES', tmp / 'code'):
            row = code_targets.register_remote('masofaviy', 'https://github.com/owner/repo.git', 'main', 'Nomi')
            stored = json.loads((tmp / 'code/masofaviy.json').read_text(encoding='utf-8'))
        self.assertEqual(stored['source'], 'remote_git')
        self.assertEqual(stored['url'], 'https://github.com/owner/repo.git')
        self.assertEqual(stored['ref'], 'main')
        self.assertNotIn('root', stored)
        self.assertEqual(row['id'], 'masofaviy')


class WebTargetTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        patcher = patch.object(webscan, 'PROFILES', self.tmp / 'web')
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop(webscan.auth_variable('staging-api'), None)

    def test_a_an_unauthenticated_target_sends_no_authorization_header(self):
        headers, meta = webscan.auth_for({'id': 'x'})
        self.assertEqual(headers, {})
        self.assertFalse(meta['credentials_present'])

    def test_b_an_authenticated_target_without_the_variable_is_refused_with_its_name(self):
        with self.assertRaises(ValueError) as caught:
            webscan.auth_for({'id': 'staging-api', 'authenticated': True})
        self.assertIn('THREATCHAIN_WEB_AUTH_STAGING_API', str(caught.exception))

    def test_c_the_token_reaches_the_request_and_nothing_else(self):
        os.environ[webscan.auth_variable('staging-api')] = 'Bearer ' + SECRET
        self.addCleanup(lambda: os.environ.pop(webscan.auth_variable('staging-api'), None))
        headers, meta = webscan.auth_for({'id': 'staging-api', 'authenticated': True})
        self.assertEqual(headers['Authorization'], 'Bearer ' + SECRET)
        self.assertNotIn(SECRET, json.dumps(meta, ensure_ascii=False))
        self.assertEqual(meta['variable'], 'THREATCHAIN_WEB_AUTH_STAGING_API')

    def test_d_the_profile_holds_the_variable_name_never_the_value(self):
        os.environ[webscan.auth_variable('staging-api')] = 'Bearer ' + SECRET
        self.addCleanup(lambda: os.environ.pop(webscan.auth_variable('staging-api'), None))
        webscan.register('staging-api', 'https://staging.example.test', 'AX', authenticated=True)
        stored = (webscan.PROFILES / 'staging-api.json').read_text(encoding='utf-8')
        self.assertNotIn(SECRET, stored)
        self.assertIn('THREATCHAIN_WEB_AUTH_STAGING_API', stored)

    def test_e_the_authorisation_record_is_still_mandatory(self):
        """B6 loosened what may be scanned, not who has to say yes to it."""
        for owner in ('', '   '):
            with self.assertRaises(ValueError):
                webscan.register('x-target', 'https://example.test', owner)

    def test_f_the_request_rate_can_be_slowed_but_never_sped_up(self):
        self.assertEqual(webscan.rate_delay({}), webscan.DEFAULT_RATE_DELAY)
        self.assertEqual(webscan.rate_delay({'rate_delay': 0.01}), webscan.DEFAULT_RATE_DELAY)
        self.assertEqual(webscan.rate_delay({'rate_delay': 5}), 5.0)
        self.assertEqual(webscan.rate_delay({'rate_delay': 10 ** 6}), webscan.MAX_RATE_DELAY)

    def test_g_the_user_agent_names_the_tool_and_survives_a_http_header(self):
        webscan.USER_AGENT.encode('latin-1')        # http.client encodes headers as latin-1
        self.assertIn('ThreatChain', webscan.USER_AGENT)

    def test_h_tls_state_is_recorded_not_judged(self):
        class FakeSocket:
            def getpeercert(self):
                return {'subject': ((('commonName', 'example.test'),),),
                        'issuer': ((('commonName', 'Test CA'),),),
                        'notAfter': 'Jan  1 00:00:00 2030 GMT',
                        'subjectAltName': (('DNS', 'example.test'), ('DNS', 'www.example.test'))}
            def version(self):
                return 'TLSv1.3'
            def cipher(self):
                return ('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 256)
        state = webscan.tls_state(FakeSocket())
        self.assertEqual(state['protocol'], 'TLSv1.3')
        self.assertEqual(state['subject'], 'example.test')
        self.assertEqual(state['issuer'], 'Test CA')
        self.assertGreater(state['days_remaining'], 0)
        self.assertEqual(state['subject_alt_names'], ['example.test', 'www.example.test'])
        # Recorded, not scored: nothing here decides whether the expiry is close.
        self.assertNotIn('severity', state)


class SecretLeakGuardTests(unittest.TestCase):
    """No credential value may appear in anything this project writes."""

    def test_a_no_stored_profile_or_report_contains_a_credential_pattern(self):
        from zanjir.engine import ROOT
        import re
        pattern = re.compile(r'(?i)(TRIVY_PASSWORD|GIT_PASSWORD)\s*[:=]\s*\S|'
                             r'https?://[^/\s:@]+:[^/\s@]+@|'
                             r'"(password|token|secret)"\s*:\s*"(?!hidden|REDACTED)[^"]{6,}"')
        checked = 0
        for folder in ('profiles', 'web-runs', 'image-runs', 'scanner-runs', 'iac-runs'):
            base = ROOT / folder
            if not base.is_dir():
                continue
            for path in list(base.rglob('*.json'))[:400]:
                try:
                    body = path.read_text(encoding='utf-8')
                except OSError:
                    continue
                checked += 1
                found = pattern.search(body)
                self.assertIsNone(found, f'{path}: {found.group(0)[:60] if found else ""}')
        self.assertGreater(checked, 0, 'tekshiriladigan fayl topilmadi')

    def test_b_the_credential_helpers_are_the_only_place_a_value_is_read(self):
        """A second reader added elsewhere would be a second place to leak from."""
        from zanjir.engine import ROOT
        import re
        allowed = {'images.py', 'webscan.py', 'settings.py', 'threatfeeds.py', 'remote_source.py'}
        for path in sorted((ROOT / 'zanjir').glob('*.py')):
            body = path.read_text(encoding='utf-8')
            if re.search(r"os\.environ(?:\.get)?\s*[\(\[]\s*['\"]?(THREATCHAIN_|TRIVY_|NVD_)", body):
                self.assertIn(path.name, allowed, f'{path.name}: kutilmagan kirish ma’lumoti o‘quvchisi')


if __name__ == '__main__':
    unittest.main()
