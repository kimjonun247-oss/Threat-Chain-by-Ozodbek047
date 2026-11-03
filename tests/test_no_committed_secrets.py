"""No credential-shaped literal is committed to this repository.

A security scanner's own tests are full of secrets on purpose -- fake ones, to
check that they are found, masked, and never pass an allowlist. Written as plain
literals they look exactly like real keys, and GitHub push protection rejected a
push of this branch over two of them (a Stripe `sk_live_` and a Slack `xoxb-`
value in a Gitleaks allowlist test). The convention since then, the one
benchmarks/run.py already followed: build such a value at run time --

    'sk_' + 'live_51Hq...'          not          'sk_live_51Hq...'

-- so the value under test is the same and the source never holds the shape.

This test enforces that over every file git tracks, plus new files not yet
added, before a push gets the chance to be refused. A deliberate exception (a
sample project whose whole point is that Gitleaks finds a hard-coded key in it)
is listed by path AND exact value in ALLOWED, with the reason.
"""
import re
import subprocess
import unittest

from zanjir.engine import ROOT

# High-confidence provider formats: the shapes GitHub push protection and
# Gitleaks treat as real credentials. Generic entropy rules are left out on
# purpose -- they would flag hashes and fixtures and teach people to ignore this.
PATTERNS = {
    'Stripe secret/restricted key': r'\b[rs]k_live_[0-9A-Za-z]{10,}',
    'Slack token': r'\bxox[abposr]-[0-9]{6,}-[0-9A-Za-z-]{6,}',
    'GitHub token': r'\bgh[pousr]_[0-9A-Za-z]{30,}|\bgithub_pat_[0-9A-Za-z_]{40,}',
    'Google API key': r'\bAIza[0-9A-Za-z_-]{35}\b',
    'AWS access key id': r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b',
    'GitLab token': r'\bglpat-[0-9A-Za-z_-]{20,}',
    'SendGrid key': r'\bSG\.[0-9A-Za-z_-]{20,}\.[0-9A-Za-z_-]{20,}',
    'npm token': r'\bnpm_[0-9A-Za-z]{36}\b',
    'private key block': r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----',
}
COMPILED = {kind: re.compile(pattern) for kind, pattern in PATTERNS.items()}

# (path, exact value) -> why it must stay a literal. Keep this list short.
ALLOWED = {
    ('samples/chain-demo/app/config.py', 'sk_' + 'live_51NxxFAKEexampleKEYforTHREATCHAINdemo00'):
        'the chain-demo scan target: Gitleaks has to find a hard-coded key in this file for the SX-001 '
        'demonstration (samples/chain-demo/zanjir-provenance.json says the key is fake and never valid)',
}


def repository_files():
    """Tracked files plus untracked ones that are not ignored -- what a push would carry next."""
    try:
        done = subprocess.run(['git', '-C', str(ROOT), 'ls-files', '-z', '--cached', '--others', '--exclude-standard'],
                              capture_output=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    if done.returncode != 0:
        return None
    return sorted({name for name in done.stdout.decode('utf-8', 'replace').split('\0') if name})


def hits():
    found = []
    for name in repository_files() or []:
        try:
            text = (ROOT / name).read_text(encoding='utf-8', errors='replace')
        except OSError:                       # deleted in the working tree but still in the index
            continue
        for kind, pattern in COMPILED.items():
            for match in pattern.finditer(text):
                found.append((name, text.count('\n', 0, match.start()) + 1, kind, match.group(0)))
    return found


class NoCommittedSecretsTests(unittest.TestCase):
    def setUp(self):
        if repository_files() is None:
            self.skipTest('git checkout emas yoki git yo‘q -- qaysi fayllar push qilinishini aniqlab bo‘lmaydi')

    def test_a_no_credential_shaped_literal_outside_the_allowlist(self):
        offending = [f'{path}:{line}  {kind}: {value[:12]}...' for path, line, kind, value in hits()
                     if (path, value) not in ALLOWED]
        self.assertEqual(offending, [], '\nSir ko‘rinishidagi literal topildi. Qiymatni ishga tushganda yig‘ing, '
                                        "masalan 'sk_' + 'live_…' (tests/test_no_committed_secrets.py):\n  "
                                        + '\n  '.join(offending))

    def test_b_every_allowlist_entry_is_still_needed(self):
        # A stale exception widens the allowlist silently; it must be removed with the literal.
        present = {(path, value) for path, _, _, value in hits()}
        self.assertEqual(sorted(set(ALLOWED) - present), [])


class DetectorControlTests(unittest.TestCase):
    """An empty result must mean "no secret", never "the patterns match nothing"."""

    SAMPLES = {
        'Stripe secret/restricted key': 'sk_' + 'live_51HqLyjWDarjtT1zdp7dcXr2r',
        'Slack token': 'xo' + 'xb-2134123412-2341234123-AbCdEfGhIjKlMnOpQrStUvWx',
        'GitHub token': 'gh' + 'p_16C7e42F292c6912E7710c838347Ae178B4a',
        'Google API key': 'AI' + 'zaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI',
        'AWS access key id': 'AK' + 'IAQ3EGRIUBCEXAMPLE',          # exactly AKIA + 16
        'GitLab token': 'gl' + 'pat-x9Ab_Cd-Ef12GhIj34Kl',
        'SendGrid key': 'S' + 'G.abcdefghijklmnopqrstuv.wxyzABCDEFGHIJKLMNOPQRSTUV0123456789abcdefg',
        'npm token': 'np' + 'm_' + 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8',
        'private key block': '-----BEGIN ' + 'RSA PRIVATE KEY-----',
    }

    def test_each_pattern_catches_its_own_shape(self):
        self.assertEqual(set(self.SAMPLES), set(COMPILED))
        for kind, value in self.SAMPLES.items():
            self.assertTrue(COMPILED[kind].search(value), kind)

    def test_the_run_time_form_is_not_flagged(self):
        source = "value = 'sk_' + 'live_51HqLyjWDarjtT1zdp7dcXr2r'\n"
        self.assertFalse(any(pattern.search(source) for pattern in COMPILED.values()))


if __name__ == '__main__':
    unittest.main()
