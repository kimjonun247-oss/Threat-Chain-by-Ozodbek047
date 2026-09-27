"""The benchmark corpus and its expectations stay consistent (fast; no scanner runs).

benchmarks/run.py does the real measuring; this only catches a corpus edited
without its expected.json, a committed token-shaped secret, or a server that
would break the runner's readiness handshake.
"""
import json
import re
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / 'benchmarks'
EXPECTED = json.loads((BENCH / 'expected.json').read_text(encoding='utf-8'))


class CorpusTests(unittest.TestCase):
    def test_sast_positive_count_matches_expected(self):
        files = [p for p in (BENCH / 'corpus/sast').rglob('*') if p.is_file() and '__pycache__' not in p.parts]
        positives = [p for p in files if 'safe' not in p.relative_to(BENCH / 'corpus/sast').parts]
        self.assertEqual(len(positives), EXPECTED['sast']['positives'])
        self.assertTrue(any('safe' in p.parts for p in files))

    def test_no_token_shaped_secret_is_committed(self):
        # Secrets are generated at run time; a literal one would trip push protection.
        pattern = re.compile(r'ghp_[A-Za-z0-9]{36}|AKIA[A-Z2-7]{16}|sk_live_[A-Za-z0-9]{10}|xox[bp]-\d|glpat-[\w-]{20}|'
                             r'-----BEGIN (RSA )?PRIVATE KEY')
        for path in BENCH.rglob('*'):
            if path.is_file() and path.suffix in {'.py', '.json', '.js', '.java', '.go', '.php', '.yml', '.yaml', '.tf', '.md'}:
                with self.subTest(path=path.name):
                    self.assertIsNone(pattern.search(path.read_text(encoding='utf-8', errors='replace')))

    def test_lockfile_sources_are_pinned_to_a_commit(self):
        for row in EXPECTED['lockfiles']:
            with self.subTest(name=row['name']):
                self.assertRegex(row['url'], r'^https://raw\.githubusercontent\.com/[^/]+/[^/]+/[0-9a-f]{40}/')
                self.assertIsInstance(row['packages'], int)
                self.assertIsInstance(row['gaps'], int)

    def test_servers_announce_readiness(self):
        for name in ('web_target.py', 'impact_target.py'):
            self.assertIn("print('ready', flush=True)", (BENCH / 'servers' / name).read_text(encoding='utf-8'))

    def test_runner_help_does_no_work(self):
        done = subprocess.run([sys.executable, str(BENCH / 'run.py'), '--help'], capture_output=True, text=True, timeout=60)
        self.assertEqual(done.returncode, 0)
        self.assertIn('--group', done.stdout)


if __name__ == '__main__':
    unittest.main()
