"""Findings-board load test: paging, search and filters on 100 000+ findings.

    python benchmarks/board_load.py                    # 120 000 findings, 4 targets
    python benchmarks/board_load.py --per-target 50000 --targets 3

Runs in a temporary THREATCHAIN_DATA_DIR; the reports are synthetic (varied
severities, rules, paths, CWE/OWASP tags), served to the board the same way the
code-scan reports are. Prints the cold build time and, for each query, the
median and the worst of several runs. Nothing is asserted here: the thresholds
live in tests/test_load_findings.py and BETA_READINESS.md quotes these numbers.
"""
import argparse
import json
import os
import random
import statistics
import sys
import tempfile
import time
from pathlib import Path

os.environ['THREATCHAIN_DATA_DIR'] = tempfile.mkdtemp(prefix='tc-board-load-')
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from unittest.mock import patch  # noqa: E402

from zanjir import engine, findings_index, findings_store  # noqa: E402

assert str(engine.DATA) != str(engine.ROOT), 'data dir not isolated'

SEVERITIES = ['ERROR', 'WARNING', 'INFO']
RULES = [f'python.lang.security.rule-{n}' for n in range(120)]
WORDS = ['sql', 'eval', 'pickle', 'yaml', 'subprocess', 'token', 'xss', 'redirect', 'crypto', 'jwt']
OWASP = [['A03:2021 - Injection'], ['A02:2021 - Cryptographic Failures'], ['A07:2021'], []]


def report(target, rid, count, seed):
    rnd = random.Random(seed)
    findings = []
    for n in range(count):
        word = rnd.choice(WORDS)
        findings.append({'fingerprint': f'{seed:02x}{n:022x}', 'rule_id': rnd.choice(RULES) + '-' + word,
                         'severity': rnd.choice(SEVERITIES), 'path': f'pkg{n % 400}/mod_{word}_{n % 97}.py',
                         'line': n % 900 + 1, 'tool': 'semgrep', 'message': f'{word} misuse number {n}',
                         'cwe_ids': [f'CWE-{rnd.choice([89, 78, 79, 502, 798])}'], 'owasp_top10_2025': rnd.choice(OWASP)})
    return {'id': rid, 'target': target, 'state': 'completed', 'created_at': '2026-01-01T00:00:00+00:00',
            'findings': findings}


def timed(fn, repeat):
    times = []
    for _ in range(repeat):
        started = time.perf_counter()
        result = fn()
        times.append(time.perf_counter() - started)
    return result, round(statistics.median(times) * 1000), round(max(times) * 1000)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--targets', type=int, default=4)
    parser.add_argument('--per-target', type=int, default=30000)
    parser.add_argument('--repeat', type=int, default=5)
    parser.add_argument('--output')
    args = parser.parse_args()
    ids = {f't{n}': f'20260101T000000-{n:08x}' for n in range(args.targets)}
    cache = {}

    def read(rid):
        if rid not in cache:
            target = next(t for t, i in ids.items() if i == rid)
            cache[rid] = report(target, rid, args.per_target, int(target[1:]) + 1)
        return cache[rid]
    world = {'code': (read, lambda limit: [{'id': rid, 'target': t, 'state': 'completed'} for t, rid in ids.items()], 'target')}
    patches = [patch.object(findings_index, 'sources', lambda: world),
               patch.object(findings_index, 'registered', lambda stage: set(ids) if stage == 'code' else set()),
               patch.object(findings_index, 'chain_rows', lambda stage: []),
               patch.object(findings_index, 'project_of', lambda stage, target: '_' + target)]
    for p in patches:
        p.start()
    for rid in ids.values():          # report generation is not part of the board's cost
        read(rid)
    findings_index.invalidate()
    started = time.perf_counter()
    total = findings_index.search()['total']
    cold = round(time.perf_counter() - started, 1)
    queries = {
        'page 1': lambda: findings_index.search(limit=50),
        'deep page (offset total-100)': lambda: findings_index.search(offset=max(0, total - 100), limit=50),
        'text "pickle"': lambda: findings_index.search(query='pickle'),
        'text two words': lambda: findings_index.search(query='sql pkg12/'),
        'severity=HIGH': lambda: findings_index.search(filters={'severity': 'HIGH'}),
        'project=_t1': lambda: findings_index.search(filters={'project': '_t1'}),
        'status=untriaged': lambda: findings_index.search(filters={'status': 'untriaged'}),
        'owasp=A03': lambda: findings_index.search(filters={'owasp': 'A03'}),
        'combo text+severity+project': lambda: findings_index.search(query='eval', filters={'severity': 'HIGH', 'project': '_t0'}),
        'detail by fingerprint': lambda: findings_index.detail('01' + '0' * 21 + '7'),
    }
    rows = {}
    for name, fn in queries.items():
        result, median, worst = timed(fn, args.repeat)
        count = result.get('total') if isinstance(result, dict) and 'total' in result else None
        rows[name] = {'median_ms': median, 'max_ms': worst, 'matches': count}
        print(f'{name:32} median {median:6d} ms   max {worst:6d} ms   matches {count}', flush=True)
    out = {'findings': total, 'targets': args.targets, 'cold_build_s': cold, 'queries': rows,
           'db_mb': round(findings_store._path().stat().st_size / 2 ** 20, 1)}
    print(json.dumps({k: v for k, v in out.items() if k != 'queries'}))
    if args.output:
        Path(args.output).write_text(json.dumps(out, indent=1), encoding='utf-8')
    for p in patches:
        p.stop()


if __name__ == '__main__':
    main()
