"""ThreatChain accuracy and target-impact benchmarks.

Runs every scanner against a corpus whose answers are known and compares the
result with benchmarks/expected.json. A drop in what is found, a new false
positive, a changed CI-gate decision or a heavier footprint on the target fails
the run -- so a rule update, a parser change or a scanner upgrade cannot lower
accuracy silently.

    python3 benchmarks/run.py                  # offline group (default)
    python3 benchmarks/run.py --group all      # also lockfiles and a registry image (network)
    python3 benchmarks/run.py --only sast web  # selected checks
    python3 benchmarks/run.py --output results.json

Isolation: everything is written to a temporary THREATCHAIN_DATA_DIR, so the
operator's reports, registrations and triage decisions are never touched. Fake
secrets are generated at run time from a fixed seed -- no token-shaped string is
committed to the repository (it would trip push protection and secret scanners).
A check whose tool is not installed is reported as SKIP, never as a pass.
"""
import argparse
import contextlib
import json
import os
import random
import shutil
import socket
import string
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
DATA = Path(tempfile.mkdtemp(prefix='threatchain-bench-data-'))
os.environ['THREATCHAIN_DATA_DIR'] = str(DATA)       # before any zanjir import
sys.path.insert(0, str(ROOT))

from zanjir import ci_gate, code_targets, iac, images, inventory, nettrust, repo_store, sbom, scanners, webscan  # noqa: E402

EXPECTED = json.loads((HERE / 'expected.json').read_text(encoding='utf-8'))
WORK = Path(tempfile.mkdtemp(prefix='threatchain-bench-work-'))
OFFLINE = ('sast', 'secrets', 'apex', 'iac', 'compose', 'web', 'impact', 'gate')
ONLINE = ('lockfiles', 'jvm_dotnet', 'image')
RESULTS = []


class Skip(Exception):
    pass


def record(name, ok, detail, metrics=None):
    status = 'PASS' if ok else 'FAIL'
    RESULTS.append({'check': name, 'status': status, 'detail': detail, 'metrics': metrics or {}})
    print(f'{status:4} {name}: {detail}', flush=True)


def copy_corpus(name):
    target = WORK / name
    shutil.copytree(HERE / 'corpus' / name, target)
    return target


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


@contextlib.contextmanager
def server(script, *args):
    port = free_port()
    # Readiness is the server's own "ready" line, not a probe connection: the
    # impact target counts every TCP connection, and a probe would be counted.
    process = subprocess.Popen([sys.executable, str(HERE / 'servers' / script), str(port), *args],
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    try:
        if process.stdout.readline().strip() != 'ready':
            raise RuntimeError(script + ' ishga tushmadi')
        yield f'http://127.0.0.1:{port}'
    finally:
        process.terminate()
        process.wait(timeout=10)


def need(ok, why):
    if not ok:
        raise Skip(why)


# --------------------------------------------------------------------------- code
def bench_sast():
    need(scanners.semgrep_exe().is_file() and scanners.gitleaks_exe().is_file(), 'Semgrep/Gitleaks o‘rnatilmagan')
    root = copy_corpus('sast')
    code_targets.register('bench-sast', root)
    report = scanners.start('bench-sast', background=False)
    files = sorted(p.relative_to(root).as_posix() for p in root.rglob('*')
                   if p.is_file() and '__pycache__' not in p.parts)   # compileall / imports leave .pyc
    positives = [f for f in files if not f.startswith('safe/')]
    found = {f['path'] for f in report['findings']}
    gate = {h['subject'] for h in ci_gate.gate_relevant({'stages': [{'kind': 'code', 'report': report}]})}
    safe_noise = sorted({f['path'] for f in report['findings']
                         if f['path'].startswith('safe/') and f.get('severity') in ('ERROR', 'WARNING')})
    spec = EXPECTED['sast']
    mode = 'with_rule_pack' if scanners.registry_manifest() else 'local_rules_only'
    found_count = len(set(positives) & found)
    gate_count = len(set(positives) & gate)
    safe_gate = sorted(g for g in gate if g.startswith('safe/'))
    ok = (len(positives) == spec['positives'] and found_count >= spec[mode]['min_found']
          and gate_count >= spec[mode]['min_gate'] and len(safe_gate) <= spec['max_gate_on_safe_files']
          and len(safe_noise) <= spec['max_error_or_warning_on_safe_files'])
    record('sast', ok, f'{mode}: topildi {found_count}/{len(positives)}, gate {gate_count}, '
                       f'xavfsizda gate {len(safe_gate)}, xavfsizda signal {len(safe_noise)}',
           {'mode': mode, 'found': found_count, 'gate': gate_count, 'missed': sorted(set(positives) - found),
            'safe_gate': safe_gate, 'safe_noise': safe_noise})
    return report


def fake_secrets(folder):
    """Realistic-format fake secrets, generated -- never stored in the repository."""
    r = random.Random(7)
    alnum = string.ascii_letters + string.digits

    def s(chars, n):
        return ''.join(r.choice(chars) for _ in range(n))
    files = {
        'aws.py': f'AWS_ACCESS_KEY_ID = "{"AKIA"}{s("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16)}"\n'
                  f'AWS_SECRET_ACCESS_KEY = "{s(alnum + "/+", 40)}"\n',
        'github.js': f'const token = "{"ghp_"}{s(alnum, 36)}";\n',
        'slack.py': f'SLACK = "{"xoxb-"}{s(string.digits, 12)}-{s(string.digits, 12)}-{s(alnum, 24)}"\n',
        'stripe.rb': f'Stripe.api_key = "{"sk_" + "live_"}{s(alnum, 24)}"\n',
        'google.java': f'class K {{ String k = "{"AI" + "za"}{s(alnum + "-_", 35)}"; }}\n',
        'sendgrid.env': f'SENDGRID_API_KEY={"S" + "G."}{s(alnum + "-_", 22)}.{s(alnum + "-_", 43)}\n',
        'db.yaml': f'database:\n  url: postgres://admin:{s(alnum, 16)}@db.internal:5432/prod\n',
        'generic.py': f'api_secret = "{s(alnum, 32)}"\n',
        'gitlab.sh': f'export GITLAB_TOKEN={"gl" + "pat-"}{s(alnum + "-_", 20)}\n',
        'neg_placeholder.py': 'API_KEY = "YOUR_API_KEY_HERE"\npassword = "changeme"\n',
        'neg_env.py': 'import os\nAWS_SECRET_ACCESS_KEY = os.environ["AWS_SECRET_ACCESS_KEY"]\n',
        'neg_example.py': 'KEY = "' + 'AKIA' + 'IOSFODNN7EXAMPLE"  # AWS documentation example\n',
    }
    for name, text in files.items():
        (folder / name).write_text(text, encoding='utf-8')
    key = subprocess.run(['openssl', 'genrsa', '2048'], capture_output=True, text=True) if shutil.which('openssl') else None
    if key and key.returncode == 0:
        (folder / 'id_rsa').write_text(key.stdout, encoding='utf-8')
    history_token = 'ghp_' + s(alnum, 36)
    return history_token


def bench_secrets():
    need(scanners.gitleaks_exe().is_file() and shutil.which('git'), 'Gitleaks yoki git yo‘q')
    root = WORK / 'secrets'
    root.mkdir()
    history_token = fake_secrets(root)
    git = ['git', '-C', str(root), '-c', 'user.email=bench@threatchain.invalid', '-c', 'user.name=bench',
           '-c', 'commit.gpgsign=false']
    subprocess.run(['git', 'init', '-q', str(root)], check=True)
    subprocess.run(git + ['add', '-A'], check=True)
    subprocess.run(git + ['commit', '-qm', 'init'], check=True)
    (root / 'history.py').write_text(f'TOKEN = "{history_token}"\n', encoding='utf-8')
    subprocess.run(git + ['add', 'history.py'], check=True)
    subprocess.run(git + ['commit', '-qm', 'leak'], check=True)
    subprocess.run(git + ['rm', '-q', 'history.py'], check=True)
    subprocess.run(git + ['commit', '-qm', 'remove'], check=True)
    code_targets.register('bench-secrets', root)
    report = scanners.start('bench-secrets', background=False)
    leaks = {f['path'] for f in report['findings'] if f['tool'] == 'gitleaks'}
    spec = EXPECTED['secrets']
    must = set(spec['must_find']) - ({'id_rsa'} if not (root / 'id_rsa').exists() else set())
    raw = json.dumps(report)
    leaked_value = any(marker in raw for marker in ('ghp_', 'sk_' + 'live_', 'BEGIN RSA', history_token))
    missed, noise = sorted(must - leaks), sorted(set(spec['must_not_find']) & leaks)
    record('secrets', not missed and not noise and not leaked_value,
           f'topildi {len(must & leaks)}/{len(must)} (git tarixi bilan), noto‘g‘ri signal {len(noise)}, '
           f'qiymat hisobotda: {"HA" if leaked_value else "yo‘q"}',
           {'missed': missed, 'false_positives': noise, 'value_in_report': leaked_value})


def bench_apex():
    need(scanners.pmd_exe().is_file() and shutil.which('java'), 'PMD yoki Java yo‘q')
    root = copy_corpus('apex')
    code_targets.register('bench-apex', root)
    report = scanners.start('bench-apex', background=False)
    rules = {f['rule_id'] for f in report['findings'] if f['tool'] == 'pmd'}
    dirty = sorted({Path(f['path']).name for f in report['findings']} & set(EXPECTED['apex']['clean_files']))
    missing = sorted(set(EXPECTED['apex']['must_find_rules']) - rules)
    record('apex', not missing and not dirty, f'PMD qoidalari {sorted(rules)}, xavfsiz faylda {len(dirty)}',
           {'missing': missing, 'dirty': dirty})


def bench_iac():
    need(images.BINARY.is_file(), 'Trivy o‘rnatilmagan')
    root = copy_corpus('iac')
    code_targets.register('bench-iac', root)
    report = iac.start('bench-iac', background=False)
    rules = {f['rule_id'] for f in report['findings']}
    missing = sorted(set(EXPECTED['iac']['must_find']) - rules)
    ok = report['state'] == 'completed' and len(report['findings']) >= EXPECTED['iac']['min_findings'] and not missing
    record('iac', ok, f"{report['state']}, {len(report['findings'])} topilma, yetishmagan {missing}",
           {'findings': len(report['findings']), 'missing': missing})


# ---------------------------------------------------------------------- compose
def bench_compose():
    rules, safe = {}, None
    for name in ('compose', 'compose-safe'):
        root = copy_corpus(name)
        bindings = json.loads((root / 'bindings.json').read_text(encoding='utf-8'))
        repo_store.register_project('bench-' + name, root, 'docker-compose.yml', bindings=bindings)
        report = repo_store.scan_profile('bench-' + name)
        if name == 'compose':
            for f in report['findings']:
                rules[f['rule_id']] = rules.get(f['rule_id'], 0) + 1
        else:
            safe = len(report['findings'])
    spec = EXPECTED['compose']
    missing = sorted(set(spec['rules']) - set(rules))
    ok = not missing and rules.get('RP-005') == spec['rp005_findings'] and safe == spec['safe_findings']
    record('compose', ok, f'qoidalar {len(set(rules) & set(spec["rules"]))}/{len(spec["rules"])}, '
                          f'RP-005 {rules.get("RP-005")}, xavfsiz Compose {safe}', {'rules': rules, 'safe': safe})


# -------------------------------------------------------------------------- web
def web_scan(target_id, url):
    webscan.register(target_id, url, 'ThreatChain benchmark', allow_private=True, replace=True)
    return webscan.start(target_id, background=False)


def bench_web():
    need(webscan.BINARY.is_file(), 'Nuclei o‘rnatilmagan')
    got, confirmation = {}, {}
    for mode in ('vuln', 'fixed'):
        with server('web_target.py', mode) as url:
            report = web_scan('bench-web-' + mode, url)
            got[mode] = {f['rule_id'] for f in report['findings']}
            confirmation[mode] = report.get('confirmation_summary') or {}
    spec = EXPECTED['web']
    missing = sorted(set(spec['vulnerable_must_find']) - got['vuln'])
    # Every theoretical finding on the vulnerable site is real, so the second
    # look must confirm all of them -- a regression in a structure check shows here.
    confirmed = confirmation['vuln'].get('confirmed', 0)
    doubted = confirmation['vuln'].get('not_reproduced', 0) + confirmation['vuln'].get('inconclusive', 0)
    ok = not missing and got['fixed'] == set(spec['fixed_exactly']) and \
        confirmed >= spec['min_confirmed'] and doubted == 0
    record('web', ok, f'zaif sayt: yetishmagan {missing}, ikkinchi GET tasdiqladi {confirmed} (shubhali {doubted}); '
                      f'tuzatilgan sayt: {sorted(got["fixed"])}',
           {'vulnerable': sorted(got['vuln']), 'fixed': sorted(got['fixed']), 'confirmation': confirmation['vuln']})


def bench_impact():
    need(webscan.BINARY.is_file(), 'Nuclei o‘rnatilmagan')
    spec = EXPECTED['impact']
    seen = {}
    for mode in ('normal', 'overloaded', 'slow'):
        stats = WORK / f'impact-{mode}.json'
        with server('impact_target.py', mode, str(stats)) as url:
            report = web_scan('bench-impact-' + mode, url)
        target = json.loads(stats.read_text(encoding='utf-8'))
        seen[mode] = {'state': report['state'], 'requests': target['requests'], 'connections': target['connections'],
                      'peak': target['peak'], 'stopped': report['impact']['stopped'],
                      'slowdowns': len(report['impact']['slowdowns'])}
    ok = (seen['normal']['connections'] <= spec['keepalive_max_connections']
          and all(row['peak'] == 1 for row in seen.values())
          and seen['overloaded']['requests'] <= spec['overloaded_max_requests']
          and seen['overloaded']['stopped'] == spec['overloaded_stop']
          and seen['slow']['state'] == spec['slow_state'] and seen['slow']['slowdowns'] <= spec['slow_max_slowdowns'])
    record('impact', ok, f"oddiy: {seen['normal']['requests']} so‘rov/{seen['normal']['connections']} ulanish; "
                         f"band server: {seen['overloaded']['requests']} so‘rov, to‘xtadi={seen['overloaded']['stopped']}; "
                         f"sekin: {seen['slow']['state']}, sekinlashuv {seen['slow']['slowdowns']}", seen)


# ------------------------------------------------------------------------- gate
def gate_exit(*args):
    done = subprocess.run([sys.executable, str(ROOT / 'ci_gate.py'), *args, '--sarif-out', str(WORK / 'gate.sarif')],
                          capture_output=True, text=True, cwd=ROOT, env={**os.environ}, timeout=1200)
    return done.returncode


def bench_gate():
    need(webscan.BINARY.is_file() and scanners.semgrep_exe().is_file(), 'Nuclei/Semgrep yo‘q')
    if not any(p['id'] == 'bench-sast' for p in code_targets.profiles()):
        code_targets.register('bench-sast', copy_corpus('sast'))
    codes = {}
    for mode, key in (('fixed', 'web-fixed'), ('vuln', 'web-vulnerable')):
        with server('web_target.py', mode) as url:
            webscan.register('bench-gate-' + mode, url, 'ThreatChain benchmark', allow_private=True, replace=True)
            codes[key] = gate_exit('--web-target', 'bench-gate-' + mode)
    codes['sast'] = gate_exit('--target', 'bench-sast', '--allow-partial')
    ok = codes == EXPECTED['gate']
    record('gate', ok, f'chiqish kodlari {codes} (kutilgan {EXPECTED["gate"]})', codes)


# ----------------------------------------------------------------------- online
def download(url, target):
    opener = urllib.request.build_opener(nettrust.proxy_handler(),
                                         urllib.request.HTTPSHandler(context=nettrust.ssl_context()))
    with opener.open(url, timeout=120) as response:
        target.write_bytes(response.read(64 * 1024 * 1024))


def bench_lockfiles():
    failures = []
    for row in EXPECTED['lockfiles']:
        folder = WORK / ('lock-' + str(abs(hash(row['url']))))
        folder.mkdir()
        try:
            download(row['url'], folder / row['file'])
        except OSError as error:
            raise Skip(f'yuklab bo‘lmadi: {type(error).__name__}')
        data = inventory.collect(folder)
        got = {'packages': data['occurrences'], 'gaps': len(data['gaps'])}
        want = {'packages': row.get('packages'), 'gaps': row.get('gaps')}
        if got != want or any(m['state'] == 'invalid' for m in data['manifests']):
            failures.append(f"{row['name']}: {got} != {want}")
        print(f"     {row['name']}: {got['packages']} paket, {got['gaps']} bo‘shliq", flush=True)
    record('lockfiles', not failures, 'hammasi kutilganidek' if not failures else '; '.join(failures))



def bench_jvm_dotnet():
    """Maven/Gradle build-tool output and NuGet locks, end to end against OSV."""
    from zanjir import advisories
    spec = EXPECTED['jvm_dotnet']
    failures, metrics = [], {}
    for folder, want in spec['projects'].items():
        data = inventory.collect(HERE / 'corpus' / 'jvm-dotnet' / folder)
        matches, details, errors, _ = advisories.query_packages(data['packages'])
        if errors and all(e.get('reason') == 'osv_query_incomplete' for e in errors) and not matches:
            raise Skip('OSV ga ulanib bo‘lmadi')
        findings = advisories.normalize(data['packages'], matches, details, {}, False)
        text = json.dumps(findings)
        missing = [cve for cve in want['must_find'] if cve not in text]
        got = {'packages': data['unique_packages'], 'gaps': [g['reason'] for g in data['gaps']]}
        if got != {'packages': want['packages'], 'gaps': want['gaps']} or missing or errors:
            failures.append(f"{folder}: {got}, topilmadi {missing}, xato {len(errors)}")
        metrics[folder] = {'packages': got['packages'], 'findings': len(findings)}
        print(f"     {folder}: {got['packages']} paket, {len(findings)} topilma, yetishmagan {missing}", flush=True)
    record('jvm_dotnet', not failures, 'hammasi kutilganidek' if not failures else '; '.join(failures), metrics)


def bench_image():
    need(images.BINARY.is_file(), 'Trivy o‘rnatilmagan')
    spec = EXPECTED['image']
    images.register('bench-image', spec['reference'], replace=True)
    report = images.start('bench-image', background=False)
    need(report['state'] in ('completed', 'partial'), f"image skan: {report['state']}")
    direct = subprocess.run([str(images.BINARY), 'image', '--disable-telemetry', '--skip-version-check', '--skip-db-update',
                             '--cache-dir', str(images.CACHE), '-q', '-f', 'json', spec['reference']],
                            capture_output=True, text=True, timeout=1200)
    rows = json.loads(direct.stdout)['Results']
    want = {(v['PkgName'], v['InstalledVersion'], v['VulnerabilityID']) for r in rows for v in (r.get('Vulnerabilities') or [])}
    got = {(f['package'], f['version'], f['advisory_id']) for f in report['findings']}
    document = sbom.build(report)
    refs = {c['bom-ref'] for c in document['components']}
    sbom_ok = len(document['vulnerabilities']) == len(got) and all(
        a['ref'] in refs for v in document['vulnerabilities'] for a in v.get('affects', []))
    ok = got == want and len(got) >= spec['min_findings'] and sbom_ok
    record('image', ok, f'ThreatChain {len(got)} / to‘g‘ridan-to‘g‘ri Trivy {len(want)}, SBOM mos: {sbom_ok}',
           {'only_threatchain': len(got - want), 'only_trivy': len(want - got)})


CHECKS = {'sast': bench_sast, 'secrets': bench_secrets, 'apex': bench_apex, 'iac': bench_iac,
          'compose': bench_compose, 'web': bench_web, 'impact': bench_impact, 'gate': bench_gate,
          'lockfiles': bench_lockfiles, 'jvm_dotnet': bench_jvm_dotnet, 'image': bench_image}


def main():
    parser = argparse.ArgumentParser(description='ThreatChain aniqlik va nishonga ta’sir benchmarklari')
    parser.add_argument('--group', choices=('offline', 'online', 'all'), default='offline')
    parser.add_argument('--only', nargs='+', choices=sorted(CHECKS))
    parser.add_argument('--output', help='natijani JSON faylga yozish')
    parser.add_argument('--keep', action='store_true', help='vaqtinchalik papkalarni o‘chirmaslik')
    parser.add_argument('--summary', help='Markdown jadvalni shu faylga qo‘shish (CI: $GITHUB_STEP_SUMMARY)')
    args = parser.parse_args()
    names = args.only or ({'offline': OFFLINE, 'online': ONLINE, 'all': OFFLINE + ONLINE}[args.group])
    print(f'Ma’lumotlar papkasi (vaqtinchalik): {DATA}', flush=True)
    started = time.monotonic()
    try:
        for name in names:
            try:
                CHECKS[name]()
            except Skip as reason:
                RESULTS.append({'check': name, 'status': 'SKIP', 'detail': str(reason), 'metrics': {}})
                print(f'SKIP {name}: {reason}', flush=True)
            except Exception as error:  # noqa: BLE001 -- a crashed check is a failed check
                record(name, False, f'yiqildi: {type(error).__name__}: {error}')
    finally:
        if not args.keep:
            shutil.rmtree(DATA, ignore_errors=True)
            shutil.rmtree(WORK, ignore_errors=True)
    summary = {k: sum(r['status'] == k for r in RESULTS) for k in ('PASS', 'FAIL', 'SKIP')}
    print(f"\nNatija: {summary['PASS']} o‘tdi, {summary['FAIL']} yiqildi, {summary['SKIP']} o‘tkazildi "
          f"· {round(time.monotonic() - started)} s", flush=True)
    if args.summary:
        icons = {'PASS': '✅', 'FAIL': '❌', 'SKIP': '⏭️'}
        lines = ['### ThreatChain benchmarklari', '', '| | Tekshiruv | Natija |', '|---|---|---|']
        lines += [f"| {icons[r['status']]} | `{r['check']}` | {str(r['detail']).replace('|', '/')} |" for r in RESULTS]
        lines += ['', f"**{summary['PASS']} o‘tdi · {summary['FAIL']} yiqildi · {summary['SKIP']} o‘tkazildi**", '']
        with open(args.summary, 'a', encoding='utf-8') as handle:
            handle.write('\n'.join(lines) + '\n')
    if args.output:
        Path(args.output).write_text(json.dumps({'summary': summary, 'results': RESULTS}, ensure_ascii=False, indent=2),
                                     encoding='utf-8')
    raise SystemExit(1 if summary['FAIL'] else 0)


if __name__ == '__main__':
    main()
