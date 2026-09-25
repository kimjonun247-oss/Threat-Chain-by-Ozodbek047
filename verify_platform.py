"""End-to-end check that every scanner really runs on *this* operating system.

The project ships separate tool builds for Windows and for macOS/Linux, and the
Windows side has only ever been checked from macOS -- by path logic and by
confirming the vendored files are real Windows executables. Neither proves a
scan runs. This script does: it executes each tool and a chain of real scans
on whichever machine it is started on, and writes the outcome to
validation-runs/platform-<os>.json.

Run it once on Windows (VERIFY-WINDOWS.cmd) and the remaining open item is
closed with evidence rather than inference.
"""
import argparse
import json
import os
import platform
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))


def step(name, func):
    started = time.monotonic()
    try:
        detail = func()
        ok = True
    except Exception as error:                       # noqa: BLE001 - every failure is a recorded result
        detail = f'{type(error).__name__}: {error}'[:400]
        ok = False
    row = {'step': name, 'passed': ok, 'seconds': round(time.monotonic() - started, 1), 'detail': detail}
    print(f"  {'OK  ' if ok else 'FAIL'} {name:34s} {row['seconds']:6.1f}s  {str(detail)[:70]}", flush=True)
    return row


def run(args, timeout=900):
    done = subprocess.run([sys.executable, *args], cwd=ROOT, capture_output=True, text=True,
                          encoding='utf-8', errors='replace', timeout=timeout)
    return done


def tool_versions():
    from zanjir import scanners, images, webscan
    found = {}
    for name, path, flag in (('semgrep', scanners.semgrep_exe(), '--version'),
                             ('gitleaks', scanners.gitleaks_exe(), 'version'),
                             ('trivy', images.BINARY, '--version'),
                             ('nuclei', webscan.BINARY, '-version'),
                             ('pmd', scanners.pmd_exe(), '--version')):
        if name == 'pmd' and not path.is_file():
            found[name] = 'o‘rnatilmagan (ixtiyoriy, Apex uchun)'
            continue
        if not path.is_file():
            raise FileNotFoundError(f'{name}: {path} yo‘q (setup_all.py ni ishga tushiring)')
        # Same no-phone-home settings the scans use: a version probe must not
        # become the one call that reaches a vendor server.
        env = {**os.environ, 'SEMGREP_ENABLE_VERSION_CHECK': '0', 'SEMGREP_SEND_METRICS': 'off'}
        # Trivy's --disable-telemetry belongs to its scan commands, not to --version.
        args = [str(path), flag] + (['-duc', '-nc'] if name == 'nuclei' else [])
        done = subprocess.run(args, capture_output=True, text=True, encoding='utf-8',
                              errors='replace', timeout=120, env=env)
        text = [line for line in (done.stdout + done.stderr).strip().splitlines() if line.strip()]
        if done.returncode != 0:
            raise RuntimeError(f'{name} ishga tushmadi (kod {done.returncode})')
        # Nuclei colours its banner even with -nc; strip terminal escapes.
        # Take the line that carries a version: PMD opens with an ASCII banner and
        # Nuclei colours its output even with -nc.
        plain = [re.sub(r'\x1b\[[0-9;]*m', '', line) for line in text]
        found[name] = next((line for line in plain if re.search(r'\d+\.\d+\.\d+', line)), 'ok')[:60]
    return found


def unit_tests():
    done = run(['-m', 'unittest', 'discover', '-s', 'tests'], timeout=1800)
    tail = (done.stderr or '').strip().splitlines()[-3:]
    if done.returncode != 0:
        raise AssertionError(' | '.join(tail))
    return ' '.join(line for line in tail if line.startswith('Ran'))


def code_scan():
    done = run(['scan_code.py', '--target', 'chain-demo'])
    report = json.loads(done.stdout)
    tools = {name: t['state'] for name, t in report['tools'].items()}
    # The demo yields 3+ findings only with the official semgrep-rules pack; with
    # the local rules alone Gitleaks' planted key is the one guaranteed match.
    # Requiring 3 without the pack failed every machine where the optional pack
    # could not be downloaded, which said nothing about the platform itself.
    from zanjir import readiness
    pack = bool(readiness.status().get('semgrep_rule_pack', {}).get('installed'))
    expected = 3 if pack else 1
    if report['state'] != 'completed' or report['count'] < expected:
        raise AssertionError(f"kutilgan: completed, >={expected} topilma; olindi: {report['state']}, {report['count']}")
    return {'count': report['count'], 'tools': tools, 'semgrep_rule_pack': pack}


def chain_rules():
    from zanjir import pipeline
    result = pipeline.start({'target': 'chain-demo', 'repository_target': 'chain-demo', 'web_target': '',
                             'image_target': '', 'online': True}, background=False)
    repo = next(s for s in result['stages'] if s['kind'] == 'repository')['report']
    rules = sorted({f['rule_id'] for f in repo['findings']})
    chain = [f['rule_id'] for f in result.get('chain_findings') or []]
    expected = {'RP-001', 'RP-005', 'RP-006', 'RP-007', 'RP-008'}
    if not expected <= set(rules) or chain != ['SX-001']:
        raise AssertionError(f'RP={rules} SX={chain}')
    return {'repository_rules': rules, 'chain': chain}


def image_chains():
    """SX-002/SX-003 over a real Compose parse and a synthetic image report.

    The Compose side is real: the bundled chain-demo file is parsed by the actual
    repository scanner. The image side is synthetic on purpose -- pulling and
    scanning a real image would make this check depend on a registry, several
    gigabytes of disk and ten minutes, and what is being verified here is the
    correlation, not Trivy.
    """
    from zanjir import chains, repo_store
    report = repo_store.scan_profile('chain-demo')
    exposed = [s['id'] for s in chains.exposed_services(report)]
    if not exposed:
        raise AssertionError('chain-demo namunasida ochiq xizmat yo‘q')
    service = exposed[0]
    image = {'id': '20260101T000000-aaaaaaaa', 'target': 'verify-image', 'state': 'completed',
             'reference': 'acme/app@sha256:' + 'a' * 64, 'kev': {'state': 'available'},
             'findings': [{'advisory_id': 'CVE-2026-1', 'package': 'openssl', 'version': '1.0.0',
                           'severity': 'CRITICAL', 'known_exploited': True, 'kev_added_on': '2026-01-01',
                           'epss': {'epss': 0.9, 'percentile': 0.99}, 'fixed_version': '1.0.1'}]}
    links = {'verify-image': {'service': service, 'how': 'declared'}}
    rp006 = {f['service_id'] for f in report['findings'] if f['rule_id'] == 'RP-006'}
    rows, gaps = chains.image_chains(report, {'verify-image': image}, links, rp006)
    got = sorted(r['rule_id'] for r in rows)
    expected = ['SX-002', 'SX-003'] if service in rp006 else ['SX-002']
    if got != expected:
        raise AssertionError(f'SX={got}, kutilgan {expected}')
    # An image nobody could link to a service must be reported, never skipped.
    _, unlinked = chains.image_chains(report, {'verify-image': image}, {}, rp006)
    if [g['kind'] for g in unlinked] != ['image_unlinked']:
        raise AssertionError(f'bog‘lanmagan image uchun bo‘shliq yo‘q: {unlinked}')
    return {'service': service, 'chain': got, 'gaps': [g['kind'] for g in gaps]}


def iac_stage():
    """Trivy's config mode over the bundled sample, plus the SBOM builder.

    Both are real: Trivy actually runs against the sample's Dockerfile, and the
    SBOM is built by the same code the API serves. The SBOM input is a small
    fixed package list rather than a fresh image scan -- pulling an image here
    would add ten minutes and a registry dependency to a platform check.
    """
    from zanjir import iac as iac_mod, repository, sbom
    report = iac_mod.start('chain-demo', background=False)
    if report['state'] != 'completed':
        raise AssertionError(f"IaC holati: {report['state']} · {report.get('message')}")
    checks = sorted({f['rule_id'] for f in report['findings']})
    if not checks:
        raise AssertionError('chain-demo Dockerfile uchun birorta tekshiruv ishlamadi')
    document = sbom.build({'id': 'verify', 'target': 'verify', 'reference': 'acme/app@sha256:' + 'a' * 64,
                           'packages': [{'name': 'openssl', 'version': '3.0.1',
                                         'purl': 'pkg:apk/alpine/openssl@3.0.1', 'type': 'alpine',
                                         'target': 'rootfs', 'licenses': ['MIT']}]})
    if (document['bomFormat'], document['specVersion'], len(document['components'])) != ('CycloneDX', '1.6', 1):
        raise AssertionError(f'SBOM noto‘g‘ri: {document["bomFormat"]} {document["specVersion"]}')
    config = ('server { add_header Strict-Transport-Security "max-age=1"; '
              'location /files { alias /var/data/; } '
              'location /api { add_header X-Cache HIT; proxy_pass http://$http_x_target; } }')
    nginx = sorted({i['rule'] for i in repository.nginx_checks(repository.nginx_tree(config, {}))})
    if nginx != ['RP-009', 'RP-010', 'RP-011']:
        raise AssertionError(f'nginx qoidalari: {nginx}')
    return {'iac_checks': checks, 'sbom': document['specVersion'], 'nginx_rules': nginx}


def remote_targets():
    """B6: a real remote clone, and the three credential boundaries.

    The clone is real -- a small public repository over https -- because the
    part that breaks in practice is git's own behaviour, not our wrapper. The
    credential checks are local: what matters is that a value read from the
    environment never reaches a profile, a report or an error message.
    """
    import os
    import shutil as shutil_mod
    from zanjir import code_targets, images as images_mod, remote_source, webscan as web
    secret = 'PLATFORM-CHECK-SECRET-4417'

    path, provenance = remote_source.clone('https://github.com/octocat/Hello-World.git')
    try:
        if not re.fullmatch(r'[0-9a-f]{40}', str(provenance.get('commit'))):
            raise AssertionError(f'commit yozilmadi: {provenance.get("commit")}')
        if not (path / 'README').is_file():
            raise AssertionError('klon bo‘sh')
    finally:
        shutil_mod.rmtree(path.parent, ignore_errors=True)
    if path.exists():
        raise AssertionError('klon o‘chirilmadi')

    for bad in ('ext::sh -c whoami', 'file:///etc', f'https://u:{secret}@host/a/b'):
        try:
            remote_source.check_url(bad)
            raise AssertionError(f'rad etilmadi: {bad}')
        except ValueError as error:
            if secret in str(error):
                raise AssertionError('xato xabarida sir chiqdi')

    if images_mod.parse_reference('alpine:3.20')['pinned']:
        raise AssertionError('teg pinned deb belgilandi')
    user_var, password_var = images_mod.credential_names('registry.example.test')
    os.environ[user_var], os.environ[password_var] = 'u', secret
    try:
        env, meta = images_mod.registry_credentials('registry.example.test', 'environment')
        if env.get('TRIVY_PASSWORD') != secret or secret in json.dumps(meta, ensure_ascii=False):
            raise AssertionError('registry kirish ma’lumoti metadata’ga sizdi')
    finally:
        os.environ.pop(user_var, None)
        os.environ.pop(password_var, None)

    variable = web.auth_variable('platform-check')
    os.environ[variable] = 'Bearer ' + secret
    try:
        headers, meta = web.auth_for({'id': 'platform-check', 'authenticated': True})
        if headers['Authorization'] != 'Bearer ' + secret or secret in json.dumps(meta, ensure_ascii=False):
            raise AssertionError('web tokeni metadata’ga sizdi')
    finally:
        os.environ.pop(variable, None)
    web.USER_AGENT.encode('latin-1')
    return {'commit': provenance['commit'], 'clone_removed': True,
            'credential_sources': ['environment'], 'user_agent': web.USER_AGENT}


def nuclei_control():
    done = run(['validate_web.py'], timeout=900)
    if done.returncode != 0:
        raise AssertionError((done.stderr or done.stdout)[-300:])
    return 'haqiqiy Nuclei sun’iy nazoratda ishladi'


def ci_gate():
    codes = {}
    for label, args in (('to‘xtatadi', ['--allow', '0']), ('o‘tkazadi', ['--allow', '99'])):
        done = run(['ci_gate.py', '--target', 'chain-demo', '--repository-target', 'chain-demo',
                    *args, '--sarif-out', str(ROOT / 'validation-runs' / 'platform-gate.sarif')])
        codes[label] = done.returncode
    if codes != {'to‘xtatadi': 1, 'o‘tkazadi': 0}:
        raise AssertionError(f'chiqish kodlari: {codes}')
    return codes


def main():
    parser = argparse.ArgumentParser(description='Joriy OS da barcha skanerlarni uchidan-uchigacha tekshirish')
    parser.add_argument('--skip-tests', action='store_true', help='Unit testlarni o‘tkazib yuborish (tezroq)')
    args = parser.parse_args()
    system = platform.system().lower() or sys.platform
    print(f'ThreatChain platforma tekshiruvi: {platform.system()} {platform.release()} · '
          f'{platform.machine()} · Python {platform.python_version()}', flush=True)
    steps = [step('Vositalar ishga tushadi', tool_versions)]
    if not args.skip_tests:
        steps.append(step('Unit testlar', unit_tests))
    steps += [step('Kod skani (Semgrep + Gitleaks)', code_scan),
              step('Zanjir qoidalari + SX-001', chain_rules),
              step('Image zanjirlari (SX-002/003)', image_chains),
              step('IaC + SBOM + nginx qoidalari', iac_stage),
              step('Masofaviy nishonlar va kirish chegaralari', remote_targets),
              step('Nuclei nazorat sinovi', nuclei_control),
              step('CI gate chiqish kodlari', ci_gate)]
    result = {'platform': system, 'release': platform.release(), 'machine': platform.machine(),
              'python': platform.python_version(), 'created_at': time.strftime('%Y-%m-%dT%H:%M:%S%z'),
              'passed': all(s['passed'] for s in steps), 'steps': steps,
              'scope': 'Haqiqiy vositalar shu OS da ishga tushirildi. Docker va jonli web nishon talab qilinmaydi.'}
    out = ROOT / 'validation-runs' / f'platform-{system}.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    print(f"\n{'HAMMASI O‘TDI' if result['passed'] else 'YIQILGAN QADAM BOR'} · natija: {out.relative_to(ROOT)}")
    raise SystemExit(0 if result['passed'] else 1)


if __name__ == '__main__':
    main()
