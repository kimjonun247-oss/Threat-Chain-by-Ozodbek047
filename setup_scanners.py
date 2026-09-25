"""Install the two scanners every code scan depends on: Semgrep and Gitleaks.

`.tools/` is not versioned, and until now only Trivy, Nuclei, the rule pack and
PMD had installers. A fresh checkout -- or the Windows CI job -- therefore had
no way to obtain Semgrep or Gitleaks at all; on this machine the macOS copies
had been put in place by hand. This script closes that gap for every platform.

  - Gitleaks: pinned release binary, SHA-256 checked against the project's own
    published checksums file over HTTPS (release signature not verified).
  - Semgrep: pinned version installed with pip into a private virtualenv under
    .tools/semgrep, so no global Python is touched. pip fetches it from PyPI
    over HTTPS; hash-pinning (--require-hashes) is not used, and that is stated
    rather than implied.

Each platform keeps its own layout (Windows: gitleaks.exe, semgrep/Scripts;
elsewhere: gitleaks, semgrep/posix/bin) so neither copy disturbs the other.
"""
import argparse
import hashlib
import io
import os
import json
import platform
import ssl
import subprocess
import sys
import tarfile
import urllib.request
import zipfile

from zanjir.engine import ROOT
from zanjir.repo_store import write_json

try:
    import certifi
    _SSL_CONTEXT = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    _SSL_CONTEXT = ssl.create_default_context()

GITLEAKS_VERSION = '8.30.1'
SEMGREP_VERSION = '1.177.0'
IS_WINDOWS = sys.platform.startswith('win')
TOOLS = ROOT / '.tools'


def gitleaks_archive():
    machine = platform.machine().lower()
    arm = machine in ('arm64', 'aarch64')
    if IS_WINDOWS:
        return f'gitleaks_{GITLEAKS_VERSION}_windows_{"arm64" if arm else "x64"}.zip'
    system = 'darwin' if sys.platform == 'darwin' else 'linux'
    return f'gitleaks_{GITLEAKS_VERSION}_{system}_{"arm64" if arm else "x64"}.tar.gz'


def download(url, limit):
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=_SSL_CONTEXT))
    with opener.open(urllib.request.Request(url, headers={'User-Agent': 'threatchain-setup'}), timeout=120) as response:
        raw = response.read(limit + 1)
    if len(raw) > limit:
        raise ValueError('Yuklama hajmi chegaradan oshdi.')
    return raw


def install_gitleaks():
    name = 'gitleaks.exe' if IS_WINDOWS else 'gitleaks'
    binary = TOOLS / 'gitleaks' / name
    # Windows keeps the original provenance.json; other platforms get their own.
    record = TOOLS / 'gitleaks' / ('provenance.json' if IS_WINDOWS else 'provenance-posix.json')
    if binary.is_file() and record.is_file():
        previous = json.loads(record.read_text(encoding='utf-8'))
        if previous.get('version') == GITLEAKS_VERSION and \
                hashlib.sha256(binary.read_bytes()).hexdigest() == previous.get('binary_sha256'):
            return f'Gitleaks {GITLEAKS_VERSION} mavjud; xeshi mos.'
    archive = gitleaks_archive()
    base = f'https://github.com/gitleaks/gitleaks/releases/download/v{GITLEAKS_VERSION}/'
    sums = download(base + f'gitleaks_{GITLEAKS_VERSION}_checksums.txt', 100_000).decode()
    expected = next((line.split()[0] for line in sums.splitlines() if line.split()[-1:] == [archive]), None)
    if not expected or len(expected) != 64:
        raise ValueError('Gitleaks rasmiy checksum topilmadi.')
    raw = download(base + archive, 50 * 1024 * 1024)
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError('Gitleaks arxivining SHA-256 mos emas; o‘rnatish to‘xtatildi.')
    if archive.endswith('.zip'):
        with zipfile.ZipFile(io.BytesIO(raw)) as bundle:
            body = bundle.read(name)
    else:
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as bundle:
            body = bundle.extractfile(bundle.getmember(name)).read()
    binary.parent.mkdir(parents=True, exist_ok=True)
    # Write beside the target and swap in one step: the existing copy may be
    # read-only (a hand-placed Homebrew binary was), and an interrupted write
    # must never leave a half-written scanner behind.
    staging = binary.with_name(binary.name + '.incoming')
    staging.write_bytes(body)
    if not IS_WINDOWS:
        staging.chmod(0o755)
    os.replace(staging, binary)
    write_json(record, {'version': GITLEAKS_VERSION, 'url': base + archive, 'archive_sha256': expected,
                        'binary_sha256': hashlib.sha256(body).hexdigest(),
                        'verification': 'SHA-256 checked against the upstream checksums file over HTTPS; signature not verified.'})
    return f'Gitleaks {GITLEAKS_VERSION} o‘rnatildi ({archive}).'


def semgrep_paths():
    venv = TOOLS / 'semgrep' if IS_WINDOWS else TOOLS / 'semgrep' / 'posix'
    bin_dir = venv / ('Scripts' if IS_WINDOWS else 'bin')
    return venv, bin_dir / ('python.exe' if IS_WINDOWS else 'python'), bin_dir / ('semgrep.exe' if IS_WINDOWS else 'semgrep')


def installed_semgrep(python):
    try:
        done = subprocess.run([str(python), '-m', 'pip', 'show', 'semgrep'], capture_output=True,
                              text=True, encoding='utf-8', errors='replace', timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return next((line.split(':', 1)[1].strip() for line in done.stdout.splitlines() if line.startswith('Version:')), None)


def install_semgrep():
    venv, python, executable = semgrep_paths()
    if executable.is_file() and installed_semgrep(python) == SEMGREP_VERSION:
        return f'Semgrep {SEMGREP_VERSION} mavjud.'
    if not python.is_file():
        subprocess.run([sys.executable, '-m', 'venv', str(venv)], check=True, timeout=600)
    subprocess.run([str(python), '-m', 'pip', 'install', '--disable-pip-version-check', '--quiet',
                    f'semgrep=={SEMGREP_VERSION}'], check=True, timeout=1800)
    if installed_semgrep(python) != SEMGREP_VERSION:
        raise ValueError('Semgrep o‘rnatildi, lekin versiyasi kutilganiga mos emas.')
    write_json(venv / 'provenance.json', {
        'version': SEMGREP_VERSION, 'source': 'PyPI via pip over HTTPS',
        'verification': 'Version pinned; pip --require-hashes not used, so package hashes are not pinned.'})
    return f'Semgrep {SEMGREP_VERSION} o‘rnatildi ({venv.relative_to(ROOT)}).'


def main():
    parser = argparse.ArgumentParser(description='Semgrep va Gitleaks’ni loyiha ichiga o‘rnatish')
    parser.add_argument('--only', choices=['semgrep', 'gitleaks'])
    args = parser.parse_args()
    failed = False
    for name, func in (('gitleaks', install_gitleaks), ('semgrep', install_semgrep)):
        if args.only and args.only != name:
            continue
        try:
            print(func(), flush=True)
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            print(f'{name}: o‘rnatilmadi — {error}', file=sys.stderr)
            failed = True
    raise SystemExit(1 if failed else 0)


if __name__ == '__main__':
    main()
