"""Install PMD, the open-source analyser that covers Apex (Salesforce).

OSS Semgrep cannot parse Apex at all -- its Apex support is a paid extension --
so Apex code was named as uncovered. PMD (BSD licence) ships an Apex security
ruleset: SOQL injection, XSS, open redirect, CRUD/sharing violations, insecure
endpoints and hard-coded credentials. It needs a Java runtime.

Integrity: the release is pinned and its SHA-256 is the digest GitHub publishes
for the asset. The release signature (.asc) is not verified -- the same level
as the Trivy and Nuclei installers in this project, and no more is claimed.
"""
import argparse
import hashlib
import io
import json
import shutil
import subprocess
import sys
import urllib.request
import zipfile

from zanjir.engine import ROOT
from zanjir.repo_store import write_json

from zanjir import nettrust

_SSL_CONTEXT = nettrust.ssl_context()

VERSION = '7.27.0'
ARCHIVE = f'pmd-dist-{VERSION}-bin.zip'
URL = f'https://github.com/pmd/pmd/releases/download/pmd_releases%2F{VERSION}/{ARCHIVE}'
SHA256 = '4ae396ffaf2b0d3ef0b73a10b2925e77066f73d57a4ce9078c60e7302bcddec9'
DEST = ROOT / '.tools/pmd'
LIMIT = 200 * 1024 * 1024


def java_available():
    try:
        done = subprocess.run(['java', '-version'], capture_output=True, text=True, timeout=30)
        return done.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def install():
    provenance = DEST / 'provenance.json'
    if provenance.is_file():
        previous = json.loads(provenance.read_text(encoding='utf-8'))
        if previous.get('version') == VERSION:
            print(f'PMD {VERSION} mavjud.')
            return
    if not java_available():
        print('Java topilmadi: PMD uchun Java 8+ kerak. Apex tekshiruvi o‘rnatilmadi.', file=sys.stderr)
        raise SystemExit(1)
    print(f'PMD {VERSION} rasmiy relizi yuklanmoqda ({ARCHIVE}).', flush=True)
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=_SSL_CONTEXT))
    with opener.open(urllib.request.Request(URL, headers={'User-Agent': 'threatchain-setup'}), timeout=300) as response:
        raw = response.read(LIMIT + 1)
    if len(raw) > LIMIT:
        raise ValueError('Arxiv kutilganidan katta.')
    if hashlib.sha256(raw).hexdigest() != SHA256:
        raise ValueError('PMD arxivining SHA-256 mos emas; o‘rnatish to‘xtatildi.')
    staging = DEST.parent / 'pmd.incoming'
    shutil.rmtree(staging, ignore_errors=True)
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        prefix = f'pmd-bin-{VERSION}/'
        for member in archive.infolist():
            if not member.filename.startswith(prefix) or '..' in member.filename:
                continue
            relative = member.filename[len(prefix):]
            if not relative:
                continue
            target = staging / relative
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.read(member))
    for launcher in (staging / 'bin/pmd',):
        if launcher.is_file():
            launcher.chmod(0o755)
    write_json(staging / 'provenance.json', {
        'version': VERSION, 'url': URL, 'archive_sha256': SHA256,
        'verification': 'SHA-256 checked against the digest GitHub publishes for the release asset; .asc signature not verified.'})
    shutil.rmtree(DEST, ignore_errors=True)
    staging.rename(DEST)
    print(f'PMD {VERSION} tayyor: {DEST.relative_to(ROOT)}')


if __name__ == '__main__':
    argparse.ArgumentParser(description='PMD ni o‘rnatish (Apex qamrovi uchun; Java kerak)').parse_args()
    try:
        install()
    except (OSError, ValueError) as error:
        print('Xato:', error, file=sys.stderr)
        raise SystemExit(1)
