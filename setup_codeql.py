"""Install the pinned CodeQL bundle (optional deep-analysis stage).

CodeQL adds what Semgrep's open-source engine cannot do: taint tracking
across files and functions (a request parameter in one module reaching a
query or a template in another). It is optional because it is large (~0.9 GB
download, ~2 GB on disk), slow (minutes per project) and licensed separately:

    CodeQL may be used free of charge on open-source code and for academic
    research. Analysing private/commercial code requires a GitHub Advanced
    Security licence. Read https://github.com/github/codeql-cli-binaries/blob/main/LICENSE.md
    before enabling it for such code.

    python3 setup_codeql.py            # download, verify SHA-256, unpack into .tools/codeql
    python3 setup_codeql.py --check    # report what is installed

The archive's SHA-256 is pinned here and must also match the checksum GitHub
publishes next to it; nothing is unpacked before both agree, and no path in
the archive may leave the destination.
"""
import argparse
import hashlib
import json
import shutil
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

from zanjir import nettrust
from zanjir.engine import ROOT

VERSION = '2.27.1'
BASE = f'https://github.com/github/codeql-action/releases/download/codeql-bundle-v{VERSION}/'
SHA256 = {
    'codeql-bundle-linux64.tar.gz': '1d380f79896ededc654c7b21fafb3360136f1aeb678ad4df4df9af3910c6b815',
    'codeql-bundle-osx64.tar.gz': 'bca7fe16689986793b8bbc75cf1e0809497b9baed7f10cde42f403eca1390c0a',
    'codeql-bundle-win64.tar.gz': '721209b52b74d0cf742c701eeb452a70f570f236c75dda6087bd4ad2a6f97202',
}
DEST = ROOT / '.tools/codeql'
LIMIT = 2 * 1024 ** 3


def archive_name():
    if sys.platform.startswith('win'):
        return 'codeql-bundle-win64.tar.gz'
    if sys.platform == 'darwin':
        return 'codeql-bundle-osx64.tar.gz'
    return 'codeql-bundle-linux64.tar.gz'


def opener():
    return urllib.request.build_opener(nettrust.proxy_handler(),
                                       urllib.request.HTTPSHandler(context=nettrust.ssl_context()))


def download(url, target):
    """Stream to `target`; returns the SHA-256. The archive never sits in memory."""
    digest = hashlib.sha256()
    total = 0
    request = urllib.request.Request(url, headers={'User-Agent': 'ThreatChain-setup/0.7'})
    with opener().open(request, timeout=120) as response, open(target, 'wb') as handle:
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > LIMIT:
                raise ValueError('Yuklama hajmi chegaradan oshdi.')
            digest.update(chunk)
            handle.write(chunk)
            if total % (100 * 1024 * 1024) < 1024 * 1024:
                print(f'  {total // (1024 * 1024)} MB', flush=True)
    return digest.hexdigest()


def safe_members(archive, destination):
    root = destination.resolve()
    for member in archive.getmembers():
        target = (root / member.name).resolve()
        if not target.is_relative_to(root):
            raise ValueError(f'Arxivda chegaradan chiquvchi yo‘l: {member.name}')
        if member.issym() or member.islnk():
            link = (target.parent / member.linkname).resolve() if member.issym() else (root / member.linkname).resolve()
            if not link.is_relative_to(root):
                raise ValueError(f'Arxivda chegaradan chiquvchi havola: {member.name}')
        yield member


def binary():
    return DEST / 'codeql' / ('codeql.exe' if sys.platform.startswith('win') else 'codeql')


def install(force=False):
    name = archive_name()
    provenance = DEST / 'provenance.json'
    if binary().is_file() and provenance.is_file() and not force:
        recorded = json.loads(provenance.read_text(encoding='utf-8'))
        if recorded.get('version') == VERSION:
            print(f'CodeQL {VERSION} mavjud.')
            return recorded
    published = opener().open(BASE + name + '.checksum.txt', timeout=60).read(4096).decode().split()[0]
    if published != SHA256[name]:
        raise ValueError('GitHub e’lon qilgan checksum pinlangan qiymatdan farq qiladi. O‘rnatish to‘xtatildi.')
    with tempfile.TemporaryDirectory(prefix='codeql-', dir=ROOT / '.tools' if (ROOT / '.tools').is_dir() else None) as work:
        work = Path(work)
        archive_path = work / name
        print(f'CodeQL {VERSION} yuklanmoqda (~0.9 GB)…', flush=True)
        actual = download(BASE + name, archive_path)
        if actual != SHA256[name]:
            raise ValueError('Yuklama SHA-256 mos emas. O‘rnatish to‘xtatildi.')
        unpacked = work / 'unpacked'
        unpacked.mkdir()
        print('Ochilmoqda…', flush=True)
        with tarfile.open(archive_path) as archive:
            # safe_members already rejects any path or link that escapes `unpacked`,
            # and the archive's SHA-256 was matched against the pinned and the
            # GitHub-published checksums above, so it is trusted. An explicit filter
            # keeps CodeQL's own file permissions and symlinks and silences the
            # Python 3.14 extraction DeprecationWarning.
            archive.extractall(unpacked, members=safe_members(archive, unpacked), filter='fully_trusted')
        if DEST.exists():
            shutil.rmtree(DEST)
        DEST.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(unpacked), str(DEST))
    record = {'version': VERSION, 'archive': name, 'archive_sha256': SHA256[name], 'source': BASE + name,
              'license': 'https://github.com/github/codeql-cli-binaries/blob/main/LICENSE.md'}
    (DEST / 'provenance.json').write_text(json.dumps(record, indent=1) + '\n', encoding='utf-8')
    print(f'CodeQL {VERSION} o‘rnatildi: {binary()}')
    return record


def main():
    parser = argparse.ArgumentParser(description='CodeQL (ixtiyoriy chuqur tahlil) o‘rnatish')
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--force', action='store_true')
    args = parser.parse_args()
    if args.check:
        print(json.dumps({'installed': binary().is_file(), 'binary': str(binary()), 'expected_version': VERSION}))
        return
    try:
        install(args.force)
    except (OSError, ValueError, tarfile.TarError) as error:
        raise SystemExit(f'CodeQL o‘rnatilmadi: {error}')


if __name__ == '__main__':
    main()
