"""Install a pinned upstream Nuclei release and two reviewed upstream templates."""
import argparse
import hashlib
import io
import json
import platform
import sys
import zipfile
from pathlib import Path
from setup_tools import download
from zanjir.engine import ROOT
from zanjir.repo_store import write_json

VERSION = '3.11.1'
COMMIT = '823ebcccf653310cb8df3264592027b437095943'
UPSTREAM = ['http/exposures/configs/git-config.yaml', 'http/miscellaneous/dir-listing.yaml']
# Windows keeps its original layout (.tools/nuclei/nuclei.exe) untouched; every
# other platform gets its own archive name and a sibling .tools/nuclei/posix/
# folder so neither copy's provenance.json is disturbed by the other.
IS_WINDOWS = sys.platform.startswith('win')
if IS_WINDOWS:
    ARCHIVE_NAME = f'nuclei_{VERSION}_windows_amd64.zip';SUBDIR = '';BINARY_NAME = 'nuclei.exe'
elif sys.platform == 'darwin':
    ARCHIVE_NAME = f'nuclei_{VERSION}_macOS_' + ('arm64' if platform.machine() == 'arm64' else 'amd64') + '.zip';SUBDIR = 'posix';BINARY_NAME = 'nuclei'
else:
    ARCHIVE_NAME = f'nuclei_{VERSION}_linux_' + ('arm64' if platform.machine() in ('aarch64', 'arm64') else 'amd64') + '.zip';SUBDIR = 'posix';BINARY_NAME = 'nuclei'


def install():
    dest = (ROOT / '.tools/nuclei' / SUBDIR) if SUBDIR else (ROOT / '.tools/nuclei')
    dest.mkdir(parents=True, exist_ok=True)
    binary = dest / BINARY_NAME
    meta = dest / 'provenance.json'
    if binary.exists():
        prior = json.loads(meta.read_text(encoding='utf-8'))
        if prior['version'] != VERSION or prior['binary_sha256'] != hashlib.sha256(binary.read_bytes()).hexdigest():
            raise ValueError('Mavjud Nuclei provenance bilan mos emas; ustiga yozilmadi.')
    else:
        base = f'https://github.com/projectdiscovery/nuclei/releases/download/v{VERSION}/'
        checks = download(base + f'nuclei_{VERSION}_checksums.txt', 100000).decode()
        expected = next(line.split()[0] for line in checks.splitlines() if line.split()[-1] == ARCHIVE_NAME)
        print('Nuclei rasmiy relizi yuklanmoqda.', flush=True)
        raw = download(base + ARCHIVE_NAME, 70 * 1024 * 1024)
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError('Nuclei SHA-256 mos emas.')
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            for entry in (BINARY_NAME, 'LICENSE.md', 'README.md'):
                if entry in archive.namelist():
                    if archive.getinfo(entry).file_size > 200 * 1024 * 1024:
                        raise ValueError('Arxiv fayli chegaradan oshdi.')
                    (dest / entry).write_bytes(archive.read(entry))
        if not IS_WINDOWS:
            binary.chmod(0o755)
        write_json(meta, {'version': VERSION, 'url': base + ARCHIVE_NAME, 'archive_sha256': expected,
                         'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                         'verification': 'Upstream HTTPS checksums; release signature not verified.'})
    rules = ROOT / 'scanner-rules/nuclei'
    rules.mkdir(parents=True, exist_ok=True)
    provenance = []
    for path in UPSTREAM:
        url = f'https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/{COMMIT}/{path}'
        raw = download(url, 100000)
        target = rules / Path(path).name
        if target.exists() and target.read_bytes() != raw:
            raise ValueError('Mahalliy template o‘zgargan; ustiga yozilmadi.')
        target.write_bytes(raw)
        provenance.append({'file': target.name, 'url': url, 'sha256': hashlib.sha256(raw).hexdigest()})
    (rules / 'UPSTREAM-LICENSE.md').write_bytes(download(f'https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/{COMMIT}/LICENSE.md', 100000))
    write_json(rules / 'upstream.json', {'commit': COMMIT, 'templates': provenance})
    print('Nuclei va ikkita tanlangan rasmiy qoida tayyor.')


if __name__ == '__main__':
    argparse.ArgumentParser(description='Nuclei va tanlangan rasmiy qoidalarni o‘rnatish').parse_args()
    install()
