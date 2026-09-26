"""Install the pinned Trivy release into this project; verify upstream SHA-256."""
import argparse
import hashlib
import io
import json
import platform
import subprocess
import sys
import tarfile
from pathlib import Path
import urllib.request
import zipfile
from zanjir.engine import ROOT
from zanjir.repo_store import write_json

from zanjir import nettrust


VERSION='0.74.0'
BASE='https://github.com/aquasecurity/trivy/releases/download/v'+VERSION+'/'
# Windows keeps its original layout (.tools/trivy/trivy.exe) untouched; every
# other platform gets its own archive name and a sibling .tools/trivy/posix/
# folder so neither copy's provenance.json is disturbed by the other.
IS_WINDOWS=sys.platform.startswith('win')
if IS_WINDOWS:
    ARCHIVE='trivy_'+VERSION+'_windows-64bit.zip';SUBDIR='';BINARY_NAME='trivy.exe'
elif sys.platform=='darwin':
    ARCHIVE='trivy_'+VERSION+('_macOS-ARM64.tar.gz' if platform.machine()=='arm64' else '_macOS-64bit.tar.gz');SUBDIR='posix';BINARY_NAME='trivy'
else:
    ARCHIVE='trivy_'+VERSION+('_Linux-ARM64.tar.gz' if platform.machine() in ('aarch64','arm64') else '_Linux-64bit.tar.gz');SUBDIR='posix';BINARY_NAME='trivy'


def download(url,limit):
    opener=urllib.request.build_opener(nettrust.proxy_handler(),urllib.request.HTTPSHandler(context=nettrust.ssl_context()))
    with opener.open(urllib.request.Request(url,headers={'User-Agent':'Zanjir-setup/0.4'}),timeout=90) as response:
        raw=response.read(limit+1)
    if len(raw)>limit:raise ValueError('Yuklama hajmi chegaradan oshdi.')
    return raw


def install():
    dest=(ROOT/'.tools/trivy'/SUBDIR) if SUBDIR else (ROOT/'.tools/trivy')
    dest.mkdir(parents=True,exist_ok=True)
    metadata=dest/'provenance.json';binary=dest/BINARY_NAME
    if binary.exists() and metadata.exists():
        previous=json.loads(metadata.read_text(encoding='utf-8'))
        if previous.get('version')==VERSION and hashlib.sha256(binary.read_bytes()).hexdigest()==previous.get('binary_sha256'):
            # Already installed is the common case, and it is exactly when the
            # databases still need warming -- so this path warms them too.
            print('Trivy '+VERSION+' mavjud; xeshi mos.');warm_databases(binary);return
        raise ValueError('Mavjud Trivy fayli provenance bilan mos emas. Avtomatik ustiga yozilmadi.')
    print('Trivy '+VERSION+' rasmiy relizi yuklanmoqda.',flush=True)
    checksums=download(BASE+'trivy_'+VERSION+'_checksums.txt',100000).decode()
    expected=next((line.split()[0] for line in checksums.splitlines() if line.split()[-1:]==[ARCHIVE]),None)
    if not expected or len(expected)!=64:raise ValueError('Rasmiy checksum topilmadi.')
    raw=download(BASE+ARCHIVE,80*1024*1024)
    if hashlib.sha256(raw).hexdigest()!=expected:raise ValueError('Yuklama SHA-256 mos emas.')
    if ARCHIVE.endswith('.zip'):
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            names=archive.namelist()
            if BINARY_NAME not in names:raise ValueError('Trivy arxivida bajariladigan fayl yo‘q.')
            for name in (BINARY_NAME,'LICENSE','README.md'):
                if name in names:
                    if archive.getinfo(name).file_size>200*1024*1024:raise ValueError('Arxiv fayli juda katta.')
                    (dest/name).write_bytes(archive.read(name))
    else:
        with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as archive:
            names=archive.getnames()
            if BINARY_NAME not in names:raise ValueError('Trivy arxivida bajariladigan fayl yo‘q.')
            for name in (BINARY_NAME,'LICENSE','README.md'):
                if name in names:
                    member=archive.getmember(name)
                    if member.size>200*1024*1024:raise ValueError('Arxiv fayli juda katta.')
                    (dest/name).write_bytes(archive.extractfile(member).read())
        binary.chmod(0o755)
    write_json(metadata,{'version':VERSION,'url':BASE+ARCHIVE,'archive_sha256':expected,
                        'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),
                        'verification':'SHA-256 checked against upstream checksums over HTTPS; Sigstore signature not verified.'})
    print('Trivy tayyor. Global dasturlar o‘zgartirilmadi.')
    warm_databases(binary)


def warm_databases(binary):
    """Fetch Trivy's vulnerability and Java databases before any scan needs them.

    Without this a scan spends its own time budget downloading them. A real
    crAPI Java image failed twice for exactly that reason: the run was killed
    while trivy-java-db was still downloading, which also meant nothing was
    cached and a plain retry failed the same way. Downloading here makes that a
    one-off cost at install time instead of a per-scan surprise.

    Failure is not fatal: the databases are fetched again on first use, just
    more slowly, so a machine that is offline right now still ends up with a
    working Trivy.
    """
    cache=ROOT/'.tools/trivy/cache'
    for label,flag,minutes in (('zaiflik bazasi','--download-db-only',10),
                               ('Java bazasi','--download-java-db-only',20)):
        print(f'{label} yuklanmoqda (bir martalik)…',flush=True)
        try:
            done=subprocess.run([str(binary),'image',flag,'--cache-dir',str(cache),'--no-progress','--disable-telemetry','--skip-version-check'],
                                capture_output=True,text=True,encoding='utf-8',errors='replace',
                                timeout=minutes*60)
            print(f'  {label}: ' + ('tayyor' if done.returncode==0 else 'yuklanmadi — birinchi skanda qayta urinadi'))
        except (OSError,subprocess.TimeoutExpired):
            print(f'  {label}: yuklanmadi — birinchi skanda qayta urinadi')


if __name__=='__main__':
    argparse.ArgumentParser(description='Trivy’ni lokal o‘rnatish (rasmiy reliz, SHA-256)').parse_args()
    install()
