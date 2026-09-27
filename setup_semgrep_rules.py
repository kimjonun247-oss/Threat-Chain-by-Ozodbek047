"""Rasmiy Semgrep qoida bazasini lokal o'rnatish (SAST chuqurligi va til qamrovi).

Loyihaning o'z lokal qoidalari (scanner-rules/semgrep.yml) o'z joyida qoladi;
bu skript ularning ustiga semgrep/semgrep-rules omboridan PINLANGAN commit'dagi
rasmiy `security` toifasidagi qoidalarni qo'shadi.

Yaxlitlik modeli (Nuclei shablonlaridagi bilan bir xil naqsh, cheklovi bilan
birga ochiq aytiladi):
  - Commit SHA qattiq pinlanadi. Git commit SHA'si butun daraxt mazmuniga
    bog'langan xesh, shuning uchun "qaysi qoidalar" degan savolga aniq javob beradi.
  - Har bir chiqarilgan fayl uchun SHA-256 manifestga yoziladi, `origin` sifatida
    aynan shu commit'dagi raw.githubusercontent URL saqlanadi — istalgan fayl
    mustaqil qayta tekshirilishi mumkin.
  - Skan vaqtida zanjir/scanners.py manifestni qayta tekshiradi (lokal
    o'zgartirishdan himoya).
  - CHEKLOV: arxiv GitHub'dan olinadi va uning baytlari oldindan ma'lum bo'lgan
    xesh bilan solishtirilmaydi (GitHub tarball baytlari barqaror emas); reliz
    imzosi ham tekshirilmaydi. Bu loyihadagi Trivy/Nuclei o'rnatuvchilari bilan
    bir xil daraja — undan yuqori kafolat da'vo qilinmaydi.

Ishlatish:  python3 setup_semgrep_rules.py [--force]
"""
import argparse
import os
import subprocess
import tempfile
import hashlib
import io
import json
import shutil
import sys
import tarfile
import urllib.request
from pathlib import Path

from vendor import yaml

from zanjir import nettrust


ROOT = Path(__file__).resolve().parent
TARGET = ROOT / 'scanner-rules/semgrep-registry'
REPO = 'semgrep/semgrep-rules'
COMMIT = '40b8c63f75dc7c22c8a77482d73bfb864b146f7e'  # 2026-07-30
ARCHIVE_URL = f'https://codeload.github.com/{REPO}/tar.gz/{COMMIT}'
RAW_BASE = f'https://raw.githubusercontent.com/{REPO}/{COMMIT}/'

# OSS Semgrep Apex'ni umuman parse qila olmaydi (`--pro-languages` kerak), shuning
# uchun Apex qoidalari har bir skanda o'zgarmas "Missing plugin" shovqini beradi —
# qamrovga hech narsa qo'shmaydi, faqat xato sonini shishiradi. Qasddan chiqarilmaydi.
EXCLUDED_LANGUAGES = ('apex',)
MAX_ARCHIVE = 64 * 1024 * 1024
MAX_RULE_FILE = 512 * 1024
# Registry papkasidan TASHQARIDA: `--config <papka>` ichidagi hamma YAML ni yuklaydi,
# shuning uchun birlashtirilgan fayl o'sha papkada tursa har bir qoida ikki marta
# o'qilardi. Bu aniqlangan xato — birlashtirish natijani o'zgartirib yuborgan edi.
MERGED_PATH = ROOT / 'scanner-rules/semgrep-merged.yml'


def wanted(rel):
    """True — agar bu arxiv a'zosi biz olib qoladigan rasmiy security qoidasi bo'lsa."""
    if not rel.endswith(('.yaml', '.yml')) or '/security/' not in rel:
        return False
    if '.test.' in rel or '.fixed.' in rel:
        return False
    return rel.split('/')[0] not in EXCLUDED_LANGUAGES


def download():
    """The pinned archive: codeload first, then the same commit over git.

    codeload.github.com is blocked on some networks where git to github.com
    works; without the pack the code scan found 11 of 30 benchmark
    vulnerabilities instead of 27. Fetching the pinned commit by id is as exact
    as the archive: git verifies the content against the commit hash.
    """
    request = urllib.request.Request(ARCHIVE_URL, headers={'User-Agent': 'threatchain-setup'})
    try:
        with urllib.request.urlopen(request, context=nettrust.ssl_context(), timeout=300) as response:
            raw = response.read(MAX_ARCHIVE + 1)
    except OSError as error:
        print(f'Arxiv yuklanmadi ({error}); pinlangan commit git orqali olinmoqda.', file=sys.stderr)
        raw = download_with_git()
    if len(raw) > MAX_ARCHIVE:
        raise ValueError('Arxiv kutilganidan katta; o‘rnatish to‘xtatildi.')
    return raw


def download_with_git():
    git = shutil.which('git')
    if not git:
        raise ValueError('Arxiv yuklanmadi va git topilmadi; qoida paketini olishning boshqa yo‘li yo‘q.')
    with tempfile.TemporaryDirectory(prefix='semgrep-rules-') as temp:
        env = {**os.environ, 'GIT_TERMINAL_PROMPT': '0'}
        def run(*args):
            done = subprocess.run([git, '-C', temp, *args], capture_output=True, env=env, timeout=600)
            if done.returncode != 0:
                raise ValueError('git: ' + done.stderr.decode('utf-8', 'replace').strip()[-300:])
            return done.stdout
        run('init', '-q')
        run('-c', 'core.hooksPath=' + temp, 'fetch', '-q', '--depth', '1', f'https://github.com/{REPO}', COMMIT)
        if run('rev-parse', 'FETCH_HEAD').decode().strip() != COMMIT:
            raise ValueError('git boshqa commit qaytardi; o‘rnatish to‘xtatildi.')
        return run('archive', '--format=tar.gz', f'--prefix=semgrep-rules-{COMMIT}/', 'FETCH_HEAD')


def extract(raw):
    """Arxivdan faqat kerakli qoidalarni ajratib, har birini YAML sifatida tekshiradi."""
    files = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            parts = member.name.split('/')
            rel = '/'.join(parts[1:])            # yuqoridagi `semgrep-rules-<commit>/` prefiksi olib tashlanadi
            if not wanted(rel):
                continue
            if '..' in parts or member.name.startswith('/'):
                raise ValueError('Arxivda shubhali yo‘l bor: ' + member.name)
            if member.size > MAX_RULE_FILE:
                continue
            body = archive.extractfile(member).read()
            try:
                parsed = yaml.safe_load(body.decode('utf-8'))
            except (UnicodeDecodeError, yaml.YAMLError):
                continue                          # noto‘g‘ri YAML — Semgrep ham uni yuklay olmaydi
            if not isinstance(parsed, dict) or not isinstance(parsed.get('rules'), list) or not parsed['rules']:
                continue
            files[rel] = (body, len(parsed['rules']))
    if not files:
        raise ValueError('Arxivdan birorta qoida chiqmadi; commit yoki filtrni tekshiring.')
    return files


def install(files):
    """Build the whole pack beside the live one, then swap it in.

    The previous version deleted the existing pack first and wrote into the gap.
    A failure partway through then left rule files with no manifest -- which
    scanners.py reads as "pack not installed", so scans would silently fall back
    to seven local rules while looking perfectly healthy. Nothing is removed now
    until a complete, validated pack exists.
    """
    staging = TARGET.parent / (TARGET.name + '.incoming')
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)
    try:
        entries = []
        rules_total = 0
        for rel in sorted(files):
            body, rule_count = files[rel]
            path = staging / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
            rules_total += rule_count
            entries.append({'file': rel, 'sha256': hashlib.sha256(body).hexdigest(),
                            'rules': rule_count, 'origin': RAW_BASE + rel})
        merged = write_merged(files)
        manifest = {'source': REPO, 'commit': COMMIT, 'archive_url': ARCHIVE_URL,
                    'category': 'security', 'excluded_languages': list(EXCLUDED_LANGUAGES),
                    'files': len(entries), 'rules': rules_total,
                    'languages': sorted({e['file'].split('/')[0] for e in entries}),
                    'merged': merged, 'entries': entries}
        (staging / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    previous = TARGET.parent / (TARGET.name + '.previous')
    shutil.rmtree(previous, ignore_errors=True)
    if TARGET.exists():
        TARGET.rename(previous)
    staging.rename(TARGET)
    shutil.rmtree(previous, ignore_errors=True)
    return manifest


def write_merged(files):
    """Write every rule into one file, because Semgrep spends its time opening files.

    Measured on a four-file project: Semgrep's own profiling reports 33.2s of
    `config_time` against 0.5s of `core_time` when the rules arrive as 1327
    separate YAML files. The same rules in a single file bring config_time to
    6.5s -- a 4.7x saving on total scan time with not one rule removed.

    The individual files stay on disk and remain what the manifest hashes, so
    integrity checking is unchanged; this file is a derived index of them and is
    hashed too, so editing it alone is caught as well.
    """
    rules = []
    for rel in sorted(files):
        body, _ = files[rel]
        try:
            parsed = yaml.safe_load(body.decode('utf-8'))
        except (UnicodeDecodeError, yaml.YAMLError):
            continue
        for rule in (parsed or {}).get('rules') or []:
            if isinstance(rule, dict) and rule.get('id'):
                rules.append(rule)
    # The official pack reuses an id across languages on purpose: `anonymous-ldap-bind`
    # exists for Java and for Python as two different rules. They are kept as they
    # are -- dropping either would remove coverage, and renaming one would break the
    # id that appears in reports and in CI SARIF output. The count is recorded so
    # the duplication is a stated fact rather than a surprise.
    ids = [r['id'] for r in rules]
    shared = sorted({i for i in ids if ids.count(i) > 1})
    text = yaml.safe_dump({'rules': rules}, allow_unicode=True, sort_keys=False)
    MERGED_PATH.parent.mkdir(parents=True, exist_ok=True)
    MERGED_PATH.write_text(text, encoding='utf-8')
    return {'file': MERGED_PATH.name, 'rules': len(rules), 'shared_ids': len(shared),
            'sha256': hashlib.sha256(MERGED_PATH.read_bytes()).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description='Rasmiy Semgrep security qoidalarini o‘rnatish')
    parser.add_argument('--force', action='store_true', help='Mavjud o‘rnatmani qayta yuklab almashtirish')
    args = parser.parse_args()
    manifest_path = TARGET / 'manifest.json'
    if manifest_path.is_file() and not args.force:
        current = json.loads(manifest_path.read_text(encoding='utf-8'))
        if current.get('commit') == COMMIT:
            print(f'Allaqachon o‘rnatilgan: {current["rules"]} qoida, {current["files"]} fayl, commit {COMMIT[:12]}.')
            print('Qayta yuklash uchun --force ishlating.')
            return
    print(f'Yuklanmoqda: {ARCHIVE_URL}')
    try:
        manifest = install(extract(download()))
    except (OSError, ValueError, tarfile.TarError) as error:
        print('Xato:', error, file=sys.stderr)
        raise SystemExit(1)
    print(f'O‘rnatildi: {manifest["rules"]} qoida, {manifest["files"]} fayl, '
          f'{len(manifest["languages"])} til ({", ".join(manifest["languages"])}).')
    print(f'Manifest: {manifest_path.relative_to(ROOT)}')


if __name__ == '__main__':
    main()
