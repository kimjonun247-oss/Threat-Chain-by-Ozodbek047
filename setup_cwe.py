"""Regenerate the CWE -> OWASP Top 10:2025 map from MITRE's official catalog.

The map lives in two places: a hand-verified baseline in zanjir/taxonomy.py that
always ships, and -- after this runs -- scanner-rules/cwe-owasp.json, regenerated
from MITRE's canonical CWE catalog so a new CWE release updates the OWASP tagging
without any hand edits. taxonomy.py prefers the JSON when it is present and valid.

Source: MITRE CWE catalog, categories 1436..1445 (OWASP Top Ten 2025, A01..A10) --
the same canonical pages the baseline was built from. Pinned to catalog v4.20 and
verified by the extracted XML's SHA-256; `--latest` fetches the newest release
instead (structurally validated, SHA not pinned).

No expat: the ten category blocks are matched with a bounded regex, so this runs
even where the interpreter's C XML parser (pyexpat) is broken -- which it is on
some current Homebrew CPython builds.

    python3 setup_cwe.py            # pinned v4.20, SHA-256 verified
    python3 setup_cwe.py --latest   # newest CWE release (structure-checked)
"""
import argparse
import hashlib
import io
import json
import re
import sys
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BASE = 'https://cwe.mitre.org/data/xml/'
VERSION = '4.20'
# SHA-256 of the extracted cwec_v4.20.xml (not the zip, whose metadata can vary).
XML_SHA256 = '1f5a78bd62e00f86436b4fe32d5034a57e8f0da88e4063b2072b664ae510912e'
# MITRE category id -> OWASP Top 10:2025 code. One category page per A0x.
CATEGORIES = {1436: 'A01', 1437: 'A02', 1438: 'A03', 1439: 'A04', 1440: 'A05',
              1441: 'A06', 1442: 'A07', 1443: 'A08', 1444: 'A09', 1445: 'A10'}
OUTPUT = ROOT / 'scanner-rules' / 'cwe-owasp.json'


def fetch_xml(latest=False):
    """Download and unzip the catalog; verify the pinned SHA unless --latest."""
    name = 'cwec_latest.xml.zip' if latest else f'cwec_v{VERSION}.xml.zip'
    request = urllib.request.Request(BASE + name, headers={'User-Agent': 'ThreatChain-setup/0.7'})
    with urllib.request.urlopen(request, timeout=300) as response:
        blob = response.read()
    with zipfile.ZipFile(io.BytesIO(blob)) as archive:
        xml_name = next((n for n in archive.namelist() if n.endswith('.xml')), None)
        if not xml_name:
            raise ValueError('CWE arxivida XML fayl topilmadi.')
        xml_bytes = archive.read(xml_name)
    if not latest:
        actual = hashlib.sha256(xml_bytes).hexdigest()
        if actual != XML_SHA256:
            raise ValueError(f'CWE katalogi SHA-256 mos emas (kutilgan {XML_SHA256}, olingan {actual}). '
                             'O‘rnatish to‘xtatildi.')
    return xml_bytes.decode('utf-8'), xml_name


def parse_map(xml, min_count=100):
    """{cwe_number: 'A0x'} from the ten OWASP category blocks. Raises if the
    catalog's shape changed, so a silent wrong map can never be written.
    `min_count` guards against a truncated download (tests lower it for fixtures)."""
    mapping = {}
    for category_id, code in CATEGORIES.items():
        block = re.search(r'<Category ID="%d"[ >].*?</Category>' % category_id, xml, re.S)
        if not block:
            raise ValueError(f'CWE kategoriyasi {category_id} ({code}) topilmadi — katalog formati o‘zgargan.')
        members = [int(x) for x in re.findall(r'<Has_Member CWE_ID="(\d+)"', block.group(0))]
        if not members:
            raise ValueError(f'CWE kategoriyasi {category_id} ({code}) bo‘sh.')
        for cwe in members:
            # OWASP categories are disjoint; if a future catalog lists a CWE twice,
            # keep the first category rather than guessing which wins.
            mapping.setdefault(cwe, code)
    if set(mapping.values()) != set(CATEGORIES.values()):
        raise ValueError('OWASP toifalari (A01..A10) to‘liq emas.')
    if len(mapping) < min_count:
        raise ValueError(f'Kutilganidan kam CWE ({len(mapping)}) — katalog to‘liq o‘qilmadi.')
    return mapping


def main():
    parser = argparse.ArgumentParser(description='CWE -> OWASP xaritasini MITRE katalogidan yangilash')
    parser.add_argument('--latest', action='store_true',
                        help='Pinlangan v%s o‘rniga eng yangi CWE relizini oladi (SHA tekshirilmaydi)' % VERSION)
    args = parser.parse_args()
    try:
        xml, xml_name = fetch_xml(latest=args.latest)
        mapping = parse_map(xml)
    except (urllib.error.URLError, OSError, ValueError, zipfile.BadZipFile) as error:
        raise SystemExit(f'CWE xaritasi yangilanmadi: {type(error).__name__}: {error}')
    catalog = re.search(r'<Weakness_Catalog[^>]*\bVersion="([^"]+)"', xml)
    record = {
        'map': {str(k): v for k, v in sorted(mapping.items())},
        'count': len(mapping),
        'owasp': 'Top 10:2025 (MITRE categories 1436-1445)',
        'source': BASE + xml_name,
        'catalog_version': catalog.group(1) if catalog else ('latest' if args.latest else VERSION),
        'xml_sha256': None if args.latest else XML_SHA256,
        'verification': 'Pinned catalog version; XML SHA-256 verified' if not args.latest
                        else 'Latest release; structure validated, SHA not pinned',
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(record, indent=1) + '\n', encoding='utf-8')
    print(f'CWE -> OWASP xaritasi yangilandi: {len(mapping)} ta CWE, '
          f'katalog v{record["catalog_version"]} -> {OUTPUT.relative_to(ROOT)}', file=sys.stderr)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
