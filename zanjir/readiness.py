"""Local pilot overview; no network probes and no security score."""
import hashlib
import json
import shutil
import sys
from pathlib import Path
from .engine import ROOT
from . import scanners, dependencies, images, repo_store, webscan, pipeline, custom_rules, threatfeeds


def code_fingerprint():
    """Hash of the server code as it sits on disk right now.

    /api/health reports the hash the running process loaded at start-up. When the
    two differ, the running server is older than the files -- the situation that
    once made an already-implemented SARIF route return 404 for a whole
    debugging session.
    """
    digest = hashlib.sha256()
    for path in sorted(Path(__file__).resolve().parent.glob('*.py')) + [ROOT / 'app.py']:
        try:
            digest.update(path.read_bytes())
        except OSError:
            continue
    return digest.hexdigest()[:16]


def status():
    tools = []
    for name, path in [('Semgrep', scanners.semgrep_exe()),
                       ('Gitleaks', scanners.gitleaks_exe()), ('Trivy', images.BINARY), ('Nuclei', webscan.BINARY),
                       ('PMD (Apex)', scanners.pmd_exe())]:
        tools.append({'name': name, 'installed': path.is_file(),
                      'note': 'Fayl mavjudligi bajarish muvaffaqiyatini kafolatlamaydi; skan holatini ko‘ring.'})
    # The official Semgrep pack is optional; a broken manifest is reported here
    # rather than raised, so the overview page still renders.
    try:
        pack = scanners.registry_manifest(cached=True)
        rules = ({'installed': True, 'rules': pack['rules'], 'files': pack['files'],
                  'languages': pack['languages'], 'commit': pack['commit'], 'source': pack['source'],
                  # Named, not silently dropped: OSS Semgrep cannot parse Apex at
                  # all, so an Apex project would otherwise look scanned.
                  'excluded_languages': pack.get('excluded_languages') or [],
                  'excluded_covered_by': 'PMD' if scanners.pmd_exe().is_file() else None,
                  # Apex is named either way; what changes is whether PMD covers it.
                  'excluded_note': (('OSS Semgrep Apex’ni parse qila olmaydi; Apex kodi PMD '
                                     '(category/apex/security.xml) bilan tekshiriladi.')
                                    if scanners.pmd_exe().is_file() else
                                    ('OSS Semgrep bu tillarni parse qila olmaydi va PMD o‘rnatilmagan — bu '
                                     'tillardagi kod tekshirilmaydi. Apex uchun: python3 setup_pmd.py'))
                                   if pack.get('excluded_languages') else None}
                 if pack else {'installed': False, 'note': 'python3 setup_semgrep_rules.py orqali o‘rnatiladi.'})
    except ValueError as error:
        rules = {'installed': False, 'error': str(error)}
    return {'version': '0.7.0', 'mode': 'online_evidence_based_pilot', 'semgrep_rule_pack': rules,
            'custom_rules': custom_rules.summary(), 'code_fingerprint': code_fingerprint(),
            # Without a key NVD allows 5 requests per 30s, so CWE enrichment is
            # slow and partial. Saying so beats letting it look like a failure.
            'nvd_api_key': {'present': bool(threatfeeds.nvd_api_key()),
                            'note': ('NVD kaliti o‘rnatilgan: CWE boyitish tez ishlaydi.'
                                     if threatfeeds.nvd_api_key() else
                                     'NVD kaliti yo‘q: 30 soniyada 5 so‘rov chegarasi, CWE boyitish sekin va '
                                     'qisman bo‘ladi. NVD_API_KEY muhit o‘zgaruvchisini o‘rnating '
                                     '(nvd.nist.gov/developers/request-an-api-key).')},
            'python': '.'.join(map(str, sys.version_info[:3])),
            'free_disk_gb': round(shutil.disk_usage(ROOT).free / 1024**3, 1),
            # Image scans need the image plus ~1 GB of working space and are refused
            # below that; warning early beats a scan that stops for lack of room.
            'disk_warning': (f'Diskda {shutil.disk_usage(ROOT).free / 1024**3:.1f} GB bo‘sh joy qoldi. Image tekshiruvi '
                             'image hajmi + 1 GB joy talab qiladi va yetmasa boshlanmaydi. Keraksiz fayllarni '
                             'bo‘shating (masalan, ishlatilmayotgan Docker/Colima image’lari).')
                            if shutil.disk_usage(ROOT).free < 5 * 1024**3 else None,
            'tools': tools, 'targets': scanners.targets(), 'image_targets': images.targets(),
            'web_targets': webscan.targets(),
            'latest': {'code': scanners.history()[:3], 'dependencies': dependencies.history()[:3], 'images': images.history()[:3],
                       'web': webscan.history()[:3], 'assessments': pipeline.history()[:3]},
            'steps': [
                'CHECK-PROJECT.cmd ni ochib ruxsat berilgan lokal loyiha papkasini kiriting.',
                'Sayt/API uchun CHECK-WEB.cmd orqali aniq URL va ruxsat bergan mas’ulni kiriting; crAPI tayyor nishon sifatida bor.',
                'Umumiy tekshiruv bo‘limida manba, web va zarur bo‘lsa image tanlab bitta jarayonni boshlang.',
                'CVE va kutubxonalar: online rejimda boshlang‘ich hisobot oling; qamrov va baza vaqtini ko‘ring.',
                'Kod va sirlar: o‘sha loyihani tanlab Semgrep va Gitleaks tekshiruvini boshlang.',
                'Docker image bo‘lsa, digest bilan ro‘yxatga oling va Image tekshiruvini bajaring.',
                'P1/P2 topilmalarini mutaxassis tekshirsin; mas’ul, qaror va asosni yozing.',
                'Alohida branchda tuzatish kiriting, funksional test va qayta skan bajaring; hisobotlarni solishtiring.'
            ],
            'limits': 'AI ishlatilmaydigan lokal pilot. Ro‘yxatdagi ruxsatli saytga cheklangan GET tekshiruvi bor. Universal pentest, barcha CVE qamrovi, RBAC va internetga ochiq ko‘p foydalanuvchili xizmat mavjud emas.'}
