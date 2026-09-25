"""Barcha skaner vositalarini va qoida bazalarini bitta buyruq bilan o'rnatish.

Yangi mashinada beshta alohida o'rnatuvchi ishga tushirish kerak edi va qaysi biri
majburiy, qaysi biri ixtiyoriy ekani hech qayerda aytilmagandi. Bu skript ularni
bir joyga yig'adi va **har birining natijasini alohida** ko'rsatadi: bittasi
yiqilsa qolganlari baribir o'rnatiladi, chunki yarim o'rnatilgan holat ham
ishlaydigan holat — masalan Trivy'siz ham kod va CVE tekshiruvlari to'liq ishlaydi.

Hech narsa global o'rnatilmaydi: hamma narsa `.tools/` va `scanner-rules/` ostiga
tushadi, har bir reliz rasmiy manbadan SHA-256 bilan tekshirib olinadi.
Cheklov ochiq aytiladi: reliz imzolari (Sigstore va h.k.) tekshirilmaydi.

Ishlatish:
    python3 setup_all.py              # yetishmaganini o'rnatadi
    python3 setup_all.py --force      # borini ham qayta yuklaydi
    python3 setup_all.py --only trivy nuclei
"""
import argparse
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent

# `optional` — bu komponentsiz ham loyiha ishlaydi, faqat tegishli bosqich o'chadi.
STEPS = (
    # Semgrep and Gitleaks come first: without them no code scan runs at all.
    {'key': 'scanners', 'script': 'setup_scanners.py', 'supports_force': False,
     'title': 'Semgrep va Gitleaks (kod va sirlar tekshiruvi)',
     'needed_for': 'Kod va sirlar bosqichi', 'optional': False},
    {'key': 'trivy', 'script': 'setup_tools.py', 'supports_force': False,
     'title': 'Trivy (Docker image tekshiruvi)',
     'needed_for': 'Docker image bosqichi', 'optional': True},
    {'key': 'nuclei', 'script': 'setup_nuclei.py', 'supports_force': False,
     'title': 'Nuclei va rasmiy shablonlar (Sayt va API)',
     'needed_for': 'Sayt va API (DAST) bosqichi', 'optional': True},
    {'key': 'semgrep-rules', 'script': 'setup_semgrep_rules.py', 'supports_force': True,
     'title': 'Rasmiy semgrep-rules security paketi (~1343 qoida, 22 til)',
     'needed_for': 'Kod bosqichining chuqurligi va til qamrovi', 'optional': True},
    {'key': 'pmd', 'script': 'setup_pmd.py', 'supports_force': False,
     'title': 'PMD (Apex/Salesforce kodi; Java kerak)',
     'needed_for': 'Apex kodini tekshirish', 'optional': True},
)


def run(step, force):
    command = [sys.executable, str(ROOT / step['script'])]
    if force and step['supports_force']:
        command.append('--force')
    started = time.monotonic()
    done = subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                          encoding='utf-8', errors='replace', timeout=1800)
    return {'ok': done.returncode == 0, 'seconds': round(time.monotonic() - started, 1),
            'output': (done.stdout or done.stderr or '').strip().splitlines()[-1:] or ['']}


def main():
    parser = argparse.ArgumentParser(description='ThreatChain: barcha vosita va qoida bazalarini o‘rnatish')
    parser.add_argument('--force', action='store_true',
                        help='Qo‘llab-quvvatlaydigan o‘rnatuvchilarni qayta yuklashga majburlash')
    parser.add_argument('--only', nargs='+', metavar='NOM', choices=[s['key'] for s in STEPS],
                        help='Faqat sanab o‘tilganlarini o‘rnatish: ' + ', '.join(s['key'] for s in STEPS))
    args = parser.parse_args()
    steps = [s for s in STEPS if not args.only or s['key'] in args.only]

    results = {}
    for step in steps:
        print(f"→ {step['title']}", flush=True)
        try:
            results[step['key']] = run(step, args.force)
        except (OSError, subprocess.TimeoutExpired) as error:
            results[step['key']] = {'ok': False, 'seconds': None, 'output': [str(error)[:200]]}
        row = results[step['key']]
        state = 'tayyor' if row['ok'] else 'BAJARILMADI'
        took = f" · {row['seconds']} s" if row['seconds'] is not None else ''
        print(f"  {state}{took} · {row['output'][0][:110]}", flush=True)

    print()
    failed = [key for key, row in results.items() if not row['ok']]
    if failed:
        print('Quyidagilar o‘rnatilmadi: ' + ', '.join(failed))
        for step in steps:
            if step['key'] in failed:
                print(f"  {step['key']}: {step['needed_for']} ishlamaydi. "
                      f"Alohida ishga tushirib xatoni ko‘ring: python3 {step['script']}")
        print('Qolgan bosqichlar baribir ishlaydi — yarim o‘rnatilgan holat ham ishlaydigan holat.')
    else:
        print('Hammasi tayyor. Interfeysni `python3 app.py` bilan oching.')
    print('Eslatma: relizlar SHA-256 bilan tekshiriladi; reliz imzolari tekshirilmaydi.')
    raise SystemExit(1 if failed else 0)


if __name__ == '__main__':
    main()
