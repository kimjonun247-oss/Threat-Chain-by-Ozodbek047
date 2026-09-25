"""CI/CD gate: run the "Umumiy tekshiruv" pipeline (or a chosen subset)
non-interactively, write a combined SARIF file, and exit non-zero if any
severe or cross-scanner chain finding exceeds --allow. See zanjir/ci_gate.py
for exactly what counts as gate-relevant and why no blended score is used.

Without the B3 flags this behaves exactly as it always has. With them it can
judge only what the change introduced:

    python3 ci_gate.py --target myapp --baseline last-green --fail-on new-high
    python3 ci_gate.py --target myapp --respect-triage

Exit codes are unchanged: 0 passed, 1 the gate stopped the build, 2 the scan
itself did not finish (which is not a pass).
"""
import sys
import argparse
import json
from pathlib import Path
from zanjir import pipeline
from zanjir import baseline as baseline_mod
from zanjir import ci_gate as gate


def main():
    p = argparse.ArgumentParser(description='ThreatChain CI/CD gate')
    p.add_argument('--target', default='', help='Ro‘yxatdagi manba kodi ID (Semgrep+Gitleaks, CVE)')
    p.add_argument('--repository-target', default='', help='Ro‘yxatdagi Repository (Compose) profil ID')
    p.add_argument('--web-target', default='', help='Ro‘yxatdagi ruxsat berilgan sayt/API ID')
    p.add_argument('--image-target', default='', help='Ro‘yxatdagi Docker image ID')
    p.add_argument('--allow', type=int, default=0, help='Ruxsat etilgan gate-relevant topilmalar soni (standart: 0)')
    p.add_argument('--sarif-out', default='threatchain.sarif', help='SARIF fayl yo‘li')
    p.add_argument('--baseline', default='',
                   help='Asos skan: hisobot ID yoki "last-green" (bir xil tanlovdagi oxirgi tugagan skan)')
    p.add_argument('--fail-on', default='any', choices=gate.FAIL_MODES,
                   help='any — barcha gate-relevant topilma (standart); new/new-high/new-critical — faqat '
                        'shu o‘zgarish kiritganlari (asos skan talab qilinadi)')
    p.add_argument('--respect-triage', action='store_true',
                   help='false_positive va accepted_risk deb yopilganlarni sanamaslik')
    args = p.parse_args()
    if args.fail_on != 'any' and not args.baseline:
        p.error('--fail-on new* uchun --baseline kerak (masalan: --baseline last-green).')
    payload = {'target': args.target, 'repository_target': args.repository_target,
               'web_target': args.web_target, 'image_target': args.image_target, 'online': True}
    try:
        report = pipeline.start(payload, background=False)
    except (ValueError, OSError) as error:
        print(json.dumps({'error': str(error)}, ensure_ascii=False))
        raise SystemExit(2)
    Path(args.sarif_out).write_text(json.dumps(pipeline.sarif(report), ensure_ascii=False, indent=2), encoding='utf-8')
    # The in-memory report from a non-background run has not been through read(),
    # so the triage overlay is applied here -- otherwise --respect-triage would
    # silently have nothing to respect.
    report = pipeline.attach_triage(report)
    before = None
    if args.baseline:
        try:
            resolved = (baseline_mod.last_green_assessment(payload, report['id'])
                        if args.baseline == 'last-green' else args.baseline)
            if not resolved:
                raise ValueError('Bir xil tanlovdagi tugagan (completed) oldingi skan topilmadi. '
                                 'Asos yaratish uchun avval --fail-on any bilan bir marta yashil skan bajaring.')
            before = pipeline.read(resolved)
        except (ValueError, OSError) as error:
            print(json.dumps({'error': str(error)}, ensure_ascii=False))
            raise SystemExit(2)
    try:
        result = gate.evaluate(report, allow=args.allow, baseline=before,
                               fail_on=args.fail_on, respect_triage=args.respect_triage)
    except ValueError as error:
        print(json.dumps({'error': str(error)}, ensure_ascii=False))
        raise SystemExit(2)
    print(json.dumps({'pipeline_state': report['state'],
                      'gate': {k: v for k, v in result.items() if k != 'hits'},
                      'sarif': args.sarif_out}, ensure_ascii=False, indent=2))
    for hit in result['hits']:
        why = f" · {hit['why']}" if hit.get('why') else ''
        print(f" - [{hit['stage']}] {hit['rule_id']} · {hit['subject']} · {hit['detail']}{why}", file=sys.stderr)
    if report['state'] == 'failed':
        raise SystemExit(2)
    raise SystemExit(0 if result['passed'] else 1)


if __name__ == '__main__':
    main()
