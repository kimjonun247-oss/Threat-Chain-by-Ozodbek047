"""Register an authorized exact web scope or run its bounded scan."""
import sys
import argparse
import json
from zanjir import webscan


def main():
    p = argparse.ArgumentParser(description='Zanjir ruxsatli sayt/API tekshiruvi')
    p.add_argument('--target', default='pilot-crapi')
    p.add_argument('--register')
    p.add_argument('--url')
    p.add_argument('--owner')
    p.add_argument('--authorized', action='store_true')
    p.add_argument('--allow-private', action='store_true')
    p.add_argument('--interactive', action='store_true')
    p.add_argument('--replace', action='store_true', help='mavjud ro‘yxatni yangilash (ruxsat qaytadan qayd etiladi)')
    p.add_argument('--window-days', help='ruxsat oynasi kunlari, masalan: mon,tue,wed,thu,fri')
    p.add_argument('--window-start', help='oyna boshlanishi HH:MM (masalan 22:00)')
    p.add_argument('--window-end', help='oyna tugashi HH:MM (masalan 06:00; tun yarmidan o‘tishi mumkin)')
    p.add_argument('--timezone', default='UTC', help='UTC ofseti, masalan +05:00')
    p.add_argument('--daily-budget', type=int, help='nishonga kuniga yuboriladigan so‘rovlar chegarasi')
    args = p.parse_args()
    window = None
    if args.window_start or args.window_end:
        window = {'start': args.window_start or '', 'end': args.window_end or '', 'timezone': args.timezone}
        if args.window_days:
            window['days'] = args.window_days
    if args.interactive:
        print('Faqat o‘zingizga tegishli yoki tekshirishga ruxsat berilgan sayt/API.\nEnter: mavjud lokal crAPI laboratoriyasi.',file=sys.stderr)
        url = input('URL: ').strip()
        if url:
            target = input('Loyiha ID (masalan: my-staging): ').strip()
            owner = input('Ruxsat bergan mas’ul: ').strip()
            if input('Shu manzilni cheklangan GET so‘rovlari bilan tekshirishga ruxsat bormi? (ha/yoq): ').strip().lower() != 'ha':
                p.error('Ruxsat tasdiqlanmadi.')
            private = input('Lokal/intranet manzilimi? (ha/yoq): ').strip().lower() == 'ha'
            webscan.register(target, url, owner, private)
            print('Nishon ro‘yxatga olindi. Sahifani yangilang.',file=sys.stderr)
            return
    elif args.register:
        if not args.url or not args.owner or not args.authorized:
            p.error('--url, --owner va --authorized kerak.')
        row = webscan.register(args.register, args.url, args.owner, args.allow_private,
                               scan_window=window, daily_request_budget=args.daily_budget, replace=args.replace)
        print('Nishon ro‘yxatga olindi' + (f" · oyna {row['scan_window']}" if row.get('scan_window') else '') +
              (f" · kuniga ≤{row['daily_request_budget']} so‘rov" if row.get('daily_request_budget') else '') + '.', file=sys.stderr)
        return
    report = webscan.start(args.target, background=False)
    print(json.dumps({k: report.get(k) for k in ('id', 'state', 'count', 'requests', 'coverage', 'message')}, ensure_ascii=False, indent=2))
    raise SystemExit(0 if report['state'] == 'completed' else 2)


if __name__ == '__main__':
    main()
