"""CLI for pinned public container images."""
import sys
import argparse
import json
from zanjir import images


def main():
    parser = argparse.ArgumentParser(description='Zanjir public image tekshiruvi')
    parser.add_argument('--target', default='pilot-crapi-web')
    parser.add_argument('--register')
    parser.add_argument('--image')
    parser.add_argument('--name')
    parser.add_argument('--max-size', default=None,
                        help='Faqat shu tekshiruv uchun hajm chegarasi (standart 1GB, eng ko‘pi 4GB). Hisobotda qayd etiladi.')
    args = parser.parse_args()
    if args.register:
        if not args.image: parser.error('--image nom@sha256:digest kerak')
        try: images.register(args.register, args.image, args.name)
        except (ValueError, OSError) as error: parser.error(str(error))
        print('Image ro‘yxatga olindi. Sahifani yangilang.',file=sys.stderr)
        return
    print('Image va zaiflik bazasi yuklanmoqda. Image ishga tushirilmaydi.', flush=True,file=sys.stderr)
    try:
        report = images.start(args.target, background=False, size_limit=args.max_size)
    except ValueError as error:
        print(json.dumps({'error': str(error)}, ensure_ascii=False))
        raise SystemExit(2)
    print(json.dumps({k: report.get(k) for k in ('id', 'state', 'count', 'severity_counts', 'message')}, ensure_ascii=False, indent=2))
    raise SystemExit(0 if report['state'] == 'completed' else 2)


if __name__ == '__main__': main()
