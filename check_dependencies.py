"""Source project onboarding and online dependency checks without build execution."""
import sys
import argparse
import hashlib
import json
from pathlib import Path
from zanjir import code_targets, dependencies, scanners


def main():
    parser=argparse.ArgumentParser(description='Zanjir kutubxonalar/CVE tekshiruvi (doim online: OSV, CISA KEV, NVD, EPSS)')
    parser.add_argument('--target',default='crapi-full')
    parser.add_argument('--register',help='Yangi loyiha ID')
    parser.add_argument('--repo',help='Lokal loyiha papkasi')
    parser.add_argument('--name')
    parser.add_argument('--interactive',action='store_true')
    args=parser.parse_args()
    if args.register:
        if not args.repo:parser.error('--repo kerak')
        print(json.dumps(code_targets.register(args.register,args.repo,args.name),ensure_ascii=False));return
    target=args.target
    if args.interactive:
        print('Zanjir: papkadagi kutubxonalar va ma’lum zaifliklar tekshiruvi.',file=sys.stderr)
        print('crAPI uchun Enter bosing yoki loyiha papkasini yozing. Kod bajarilmaydi.',file=sys.stderr)
        value=input('Loyiha papkasi: ').strip().strip('"')
        if value:
            source=Path(value).resolve()
            existing=next((p for p in code_targets.profiles() if Path(p['root'])==source),None)
            target=existing['id'] if existing else 'project-'+hashlib.sha256(str(source).encode()).hexdigest()[:10]
            if not existing:code_targets.register(target,source,source.name)
        print('Tekshiruv doim online: OSV, CISA KEV, NVD va EPSS ga paket nomlari va versiyalarini yuboradi. Kod va sirlar yuborilmaydi.',file=sys.stderr)
    scanners.check_target(target)
    print('Tekshiruv boshlandi. Natija CVE va kutubxonalar bo‘limida saqlanadi.',flush=True,file=sys.stderr)
    report=dependencies.start(target,background=False)
    print(json.dumps({key:report.get(key) for key in ('id','target','state','count','priority_counts','progress')},ensure_ascii=False,indent=2))
    print('Hisobot: '+str(dependencies.RUNS/report['id']/'report.json'),file=sys.stderr)
    raise SystemExit(0 if report['state']=='completed' else 2)


if __name__=='__main__':
    try:main()
    except (ValueError,OSError) as error:
        print('Tekshiruv boshlanmadi: '+str(error),file=sys.stderr);raise SystemExit(2)
