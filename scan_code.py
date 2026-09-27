import sys
import argparse,json
from zanjir import scanners

if __name__=='__main__':
    parser=argparse.ArgumentParser(description='Zanjir lokal Semgrep va Gitleaks tekshiruvi')
    parser.add_argument('--target',default='crapi-full')
    parser.add_argument('--diagnose-latest',action='store_true',help='Faqat sun’iy faylda Semgrep diagnostikasi')
    args=parser.parse_args()
    if args.diagnose_latest:
        history=scanners.history()
        if not history:parser.error('Avvalgi skan hisoboti topilmadi.')
        print('Semgrep sun’iy faylda tekshirilmoqda. Repository qayta skan qilinmaydi.',flush=True,file=sys.stderr)
        diagnostic=scanners.diagnose_semgrep(history[0]['id'])
        print(json.dumps({'report_id':history[0]['id'],'steps':[
            {key:step[key] for key in ('step','exit_code','error_type') if key in step}
            for step in diagnostic['steps']]},indent=2))
        print('Diagnostika saqlandi. Natijani hisobot papkasida ko‘ring.',flush=True,file=sys.stderr)
        raise SystemExit(0)
    try:report=scanners.start(args.target,background=False)
    except (ValueError,OSError) as error:
        print('Tekshiruv boshlanmadi: '+str(error),file=sys.stderr);raise SystemExit(2)
    print(json.dumps({key:report.get(key) for key in ('id','state','count','tools','coverage')},indent=2,ensure_ascii=False))
    if report.get('tools',{}).get('semgrep',{}).get('state')=='failed':
        print('Semgrep xatosi maxfiy ma’lumotsiz sinov faylida tekshirilmoqda...',flush=True,file=sys.stderr)
        scanners.diagnose_semgrep(report['id'])
        print('Alohida diagnostika saqlandi.',flush=True,file=sys.stderr)
    raise SystemExit(0 if report['state']=='completed' else 2)
