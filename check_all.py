import argparse
import json
from zanjir import pipeline


def main():
    p = argparse.ArgumentParser(description='Zanjir umumiy pilot tekshiruvi')
    p.add_argument('--target', default='crapi-full')
    p.add_argument('--repository-target', default='')
    p.add_argument('--web-target', default='')
    p.add_argument('--image-target', default='')
    p.add_argument('--online', action='store_true')
    a = p.parse_args()
    r = pipeline.start(vars(a), background=False)
    print(json.dumps({'id': r['id'], 'state': r['state'], 'stages': [{k: s.get(k) for k in ('kind', 'state', 'count', 'report_id')} for s in r['stages']]}, ensure_ascii=False, indent=2))
    raise SystemExit(0 if r['state'] == 'completed' else 2)


if __name__ == '__main__':
    main()
