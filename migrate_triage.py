"""Import the old per-report reviews into the project-scoped triage store.

Before B2 a review was stored against a report: dependency reviews in
`dependency-runs/<id>/reviews.json` and repository reviews in
`repository-runs/reviews.json`. Both are now read by zanjir/triage.py and
re-filed under (project, fingerprint), so the decision survives the next scan.

Nothing is deleted or rewritten. Each source keeps working for the endpoints
that already read it, and a `reviews.migrated.json` marker beside it records
what was imported -- delete the marker to run the import again. An existing
triage decision is never overwritten.

    python3 migrate_triage.py --dry-run
    python3 migrate_triage.py
"""
import argparse
import json

from zanjir import triage


def main():
    parser = argparse.ArgumentParser(description='Eski review’larni triage do‘koniga ko‘chirish')
    parser.add_argument('--dry-run', action='store_true', help='Hech nima yozmasdan nimalar ko‘chishini ko‘rsatadi')
    parser.add_argument('--json', action='store_true', help='Natijani JSON sifatida chiqaradi')
    args = parser.parse_args()
    result = triage.migrate(dry_run=args.dry_run)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=1))
        raise SystemExit(0)
    head = 'Ko‘chiriladi' if args.dry_run else 'Ko‘chirildi'
    print(f'{head}: {result["count"]} ta qaror')
    for row in result['imported']:
        print(f'  {row["stage"]:13} {row["scope"]:24} {row["fingerprint"]} -> {row["status"]}')
    for note in result['notes']:
        print(f'  e’tibor: {note}')
    if args.dry_run and result['count']:
        print('\nYozish uchun --dry-run siz qayta ishga tushiring.')
    raise SystemExit(0)


if __name__ == '__main__':
    main()
