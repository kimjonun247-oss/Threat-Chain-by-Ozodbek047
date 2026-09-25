"""Real OSV positive/fixed-version control. Does not install or execute packages."""
import argparse
import json
from zanjir.engine import ROOT
from zanjir import code_targets, dependencies, repo_store


def archive_superseded_pair(previous, keep):
    """Move the pair the new result replaced out of the live listing.

    Every run adds a before/after pair, and only the newest pair is referenced
    as evidence. Left alone, 53 superseded control reports had filled more than
    half of the global dependency listing and pushed real projects out of it.
    The pair is moved, never deleted -- `dependency-runs/_archive/` keeps it.
    """
    archive = dependencies.RUNS / '_archive'
    for key in ('before', 'after'):
        rid = previous.get(key)
        if not isinstance(rid, str) or rid in keep:
            continue
        source = dependencies.RUNS / rid
        if source.is_dir() and dependencies.scanners.ID.fullmatch(rid):
            archive.mkdir(exist_ok=True)
            source.rename(archive / rid)


def main():
    parser = argparse.ArgumentParser(description='Zanjir OSV nazorat sinovi (doim online)')
    parser.parse_args()
    target = 'validation-osv-control'
    folder = ROOT / 'validation-runs/osv-control/source'
    folder.mkdir(parents=True, exist_ok=True)
    if not any(row['id'] == target for row in code_targets.profiles()):
        code_targets.register(target, folder, 'Nazorat namunasi · lodash versiyalari')
    reports = []
    for version in ('4.17.20', '4.17.21'):
        repo_store.write_json(folder/'package-lock.json', {'name': 'zanjir-control', 'lockfileVersion': 3,
                'packages': {'node_modules/lodash': {'version': version}}})
        report = dependencies.start(target, background=False)
        reports.append(report)
        print(version + ': ' + report['state'], flush=True)
    before, after = reports
    cve = 'CVE-2021-23337'
    advisory = 'GHSA-35jh-r3h4-6jhm'
    def matched(report):
        return any(advisory in row['matched_advisory_ids'] for row in report['findings'])
    assertions = {'old_version_matches_known_cve': matched(before), 'fixed_version_no_longer_matches_that_cve': not matched(after),
                  'both_queries_finished': all(r['state'] in {'completed', 'partial'} and not r.get('query_errors') and r.get('feeds',{}).get('osv',{}).get('checked_packages') == 1 for r in reports)}
    result = {'created_at': dependencies.now(), 'control_cve': cve, 'matched_record': advisory, 'before': before['id'], 'after': after['id'],
              'versions': ['4.17.20','4.17.21'], 'assertions': assertions, 'passed': all(assertions.values()),
              'comparison': dependencies.compare(before, after),
              'limits': 'Faqat ko‘rsatilgan advisory uchun versiya farqi tekshirildi. Yangi advisory eski CVE ni alias sifatida saqlashi mumkin; faqat bevosita matched record hisoblanadi. 4.17.21 barcha zaifliklardan xoli deb aytilmaydi. Paketlar o‘rnatilmadi va bajarilmadi.'}
    result_path = ROOT/'validation-runs/osv-control/result.json'
    try:
        superseded = json.loads(result_path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        superseded = {}
    repo_store.write_json(result_path, result)
    archive_superseded_pair(superseded, keep={before['id'], after['id']})
    print(json.dumps(result, ensure_ascii=False, indent=2))
    raise SystemExit(0 if result['passed'] else 1)


if __name__ == '__main__': main()
