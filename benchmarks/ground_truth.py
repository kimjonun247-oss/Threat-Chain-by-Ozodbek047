"""Recall and false-positive counts on public vulnerable (and clean) projects.

    python benchmarks/ground_truth.py --workdir /srv/gt          # clone + scan all
    python benchmarks/ground_truth.py --only dvwa requests --output gt.json

Needs network (git clone) and the installed scanners; meant for the server, not
a laptop (see BENCHMARKS.md). Each project is cloned shallow at its `ref`, the
commit actually scanned is recorded, and the code stage runs exactly as an
operator's scan would (scanners.start, isolated THREATCHAIN_DATA_DIR).

Per project it reports:
  recall      labels found / labels whose path exists (a label whose file is not
              in the checkout is listed as `label path missing`, not as a miss)
  gate_fp     gate-relevant findings in a clean project (each one stops a build)
  signals     ERROR/WARNING findings, total and in shipped code (path_class=prod)
  unlabeled   for a vulnerable project: ERROR/WARNING findings in shipped code
              on no labelled path -- an upper bound on its false positives, since
              these projects contain more flaws than any label list names
The cloned code is only read by the scanners; nothing in it is executed.
"""
import argparse
import fnmatch
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

os.environ.setdefault('THREATCHAIN_DATA_DIR', tempfile.mkdtemp(prefix='tc-ground-truth-'))
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from zanjir import ci_gate, code_targets, engine, pathclass, scanners  # noqa: E402

SPEC = json.loads((Path(__file__).with_name('ground_truth.json')).read_text(encoding='utf-8'))['projects']


def _require_isolated_data_dir():
    # The guard lives at the scan entry, not at import. engine.DATA is resolved
    # once, when zanjir is first imported; the setdefault above only isolates it
    # when this module is that first importer (the standalone `python
    # benchmarks/ground_truth.py` run). Imported into a process where zanjir is
    # already loaded -- the unit suite importing this module to test matches()
    # -- the env var comes too late, but no scan runs, so nothing is written to
    # the real data dir. Checking here fails loudly before any scan would.
    assert str(engine.DATA) != str(engine.ROOT), 'data dir not isolated'


def cwes(finding):
    return {int(n) for c in finding.get('cwe_ids') or [] for n in re.findall(r'\d+', str(c))[:1]}


def matches(label, finding):
    path = finding.get('path') or ''
    if not (fnmatch.fnmatch(path, label['path']) or path == label['path']):
        return False
    if label.get('secret') and finding.get('tool') == 'gitleaks':
        return True
    return bool(cwes(finding) & set(label['cwe']))


def clone(name, spec, workdir):
    folder = workdir / name
    if not folder.exists():
        subprocess.run(['git', 'clone', '--depth', '1', '--branch', spec['ref'], '--quiet', spec['repo'], str(folder)],
                       check=True, timeout=1800)
    commit = subprocess.run(['git', '-C', str(folder), 'rev-parse', 'HEAD'], capture_output=True, text=True,
                            check=True).stdout.strip()
    return folder, commit


def judge(name, spec, folder, commit):
    _require_isolated_data_dir()
    target = 'gt-' + name
    if target not in {p['id'] for p in code_targets.profiles()}:
        code_targets.register(target, folder)
    started = time.perf_counter()
    report = scanners.start(target, background=False, full=True)
    wall = round(time.perf_counter() - started, 1)
    findings = report['findings']
    signals = [f for f in findings if str(f.get('severity') or '').upper() in ('ERROR', 'WARNING') or f.get('tool') == 'gitleaks']
    prod = [f for f in signals if (f.get('path_class') or pathclass.classify(f.get('path'))) == pathclass.PROD]
    gate = [f for f in findings if ci_gate.code_gate_reason(f)]
    labels, missing_paths, found, missed = spec['labels'], [], [], []
    for label in labels:
        exists = any(fnmatch.fnmatch(p.relative_to(folder).as_posix(), label['path'])
                     for p in folder.rglob('*') if p.is_file()) or (folder / label['path']).is_file()
        if not exists:
            missing_paths.append(label['path'])
        elif any(matches(label, f) for f in findings):
            found.append(label['what'])
        else:
            missed.append(label['what'])
    checked = len(found) + len(missed)
    unlabeled = [f for f in prod if not any(fnmatch.fnmatch(f.get('path') or '', l['path']) or f.get('path') == l['path']
                                            for l in labels)]
    return {'project': name, 'commit': commit, 'clean': bool(spec.get('clean')), 'state': report['state'], 'wall_s': wall,
            'files': report['coverage'].get('files'), 'findings': len(findings), 'signals': len(signals),
            'signals_prod': len(prod), 'gate': len(gate), 'gate_prod': sum(1 for f in gate if f in prod),
            'recall': None if spec.get('clean') or not checked else round(len(found) / checked, 3),
            'found': found, 'missed': missed, 'label_path_missing': missing_paths,
            'unlabeled_prod_signals': None if spec.get('clean') else len(unlabeled),
            'top_rules': sorted(((sum(1 for f in prod if f['rule_id'] == r), r) for r in {f['rule_id'] for f in prod}),
                                reverse=True)[:10]}


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--workdir', default=str(Path(tempfile.gettempdir()) / 'tc-ground-truth-src'))
    parser.add_argument('--only', nargs='+', choices=sorted(SPEC))
    parser.add_argument('--output')
    args = parser.parse_args()
    workdir = Path(args.workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    rows = []
    for name in args.only or sorted(SPEC):
        try:
            folder, commit = clone(name, SPEC[name], workdir)
            row = judge(name, SPEC[name], folder, commit)
        except (OSError, subprocess.SubprocessError, ValueError) as error:
            row = {'project': name, 'error': f'{type(error).__name__}: {error}'}
        rows.append(row)
        print(json.dumps({k: v for k, v in row.items() if k != 'top_rules'}, ensure_ascii=False), flush=True)
    if args.output:
        Path(args.output).write_text(json.dumps(rows, ensure_ascii=False, indent=1), encoding='utf-8')


if __name__ == '__main__':
    main()
