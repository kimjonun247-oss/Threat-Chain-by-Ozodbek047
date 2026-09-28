"""Optional deep analysis: CodeQL taint tracking across files and functions.

Semgrep's open-source engine matches patterns inside one function (and, with
taint mode, inside one file). A request value read in `routes.py` and passed
through a helper in `db.py` into a raw SQL string is invisible to it. CodeQL
builds a database of the whole program and follows the data, so it reports
that flow -- with every step, source to sink -- which is what this stage adds.

It is opt-in (settings: deep_analysis.codeql) because it is large, slow and
separately licensed; see setup_codeql.py. What it runs:

  - languages detected in the scan snapshot that CodeQL analyses **without a
    build**: Python, JavaScript/TypeScript, Ruby, Java/Kotlin and C# with
    `--build-mode=none`. Go, C/C++ and Swift need the project to be compiled,
    which would execute its build scripts -- this project never runs repository
    code, so they are listed as not covered. PHP is not supported by CodeQL
    at all (its inter-file analysis needs Semgrep Pro, a commercial engine).
  - the `security-extended` query suite of each language, from the bundle
    (no network: --no-download), at low priority, with a time limit.

Findings carry the data-flow path (source and sink file:line, step count),
the rule's CWE tags and security-severity, and stay `unverified_static`: a
flow CodeQL can prove in code is not proof it is reachable in production.
"""
import json
import os
import re
import subprocess
import sys
from pathlib import Path

from . import findings as findings_mod
from . import priority, taxonomy
from .engine import ROOT

TOOLS = ROOT / '.tools/codeql'
TIMEOUT = 1800
EXTENSIONS = {
    'python': ('.py',),
    'javascript': ('.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.vue'),
    'ruby': ('.rb', '.erb'),
    'java': ('.java', '.kt'),
    'csharp': ('.cs', '.cshtml', '.razor'),
}
NEEDS_BUILD = {'go': ('.go',), 'cpp': ('.c', '.cc', '.cpp', '.h', '.hpp'), 'swift': ('.swift',)}
UNSUPPORTED = {'php': ('.php',)}
SUITE = '{lang}-security-extended.qls'
PACK = {'python': 'codeql/python-queries', 'javascript': 'codeql/javascript-queries', 'ruby': 'codeql/ruby-queries',
        'java': 'codeql/java-queries', 'csharp': 'codeql/csharp-queries'}
SEVERITY = [(9.0, 'ERROR'), (7.0, 'ERROR'), (4.0, 'WARNING'), (0.1, 'INFO')]


def binary():
    return TOOLS / 'codeql' / ('codeql.exe' if sys.platform.startswith('win') else 'codeql')


def installed():
    return binary().is_file()


def enabled():
    from . import settings
    return bool((settings.read().get('deep_analysis') or {}).get('codeql'))


def languages(source):
    """(analysable, needs_build, unsupported) language names present in the snapshot."""
    suffixes = {path.suffix.lower() for path in Path(source).rglob('*') if path.is_file()}
    pick = lambda table: sorted(lang for lang, exts in table.items() if suffixes & set(exts))
    return pick(EXTENSIONS), pick(NEEDS_BUILD), pick(UNSUPPORTED)


def version(env):
    done = subprocess.run([str(binary()), 'version', '--format=json'], capture_output=True, text=True, timeout=120, env=env)
    # `codeql version --format=json` is an object today, but a future CLI (or an
    # error written to stdout) could hand back a list or malformed JSON. Reading
    # the field defensively keeps a surprise here from raising AttributeError,
    # which run()'s except below does not catch and which would sink the whole
    # code scan rather than just this optional stage.
    try:
        data = json.loads(done.stdout)
    except (ValueError, TypeError):
        return ''
    return str(data.get('version') or '') if isinstance(data, dict) else ''


def severity_of(rule):
    props = rule.get('properties') or {}
    try:
        score = float(props.get('security-severity'))
    except (TypeError, ValueError):
        score = None
    if score is not None:
        return next(level for floor, level in SEVERITY + [(0, 'INFO')] if score >= floor), score
    return {'error': 'ERROR', 'warning': 'WARNING'}.get(props.get('problem.severity'), 'INFO'), None


def location(loc):
    physical = (loc or {}).get('physicalLocation') or {}
    uri = ((physical.get('artifactLocation') or {}).get('uri') or '').replace('\\', '/')
    line = int((physical.get('region') or {}).get('startLine') or 0)
    return uri, line


def normalize(sarif, source):
    """SARIF from `codeql database analyze` -> code findings with their data-flow path."""
    result = []
    for run in sarif.get('runs') or []:
        driver = (run.get('tool') or {}).get('driver') or {}
        rules = {rule.get('id'): rule for rule in driver.get('rules') or []}
        for extension in (run.get('tool') or {}).get('extensions') or []:
            rules.update({rule.get('id'): rule for rule in extension.get('rules') or []})
        for row in run.get('results') or []:
            rule_id = str(row.get('ruleId') or '')
            if not re.fullmatch(r'[A-Za-z0-9_./-]{1,220}', rule_id):
                continue
            path, line = location((row.get('locations') or [{}])[0])
            if not path or line < 1 or not (Path(source) / path).resolve().is_relative_to(Path(source).resolve()):
                continue
            rule = rules.get(rule_id) or {}
            tags = (rule.get('properties') or {}).get('tags') or []
            cwes = sorted({'CWE-' + str(int(m.group(1))) for tag in tags
                           for m in [re.fullmatch(r'external/cwe/cwe-(\d+)', str(tag))] if m})
            level, score = severity_of(rule)
            flow = None
            for code_flow in row.get('codeFlows') or []:
                steps = [location(step.get('location')) for thread in code_flow.get('threadFlows') or []
                         for step in thread.get('locations') or []]
                steps = [step for step in steps if step[0]]
                if steps:
                    files = sorted({step[0] for step in steps})
                    flow = {'source': f'{steps[0][0]}:{steps[0][1]}', 'sink': f'{steps[-1][0]}:{steps[-1][1]}',
                            'steps': len(steps), 'files': files, 'cross_file': len(files) > 1}
                    break
            mapped = taxonomy.tag_from_metadata(cwes) if cwes else {'cwe_ids': [], 'owasp_top10_2025': []}
            message = str(((row.get('message') or {}).get('text')) or rule.get('shortDescription', {}).get('text') or rule_id)
            result.append({
                'tool': 'codeql', 'rule_id': rule_id, 'path': path, 'line': line,
                'fingerprint': findings_mod.fingerprint('codeql', {'rule_id': rule_id, 'path': path,
                                                                   'sink': flow['sink'] if flow else f'{path}:{line}',
                                                                   'source': flow['source'] if flow else ''}),
                'message': re.sub(r'\s+', ' ', message)[:500], 'severity': level, 'security_severity': score,
                'state': 'unverified_static', 'secret_value': None,
                'cwe_ids': mapped['cwe_ids'] or cwes, 'owasp_top10_2025': mapped['owasp_top10_2025'],
                'data_flow': flow, 'verified': False,
                'verification_note': ('CodeQL kod bo‘yicha manbadan xavfli nuqtagacha ma’lumot oqimini topdi'
                                      + (f" ({flow['steps']} qadam, {len(flow['files'])} fayl)" if flow else '') +
                                      '; ishlab chiqarishda bu yo‘lga yetib bo‘lishi va amaliy ta’siri tekshirilmagan.'),
            })
    return result


def run(source, work, env, cancel=None):
    """Analyse the snapshot. Returns (tool record, findings); never raises for a tool failure."""
    record = {'state': 'completed', 'count': 0, 'languages': [], 'not_covered': {}}
    analysable, needs_build, unsupported = languages(source)
    record['not_covered'] = {**{lang: 'build talab qiladi (repository kodi bajarilmaydi)' for lang in needs_build},
                             **{lang: 'CodeQL qo‘llamaydi (fayllararo tahlil uchun Semgrep Pro kerak)' for lang in unsupported}}
    if not installed():
        return {**record, 'state': 'failed', 'message': 'CodeQL o‘rnatilmagan: python3 setup_codeql.py'}, []
    try:
        record['version'] = version(env)
    except (OSError, ValueError, subprocess.SubprocessError):
        return {**record, 'state': 'failed', 'message': 'CodeQL versiyasini aniqlab bo‘lmadi.'}, []
    found, failures = [], {}
    for lang in analysable:
        database, output = Path(work) / f'codeql-db-{lang}', Path(work) / f'codeql-{lang}.sarif'
        create = [str(binary()), 'database', 'create', str(database), f'--language={lang}', f'--source-root={source}',
                  '--build-mode=none', '--threads=2', '--ram=2048', '--overwrite', '--quiet']
        analyze = [str(binary()), 'database', 'analyze', str(database), f'{PACK[lang]}:codeql-suites/{SUITE.format(lang=lang)}',
                   '--format=sarif-latest', f'--output={output}', '--threads=2', '--ram=2048', '--no-download',
                   f'--sarif-category={lang}', '--quiet']
        try:
            for command in (create, analyze):
                gentle, low = priority.gentle(command)
                done = subprocess.run(gentle, cwd=work, env=env, capture_output=True, text=True, encoding='utf-8',
                                      errors='replace', timeout=TIMEOUT, **low)
                if done.returncode != 0:
                    raise ValueError(f'{command[1]} {command[2]} kod {done.returncode}: ' + done.stderr.strip()[-300:])
            rows = normalize(json.loads(output.read_text(encoding='utf-8')), source)
            found += rows
            record['languages'].append({'language': lang, 'findings': len(rows)})
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            failures[lang] = type(error).__name__ + (': ' + str(error)[:300] if isinstance(error, ValueError) else '')
    record['count'] = len(found)
    record['cross_file_flows'] = sum(bool((f.get('data_flow') or {}).get('cross_file')) for f in found)
    if failures:
        record['failures'] = failures
        record['state'] = 'partial' if record['languages'] else 'failed'
    if not analysable:
        record['message'] = 'CodeQL tahlil qila oladigan (build talab qilmaydigan) til topilmadi.'
    return record, found
