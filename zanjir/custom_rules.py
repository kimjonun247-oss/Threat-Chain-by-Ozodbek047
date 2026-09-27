"""Operator-authored Semgrep rules, added from the web interface.

Why only Semgrep YAML, and nothing else:

  - Semgrep rules are *declarative*. A rule describes a pattern to look for; it
    cannot execute code, open a socket or read a file outside the snapshot. The
    project's Python chain rules (RP-00X in repository.py, SX-00X in
    chain_secrets.py) are the opposite -- they are program logic, and accepting
    them over HTTP would put arbitrary code execution inside a security tool.
    Those stay in the repository, written by hand and reviewed.
  - Nuclei templates are deliberately NOT accepted here either. A template
    issues real network requests, so accepting one from a form would let the
    interface aim traffic at any host -- that needs the same written-authorisation
    model the "Sayt va API" section already enforces for targets, not a text box.

Trust boundary: the server is bound to localhost and rejects cross-site requests,
so whoever can reach this endpoint can already register a project directory for
scanning. Adding a declarative rule is no more privileged than that. The checks
below are therefore about keeping bad rules from silently corrupting scan
results, not about defending against a remote attacker.

Every rule is validated twice: structurally here, then by Semgrep's
its own rule parser (a scan of an empty folder, fully offline), which is the only
thing that truly knows whether a pattern parses.
"""
import datetime
import json
import re
import subprocess
import tempfile
from pathlib import Path

from vendor import yaml

from .engine import ROOT
from . import repo_store

DIRECTORY = ROOT / 'scanner-rules/local'
MAX_BYTES = 16 * 1024
MAX_RULES = 20
ID = re.compile(r'^[a-z0-9][a-z0-9._-]{2,80}$')

SEVERITIES = {'ERROR', 'WARNING', 'INFO'}
# Languages this project's bundled Semgrep (OSS build) can actually parse.
LANGUAGES = {'python', 'javascript', 'typescript', 'go', 'java', 'ruby', 'php', 'c', 'cpp',
             'csharp', 'kotlin', 'scala', 'rust', 'bash', 'json', 'yaml', 'html', 'generic',
             'dockerfile', 'terraform', 'solidity', 'ocaml', 'clojure'}
PATTERN_KEYS = {'pattern', 'patterns', 'pattern-either', 'pattern-regex', 'pattern-sources'}
ALLOWED_KEYS = PATTERN_KEYS | {'id', 'message', 'languages', 'severity', 'metadata', 'paths',
                               'mode', 'pattern-not', 'pattern-inside', 'pattern-not-inside',
                               'pattern-not-regex', 'metavariable-pattern', 'metavariable-regex',
                               'metavariable-comparison', 'focus-metavariable'}
# `fix`/`fix-regex` rewrite source files (only under --autofix, which this project
# never passes -- refused anyway, since a scanner has no business editing code).
# `options`/`join`/`r2c-internal-*` change engine behaviour or reach the network.
FORBIDDEN_KEYS = {'fix', 'fix-regex', 'fix_regex', 'options', 'join',
                  'r2c-internal-project-depends-on', 'pattern-propagators'}


def parse(text):
    """YAML with the same bounds repository.py applies to untrusted compose files."""
    if not isinstance(text, str) or not text.strip():
        raise ValueError('Qoida matni bo‘sh.')
    if len(text.encode('utf-8')) > MAX_BYTES:
        raise ValueError(f'Qoida matni {MAX_BYTES // 1024} KiB dan oshmasligi kerak.')
    depth = 0
    # The depth/alias scan runs before safe_load and parses the document itself,
    # so it raises on malformed YAML too. Without this guard a rule editor typo
    # ("rules: [") escaped as a yaml.YAMLError -- not a ValueError -- past the
    # handler in app.py, and the browser got a closed connection instead of a
    # message saying which line was wrong.
    try:
        for event in yaml.parse(text):
            if isinstance(event, (yaml.MappingStartEvent, yaml.SequenceStartEvent)):
                depth += 1
            if isinstance(event, (yaml.MappingEndEvent, yaml.SequenceEndEvent)):
                depth -= 1
            if depth > 20:
                raise ValueError('YAML murakkabligi chegaradan oshdi.')
            if isinstance(event, yaml.AliasEvent):
                raise ValueError('YAML alias/anchor qo‘llanmaydi; qoidani to‘liq yozing.')
        parsed = yaml.safe_load(text)
    except yaml.YAMLError as error:
        raise ValueError('YAML o‘qilmadi: ' + str(getattr(error, 'problem', error))[:200]) from None
    if not isinstance(parsed, dict) or set(parsed) != {'rules'}:
        raise ValueError('Yuqori darajada faqat bitta `rules:` kaliti bo‘lishi kerak.')
    rules = parsed['rules']
    if not isinstance(rules, list) or not rules:
        raise ValueError('`rules:` ro‘yxati bo‘sh bo‘lmasligi kerak.')
    if len(rules) > MAX_RULES:
        raise ValueError(f'Bir faylda {MAX_RULES} tadan ko‘p qoida bo‘lmasligi kerak.')
    return parsed


def check_rule(rule, index):
    where = f'{index + 1}-qoida'
    if not isinstance(rule, dict):
        raise ValueError(f'{where}: obyekt bo‘lishi kerak.')
    forbidden = sorted(set(rule) & FORBIDDEN_KEYS)
    if forbidden:
        raise ValueError(f'{where}: bu kalitlar qabul qilinmaydi — {", ".join(forbidden)}. '
                         'Ular manba faylini o‘zgartiradi yoki engine sozlamasiga tegadi.')
    unknown = sorted(set(rule) - ALLOWED_KEYS)
    if unknown:
        raise ValueError(f'{where}: noma’lum kalit — {", ".join(unknown)}.')
    rule_id = rule.get('id')
    if not isinstance(rule_id, str) or not ID.fullmatch(rule_id):
        raise ValueError(f'{where}: `id` kichik harf, raqam, nuqta, tire va pastki chiziqdan '
                         'iborat 3–81 belgi bo‘lishi kerak.')
    if not isinstance(rule.get('message'), str) or not rule['message'].strip():
        raise ValueError(f'{where}: `message` kerak — topilma nima ekanini tushuntiradi.')
    severity = rule.get('severity')
    if severity not in SEVERITIES:
        raise ValueError(f'{where}: `severity` {", ".join(sorted(SEVERITIES))} dan biri bo‘lishi kerak.')
    languages = rule.get('languages')
    if not isinstance(languages, list) or not languages:
        raise ValueError(f'{where}: `languages` ro‘yxati kerak.')
    unsupported = sorted({str(l) for l in languages} - LANGUAGES)
    if unsupported:
        raise ValueError(f'{where}: qo‘llanmaydigan til — {", ".join(unsupported)}.')
    if not set(rule) & PATTERN_KEYS:
        raise ValueError(f'{where}: kamida bitta naqsh kaliti kerak ({", ".join(sorted(PATTERN_KEYS))}).')
    # Without a CWE the finding reaches the report with no CWE and no OWASP
    # category, and this project never guesses one after the fact.
    metadata = rule.get('metadata')
    cwe = metadata.get('cwe') if isinstance(metadata, dict) else None
    if isinstance(cwe, (str, int)):
        cwe = [cwe]
    if not isinstance(cwe, list) or not any(re.match(r'\s*(?:CWE-)?\d+', str(c), re.IGNORECASE) for c in cwe or []):
        raise ValueError(f'{where}: `metadata.cwe` kerak, masalan ["CWE-89: SQL Injection"]. '
                         'CWE’siz topilma OWASP toifasiga bog‘lanmaydi va bu yerda taxmin qilinmaydi.')
    return rule_id


def semgrep_validate(text):
    """Semgrep's own parser -- the only check that knows if a pattern parses.

    `semgrep --validate` was used before, but it also downloads a lint rule set
    from semgrep.dev: offline or behind a proxy that blocks it, every call hung for
    about 100 seconds and the request handler with it. Loading the rule for a scan
    of an empty folder runs the same rule parser, fully offline, in ~2 seconds.
    """
    from . import scanners
    binary = scanners.semgrep_exe()
    if not binary.is_file():
        raise ValueError('Semgrep o‘rnatilmagan; qoidani tekshirib bo‘lmadi.')
    with tempfile.TemporaryDirectory(prefix='rule-') as temp:
        path = Path(temp) / 'candidate.yml'
        path.write_text(text, encoding='utf-8')
        empty = Path(temp) / 'empty'
        empty.mkdir()
        try:
            process = subprocess.run(
                [str(binary), 'scan', '--config', str(path), '--metrics', 'off',
                 '--disable-version-check', '--json', '--quiet', str(empty)],
                cwd=temp, env=scanners.environment(Path(temp)), capture_output=True,
                text=True, encoding='utf-8', errors='replace', timeout=120)
        except (OSError, subprocess.TimeoutExpired):
            raise ValueError('Semgrep tekshiruvi bajarilmadi.')
    errors = None
    try:
        errors = json.loads(process.stdout).get('errors') or []
    except (ValueError, AttributeError):
        pass
    if process.returncode == 0 and errors == []:
        return
    if errors:
        detail = ' '.join(str(e.get('message') or e.get('long_msg') or e.get('type') or '') for e in errors
                          if isinstance(e, dict))
    else:
        detail = process.stderr
    raise ValueError('Semgrep qoidani qabul qilmadi: ' + (' '.join(detail.split())[:400] or
                                                          f'chiqish kodi {process.returncode}'))


def taken_ids(exclude=None):
    """Rule ids already in use, so a new rule cannot quietly shadow another."""
    used = {}
    for row in listing():
        if row['name'] == exclude:
            continue
        for rule_id in row['rule_ids']:
            used[rule_id] = row['name']
    return used


def validate(text, name=None):
    """Full check without saving. Returns the rule ids the text would register."""
    parsed = parse(text)
    ids = []
    for index, rule in enumerate(parsed['rules']):
        ids.append(check_rule(rule, index))
    duplicates = sorted(i for i in ids if ids.count(i) > 1)
    if duplicates:
        raise ValueError('Fayl ichida `id` takrorlangan: ' + ', '.join(sorted(set(duplicates))))
    clash = taken_ids(exclude=name)
    for rule_id in ids:
        if rule_id in clash:
            raise ValueError(f'`{rule_id}` allaqachon `{clash[rule_id]}` faylida ishlatilgan.')
    semgrep_validate(text)
    return ids


def safe_name(value):
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise ValueError('Fayl nomi kichik harf, raqam, nuqta, tire va pastki chiziqdan iborat 3–81 belgi bo‘lishi kerak.')
    return value


def path_for(name):
    path = (DIRECTORY / (safe_name(name) + '.yml')).resolve()
    if path.parent != DIRECTORY.resolve():
        raise ValueError('Fayl yo‘li chegaradan chiqdi.')
    return path


def save(name, text, note=''):
    name = safe_name(name)
    if not isinstance(note, str) or len(note) > 500:
        raise ValueError('Izoh 500 belgidan oshmasligi kerak.')
    ids = validate(text, name=name)
    DIRECTORY.mkdir(parents=True, exist_ok=True)
    path_for(name).write_text(text, encoding='utf-8')
    repo_store.write_json(DIRECTORY / (name + '.meta.json'), {
        'name': name, 'rule_ids': ids, 'note': note.strip(),
        'saved_at': datetime.datetime.now(datetime.timezone.utc).isoformat()})
    return describe(name)


def describe(name):
    path = path_for(name)
    meta_path = DIRECTORY / (name + '.meta.json')
    try:
        meta = json.loads(meta_path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        meta = {}
    text = path.read_text(encoding='utf-8')
    try:
        rule_ids = [r.get('id') for r in parse(text)['rules']]
    except ValueError:
        rule_ids = meta.get('rule_ids') or []
    return {'name': name, 'rule_ids': [r for r in rule_ids if r], 'note': meta.get('note', ''),
            'saved_at': meta.get('saved_at'), 'bytes': len(text.encode('utf-8')), 'text': text}


def listing():
    if not DIRECTORY.is_dir():
        return []
    rows = []
    for path in sorted(DIRECTORY.glob('*.yml')):
        try:
            rows.append(describe(path.stem))
        except (OSError, ValueError):
            continue
    return rows


def delete(name):
    path = path_for(name)
    if not path.is_file():
        raise ValueError('Bunday qoida fayli yo‘q.')
    path.unlink()
    (DIRECTORY / (name + '.meta.json')).unlink(missing_ok=True)
    return {'name': name, 'deleted': True}


def active():
    """The directory to hand Semgrep, or None when no local rule is saved."""
    return DIRECTORY if DIRECTORY.is_dir() and any(DIRECTORY.glob('*.yml')) else None


def messages():
    """rule_id -> the rule's own wording, for the same reason the official pack
    is read this way: Semgrep interpolates matched source text into its output,
    the rule file's text is fixed."""
    result = {}
    for row in listing():
        try:
            parsed = parse(row['text'])
        except ValueError:
            continue
        for rule in parsed['rules']:
            if isinstance(rule, dict) and rule.get('id') and rule.get('message'):
                result[str(rule['id'])] = ' '.join(str(rule['message']).split())[:400]
    return result


def summary():
    rows = listing()
    return {'files': len(rows), 'rules': sum(len(r['rule_ids']) for r in rows)}
