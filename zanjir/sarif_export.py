"""Best-effort SARIF 2.1.0 conversion for the "Umumiy tekshiruv" pipeline.

Repository (Compose/Nginx) findings already carry precise file:line evidence
and get their own richer converter in zanjir/repository.py:sarif(); this
module reuses that one for the 'repository' stage and covers the other four
stages plus the cross-scanner chain (SX-001) with a best-effort mapping --
their finding shapes vary a lot, and several (dependencies, images) have no
source file location at all. A result with no usable location is still
emitted (SARIF allows it); it just won't get an inline PR annotation from
most CI consumers, only a plain list entry.
"""
from . import findings as findings_mod, repository as repository_mod

TOOL_NAME = 'ThreatChain'
_LEVELS = {'CRITICAL': 'error', 'HIGH': 'error', 'ERROR': 'error',
           'MEDIUM': 'warning', 'WARNING': 'warning',
           'LOW': 'note', 'UNKNOWN': 'note', 'NOTE': 'note', 'INFO': 'note'}


def _level(value):
    return _LEVELS.get(str(value or '').upper(), 'warning')


def _entry(rule_id, title, level, cwe_ids, path=None, line=None, fingerprint=None):
    return {'rule_id': str(rule_id), 'title': title or str(rule_id), 'level': level,
            'cwe_ids': cwe_ids or [], 'path': path, 'line': line, 'fingerprint': fingerprint}


def _code_entries(findings):
    # Gitleaks has no per-rule severity, so every secret match stays 'error'.
    # Semgrep findings carry the rule's own ERROR/WARNING/INFO once the official
    # pack is installed; without it there is no severity and 'warning' stands.
    return [_entry(f['rule_id'], f.get('message'),
                   'error' if f.get('tool') == 'gitleaks' else _level(f.get('severity') or 'WARNING'),
                   f.get('cwe_ids'), f.get('path'), f.get('line'), f.get('fingerprint')) for f in findings]


def _dependencies_entries(findings):
    return [_entry(f.get('advisory_id') or f['package']['name'],
                    f"{f['package']['name']} {f['package']['version']}: {f.get('summary') or f.get('advisory_id')}",
                    _level(f.get('severity')), f.get('cwe_ids'), fingerprint=f.get('fingerprint')) for f in findings]


def _images_entries(findings):
    return [_entry(f.get('advisory_id') or f['package'], f"{f['package']} {f['version']}: {f.get('title') or f.get('advisory_id')}",
                    _level(f.get('severity')), f.get('cwe_ids'), fingerprint=f.get('fingerprint')) for f in findings]


def _web_entries(findings):
    return [_entry(f.get('rule_id') or f.get('title'), f.get('title'), _level(f.get('severity')),
                    f.get('cwe_ids'), f.get('path'), fingerprint=f.get('fingerprint')) for f in findings]


def _iac_entries(findings):
    return [_entry(f.get('rule_id'), f.get('title') or f.get('message'), _level(f.get('severity')),
                    f.get('cwe_ids'), f.get('path'), f.get('line'), f.get('fingerprint')) for f in findings]


def _chain_entries(findings):
    return [_entry(f['rule_id'], f.get('title'), _level(f.get('level')), f.get('cwe_ids'),
                    f.get('evidence', {}).get('gitleaks_path'), f.get('evidence', {}).get('gitleaks_line'),
                    f.get('fingerprint'))
            for f in findings]


_STAGE_CONVERTERS = {'code': _code_entries, 'dependencies': _dependencies_entries,
                      'images': _images_entries, 'web': _web_entries, 'iac': _iac_entries}


def _run(entries, stage):
    rules, seen, results = [], set(), []
    for e in entries:
        if e['rule_id'] not in seen:
            seen.add(e['rule_id'])
            rules.append({'id': e['rule_id'], 'shortDescription': {'text': e['title']},
                          'properties': {'tags': e['cwe_ids']}})
        result = {'ruleId': e['rule_id'], 'level': e['level'], 'message': {'text': e['title']}}
        # The same key the repository converter has always used, now on every
        # stage: GitHub and GitLab track a SARIF result across runs by this
        # value, so without it an unchanged finding is re-reported as new on
        # every scan and its resolved comments are lost.
        if e.get('fingerprint'):
            result['partialFingerprints'] = {findings_mod.VERSION: e['fingerprint']}
        if e['path']:
            result['locations'] = [{'physicalLocation': {'artifactLocation': {'uri': str(e['path']).replace('\\', '/')},
                                    'region': {'startLine': max(1, int(e['line'] or 1))}}}]
        results.append(result)
    return _label({'tool': {'driver': {'name': TOOL_NAME, 'rules': rules}}, 'results': results}, stage)


STAGE_TOOLS = {'code': 'Semgrep + Gitleaks (+ PMD)', 'repository': 'ThreatChain Compose/Nginx qoidalari',
               'dependencies': 'OSV + CISA KEV + NVD + EPSS', 'images': 'Trivy image', 'iac': 'Trivy config',
               'web': 'Nuclei + ThreatChain HTTP', 'chain': 'ThreatChain cross-skaner zanjirlari'}


def _label(run, stage):
    """Give each run its own category and say which scanner produced it.

    Every run used to be an anonymous "ThreatChain" run. GitHub code scanning
    identifies a run by tool name + category, and it no longer merges several
    runs that share both, so a multi-stage file could be rejected, and nothing
    in the file said which scanner a result came from. The driver name stays
    "ThreatChain" so alerts keep their identity; the category and a property
    carry the stage.
    """
    run['automationDetails'] = {'id': f'threatchain/{stage}/'}
    driver = run['tool']['driver']
    driver.setdefault('version', repository_mod.VERSION)
    driver['informationUri'] = 'https://github.com/kimjonun247-oss/Kim-Jon-Un'
    run['properties'] = {**run.get('properties', {}), 'stage': stage, 'scanner': STAGE_TOOLS.get(stage, stage)}
    return run


def build(report):
    """report: a completed pipeline (assessment) report, as returned by pipeline.read()."""
    runs = []
    for stage in report.get('stages', []):
        child = stage.get('report')
        if not child:
            continue
        if stage['kind'] == 'repository':
            runs.append(_label(repository_mod.sarif(child)['runs'][0], 'repository'))
            continue
        converter = _STAGE_CONVERTERS.get(stage['kind'])
        if converter:
            runs.append(_run(converter(child.get('findings') or []), stage['kind']))
    chain_findings = report.get('chain_findings') or []
    if chain_findings:
        runs.append(_run(_chain_entries(chain_findings), 'chain'))
    if not runs:
        runs.append(_run([], 'empty'))
    return {'$schema': 'https://json.schemastore.org/sarif-2.1.0.json', 'version': '2.1.0', 'runs': runs}
