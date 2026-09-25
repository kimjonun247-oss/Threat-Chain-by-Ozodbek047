"""CycloneDX 1.6 SBOM built from an image report's own package inventory.

Why not `trivy image --format cyclonedx`: that would download and scan the image
a second time -- ten minutes and a gigabyte for an answer already sitting in the
report. Trivy runs with `--list-all-pkgs`, so the package list is part of the
same evidence the findings came from, and building the SBOM from it means the
document and the vulnerability report can never disagree about what is installed.

Two limits are stated in the document itself rather than implied:

  - It describes what Trivy found inside the image, which is not necessarily
    everything: a package installed outside a known manager is invisible to it.
  - A report produced before this module existed carries no package list. That
    is an error with a reason, not an empty SBOM -- an SBOM claiming zero
    components would be a false statement about the image.
"""
import datetime
import hashlib
import json
import uuid

SPEC_VERSION = '1.6'
FORMAT = 'CycloneDX'
# Named so a validator can find the schema without being told which version.
SCHEMA = 'http://cyclonedx.org/schema/bom-1.6.schema.json'
NOTE = ('Trivy aniqlagan paketlar ro‘yxati. Ma’lum paket menejeridan tashqarida o‘rnatilgan fayllar '
        'bu ro‘yxatga kirmaydi, shuning uchun bu image ichidagi hamma narsaning to‘liq kafolati emas.')


def _ref(package, index):
    """A stable bom-ref: the PURL when Trivy produced one, else a hash of the row."""
    if package.get('purl'):
        return package['purl']
    seed = json.dumps([package.get('target'), package.get('name'), package.get('version')], sort_keys=True)
    return 'urn:threatchain:' + hashlib.sha256(seed.encode('utf-8')).hexdigest()[:32]


def component(package, index):
    row = {'type': 'library', 'bom-ref': _ref(package, index),
           'name': package.get('name') or '', 'version': package.get('version') or ''}
    if package.get('purl'):
        row['purl'] = package['purl']
    if package.get('licenses'):
        # `expression` is not used: Trivy reports license *names*, and turning a
        # list of names into an SPDX expression would assert a relationship
        # (AND/OR) that nothing in the evidence establishes.
        row['licenses'] = [{'license': {'name': name}} for name in package['licenses']]
    if package.get('target'):
        row['properties'] = [{'name': 'threatchain:target', 'value': str(package['target'])},
                             {'name': 'threatchain:type', 'value': str(package.get('type') or '')}]
    return row


SEVERITIES = {'CRITICAL': 'critical', 'HIGH': 'high', 'MEDIUM': 'medium', 'LOW': 'low', 'NEGLIGIBLE': 'info'}


def vulnerabilities(report, prefix=''):
    """The image report's own advisory matches as CycloneDX `vulnerabilities`.

    The SBOM used to list components only, so the 85 CVEs known for
    python:3.9.0-alpine were missing from the one export a downstream tool would
    read. Each entry points at the exact component (`affects.ref`); a match whose
    package is not in the inventory is kept with no `affects` rather than being
    attached to a guessed component.
    """
    refs = {}
    for index, package in enumerate(report.get('packages') or []):
        refs.setdefault((package.get('target'), package.get('name'), package.get('version')),
                        prefix + _ref(package, index))
        refs.setdefault((None, package.get('name'), package.get('version')), prefix + _ref(package, index))
    rows = []
    for finding in report.get('findings') or []:
        advisory = str(finding.get('advisory_id') or '')
        if not advisory:
            continue
        key = (finding.get('target'), finding.get('package'), finding.get('version'))
        ref = refs.get(key) or refs.get((None, finding.get('package'), finding.get('version')))
        row = {'bom-ref': prefix + 'vuln:' + advisory + ':' + str(finding.get('package')) + '@' + str(finding.get('version')),
               'id': advisory,
               'ratings': [{'severity': SEVERITIES.get(str(finding.get('severity') or '').upper(), 'unknown'),
                            'method': 'other', 'source': {'name': str(finding.get('source') or 'trivy')}}],
               'description': str(finding.get('title') or '')[:1000]}
        if finding.get('source'):
            row['source'] = {'name': str(finding['source'])}
        cwes = [int(c.split('-')[1]) for c in finding.get('cwe_ids') or [] if str(c).startswith('CWE-') and c[4:].isdigit()]
        if cwes:
            row['cwes'] = cwes
        if finding.get('fixed_version'):
            row['recommendation'] = f"{finding.get('package')} paketini {finding['fixed_version']} yoki undan yangi versiyaga yangilang."
        if ref:
            row['affects'] = [{'ref': ref}]
        properties = []
        if finding.get('known_exploited') is not None:
            properties.append({'name': 'threatchain:cisa_kev', 'value': str(bool(finding['known_exploited'])).lower()})
        if finding.get('epss') is not None:
            properties.append({'name': 'threatchain:epss', 'value': str(finding['epss'])})
        if properties:
            row['properties'] = properties
        rows.append(row)
    return rows


def build(report, serial=None):
    """One image report -> one CycloneDX document."""
    packages = report.get('packages')
    if packages is None:
        raise ValueError('Bu hisobotda paket ro‘yxati yo‘q (SBOM qo‘llab-quvvatlanishidan oldin olingan). '
                         'SBOM olish uchun image’ni qayta skanerlang.')
    reference = report.get('reference') or ''
    document = {
        '$schema': SCHEMA, 'bomFormat': FORMAT, 'specVersion': SPEC_VERSION,
        'serialNumber': serial or ('urn:uuid:' + str(uuid.uuid5(uuid.NAMESPACE_URL, 'threatchain:' + str(report.get('id'))))),
        'version': 1,
        'metadata': {
            'timestamp': report.get('created_at') or datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'tools': {'components': [{'type': 'application', 'name': 'ThreatChain',
                                      'version': str(report.get('schema_version') or 1)},
                                     {'type': 'application', 'name': 'trivy',
                                      'version': str((report.get('tool') or {}).get('version') or '')}]},
            'component': {'type': 'container', 'bom-ref': reference or str(report.get('target') or ''),
                          'name': reference.split('@')[0] or str(report.get('target') or ''),
                          'version': reference.split('@')[-1] if '@' in reference else ''},
            'properties': [{'name': 'threatchain:report_id', 'value': str(report.get('id') or '')},
                           {'name': 'threatchain:image_target', 'value': str(report.get('target') or '')},
                           {'name': 'threatchain:image_id', 'value': str(report.get('image_id') or '')},
                           {'name': 'threatchain:scan_state', 'value': str(report.get('state') or '')},
                           {'name': 'threatchain:coverage_note', 'value': NOTE}],
        },
        'components': [component(package, index) for index, package in enumerate(packages)],
        'vulnerabilities': vulnerabilities(report),
    }
    return document


def merge(reports, name='threatchain-project'):
    """One document for a whole project: every image, components kept apart.

    Components are not de-duplicated across images. Two images containing the
    same version of a library are two places to patch, and collapsing them into
    one component would hide that.
    """
    usable = [r for r in reports if isinstance(r, dict) and r.get('packages') is not None]
    if not usable:
        raise ValueError('Paket ro‘yxati bor birorta image hisoboti yo‘q; avval image’larni qayta skanerlang.')
    components, references, vulns = [], [], []
    for report in usable:
        reference = report.get('reference') or str(report.get('target') or '')
        references.append({'type': 'container', 'bom-ref': reference,
                           'name': reference.split('@')[0], 'version': reference.split('@')[-1] if '@' in reference else ''})
        for index, package in enumerate(report['packages']):
            row = component(package, index)
            row['bom-ref'] = f"{report.get('target')}|{row['bom-ref']}"
            row.setdefault('properties', []).append(
                {'name': 'threatchain:image_target', 'value': str(report.get('target') or '')})
            components.append(row)
        vulns += vulnerabilities(report, prefix=f"{report.get('target')}|")
    return {
        '$schema': SCHEMA, 'bomFormat': FORMAT, 'specVersion': SPEC_VERSION,
        'serialNumber': 'urn:uuid:' + str(uuid.uuid5(uuid.NAMESPACE_URL, 'threatchain:project:' + name)),
        'version': 1,
        'metadata': {'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                     'tools': {'components': [{'type': 'application', 'name': 'ThreatChain'}]},
                     'component': {'type': 'application', 'bom-ref': name, 'name': name},
                     'properties': [{'name': 'threatchain:images', 'value': str(len(usable))},
                                    {'name': 'threatchain:skipped_images',
                                     'value': str(len(reports) - len(usable))},
                                    {'name': 'threatchain:coverage_note', 'value': NOTE}]},
        'components': components,
        'vulnerabilities': vulns,
        'dependencies': [{'ref': name, 'dependsOn': [r['bom-ref'] for r in references]}],
    }
