"""Cross-scanner chains: findings that only exist when two scanners are read together.

Each SX rule joins facts that are unremarkable on their own. An open port is
normal. A dev-looking string in source is normal. A CVE in a base image is
normal. Put two of them on the same service and the pair is the finding -- this
is the "toxic combination" model that cloud security platforms apply to cloud
resources, applied here to a Compose file and the scanners around it.

  SX-001  exposed service + a hardcoded secret in that service's own source
          (repository + code)
  SX-002  exposed service + a known-exploited or critical CVE in its image
          (repository + images)
  SX-003  exposed service running with debug on + a CVE that already has a fix
          (repository/RP-006 + images)

Three rules hold for all of them:

  1. **Pure over completed reports.** Nothing here scans, fetches or guesses.
     Every input is a finished report, so a chain finding can always be traced
     back to the two pieces of evidence it was built from.
  2. **A service is linked to its image, never assumed to be.** When the link
     cannot be made the image is reported as unlinked; an unchecked image must
     not look like a clean one.
  3. **What could not be evaluated is said out loud.** correlate() returns gaps
     alongside findings -- a missing KEV catalogue, an unlinked image, a stage
     that was not selected. Silence is not evidence of absence.

secret_value is never read or re-exposed: Gitleaks findings only ever carry
'hidden' for that field.
"""
from . import findings as findings_mod, taxonomy

RULES = {
    'SX-001': ('Ochiq xizmat manbasida qattiq kodlangan sir topildi',
               'Sirni darhol almashtiring (rotate) va muhit o‘zgaruvchisi yoki sir boshqaruvchisiga ko‘chiring; '
               'xizmat ochiq qolishi kerak bo‘lsa ham, manbada qattiq kodlangan qiymat qolmasligi kerak.'),
    'SX-002': ('Tashqariga ochiq xizmatning image’ida ekspluatatsiya qilinayotgan CVE bor',
               'Image’ni tuzatilgan versiyaga yangilang va qayta yig‘ing. Darhol imkoni bo‘lmasa, xizmatni host '
               'portidan olib tashlang yoki faqat ichki tarmoqqa cheklang — CVE tuzatilmaguncha ochiq qoldirmang.'),
    'SX-003': ('Debug rejimida ishlayotgan ochiq xizmatda tuzatilishi mumkin bo‘lgan CVE bor',
               'Debug/dev rejimini o‘chiring va image’ni tuzatilgan versiyaga yangilang. Debug rejimi xato '
               'xabarlari orqali ichki tuzilmani ochadi va bu CVE’dan foydalanishni osonlashtiradi.'),
}
# SX-001: CWE-798 Use of Hard-coded Credentials + CWE-668 Exposure to Wrong Sphere.
CWE_IDS = [798, 668]
# SX-002/SX-003: CWE-1395 Dependency on Vulnerable Third-Party Component (A03)
# + CWE-668 Exposure of Resource to Wrong Sphere (A01). The pair is the point:
# the component is vulnerable *and* it is reachable.
SUPPLY_CHAIN_CWE = [1395, 668]
# The severity that makes a CVE worth chaining on its own, when KEV says nothing.
CHAIN_SEVERITY = 'CRITICAL'


def exposed_services(repository_report):
    """Services with at least one non-loopback host port -- the RP-001 condition."""
    return [s for s in (repository_report or {}).get('services', [])
            if any(p.get('scope') != 'loopback' for p in s.get('ports') or [])]


def port_summary(service):
    return ', '.join(f"{p.get('host_ip') or '0.0.0.0'}:{p.get('published')}→{p.get('target')}"
                     for p in service.get('ports') or [] if p.get('scope') != 'loopback')[:300]


def correlate(code_report, repository_report):
    gitleaks_findings = [f for f in (code_report or {}).get('findings', []) if f.get('tool') == 'gitleaks']
    if not gitleaks_findings:
        return []
    reachable = [s for s in (repository_report or {}).get('services', [])
                 if s.get('build_context') and any(p['scope'] != 'loopback' for p in s.get('ports', []))]
    if not reachable:
        return []
    cwe_ids = [f'CWE-{c}' for c in CWE_IDS]
    owasp = taxonomy.classify(CWE_IDS)
    results = []
    for service in reachable:
        context = service['build_context']
        prefix = context + '/'
        for gf in gitleaks_findings:
            path = gf.get('path', '')
            if path != context and not path.startswith(prefix):
                continue
            results.append({
                'rule_id': 'SX-001', 'title': RULES['SX-001'][0], 'service_id': service['id'],
                # Built from the component finding's own identity, so the chain
                # is stable for exactly as long as the secret it rests on is.
                # Reports written before B1 carry no fingerprint; the path is the
                # documented fallback there, which is weaker but never wrong.
                'fingerprint': findings_mod.derived('SX-001', [service['id'], gf.get('fingerprint') or path]),
                'detail': (f"{service['id']} xizmati host portidan to‘g‘ridan-to‘g‘ri ochiq va uning manba katalogida "
                           f"({context}) Gitleaks {gf.get('rule_id', '?')} sirini topdi ({path}:{gf.get('line', '?')}). "
                           "Ikkalasi alohida to‘g‘ri: kodda test/dev qiymati qolishi va portni ochish alohida hodisalar. "
                           "Ammo birgalikda: bu xizmat boshqa yo‘l bilan (masalan boshqa zanjir topilmasi orqali) "
                           "buzilsa, sirning o‘zi darhol qo‘lga tushadi."),
                'remediation': RULES['SX-001'][1], 'cwe_ids': cwe_ids, 'owasp_top10_2025': owasp,
                'level': 'warning', 'verified': False, 'runtime_verified': False,
                'verification_note': 'Ikki mustaqil statik skaner natijasi bog‘langan; sirning haqiqiyligi va '
                                      'portning tashqi ochiqligi alohida-alohida qo‘lda tasdiqlanishi shart.',
                'evidence': {'gitleaks_path': path, 'gitleaks_line': gf.get('line'), 'gitleaks_rule_id': gf.get('rule_id'),
                             'compose_service': service['id'], 'build_context': context},
            })
    return results


def image_chains(repository_report, image_reports, links, rp006_services, ambiguous=()):
    """SX-002 and SX-003: an exposed service and the CVEs of the image it runs.

    `links` maps an image target id to the Compose service it runs, as
    portfolio.link_images() resolved it. `rp006_services` are the services the
    repository scanner already flagged as debug-enabled and exposed, so SX-003
    rests on RP-006's own judgement instead of parsing the environment twice.
    """
    exposed = {s['id']: s for s in exposed_services(repository_report)}
    cwe_ids = [f'CWE-{c}' for c in SUPPLY_CHAIN_CWE]
    owasp = taxonomy.classify(SUPPLY_CHAIN_CWE)
    results, gaps = [], []
    # One image behind several services is a different problem from an image
    # nothing matched, and the operator fixes it differently -- so it gets its
    # own gap instead of being reported as "unlinked".
    unclear = {row['image']: row.get('services') or [] for row in ambiguous or ()}
    for target, services in sorted(unclear.items()):
        gaps.append({'kind': 'image_ambiguous', 'image': target, 'services': sorted(services),
                     'detail': f'{target} image’ini bir nechta xizmat ishlatadi ({", ".join(sorted(services))}); '
                               'qaysi biri tashqariga ochiqligini image nomidan aniqlab bo‘lmaydi, shuning uchun '
                               'zanjir qoidalari tekshirilmadi. Loyiha ta’rifida `service` ni aniq ko‘rsating.'})
    for target, report in sorted(image_reports.items()):
        if target in unclear:
            continue
        link = links.get(target)
        if not link:
            gaps.append({'kind': 'image_unlinked', 'image': target,
                         'detail': f'{target} image’i Compose xizmatiga bog‘lanmadi; u uchun zanjir '
                                   'qoidalari tekshirilmadi. Loyiha ta’rifida `service` ni ko‘rsating.'})
            continue
        service = exposed.get(link['service'])
        if service is None:
            continue                      # linked, but this service is not exposed: no chain
        if (report or {}).get('state') not in ('completed', 'partial'):
            gaps.append({'kind': 'image_not_scanned', 'image': target, 'service': link['service'],
                         'detail': f'{target} image skani tugamagan ("{(report or {}).get("state")}"); '
                                   f'{link["service"]} xizmati uchun CVE zanjiri tekshirilmadi.'})
            continue
        if report.get('state') == 'partial':
            gaps.append({'kind': 'image_partial', 'image': target, 'service': link['service'],
                         'detail': f'{target} image skani qisman tugagan: {str(report.get("message") or "")[:160]} '
                                   'Topilgan zanjirlar haqiqiy, lekin qamrovdan tushib qolgan CVE’lar bo‘lishi mumkin.'})
        kev_state = ((report.get('kev') or {}).get('state')) or 'unknown'
        if kev_state != 'available':
            # Stated, not silently treated as "no exploited CVEs". Severity still
            # works, so the rule keeps running on CRITICAL rather than going dark.
            gaps.append({'kind': 'kev_unavailable', 'image': target, 'service': link['service'],
                         'detail': f'CISA KEV ro‘yxati olinmadi ("{kev_state}"); {target} uchun faqat '
                                   f'{CHAIN_SEVERITY} og‘irlik bo‘yicha tekshirildi. Ekspluatatsiya '
                                   'qilinayotgani ma’lum, lekin kritik bo‘lmagan CVE’lar o‘tkazib yuborilgan '
                                   'bo‘lishi mumkin.'})
        for finding in report.get('findings') or []:
            results += _cve_chains(service, target, report, finding, link, cwe_ids, owasp,
                                   kev_state, link['service'] in rp006_services)
    return results, gaps


def _cve_chains(service, target, report, finding, link, cwe_ids, owasp, kev_state, debug_on):
    exploited = finding.get('known_exploited') is True
    critical = str(finding.get('severity') or '').upper() == CHAIN_SEVERITY
    if not exploited and not critical:
        return []
    advisory = finding.get('advisory_id') or ''
    epss = finding.get('epss') or {}
    evidence = {'compose_service': service['id'], 'host_ports': port_summary(service),
                'image_target': target, 'image_reference': report.get('reference'),
                'package': finding.get('package'), 'installed_version': finding.get('version'),
                'advisory_id': advisory, 'severity': finding.get('severity'),
                'known_exploited': finding.get('known_exploited'), 'kev_added_on': finding.get('kev_added_on'),
                'kev_state': kev_state, 'epss': epss.get('epss'), 'epss_percentile': epss.get('percentile'),
                'fixed_version': finding.get('fixed_version') or None, 'link': link['how']}
    why = ('CISA KEV ro‘yxatida — real hujumlarda ishlatilgani ma’lum'
           if exploited else f'{CHAIN_SEVERITY} og‘irlik bahosi')
    rows = [_chain('SX-002', service, cwe_ids, owasp, evidence,
                   f"{service['id']} xizmati host portidan ochiq ({port_summary(service)}) va u ishlatadigan "
                   f"{target} image’ida {finding.get('package')} {finding.get('version')} paketida {advisory} bor "
                   f"({why}). Alohida olganda ikkalasi ham odatiy: xizmatni tashqariga ochish va image’da "
                   f"tuzatilmagan CVE qolishi. Birgalikda esa zaif komponent to‘g‘ridan-to‘g‘ri tashqaridan "
                   f"yetib boriladigan bo‘lib qoladi.",
                   'error' if exploited else 'warning',
                   [target, service['id'], advisory])]
    # SX-003 needs all three: exposed, debug on (RP-006) and a fix already available.
    # It is deliberately a second finding rather than a replacement for SX-002:
    # the two have different fixes (update the image / also turn debug off), and
    # keeping them apart means turning debug off removes exactly one finding
    # instead of swapping one identity for another in the next baseline diff.
    # They are linked so a reader sees one problem, not two.
    if debug_on and finding.get('fixed_version'):
        rows.append(_chain('SX-003', service, cwe_ids, owasp,
                           {**evidence, 'rp006': True, 'escalates': rows[0]['fingerprint']},
                           f"{service['id']} xizmati host portidan ochiq, debug/dev rejimida ishlaydi (RP-006) va "
                           f"{target} image’idagi {finding.get('package')} {finding.get('version')} paketida "
                           f"{advisory} bor — bu CVE uchun tuzatilgan versiya allaqachon mavjud "
                           f"({finding.get('fixed_version')}). Uchalasi birga: batafsil xato xabarlari ichki "
                           f"tuzilmani ochadi, CVE esa hali tuzatilmagan, xizmat esa tashqaridan yetib boriladi. "
                           f"Bu o‘sha CVE bo‘yicha SX-002 zanjirining kuchaytirilgan holati.",
                           'error', [target, service['id'], advisory, 'rp006']))
        rows[1]['escalates'] = rows[0]['fingerprint']
    return rows


def _chain(rule_id, service, cwe_ids, owasp, evidence, detail, level, identity):
    return {
        'rule_id': rule_id, 'title': RULES[rule_id][0], 'service_id': service['id'],
        'fingerprint': findings_mod.derived(rule_id, identity),
        'detail': detail, 'remediation': RULES[rule_id][1],
        'cwe_ids': cwe_ids, 'owasp_top10_2025': owasp, 'level': level,
        'verified': False, 'runtime_verified': False,
        'verification_note': ('Ikki mustaqil skaner natijasi bog‘langan: Compose tahlili portni, Trivy esa '
                              'paket–CVE mosligini ko‘rsatadi. Image ishga tushirilmagan va zaif kod yo‘li '
                              'amalda chaqirilishi tekshirilmagan — mutaxassis qo‘lda tasdiqlashi shart.'),
        'evidence': evidence,
    }


def correlate_all(stage_reports, links=None, image_reports=None, ambiguous=None):
    """Every chain rule over one assessment's stage reports.

    Returns findings and gaps together, because "this could not be checked" is
    as much a result as a finding. The caller stores both.
    """
    code = stage_reports.get('code')
    repository = stage_reports.get('repository')
    results, gaps = [], []
    if code and repository:
        results += correlate(code, repository)
    elif repository and not code:
        gaps.append({'kind': 'stage_missing', 'detail': 'Kod bosqichi tanlanmagan; SX-001 (sir + ochiq port) '
                                                        'tekshirilmadi.'})
    if repository and image_reports:
        rp006 = {f.get('service_id') for f in repository.get('findings') or [] if f.get('rule_id') == 'RP-006'}
        rows, image_gaps = image_chains(repository, image_reports, links or {}, rp006, ambiguous or ())
        results += rows
        gaps += image_gaps
    elif repository and not image_reports:
        gaps.append({'kind': 'stage_missing', 'detail': 'Image bosqichi tanlanmagan; SX-002 va SX-003 '
                                                        '(ochiq xizmat + CVE) tekshirilmadi.'})
    if not repository:
        gaps.append({'kind': 'stage_missing', 'detail': 'Repository (Compose) bosqichi tanlanmagan; hech bir '
                                                        'cross-skaner zanjiri tekshirilmadi.'})
    return {'findings': results, 'gaps': gaps}
