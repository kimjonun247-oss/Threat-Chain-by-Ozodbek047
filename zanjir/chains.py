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
    'SX-004': ('Tashqariga ochiq xizmat manbasida ekspluatatsiyaga yaroqli zaiflik bor',
               'Zaif kod yo‘lini tuzating (parametrlangan so‘rov, kirishni tozalash, xavfsiz deserializatsiya). '
               'Tuzatilmaguncha xizmatni host portidan olib tashlang yoki faqat ichki tarmoqqa cheklang.'),
    'SX-005': ('Tashqariga ochiq xizmatning asos image’i qo‘llab-quvvatlanmaydi (EOL)',
               'Asos image’ni qo‘llab-quvvatlanadigan versiyaga yangilang va qayta yig‘ing. EOL OS uchun yangi '
               'tuzatish chiqmaydi — ochiq qoldirish doimiy, tuzalmaydigan xavf.'),
    'SX-006': ('Tashqariga ochiq xizmatning manba bog‘liqligida ekspluatatsiya qilinayotgan yoki kritik CVE bor',
               'Zaif kutubxonani tuzatilgan versiyaga yangilang va qayta yig‘ing. Darhol imkoni bo‘lmasa, xizmatni '
               'host portidan olib tashlang yoki ichki tarmoqqa cheklang — CVE tuzatilmaguncha ochiq qoldirmang.'),
    'SX-007': ('Konteynerdan chiqish imtiyozli, tashqariga ochiq xizmatda ekspluatatsiyaga yaroqli zaiflik yoki sir bor',
               'Avval konteyner chiqish yo‘lini yoping (docker.sock mount’ini olib tashlang, privileged/xavfli cap’ni '
               'bekor qiling), so‘ng zaiflik yoki sirni tuzating. Bu ikkisi birga — kodni ekspluatatsiya qilish host '
               'nazoratiga olib boradi.'),
}
# SX-001: CWE-798 Use of Hard-coded Credentials + CWE-668 Exposure to Wrong Sphere.
CWE_IDS = [798, 668]
# SX-002/SX-003: CWE-1395 Dependency on Vulnerable Third-Party Component (A03)
# + CWE-668 Exposure of Resource to Wrong Sphere (A01). The pair is the point:
# the component is vulnerable *and* it is reachable.
SUPPLY_CHAIN_CWE = [1395, 668]
# The severity that makes a CVE worth chaining on its own, when KEV says nothing.
CHAIN_SEVERITY = 'CRITICAL'

# SX-004: the code-weakness classes an attacker reaches *through* a service's own
# port -- injection, traversal, SSRF, deserialization, template/expression. A
# weakness of another class (weak crypto, missing header) is real but is not
# turned into a remote entry point by exposure, so it is not chained here.
EXPLOITABLE_CWE = {22, 74, 77, 78, 79, 89, 90, 91, 94, 98, 434, 502, 611, 776, 917, 918, 943, 1336}


def _cwe_number(cwe):
    try:
        return int(str(cwe).split('-')[-1])
    except (TypeError, ValueError):
        return -1


def _exploitable(cwe_ids):
    """The exploitable-class CWE tags of a code finding, in the order given."""
    return [c for c in (cwe_ids or []) if _cwe_number(c) in EXPLOITABLE_CWE]


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


def code_weakness_chains(code_report, repository_report):
    """SX-004: an exposed service with an externally exploitable weakness in its
    own source. SX-001 chains a hard-coded secret; this chains an injection,
    SSRF, traversal or deserialization flaw -- the classes an attacker reaches
    through the very port the service exposes, so 'reachable' becomes 'directly
    attackable'. INFO-level findings are left out: they are style notes, not the
    remote entry point the pairing is about."""
    weaknesses = [f for f in (code_report or {}).get('findings', [])
                  if f.get('tool') in ('semgrep', 'codeql', 'pmd')
                  and str(f.get('severity') or '').upper() != 'INFO'
                  and _exploitable(f.get('cwe_ids'))]
    if not weaknesses:
        return []
    reachable = [s for s in (repository_report or {}).get('services', [])
                 if s.get('build_context') and any(p['scope'] != 'loopback' for p in s.get('ports', []))]
    results = []
    for service in reachable:
        context = service['build_context']
        prefix = context + '/'
        for wf in weaknesses:
            path = wf.get('path', '')
            if path != context and not path.startswith(prefix):
                continue
            hit = _exploitable(wf.get('cwe_ids'))
            cwe_ids = sorted(set(hit + ['CWE-668']))
            results.append({
                'rule_id': 'SX-004', 'title': RULES['SX-004'][0], 'service_id': service['id'],
                'fingerprint': findings_mod.derived('SX-004', [service['id'], wf.get('fingerprint') or path]),
                'detail': (f"{service['id']} xizmati host portidan ochiq ({port_summary(service)}) va uning manba "
                           f"katalogida ({context}) {wf.get('tool')} {wf.get('rule_id', '?')} zaifligini topdi "
                           f"({path}:{wf.get('line', '?')}, {', '.join(hit)}). Bu sinf aynan ochiq port orqali "
                           "hujumchi yeta oladigan turdagi: alohida har biri statik topilma, birga esa "
                           "to‘g‘ridan-to‘g‘ri ekspluatatsiya yuzasi."),
                'remediation': RULES['SX-004'][1], 'cwe_ids': cwe_ids,
                'owasp_top10_2025': taxonomy.classify([_cwe_number(c) for c in cwe_ids]),
                'level': 'error', 'verified': False, 'runtime_verified': False,
                'verification_note': ('Ikki mustaqil statik skaner bog‘landi: Compose portni, kod skaneri esa '
                                      'zaif naqshni ko‘rsatadi. Zaif kod yo‘li amalda chaqirilishi va tashqaridan '
                                      'yetib borilishi qo‘lda tasdiqlanishi shart.'),
                'evidence': {'code_tool': wf.get('tool'), 'code_rule': wf.get('rule_id'),
                             'code_path': f"{path}:{wf.get('line', '?')}", 'code_cwe': hit,
                             'compose_service': service['id'], 'host_ports': port_summary(service),
                             'build_context': context},
            })
    return results


def eol_image_chains(repository_report, image_reports, links):
    """SX-005: an exposed service whose base image is past end-of-life. No vendor
    fix will come for the next CVE, so the exposure is permanent rather than a
    race against a patch -- and a low CVE count on an EOL OS reads as 'safe' when
    it only means the feed stopped tracking it."""
    exposed = {s['id']: s for s in exposed_services(repository_report)}
    results = []
    for target, report in sorted((image_reports or {}).items()):
        os_info = (report or {}).get('os') or {}
        if not os_info.get('EOSL'):
            continue
        link = (links or {}).get(target)
        service = exposed.get(link['service']) if link else None
        if service is None:
            continue
        name = f"{os_info.get('Family', '')} {os_info.get('Name', '')}".strip()
        results.append({
            'rule_id': 'SX-005', 'title': RULES['SX-005'][0], 'service_id': service['id'],
            'fingerprint': findings_mod.derived('SX-005', [service['id'], target, str(os_info.get('Name'))]),
            'detail': (f"{service['id']} xizmati host portidan ochiq ({port_summary(service)}) va uning {target} "
                       f"image’i {name} — qo‘llab-quvvatlash muddati tugagan (EOL). Bunday OS uchun yangi "
                       "zaifliklar bazaga kiritilmaydi va tuzatish chiqmaydi: kam CVE ko‘rinishi 'xavfsiz' "
                       "degani emas, aksincha doimiy, tuzalmaydigan ochiq xavf."),
            'remediation': RULES['SX-005'][1],
            'cwe_ids': ['CWE-668', 'CWE-1104'], 'owasp_top10_2025': taxonomy.classify([668, 1104]),
            'level': 'error', 'verified': False, 'runtime_verified': False,
            'verification_note': ('Compose portni, Trivy esa asos OS ning EOL holatini ko‘rsatdi. Amaliy ta’sir '
                                  'asos image qo‘llab-quvvatlanadigan versiyaga yangilangach yo‘qoladi.'),
            'evidence': {'compose_service': service['id'], 'host_ports': port_summary(service),
                         'image_target': target, 'os': name},
        })
    return results


def dependency_chains(dependency_report, repository_report):
    """SX-006: an exposed service whose own source dependencies carry a
    known-exploited or critical CVE. SX-002 catches this in the built image;
    this catches it at source -- before a build, or for a project that ships no
    image at all -- by matching the manifest that declares the package to the
    service's build context. Only P1 (KEV-exploited or CRITICAL) findings chain:
    a reachable service with an actively exploited library is the toxic pair."""
    high = [f for f in (dependency_report or {}).get('findings', []) if f.get('priority') == 'P1']
    if not high:
        return []
    reachable = [s for s in (repository_report or {}).get('services', [])
                 if s.get('build_context') and any(p['scope'] != 'loopback' for p in s.get('ports', []))]
    results = []
    for service in reachable:
        context = service['build_context']
        prefix = context + '/'
        for f in high:
            locs = [o for o in f.get('occurrences') or []
                    if (o.get('manifest') or '') == context or str(o.get('manifest') or '').startswith(prefix)]
            if not locs:
                continue
            pkg = f.get('package') or {}
            cwe_ids = sorted(set((f.get('cwe_ids') or []) + [f'CWE-{c}' for c in SUPPLY_CHAIN_CWE]))
            results.append({
                'rule_id': 'SX-006', 'title': RULES['SX-006'][0], 'service_id': service['id'],
                'fingerprint': findings_mod.derived('SX-006', [service['id'], f.get('fingerprint') or f.get('advisory_id') or '']),
                'detail': (f"{service['id']} xizmati host portidan ochiq ({port_summary(service)}) va uning manba "
                           f"bog‘liqligida {pkg.get('ecosystem')} {pkg.get('name')} {pkg.get('version')} paketida "
                           f"{f.get('advisory_id')} bor ({locs[0].get('manifest')}). "
                           + ('CISA KEV: real hujumlarda ishlatilgani ma’lum.' if f.get('known_exploited') else 'Kritik og‘irlik bahosi.')
                           + ' Zaif kutubxona tashqariga ochiq xizmatda ishlaydi — alohida har biri odatiy, birga esa hujum yuzasi.'),
                'remediation': RULES['SX-006'][1],
                'cwe_ids': cwe_ids,
                'owasp_top10_2025': taxonomy.classify([_cwe_number(c) for c in cwe_ids]),
                'level': 'error', 'verified': False, 'runtime_verified': False,
                'verification_note': ('Kutubxona CVE mosligi (OSV/CISA KEV) va Compose port ochiqligi bog‘landi; '
                                      'image ishga tushirilmagan va zaif kutubxona yo‘li amalda chaqirilishi tekshirilmagan.'),
                'evidence': {'compose_service': service['id'], 'host_ports': port_summary(service),
                             'package': f"{pkg.get('name')} {pkg.get('version')}", 'advisory_id': f.get('advisory_id'),
                             'manifest': locs[0].get('manifest'), 'known_exploited': f.get('known_exploited'),
                             'build_context': context},
            })
    return results


# SX-007: the privileges that turn code execution in a container into control of
# the host. CWE-250 Execution with Unnecessary Privileges + CWE-668.
ESCAPE_CWE = [250, 668]


def escape_escalation_chains(code_report, repository_report):
    """SX-007: an exposed service that can both be broken into and break out.

    It fires only when one service carries all three facts: it is exposed, it has
    a container-escape primitive (RP-007 docker.sock or RP-008 privileged/caps),
    and its own source holds an externally exploitable weakness or a hard-coded
    secret. Each is already its own finding; together they are the full path --
    exploit the code, then escape the container to the host -- so this is the one
    chain reported at the top of the list."""
    repo = repository_report or {}
    escape = {f.get('service_id') for f in repo.get('findings') or [] if f.get('rule_id') in ('RP-007', 'RP-008')}
    if not escape:
        return []
    exposed = {s['id']: s for s in exposed_services(repo) if s.get('build_context') and s['id'] in escape}
    if not exposed:
        return []
    entries = [f for f in (code_report or {}).get('findings', [])
               if (f.get('tool') == 'gitleaks')
               or (f.get('tool') in ('semgrep', 'codeql', 'pmd')
                   and str(f.get('severity') or '').upper() != 'INFO' and _exploitable(f.get('cwe_ids')))]
    results = []
    for sid, service in sorted(exposed.items()):
        context = service['build_context']
        prefix = context + '/'
        for f in entries:
            path = f.get('path', '')
            if path != context and not path.startswith(prefix):
                continue
            is_secret = f.get('tool') == 'gitleaks'
            kind = 'qattiq kodlangan sir' if is_secret else f"ekspluatatsion zaiflik ({', '.join(_exploitable(f.get('cwe_ids')))})"
            results.append({
                'rule_id': 'SX-007', 'title': RULES['SX-007'][0], 'service_id': sid,
                'fingerprint': findings_mod.derived('SX-007', [sid, f.get('fingerprint') or path]),
                'detail': (f"{sid} xizmati host portidan ochiq va konteynerdan chiqish imtiyoziga ega "
                           "(docker.sock yoki privileged/xavfli capability), ayni paytda uning manba katalogida "
                           f"({context}) {kind} bor ({path}:{f.get('line', '?')}). Uchalasi birga: kodni "
                           "ekspluatatsiya qilish konteynerni, keyin esa host’ni egallashga olib boradi."),
                'remediation': RULES['SX-007'][1],
                'cwe_ids': sorted(set((_exploitable(f.get('cwe_ids')) if not is_secret else []) + [f'CWE-{c}' for c in ESCAPE_CWE])),
                'owasp_top10_2025': taxonomy.classify(ESCAPE_CWE + [_cwe_number(c) for c in (_exploitable(f.get('cwe_ids')) if not is_secret else [])]),
                'level': 'error', 'verified': False, 'runtime_verified': False,
                'verification_note': ('Compose konteyner imtiyozini va host portini, kod skaneri esa manbadagi '
                                      'kirish nuqtasini ko‘rsatdi; amaliy zanjir qo‘lda tasdiqlanishi shart.'),
                'evidence': {'compose_service': sid, 'host_ports': port_summary(service), 'build_context': context,
                             'entry_kind': 'secret' if is_secret else 'code_weakness',
                             'entry_tool': f.get('tool'), 'entry_rule': f.get('rule_id'),
                             'entry_path': f"{path}:{f.get('line', '?')}"},
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
    deps = stage_reports.get('dependencies')
    results, gaps = [], []
    if code and repository:
        results += correlate(code, repository)                  # SX-001
        results += code_weakness_chains(code, repository)       # SX-004
        results += escape_escalation_chains(code, repository)   # SX-007
    elif repository and not code:
        gaps.append({'kind': 'stage_missing', 'detail': 'Kod bosqichi tanlanmagan; SX-001 (sir + ochiq port) '
                                                        'tekshirilmadi.'})
    if repository and image_reports:
        rp006 = {f.get('service_id') for f in repository.get('findings') or [] if f.get('rule_id') == 'RP-006'}
        rows, image_gaps = image_chains(repository, image_reports, links or {}, rp006, ambiguous or ())
        results += rows                                          # SX-002, SX-003
        results += eol_image_chains(repository, image_reports, links or {})  # SX-005
        gaps += image_gaps
    if deps and repository:
        results += dependency_chains(deps, repository)          # SX-006
    elif repository and not image_reports:
        gaps.append({'kind': 'stage_missing', 'detail': 'Image bosqichi tanlanmagan; SX-002 va SX-003 '
                                                        '(ochiq xizmat + CVE) tekshirilmadi.'})
    if not repository:
        gaps.append({'kind': 'stage_missing', 'detail': 'Repository (Compose) bosqichi tanlanmagan; hech bir '
                                                        'cross-skaner zanjiri tekshirilmadi.'})
    return {'findings': results, 'gaps': gaps}
