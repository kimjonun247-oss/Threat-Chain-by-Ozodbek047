"""CWE -> OWASP Top 10:2025 mapping and known rule -> CWE tags.

OWASP Top 10:2025 was published in January 2026 (announced Nov 2025 at the
OWASP Global AppSec Conference) -- the first revision since 2021. Category
membership below was pulled directly from MITRE's own CWE category pages
(cwe.mitre.org/data/definitions/1436.html .. 1445.html, one page per A01-A10),
which are the canonical machine-readable source OWASP itself points to. All
249 members of the ten categories are mirrored here -- every CWE those pages
list, re-checked against them on 2026-09-25 (CWE-1450 is the parent view
"Weaknesses in OWASP Top Ten RC1 (2025)", not a member, so it is not mapped).
A CWE missing from CWE_TO_OWASP is still shown as a plain CWE-ID; it is never
guessed into a category (e.g. CWE-400 "Uncontrolled Resource Consumption" and
CWE-1333 "Inefficient Regular Expression Complexity" were checked directly
and are NOT members of any OWASP Top 10:2025 category, unlike some informal
2021-era mappings that grouped them under Insecure Design).
"""
import re

OWASP_TOP10_2025 = {
    'A01': 'A01:2025 – Broken Access Control',
    'A02': 'A02:2025 – Security Misconfiguration',
    'A03': 'A03:2025 – Software Supply Chain Failures',
    'A04': 'A04:2025 – Cryptographic Failures',
    'A05': 'A05:2025 – Injection',
    'A06': 'A06:2025 – Insecure Design',
    'A07': 'A07:2025 – Authentication Failures',
    'A08': 'A08:2025 – Software or Data Integrity Failures',
    'A09': 'A09:2025 – Security Logging and Alerting Failures',
    'A10': 'A10:2025 – Mishandling of Exceptional Conditions',
}

# CWE number -> OWASP Top 10:2025 category code. Source: MITRE CWE category
# pages 1436 (A01) through 1445 (A10), fetched directly; see module docstring.
CWE_TO_OWASP = {
    # A01:2025 - Broken Access Control (CWE-1436)
    22:'A01',23:'A01',36:'A01',59:'A01',61:'A01',65:'A01',200:'A01',201:'A01',
    219:'A01',
    276:'A01',281:'A01',282:'A01',283:'A01',284:'A01',285:'A01',352:'A01',
    359:'A01',377:'A01',379:'A01',402:'A01',424:'A01',425:'A01',441:'A01',
    497:'A01',538:'A01',540:'A01',548:'A01',552:'A01',566:'A01',601:'A01',
    615:'A01',639:'A01',668:'A01',732:'A01',749:'A01',862:'A01',863:'A01',
    918:'A01',922:'A01',1275:'A01',
    # A02:2025 - Security Misconfiguration (CWE-1437)
    5:'A02',11:'A02',13:'A02',15:'A02',16:'A02',260:'A02',315:'A02',489:'A02',
    526:'A02',547:'A02',611:'A02',614:'A02',776:'A02',942:'A02',1004:'A02',
    1174:'A02',
    # A03:2025 - Software Supply Chain Failures (CWE-1438)
    447:'A03',477:'A03',1035:'A03',1104:'A03',1329:'A03',1395:'A03',
    # A04:2025 - Cryptographic Failures (CWE-1439)
    261:'A04',296:'A04',319:'A04',320:'A04',321:'A04',322:'A04',323:'A04',
    324:'A04',325:'A04',326:'A04',327:'A04',328:'A04',329:'A04',330:'A04',
    331:'A04',332:'A04',334:'A04',335:'A04',336:'A04',337:'A04',338:'A04',
    340:'A04',342:'A04',347:'A04',523:'A04',757:'A04',759:'A04',760:'A04',
    780:'A04',916:'A04',1240:'A04',1241:'A04',
    # A05:2025 - Injection (CWE-1440)
    20:'A05',74:'A05',76:'A05',77:'A05',78:'A05',79:'A05',80:'A05',83:'A05',
    86:'A05',88:'A05',89:'A05',90:'A05',91:'A05',93:'A05',94:'A05',95:'A05',
    96:'A05',97:'A05',98:'A05',99:'A05',103:'A05',104:'A05',112:'A05',
    113:'A05',114:'A05',115:'A05',116:'A05',129:'A05',159:'A05',
    470:'A05',493:'A05',500:'A05',564:'A05',610:'A05',643:'A05',644:'A05',
    917:'A05',
    # A06:2025 - Insecure Design (CWE-1441)
    73:'A06',183:'A06',256:'A06',266:'A06',269:'A06',286:'A06',311:'A06',
    312:'A06',313:'A06',316:'A06',362:'A06',382:'A06',419:'A06',434:'A06',
    436:'A06',444:'A06',451:'A06',454:'A06',472:'A06',501:'A06',522:'A06',
    525:'A06',539:'A06',598:'A06',602:'A06',628:'A06',642:'A06',646:'A06',
    653:'A06',656:'A06',657:'A06',676:'A06',693:'A06',799:'A06',807:'A06',
    841:'A06',1021:'A06',1022:'A06',1125:'A06',
    # A07:2025 - Authentication Failures (CWE-1442)
    258:'A07',259:'A07',287:'A07',288:'A07',289:'A07',290:'A07',291:'A07',
    293:'A07',294:'A07',295:'A07',297:'A07',298:'A07',299:'A07',300:'A07',
    302:'A07',303:'A07',304:'A07',305:'A07',306:'A07',307:'A07',308:'A07',
    309:'A07',346:'A07',350:'A07',384:'A07',521:'A07',613:'A07',620:'A07',
    640:'A07',798:'A07',940:'A07',941:'A07',1390:'A07',1391:'A07',1392:'A07',
    1393:'A07',
    # A08:2025 - Software or Data Integrity Failures (CWE-1443)
    345:'A08',353:'A08',426:'A08',427:'A08',494:'A08',502:'A08',506:'A08',
    509:'A08',565:'A08',784:'A08',829:'A08',830:'A08',915:'A08',926:'A08',
    # A09:2025 - Security Logging and Alerting Failures (CWE-1444)
    117:'A09',221:'A09',223:'A09',532:'A09',778:'A09',
    # A10:2025 - Mishandling of Exceptional Conditions (CWE-1445)
    209:'A10',215:'A10',234:'A10',235:'A10',248:'A10',252:'A10',274:'A10',
    280:'A10',369:'A10',390:'A10',391:'A10',394:'A10',396:'A10',397:'A10',
    460:'A10',476:'A10',478:'A10',484:'A10',550:'A10',636:'A10',703:'A10',
    754:'A10',755:'A10',756:'A10',
}

# Findings whose exact CWE is known ahead of time (this project's own rules,
# fixed Nuclei templates and fixed HTTP header checks). Keyed by rule/finding id.
RULE_CWE = {
    'zanjir.python.shell-execution': [78], 'zanjir.python.eval': [95],
    'zanjir.python.tls-verification-disabled': [295], 'zanjir.javascript.eval': [95],
    'zanjir.javascript.shell-execution': [78], 'zanjir.go.tls-verification-disabled': [295],
    'zanjir.java.process-execution': [78],
    'zanjir.python.command-injection': [78], 'zanjir.python.sql-injection': [89],
    'zanjir.python.sql-string-building': [89], 'zanjir.python.insecure-deserialization': [502],
    'zanjir.python.pickle-usage': [502], 'zanjir.python.yaml-unsafe-load': [502],
    'zanjir.python.flask-debug': [489], 'zanjir.python.weak-hash': [328],
    'zanjir.javascript.command-injection': [78], 'zanjir.javascript.sql-injection': [89],
    'zanjir.java.sql-string-building': [89], 'zanjir.go.sql-string-building': [89],
    'zanjir.java.command-injection': [78], 'zanjir.java.sql-injection': [89],
    'zanjir.java.insecure-deserialization': [502], 'zanjir.go.sql-injection': [89],
    'zanjir.go.command-injection': [78], 'zanjir.php.sql-injection': [89], 'zanjir.php.xss': [79],
    'zanjir.python.xxe': [611], 'zanjir.python.template-injection': [1336], 'zanjir.javascript.prototype-pollution': [1321],
    'dir-listing': [548], 'http-dir-listing': [548], 'git-config': [538], 'zanjir-compose': [538],
    'zanjir-env': [522], 'zanjir-openapi': [200], 'zanjir-sql-backup': [538],
    'ambiguous-fallback': [200],
    'http-transport': [319], 'x-content-type-options': [16],
    'strict-transport-security': [319], 'csp-missing': [1021], 'frame-protection': [1021],
    'RP-001': [284], 'RP-002': [295], 'RP-003': [284], 'RP-004': [290], 'RP-005': [668], 'RP-006': [489],
    'RP-007': [269], 'RP-008': [269],
    # RP-009 alias traversal, RP-010 SSRF through a client-controlled upstream,
    # RP-011 security headers silently dropped by nginx's add_header rules.
    'RP-009': [22], 'RP-010': [918], 'RP-011': [693],
    # API inventory: an exposed spec leaks the API surface (CWE-200); a
    # documented endpoint reachable without auth is missing authorization (CWE-862).
    'api-spec-exposed': [200], 'api-endpoint-unauthenticated': [862],
    'cors-reflected-origin-credentials': [942], 'cors-wildcard-credentials': [942],
    'cookie-missing-secure': [614], 'cookie-missing-httponly': [1004],
    'server-fingerprint': [200], 'error-disclosure': [209],
    # PMD 7 category/apex/security.xml -- the Apex coverage OSS Semgrep lacks.
    # Each CWE is the weakness the rule's own description names.
    'ApexBadCrypto': [321], 'ApexCRUDViolation': [862], 'ApexDangerousMethods': [749],
    'ApexInsecureEndpoint': [319], 'ApexOpenRedirect': [601], 'ApexSharingViolations': [284],
    'ApexSOQLInjection': [89], 'ApexSuggestUsingNamedCred': [798],
    'ApexXSSFromEscapeFalse': [79], 'ApexXSSFromURLParam': [79],
}
GITLEAKS_DEFAULT_CWE = [798]


def owasp_category(cwe_number):
    code = CWE_TO_OWASP.get(cwe_number)
    return {'code': code, 'name': OWASP_TOP10_2025[code]} if code else None


def classify(cwe_ids):
    """cwe_ids: iterable of 'CWE-123' strings or ints. Returns sorted unique OWASP entries."""
    numbers = set()
    for value in cwe_ids or []:
        match = re.fullmatch(r'(?:CWE-)?(\d+)', str(value).strip(), re.IGNORECASE)
        if match:
            numbers.add(int(match.group(1)))
    categories = {}
    for number in numbers:
        entry = owasp_category(number)
        if entry:
            categories[entry['code']] = entry
    return sorted(categories.values(), key=lambda item: item['code'])


def tag_static(tool, rule_id):
    """CWE/OWASP tags for a scanner/nuclei/repository rule id known ahead of time."""
    cwes = sorted(set(RULE_CWE.get(rule_id, GITLEAKS_DEFAULT_CWE if tool == 'gitleaks' else [])))
    return {'cwe_ids': [f'CWE-{c}' for c in cwes], 'owasp_top10_2025': classify(cwes)}


def tag_from_metadata(values):
    """CWE/OWASP tags from a rule's own declared CWE metadata.

    Official Semgrep rules carry `metadata.cwe` entries shaped like
    "CWE-78: Improper Neutralization of ...". Only the identifier is trusted:
    the OWASP category is always derived through this module's own MITRE-sourced
    CWE_TO_OWASP map, never taken from the upstream rule's own `owasp` field, so
    a single authoritative mapping stays in force across every scanner.
    Returns None when the rule declares no parsable CWE, so the caller can fall
    back to tag_static() for this project's own rules.
    """
    if isinstance(values, (str, int)):
        values = [values]
    numbers = set()
    for value in values or []:
        match = re.match(r'\s*(?:CWE-)?(\d+)', str(value), re.IGNORECASE)
        if match:
            numbers.add(int(match.group(1)))
    if not numbers:
        return None
    return {'cwe_ids': [f'CWE-{n}' for n in sorted(numbers)], 'owasp_top10_2025': classify(sorted(numbers))}
