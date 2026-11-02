"""Read-only analysis of Kubernetes manifests, in the shape the Compose analyzer reports.

The chain rules (SX-00x) join "this service is reachable from outside" with what
the other scanners found about it. Until now only a Compose file could say which
services are reachable, and large systems are not deployed with Compose. This
module answers the same questions from plain manifests:

  - which workloads exist and what image each runs
        Deployment, StatefulSet, DaemonSet, ReplicaSet, Job, CronJob, Pod
  - which of them are reachable from outside the cluster
        a Service of type LoadBalancer or NodePort selecting the workload, an
        Ingress routing to such a Service, a container `hostPort`, `hostNetwork`
  - what a compromised one could do
        privileged containers, dangerous capabilities, host namespaces, a
        container-runtime socket mounted from the host

and reports them under the rule ids the Compose analyzer already uses, because
they are the same statements about a different deployment format:

  RP-001  workload reachable from outside the cluster
  RP-005  data store in the namespace of a reachable workload, with no
          NetworkPolicy restricting who may connect to it
  RP-006  debug/dev mode on a reachable workload
  RP-007  container-runtime socket mounted into a reachable workload
  RP-008  privileged / host-namespace workload that is reachable

The report has the same keys as a Compose report -- `services` with `ports`,
`image`, `networks` -- so image linking and every chain rule work unchanged.

What this does not do, and says so in the report: it reads the files as written.
Helm templates and Kustomize overlays are not rendered (a file containing `{{`
is listed as unread), nothing is asked of a live cluster, and admission
controllers, service meshes and cloud firewalls are invisible to it.
"""
import datetime
import os
import time
import uuid
from pathlib import Path

from vendor import yaml

from .engine import Notes, canonical, digest, note_gap, skip_directory
from . import taxonomy
from . import verification as verification_mod

WORKLOADS = {'Deployment', 'StatefulSet', 'DaemonSet', 'ReplicaSet', 'Job', 'CronJob', 'Pod', 'ReplicationController'}
EXTERNAL_SERVICE_TYPES = {'LoadBalancer', 'NodePort'}
RUNTIME_SOCKETS = ('docker.sock', 'containerd.sock', 'crio.sock', 'cri-dockerd.sock')
MAX_FILES = 2000
MAX_DOCUMENTS = 20000
SUFFIXES = ('.yaml', '.yml')
LIMITS = ['Faqat berilgan Kubernetes manifest fayllari o‘qildi; hech narsa bajarilmadi va klasterga so‘rov yuborilmadi.',
          'Helm shablonlari va Kustomize overlay’lari render qilinmaydi: `{{` bo‘lgan fayllar o‘qilmagan deb ko‘rsatiladi. '
          'Render qilingan natijani (`helm template`, `kustomize build`) ko‘rsating.',
          'Ishlayotgan klaster holati, admission controller, service mesh, bulut firewall va LoadBalancer manba cheklovlari ko‘rinmaydi.',
          'Service → workload bog‘lanishi faqat `selector` va `labels` mosligidan olinadi.',
          'Ogohlantirishlar review talab qiladi; bu audit muvofiqligi yoki real ekspluatatsiya isboti emas.']


def applies(root, path):
    """Whether `path` (as registered in the `compose` field) names Kubernetes manifests."""
    try:
        target = (Path(root) / str(path)).resolve()
        if not target.is_relative_to(Path(root).resolve()):
            return False
        if target.is_dir():
            return True
        if not target.is_file() or target.suffix.lower() not in SUFFIXES:
            return False
        head = target.read_bytes()[:200_000].decode('utf-8', 'replace')
    except OSError:
        return False
    lines = [line for line in head.splitlines() if line and not line.startswith(('#', ' ', '-'))]
    keys = {line.split(':', 1)[0] for line in lines if ':' in line}
    return {'apiVersion', 'kind'} <= keys and 'services' not in keys


def manifest_files(root, path):
    """Repository-relative manifest paths under `path`, sorted, plus how many were left out."""
    root = Path(root).resolve()
    start = (root / str(path)).resolve()
    if not start.is_relative_to(root):
        raise ValueError('Manifest yo‘li repository chegarasidan tashqarida.')
    if start.is_file():
        return [start.relative_to(root).as_posix()], 0
    found, extra = [], 0
    for current, dirs, files in os.walk(start, followlinks=False):
        dirs[:] = sorted(d for d in dirs if not skip_directory(current, d) and not os.path.islink(os.path.join(current, d)))
        for name in sorted(files):
            if not name.lower().endswith(SUFFIXES) or os.path.islink(os.path.join(current, name)):
                continue
            if len(found) >= MAX_FILES:
                extra += 1
                continue
            found.append((Path(current) / name).relative_to(root).as_posix())
    return found, extra


def documents(text):
    """Every YAML document of a manifest file as (mapping, line of its first key)."""
    from .repository import StrictLoader, MAX_CONFIG_BYTES, MAX_YAML_NODES
    if len(text) > MAX_CONFIG_BYTES:
        raise ValueError('Fayl hajmi chegaradan oshdi.')
    loader = StrictLoader(text)
    result, count = [], 0

    def visit(node, depth=0):
        nonlocal count
        count += 1
        if depth > 50 or count > MAX_YAML_NODES:
            raise ValueError('YAML murakkabligi chegaradan oshdi.')
        if isinstance(node, yaml.MappingNode):
            for _, value in node.value:
                visit(value, depth + 1)
        elif isinstance(node, yaml.SequenceNode):
            for value in node.value:
                visit(value, depth + 1)
    try:
        while loader.check_node():
            node = loader.get_node()
            visit(node)
            value = loader.construct_document(node)
            if isinstance(value, dict):
                result.append((value, node.start_mark.line + 1))
    except yaml.YAMLError as error:
        mark = getattr(error, 'problem_mark', None)
        raise ValueError('YAML o‘qilmadi' + (f' ({mark.line + 1}-qator)' if mark is not None else '')) from None
    finally:
        loader.dispose()
    return result


def pod_spec(kind, document):
    """(pod spec, pod labels) of a workload document."""
    spec = document.get('spec') if isinstance(document.get('spec'), dict) else {}
    metadata = document.get('metadata') if isinstance(document.get('metadata'), dict) else {}
    if kind == 'Pod':
        return spec, metadata.get('labels') or {}
    if kind == 'CronJob':
        spec = ((spec.get('jobTemplate') or {}).get('spec') or {}) if isinstance(spec.get('jobTemplate'), dict) else {}
    template = spec.get('template') if isinstance(spec.get('template'), dict) else {}
    labels = (template.get('metadata') or {}).get('labels') if isinstance(template.get('metadata'), dict) else None
    return (template.get('spec') if isinstance(template.get('spec'), dict) else {}), labels or {}


def selects(selector, labels):
    return bool(selector) and isinstance(selector, dict) and isinstance(labels, dict) and \
        all(labels.get(key) == value for key, value in selector.items())


def containers_of(spec):
    rows = []
    for key in ('containers', 'initContainers'):
        for item in spec.get(key) or []:
            if isinstance(item, dict):
                rows.append(item)
    return rows


def scan(root, path, provenance=None):
    from .repository import (RULES, DATASTORE_IMAGE, DEBUG_ENV_TRUE, DANGEROUS_CAPS, VERSION, safe_read)
    started = time.perf_counter()
    root = Path(root).resolve()
    evidence, files, unknowns, findings = [], [], Notes(), []

    def fact(file, line, label, value):
        eid = f'R{len(evidence) + 1:03}'
        evidence.append({'id': eid, 'path': file, 'line': line, 'label': label, 'value': value})
        return eid

    index = {}

    def finding(rule, service, key, detail, eids, level='warning'):
        fingerprint = digest(canonical([rule, service, key]))[:24]
        if fingerprint in index:
            index[fingerprint]['evidence_ids'] = list(dict.fromkeys(index[fingerprint]['evidence_ids'] + eids))
            return
        tags = taxonomy.tag_static('repository', rule)
        row = {'rule_id': rule, 'fingerprint': fingerprint, 'service_id': service, 'title': RULES[rule][0],
               'detail': detail, 'evidence_ids': eids, 'level': level, 'status': 'review_required',
               'remediation': REMEDIES.get(rule, RULES[rule][1]), 'runtime_verified': False, 'verified': False,
               'cwe_ids': tags['cwe_ids'], 'owasp_top10_2025': tags['owasp_top10_2025'],
               'verification_note': ('Kubernetes manifestlaridan statik o‘qilgan deklaratsiya; ishlayotgan klaster, '
                                     'tarmoq siyosati plagini va bulut firewall tekshirilmagan. Mutaxassis qo‘lda '
                                     'ko‘rib chiqishi shart.')}
        index[fingerprint] = row
        findings.append(row)

    paths, extra = manifest_files(root, path)
    if extra:
        note_gap(unknowns, f'{extra} ta manifest fayli {MAX_FILES} fayl chegarasidan tashqarida qoldi; qamrov to‘liq emas.',
                 not_reached=extra)
    workloads, services, ingresses, policies = [], [], [], []
    total = 0
    for relative in paths:
        try:
            text = safe_read(root, relative)
        except (ValueError, OSError, UnicodeDecodeError) as error:
            note_gap(unknowns, f'{relative}: o‘qilmadi — {error}')
            continue
        if '{{' in text:
            note_gap(unknowns, f'{relative}: Helm/Go shabloni (`{{{{`), render qilinmagan — o‘qilmadi.')
            continue
        try:
            parsed = documents(text)
        except ValueError as error:
            note_gap(unknowns, f'{relative}: {error}')
            continue
        files.append({'path': relative, 'sha256': digest(text.encode()), 'bytes': len(text.encode())})
        for document, line in parsed:
            total += 1
            if total > MAX_DOCUMENTS:
                raise ValueError(f'{MAX_DOCUMENTS} tadan ko‘p manifest hujjati qo‘llanmaydi.')
            kind = document.get('kind')
            metadata = document.get('metadata') if isinstance(document.get('metadata'), dict) else {}
            name, namespace = metadata.get('name'), metadata.get('namespace') or 'default'
            if not isinstance(kind, str) or not isinstance(name, str):
                continue
            row = {'kind': kind, 'name': name, 'namespace': str(namespace), 'path': relative, 'line': line,
                   'document': document}
            if kind in WORKLOADS:
                workloads.append(row)
            elif kind == 'Service':
                services.append(row)
            elif kind == 'Ingress':
                ingresses.append(row)
            elif kind == 'NetworkPolicy':
                policies.append(row)
            elif kind in ('Kustomization', 'HelmRelease'):
                note_gap(unknowns, f'{relative}: {kind} render qilinmaydi; u qo‘shadigan resurslar ko‘rinmaydi.')
    if not workloads:
        raise ValueError('Kubernetes workload (Deployment, StatefulSet, Pod, …) topilmadi.')

    # Services an Ingress routes to are reachable from outside whatever their type.
    routed = {}
    for ingress in ingresses:
        spec = ingress['document'].get('spec') if isinstance(ingress['document'].get('spec'), dict) else {}
        backends = [spec.get('defaultBackend') or spec.get('backend')]
        for rule in spec.get('rules') or []:
            for item in ((rule or {}).get('http') or {}).get('paths') or []:
                backends.append((item or {}).get('backend'))
        for backend in backends:
            if not isinstance(backend, dict):
                continue
            target = (backend.get('service') or {}).get('name') if isinstance(backend.get('service'), dict) \
                else backend.get('serviceName')
            if isinstance(target, str):
                routed.setdefault((ingress['namespace'], target), ingress)

    inventory = []
    for workload in workloads:
        spec, labels = pod_spec(workload['kind'], workload['document'])
        containers = containers_of(spec)
        sid = workload['name'] if workload['namespace'] == 'default' else f"{workload['namespace']}/{workload['name']}"
        if any(row['id'] == sid for row in inventory):
            sid = f"{sid}:{workload['kind'].lower()}"
        service_eid = fact(workload['path'], workload['line'], 'Workload', {'kind': workload['kind'], 'name': sid})
        ports = []
        for service in services:
            if service['namespace'] != workload['namespace']:
                continue
            sspec = service['document'].get('spec') if isinstance(service['document'].get('spec'), dict) else {}
            if not selects(sspec.get('selector'), labels):
                continue
            kind = sspec.get('type') or 'ClusterIP'
            ingress = routed.get((service['namespace'], service['name']))
            if kind not in EXTERNAL_SERVICE_TYPES and ingress is None:
                continue
            via = kind if kind in EXTERNAL_SERVICE_TYPES else 'Ingress'
            for port in sspec.get('ports') or [{}]:
                port = port if isinstance(port, dict) else {}
                published = port.get('nodePort') or port.get('port') or 0
                target = port.get('targetPort') if isinstance(port.get('targetPort'), int) else port.get('port')
                eid = fact(service['path'], service['line'], 'Tashqi kirish yo‘li',
                           {'service': service['name'], 'type': kind, 'via': via, 'port': port.get('port'),
                            **({'ingress': ingress['name']} if ingress is not None else {})})
                ports.append({'host_ip': None, 'published': str(published), 'target': int(target or 0),
                              'protocol': str(port.get('protocol') or 'TCP').lower(), 'scope': 'all_interfaces',
                              'evidence_id': eid, 'via': via})
        for container in containers:
            for port in container.get('ports') or []:
                if isinstance(port, dict) and port.get('hostPort'):
                    eid = fact(workload['path'], workload['line'], 'hostPort',
                               {'container': container.get('name'), 'hostPort': port['hostPort']})
                    ports.append({'host_ip': port.get('hostIP'), 'published': str(port['hostPort']),
                                  'target': int(port.get('containerPort') or 0),
                                  'protocol': str(port.get('protocol') or 'TCP').lower(), 'scope': 'all_interfaces',
                                  'evidence_id': eid, 'via': 'hostPort'})
        if spec.get('hostNetwork') is True and not ports:
            eid = fact(workload['path'], workload['line'], 'hostNetwork', True)
            ports.append({'host_ip': None, 'published': 'host', 'target': 0, 'protocol': 'tcp',
                          'scope': 'all_interfaces', 'evidence_id': eid, 'via': 'hostNetwork'})
        images = [str(c.get('image')) for c in containers if c.get('image')]
        row = {'id': sid, 'ports': ports, 'networks': [workload['namespace']], 'image': images[0] if images else '',
               'images': images, 'build_context': None, 'evidence_id': service_eid, 'auth_status': 'unknown',
               'runtime_verified': False, 'kind': workload['kind'], 'namespace': workload['namespace'],
               'labels': labels, '_spec': spec, '_containers': containers, '_where': (workload['path'], workload['line'])}
        inventory.append(row)
        if len(images) > 1:
            unknowns.append(f'{sid}: {len(images)} ta konteyner; image bog‘lanishi faqat birinchisi ({images[0]}) bo‘yicha.')

    for row in inventory:
        sid, spec, containers = row['id'], row['_spec'], row['_containers']
        file, line = row['_where']
        exposed = [p['evidence_id'] for p in row['ports']]
        if not exposed:
            continue
        ways = sorted({p['via'] for p in row['ports']})
        finding('RP-001', sid, 'external:' + ','.join(ways),
                f"{sid} ({row['kind']}) klaster tashqarisidan yetib boriladigan qilib e’lon qilingan ({', '.join(ways)}). "
                "LoadBalancer manba cheklovi, bulut firewall va ingress autentifikatsiyasi manifestdan ko‘rinmaydi — "
                "tasdiqlanishi kerak.", exposed)
        debug = {}
        for container in containers:
            for item in container.get('env') or []:
                if isinstance(item, dict) and isinstance(item.get('name'), str) and item.get('value') is not None:
                    name = item['name'].lower()
                    if name in DEBUG_ENV_TRUE and str(item['value']).strip().lower() in DEBUG_ENV_TRUE[name]:
                        debug[item['name']] = str(item['value'])
        if debug:
            eid = fact(file, line, 'Debug muhit o‘zgaruvchisi', debug)
            finding('RP-006', sid, ','.join(sorted(debug)),
                    f"{sid} workload’ida debug/dev muhiti yoqilgan ({', '.join(f'{k}={v}' for k, v in debug.items())}) "
                    "va u klaster tashqarisidan yetib boriladi. Debug rejimi batafsil xato sahifalari yoki qo‘shimcha "
                    "ichki yo‘llarni ochadi — endi ular tashqi tarmoqdan ham yetkaziladi.", [eid] + exposed)
        sockets = sorted({str((volume.get('hostPath') or {}).get('path'))
                          for volume in spec.get('volumes') or []
                          if isinstance(volume, dict) and isinstance(volume.get('hostPath'), dict)
                          and str((volume['hostPath'].get('path') or '')).endswith(RUNTIME_SOCKETS)})
        if sockets:
            eid = fact(file, line, 'Konteyner runtime soketi (hostPath)', {'hostPath': sockets})
            finding('RP-007', sid, 'runtime-socket',
                    f"{sid} workload’iga node’dagi konteyner runtime soketi ulangan ({sockets[0]}) va u klaster "
                    "tashqarisidan yetib boriladi. Bu workload buzilsa, node’dagi barcha konteynerlar ustidan "
                    "nazorat — amalda node root huquqi — qo‘lga kiritiladi.", [eid] + exposed, 'error')
        privileged, caps = False, set()
        for container in containers:
            context = container.get('securityContext') if isinstance(container.get('securityContext'), dict) else {}
            privileged = privileged or context.get('privileged') is True
            added = (context.get('capabilities') or {}).get('add') if isinstance(context.get('capabilities'), dict) else None
            caps |= {str(c).upper() for c in added or [] if str(c).upper() in DANGEROUS_CAPS}
        host = sorted(key for key in ('hostPID', 'hostIPC', 'hostNetwork') if spec.get(key) is True)
        if privileged or caps or host:
            eid = fact(file, line, 'Workload imtiyozlari', {'privileged': privileged, 'capabilities': sorted(caps),
                                                             'host_namespaces': host})
            bits = [b for b in ('privileged: true' if privileged else '',
                                'capabilities: ' + ', '.join(sorted(caps)) if caps else '', ', '.join(host)) if b]
            finding('RP-008', sid, 'privileged' if privileged else ','.join(sorted(caps) + host),
                    f"{sid} workload’i kengaytirilgan imtiyozlar bilan ishlaydi ({'; '.join(bits)}) va klaster "
                    "tashqarisidan yetib boriladi. Bu workload buzilsa, konteyner izolyatsiyasidan chiqib node’ga "
                    "ta’sir qilish imkoniyati tashqi tarmoqdan ochiladi.", [eid] + exposed, 'error')

    # RP-005: a data store beside a reachable workload with nothing restricting who may connect.
    for row in inventory:
        if row['ports'] or not any(DATASTORE_IMAGE.search(image) for image in row['images']):
            continue
        reaching = [other for other in inventory if other['ports'] and other['namespace'] == row['namespace']]
        if not reaching:
            continue
        guarded = [policy for policy in policies if policy['namespace'] == row['namespace'] and _restricts(policy, row['labels'])]
        if guarded:
            continue
        names = ', '.join(other['id'] for other in reaching)
        finding('RP-005', row['id'], 'datastore',
                f"{row['id']} (image: {row['image']}) tashqaridan yetib boriladigan {len(reaching)} ta workload ({names}) "
                f"bilan bitta namespace’da ({row['namespace']}) va unga kirishni cheklaydigan NetworkPolicy yo‘q. "
                "Kubernetes’da standart holatda har pod har podga ulana oladi: shu workload’lardan biri buzilsa, "
                "ma’lumotlar bazasi portiga to‘g‘ridan-to‘g‘ri yetiladi. Faqat kerakli pod’larga ruxsat beradigan "
                "ingress NetworkPolicy qo‘shing.",
                [other['evidence_id'] for other in reaching] + [row['evidence_id']])

    for row in inventory:
        for key in ('_spec', '_containers', '_where'):
            row.pop(key, None)
    now = datetime.datetime.now(datetime.timezone.utc)
    report = {'schema_version': 2, 'kind': 'repository', 'platform': 'kubernetes',
              'id': now.strftime('%Y%m%dT%H%M%S') + '-' + uuid.uuid4().hex[:8], 'created_at': now.isoformat(),
              'engine_version': VERSION, 'duration_ms': round((time.perf_counter() - started) * 1000, 2),
              'repository': provenance or {'repository': root.name, 'commit': None},
              'profile': {'compose': path, 'env_file': None, 'bindings': [], 'platform': 'kubernetes'},
              'input_sha256': digest(canonical({'files': files, 'bindings': [], 'compose': path, 'env_file': None})),
              'files': files, 'services': inventory, 'edges': [], 'evidence': evidence, 'findings': findings,
              'unknowns': list(dict.fromkeys(unknowns)), 'coverage_gaps': unknowns.coverage(),
              'summary': {'services': len(inventory), 'published_ports': sum(len(s['ports']) for s in inventory),
                          'loopback_ports': 0, 'proxy_routes': 0, 'findings': len(findings), 'runtime_confirmed': 0,
                          'manifests': len(files), 'network_policies': len(policies), 'ingresses': len(ingresses)},
              'verification_summary': verification_mod.summarize(findings), 'limits': LIMITS,
              # The ready-made diffs are written for Compose and nginx files; a
              # manifest gets advice in each finding's `remediation` instead.
              'fix_plan': {'files': [], 'advice': [],
                           'summary': {'files_with_diff': 0, 'rules_fixed': 0, 'advice_only': 0},
                           'note': 'Kubernetes manifestlari uchun tayyor diff yaratilmaydi; har topilmadagi tavsiyaga qarang.'}}
    return report


def _restricts(policy, labels):
    """A NetworkPolicy that governs who may connect to pods with these labels."""
    spec = policy['document'].get('spec') if isinstance(policy['document'].get('spec'), dict) else {}
    types = spec.get('policyTypes') or ['Ingress']
    if 'Ingress' not in types:
        return False
    selector = spec.get('podSelector') if isinstance(spec.get('podSelector'), dict) else {}
    wanted = selector.get('matchLabels')
    if selector.get('matchExpressions'):
        return False                      # not evaluated here, so not counted as protection
    if not (not wanted or selects(wanted, labels)):   # an empty selector covers every pod of the namespace
        return False                      # this policy does not govern the pod we care about
    # The policy governs the pod. It only *restricts* who may connect if it
    # actually limits ingress sources: a missing/empty `ingress` is default-deny
    # (restrictive), but a rule with no `from` (e.g. `ingress: [{}]`) allows every
    # source and must NOT be counted as protection. Audit 2026-10-26 D4.
    ingress = spec.get('ingress')
    if not ingress:                       # None or [] -> default-deny ingress
        return True
    if not isinstance(ingress, list):
        return False
    return all(isinstance(rule, dict) and rule.get('from') for rule in ingress)


REMEDIES = {
    'RP-001': 'Service turini va Ingress’ni tekshiring: tashqi kirish kerak bo‘lmasa ClusterIP qiling; kerak bo‘lsa '
              'loadBalancerSourceRanges, ingress autentifikatsiyasi va TLS ni tasdiqlang.',
    'RP-005': 'Ma’lumotlar bazasi pod’lari uchun faqat kerakli pod’lardan kirishga ruxsat beradigan ingress '
              'NetworkPolicy yozing (va klasterda uni bajaradigan CNI borligini tekshiring).',
    'RP-006': 'Tashqaridan yetib boriladigan workload’da debug/dev muhit o‘zgaruvchisini o‘chiring.',
    'RP-007': 'Runtime soketini hostPath orqali ulamang; zarur bo‘lsa uni tashqaridan yetib bo‘lmaydigan alohida '
              'workload’ga ko‘chiring.',
    'RP-008': '`privileged`, xavfli capability va host namespace’larni olib tashlang; `allowPrivilegeEscalation: false`, '
              '`runAsNonRoot: true` va kerakli minimal capability bilan cheklang.',
}
