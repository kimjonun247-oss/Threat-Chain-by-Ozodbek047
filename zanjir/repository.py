"""Read-only, bounded Compose/Nginx source analyzer. Never executes repository code."""
from __future__ import annotations
import datetime
import ipaddress
import json
import posixpath
import re
from pathlib import Path
import time
import uuid
from urllib.parse import urlsplit
from vendor import yaml
from .engine import Notes, canonical, digest, note_gap
from . import findings as findings_mod, taxonomy
from . import verification as verification_mod

VERSION = '0.7.0'
RULES = {
    'RP-001': ('Host interfeysiga chiqarilgan port', 'Portni kerakli interfeysga bog‘lang va real firewall ruxsatini tekshiring.'),
    'RP-002': ('HTTPS upstream sertifikati tekshirilmaydi', 'Ishonchli CA, server nomi va SNI sozlamalarini moslab, proxy_ssl_verify on bilan test muhitida tekshiring.'),
    'RP-003': ('Proxy ortidagi xizmatga parallel host yo‘li', 'Bevosita port zarurligini va undagi autentifikatsiyani tekshiring. Kerak bo‘lmasa portni yopib, proxy orqali foydalanishni qayta sinang.'),
    'RP-004': ('Gateway ishonch sarlavhasi to‘g‘ridan-to‘g‘ri yo‘l orqali soxtalashtirilishi mumkin',
               'Backend shu sarlavhaga (masalan X-User/X-Role) faqat gateway orqali ishonishi kerak. Bevosita portni yoping YOKI backend’ning o‘zida ushbu sarlavhani faqat ichki tarmoqdan qabul qilishni (masalan mTLS yoki ichki tarmoq ACL bilan) tasdiqlang.'),
    'RP-005': ('Segmentatsiyasiz tarmoq: ochiq xizmat ichki ma’lumotlar bazasiga bevosita yeta oladi',
               'Ma’lumotlar bazasi/navbat kabi ichki xizmatlarni alohida ichki Docker tarmog‘iga (masalan internal: true) ajrating, uni tashqi portga ochiq xizmatlar bilan bitta tarmoqda qoldirmang.'),
    'RP-006': ('Debug/dev rejimi yoqilgan xizmat host portidan bevosita ochiq',
               'Production yoki tashqi portga ochiq konteynerlarda debug/dev muhit o‘zgaruvchisini o‘chiring yoki alohida, faqat ichki tarmoqdan foydalaniladigan sozlamaga ko‘chiring.'),
    'RP-007': ('Docker socket konteyner ichiga ulangan va xizmat host portidan ochiq',
               'Docker socketni konteynerga ulamang; zarur bo‘lsa faqat ichki (tashqi portsiz) xizmatga cheklang yoki faqat o‘qishga ruxsat beruvchi Docker socket proxy ishlating.'),
    'RP-008': ('Kengaytirilgan imtiyozli konteyner (privileged/xavfli capability) host portidan ochiq',
               '"privileged: true" yoki xavfli cap_add’ni olib tashlang; zarur bo‘lsa faqat kerakli minimal capability qoldiring va xizmatni tashqi portga chiqarmang.'),
    # RP-009..011: nginx faylining o‘zidagi kamchiliklar — Compose konteksti kerak emas.
    'RP-009': ('location + alias juftligi yo‘l chegarasidan chiqishga imkon beradi',
               'location yo‘lini "/" bilan tugating (masalan `location /files/`) yoki alias o‘rniga root ishlating. '
               'Hozirgi holatda /files../ ko‘rinishidagi so‘rov alias papkasidan yuqoriga chiqishi mumkin.'),
    'RP-010': ('proxy_pass manzili so‘rovchi boshqaradigan o‘zgaruvchidan quriladi (SSRF)',
               'Upstream manzilini so‘rov sarlavhasi yoki parametridan olmang. Ruxsat berilgan upstream’lar '
               'ro‘yxatini (map yoki upstream bloki) ishlating; dinamik kerak bo‘lsa, qiymatni oq ro‘yxat bilan cheklang.'),
    'RP-011': ('Ichki blokdagi add_header yuqoridagi xavfsizlik sarlavhalarini bekor qiladi',
               'nginx add_header direktivalarini darajalar bo‘ylab birlashtirmaydi: ichki blokda bittasi e’lon '
               'qilinsa, yuqoridagilarning barchasi shu blok uchun ishlamaydi. Yo‘qolgan sarlavhalarni shu blokda '
               'qayta yozing yoki `always` bilan bitta joyda boshqaring.'),
}
# Header names a gateway sets to assert caller identity for a trusting backend.
# If the same backend is *also* reachable directly (RP-003), any caller can
# forge one of these and impersonate an authenticated user — a chain failure
# where the proxy config and the port mapping are each individually plausible.
TRUST_HEADER = re.compile(r'(?i)^(x-user|x-role|x-auth[a-z-]*|x-forwarded-user|x-identity|x-account|x-admin|authorization)$')
# Image names that strongly imply a data-bearing internal service (database,
# broker, cache). Used only to decide which "no host port" services are worth
# flagging for RP-005 — a plain internal microservice with an unrecognized
# image is left alone rather than guessed at.
DATASTORE_NAMES = frozenset({'postgres', 'postgresql', 'postgis', 'timescaledb', 'mysql', 'mariadb', 'percona',
                             'mongo', 'mongodb', 'redis', 'valkey', 'keydb', 'elasticsearch', 'opensearch',
                             'rabbitmq', 'memcached', 'cassandra', 'scylla', 'couchdb', 'neo4j', 'influxdb',
                             'clickhouse', 'cockroach', 'cockroachdb', 'kafka', 'zookeeper', 'etcd', 'consul',
                             'vault', 'sqlserver', 'mssql', 'dynamodb', 'minio', 'chroma', 'chromadb'})
# Tools that sit beside a data store and carry its name without being one: a
# metrics exporter, an admin UI, a backup job. A substring match on the image
# name flagged every one of them (postgres-exporter, mongo-express, kafka-ui).
DATASTORE_COMPANIONS = frozenset({'exporter', 'ui', 'express', 'admin', 'adminer', 'insight', 'redisinsight',
                                  'commander', 'client', 'cli', 'backup', 'operator', 'proxy', 'manager',
                                  'dashboard', 'browser', 'gui', 'web', 'migrate', 'migrations', 'tools',
                                  'connect', 'rest', 'schema', 'registry', 'pgadmin', 'pgadmin4', 'phpmyadmin',
                                  'kibana', 'agent', 'sidecar', 'init', 'test', 'tests'})


class _DatastoreImage:
    """`.search(image)` -> truthy when the image is itself a data store.

    The repository path (registry host, tag and digest removed) is split into
    name tokens and one of them has to *be* a data store name: `chromatic/web`
    and `mycorp/netcdf-tools` contain "chroma" and "etcd" as substrings and are
    neither. An image naming a companion tool is left alone -- guessing there
    would report a metrics exporter as an unsegmented database.
    """

    @staticmethod
    def tokens(image):
        name = str(image or '').lower().split('@', 1)[0]
        parts = name.split('/')
        if len(parts) > 1 and ('.' in parts[0] or ':' in parts[0] or parts[0] == 'localhost'):
            parts = parts[1:]                       # registry host[:port]
        parts[-1] = parts[-1].split(':', 1)[0]      # tag
        return [token for part in parts for token in re.split(r'[^a-z0-9]+', part) if token]

    def search(self, image):
        tokens = set(self.tokens(image))
        return bool(tokens & DATASTORE_NAMES) and not tokens & DATASTORE_COMPANIONS


DATASTORE_IMAGE = _DatastoreImage()
# Framework env vars that switch on verbose errors, interactive debuggers or
# dev-only routes. Each maps its variable name (lowercased) to the set of
# values (lowercased) that mean "debug/dev is on" for that framework.
DEBUG_ENV_TRUE = {
    'debug':{'1','true','yes','on'}, 'flask_debug':{'1','true','yes','on'},
    'django_debug':{'1','true','yes','on'}, 'app_debug':{'1','true','yes','on'},
    'node_env':{'development','dev'}, 'rails_env':{'development','dev'},
    'aspnetcore_environment':{'development'}, 'spring_profiles_active':{'dev','development'},
}
# Bind-mounting the Docker socket into a container hands it full control of the
# host's Docker API -- normally daemon-equivalent (root) access.
DOCKER_SOCKET = re.compile(r'(?i)/var/run/docker\.sock|//\./pipe/docker_engine')
# Kernel-level capabilities that let a container break out of normal isolation.
# Not every cap_add is dangerous (e.g. NET_BIND_SERVICE is routine); only these.
DANGEROUS_CAPS = {'ALL','SYS_ADMIN','SYS_PTRACE','SYS_MODULE','SYS_RAWIO','NET_ADMIN','DAC_READ_SEARCH'}


# Written for a demo stack; a platform's Compose file has hundreds of services
# and is several megabytes with its anchors expanded. Every limit is still a
# limit -- the parser never reads an unbounded document.
MAX_CONFIG_BYTES = 8_000_000
MAX_YAML_EVENTS = 600_000
MAX_YAML_NODES = 300_000
MAX_SERVICES = 2000
MAX_INCLUDES = 50


def safe_read(root, relative):
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        raise ValueError('Repository ichidagi nisbiy fayl yo‘li kerak.')
    file = (root / relative).resolve()
    if not file.is_relative_to(root.resolve()) or not file.is_file():
        raise ValueError('Fayl repository chegarasidan tashqarida yoki mavjud emas.')
    if file.stat().st_size > MAX_CONFIG_BYTES:
        raise ValueError(f'Fayl {MAX_CONFIG_BYTES // 1_000_000} MB chegarasidan katta.')
    return file.read_bytes().decode('utf-8-sig')


MERGE_TAG = 'tag:yaml.org,2002:merge'


class StrictLoader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        # A key written twice in one mapping is still an error. Keys that arrive
        # through a merge (`<<: *defaults`) are not duplicates: the mapping's own
        # keys override them, which is what Compose does.
        own = set()
        for key_node, _ in node.value:
            if key_node.tag == MERGE_TAG:
                continue
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, (str, int, float, bool)) or key in own:
                raise ValueError('YAML kaliti takrorlangan yoki qo‘llanmaydi.')
            own.add(key)
        self.flatten_mapping(node)
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, (str, int, float, bool)):
                raise ValueError('YAML kaliti qo‘llanmaydi.')
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def parse_yaml(text):
    """Parse a Compose document, with every parser failure arriving as a ValueError.

    yaml.YAMLError is not a ValueError, so an unguarded parse escapes the
    `except ValueError` handlers in app.py and kills the request with no
    response at all. That happened once in custom_rules.py (A22) and the same
    shape was still here: pointing a registration at any non-YAML file -- an
    /etc/hosts, a README -- closed the connection instead of saying which line
    was wrong. Both the event scan below and the node construction further down
    can raise, so the whole body is guarded.
    """
    try:
        return _parse_yaml(text)
    except yaml.YAMLError as error:
        mark = getattr(error, 'problem_mark', None)
        where = f' ({mark.line + 1}-qator)' if mark is not None else ''
        raise ValueError('YAML o‘qilmadi' + where + ': ' + str(getattr(error, 'problem', error))[:200]) from None


def _parse_yaml(text):
    if len(text) > MAX_CONFIG_BYTES:
        raise ValueError('YAML hajmi chegaradan oshdi.')
    depth=0
    events=0
    for event in yaml.parse(text):
        events+=1
        if isinstance(event,(yaml.MappingStartEvent,yaml.SequenceStartEvent)):
            depth+=1
        if isinstance(event,(yaml.MappingEndEvent,yaml.SequenceEndEvent)):
            depth-=1
        if depth>50 or events>MAX_YAML_EVENTS:
            raise ValueError('YAML murakkabligi chegaradan oshdi.')
        # Anchors and merge keys are how large Compose files share settings
        # (`x-defaults: &defaults` ... `<<: *defaults`), so they are read. An
        # alias cannot be used as a bomb here: every expanded node is counted
        # below and construction shares one object per anchor.
    loader = StrictLoader(text)
    try:
        node = loader.get_single_node()
        if node is None:
            raise ValueError('Bo‘sh YAML.')
        locations = {}
        count = 0
        def visit(current, path=(), depth=0):
            nonlocal count
            count += 1
            if depth > 50 or count > MAX_YAML_NODES:
                raise ValueError('YAML murakkabligi chegaradan oshdi.')
            locations[path] = current.start_mark.line + 1
            if isinstance(current, yaml.MappingNode):
                for key, value in current.value:
                    visit(value, path+(str(key.value),), depth+1)
            elif isinstance(current, yaml.SequenceNode):
                for index, value in enumerate(current.value):
                    visit(value, path+(str(index),), depth+1)
        visit(node)
        return loader.construct_document(node), locations
    finally:
        loader.dispose()


VARIABLE = re.compile(r'\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(:-|-|:\?|\?)([^{}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)')


def interpolate(text, values, unknowns, context):
    if not isinstance(text, str):
        return text
    text = text.replace('$$', '\x00')
    def substitute(match):
        key = match[1] or match[4]
        operator, fallback = match[2], match[3]
        value = values.get(key)
        if value is not None and (str(value) != '' or operator == '-'):
            return str(value)
        if operator in {':-', '-'}:
            return fallback
        unknowns.append(f'{context}: {key} qiymati noma’lum.')
        return 'UNRESOLVED_' + key
    return VARIABLE.sub(substitute, text).replace('\x00', '$')


def dotenv(text):
    values = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('export '):
            line = line[7:]
        if '=' not in line:
            raise ValueError('.env satri qo‘llanmaydi.')
        key, value = line.split('=',1)
        key, value = key.strip(), value.strip()
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*',key) or key in values:
            raise ValueError('.env kaliti takrorlangan yoki noto‘g‘ri.')
        if value.startswith(('"', "'")):
            quote = value[0]
            end = value.find(quote,1)
            if end < 0 or value[end+1:].strip().lstrip('#').strip() and not value[end+1:].strip().startswith('#'):
                raise ValueError('.env quote formati qo‘llanmaydi.')
            value = value[1:end]
        else:
            value = value.split(' #',1)[0].rstrip()
        if '$' in value or '\\' in value:
            raise ValueError('.env interpolatsiya/escape hozir qo‘llanmaydi; literal qiymat bering.')
        values[key] = value
    return values


def port_mapping(value):
    protocol = 'tcp'
    if isinstance(value, dict):
        target, published = value.get('target'), value.get('published')
        if published is None:
            published = 'dynamic'
        host = value.get('host_ip')
        protocol = value.get('protocol','tcp')
    elif isinstance(value, (str,int)) and not isinstance(value,bool):
        raw = str(value)
        if '/' in raw:
            raw, protocol = raw.rsplit('/',1)
        match = re.fullmatch(r'(?:\[([^]]+)\]:|([^:]+):)?([^:]+):([^:]+)',raw)
        if match:
            host, published, target = match[1] or match[2], match[3], match[4]
        elif re.fullmatch(r'\d+(-\d+)?',raw):
            host,published,target = None,'dynamic',raw
        else:
            raise ValueError('Port formati yoki diapazoni qo‘llanmaydi.')
    else:
        raise ValueError('Port formati noto‘g‘ri.')
    # `8000-8010:8000-8010` publishes eleven ports. It was refused as a format
    # error, so a service exposing a whole range produced no finding at all.
    target, target_end = port_span(target, 'Target port noto‘g‘ri.')
    if published != 'dynamic':
        first, last = port_span(published, 'Host port diapazoni qo‘llanmaydi.')
        published = str(first) if first == last else f'{first}-{last}'
    if protocol not in {'tcp','udp'}:
        raise ValueError('Protokol qo‘llanmaydi.')
    if host is None:
        scope = 'default_interfaces'
    else:
        address = ipaddress.ip_address(str(host))
        scope = 'loopback' if address.is_loopback else 'all_interfaces' if address.is_unspecified else 'specific_interface'
    return {'host_ip':host,'published':str(published),'target':int(target),'protocol':protocol,'scope':scope,
            **({'target_end':target_end} if target_end != target else {})}


def port_span(value, message):
    """(first, last) of `8080` or `8000-8010`; raises ValueError(message) otherwise."""
    match = re.fullmatch(r'(\d+)(?:-(\d+))?', str(value))
    if not match:
        raise ValueError(message)
    first, last = int(match[1]), int(match[2] or match[1])
    if not 1 <= first <= last <= 65535:
        raise ValueError(message)
    return first, last


TOKEN = re.compile(r'#[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{};]|[^\s{};]+')


def nginx_tree(text, values):
    """Parse an nginx file into a directive tree.

    Split out of nginx_routes() so the config checks (RP-009..011) can walk the
    same tree instead of re-parsing, and so a parser change cannot make the two
    disagree about what the file says.
    """
    # Only template ${NAME} values are replaced; nginx runtime $variables are not evaluated.
    expanded = re.sub(r'\$\{([A-Za-z_][A-Za-z0-9_]*)\}',lambda m:str(values.get(m[1], 'UNRESOLVED_'+m[1])),text)
    tokens = [(m.group(), expanded.count('\n',0,m.start())+1) for m in TOKEN.finditer(expanded) if not m.group().startswith('#')]
    root = {'name':'root','args':[],'line':1,'children':[]}
    stack, pending = [root], []
    for token,line in tokens:
        if token in {'{',';'}:
            if not pending:
                raise ValueError('Nginx blok formati qo‘llanmaydi.')
            entry = {'name':pending[0][0], 'args':[t[0].strip('"\'') for t in pending[1:]], 'line':pending[0][1], 'children':[]}
            stack[-1]['children'].append(entry)
            if token == '{':
                stack.append(entry)
                if len(stack)>50:
                    raise ValueError('Nginx nesting chegaradan oshdi.')
            pending=[]
        elif token == '}':
            # Lua statements are deliberately ignored; they are not interpreted as routing/auth rules.
            pending=[]
            if len(stack)==1:
                raise ValueError('Nginx yopish bloki noto‘g‘ri.')
            stack.pop()
        else:
            pending.append((token,line))
    if len(stack)!=1:
        raise ValueError('Nginx bloki yopilmagan.')
    return root


# Headers whose loss changes the browser's security posture. Used by RP-011.
SECURITY_HEADERS = {'strict-transport-security', 'content-security-policy', 'x-frame-options',
                    'x-content-type-options', 'referrer-policy', 'permissions-policy',
                    'cross-origin-opener-policy', 'cross-origin-resource-policy',
                    'content-security-policy-report-only', 'x-permitted-cross-domain-policies'}
# Variables whose value the client controls. A proxy_pass built from one of
# these lets the caller choose the upstream, which is the SSRF condition.
CLIENT_VARIABLE = re.compile(r'\$(http_[a-z0-9_]+|arg_[a-z0-9_]+|uri|document_uri|request_uri|host|args|query_string)\b',
                             re.IGNORECASE)
NGINX_CHECK_RULES = ('RP-009', 'RP-010', 'RP-011')


def upstream_authority(value):
    """The host[:port] part of a proxy_pass value.

    `proxy_pass http://backend:8080$request_uri;` forwards the caller's path to
    a fixed host, which is how most reverse proxies are written and is not SSRF.
    Only a client-controlled variable in the authority lets the caller pick the
    upstream, so that is the only part RP-010 looks at.
    """
    rest = value.split('://', 1)[1] if '://' in value else value
    # $uri, $request_uri and $document_uri always begin with "/", so they start
    # the path when written straight after a host (`http://api$uri`). With no
    # host before it (`http://$request_uri/x`) the variable *is* the authority.
    return re.split(r'[/?]|(?<=.)\$(?:request_uri|document_uri|uri)\b', rest, maxsplit=1)[0]


def identity_header(directive):
    """True when a proxy_set_header makes the gateway vouch for the caller.

    Relaying what the client sent (`Authorization $http_authorization`) or
    clearing the header (`X-User ""`) asserts nothing: the backend receives
    exactly what it would have received on its own port, so a direct path adds
    no forgery. Only a value the gateway computes (`$remote_user`, an
    auth_request variable, a literal) is an identity the backend has to trust.
    """
    args = directive['args']
    if not args or not TRUST_HEADER.fullmatch(args[0]):
        return False
    value = args[1] if len(args) > 1 else ''
    relayed = '$http_' + args[0].lower().replace('-', '_')
    return bool(value) and value.lower() != relayed


def nginx_checks(root):
    """Config weaknesses that need no Compose context: RP-009, RP-010, RP-011.

    Deliberately narrow. Gixy checks nginx far more deeply and this is not an
    attempt to match it; these three were chosen because each one silently
    undoes a protection the operator believes is in place, which is the same
    shape as the RP chain rules.
    """
    issues = []

    def blocks(node):
        for child in node['children']:
            if child['children']:
                yield child
                yield from blocks(child)

    def directives(node, name):
        return [c for c in node['children'] if c['name'] == name]

    for block in blocks(root):
        # -- RP-009: alias traversal ------------------------------------------
        # `location /files { alias /var/data/; }` -- a prefix location that does
        # not end in '/' combined with an alias lets a request for
        # /files../etc/passwd resolve above the alias root. With the trailing
        # slash on the location, nginx normalises the path and the trick fails.
        if block['name'] == 'location' and block['args']:
            modifier = block['args'][0] if block['args'][0] in ('=', '~', '~*', '^~') else ''
            path = block['args'][-1]
            for alias in directives(block, 'alias'):
                if not modifier and not path.endswith('/') and alias['args'] and alias['args'][0].endswith('/'):
                    issues.append({'rule': 'RP-009', 'line': alias['line'], 'location': path,
                                   'value': alias['args'][0], 'directive': 'alias'})

        # -- RP-010: client-controlled proxy_pass (SSRF) ----------------------
        for proxy in directives(block, 'proxy_pass'):
            if not proxy['args']:
                continue
            match = CLIENT_VARIABLE.search(upstream_authority(proxy['args'][0]))
            if match:
                issues.append({'rule': 'RP-010', 'line': proxy['line'],
                               'location': ' '.join(block['args']) if block['name'] == 'location' else block['name'],
                               'value': proxy['args'][0], 'variable': match.group(0), 'directive': 'proxy_pass'})

    # -- RP-011: add_header inheritance -------------------------------------
    # nginx does not merge add_header across levels: as soon as a nested block
    # declares one, every add_header from its parents stops applying to that
    # block. A server-wide HSTS or CSP therefore disappears inside any location
    # that adds a header of its own -- and nothing warns about it.
    def header_names(node):
        return {h['args'][0].lower().rstrip(':') for h in directives(node, 'add_header') if h['args']}

    def inherited(node, outer):
        own = header_names(node)
        lost = sorted((outer & SECURITY_HEADERS) - own)
        if own and lost:
            line = next((h['line'] for h in directives(node, 'add_header')), node['line'])
            issues.append({'rule': 'RP-011', 'line': line,
                           'location': ' '.join(node['args']) if node['args'] else node['name'],
                           'value': ', '.join(lost), 'directive': 'add_header'})
        carried = own or outer
        for child in node['children']:
            if child['children']:
                inherited(child, carried)

    for child in root['children']:
        if child['children']:
            inherited(child, header_names(child) or set())
    return issues


def nginx_routes(text, values):
    root=nginx_tree(text,values)
    result=[]
    includes=[]
    def walk(node,location=None,verify=None,listen=None):
        directives=node['children']
        local_verify=next((c for c in directives if c['name']=='proxy_ssl_verify'),verify)
        local_listen=next((c['args'][0] for c in directives if c['name']=='listen' and c['args']),listen)
        if node['name']=='location':
            location=' '.join(node['args'])
        for child in directives:
            if child['name']=='include':
                includes.append(child['line'])
            if child['name']=='proxy_pass' and child['args']:
                url=child['args'][0]
                try:
                    parsed=urlsplit(url)
                    target=parsed.hostname
                    port=parsed.port or (443 if parsed.scheme=='https' else 80)
                except ValueError:
                    target,port=None,None
                trust_headers=sorted({d['args'][0] for d in directives if d['name']=='proxy_set_header' and identity_header(d)})
                result.append({'location':location,'url':url,'target':target,'target_port':port,'scheme':url.split(':',1)[0],
                               'line':child['line'],'listen':local_listen,'verify':local_verify['args'][0] if local_verify and local_verify['args'] else None,
                               'verify_line':local_verify['line'] if local_verify else None,'trust_headers':trust_headers})
            if child['children'] and child['name'] not in {'rewrite_by_lua_block','access_by_lua_block','content_by_lua_block'}:
                walk(child,location,local_verify,local_listen)
    walk(root)
    return result,includes


# Keys Compose appends when a service extends another; every other sequence is
# replaced by the extending service's own value.
APPENDED_KEYS = frozenset({'ports', 'expose', 'volumes', 'cap_add', 'cap_drop', 'devices', 'dns', 'env_file',
                           'security_opt', 'tmpfs', 'external_links'})
MAX_EXTENDS_DEPTH = 8


def _as_mapping(value):
    """`environment` and `labels` may be a list of KEY=VALUE; merge them as mappings."""
    if isinstance(value, list):
        return dict(item.split('=', 1) if isinstance(item, str) and '=' in item else (str(item), None) for item in value)
    return value


OVERRIDE_NAMES = {'docker-compose.yml': 'docker-compose.override.yml', 'docker-compose.yaml': 'docker-compose.override.yaml',
                  'compose.yml': 'compose.override.yml', 'compose.yaml': 'compose.override.yaml'}


def override_path(compose):
    """The override file Compose reads by itself beside a default-named file.

    `docker compose up` merges `docker-compose.override.yml` over
    `docker-compose.yml` without being asked, and that file is where a team
    usually publishes ports and turns debugging on. Reading only the main file
    described a stack nobody runs. A file given under any other name has no
    implicit override, so none is looked for.
    """
    name = posixpath.basename(str(compose).replace('\\', '/'))
    other = OVERRIDE_NAMES.get(name)
    return rebase(compose, other) if other else None


def merge_service(base, own, keep_all=False):
    """A service as Compose builds it from `extends` (or, with `keep_all`, from
    an override file): mappings are merged, the listed sequences are appended,
    everything else is the later definition's."""
    merged = dict(base)
    for key, value in own.items():
        if key == 'extends':
            continue
        inherited = merged.get(key)
        if key in ('environment', 'labels') and inherited is not None:
            inherited, value = _as_mapping(inherited), _as_mapping(value)
        if isinstance(inherited, dict) and isinstance(value, dict):
            merged[key] = {**inherited, **value}
        elif isinstance(inherited, list) and isinstance(value, list) and key in APPENDED_KEYS:
            merged[key] = inherited + [item for item in value if item not in inherited]
        else:
            merged[key] = value
    # Compose does not carry these two across an `extends`; an override file
    # keeps everything the main file said.
    for key in () if keep_all else ('depends_on', 'volumes_from'):
        if key in base and key not in own:
            merged.pop(key, None)
    return merged


def resolve_extends(services, origins, read, unknowns):
    """Replace every `extends:` with the service it produces, in place.

    A service that extends a base inherits the base's ports, capabilities and
    volumes, and those are exactly what the rules below look at: left
    unresolved, an exposed privileged service looked like a harmless one with an
    "extends is present" note beside it. What cannot be resolved -- a missing
    file or service, a cycle -- stays as it was and is named in `unknowns`.
    """
    files = {}

    def load(path):
        if path not in files:
            parsed, _ = parse_yaml(read(path))
            files[path] = parsed.get('services') if isinstance(parsed, dict) and isinstance(parsed.get('services'), dict) else {}
        return files[path]

    def build(sid, service, origin, trail):
        target = service.get('extends')
        if target is None:
            return service
        if len(trail) >= MAX_EXTENDS_DEPTH:
            raise ValueError('extends zanjiri juda chuqur yoki aylanma')
        name, other = (target, None) if isinstance(target, str) else \
            (target.get('service'), target.get('file')) if isinstance(target, dict) else (None, None)
        if not isinstance(name, str) or (other is not None and not isinstance(other, str)):
            raise ValueError('extends formati noma’lum')
        source = rebase(origin, other) if other else origin
        # A base named without a file lives beside the service that names it:
        # in the external file we are already in, or among the project's own.
        pool = load(source) if other else (files[origin] if origin in files else services)
        base = pool.get(name)
        if not isinstance(base, dict) or (source, name) in trail:
            raise ValueError(f'asos xizmat topilmadi yoki aylanma: {name}')
        return merge_service(build(name, base, source, trail + [(source, name)]), service)

    for sid in list(services):
        service = services[sid]
        if not isinstance(service, dict) or 'extends' not in service:
            continue
        origin = origins[sid][0]
        try:
            services[sid] = build(sid, service, origin, [(origin, sid)])
        except (ValueError, OSError) as error:
            note_gap(unknowns, f'{sid}: extends yechilmadi — {error}; shu xizmat uchun qamrov to‘liq emas.')


def include_paths(value, compose, unknowns):
    """Repository-relative paths named by a top-level `include:`, in order."""
    if value is None:
        return []
    if not isinstance(value, list):
        note_gap(unknowns, 'Compose include ro‘yxat emas; yechilmadi.')
        return []
    paths = []
    for entry in value:
        named = entry.get('path') if isinstance(entry, dict) else entry
        for one in (named if isinstance(named, list) else [named]):
            if not isinstance(one, str) or not one or '$' in one or '://' in one or one.startswith(('/', '\\')):
                note_gap(unknowns, f'Compose include yozuvi yechilmadi ({str(one)[:80]}); qamrov to‘liq emas.')
                continue
            paths.append(rebase(compose, one) or one)
    if len(paths) > MAX_INCLUDES:
        note_gap(unknowns, f'{len(paths)} ta include; faqat birinchi {MAX_INCLUDES} tasi o‘qildi.', not_reached=len(paths) - MAX_INCLUDES)
    return list(dict.fromkeys(paths))[:MAX_INCLUDES]


def rebase(origin, relative):
    """`relative` (as written in the file `origin`) expressed from the repository root.

    Returns '.' for the root itself. A path that climbs out of the repository is
    returned as written: it cannot match anything inside, and safe_read() refuses
    it if it is ever opened.
    """
    base = posixpath.dirname(str(origin).replace('\\', '/'))
    joined = posixpath.normpath(posixpath.join(base, str(relative).replace('\\', '/')))
    if joined.startswith('../') or joined == '..' or joined.startswith('/'):
        return str(relative)
    return joined


def scan_repository(root, compose, env_file=None, bindings=None, provenance=None):
    # A folder of manifests (or one manifest file) in the `compose` field is a
    # Kubernetes deployment: the same questions, answered from another format,
    # and reported in the same shape so every chain rule applies to it.
    from . import kubernetes
    if isinstance(compose,str) and kubernetes.applies(root,compose):
        if env_file or bindings:
            raise ValueError('Kubernetes manifestlari uchun .env va proxy binding qo‘llanmaydi.')
        return kubernetes.scan(root,compose,provenance)
    started=time.perf_counter()
    root=Path(root).resolve()
    evidence,files,unknowns,findings,edges=[],[],Notes(),[],[]
    bindings=bindings or []
    if not isinstance(bindings,list) or len(bindings)>50:
        raise ValueError('Proxy binding ro‘yxati noto‘g‘ri yoki juda katta.')
    def read(relative):
        text=safe_read(root,relative)
        if not any(f['path']==relative for f in files):
            files.append({'path':relative,'sha256':digest(text.encode()),'bytes':len(text.encode())})
        return text
    def fact(path,line,label,value):
        eid=f'R{len(evidence)+1:03}'
        evidence.append({'id':eid,'path':path,'line':line,'label':label,'value':value})
        return eid
    by_fingerprint={}   # a scan through `findings` per new finding was O(F^2) on a large Compose file
    def finding(rule,service,key,detail,eids,severity='warning'):
        fingerprint=digest(canonical([rule,service,key]))[:24]
        existing=by_fingerprint.get(fingerprint)
        if existing:
            existing['evidence_ids']=list(dict.fromkeys(existing['evidence_ids']+eids))
            return
        tags=taxonomy.tag_static('repository',rule)
        findings.append({'rule_id':rule,'fingerprint':fingerprint,'service_id':service,'title':RULES[rule][0],
                         'detail':detail,'evidence_ids':eids,'level':severity,'status':'review_required',
                         'remediation':RULES[rule][1],'runtime_verified':False,'verified':False,
                         'cwe_ids':tags['cwe_ids'],'owasp_top10_2025':tags['owasp_top10_2025'],
                         'verification_note':'Compose/Nginx konfiguratsiyasidan statik o‘qilgan deklaratsiya; runtime, firewall va autentifikatsiya tekshirilmagan. Mutaxassis qo‘lda ko‘rib chiqishi shart.'})
        by_fingerprint[fingerprint]=findings[-1]
    compose_text=read(compose)
    document,locations=parse_yaml(compose_text)
    if not isinstance(document,dict) or not isinstance(document.get('services'),dict):
        raise ValueError('Compose services mapping topilmadi.')
    # Which file each service was read from, and that file's line index.
    origins={sid:(compose,locations) for sid in document['services']}
    for included in include_paths(document.get('include'),compose,unknowns):
        # `include:` is how a large stack is split into files. The named files are
        # read like the main one; a service the main file also defines keeps the
        # main file's definition.
        try:
            other,other_locations=parse_yaml(read(included))
            if not isinstance(other,dict) or not isinstance(other.get('services') or {},dict):
                raise ValueError('services mapping yo‘q')
            if 'include' in other:
                note_gap(unknowns, f'{included}: ichki include yechilmadi; qamrov to‘liq emas.')
            for sid,service in (other.get('services') or {}).items():
                if sid not in document['services']:
                    document['services'][sid]=service
                    origins[sid]=(included,other_locations)
        except (ValueError,OSError) as error:
            note_gap(unknowns, f'include {included}: o‘qilmadi — {error}')
    overrides=[]
    override=override_path(compose)
    if override and (root/override).is_file():
        try:
            other,other_locations=parse_yaml(read(override))
            layered=other.get('services') if isinstance(other,dict) else None
            if not isinstance(layered,dict):
                raise ValueError('services mapping yo‘q')
            for sid,service in layered.items():
                if isinstance(document['services'].get(sid),dict) and isinstance(service,dict):
                    document['services'][sid]=merge_service(document['services'][sid],service,keep_all=True)
                else:
                    document['services'][sid]=service
                    origins[sid]=(override,other_locations)
            overrides.append(override)
        except (ValueError,OSError) as error:
            note_gap(unknowns, f'{override}: override fayli o‘qilmadi — {error}; qamrov to‘liq emas.')
    if len(document['services'])>MAX_SERVICES:
        # A bound, not a failure: the first MAX_SERVICES are analysed and the rest
        # are reported as never reached (it used to fail the repository stage).
        excess=len(document['services'])-MAX_SERVICES
        document['services']=dict(list(document['services'].items())[:MAX_SERVICES])
        note_gap(unknowns, f'{MAX_SERVICES+excess} ta xizmat; faqat birinchi {MAX_SERVICES} tasi tahlil qilindi.',
                 not_reached=excess)
    if 'extends' in document:
        note_gap(unknowns, 'Compose extends qo‘llanmaydi; qamrov to‘liq emas.')
    env=dotenv(read(env_file)) if env_file else {}
    inventory=[]
    service_environments={}
    resolve_extends(document['services'],origins,read,unknowns)
    for sid,service in document['services'].items():
        if not isinstance(sid,str) or not isinstance(service,dict):
            raise ValueError('Xizmat formati noto‘g‘ri.')
        origin,where=origins[sid]
        line=where.get(('services',sid),1)
        service_id=fact(origin,line,'Xizmat',sid)
        nets=service.get('networks',{'default':None})
        if isinstance(nets,(dict,list)):
            nets=list(nets)
        else:
            nets=[]
            unknowns.append(f'{sid}: networks formati noma’lum.')
        if 'network_mode' in service:
            nets=[]
            unknowns.append(f'{sid}: network_mode uchun reachability hisoblanmadi.')
        for key in ['profiles','env_file']:
            if key in service:
                unknowns.append(f'{sid}: {key} mavjud; ishga tushirish shartlari/qamrov to‘liq yechilmagan.')
        ports=[]
        raw_ports=service.get('ports',[])
        if not isinstance(raw_ports,list):
            raw_ports=[]
            unknowns.append(f'{sid}: ports ro‘yxat emas.')
        for index,value in enumerate(raw_ports):
            try:
                normalized={k:interpolate(v,env,unknowns,sid) for k,v in value.items()} if isinstance(value,dict) else interpolate(value,env,unknowns,sid)
                port=port_mapping(normalized)
                eid=fact(origin,where.get(('services',sid,'ports',str(index)),line),'Host port mapping',port)
                port['evidence_id']=eid
                ports.append(port)
                if port['scope']!='loopback':
                    finding('RP-001',sid,f"{port['protocol']}:{port['target']}:{port['published']}",
                            f"Host interfeysi: {port['host_ip'] or 'Compose default'}. Internetdan ochiqlik, daemon sozlamasi va firewall tasdiqlanmagan.",[eid])
            except (ValueError,TypeError) as error:
                unknowns.append(f'{sid}: port tahlili — {error}')
        raw_environment=service.get('environment',{})
        if isinstance(raw_environment,list):
            raw_environment=dict(item.split('=',1) if '=' in item else (item,None) for item in raw_environment if isinstance(item,str))
        if not isinstance(raw_environment,dict):
            raw_environment={}
        values={str(k):interpolate(v,env,unknowns,sid) for k,v in raw_environment.items() if isinstance(v,(str,int,bool))}
        debug_hits={k:v for k,v in values.items() if k.lower() in DEBUG_ENV_TRUE and str(v).strip().lower() in DEBUG_ENV_TRUE[k.lower()]}
        exposed_ports=[p for p in ports if p['scope']!='loopback']
        if debug_hits and exposed_ports:
            env_eid=fact(origin,line,'Debug muhit o‘zgaruvchisi',debug_hits)
            finding('RP-006',sid,','.join(sorted(debug_hits)),
                    f"{sid} xizmatida debug/dev muhiti yoqilgan ({', '.join(f'{k}={v}' for k,v in debug_hits.items())}) va shu xizmat host portidan ham to‘g‘ridan-to‘g‘ri ochiq. Ikkalasi alohida to‘g‘ri: debug rejimi lokal ishlab chiqish uchun odatiy, portni ochish ham alohida qaror. Ammo birgalikda: debug rejimi ko‘pincha batafsil xato sahifalari, interaktiv konsol yoki qo‘shimcha ichki yo‘llarni yoqadi — bular endi tashqi tarmoqdan ham yetkazilishi mumkin.",
                    [env_eid]+[p['evidence_id'] for p in exposed_ports])
        raw_volumes=service.get('volumes',[])
        if not isinstance(raw_volumes,list):
            raw_volumes=[]
        socket_sources=[]
        for vol in raw_volumes:
            if isinstance(vol,str):
                source=vol.split(':',1)[0]
            elif isinstance(vol,dict):
                source=str(vol.get('source',''))
            else:
                continue
            if DOCKER_SOCKET.search(source):
                socket_sources.append(source)
        if socket_sources and exposed_ports:
            vol_eid=fact(origin,line,'Docker socket mount',{'volumes':socket_sources})
            finding('RP-007',sid,'docker.sock',
                    f"{sid} xizmati Docker socketni ({socket_sources[0]}) konteyner ichiga ulagan va shu bilan birga host portidan ham to‘g‘ridan-to‘g‘ri ochiq. Ikkalasi alohida to‘g‘ri: ba’zi vositalarga (masalan CI runner, monitoring) Docker socket kerak, portni ochish ham alohida qaror. Ammo birgalikda: bu xizmat buzilsa, tashqi tarmoqdan Docker API’ga to‘liq — odatda daemon/root darajasidagi — nazorat qo‘lga kiritiladi.",
                    [vol_eid]+[p['evidence_id'] for p in exposed_ports],'error')
        privileged=bool(service.get('privileged'))
        raw_caps=service.get('cap_add',[])
        if not isinstance(raw_caps,list):
            raw_caps=[]
        dangerous_caps=sorted({c.upper() for c in raw_caps if isinstance(c,str) and c.upper() in DANGEROUS_CAPS})
        if (privileged or dangerous_caps) and exposed_ports:
            cap_eid=fact(origin,line,'Konteyner imtiyozlari',{'privileged':privileged,'cap_add':dangerous_caps})
            detail_bits='privileged: true'+(f", cap_add: {', '.join(dangerous_caps)}" if dangerous_caps else '') if privileged else f"cap_add: {', '.join(dangerous_caps)}"
            finding('RP-008',sid,'privileged' if privileged else ','.join(dangerous_caps),
                    f"{sid} xizmati kengaytirilgan yadro imtiyozlari bilan ishlaydi ({detail_bits}) va host portidan ham to‘g‘ridan-to‘g‘ri ochiq. Ikkalasi alohida to‘g‘ri: ba’zi ish yuklamalariga bu imtiyoz kerak, portni ochish ham alohida qaror. Ammo birgalikda: bu xizmat buzilsa, standart konteyner izolyatsiyasidan tashqariga chiqib, xost yadrosiga ta’sir qilish imkoniyati tashqi tarmoqdan ham ochiladi.",
                    [cap_eid]+[p['evidence_id'] for p in exposed_ports],'error')
        service_environments[sid]=values
        raw_build=service.get('build')
        if isinstance(raw_build,str):
            build_context=raw_build
        elif isinstance(raw_build,dict) and isinstance(raw_build.get('context'),str):
            build_context=raw_build['context']
        else:
            build_context=None
        if build_context:
            build_context=build_context.strip()
            if build_context.startswith('./'):
                build_context=build_context[2:]
            build_context=build_context.rstrip('/') or None
        # A build context is relative to the file that declares it. Chains match
        # it against repository paths, so it is rebased onto the repository root
        # (`deploy/compose.yml` + `build: ../api` is `api`).
        if build_context:
            build_context=rebase(origin,build_context)
        inventory.append({'id':sid,'ports':ports,'networks':nets,'image':str(service.get('image','')),
                          'build_context':build_context,
                          'evidence_id':service_id,'auth_status':'unknown','runtime_verified':False})
    by_id={s['id']:s for s in inventory}
    exposed_services=[s for s in inventory if any(p['scope']!='loopback' for p in s['ports'])]
    for target in inventory:
        if target['ports'] or not DATASTORE_IMAGE.search(target['image']):
            continue
        # One finding per data store, naming every exposed service that can reach
        # it. It used to be one finding per (service, store) pair: a single
        # Postgres reachable from six exposed services produced six findings for
        # one fix (put the store on an internal network).
        reaching=[]
        for exposed in exposed_services:
            if exposed['id']==target['id']:
                continue
            shared=sorted(set(exposed['networks']) & set(target['networks']))
            if shared:
                reaching.append((exposed,shared))
        if not reaching:
            continue
        names=', '.join(e['id'] for e,_ in reaching)
        networks=sorted({n for _,shared in reaching for n in shared})
        # The key is the data store alone. It used to list every reaching service,
        # so exposing one more service changed the identity: the old finding
        # "disappeared", a "new" one failed the gate, and its triage was lost.
        finding('RP-005',target['id'],'datastore',
                f"Host portidan ochiq {len(reaching)} ta xizmat ({names}) {target['id']} (image: {target['image']}) bilan bir xil Docker tarmog‘ida ({', '.join(networks)}) ishlaydi. Har biri alohida to‘g‘ri: xizmatni tashqariga ochish va standart Compose tarmog‘idan foydalanish odatiy holat. Ammo birgalikda: shu xizmatlardan biri buzilsa, gateway yoki ilova darajasidagi autentifikatsiyasiz, to‘g‘ridan-to‘g‘ri Docker ichki DNS orqali {target['id']} portiga yetish mumkin. Tuzatish bitta: {target['id']}ni faqat kerakli xizmatlar ulangan ichki (internal) tarmoqqa o‘tkazing.",
                [e['evidence_id'] for e,_ in reaching]+[target['evidence_id']],'warning')
    for binding in bindings:
        if not isinstance(binding,dict) or binding.get('service_id') not in by_id:
            unknowns.append('Proxy faylini xizmatga bog‘lash noto‘g‘ri.')
            continue
        sid=binding['service_id']
        condition=binding.get('when')
        if condition and env.get(condition.get('key')) not in condition.get('values',[]):
            continue
        path=binding.get('path')
        values={**service_environments[sid],**binding.get('template_variables',{})}
        try:
            text=read(path)
            routes,includes=nginx_routes(text,values)
            if includes:
                unknowns.append(f'{path}: include fayllari yechilmagan; to‘liq nginx xatti-harakati noma’lum.')
            bind_eid=fact('profile.json',1,'Qo‘lda berilgan source → service mapping',{'service_id':sid,'path':path})
            # Config-only weaknesses first: these need no Compose context, so
            # they are reported even for a proxy whose upstream never resolves
            # to a known service.
            for issue in nginx_checks(nginx_tree(text,values)):
                issue_eid=fact(path,issue['line'],issue['directive'],
                               {'location':issue['location'],'value':issue['value'],
                                **({'variable':issue['variable']} if issue.get('variable') else {})})
                detail={
                    'RP-009':(f"{path}:{issue['line']} — `location {issue['location']}` prefiks mosligi `/` bilan "
                              f"tugamaydi, lekin ichida `alias {issue['value']}` bor. nginx bu juftlikda yo‘lni "
                              f"normallashtirmaydi: `{issue['location']}../` ko‘rinishidagi so‘rov alias papkasidan "
                              f"yuqoriga chiqishi mumkin. Har ikkala direktiva alohida to‘g‘ri; muammo aynan ularning "
                              f"birga kelishida."),
                    'RP-010':(f"{path}:{issue['line']} — `proxy_pass {issue['value']}` manzili "
                              f"`{issue.get('variable')}` o‘zgaruvchisidan quriladi, ya’ni upstream hostni so‘rov "
                              f"yuboruvchi tanlaydi. Bu ichki tarmoqdagi istalgan manzilga so‘rov yuborish (SSRF) "
                              f"imkonini beradi. Amaliy ta’sir DNS resolver sozlamasi va tarmoq segmentatsiyasiga "
                              f"bog‘liq — qo‘lda tekshirilishi shart."),
                    'RP-011':(f"{path}:{issue['line']} — `{issue['location']}` blokida o‘z `add_header` direktivasi "
                              f"bor. nginx add_header’ni darajalar bo‘ylab birlashtirmaydi, shuning uchun yuqorida "
                              f"e’lon qilingan `{issue['value']}` sarlavha(lar)i aynan shu blok uchun umuman "
                              f"yuborilmaydi. Sarlavhalar sozlangandek ko‘rinadi, lekin bu yo‘lda ishlamaydi."),
                }[issue['rule']]
                finding(issue['rule'],sid,f"{path}:{issue['line']}:{issue['rule']}",detail,
                        [bind_eid,issue_eid],'error' if issue['rule']=='RP-010' else 'warning')
            for route in routes:
                target=route['target']
                if not target or 'UNRESOLVED_' in route['url'] or '$' in route['url']:
                    unknowns.append(f'{path}:{route["line"]}: proxy target/protokol yechilmagan.')
                    continue
                if target not in by_id:
                    unknowns.append(f'{path}:{route["line"]}: {target} Compose xizmatiga bog‘lanmadi.')
                    continue
                eid=fact(path,route['line'],'Proxy yo‘li',{'service':sid,'location':route['location'],'upstream':route['url'],'listen':route['listen']})
                shared=sorted(set(by_id[sid]['networks']) & set(by_id[target]['networks']))
                edge={'from':sid,'to':target,'type':'proxy_route','location':route['location'], 'listen':route['listen'],
                      'target_port':route['target_port'],'scheme':route['scheme'],'shared_networks':shared,
                      'reachability':'candidate' if shared else 'unknown','evidence_ids':[bind_eid,eid], 'runtime_verified':False}
                edges.append(edge)
                if route['scheme']=='https' and route['verify']=='off':
                    verify_eid=fact(path,route['verify_line'],'proxy_ssl_verify','off')
                    finding('RP-002',sid,f'{target}:{route["target_port"]}:{route["location"]}',
                            f"{sid} → {target}, {route['location']}: HTTPS tanlangan, lekin upstream sertifikatini tekshirish off. Source mapping qo‘lda berilgan; deployed image mosligi va amaliy ta’sir tekshirilmagan.",[bind_eid,eid,verify_eid])
                parallel=[p for p in by_id[target]['ports'] if route['target_port'] is not None and p['target']<=route['target_port']<=p.get('target_end',p['target']) and p['protocol']=='tcp']
                if parallel:
                    scopes=', '.join(sorted(set(p['scope'] for p in parallel)))
                    finding('RP-003',target,f'{sid}:{route["target_port"]}',
                            f"{target} proxy orqali ham, host porti orqali ham ko‘rsatilgan ({scopes}). Bu autentifikatsiyani chetlab o‘tish isboti emas; ruxsat talabi va amaliy kirish tekshirilishi kerak.",[bind_eid,eid]+[p['evidence_id'] for p in parallel], 'note')
                    if route['trust_headers']:
                        header_eid=fact(path,route['line'],'Gateway ishonch sarlavhasi',{'proxy_set_header':route['trust_headers']})
                        finding('RP-004',target,f'{sid}:{route["target_port"]}:{",".join(route["trust_headers"])}',
                                f"{sid} → {target} proxysi {', '.join(route['trust_headers'])} orqali chaqiruvchi shaxsini backendga uzatadi — gateway o‘zi buni to‘g‘ri sozlagan. Ammo xuddi shu {target} xizmati host portidan ham to‘g‘ridan-to‘g‘ri ochiq ({scopes}); bu holda istalgan tashqi so‘rovchi shu sarlavha(lar)ni o‘zi soxta qiymat bilan yuborib, gateway autentifikatsiyasini butunlay chetlab o‘tishi mumkin. Ikkala tomon (proxy sozlamasi va port mappingi) alohida qaraganda “to‘g‘ri”; zaiflik faqat ularni birlashtirganda paydo bo‘ladi.",
                                [bind_eid,eid,header_eid]+[p['evidence_id'] for p in parallel],'error')
        except (ValueError,OSError,TypeError) as error:
            unknowns.append(f'{path}: proxy adapteri — {error}')
    now=datetime.datetime.now(datetime.timezone.utc)
    report={'schema_version':2,'kind':'repository','id':now.strftime('%Y%m%dT%H%M%S')+'-'+uuid.uuid4().hex[:8],
            'created_at':now.isoformat(),'engine_version':VERSION,'duration_ms':round((time.perf_counter()-started)*1000,2),
            'repository':provenance or {'repository':root.name,'commit':None}, 'profile':{'compose':compose,'env_file':env_file,'bindings':bindings,**({'overrides':overrides} if overrides else {})},
            'input_sha256':digest(canonical({'files':files,'bindings':bindings,'compose':compose,'env_file':env_file})), 'files':files,'services':inventory,'edges':edges,
            'evidence':evidence,'findings':findings,'unknowns':list(dict.fromkeys(unknowns)),'coverage_gaps':unknowns.coverage(),
            'summary':{'services':len(inventory),'published_ports':sum(len(s['ports']) for s in inventory),
                       'loopback_ports':sum(p['scope']=='loopback' for s in inventory for p in s['ports']),
                       'proxy_routes':len(edges),'findings':len(findings),'runtime_confirmed':0},
            'verification_summary':verification_mod.summarize(findings),
            'limits':['Faqat berilgan Compose fayli, .env va proxy bindinglar o‘qildi; repository kodi bajarilmadi.',
                      'Ishga tushirilgan konteynerlar, image digest, firewall va autentifikatsiya tekshirilmagan.',
                      'Source → image mosligi qo‘lda berilgan mapping; latest image aynan shu commitdan ekanligi isbotlanmagan.',
                      'Nginx Lua va murakkab dinamik marshrutlar bajarilmaydi. Proxy grafigi hujum grafigi emas.',
                      'Boshqa override fayllari va shell environment qo‘llanmaydi; .env faqat literal qiymatlarni qo‘llaydi.',
                      'Ogohlantirishlar review talab qiladi; bu audit muvofiqligi yoki real ekspluatatsiya isboti emas.']}
    # Ready diffs for the Compose/nginx fixes that are one deterministic edit,
    # made now while the files are at hand (zanjir/fixes.py).
    from . import fixes
    report['fix_plan']=fixes.repository_plan(report,lambda relative:safe_read(root,relative))
    return report


def sarif(report):
    rules=[{'id':rid,'shortDescription':{'text':title},'help':{'text':remedy},
            'properties':{'tags':taxonomy.tag_static('repository',rid)['cwe_ids']}} for rid,(title,remedy) in RULES.items()]
    evidence={e['id']:e for e in report['evidence']}
    results=[]
    for finding in report['findings']:
        locations=[]
        for eid in finding['evidence_ids']:
            e=evidence[eid]
            if e['path']=='profile.json':
                continue
            locations.append({'physicalLocation':{'artifactLocation':{'uri':e['path'].replace('\\','/')},'region':{'startLine':e['line']}}})
        results.append({'ruleId':finding['rule_id'],'level':finding['level'],'message':{'text':finding['detail']},'locations':locations[:1],
                        'relatedLocations':[{'id':i+1,**loc} for i,loc in enumerate(locations[1:])],
                        'partialFingerprints':{'zanjir/v1':finding['fingerprint'],
                                                               # Both keys on purpose: 'zanjir/v1' is what every
                                                               # SARIF this project ever exported used, and dropping
                                                               # it would make GitHub re-report every existing
                                                               # repository finding as new. The shared name is now
                                                               # findings.VERSION, which the other four stages use.
                                                               findings_mod.VERSION:finding['fingerprint']},'properties':{'runtime_verified':False,'status':'review_required'}})
    return {'$schema':'https://json.schemastore.org/sarif-2.1.0.json','version':'2.1.0','runs':[{'tool':{'driver':{'name':'ThreatChain','version':VERSION,'rules':rules}},'results':results}]}
