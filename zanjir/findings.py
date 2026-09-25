"""One stable identity for a finding, shared by every scanner.

Three features in REJA.md need the same thing first: "is this the same finding
as last time?" Triage decisions have to survive a rescan, a baseline has to tell
a new finding from an old one, and deduplication has to recognise one finding
reported twice. Today only the repository scanner answers that question; the
other five either have no identifier at all (code) or an ad-hoc one computed in
their own module from their own field list (dependencies, images, web).

The model is DefectDojo's: a per-scanner list of the fields that make up a
finding's identity (its `HASHCODE_FIELDS_PER_SCANNER`), hashed into one value.
The field lists here are our own, and two rules shape them:

  1. **A line number is never part of an identity.** Adding ten lines at the top
     of a file moves every finding below it. DefectDojo does include `line` for
     several parsers and accepts that churn; we cannot, because a triage decision
     that evaporates on an unrelated edit is worse than no triage at all. Code
     findings use the text of the matched line instead, whitespace-collapsed.
  2. **A missing field is an error, not a different hash.** `fingerprint()`
     refuses a value set that does not match the declared fields exactly. The
     alternative -- filling in a default -- silently produces a new identity for
     an old finding, which is the one failure this module exists to prevent.

`fingerprint` is added alongside each scanner's existing fields; nothing is
renamed or removed, and the identifiers the modules already compute keep their
own names and values.
"""
import hashlib
import json
import re

VERSION = 'threatchain/v1'
CONTEXT_LIMIT = 120
WHITESPACE = re.compile(r'\s+')

# Scanner -> the exact fields that make up an identity. Every list is explained
# where it is not obvious; the two that carry a real trade-off are gitleaks and
# images, and both are spelled out below.
FIELDS_PER_TOOL = {
    'semgrep': ('rule_id', 'path', 'context'),
    'pmd': ('rule_id', 'path', 'context'),
    # gitleaks is the one scanner whose finding text we deliberately cannot see:
    # it runs with --redact=100, so `Secret` and `Match` arrive as the literal
    # string "REDACTED" and there is nothing to hash. Hashing the secret would
    # be the obvious identity and it is not available by design -- and should not
    # be, since a SHA-256 of a low-entropy secret inside an exported SARIF file
    # turns a guess into a confirmation. Column and entropy come from the secret
    # without revealing it, they do not move when lines shift, and together they
    # separate two different secrets matched by one rule in one file. Two matches
    # at the same column with the same entropy would collide; that is accepted
    # and stated rather than papered over.
    'gitleaks': ('rule_id', 'path', 'column', 'entropy'),
    # A package's identity does not include where the lockfile lives: moving a
    # manifest is not a new vulnerability.
    'dependencies': ('ecosystem', 'package', 'advisory_id'),
    # Two deliberate choices here, both about surviving a rebuild:
    #   image_target, not the image digest -- every rebuild produces a new digest,
    #   so a digest-based identity would drop every triage decision exactly when
    #   the operator most needs to see what is still open. The registered target
    #   id is stable across rebuilds and still separates the same CVE in two
    #   different images, which the module's own `id` field does not do.
    #   No version, matching 'dependencies' above -- if an upgrade fixes the CVE
    #   the finding disappears on its own, and if it does not, it is still the
    #   same unfixed problem and its triage decision should carry over.
    'images': ('image_target', 'package', 'advisory_id'),
    # Only GET is ever sent today, so `method` is constant -- it is in the identity
    # so that a later check using another method cannot collide with this one.
    'web': ('rule_id', 'path', 'method'),
    # No line: Trivy reports one finding per file for most Dockerfile checks and
    # a line only for some, so including it would give two identities to one
    # check depending on which kind it is. `provider` separates a Dockerfile
    # check from a Kubernetes one that happens to share an id.
    'iac': ('rule_id', 'path', 'provider'),
}
# The repository scanner (and the cross-scanner chains built on it) already
# computes a stable fingerprint from its own evidence ids. It is reused as-is
# rather than recomputed, so existing reviews keyed by it keep working.
REUSED = ('repository', 'chain')


def context(text):
    """The matched line, reduced to what survives reformatting.

    Whitespace is collapsed because an indentation change is not a new finding,
    and the result is cut to CONTEXT_LIMIT characters so a minified or generated
    line does not put a whole file into the hash.
    """
    return WHITESPACE.sub(' ', str(text or '')).strip()[:CONTEXT_LIMIT]


def entropy(value):
    """gitleaks reports entropy as a float; round it so a rescan agrees with itself."""
    try:
        return f'{float(value):.3f}'
    except (TypeError, ValueError):
        return ''


# Applied to a field before hashing, so the same input always hashes the same
# way no matter which module passes it in.
NORMALISE = {'context': context, 'entropy': entropy}


def fingerprint(tool, values):
    """24 hex characters identifying one finding of one scanner.

    `values` must carry exactly the fields FIELDS_PER_TOOL declares for `tool` --
    no more, no fewer. See the module docstring for why a missing field raises
    instead of defaulting.
    """
    if tool in REUSED:
        raise ValueError(f'{tool} o‘z fingerprint’ini hisoblaydi; uni qayta hisoblash mumkin emas.')
    fields = FIELDS_PER_TOOL.get(tool)
    if fields is None:
        raise ValueError(f'Noma’lum skaner: {tool}')
    if not isinstance(values, dict) or set(values) != set(fields):
        missing = sorted(set(fields) - set(values or {}))
        extra = sorted(set(values or {}) - set(fields))
        raise ValueError(f'{tool} uchun maydonlar mos emas. Yetmaydi: {missing}; ortiqcha: {extra}')
    # Normalising here rather than in the callers: a scanner module that forgot
    # to collapse whitespace would produce a different identity for an unchanged
    # finding, and nothing would report it.
    payload = [VERSION, tool] + [NORMALISE.get(field, str)(values[field]) for field in fields]
    return hashlib.sha256(json.dumps(payload, ensure_ascii=False).encode('utf-8')).hexdigest()[:24]


def derived(rule_id, parts):
    """Identity for a cross-scanner chain finding (SX-00X).

    A chain finding has no fields of its own: it exists because two component
    findings exist together. So its identity is built from theirs -- pass the
    rule id and the components' own identities. Written here rather than in
    chain_secrets.py so SX-002 and later chains cannot invent a second scheme.
    """
    payload = [VERSION, 'chain', str(rule_id)] + [str(part) for part in parts]
    return hashlib.sha256(json.dumps(payload, ensure_ascii=False).encode('utf-8')).hexdigest()[:24]

