"""Aggregate the verified-vs-manual-review split every finding is tagged with.

Every finding across scanners/dependencies/images/webscan/repository carries a
`verified` (or the older `runtime_verified`) boolean:
  True  -> directly confirmed by real interaction with the authorized target
           (an actual HTTP response, an actual TLS handshake, an actual image
           layer) -- not proof of exploitability or business impact, just that
           the underlying observation is real, not inferred.
  False -> a static or database match (source pattern, secret-like string,
           package/version advisory lookup, image package inventory, parsed
           config) with no direct proof it is reachable or true right now.
"""

NOTE = ('confirmed_by_evidence: nishonning haqiqiy javobi/holati bilan bevosita kuzatilgan. '
        'manual_review_required: statik yoki bazaviy moslik — mutaxassis tomonidan qo‘lda tasdiqlanishi shart.')


def is_verified(finding):
    if 'verified' in finding:
        return bool(finding['verified'])
    return bool(finding.get('runtime_verified', False))


def summarize(findings):
    findings = findings or []
    total = len(findings)
    confirmed = sum(1 for item in findings if is_verified(item))
    return {'total': total, 'confirmed_by_evidence': confirmed,
            'manual_review_required': total - confirmed, 'note': NOTE}


def summarize_many(finding_lists):
    """Combine several already-computed summarize() results (e.g. one per pipeline stage)."""
    total = sum(item['total'] for item in finding_lists)
    confirmed = sum(item['confirmed_by_evidence'] for item in finding_lists)
    return {'total': total, 'confirmed_by_evidence': confirmed,
            'manual_review_required': total - confirmed, 'note': NOTE}
