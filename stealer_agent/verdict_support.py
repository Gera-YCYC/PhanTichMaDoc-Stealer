"""Require an explicit evidence chain before retaining a stealer verdict.

The support sets come from the SLM and remain hypotheses for independent review.
This gate checks coverage/references, not semantic truth or malicious intent.
"""
from __future__ import annotations

import copy

SUPPORT_KEYS = ('sensitive_collection_claim_ids', 'outbound_transfer_claim_ids', 'data_link_claim_ids')


def enforce_stealer_support(report, support):
    result = copy.deepcopy(report)
    behavior_ids = {c['id'] for c in result['claims'] if c['kind'] == 'behavior'}
    cited = set(result['verdict_claim_ids'])
    missing = []
    invalid = []
    for key in SUPPORT_KEYS:
        values = support.get(key, [])
        if not values:
            missing.append(key)
        elif not set(values) <= behavior_ids & cited:
            invalid.append(key)
    result['verdict_support'] = {key: list(support.get(key, [])) for key in SUPPORT_KEYS}
    result['verdict_support_scope'] = 'SLM-assigned claim roles; coverage check only, not independent semantic verification'
    result['verdict_support_missing'] = missing
    result['verdict_support_invalid'] = invalid
    if result['verdict'] == 'malicious' and (missing or invalid):
        result['verdict'] = 'suspicious' if cited & behavior_ids else 'inconclusive'
        result['validation_notes'].append('stealer_verdict_requires_collection_transfer_and_explicit_data_link')
    return result
