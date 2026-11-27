"""Bounded typed call facts from recovered source; no sample execution.

Only supported lexical bindings are emitted. Missing facts never imply benignness.
These facts describe API calls, not runtime success, sensitive contents or C2.
"""
from __future__ import annotations

import hashlib
from .syntax_context import reconstruct
from stealer_agent.journal import canonical

VERSION = 'static-operation-facts/2'


def extract_operations(record, *, max_facts=60):
    if not 1 <= max_facts <= 100:
        raise ValueError('Invalid operation bound')
    source, mapping = reconstruct(record)
    if record['tool'] == 'decompile_dotnet':
        from .operation_dotnet import candidates
    else:
        from .operation_python import candidates
    rows = {r['line']: r for r in record['lines']}
    facts = []
    for item in candidates(source):
        ranges, selected = [], set()
        for start, end in item.pop('source_ranges'):
            numbers = [n for s in range(start, end+1) for n in mapping.get(s, [])]
            if not numbers or len(numbers) > 40:
                break
            selected.update(numbers)
            part = {'line': numbers[0], 'end_line': numbers[-1]}
            if part not in ranges:
                ranges.append(part)
        else:
            if not ranges or len(ranges) > 6 or sum(len(rows[n]['text'])+1 for n in selected) > 4600:
                continue
            body = {**item, 'backend': VERSION, 'evidence_id': record['evidence_id'], 'sample_sha256':record['sample_sha256'],
                    'output_sha256':record['output_sha256'], 'ranges':ranges,
                    'scope':'Static API call under supported lexical binding; no runtime observation or sensitive-content inference'}
            body['fact_id'] = 'op_' + hashlib.sha256(canonical(body)).hexdigest()[:16]
            facts.append(body)
            if len(facts) >= max_facts:
                break
    return {'backend':VERSION, 'facts':facts, 'source_sha256':hashlib.sha256(source).hexdigest(),
            'limitations':['Supported direct calls only; aliases, reflection and unresolved bindings can be omitted.',
                           'No reachability, successful execution, secret contents or malicious verdict is inferred.']}
