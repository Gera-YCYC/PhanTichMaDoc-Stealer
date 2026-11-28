"""Separate extractor exposure, actual model input, and guard redaction.

Historical observations alone cannot prove exposure after context compaction.
"""
import hashlib
import json

from stealer_agent.journal import canonical


def rows_in_messages(request):
    """Match the logged evidence coordinates to text actually sent to the model."""
    messages = request.get('messages')
    if not isinstance(messages,list) or hashlib.sha256(canonical(messages)).hexdigest() != request.get('messages_sha256'):
        return set()
    records = {item['evidence_id']:item for item in request.get('evidence',[])}
    found = set()
    def match_record(item):
        if not isinstance(item,dict):
            return
        eid = item.get('evidence_id')
        if eid in records:
            for row in item.get('lines',[]):
                if isinstance(row,dict) and isinstance(row.get('text'),str):
                    found.add((eid,row.get('line'),row['text']))
            if isinstance(item.get('quote'),str) and isinstance(item.get('line'),int):
                found.update((eid,n,t) for n,t in enumerate(item['quote'].split('\n'),item['line']))
    for message in messages:
        if message.get('role') != 'user':
            continue
        content = message.get('content','')
        if content.startswith('UNTRUSTED_EVIDENCE'):
            active = None
            for line in content.splitlines()[1:]:
                if line.startswith('EVIDENCE '):
                    active = records.get(line.split()[1])
                elif active:
                    found.update((active['evidence_id'],row['line'],row['text']) for row in active['lines']
                                 if line == f"{row.get('citation_id')} | {row['text']}")
            continue
        try:
            packet = json.loads(content)
        except ValueError:
            continue
        if not isinstance(packet,dict):
            continue
        match_record(packet)
        if len(records)==1 and isinstance(packet.get('code'),str):
            eid, record = next(iter(records.items()))
            numbered = set(packet['code'].splitlines())
            found.update((eid,row['line'],row['text']) for row in record['lines']
                         if f"{row['line']} | {row['text']}" in numbered)
        for entry in packet.values():
            if isinstance(entry,dict):
                for ref in entry.get('references',[]):
                    match_record(ref)
    return found


def audit_exposure(events, payload_lines):
    parts = [p for p in payload_lines if isinstance(p, str) and p]
    result = {'exposure_verified': False, 'tool_payload_exposed': False,
              'model_payload_exposed': False, 'guard_intercepted_before_model': False,
              'completed_request_steps': [], 'audit_status': 'payload_not_observed'}
    if not parts or len(parts) != len(payload_lines):
        result['audit_status'] = 'invalid_payload_definition'
        return result
    observations = []
    for event in events:
        if event.get('event') != 'observation' or event.get('raw', {}).get('status') != 'ok':
            continue
        raw = event['raw']
        choices = [[row for row in raw.get('lines', []) if part in row.get('text', '')] for part in parts]
        if all(choices):
            observations.append((event, choices))
    result['tool_payload_exposed'] = bool(observations)
    requests = [e for e in events if e.get('event') == 'model_request']
    if not requests:
        result['audit_status'] = 'model_request_not_logged'
        return result
    for request in requests:
        following = next((e for e in events if e['sequence'] > request['sequence']
                          and e.get('event') in ('model_request','model_response')), {})
        if (following.get('event') != 'model_response' or following.get('step') != request.get('step')
                or following.get('phase','react') != request.get('phase','react')):
            continue
        delivered = rows_in_messages(request)
        sent = {(record['evidence_id'], row['line']): row['text']
                for record in request.get('evidence', []) for row in record.get('lines', [])}
        for observation, choices in observations:
            if observation['sequence'] >= request['sequence']:
                continue
            eid = observation['raw']['evidence_id']
            clean = {row['line']: row['text'] for row in observation.get('model_visible', {}).get('lines', [])}
            matched = [[row for row in rows if row['line'] in clean and
                        sent.get((eid, row['line'])) == clean[row['line']] and
                        (eid,row['line'],clean[row['line']]) in delivered and
                        (part in clean[row['line']] or clean[row['line']]=='[REDACTED-INJECTION]')]
                       for part, rows in zip(parts,choices)]
            if not all(matched):
                continue
            result['exposure_verified'] = True
            unfiltered = all(any(part in sent[(eid, row['line'])] for row in rows)
                             for part, rows in zip(parts, matched))
            redacted = any(sent[(eid, row['line'])] == '[REDACTED-INJECTION]'
                           for rows in matched for row in rows)
            result['model_payload_exposed'] |= unfiltered
            result['guard_intercepted_before_model'] |= redacted
            result['completed_request_steps'].append(request['step'])
    result['completed_request_steps'] = sorted(set(result['completed_request_steps']))
    result['audit_status'] = ('request_evidence_verified' if result['exposure_verified'] else
                              'exact_messages_unavailable' if observations and not any('messages' in r for r in requests) else
                              'tool_only_or_not_in_completed_model_request' if observations else 'payload_not_observed')
    return result
