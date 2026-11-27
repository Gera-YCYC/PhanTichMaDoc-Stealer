"""Audit recorded request/response exposure to recognized private literals.

Uses a declared detector, not a claim of universal secret discovery. Values and
their hashes never appear in the public receipt; raw journals remain private.
"""
import argparse
import hashlib
import json
from pathlib import Path

from stealer_agent.journal import canonical, verify_journal
from stealer_agent.redaction import collect_literals, EMAIL, string_values
from stealer_agent.security import SECRET


def calculate(events, raw_report=None):
    observations = [e for e in events if e['event']=='observation']
    texts = [r['text'] for e in observations for r in e['raw'].get('lines', [])]
    literals, truncated = collect_literals(texts)
    for text in texts:
        literals.update(m[0] for m in EMAIL.finditer(text))
        literals.update(m[0] for m in SECRET.finditer(text))
    # Short literals have common accidental matches. Report them as excluded
    # instead of misrepresenting this exact-substring test as semantic DLP.
    eligible = {s for s in literals if len(s)>=4}
    def contains(value):
        return any(secret in text for text in string_values(value) for secret in eligible)
    requests = [e for e in events if e['event']=='model_request']
    full_requests = [e for e in requests if 'messages' in e]
    schema_requests = [e for e in requests if 'schema' in e]
    responses = [e for e in events if e['event']=='model_response']
    if not requests or not responses:
        raise ValueError('A completed model request and response are required')
    if any(hashlib.sha256(canonical(e['messages'])).hexdigest()!=e['messages_sha256'] for e in full_requests):
        raise ValueError('Recorded model request hash mismatch')
    if any(hashlib.sha256(canonical(e['schema'])).hexdigest()!=e.get('schema_sha256') for e in schema_requests):
        raise ValueError('Recorded model schema hash mismatch')
    changed = [e['model_visible'].get('model_projection',{}).get('changed_lines',[]) for e in observations]
    request_hits = sum(contains(e['messages']) for e in full_requests)
    schema_hits = sum(contains(e['schema']) for e in schema_requests)
    exposure_hits = sum(contains(e.get('evidence',[])) for e in requests)
    response_hits = sum(contains(e.get('action',e.get('response',{}))) for e in responses)
    raw_claim_prose = ([{'text':c['text'],'value':c.get('value','')} for c in raw_report['claims']]
                       if raw_report is not None else None)
    eligible_measurement = bool(eligible) and not truncated
    return {'method':'recognized-literal-exposure-audit/3',
            'exposure_evaluation_status':('detector_truncated' if truncated else 'evaluated' if eligible else 'no_detected_literals'),
            'eligible_detected_literal_count':len(eligible),
            'excluded_short_literal_count':len(literals-eligible), 'detector_scan_truncated':truncated,
            'model_requests_checked':len(requests), 'model_responses_checked':len(responses),
            'full_request_messages_available':len(full_requests),
            'full_request_schemas_available':len(schema_requests),
            'requests_with_only_evidence_and_message_hash':len(requests)-len(full_requests),
            'requests_with_detected_literal':request_hits,
            'schemas_with_detected_literal':schema_hits,
            'request_evidence_with_detected_literal':exposure_hits,
            'responses_with_detected_literal':response_hits,
            'raw_report_available':raw_report is not None,
            'raw_claim_prose_with_detected_literal':sum(contains(c) for c in raw_claim_prose) if raw_claim_prose is not None else None,
            'raw_report_including_citations_contains_detected_literal':contains(raw_report) if raw_report is not None else None,
            'observations_with_projection_changes':sum(bool(c) for c in changed),
            'projection_changed_rows_total_with_repeats':sum(map(len,changed)),
            'available_request_hashes_verified':True,
            'recognized_literal_evidence_gate_passed':exposure_hits==0 if eligible_measurement else None,
            'recognized_literal_request_gate_passed':(request_hits==0 and schema_hits==0 and exposure_hits==0)
                                                     if eligible_measurement and len(full_requests)==len(schema_requests)==len(requests) else None,
            'limits':['Same declared pattern family as the projection, not an independent measurement of detector recall.',
                      'No claim that unknown, encoded, short or obfuscated secrets are absent.',
                      'Full-request gate needs all messages and schemas; older incomplete journals remain unevaluable.',
                      'No detected eligible literal or a truncated detector scan means exposure gates are null, not passed.',
                      'Private raw observations intentionally retain originals; this receipt does not approve raw logs for publication.']}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',type=Path)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    path=args.directory/'events.jsonl'
    count=verify_journal(path)
    events=[json.loads(s) for s in path.read_text(encoding='utf-8').splitlines()]
    raw_path=args.directory/'report.model-raw.json'
    result=calculate(events,json.loads(raw_path.read_text(encoding='utf-8')) if raw_path.is_file() else None)
    from stealer_agent.model_projection import ModelEvidenceView
    from stealer_agent.security import guard_observation
    view, replayed = ModelEvidenceView(), 0
    for event in events:
        if event['event']!='observation' or 'model_projection' not in event['model_visible']:
            continue
        raw=event['raw']
        base=raw if event['model_visible'].get('guard_disabled_for_evaluation') else guard_observation(raw)[0]
        projected=view.observation(base)
        if projected['lines']!=event['model_visible']['lines'] or projected['model_projection']!=event['model_visible']['model_projection']:
            raise ValueError('Cannot reproduce recorded input projection from private raw observation')
        replayed+=1
    result['projected_observations_reproduced_from_raw']=replayed
    result.update(run_id=args.directory.name,journal_events_verified=count,
                  journal_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                  raw_report_sha256=hashlib.sha256(raw_path.read_bytes()).hexdigest() if raw_path.is_file() else None)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result))


if __name__=='__main__':
    main()
