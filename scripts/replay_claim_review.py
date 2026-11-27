"""Measure a critic on fixed real-source claims; never feed audit labels to the SLM."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from jsonschema import Draft202012Validator
from stealer_agent.api_reference import reference_for, reference_prompt
from stealer_agent.evidence_cards import REVIEW_PROMPT, REVIEW_SCHEMA, object_schema
from stealer_agent.journal import canonical, dump_json, Journal, verify_journal
from stealer_agent.telemetry import available_memory_bytes
from stealer_agent.transport import OllamaClient


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', required=True)
    parser.add_argument('--audit', type=Path, required=True)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--decision-first', action='store_true')
    parser.add_argument('--no-api-guidance', action='store_true')
    parser.add_argument('--limit', type=int, default=0, help='Bounded smoke check only; zero reviews the full fixed report')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source = (ROOT/'runs'/args.run).resolve(strict=True)
    if source.parent != (ROOT/'runs').resolve():
        raise ValueError('Expected local run ID')
    verify_journal(source/'events.jsonl')
    raw_bytes = (source/'report.model-raw.json').read_bytes()
    raw = json.loads(raw_bytes)
    if args.limit < 0 or args.limit > len(raw['claims']):
        raise ValueError('Invalid claim limit')
    selected_claims = raw['claims'][:args.limit] if args.limit else raw['claims']
    config = json.loads(args.config.read_text(encoding='utf-8'))
    client = OllamaClient(config)
    model = client.inspect()
    schema = object_schema({key: REVIEW_SCHEMA['properties'][key] for key in ('supported', 'reason')}) if args.decision_first else REVIEW_SCHEMA
    run_id = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S') + '_' + uuid.uuid4().hex[:8]
    journal = Journal(ROOT/'private/report-experiments'/run_id)
    source_files = {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in sorted((ROOT/'stealer_agent').glob('*.py'))}
    settings = {'decision_first': args.decision_first, 'api_guidance': not args.no_api_guidance,
                'seed': config.get('seed'), 'num_ctx':config.get('num_ctx'), 'num_predict':config.get('num_predict'),
                'think':config.get('think'), 'claim_limit':args.limit,
                'config_sha256':hashlib.sha256(args.config.read_bytes()).hexdigest()}
    journal.append('critic_replay_started', source_run=args.run, model=model, settings=settings,
                   source_files=source_files, source_manifest_sha256=hashlib.sha256(canonical(source_files)).hexdigest(),
                   raw_report_sha256=hashlib.sha256(raw_bytes).hexdigest(), schema=schema,
                   scope='Same fixed claims and captured VM source; no new tool analysis or live sample demo')
    print(json.dumps({'run_id': run_id, 'claims': len(selected_claims), 'settings': settings}), flush=True)
    decisions = []
    metrics = {'model_calls':0, 'prompt_tokens':0, 'completion_tokens':0, 'minimum_free_ram_bytes':None}
    start = time.perf_counter()
    for claim in selected_claims:
        free = available_memory_bytes()
        if free is not None:
            metrics['minimum_free_ram_bytes'] = min(free, metrics['minimum_free_ram_bytes'] or free)
            if free < 256*1024*1024:
                client.unload()
                raise RuntimeError('ResourceBudgetExceeded')
        refs = claim['evidence']
        code = '\n\n'.join(f"SECTION {i+1} original lines {r['line']}-{r['end_line']}\n" +
                  '\n'.join(f"{r['line']+n} | {s}" for n,s in enumerate(r['quote'].split('\n'))) for i,r in enumerate(refs))
        pack = reference_for(code) if not args.no_api_guidance else {'entries':[]}
        messages = [{'role':'system', 'content':REVIEW_PROMPT+reference_prompt(pack)},
                    {'role':'user', 'content':json.dumps({'claim':claim['text'], 'code':code}, ensure_ascii=False)}]
        journal.append('model_request', claim_id=claim['id'], messages=messages,
                       messages_sha256=hashlib.sha256(canonical(messages)).hexdigest(), evidence=refs, api_reference=pack)
        response, usage = client.chat(messages, schema)
        valid = Draft202012Validator(schema).is_valid(response)
        journal.append('model_response', claim_id=claim['id'], response=response, metrics=usage, schema_valid=valid)
        metrics['model_calls'] += 1
        for k in ('prompt_tokens','completion_tokens'):
            metrics[k] += usage.get(k) or 0
        decisions.append({'claim_id':claim['id'], 'supported':response.get('supported') if valid else None,
                          'schema_valid':valid})
        print(json.dumps(decisions[-1]), flush=True)
    metrics['elapsed_s'] = round(time.perf_counter()-start, 4)
    # Read labels only after the last model response. Never put them in prompts.
    audit = json.loads(args.audit.read_text(encoding='utf-8'))
    assert audit['raw_report_sha256'] == hashlib.sha256(raw_bytes).hexdigest()
    labels = {r['claim_id']: r['label']=='correct' for r in audit['claims']}
    assert set(labels) == {c['id'] for c in raw['claims']}
    matrix = Counter(('accepted' if r['supported'] is True else 'rejected' if r['supported'] is False else 'invalid') +
                     ('_correct' if labels[r['claim_id']] else '_not_supported') for r in decisions)
    result = {'run_id':run_id, 'source_run':args.run, 'kind':'fixed-real-claim-critic-experiment-not-live-demo',
              'model':{k:model.get(k) for k in ('tag','digest')}, 'settings':settings,
              'raw_report_sha256':hashlib.sha256(raw_bytes).hexdigest(),
              'audit_sha256':hashlib.sha256(args.audit.read_bytes()).hexdigest(),
              'source_manifest_sha256':hashlib.sha256(canonical(source_files)).hexdigest(),
              'claim_count':len(decisions), 'source_claim_count':len(raw['claims']),
              'full_report_reviewed':len(decisions)==len(raw['claims']),
              'decisions':decisions, 'confusion_counts':dict(matrix), 'metrics':metrics,
              'limits':['Reference labels are a development source audit, not lecturer/human approval.',
                        'This measures critic decisions on fixed claims, not full-agent precision, recall or verdict.',
                        'No new malware/tool execution occurred; audit labels were not sent to the model.']}
    journal.append('critic_replay_finished', result=result)
    result['journal_events'] = verify_journal(journal.path)
    result['journal_sha256'] = hashlib.sha256(journal.path.read_bytes()).hexdigest()
    dump_json(args.output, result)
    print(json.dumps({'output':str(args.output), 'confusion_counts':dict(matrix), 'elapsed_s':metrics['elapsed_s']}), flush=True)


if __name__ == '__main__':
    main()
