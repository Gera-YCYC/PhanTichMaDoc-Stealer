"""Publish allowlisted run metadata, never raw model messages or candidate data."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from stealer_agent.journal import dump_json, verify_journal
from stealer_agent.yara_corpus import validate_scan


def export(run, snapshot):
    count = verify_journal(run/'events.jsonl')
    events = [json.loads(line) for line in (run/'events.jsonl').read_text(encoding='utf-8').splitlines()]
    start = events[0]
    manifest = json.loads((ROOT/'private/source-snapshots'/snapshot/'manifest.json').read_text())
    if not all(manifest.get(name) == digest for name, digest in start['source_files'].items()):
        raise ValueError('Snapshot does not match source recorded at run start')
    summary = json.loads((run/'summary.private.json').read_text(encoding='utf-8'))
    frozen = next(e for e in events if e['event'] == 'rules_frozen')
    source = (run/'generated.yar').read_text(encoding='utf-8')
    if hashlib.sha256(source.encode()).hexdigest() != frozen['rule_sha256']:
        raise ValueError('Frozen rule hash differs')
    for partition, key in (('training','development'), ('holdout','holdout')):
        validate_scan(summary[key], start['corpus'], partition, source)
    later_models = sum(e['event'] == 'model_request' and e['sequence'] > frozen['sequence'] for e in events)
    if later_models:
        raise ValueError('Model called after rule freeze')
    public = []
    for event in events:
        row = {k: event[k] for k in ('sequence','timestamp','event','sha256')}
        row.update({k: event[k] for k in ('sample','attempt','phase','messages_sha256','schema_sha256') if k in event})
        if event['event'] == 'model_draft':
            row['selection'] = {k: event['response'].get(k) for k in ('selected_ids','condition')}
            row['metrics'] = {k: event['metrics'].get(k) for k in ('latency_s','prompt_tokens','completion_tokens','done_reason')}
        if 'raw' in event:
            row['tool'] = {k: event['raw'].get(k) for k in ('tool','sample','sample_sha256','status','backend',
                'evidence_id','output_sha256','duration_s','page','page_count')}
        if event['event'] == 'draft_rejected':
            row['rejected'] = True  # Error may contain source literals; retained only privately.
        public.append(row)
    receipt = {k: summary[k] for k in ('status','profile','corpora_sha256','model','rule_count','development',
        'holdout','independent_replay_equal','measured_thresholds_met','telemetry','coursework_accepted')}
    clean_rows = [r for part in ('development','holdout') for r in summary[part]['results'] if not r['positive']]
    receipt.update(run_id=run.name, source_snapshot=snapshot,
        model_digest=start['model']['digest'],
        model_config={k: start['config'][k] for k in ('num_ctx','num_predict','seed','think') if k in start['config']},
        journal_sha256=hashlib.sha256((run/'events.jsonl').read_bytes()).hexdigest(),
        journal_events=count, full_model_requests=sum(e['event']=='model_request' for e in events),
        model_calls_after_freeze=later_models,
        all_declared_clean={'count': len(clean_rows), 'false_positives':sum(r['matched'] for r in clean_rows),
                            'scope':'Includes development negatives and previously seen validation negatives; not all blind holdout'},
        limitations=summary.get('limitations',[]) + ['No human/GV approval; no unseen malware sensitivity measured.'],
        public_log_scope='Allowlisted metadata projection; sha256 fields identify original private events, not hashes of these projected rows')
    target = ROOT/'deliverables/real-demo-evidence/yara-runs'/run.name
    dump_json(target/'receipt.json', receipt)
    dump_json(target/'events.public.json', public)
    print(json.dumps({'run_id':run.name,'events':count,'public_directory':str(target),
                      'measured_thresholds_met':receipt['measured_thresholds_met']}))


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run',type=Path)
    parser.add_argument('--snapshot',required=True)
    args=parser.parse_args()
    export(args.run.resolve(strict=True),args.snapshot)
