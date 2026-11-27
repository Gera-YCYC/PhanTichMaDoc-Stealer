"""Export a metadata-only receipt for actual runs without raw malware features/keys."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from stealer_agent.journal import verify_journal, dump_json, utc_now


def summarize_run(run_id):
    if not re.fullmatch(r'\d{8}T\d{6}_[a-f0-9]{8}',run_id):
        raise ValueError('Expected an actual analysis run ID')
    path=ROOT/'runs'/run_id
    count=verify_journal(path/'events.jsonl')
    report=json.loads((path/'report.private.json').read_text(encoding='utf-8'))
    events=[json.loads(s) for s in (path/'events.jsonl').read_text(encoding='utf-8').splitlines()]
    actions=[{'step':e['step'],'action':e['action']} for e in events if e['event']=='action_dispatched']
    observations=[{k:e['raw'].get(k) for k in ('tool','backend','status','evidence_id','sample_sha256',
                  'output_sha256','total_lines','duration_s')} for e in events if e['event']=='observation']
    requests=[{'step':e['step'],'messages_sha256':e['messages_sha256'],
               'evidence_line_count':sum(len(item['lines']) for item in e['evidence'])}
              for e in events if e['event']=='model_request']
    return {'run_id':run_id,'sample':report['sample'],'sample_sha256':report['sample_sha256'],
            'status':report['status'],'model':{k:report['model'][k] for k in ('tag','digest')},
            'successful_tools':report['successful_tools'],'verdict':report['analysis']['verdict'],
            'proposed_verdict':report['analysis'].get('proposed_verdict'),
            'accepted_claims':len(report['analysis']['claims']),
            'rejected_claims':len(report['analysis']['rejected_claims']),
            'metrics':report['metrics'],'acceptance':report['acceptance'],
            'journal_events_verified':count,'journal_sha256':hashlib.sha256((path/'events.jsonl').read_bytes()).hexdigest(),
            'report_sha256':hashlib.sha256((path/'report.private.json').read_bytes()).hexdigest(),
            'source_manifest_sha256':next(e['manifest_sha256'] for e in events if e['event']=='source_version'),
            'actions':actions,'observations':observations,'requests':requests}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--run',action='append',required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    result={'created_at':utc_now(),'kind':'metadata-only-actual-run-receipt',
            'scope':'Real public malware, static tools in VM, local SLM. No sample execution. Not a quality score.',
            'runs':[summarize_run(run_id) for run_id in args.run], 'coursework_complete':False}
    dump_json(args.output,result)
    print(json.dumps({'runs':len(result['runs']),'output':str(args.output),'raw_sample_features_exported':False}))


if __name__=='__main__':
    main()
