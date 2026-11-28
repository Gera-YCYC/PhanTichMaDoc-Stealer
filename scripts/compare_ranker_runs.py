"""Compare real full-agent runs with source-order and trained retrieval respectively."""
import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts.report_experiment_receipt import summarize
from stealer_agent.journal import canonical, dump_json


def arm(name, baseline):
    folder=(ROOT/'runs'/name).resolve(strict=True)
    if folder.parent != (ROOT/'runs').resolve() or name != folder.name:
        raise ValueError('Expected one run ID')
    receipt=summarize(folder)
    events=[json.loads(l) for l in (folder/'events.jsonl').read_bytes().splitlines()]
    config=dict(next(e for e in events if e['event']=='run_started')['config'])
    if bool(config.pop('occurrence_order',False)) != baseline:
        raise ValueError('Run has the wrong retrieval setting')
    files=next(e for e in events if e['event']=='source_version')['files']
    checkpoint=files['vm_tools/code_ranker.json']
    queries={e['step']:e for e in events if e['event']=='action_dispatched' and e['action']=='search_evidence'}
    results=[e['raw'] for e in events if e['event']=='observation' and e['step'] in queries and
             e['raw'].get('status')=='ok' and e['raw'].get('tool') in
             {'decompile_dotnet','decompile_python','disassemble_python','decode_python_literals','python_ast'}]
    if not results or any(r['retrieval_model_sha256'] != (None if baseline else checkpoint) for r in results):
        raise ValueError('VM search observations do not prove the claimed ranking condition')
    return {'run_id':name,'sample_sha256':receipt['sample_sha256'],'model_digest':receipt['model']['digest'],
            'source_manifest_sha256':receipt['source_manifest_sha256'],
            'shared_config_sha256':hashlib.sha256(canonical(config)).hexdigest(),
            'journal_sha256':receipt['journal']['sha256'],'status':receipt['status'],'verdict':receipt['verdict'],
            'backend_ranker_sha256':None if baseline else checkpoint,'code_searches':len(results),
            'nonempty_code_searches':sum(r['hit_count']>0 for r in results),
            'fallback_reads':sum(e['event']=='navigation_page_read' for e in events),
            'raw_claim_count':receipt['proposed_claims'],'accepted_claim_count':receipt['accepted_claims'],
            'successful_tools':receipt['successful_tools'],'metrics':receipt['metrics']}


def compare(first, second):
    before, after=arm(first,True),arm(second,False)
    for key in ('shared_config_sha256','sample_sha256','model_digest','source_manifest_sha256'):
        if not before[key] or before[key] != after[key]:
            raise ValueError('The runs differ beyond retrieval order: '+key)
    return {'experiment':'full-agent-source-order-vs-trained-retriever','before':before,'after':after,
            'scope':'Paired runs on one development sample. Different trajectories are possible. Number of claims is not semantic accuracy.',
            'slm_weights_updated':False,'human_reviewers':[]}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--before',required=True)
    p.add_argument('--after',required=True)
    p.add_argument('--output',required=True,type=Path)
    args=p.parse_args()
    result=compare(args.before,args.after)
    dump_json(args.output,result)
    for side in ('before','after'):
        row=result[side]
        print(side,row['run_id'],row['status'],row['nonempty_code_searches'],row['accepted_claim_count'])
