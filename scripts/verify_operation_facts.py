"""Run typed extraction on immutable real VM records and export metadata only."""
import hashlib
import argparse
import json
from pathlib import Path
import re
import subprocess
from sync_vm import SSH, DEST

ROOT=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output',type=Path,default=ROOT/'deliverables/real-demo-evidence/typed-operations-v6-real-source-check.json')
args=parser.parse_args()
cases=[]
for run,tool in [('20261127T180215_b3a8ccf4','decompile_dotnet'),('20261127T175019_6cbdf3e9','decode_python_literals')]:
    path=ROOT/'runs'/run/'events.jsonl'
    events=[json.loads(s) for s in path.read_text(encoding='utf-8').splitlines()]
    obs=next(e['raw'] for e in events if e['event']=='observation' and e['raw']['tool']==tool and e['raw']['status']=='ok')
    if not re.fullmatch('ev_[a-f0-9]{16}',obs['evidence_id']):
        raise ValueError('Invalid evidence ID')
    cases.append({'source_run':run,'evidence_id':obs['evidence_id'],'sample_sha256':obs['sample_sha256'],
                  'output_sha256':obs['output_sha256'],'journal_sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
script='''import hashlib,json
from collections import Counter
from pathlib import Path
from stealer_agent.journal import canonical
from vm_tools.operation_facts import extract_operations
cases=CASES
results=[]
root=Path('/opt/stealer-lab/private/tool-evidence')
modules={name:hashlib.sha256((Path('/opt/stealer-lab/vm_tools')/name).read_bytes()).hexdigest()
         for name in ('operation_facts.py','operation_dotnet.py','table_access.py','operation_python.py','syntax_context.py','context_worker.py')}
for case in cases:
    record=json.loads((root/(case['evidence_id']+'.json')).read_text())
    assert record['sample_sha256']==case['sample_sha256']
    assert record['output_sha256']==case['output_sha256']==hashlib.sha256(canonical(record['lines'])).hexdigest()
    out=extract_operations(record)
    destination=root/(out['backend'].replace('/','-')+'-'+case['evidence_id']+'.json')
    destination.write_text(json.dumps(out,ensure_ascii=False))
    results.append({**case,'backend':out['backend'],'fact_count':len(out['facts']),
        'operation_counts':dict(Counter(f['operation'] for f in out['facts'])),
        'facts':[{'fact_id':f['fact_id'],'operation':f['operation'],'api':f['api'],'ranges':f['ranges'],
                  'input_roles':list(f['inputs']),'result_meaning':f['result']['meaning']} for f in out['facts']],
        'artifact_sha256':hashlib.sha256(destination.read_bytes()).hexdigest(),
        'source_rows_hash_verified':True,'source_sha256':out['source_sha256']})
print(json.dumps({'kind':'typed-parser-check-on-real-VM-source-not-live-agent-demo','extractor_source':modules,'cases':results,
                  'limits':['API call facts only; no runtime success, sensitive-content proof or verdict.',
                            'Source, argument expression values and credentials excluded from this receipt.']}))
'''.replace('CASES',repr(cases))
data=subprocess.check_output(['ssh',*SSH,DEST,
    'sudo -u analyst env PYTHONPATH=/opt/stealer-lab:/opt/stealer-lab/deps python3 -'],input=script.encode(),timeout=60)
result=json.loads(data)
path=args.output
path.parent.mkdir(parents=True,exist_ok=True)
path.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'receipt':str(path),'cases':[{'source_run':r['source_run'],'facts':r['fact_count'],'counts':r['operation_counts']} for r in result['cases']]}))
