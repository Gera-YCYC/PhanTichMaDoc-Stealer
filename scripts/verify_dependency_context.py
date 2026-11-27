"""Verify bounded helper citations on immutable real source inside the VM."""
import hashlib
import json
from pathlib import Path
import subprocess
from sync_vm import SSH, DEST

ROOT=Path(__file__).resolve().parents[1]
source_run='20261127T175019_6cbdf3e9'
events=[json.loads(s) for s in (ROOT/'runs'/source_run/'events.jsonl').read_text(encoding='utf-8').splitlines()]
record=next(e['raw'] for e in events if e['event']=='observation' and
            e['raw']['tool']=='decode_python_literals' and e['raw']['status']=='ok')
case={k:record[k] for k in ('evidence_id','sample_sha256','output_sha256')}
script='''import hashlib,json
from pathlib import Path
from stealer_agent.journal import canonical
from vm_tools.syntax_context import related_contexts,index_source
case=CASE
root=Path('/opt/stealer-lab')
record=json.loads((root/'private/tool-evidence'/(case['evidence_id']+'.json')).read_text())
assert record['sample_sha256']==case['sample_sha256']
assert record['output_sha256']==case['output_sha256']==hashlib.sha256(canonical(record['lines'])).hexdigest()
index=index_source(record)
helper=next(f for f in index['functions'] if f['name']=='decrypt_password')
mapping=index['mapping']
expected={'line':mapping[helper['start']][0],'end_line':mapping[helper['end']][-1]}
results=[]
for name in ('get_login_data','get_credit_cards'):
    target=next(f for f in index['functions'] if f['name']==name)
    call=next(link for link in index['links'] if link['caller'] is target and link['callee'] is helper)
    context=related_contexts(record,[mapping[call['call_line']][0]])
    matches=[link for link in context['context_links'] if
             link.get('related_context_kind')=='callee_dependency_candidate_not_dataflow_proof' and
             link['ranges'][1]['line']==mapping[target['start']][0]]
    assert matches and matches[0]['ranges'][2]==expected
    rows={r['line']:r for r in context['lines']}
    assert all(r==record['lines'][n-1] for n,r in rows.items())
    assert all(n in rows for n in range(expected['line'],expected['end_line']+1))
    results.append({'function':name,'anchor_line':mapping[call['call_line']][0],
                    'helper_complete_range':expected,'ranges':matches[0]['ranges'],
                    'original_rows_verified':True,'backend':context['syntax_context']['backend']})
print(json.dumps({'kind':'real-source-helper-context-check-not-model-inference',**case,
    'source_sha256':index['source_sha256'],'parser_sha256':hashlib.sha256((root/'vm_tools/syntax_context.py').read_bytes()).hexdigest(),
    'checks':results,'limits':['Unique-name syntax candidate only; no executed behavior or semantic/dataflow proof.',
                              'No model accuracy score; source text and credential literals excluded.']}))
'''.replace('CASE',repr(case))
data=subprocess.check_output(['ssh',*SSH,DEST,
    'sudo -u analyst env PYTHONPATH=/opt/stealer-lab:/opt/stealer-lab/deps python3 -'],input=script.encode(),timeout=60)
result=json.loads(data)
result['source_run']=source_run
result['local_parser_sha256']=hashlib.sha256((ROOT/'vm_tools/syntax_context.py').read_bytes()).hexdigest()
assert result['local_parser_sha256']==result['parser_sha256']
output=ROOT/'deliverables/real-demo-evidence/dependency-context-real-source-check.json'
output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'receipt':str(output),'checks':result['checks']}))
