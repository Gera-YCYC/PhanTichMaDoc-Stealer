"""Check the parser on immutable real VM features; not a fresh ReAct demo."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
from sync_vm import SSH, DEST

ROOT = Path(__file__).resolve().parents[1]
cases = []
for run, query in [('20261127T171819_406f8937', 'sendmail'), ('20261127T172625_ba003503', 'UploadFile')]:
    path = ROOT/'runs'/run/'events.jsonl'
    events = [json.loads(s) for s in path.read_text(encoding='utf-8').splitlines()]
    observation = next(e['raw'] for e in events if e['event'] == 'observation' and e['raw'].get('search_query') == query)
    eid = observation['evidence_id']
    if not re.fullmatch(r'ev_[a-f0-9]{16}', eid):
        raise ValueError('Invalid evidence ID')
    cases.append({'run': run, 'evidence_id': eid, 'sample_sha256': observation['sample_sha256'],
                  'output_sha256': observation['output_sha256'], 'query': query,
                  'anchors': [g['anchor_line'] for g in observation['search_groups']],
                  'source_journal_sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
script = '''import hashlib,json
from pathlib import Path
from vm_tools.syntax_context import related_contexts
cases=CASES
results=[]
for case in cases:
 record=json.loads((Path('/opt/stealer-lab/private/tool-evidence')/(case['evidence_id']+'.json')).read_text())
 assert record['sample_sha256']==case['sample_sha256'] and record['output_sha256']==case['output_sha256']
 result=related_contexts(record,case['anchors'])
 assert all(row==record['lines'][row['line']-1] for row in result['lines'])
 results.append({**case,'syntax_context':result['syntax_context'],'returned_lines':len(result['lines']),
                 'context_links':result['context_links'],'exact_source_rows_verified':True})
print(json.dumps({'kind':'real-VM-parser-check-on-captured-source-not-live-agent-demo','cases':results}))
'''.replace('CASES', repr(cases))
result = json.loads(subprocess.check_output(['ssh', *SSH, DEST,
    'sudo -u analyst env PYTHONPATH=/opt/stealer-lab:/opt/stealer-lab/deps python3 -'], input=script.encode(), timeout=40))
path = ROOT/'deliverables/real-demo-evidence/syntax-context-real-source-check.json'
path.write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
print(json.dumps(result, indent=2))
