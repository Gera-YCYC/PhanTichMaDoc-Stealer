"""Verify reference-unit coordinates/markers in the VM; never grade model text."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from sync_vm import SSH, DEST

ROOT=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--profile',type=Path,required=True)
parser.add_argument('--evidence-id',help='A local immutable VM record for the same decoded source')
parser.add_argument('--output',type=Path,required=True)
args=parser.parse_args()
profile_bytes=args.profile.read_bytes()
profile=json.loads(profile_bytes)
eid=args.evidence_id or profile['source_record']['evidence_id']
if not re.fullmatch('ev_[a-f0-9]{16}',eid):
    raise ValueError('Invalid evidence ID')
script='''import hashlib,json
from pathlib import Path
from stealer_agent.journal import canonical
from vm_tools.syntax_context import reconstruct
profile=PROFILE
eid=EID
record=json.loads((Path('/opt/stealer-lab/private/tool-evidence')/(eid+'.json')).read_text())
assert record['sample_sha256']==profile['sample_sha256']
assert record['output_sha256']==hashlib.sha256(canonical(record['lines'])).hexdigest()
source,_=reconstruct(record)
assert hashlib.sha256(source).hexdigest()==profile['source_record']['parser_source_sha256']
rows={r['line']:r['text'] for r in record['lines']}
verified=[]
for unit in profile['units']:
    quotes=[]
    ranges=[]
    for ref in unit['ranges']:
        assert 1<=ref['line']<=ref['end_line'] and ref['end_line']-ref['line']<40
        quote='\\n'.join(rows[n] for n in range(ref['line'],ref['end_line']+1))
        quotes.append(quote)
        ranges.append({**ref,'quote_sha256':hashlib.sha256(quote.encode()).hexdigest()})
    assert all(marker in '\\n'.join(quotes) for marker in unit['required_markers']),unit['id']
    verified.append({'unit_id':unit['id'],'ranges':ranges,'markers_present':True})
print(json.dumps({'evidence_id':eid,'sample_sha256':record['sample_sha256'],'output_sha256':record['output_sha256'],
                  'parser_source_sha256':hashlib.sha256(source).hexdigest(),'verified_units':verified}))
'''.replace('PROFILE',repr(profile)).replace('EID',repr(eid))
result=json.loads(subprocess.check_output(['ssh',*SSH,DEST,
    'sudo -u analyst env PYTHONPATH=/opt/stealer-lab:/opt/stealer-lab/deps python3 -'],input=script.encode(),timeout=60))
result.update(kind='reference-unit-source-provenance-check-not-semantic-grade',
              profile_id=profile['profile_id'],profile_sha256=hashlib.sha256(profile_bytes).hexdigest(),
              units_checked=len(result['verified_units']),scoring_ready=False,
              limits=['Source hashes, coordinate ranges and marker presence only; no model correctness score.',
                      'Reference definitions are a development source audit, not lecturer or human approval.'])
args.output.parent.mkdir(parents=True,exist_ok=True)
args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'receipt':str(args.output),'units_checked':result['units_checked'],'scoring_ready':False}))
