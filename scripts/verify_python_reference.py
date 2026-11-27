"""Verify a public reference against immutable VM evidence, exporting metadata only."""
import json
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts.sync_vm import SSH,DEST
from stealer_agent.journal import dump_json,utc_now


def main():
    profile=json.loads((ROOT/'eval/reference_profiles/python2024.static.json').read_text(encoding='utf-8'))
    script='''import hashlib,json
from pathlib import Path
p=PROFILE
root=Path('/opt/stealer-lab/private/tool-evidence')
matches=[]
for path in [root/(p['static_evidence']['evidence_id']+'.json')]:
 r=json.loads(path.read_text())
 if r.get('tool')=='decode_python_literals' and r.get('sample_sha256')==p['sample_sha256'] and r.get('status')=='ok':
  joined={}
  for row in r['lines']: joined[row['source_line']]=joined.get(row['source_line'],'')+row['text']
  lines=[t for n,t in joined.items() if n>=3][:p['static_evidence']['payload_lines']]
  sha=hashlib.sha256('\\n'.join(lines).encode()).hexdigest()
  if sha==p['static_evidence']['normalized_source_sha256']:
   checks=[]
   for fact in p['facts']:
    text='\\n'.join(lines[n-1] for n in fact['lines'])
    checks.append({'id':fact['id'],'markers_verified':all(marker in text for marker in fact['markers']), 'lines':fact['lines']})
   matches.append({'evidence_id':r['evidence_id'],'output_sha256':r['output_sha256'],'normalized_source_sha256':sha,'facts':checks})
print(json.dumps({'matching_records':matches,'passed':bool(matches) and all(c['markers_verified'] for m in matches for c in m['facts'])}))
'''.replace('PROFILE',repr(profile))
    result=json.loads(subprocess.check_output(['ssh',*SSH,DEST,'sudo python3 -'],input=script.encode(),timeout=40))
    result.update(created_at=utc_now(),kind='VM-source-marker-audit-not-human-adjudication',sample_sha256=profile['sample_sha256'])
    dump_json(ROOT/'deliverables/real-demo-evidence/python-reference-verification.json',result)
    print(json.dumps(result))
    return 0 if result['passed'] else 2


if __name__=='__main__': raise SystemExit(main())
