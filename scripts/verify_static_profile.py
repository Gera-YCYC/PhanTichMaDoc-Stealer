"""Check a declared static reference inside the VM and return metadata only."""
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts.sync_vm import SSH, DEST
from stealer_agent.journal import dump_json, utc_now


def verify(profile_path, output):
    data=profile_path.read_bytes()
    profile=json.loads(data)
    src=profile['source_record']
    if not re.fullmatch('ev_[0-9a-f]{16}',src['evidence_id']):
        raise ValueError('Invalid evidence record ID')
    checks=profile['source_checks']
    if set(checks)!={u['id'] for u in profile['units']}:
        raise ValueError('A source check is required for each unit')
    for unit in profile['units']:
        mentioned={n for r in unit['source_references'] if r['evidence_id']==src['evidence_id']
                   for n in range(r['line'],r['end_line']+1)}
        if mentioned != {int(n) for n in checks[unit['id']]}:
            raise ValueError('Reference coordinates and checks differ')
    worker="""import json,hashlib,re
from pathlib import Path
from stealer_agent.journal import canonical
r=json.loads((Path('/opt/stealer-lab/private/tool-evidence')/(eid+'.json')).read_bytes())
assert r['sample_sha256']==digest and r['output_sha256']==output==hashlib.sha256(canonical(r['lines'])).hexdigest()
rows={x['line']:x['text'] for x in r['lines']}
for uid,markers in checks.items():
    for n,terms in markers.items():
        for term in terms:
            line=rows[int(n)]
            if term=='<DISCORD_WEBHOOK_SHAPE>':
                matched=re.search(r'https?://(?:www[.])?discord(?:app)?[.]com/api/webhooks/\\d{8,24}/[A-Za-z0-9_-]{20,}',line,re.I)
            else:
                matched=term.casefold() in line.casefold()
            if not matched: raise ValueError((uid,n))
print(json.dumps({'units':len(checks),'source_lines':len(set(n for v in checks.values() for n in v))}))
"""
    params=f"eid={src['evidence_id']!r}\ndigest={profile['sample_sha256']!r}\noutput={src['output_sha256']!r}\nchecks={checks!r}\n"
    receipt=json.loads(subprocess.check_output(['ssh',*SSH,DEST,
        'sudo -u analyst env PYTHONPATH=/opt/stealer-lab:/opt/stealer-lab/deps python3 -'],input=(params+worker).encode(),timeout=30))
    dump_json(output,{**receipt,'profile_sha256':hashlib.sha256(data).hexdigest(),'source':src,
                      'sample_sha256':profile['sample_sha256'],'checked_at':utc_now(),'source_literals_exported':False})
    print(json.dumps(receipt))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    verify(args.profile,args.output)
