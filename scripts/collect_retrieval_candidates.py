"""Export bounded numeric retrieval features; raw samples and full source stay in VM."""
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.sync_vm import SSH, DEST
from stealer_agent.journal import dump_json

GUEST = '''import hashlib,json,sys
from pathlib import Path
sys.path.insert(0,'/opt/stealer-lab')
from vm_tools.code_search import candidates,FEATURES,VERSION
base=Path('/opt/stealer-lab')
cfg=json.loads((base/'config/vm.json').read_text())
latest={}
for p in sorted(Path(cfg['evidence_dir']).glob('ev_*.json'),key=lambda p:p.stat().st_mtime):
 r=json.loads(p.read_text())
 if r['sample'].startswith('public_') and r['tool'] in ('decompile_dotnet','disassemble_python') and r['status']=='ok':
  latest[r['sample']]=r
queries=['Login Data','password_value','cookie','token','UploadFile','urlbot','webhook','SmtpClient','NetworkCredential','requests','send','CryptUnprotectData','CopyFromScreen','Local State','base64','SQLite','AES','GetValue','FileGet','smtplib']
rows=[]
for sample,r in sorted(latest.items()):
 seen=set()
 for q in queries:
  hits=candidates(r,q)
  # First/middle/last occurrences; deterministic sampling before any labeling.
  selected=sorted(set([*range(min(3,len(hits))),len(hits)//2,len(hits)-1])) if hits else []
  for n in selected:
   c=hits[n]
   key=(q,c['line'])
   if key in seen: continue
   seen.add(key)
   anchor=r['lines'][c['index']]['text']
   rows.append({'sample':sample,'sample_sha256':r['sample_sha256'],'tool':r['tool'],
    'output_sha256':r['output_sha256'],'line':c['line'],'query':q,'features':c['features'],
    'anchor_sha256':hashlib.sha256(anchor.encode()).hexdigest(), 'preview':anchor[:500]})
print(json.dumps({'feature_version':VERSION,'features':FEATURES,'rows':rows}))
'''


def main():
    result = json.loads(subprocess.check_output(['ssh', *SSH, DEST, 'sudo python3 -'],
                                              input=GUEST.encode(), timeout=40))
    for i, row in enumerate(result['rows'], 1):
        row['id'] = 'R'+str(i).zfill(4)
    dump_json(ROOT/'private/retrieval-candidates.json', result)
    print(json.dumps({'candidates':len(result['rows']), 'samples':sorted({r['sample'] for r in result['rows']})}))


if __name__ == '__main__':
    main()
