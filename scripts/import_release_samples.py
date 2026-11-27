"""Transfer encrypted archives to the pinned VM; no host-side malware decryption."""
import hashlib
import json
from pathlib import Path
import subprocess
from sync_vm import SSH, DEST

ROOT=Path(__file__).resolve().parents[1]
lock=json.loads((ROOT/'config/release-assets.lock.json').read_text())
base=ROOT/'private/release-assets'
files=[]
for item in lock['assets']:
    if item['file'].endswith('.research.zip') or item['file']=='research-assets.json':
        file=base/item['file']
        if hashlib.sha256(file.read_bytes()).hexdigest()!=item['sha256']:
            raise ValueError('Asset mismatch: '+file.name)
        files.append(file)
files.extend([ROOT/'config/public-samples.json',ROOT/'config/release-assets.lock.json',
              ROOT/'scripts/import_release_samples_vm.py'])
subprocess.run(['ssh',*SSH,DEST,'mkdir -p /home/labadmin/release-import'],check=True)
subprocess.run(['scp',*SSH,*map(str,files),DEST+':/home/labadmin/release-import/'],check=True)
command='sudo env PYTHONPATH=/opt/stealer-lab/deps python3 /home/labadmin/release-import/import_release_samples_vm.py'
raw=subprocess.check_output(['ssh',*SSH,DEST,command],timeout=120)
result=json.loads(raw)
out=ROOT/'evidence/local/release-import.json'
out.parent.mkdir(parents=True,exist_ok=True)
out.write_text(json.dumps(result,indent=2))
print(json.dumps({'verified_samples':len(result['samples']),'executed':False,'receipt':str(out)}))
