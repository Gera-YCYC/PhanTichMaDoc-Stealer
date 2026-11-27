"""Decrypt pinned research archives only inside the offline lab. Never executes samples."""
import grp
import hashlib
import json
import os
from pathlib import Path
import subprocess
import pyzipper

base=Path('/home/labadmin/release-import')
root=Path('/opt/stealer-lab')
if 'VMware' not in Path('/sys/class/dmi/id/product_name').read_text():
    raise RuntimeError('Not the isolated VMware lab')
for family in ('-4','-6'):
    if subprocess.check_output(['ip',family,'route','show','default'],text=True).strip():
        raise RuntimeError('Default route present; refusing import')
samples=json.loads((base/'public-samples.json').read_text())['samples']
lock=json.loads((base/'release-assets.lock.json').read_text())
locked={a['file']:a for a in lock['assets']}
manifest=base/'research-assets.json'
if hashlib.sha256(manifest.read_bytes()).hexdigest()!=locked[manifest.name]['sha256']:
    raise ValueError('Research manifest hash mismatch')
assets=json.loads(manifest.read_text())['assets']
receipts=[]
for item in assets:
    name=item['sample']
    if name not in samples or Path(name).name!=name or Path(item['file']).name!=item['file']:
        raise ValueError('Unexpected sample or path')
    archive=base/item['file']
    record=samples[name]
    if archive.stat().st_size>64000000 or hashlib.sha256(archive.read_bytes()).hexdigest()!=locked[archive.name]['sha256']:
        raise ValueError('Encrypted archive hash mismatch')
    with pyzipper.AESZipFile(archive) as z:
        entries=z.infolist()
        if len(entries)!=1 or entries[0].filename!=name or entries[0].file_size!=record['size_bytes']:
            raise ValueError('Expected exactly one pinned sample')
        data=z.read(name,pwd=b'infected')
    if hashlib.sha256(data).hexdigest()!=record['sha256'] or not data.startswith(b'MZ'):
        raise ValueError('Decrypted sample SHA256/format mismatch')
    target=root/'samples'/name
    if target.exists():
        if hashlib.sha256(target.read_bytes()).hexdigest()!=record['sha256']:
            raise FileExistsError('Existing sample differs; no overwrite')
    else:
        with target.open('xb') as output:
            output.write(data)
    target.chmod(0o440)
    os.chown(target,0,grp.getgrnam('analyst').gr_gid)
    receipts.append({'sample':name,'sha256':record['sha256'],'bytes':len(data),'executed':False})
result={'samples':receipts,'decrypted_inside_vm':True,'executed':False}
(root/'private/release-import-receipt.json').write_text(json.dumps(result,indent=2))
print(json.dumps(result))
