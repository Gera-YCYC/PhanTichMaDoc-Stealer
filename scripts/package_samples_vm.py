"""Package pinned public malware as encrypted research archives, inside the VM only."""
import hashlib
import json
from pathlib import Path
import sys
import pyzipper

if 'VMware' not in Path('/sys/class/dmi/id/product_name').read_text():
    raise RuntimeError('This packaging operation must run in the isolated VMware lab')
manifest=json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
out=Path('/home/labadmin/research-release')
out.mkdir(exist_ok=True)
assets=[]
for name,record in manifest['samples'].items():
    data=(Path('/opt/stealer-lab/samples')/name).read_bytes()
    if hashlib.sha256(data).hexdigest()!=record['sha256']:
        raise ValueError('Pinned sample hash mismatch: '+name)
    archive=out/(name+'.research.zip')
    if archive.exists():
        raise FileExistsError('Do not silently replace an existing release archive')
    with pyzipper.AESZipFile(archive,'w',compression=pyzipper.ZIP_DEFLATED,encryption=pyzipper.WZ_AES) as z:
        z.setpassword(b'infected')
        z.writestr(name,data)
    with pyzipper.AESZipFile(archive) as z:
        restored=z.read(name,pwd=b'infected')
    if hashlib.sha256(restored).hexdigest()!=record['sha256']:
        raise ValueError('Encrypted archive verification failed')
    archive.chmod(0o644)
    assets.append({'file':archive.name,'sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),
                   'bytes':archive.stat().st_size,'sample':name,'sample_sha256':record['sha256'],
                   'source':record['source'],'encrypted':True,'executed':False})
(out/'research-assets.json').write_text(json.dumps({'assets':assets,'archive_password':'infected'},indent=2))
print(json.dumps({'encrypted_assets':len(assets),'directory':str(out)}))
