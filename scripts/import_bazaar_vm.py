"""Read encrypted archive from stdin, decrypt only inside VM, require expected SHA256."""
import grp
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import pyzipper

expected = sys.argv[1]
approved = {'d4f57b427a281c4dc32d6b8cc12195e0ce262c9f80ac8a8505ff3a0b47536324': 'public_luna.bin',
            '926755cc31c239edc78b3ef4aa3b3cc64fbe7209d907f9d1cdaa4b560662adfc': 'public_mercurial.bin',
            '7430d4ff91880ad8296ea94fe9c43aab5a92f1901386ffdc0c7a829359d210db': 'public_python2024.bin'}
if expected not in approved:
    raise ValueError('Unapproved sample hash')
if not Path('/sys/class/dmi/id/product_name').read_text().startswith('VMware'):
    raise ValueError('Not the isolated lab VM')
blob = sys.stdin.buffer.read(64_000_001)
if len(blob) > 64_000_000:
    raise ValueError('Archive too large')
with pyzipper.AESZipFile(io.BytesIO(blob)) as archive:
    entries = [i for i in archive.infolist() if not i.is_dir()]
    if len(entries) != 1 or not 0 < entries[0].file_size <= 32_000_000:
        raise ValueError('Expected one bounded binary')
    data = archive.read(entries[0], pwd=b'infected')
if hashlib.sha256(data).hexdigest() != expected or not data.startswith(b'MZ'):
    raise ValueError('Sample hash/format mismatch')
root = Path('/opt/stealer-lab')
target = root / 'samples' / approved[expected]
if target.exists() and target.read_bytes() != data:
    raise ValueError('Existing sample changed')
target.write_bytes(data)
target.chmod(0o440)
os.chown(target, 0, grp.getgrnam('analyst').gr_gid)
config = root / 'config/vm.json'
value = json.loads(config.read_text())
value['max_sample_bytes'] = 32_000_000
config.write_text(json.dumps(value, indent=2))
print(json.dumps({'sample': target.name, 'sha256': expected, 'size_bytes': len(data),
                  'archive_sha256': hashlib.sha256(blob).hexdigest(), 'executed': False}))
