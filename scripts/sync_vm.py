"""Sync trusted source only through pinned SSH; never copy samples from VM to host."""
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]
SSH = ['-i', str(ROOT / 'private/lab-vm/admin_ed25519'), '-o', 'BatchMode=yes', '-o',
       'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + str(ROOT / 'private/lab-vm/known_hosts')]
DEST = 'labadmin@192.168.56.101'


def sync():
    paths = [p for name in ('stealer_agent', 'vm_tools') for p in (ROOT / name).glob('*.py')]
    paths.extend((ROOT/'vm_tools').glob('code_ranker.json'))
    bundle = ROOT / 'private/lab-vm/source-update.tar'
    manifest = {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    with tarfile.open(bundle, 'w') as archive:
        for path in paths:
            archive.add(path, arcname=path.relative_to(ROOT).as_posix())
    receipt = ROOT / 'evidence/local/source-manifest.json'
    receipt.write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    subprocess.run(['scp', *SSH, str(bundle), str(receipt), DEST + ':/home/labadmin/'], check=True)
    command = ('sudo systemctl stop stealer-lab.service && '
               'sudo tar -xf /home/labadmin/source-update.tar -C /opt/stealer-lab && '
               'sudo chown -R root:root /opt/stealer-lab/stealer_agent /opt/stealer-lab/vm_tools && '
               'sudo find /opt/stealer-lab/stealer_agent /opt/stealer-lab/vm_tools -type d -exec chmod 0755 {} + && '
               'sudo find /opt/stealer-lab/stealer_agent /opt/stealer-lab/vm_tools -type f -exec chmod 0644 {} + && '
               'sudo cp /home/labadmin/source-manifest.json /opt/stealer-lab/source-manifest.json && '
               'sudo systemctl start stealer-lab.service')
    subprocess.run(['ssh', *SSH, DEST, command], check=True)
    print(json.dumps({'source_files': len(paths), 'manifest': str(receipt), 'service_restarted': True}))


if __name__ == '__main__':
    sync()
