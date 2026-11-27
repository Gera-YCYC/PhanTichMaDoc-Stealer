"""Run only inside the lab VM after transferring reviewed offline assets."""
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile
import zipfile

assets = Path('/home/labadmin/extensions')
root = Path('/opt/stealer-lab')
receipt = json.loads((assets / 'receipt.json').read_text())
for item in receipt:
    if hashlib.sha256((assets / item['name']).read_bytes()).hexdigest() != item['sha256']:
        raise ValueError('Transferred asset digest mismatch')
subprocess.run(['dpkg', '-i', *[str(p) for p in assets.glob('*.deb')]], check=True)
source = assets / 'pycdc-source'
source.mkdir(exist_ok=True)
with tarfile.open(assets / 'pycdc-source.tar.gz') as archive:
    archive.extractall(source, filter='data')
checkout = next(source.glob('pycdc-*'))
build = assets / 'pycdc-build'
subprocess.run(['cmake', '-S', str(checkout), '-B', str(build), '-DCMAKE_BUILD_TYPE=Release'], check=True)
subprocess.run(['cmake', '--build', str(build), '-j', '2'], check=True)
for name in ('pycdc', 'pycdas'):
    dest = root / 'bin' / name
    dest.write_bytes((build / name).read_bytes())
    dest.chmod(0o755)
vendor = root / 'vendor'
vendor.mkdir(exist_ok=True)
for name in ('pyinstxtractor.py', 'pyinstxtractor-LICENSE'):
    (vendor / name).write_bytes((assets / name).read_bytes())
with zipfile.ZipFile(next(assets.glob('yara_python*.whl'))) as archive:
    archive.extractall(root / 'deps')
config = root / 'config/vm.json'
data = json.loads(config.read_text())
data.update(pycdc=str(root / 'bin/pycdc'), pycdas=str(root / 'bin/pycdas'), pyinstxtractor=str(vendor / 'pyinstxtractor.py'))
config.write_text(json.dumps(data, indent=2))
print('Extension tools installed offline; service not restarted until code sync')
