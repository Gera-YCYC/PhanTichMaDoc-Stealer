"""VM-only build of benign fixtures and labeled marker-detection corpus."""
import hashlib
import json
from pathlib import Path
import os
import subprocess
import zipfile

root = Path('/opt/stealer-lab')
assets = Path('/home/labadmin/fixture-wheels')
build = Path('/home/labadmin/fixture-build')
deps = build / 'deps'
deps.mkdir(parents=True, exist_ok=True)
for wheel in assets.glob('*.whl'):
    if wheel.name.startswith(('pyinstaller-', 'pyinstaller_hooks_', 'setuptools-', 'packaging-', 'altgraph-')):
        with zipfile.ZipFile(wheel) as archive:
            archive.extractall(deps)
for binary in deps.glob('PyInstaller/bootloader/*/*'):
    if binary.is_file():
        binary.chmod(0o755)
script = build / 'safe_bundle.py'
script.write_text('DOCUMENTATION_URL = "https://fixture.invalid/documentation"\nSAFE_LAB_FIXTURE = True\n')
env = {**os.environ, 'PYTHONPATH': str(deps)}
subprocess.run(['/usr/bin/python3', '-m', 'PyInstaller', '--onefile', '--name', 'safe_bundle.bin',
                '--distpath', str(build / 'dist'), '--workpath', str(build / 'work'),
                '--specpath', str(build), str(script)], check=True, env=env, cwd=build)
samples = root / 'samples'
(samples / 'safe_bundle.bin').write_bytes((build / 'dist/safe_bundle.bin').read_bytes())
(samples / 'marker_holdout.txt').write_bytes('SAFE_LAB_FIXTURE\nhttps://fixture.invalid/documentation\n'.encode('utf-16le'))
(samples / 'clean_holdout.txt').write_text('Ordinary course documentation.\nNo marker detected.\n')
def case(name, positive):
    return {'sample': name, 'positive': positive, 'sha256': hashlib.sha256((samples / name).read_bytes()).hexdigest()}
manifest = {'dataset_origin': 'synthetic-marker-detection-not-malware-accuracy', 'corpora': {
    'training': [case('LabFixture.dll', True), case('clean_example.py', False)],
    'holdout': [case('marker_holdout.txt', True), case('indicators_only.py', False), case('clean_holdout.txt', False)]}}
path = root / 'config/yara-demo-corpus.json'
path.write_text(json.dumps(manifest, indent=2))
config_path = root / 'config/vm.json'
config = json.loads(config_path.read_text())
config['yara_manifest'] = str(path)
config_path.write_text(json.dumps(config, indent=2))
subprocess.run(['chown', '-R', 'root:analyst', str(samples)], check=True)
for sample in samples.iterdir():
    if sample.is_file():
        sample.chmod(0o440)
print(json.dumps({'fixture': case('safe_bundle.bin', False), 'corpus': manifest}))
