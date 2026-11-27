"""Version the observed false positive as development; add a fresh official app.

Keeps v1/v2 locks/results intact. Downloads only a pinned clean program and
imports bytes into the isolated VM without executing it.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import urllib.request
from sync_vm import ROOT, SSH, DEST

URL = 'https://github.com/mikf/gallery-dl/releases/download/v1.27.5/gallery-dl.exe'
DIGEST = '762fd8ff6dc50b94c05054a0f3a6177e715f60b523bf55a31cc3b6a2fda0c623'


def main():
    old = json.loads((ROOT/'eval/corpora/real-yara-challenge-v2.json').read_text(encoding='utf-8'))
    stage = ROOT/'private/clean-challenge'
    app = stage/'clean_gallerydl_1275.bin'
    if not app.exists():
        urllib.request.urlretrieve(URL, app)
    if app.stat().st_size != 13_060_647 or hashlib.sha256(app.read_bytes()).hexdigest() != DIGEST:
        raise ValueError('Pinned gallery-dl size/hash mismatch')
    negative = next(r for r in old['corpora']['holdout'] if r['sample'] == 'clean_ytdlp_20240806.bin')
    case = {'sample': app.name, 'sha256': DIGEST, 'positive': False}
    metadata = {**case, 'bytes': app.stat().st_size, 'source': URL, 'version': '1.27.5',
        'label_basis': 'Official open-source gallery downloader; expected non-stealer',
        'source_verification': 'HTTPS official GitHub release asset and locally pinned SHA256; GPG not verified',
        'build_source': 'https://github.com/mikf/gallery-dl/blob/v1.27.5/.github/workflows/executables.yml',
        'packaging': 'Project publishes PyInstaller builds; actual archive metadata verified separately inside VM'}
    lock = {'schema_version': 1, 'dataset_origin': 'real-yara-development-with-hard-negative/3',
        'corpora': {'training': old['corpora']['training']+[negative],
                   'holdout': [r for r in old['corpora']['holdout'] if r != negative]+[case]},
        'source_manifest': {'rows': old['source_manifest']['rows']+[metadata], 'sample_execution': False},
        'fresh_negative_hashes': [DIGEST],
        'limits': ['Five malware and yt-dlp are development; yt-dlp exposed a false positive in v1.',
                   'The partition called holdout includes 37 previously inspected Microsoft files; only gallery-dl is newly held out for this revision.',
                   '39 clean files total across both partitions; two legitimate PyInstaller apps, not full ecosystem coverage.',
                   'No unseen positive specimens; build-specific archive-name rules are vulnerable to renaming.',
                   'Rule quality does not establish behavior/IOC/ATT&CK/report quality.']}
    path = ROOT/'eval/corpora/real-yara-development-v3.json'
    if path.exists() and json.loads(path.read_text(encoding='utf-8')) != lock:
        raise ValueError('Existing v3 lock differs')
    path.write_text(json.dumps(lock, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    for file, name in ((path, 'yara-v3-manifest.json'), (app, app.name)):
        subprocess.run(['scp', *SSH, str(file), DEST+':/home/labadmin/'+name], check=True)
    code = '''import hashlib,json,pathlib
root=pathlib.Path('/opt/stealer-lab')
raw=pathlib.Path('/home/labadmin/yara-v3-manifest.json').read_bytes()
assert hashlib.sha256(raw).hexdigest()==MANIFEST_DIGEST
manifest=json.loads(raw)
data=pathlib.Path('/home/labadmin/clean_gallerydl_1275.bin').read_bytes()
assert len(data)==13060647 and hashlib.sha256(data).hexdigest()==APP_DIGEST
path=root/'samples/clean_gallerydl_1275.bin'
assert not path.is_symlink()
if path.exists(): assert path.read_bytes()==data
else: path.write_bytes(data); path.chmod(0o444)
for partition in manifest['corpora'].values():
    for row in partition:
        assert pathlib.Path(row['sample']).name==row['sample']
        assert hashlib.sha256((root/'samples'/row['sample']).read_bytes()).hexdigest()==row['sha256']
output=root/'private/evaluation/real-yara-development-v3.json'
if output.exists(): assert output.read_bytes()==raw
else: output.write_bytes(raw)
print(json.dumps({'negative_total':39,'positive_development':5,'new_negative':1,'manifest_sha256':hashlib.sha256(raw).hexdigest(),'sample_execution':False}))
'''.replace('MANIFEST_DIGEST', repr(hashlib.sha256(path.read_bytes()).hexdigest())).replace('APP_DIGEST', repr(DIGEST))
    result = subprocess.run(['ssh', *SSH, DEST, 'sudo python3 -'], input=code, text=True, capture_output=True, check=True)
    receipt = json.loads(result.stdout)
    (ROOT/'deliverables/real-demo-evidence/real-yara-v3-import.json').write_text(json.dumps(receipt, indent=2)+'\n')
    print(json.dumps(receipt))


if __name__ == '__main__':
    main()
