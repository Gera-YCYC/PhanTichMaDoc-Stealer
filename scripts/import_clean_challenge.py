"""Import only the explicit clean challenge lock, without changing service profiles."""
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile
from sync_vm import ROOT, SSH, DEST

GUEST = '''import hashlib,json,pathlib,tarfile
root=pathlib.Path('/opt/stealer-lab')
samples=root/'samples'
with tarfile.open('/home/labadmin/clean-challenge.tar') as bundle:
    member=bundle.getmember('manifest.json')
    assert member.isfile() and member.size<200000
    raw=bundle.extractfile(member).read()
    assert hashlib.sha256(raw).hexdigest()==EXPECTED
    manifest=json.loads(raw)
    rows=manifest['source_manifest']['rows']
    assert len(rows)==38 and len({r['sha256'] for r in rows})==38
    assert len(bundle.getmembers())==39
    assert set(bundle.getnames())=={'manifest.json',*(r['sample'] for r in rows)}
    for row in rows:
        name=row['sample']; member=bundle.getmember(name)
        assert pathlib.Path(name).name==name and name.startswith('clean_') and name.endswith('.bin')
        assert member.isfile() and member.size==row['bytes'] and 1<=member.size<=32000000
        data=bundle.extractfile(member).read()
        assert hashlib.sha256(data).hexdigest()==row['sha256'] and row['positive'] is False
        path=samples/name
        assert not path.is_symlink()
        if path.exists(): assert path.read_bytes()==data
        else: path.write_bytes(data); path.chmod(0o444)
    for row in manifest['corpora']['training']:
        assert pathlib.Path(row['sample']).name==row['sample'] and row['positive'] is True
        assert hashlib.sha256((samples/row['sample']).read_bytes()).hexdigest()==row['sha256']
output=root/'private/evaluation/real-yara-challenge-v2.json'
if output.exists(): assert output.read_bytes()==raw
else: output.write_bytes(raw)
print(json.dumps({'clean_files_verified':38,'new_clean':30,'manifest_sha256':hashlib.sha256(raw).hexdigest(),'sample_execution':False}))
'''


def main():
    lock = ROOT/'eval/corpora/real-yara-challenge-v2.json'
    manifest = json.loads(lock.read_text(encoding='utf-8'))
    archive = ROOT/'private/clean-challenge/clean-challenge.tar'
    with tarfile.open(archive, 'w') as tar:
        tar.add(lock, arcname='manifest.json')
        for row in manifest['source_manifest']['rows']:
            path = ROOT/'private/clean-challenge'/row['sample']
            if path.parent != ROOT/'private/clean-challenge' or path.is_symlink():
                raise ValueError('Invalid challenge path')
            if hashlib.sha256(path.read_bytes()).hexdigest() != row['sha256']:
                raise ValueError('Local challenge hash differs')
            tar.add(path, arcname=row['sample'])
    subprocess.run(['scp', *SSH, str(archive), DEST+':/home/labadmin/clean-challenge.tar'], check=True)
    code = GUEST.replace('EXPECTED', repr(hashlib.sha256(lock.read_bytes()).hexdigest()))
    result = subprocess.run(['ssh', *SSH, DEST, 'sudo python3 -'], input=code, text=True, capture_output=True, check=True)
    output = json.loads(result.stdout)
    receipt = ROOT/'deliverables/real-demo-evidence/real-clean-challenge-import.json'
    receipt.write_text(json.dumps(output, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(output))


if __name__ == '__main__':
    main()
