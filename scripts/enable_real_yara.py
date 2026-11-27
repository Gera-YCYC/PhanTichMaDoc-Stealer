"""Register an already imported, hash-pinned real corpus; keep fixture config intact."""
import hashlib
import argparse
import json
from pathlib import Path
import subprocess
from sync_vm import ROOT, SSH, DEST


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', choices=['real-v1', 'real-v3'], default='real-v1')
    profile = parser.parse_args().profile
    filename = 'real-yara-v1.json' if profile == 'real-v1' else 'real-yara-development-v3.json'
    manifest = json.loads((ROOT/'eval/corpora'/filename).read_text(encoding='utf-8'))
    digest = hashlib.sha256(json.dumps(manifest['corpora'], sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    code = '''import hashlib,json,pathlib
root=pathlib.Path('/opt/stealer-lab')
manifest=root/'private/evaluation'/FILENAME
data=json.loads(manifest.read_text())
actual=hashlib.sha256(json.dumps(data['corpora'],sort_keys=True,separators=(',',':')).encode()).hexdigest()
assert actual == EXPECTED, 'Host/VM corpus lock mismatch'
path=root/'config/vm.json'
config=json.loads(path.read_text())
config.setdefault('yara_profiles',{})[PROFILE]=str(manifest)
path.write_text(json.dumps(config,indent=2)+'\\n')
print(json.dumps({'profile':PROFILE,'corpora_sha256':actual,'fixture_preserved':bool(config.get('yara_manifest'))}))
'''.replace('EXPECTED', repr(digest)).replace('FILENAME', repr(filename)).replace('PROFILE', repr(profile))
    result = subprocess.run(['ssh', *SSH, DEST, "sudo python3 -"], input=code, text=True,
                            capture_output=True, check=True)
    print(result.stdout.strip())
    subprocess.run(['ssh', *SSH, DEST, 'sudo systemctl restart stealer-lab.service'], check=True)


if __name__ == '__main__':
    main()
