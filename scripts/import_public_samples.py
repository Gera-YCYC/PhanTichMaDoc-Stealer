"""Fetch only two pinned research archives into RAM; decrypt exclusively in the VM."""
import json
from pathlib import Path
import subprocess
import urllib.request
from sync_vm import SSH, DEST, ROOT

COMMIT = '1b3add9538fc40c0e59bd7488d267b1ec796a43d'
subprocess.run(['scp', *SSH, str(ROOT / 'scripts/import_public_vm.py'), DEST + ':/home/labadmin/'], check=True)
for family in ('gomorrah', 'agenttesla'):
    url = f'https://raw.githubusercontent.com/jstrosch/malware-samples/{COMMIT}/binaries/{family}/2020/April/samples_pcap.zip'
    with urllib.request.urlopen(url, timeout=45) as response:
        blob = response.read(8_000_001)
    if len(blob) > 8_000_000:
        raise ValueError('Archive too large')
    result = subprocess.run(['ssh', *SSH, DEST, f'sudo python3 /home/labadmin/import_public_vm.py {family}'],
                            input=blob, capture_output=True, check=True, timeout=60)
    receipt = {**json.loads(result.stdout), 'url': url, 'repository_commit': COMMIT,
               'host_plaintext_file_created': False}
    (ROOT / f'evidence/local/public-{family}.json').write_text(json.dumps(receipt, indent=2), encoding='utf-8')
    print(json.dumps(receipt), flush=True)
