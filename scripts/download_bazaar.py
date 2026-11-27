"""Download an exact public research sample; Auth-Key stays in local memory."""
import hashlib
import argparse
import json
from pathlib import Path
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from sync_vm import ROOT, SSH, DEST

SAMPLES = {
    'luna': 'd4f57b427a281c4dc32d6b8cc12195e0ce262c9f80ac8a8505ff3a0b47536324',
    'mercurial': '926755cc31c239edc78b3ef4aa3b3cc64fbe7209d907f9d1cdaa4b560662adfc',
    'python2024': '7430d4ff91880ad8296ea94fe9c43aab5a92f1901386ffdc0c7a829359d210db'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--sample', choices=SAMPLES, default='luna')
    args = parser.parse_args()
    SHA256 = SAMPLES[args.sample]
    token = (ROOT / 'config/malwarebazaar.token').read_text(encoding='utf-8-sig').strip()
    if not token or any(c.isspace() for c in token):
        raise ValueError('Auth-Key file must contain only a single key; contents withheld')
    body = urllib.parse.urlencode({'query': 'get_file', 'sha256_hash': SHA256}).encode()
    request = urllib.request.Request('https://mb-api.abuse.ch/api/v1/', data=body,
                                     headers={'Auth-Key': token, 'Content-Type': 'application/x-www-form-urlencoded'})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            blob = response.read(64_000_001)
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f'MalwareBazaar returned HTTP {exc.code}; credentials and response withheld') from None
    if len(blob) > 64_000_000 or not blob.startswith(b'PK'):
        raise ValueError('No bounded ZIP sample returned; response withheld')
    subprocess.run(['scp', *SSH, str(ROOT / 'scripts/import_bazaar_vm.py'), DEST + ':/home/labadmin/'], check=True)
    result = subprocess.run(['ssh', *SSH, DEST,
        'sudo env PYTHONPATH=/opt/stealer-lab/deps python3 /home/labadmin/import_bazaar_vm.py ' + SHA256],
        input=blob, capture_output=True, timeout=90)
    if result.returncode:
        raise RuntimeError('VM import rejected: ' + result.stderr.decode('utf-8', 'replace')[-500:])
    receipt = json.loads(result.stdout)
    receipt.update(source='https://bazaar.abuse.ch/sample/' + SHA256 + '/', host_plaintext_file_created=False)
    (ROOT / f'evidence/local/public-{args.sample}.json').write_text(json.dumps(receipt, indent=2), encoding='utf-8')
    print(json.dumps(receipt))


if __name__ == '__main__':
    main()
