"""Read public sample metadata with local Auth-Key, never expose the credential."""
import json
from pathlib import Path
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
hashes = ['6ce9a32dab44d084a6664b9ea6f6c2274632c6f014a251929755c890f75c19e5',
          'aae7e6c7ae3fd67dd9918c84211857bfb00f98b5f886b7dcfab88119c04cf2e6',
          '24c7c6cc3124b20c717ac485e263193e351f0ab2e672b353b38688ba218bda9a',
          '7430d4ff91880ad8296ea94fe9c43aab5a92f1901386ffdc0c7a829359d210db']
token = (ROOT / 'config/malwarebazaar.token').read_text(encoding='utf-8-sig').strip()
rows = []
for digest in hashes:
    request = urllib.request.Request('https://mb-api.abuse.ch/api/v1/',
        data=urllib.parse.urlencode({'query': 'get_info', 'hash': digest}).encode(),
        headers={'Auth-Key': token})
    with urllib.request.urlopen(request, timeout=30) as response:
        obj = json.load(response)
    for item in obj.get('data', []):
        rows.append({k: item.get(k) for k in ('sha256_hash', 'file_name', 'file_size', 'file_type',
                                             'signature', 'tags', 'first_seen')})
(ROOT / 'evidence/local/python-candidate-metadata.json').write_text(json.dumps(rows, indent=2), encoding='utf-8')
print(json.dumps(rows, indent=2))
