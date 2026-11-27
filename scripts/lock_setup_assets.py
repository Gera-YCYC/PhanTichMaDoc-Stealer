"""Maintainer helper: lock existing verified setup assets to upstream URLs and SHA256."""
import hashlib
import json
from pathlib import Path
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
base = ROOT/'private/lab-assets'
receipt = json.loads((base/'asset-receipt.json').read_text())
items = []
def add(path, url, digest=None):
    file = base/path
    actual = hashlib.sha256(file.read_bytes()).hexdigest()
    if digest and actual != digest:
        raise ValueError('Digest mismatch: '+path)
    items.append({'path':path,'url':url,'bytes':file.stat().st_size,'sha256':actual})

add('noble-server-cloudimg-amd64.vmdk',receipt['ubuntu_url'],receipt['sha256_expected'])
add('ilspy-linux.nupkg',receipt['ilspy_url'],receipt['ilspy_nupkg_sha256'])
for item in json.loads((base/'extensions/receipt.json').read_text()):
    add('extensions/'+item['name'], item['url'], item['sha256'])
needed = {'jsonschema','attrs','referencing','rpds_py','jsonschema_specifications',
          'typing_extensions','pefile','yara_python','pyzipper','pycryptodomex',
          'tree_sitter','tree_sitter_python','tree_sitter_c_sharp'}
for wheel in sorted((base/'wheels').glob('*.whl')):
    package, version = wheel.name.split('-')[:2]
    if package not in needed or wheel.name.startswith('pefile-2023'):
        continue
    with urllib.request.urlopen('https://pypi.org/pypi/'+package+'/'+version+'/json',timeout=30) as response:
        metadata = json.load(response)
    upstream = next(u for u in metadata['urls'] if u['filename']==wheel.name)
    add('wheels/'+wheel.name,upstream['url'],upstream['digests']['sha256'])
(ROOT/'config/setup-assets.lock.json').write_text(json.dumps({'assets':items,
    'ilspy_binary_sha256':receipt['ilspy_binary_sha256'],
    'scope':'Ubuntu 24.04 amd64 / CPython 3.12 guest; pinned download-only dependencies'},indent=2)+'\n')
print(json.dumps({'locked_assets':len(items)}))
