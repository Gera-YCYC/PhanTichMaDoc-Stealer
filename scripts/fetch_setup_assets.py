"""Fetch exact upstream dependencies on host; the guest stays offline."""
import argparse
import concurrent.futures
import hashlib
import json
from pathlib import Path
import shutil
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    digest=hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda:stream.read(4*1024*1024),b''):
            digest.update(chunk)
    return digest.hexdigest()


def fetch(item, base, verify_only=False):
    dest=(base/item['path']).resolve()
    if not dest.is_relative_to(base.resolve()):
        raise ValueError('Asset path escapes cache')
    dest.parent.mkdir(parents=True,exist_ok=True)
    if not dest.exists():
        if verify_only:
            raise FileNotFoundError(dest.name)
        temporary=dest.with_name(dest.name+'.partial')
        if not item['url'].startswith('https://'):
            raise ValueError('HTTPS required')
        with urllib.request.urlopen(item['url'],timeout=60) as response, temporary.open('wb') as output:
            written=0
            while chunk:=response.read(1024*1024):
                written+=len(chunk)
                if written>item['bytes']:
                    raise ValueError('Asset exceeds expected size')
                output.write(chunk)
        if temporary.stat().st_size!=item['bytes'] or sha(temporary)!=item['sha256']:
            raise ValueError('Downloaded SHA256 mismatch: '+dest.name)
        temporary.replace(dest)
    if dest.stat().st_size!=item['bytes'] or sha(dest)!=item['sha256']:
        raise ValueError('Cached SHA256 mismatch: '+dest.name)
    return dest


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--verify-only',action='store_true')
    args=parser.parse_args()
    lock=json.loads((ROOT/'config/setup-assets.lock.json').read_text())
    base=ROOT/'private/lab-assets'
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        for dest in pool.map(lambda item:fetch(item,base,args.verify_only),lock['assets']):
            print('Verified '+dest.name,flush=True)
    with zipfile.ZipFile(base/'ilspy-linux.nupkg') as archive:
        candidates=[n for n in archive.namelist() if n.endswith('/ilspycmd')]
        if len(candidates)!=1:
            raise ValueError('Unexpected ILSpy package')
        binary=archive.read(candidates[0])
    if hashlib.sha256(binary).hexdigest()!=lock['ilspy_binary_sha256']:
        raise ValueError('ILSpy binary hash mismatch')
    (base/'ilspycmd').write_bytes(binary)
    extensions=[{'name':Path(a['path']).name,'url':a['url'],'bytes':a['bytes'],'sha256':a['sha256']}
                for a in lock['assets'] if a['path'].startswith('extensions/')]
    yara=next(a for a in lock['assets'] if a['path'].startswith('wheels/yara_python-'))
    shutil.copy2(base/yara['path'],base/'extensions'/Path(yara['path']).name)
    extensions.append({'name':Path(yara['path']).name,'sha256':yara['sha256'],'url':yara['url'],'bytes':yara['bytes']})
    (base/'extensions/receipt.json').write_text(json.dumps(extensions,indent=2))
    print('All setup assets verified. VM has not been modified.')


if __name__=='__main__':
    main()
