"""Restore the exact Ollama store from split TAR assets, without executing any archive content."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import tarfile
from fetch_setup_assets import sha

ROOT=Path(__file__).resolve().parents[1]


class PartsReader(io.RawIOBase):
    def __init__(self,paths):
        self.paths=iter(paths)
        self.handle=None
    def readable(self):
        return True
    def read(self,size=-1):
        if size<0:
            raise ValueError('Unbounded archive read refused')
        chunks=[]
        remaining=size
        while remaining:
            if self.handle is None:
                path=next(self.paths,None)
                if path is None:
                    break
                self.handle=path.open('rb')
            data=self.handle.read(remaining)
            if not data:
                self.handle.close()
                self.handle=None
                continue
            chunks.append(data)
            remaining-=len(data)
        return b''.join(chunks)
    def close(self):
        if self.handle:
            self.handle.close()
        super().close()


def restore(base,dest):
    lock=json.loads((ROOT/'config/release-assets.lock.json').read_text())
    manifests={a['file']:a for a in lock['assets']}
    meta_path=base/'model-assets.json'
    if sha(meta_path)!=manifests['model-assets.json']['sha256']:
        raise ValueError('Model manifest differs from source lock')
    meta=json.loads(meta_path.read_text())
    paths=[]
    for part in meta['parts']:
        p=base/part['file']
        if Path(part['file']).name!=part['file'] or sha(p)!=part['sha256'] or p.stat().st_size!=part['bytes']:
            raise ValueError('Model part hash/size mismatch')
        paths.append(p)
    expected={m['path']:m for m in meta['members']}
    if len(expected)!=len(meta['members']):
        raise ValueError('Duplicate model member')
    if dest.exists():
        for name,record in expected.items():
            p=(dest/name).resolve()
            if not p.is_relative_to(dest.resolve()) or not p.is_file() or sha(p)!=record['sha256']:
                raise FileExistsError('Existing model store differs. Use a new destination; no overwrite.')
        print('Existing exact model store verified; unchanged.')
        return
    staging=dest.with_name(dest.name+'.restoring')
    staging.mkdir(parents=True,exist_ok=False)
    seen=set()
    with PartsReader(paths) as reader, tarfile.open(fileobj=reader,mode='r|') as archive:
        for member in archive:
            record=expected.get(member.name)
            target=(staging/member.name).resolve()
            if (not member.isfile() or record is None or member.name in seen or
                member.size!=record['bytes'] or not target.is_relative_to(staging.resolve())):
                raise ValueError('Unexpected model archive member')
            target.parent.mkdir(parents=True,exist_ok=True)
            digest=hashlib.sha256()
            with archive.extractfile(member) as src, target.open('xb') as output:
                while block:=src.read(4*1024*1024):
                    digest.update(block)
                    output.write(block)
            if digest.hexdigest()!=record['sha256']:
                raise ValueError('Restored member hash mismatch')
            seen.add(member.name)
    if seen!=set(expected):
        raise ValueError('Missing model member')
    staging.rename(dest)
    print('Restored and verified '+str(len(seen))+' exact model members.')


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--destination',type=Path,default=ROOT/'private/ollama-models')
    parser.add_argument('--assets',type=Path,default=ROOT/'private/release-assets')
    args=parser.parse_args()
    restore(args.assets,args.destination)
