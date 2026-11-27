"""Build byte-identical Ollama store parts for a GitHub Release (local staging only)."""
import hashlib
import json
from pathlib import Path
import tarfile
import sys

root=Path(__file__).resolve().parents[1]
store=root/'private/ollama-models'
out=root/'private/release-assets'
out.mkdir(parents=True,exist_ok=True)


class Parts:
    def __init__(self):
        self.limit=1500*1024*1024
        self.parts=[]
        self.handle=None
        self.size=0
        self.digest=None
    def write(self,data):
        original=len(data)
        while data:
            if self.handle is None:
                self.path=out/f'ollama-model.tar.part{len(self.parts)+1:02d}'
                self.handle=self.path.open('xb')
                self.digest=hashlib.sha256()
                self.size=0
            chunk=data[:self.limit-self.size]
            self.handle.write(chunk);self.digest.update(chunk);self.size+=len(chunk)
            data=data[len(chunk):]
            if self.size==self.limit:
                self.close_part()
        return original
    def close_part(self):
        if self.handle is not None:
            self.handle.close()
            self.parts.append({'file':self.path.name,'bytes':self.size,'sha256':self.digest.hexdigest()})
            self.handle=None


def digest_file(path):
    h=hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(4*1024*1024),b''):h.update(block)
    return h.hexdigest()


members=[]
for folder in ('blobs','manifests','manifests-v2'):
    for path in sorted((store/folder).rglob('*')):
        if path.is_file():
            sha=digest_file(path)
            if folder=='blobs' and path.name!='sha256-'+sha:
                raise ValueError('Model blob content digest mismatch')
            members.append({'path':path.relative_to(store).as_posix(),'bytes':path.stat().st_size,'sha256':sha})
writer=Parts()
with tarfile.open(fileobj=writer,mode='w|',format=tarfile.PAX_FORMAT) as archive:
    for member in members:
        p=store/member['path']
        info=tarfile.TarInfo(member['path']);info.size=p.stat().st_size;info.mode=0o644
        with p.open('rb') as stream:archive.addfile(info,stream)
writer.close_part()
result={'model':'qwen2.5-coder:7b','format':'tar split in ordered parts','parts':writer.parts,'members':members,
        'observed_ollama_digest':'dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364',
        'license':'Apache-2.0; original license also preserved in the model blobs',
        'source':'https://huggingface.co/Qwen/Qwen2.5-Coder-7B-Instruct',
        'excluded':'runtime metadata cache; no model weight or template omitted','published':False}
(out/'model-assets.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
print(json.dumps({'parts':writer.parts,'model_members':len(members)}),flush=True)
