"""Stage reviewed project files at the root of the user-selected repository."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--repo',type=Path,default=ROOT/'private/group-delivery-repo')
repo=parser.parse_args().repo.resolve(strict=True)
expected=json.loads((ROOT/'config/release-assets.lock.json').read_text())['repository']
remote=subprocess.check_output(['git','remote','get-url','origin'],cwd=repo,text=True).strip()
if remote.removesuffix('.git')!='https://github.com/'+expected:
    raise ValueError('Delivery remote is not the configured user-selected repository')
files=[]
for folder in ('stealer_agent','vm_tools','tests','scripts','eval','training','.github'):
    files.extend(p for p in (ROOT/folder).rglob('*') if p.is_file() and not any(n in p.relative_to(ROOT).parts for n in ('__pycache__','data','runs','experiments'))
                 and p.name != 'stage_for_repository.py'
                 and p.suffix in ('.py','.ps1','.mjs','.md','.json','.txt','.yml','.yaml','.jsonl'))
files.extend(p for p in (ROOT/'docs').rglob('*') if p.is_file() and p.suffix.lower() in ('.md','.jpg','.png','.txt','.json'))
files.extend(p for p in (ROOT/'fixtures/safe').rglob('*') if p.is_file() and p.suffix in ('.py','.cs','.md'))
files.extend((ROOT/'config').glob('*.example.json'))
files.extend(ROOT/'config'/n for n in ('public-samples.json','setup-assets.lock.json','release-assets.lock.json','analysis-tools.lock.json'))
files.extend(ROOT/n for n in ('README.md','.gitignore','.gitattributes','SECURITY.md','agent_react.py',
                             'pyproject.toml','audit/AUDIT_REPORT.md','audit/review_checks.py'))
files.extend(ROOT.glob('requirements*.txt'))
files.extend(p for p in (ROOT/'training/experiments').rglob('*') if p.is_file() and p.suffix in ('.json','.md'))
files.extend(p for p in (ROOT/'deliverables/real-demo-evidence').rglob('*') if p.is_file() and p.suffix in ('.json','.md'))
files.append(ROOT/'deliverables/StealerLab_Buoi4.pptx')
legacy_lock=ROOT/'docs/legacy-source-manifest.json'
legacy=[]
if legacy_lock.is_file():
    for row in json.loads(legacy_lock.read_text(encoding='utf-8'))['files']:
        path=repo/row['path']
        data=path.read_bytes()
        if len(data)!=row['bytes'] or hashlib.sha256(data).hexdigest()!=row['sha256']:
            raise ValueError('Preserved original source changed: '+row['path'])
        legacy.append(row)
tokens=[p.read_bytes().strip() for p in (ROOT/'config').glob('*.token') if p.stat().st_size]
manifest=[]
for path in sorted(set(files)):
    data=path.read_bytes()
    if any(t in data for t in tokens if len(t)>20):
        raise ValueError('Known credential found: '+path.name)
    relative=path.relative_to(ROOT)
    target=repo/relative
    target.parent.mkdir(parents=True,exist_ok=True)
    target.write_bytes(data)
    manifest.append({'path':relative.as_posix(),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
manifest.extend(legacy)
(repo/'source-manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'files':len(manifest),'remote':expected,'remote_write':False}))
