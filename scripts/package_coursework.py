"""Local allowlist bundle; excludes VM/models/keys/malware/raw public reports."""
import hashlib
import json
from pathlib import Path
import zipfile
from datetime import datetime,timezone

root=Path(__file__).resolve().parents[1]
stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
files=[]
files.extend(p for p in (root/'lab_web').rglob('*') if p.is_file() and p.suffix in ('.py','.js','.css','.html'))
for folder in ('stealer_agent','vm_tools','tests','scripts','eval','training','.github'):
    files += [p for p in (root/folder).rglob('*') if p.is_file()
              and not any(n in p.relative_to(root).parts for n in ('__pycache__','data','runs','experiments'))
              and p.name != 'stage_for_repository.py'
              and p.suffix in ('.py','.ps1','.mjs','.md','.json','.txt','.yml','.yaml')]
files += [p for p in (root/'docs').rglob('*') if p.is_file() and p.suffix.lower() in ('.md','.jpg','.png','.txt','.json')]
files += list((root/'config').glob('*.example.json'))
files += [root/'config'/name for name in ('public-samples.json','setup-assets.lock.json','release-assets.lock.json','analysis-tools.lock.json')]
files += [p for p in (root/'fixtures/safe').rglob('*') if p.is_file() and p.suffix in ('.py','.cs','.md')]
files += [root/'deliverables/StealerLab_Buoi4.pptx']
files += [p for p in (root/'deliverables/real-demo-evidence').rglob('*') if p.is_file() and p.suffix in ('.json','.jsonl','.md')]
files += [root/'README.md',root/'SECURITY.md',root/'agent_react.py',root/'pyproject.toml',root/'.gitignore',root/'.gitattributes',root/'audit/AUDIT_REPORT.md',root/'audit/review_checks.py']
files += list(root.glob('requirements*.txt'))
files += [p for p in (root/'training/experiments').rglob('*') if p.is_file() and p.suffix in ('.json','.md')]
secrets=[p.read_bytes().strip() for p in (root/'config').glob('*.token') if p.stat().st_size]
manifest=[]
dest=root/'deliverables'/f'StealerLab_source_{stamp}.zip'
with zipfile.ZipFile(dest,'x',zipfile.ZIP_DEFLATED) as archive:
    for p in sorted(set(files)):
        data=p.read_bytes()
        if any(len(secret)>20 and secret in data for secret in secrets):
            raise RuntimeError('Secret scan blocked an artifact: '+p.relative_to(root).as_posix())
        relative=p.relative_to(root).as_posix()
        archive.writestr('StealerLab/'+relative,data)
        manifest.append({'path':relative,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
    archive.writestr('StealerLab/package-manifest.json',json.dumps(manifest,ensure_ascii=False,indent=2))
with zipfile.ZipFile(dest) as archive:
    if archive.testzip() is not None:
        raise RuntimeError('ZIP CRC validation failed')
receipt={'archive':dest.name,'sha256':hashlib.sha256(dest.read_bytes()).hexdigest(),'files':len(manifest),
         'bytes':dest.stat().st_size,'excluded':['VM','models','tokens','SSH keys','malware','raw public run logs'],
         'published':False,'clean_machine_reproduction_verified':False}
(root/'deliverables/package-receipt.json').write_text(json.dumps(receipt,indent=2))
print(json.dumps(receipt))
