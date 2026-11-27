"""Transfer locally verified clean files into the isolated VM; publish metadata only."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tarfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts.sync_vm import SSH,DEST
from stealer_agent.journal import dump_json,utc_now


def main():
    stage=ROOT/'private/clean-corpus'
    manifest=json.loads((stage/'manifest.json').read_text(encoding='utf-8-sig'))
    rows=manifest['rows']
    if len(rows)!=8 or len({r['sha256'] for r in rows})!=8:
        raise ValueError('Exactly eight distinct signed utilities required')
    archive=stage/'clean-corpus.tar'
    with tarfile.open(archive,'w') as bundle:
        bundle.add(stage/'manifest.json',arcname='manifest.json')
        for row in rows:
            name=row['sample']
            if Path(name).name!=name or not name.startswith('clean_ms_') or not name.endswith('.bin'):
                raise ValueError('Invalid clean name')
            path=stage/name
            if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest()!=row['sha256']:
                raise ValueError('Local clean file differs')
            bundle.add(path,arcname=name)
    for source,destination in ((archive,'clean-corpus.tar'),
            (ROOT/'scripts/import_clean_corpus_vm.py','import_clean_corpus_vm.py'),
            (ROOT/'config/public-samples.json','clean-public-samples.json')):
        subprocess.run(['scp',*SSH,str(source),DEST+':/home/labadmin/'+destination],check=True)
    result=json.loads(subprocess.check_output(['ssh',*SSH,DEST,
            'sudo python3 /home/labadmin/import_clean_corpus_vm.py'],timeout=60))
    corpus=result.pop('manifest')
    output=ROOT/'eval/corpora/real-yara-v1.json'
    if output.exists() and json.loads(output.read_text())['corpora']!=corpus['corpora']:
        raise ValueError('Host corpus lock differs; keep old version and choose a new revision')
    dump_json(output,corpus)
    result.update(created_at=utc_now(),kind='real-clean-corpus-import-not-detection-evaluation',
                  host_manifest_sha256=hashlib.sha256(output.read_bytes()).hexdigest(),
                  source_files={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in
                    ('scripts/prepare_clean_corpus.ps1','scripts/import_clean_corpus.py','scripts/import_clean_corpus_vm.py')})
    dump_json(ROOT/'deliverables/real-demo-evidence/real-clean-corpus-import.json',result)
    print(json.dumps(result))


if __name__=='__main__':
    main()
