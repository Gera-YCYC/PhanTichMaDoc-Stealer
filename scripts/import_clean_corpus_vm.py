"""VM-only import of an explicit clean corpus and an independent YARA manifest.

Does not replace the existing fixture manifest or restart the tool service.
No sample is executed. The archive is produced from verified OS files by the host.
"""
import hashlib
import json
from pathlib import Path
import tarfile

ROOT=Path('/opt/stealer-lab')


def main():
    config=json.loads((ROOT/'config/vm.json').read_text())
    samples=Path(config['sample_dir']).resolve(strict=True)
    archive=Path('/home/labadmin/clean-corpus.tar')
    with tarfile.open(archive) as bundle:
        entry=bundle.getmember('manifest.json')
        if not entry.isfile() or entry.size>100_000:
            raise ValueError('Invalid clean manifest')
        manifest=json.loads(bundle.extractfile(entry).read().decode('utf-8-sig'))
        rows=manifest['rows']
        expected={'manifest.json',*(r['sample'] for r in rows)}
        if len(rows)!=8 or set(bundle.getnames())!=expected or len(bundle.getmembers())!=9:
            raise ValueError('Unexpected archive members')
        if len({r['sha256'] for r in rows})!=8:
            raise ValueError('Duplicate clean samples')
        for row in rows:
            name=row['sample']
            if Path(name).name!=name or not name.startswith('clean_ms_') or not name.endswith('.bin'):
                raise ValueError('Invalid clean sample name')
            member=bundle.getmember(name)
            if not member.isfile() or not 1<=member.size<=8_000_000 or member.size!=row['bytes']:
                raise ValueError('Invalid clean member type/size')
            data=bundle.extractfile(member).read()
            if hashlib.sha256(data).hexdigest()!=row['sha256'] or row['positive'] is not False:
                raise ValueError('Clean hash/label mismatch')
            if row['signature_status']!='Valid' or 'O=Microsoft Corporation' not in row['publisher']:
                raise ValueError('Host signature verification is missing')
            target=samples/name
            if target.is_symlink() or (target.exists() and target.read_bytes()!=data):
                raise ValueError('Refusing to replace existing sample')
            if not target.exists():
                target.write_bytes(data)
                target.chmod(0o444)
    public=json.loads(Path('/home/labadmin/clean-public-samples.json').read_text())
    positive=[]
    for name,meta in public['samples'].items():
        path=samples/name
        if hashlib.sha256(path.read_bytes()).hexdigest()!=meta['sha256']:
            raise ValueError('Public sample hash mismatch')
        positive.append({'sample':name,'sha256':meta['sha256'],'positive':True})
    lock={'schema_version':1,'dataset_origin':'public-malware-development-and-signed-clean-holdout/1',
          'corpora':{'training':positive,
                     'holdout':[{'sample':r['sample'],'sha256':r['sha256'],'positive':False} for r in rows]},
          'source_manifest':manifest,
          'limits':['Five malware specimens are development, not independent positive holdout.',
                    'Eight clean files were locked before new rule tuning; holdout TPR is null without positives.',
                    'Native Windows and managed tools only; no benign PyInstaller coverage yet.',
                    'Signature verification occurred on Windows, VM independently verifies exact hashes.',
                    'No source sample execution; these labels describe expected software identity, not all possible uses.']}
    output=ROOT/'private/evaluation/real-yara-v1.json'
    output.parent.mkdir(parents=True,exist_ok=True)
    if output.exists():
        old=json.loads(output.read_text())
        if old['corpora']!=lock['corpora']:
            raise ValueError('Corpus lock already exists with different hashes; create a new revision')
    else:
        output.write_text(json.dumps(lock,indent=2)+'\n')
    saved=output.read_bytes()
    print(json.dumps({'manifest_path':str(output),'manifest_sha256':hashlib.sha256(saved).hexdigest(),
                      'malware_development_count':len(positive),'clean_holdout_count':len(rows),
                      'tool_service_config_changed':False,'samples_executed':False,'manifest':json.loads(saved)}))


if __name__=='__main__':
    main()
