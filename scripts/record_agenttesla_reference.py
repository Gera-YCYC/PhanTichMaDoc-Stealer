"""Verify a scoped static and publisher reference for the third development case."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.sync_vm import SSH, DEST
from stealer_agent.journal import dump_json, utc_now

SAMPLE = 'public_agenttesla.bin'
DIGEST = 'a4fdc26d6b70eaf0a62cca36286412901f48881eae616d38b96d8ae0cb0f29c7'
RECORD = 'ev_7548315e8c494f18'
OUTPUT = 'b707af40e0f6a0aea0381212c71907ef70a34645671b53a6695381b472a0a7a0'
PUBLISHER = ('https://raw.githubusercontent.com/jstrosch/malware-samples/'
             '1b3add9538fc40c0e59bd7488d267b1ec796a43d/binaries/agenttesla/2020/April/README.md')
PUBLISHER_HASH = 'efc6954514c9b3dbb47ce3617632ae8c5586a0890d22a4c5448ca2ad5b7d1949'
SOURCE_UNITS = [
    ('assembly-load', 'Calls the managed assembly loader.', {275:['Assembly.Load']}, 'behavior'),
    ('method-lookup', 'Looks up a method using reflection.', {282:['GetMethod','MethodInfo']}, 'behavior'),
    ('method-invoke', 'Invokes the reflected method.', {282:['MethodInfo'],283:['Invoke(']}, 'behavior'),
    ('manifest-stream', 'Opens manifest resource streams from the executing assembly.',
     {1803:['Assembly.GetExecutingAssembly','GetManifestResourceStream'],
      1804:['Assembly.GetExecutingAssembly','GetManifestResourceStream']}, 'behavior'),
    ('resource-object', 'Retrieves a resource object using ResourceManager.', {3336:['ResourceManager','GetObject']}, 'behavior'),
    ('interop-declaration', 'Declares a native import.', {919:['DllImport'],920:['static']}, 'observation'),
]


def main():
    with urlopen(PUBLISHER, timeout=20) as response:
        metadata = response.read(4096)
    if hashlib.sha256(metadata).hexdigest() != PUBLISHER_HASH:
        raise ValueError('Publisher reference changed')
    checks = {uid:marks for uid,_,marks,_ in SOURCE_UNITS}
    worker = """from pathlib import Path
import hashlib,json
from stealer_agent.journal import canonical
root=Path('/opt/stealer-lab')
sample=(root/'samples'/filename).read_bytes()
assert hashlib.sha256(sample).hexdigest()==digest
r=json.loads((root/'private/tool-evidence'/(eid+'.json')).read_bytes())
assert r['sample_sha256']==digest and r['output_sha256']==output==hashlib.sha256(canonical(r['lines'])).hexdigest()
rows={line['line']:line['text'] for line in r['lines']}
for uid,required in checks.items():
    for n,tokens in required.items():
        if not all(t in rows[n] for t in tokens): raise ValueError((uid,n))
print(json.dumps({'sample_md5':hashlib.md5(sample).hexdigest(),'checked_source_units':len(checks)}))
"""
    params = f'filename={SAMPLE!r}\ndigest={DIGEST!r}\neid={RECORD!r}\noutput={OUTPUT!r}\nchecks={checks!r}\n'
    verification = json.loads(subprocess.check_output(['ssh',*SSH,DEST,
        'sudo -u analyst env PYTHONPATH=/opt/stealer-lab:/opt/stealer-lab/deps python3 -'],
        input=(params+worker).encode(),timeout=30))
    lines = metadata.decode().splitlines()
    if verification['sample_md5'] not in metadata.decode() or 'exfil via SMTP' not in lines[11]:
        raise ValueError('Publisher did not establish sample identity and transfer channel')
    source = {'evidence_id':RECORD,'output_sha256':OUTPUT}
    publisher = {'url':PUBLISHER,'content_sha256':PUBLISHER_HASH,'line':12}
    units = [{'id':uid,'kind':kind,'proposition':statement,
              'source_references':[{'evidence_id':RECORD,'line':n,'end_line':n} for n in marks]}
             for uid,statement,marks,kind in SOURCE_UNITS]
    units.append({'id':'smtp-exfil','kind':'behavior','proposition':'Transfers data via SMTP.',
                  'source_references':[publisher]})
    profile = {'schema_version':1,'profile_id':'agenttesla.atomic-development/1','sample_sha256':DIGEST,
               'scope':'Six enumerated static sites plus the externally observed SMTP transfer channel. No runtime execution in this project.',
               'reference_method':'Hash-pinned ILSpy source and publisher record matched by MD5 to the exact SHA-256 verified lab sample.',
               'dataset_split':'development','expected_verdict':'malicious','model_self_review_used_as_truth':False,
               'human_reviewers':[],'scoring_ready':True,'source_references':[source,publisher],'units':units}
    path=ROOT/'eval/reference_units/agenttesla.atomic-v1.json'
    dump_json(path,profile)
    dump_json(ROOT/'deliverables/real-demo-evidence/agenttesla-atomic-source-check.json',
              {**verification,'checked_at':utc_now(),'sample_sha256':DIGEST,'source':source,'publisher':publisher,
               'profile_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
               'publisher_sample_identifier_verified':True,'source_only_confirms_technical_sites':True})
    print('Verified six source units, publisher SMTP observation and matching sample identity.')


if __name__=='__main__':
    main()
