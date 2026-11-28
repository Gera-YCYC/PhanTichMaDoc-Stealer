"""Build a scoped Gomorrah reference from a hash-pinned ILSpy record in the VM."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.sync_vm import SSH, DEST
from stealer_agent.journal import dump_json

DIGEST = '93d03c6d0c24ce480a06e77c84b33e0bbc0d606fd055ef7cedf772db05c7891d'
OUTPUT = 'cb2c5fe9b73249187551e5970da5c0637de37e8dd490695e24072bdd995693b5'
EID = 'ev_810c7f7d23014486'


def reference():
    units, checks = [], {}
    def add(key, proposition, markers, kind='behavior'):
        units.append({'id': key, 'kind': kind, 'proposition': proposition,
                      'source_references': [{'evidence_id': EID, 'line': n, 'end_line': n} for n in markers]})
        checks[key] = markers
    for browser, opened, origin in [('Opera', 1055, 1067), ('Chrome', 1103, 1115)]:
        prefix = browser.lower() + '-'
        add(prefix+'open', 'Opens the '+browser+' Login Data path with SQLiteHandler.', {opened: ['SQLiteHandler', browser, 'Login Data']})
        add(prefix+'table', 'Selects the logins table in '+browser+' data.', {opened: ['Login Data'], opened+1: ['ReadTable', 'logins']})
        for i, column in enumerate(('origin_url', 'username_value', 'password_value')):
            add(prefix+column, 'Reads '+column+' from the '+browser+' logins table.',
                {opened+1: ['ReadTable', 'logins'], origin+i: ['GetValue', column]})
        add(prefix+'decrypt-call', 'Passes bytes derived from the selected password_value to the local Decrypt helper.',
            {origin+2: ['value3', 'password_value'], origin+3: ['Decrypt(Encoding.Default.GetBytes(value3))']})
        add(prefix+'account', 'Constructs a '+browser+' Account using the selected fields and password variable.',
            {origin+4: ['new Account(', browser, 'value2, password, value']})
    groups = [('passwords',3577,'Passwords'), ('emails',3603,'emails_pass'), ('info',3629,'info_pc'),
              ('cc',3655,'CC'), ('screen',3681,'path_screenshot')]
    for key, n, operand in groups:
        add(key+'-upload', 'Supplies '+operand+' as the local file path to WebClient.UploadFile with urlbot + text.',
            {n: ['UploadFile(urlbot + text, '+operand+')']})
        add(key+'-ascii', 'Decodes the '+key+' upload response bytes as ASCII text.',
            {n: ['byte[] array', 'UploadFile'], n+1: ['Encoding.ASCII.GetString(array)']})
    for key, n, dest in [('one',4253,'URL_CC1'),('two',4306,'URL_CC2')]:
        add('late-'+key+'-upload', 'Invokes UploadFile by name with destination '+dest+' and the current path variable.',
            {n-4:[dest], n-3:['current'], n:['LateGet','"UploadFile"']})
        add('late-'+key+'-ascii', 'Decodes the late-bound '+dest+' upload response and stores the ASCII text in current.',
            {n:['LateGet','"UploadFile"'], n+9:['(byte[])obj'], n+10:['current = Encoding.ASCII.GetString']})
    add('dpapi', 'Calls CryptUnprotectData with input and output data structures.', {880:['CryptUnprotectData(', 'pDataIn', 'pDataOut']})
    add('utf8', 'Decodes bytes to text with the UTF-8 decoder.', {884:['Encoding.UTF8.GetString']})
    add('decrypt-declaration', 'Declares a Decrypt method taking a byte array.', {793:['string Decrypt(byte[]']}, 'observation')
    add('capture', 'Implements copying pixels from the screen.', {4200:['CopyFromScreen']})
    add('save-capture', 'Saves the capture to the screenshot path in PNG format.', {4200:['CopyFromScreen'],4201:['PictureBox1.Image'],4202:['Image.Save','path_screenshot','ImageFormat.Png']})
    add('self-read', 'Reads data from the executable path.', {3444:['FileOpen','Application.ExecutablePath'],3446:['FileGet']})
    add('config-split', 'Splits the self-read configuration text at the literal delimiter.', {3446:['FileGet'],3448:['Strings.Split','|FS|']})
    add('config-field', 'Assigns element 1 of the split data to urlbot.', {3448:['Strings.Split'],3449:['urlbot = array[1]']})
    for key,n,fragment in [('logs',3573,'/logs.php?hwid='),('screen',3677,'/screen.php?hwid=')]:
        add(key+'-fragment', 'Static relative upload URI fragment '+fragment+' (destination host unresolved).',
            {n:[fragment,'HWID()'],n+4:['UploadFile(urlbot + text']}, 'ioc')
    add('browser-attack', 'T1555.003: reads stored browser login credentials.',
        {1103:['Login Data'],1104:['ReadTable','logins'],1116:['username_value'],1117:['password_value']}, 'attack')
    add('screen-attack', 'T1113: code implements screen capture.', {4200:['CopyFromScreen'],4202:['Image.Save']}, 'attack')
    return units, checks


def main():
    units, checks = reference()
    # All values in this program are local constants or literal audit markers.
    # Guest returns hashes/counts only. The executable sample remains in the VM.
    guest = """import hashlib,json
from pathlib import Path
from stealer_agent.journal import canonical
r=json.loads((Path('/opt/stealer-lab/private/tool-evidence')/(eid+'.json')).read_bytes())
assert r['sample_sha256']==sample and r['output_sha256']==output==hashlib.sha256(canonical(r['lines'])).hexdigest()
rows={x['line']:x['text'] for x in r['lines']}
for unit, markers in checks.items():
    for n, parts in markers.items():
        assert all(p in rows[n] for p in parts), (unit,n)
print(json.dumps({'checked_units':len(checks),'checked_lines':len({n for m in checks.values() for n in m})}))
"""
    params = f'eid={EID!r}\nsample={DIGEST!r}\noutput={OUTPUT!r}\nchecks={checks!r}\n'
    receipt = json.loads(subprocess.check_output(['ssh',*SSH,DEST,
        'sudo -u analyst env PYTHONPATH=/opt/stealer-lab:/opt/stealer-lab/deps python3 -'],
        input=(params + guest).encode(), timeout=30))
    profile = {'schema_version':1,'profile_id':'gomorrah.atomic-development/1','sample_sha256':DIGEST,
               'scope':'Declared ILSpy sites for two browser stores, DPAPI, configuration, screen capture and file uploads.',
               'source_references':[{'evidence_id':EID,'output_sha256':OUTPUT},'eval/reference_profiles/gomorrah.static.json'],
               'reference_method':'Source-level development audit. Every declared reference site checked against immutable VM rows.',
               'model_self_review_used_as_truth':False,'human_reviewers':[],'dataset_split':'development',
               'reference_created_after_development_runs':True,'scoring_ready':True,'units':units,
               'limits':['Coverage is limited to these source sites. Runtime delivery and exact destination host remain unverified.']}
    target=ROOT/'eval/reference_units/gomorrah.atomic-v1.json'
    dump_json(target,profile)
    receipt.update(output_sha256=OUTPUT,sample_sha256=DIGEST,evidence_id=EID,
                   profile_sha256=hashlib.sha256(target.read_bytes()).hexdigest())
    dump_json(ROOT/'deliverables/real-demo-evidence/gomorrah-atomic-source-check.json',receipt)
    print(json.dumps(receipt))


if __name__=='__main__':
    main()
