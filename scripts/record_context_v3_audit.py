"""Record the explicit source review of one fixed development run, not auto-grade."""
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from stealer_agent.journal import dump_json, utc_now, verify_journal
from eval.claim_audit import calculate


def main():
    directory=ROOT/'runs/20261127T201007_3f8805e5'
    raw_bytes=(directory/'report.model-raw.json').read_bytes()
    digest=hashlib.sha256(raw_bytes).hexdigest()
    assert digest=='3ec56efd85f5a3c8780dd3125990994e7049db439d14e6ff0ecdf6bbf652fe96'
    raw=json.loads(raw_bytes)
    result=json.loads((directory/'report.private.json').read_text(encoding='utf-8'))
    verify_journal(directory/'events.jsonl')
    events=[json.loads(s) for s in (directory/'events.jsonl').read_text(encoding='utf-8').splitlines()]
    projected={}
    for event in events:
        if event['event']=='observation':
            clean=event['model_visible']
            projected.setdefault(clean['evidence_id'],{}).update({r['line']:r['text'] for r in clean['lines']})
    notes={
        'C1':('correct','Caller and login helper show browser-profile Login Data copied to a temporary database.'),
        'C2':('correct','Citations include the selected password field, master_key argument and complete helper with AES.MODE_GCM and cipher.decrypt. This describes static capability, not successful recovery of real credentials. Same-model review incorrectly says the decryption implementation is absent.'),
        'C3':('correct','The cited card helper includes SELECT card fields including card_number_encrypted and cursor.fetchall. No runtime result is inferred.'),
        'C4':('correct','The card field is passed to decrypt_password with master_key; the same citation includes the complete AES-GCM helper.'),
        'C5':('correct','The source constructs from_email with get_computer_name and the projected literal, creates the MIME message and sets From. The hostname helper is included. The hidden address itself is not claimed known.'),
        'C6':('unsupported','The submitted range declares SMTP settings but ends before SMTP construction, authentication and sendmail. It supports configuration presence, not the asserted use of those credentials for sending.'),
        'C7':('unsupported','Archive implementation is present, but the claim additionally identifies its contents as browser data files. The caller only invokes save_results; this citation lacks its write implementation and the binding of staged files to the archived directory.'),
        'C8':('correct','The helper explicitly calls shutil.make_archive with zip format and a temporary Browser base path. This describes the static API operation and output name, not observed filesystem success.'),
        'C9':('correct','The supplied range includes smtplib.SMTP(smtp_server, smtp_port); the claim describes that construction without inventing credential values or runtime connection success.'),
        'C10':('correct','The supplied range includes msg.as_string and server.sendmail(from_email, to_email, text). The claim does not assert delivered mail or actual sensitive contents.'),
        'C11':('correct','The supplied caller assigns subject/message/recipient and passes them together with variable zip_path to send_email. Here zip_path is treated as the argument expression, not a literal path or proof that an attachment was sent.'),
        'C12':('unsupported','The cited caller invokes combine_and_zip_files and stores its result, but the claim asserts the helper combines/zips files. Its implementation is absent from this claim citation, although a different claim has it.'),
    }
    assert {c['id'] for c in raw['claims']}==set(notes)
    rows=[]
    for claim in raw['claims']:
        refs=[]
        for ref in claim['evidence']:
            text='\n'.join(projected[ref['evidence_id']][n] for n in range(ref['line'],ref['end_line']+1))
            assert text==ref['quote']
            refs.append({k:ref[k] for k in ('evidence_id','line','end_line')} |
                        {'projected_quote_sha256':hashlib.sha256(text.encode()).hexdigest()})
        label,reason=notes[claim['id']]
        rows.append({'claim_id':claim['id'],'label':label,'grounded':label=='correct',
                     'reviewer':'automated-source-audit; not human approval, not Qwen self-review',
                     'truth_reference':'Submitted ranges at original VM coordinates, checked against private observations and development reference units',
                     'reason':reason,'submitted_citations':refs})
    audit={'created_at':utc_now(),'run_id':directory.name,'sample_sha256':result['sample_sha256'],
           'dataset_origin':'public-development-sample-source-audit','human_reviewers':[],
           'raw_report_sha256':digest,'journal_sha256':hashlib.sha256((directory/'events.jsonl').read_bytes()).hexdigest(),
           'source_manifest_sha256':next(e['manifest_sha256'] for e in events if e['event']=='source_version'),
           'all_submitted_quotes_verified_against_projected_observations':True,
           'scope':'Twelve raw claims including the rejected correct C2. Static capabilities only. Projected quotes are not raw bytes; literal values remain private. Composite qualifiers are reviewed strictly and labels remain open to independent correction.',
           'claims':rows}
    dump_json(ROOT/'eval/adjudications/python2024-context-v3-projection-full-audit.json',audit)
    score=calculate(raw_bytes,result['analysis'],audit)
    dump_json(ROOT/'deliverables/real-demo-evidence/python2024-context-v3-projection-claim-score.json',score)
    print(json.dumps(score))


if __name__=='__main__':
    main()
