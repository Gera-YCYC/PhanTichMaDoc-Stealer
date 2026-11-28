"""Score two pinned Gomorrah reports against the same ILSpy reference units."""
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from eval.atomic_units import calculate
from stealer_agent.journal import canonical, dump_json, verify_journal

FULL = '20261127T212209_478cc179'
NARROW = '20261127T223332_6006a331'
AUDITS = ROOT / 'eval/adjudications'
OUT = ROOT / 'deliverables/real-demo-evidence'
SITE = {3577:'passwords-upload',3578:'passwords-ascii',3603:'emails-upload',3604:'emails-ascii',
        3629:'info-upload',3630:'info-ascii',3655:'cc-upload',3656:'cc-ascii',
        3681:'screen-upload',3682:'screen-ascii'}
FULL_UNITS = ['emails-upload','cc-upload','screen-upload','screen-ascii','info-upload','info-ascii',
              'passwords-upload','passwords-ascii',None,None,None,None,None,'late-one-ascii',
              'late-two-upload','late-two-ascii','dpapi','utf8',None,'decrypt-declaration']


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    profile=(ROOT/'eval/reference_units/gomorrah.atomic-v1.json').read_bytes()
    assert sha(profile)==json.loads((OUT/'gomorrah-atomic-source-check.json').read_bytes())['profile_sha256']
    for name,is_full in [(FULL,True),(NARROW,False)]:
        directory=(ROOT/('runs' if is_full else 'private/report-experiments'))/name
        verify_journal(directory/'events.jsonl')
        raw_bytes=(directory/'report.model-raw.json').read_bytes()
        if is_full:
            audit=json.loads((AUDITS/'gomorrah-operations-v8-full-audit.json').read_bytes())
            checked=canonical(json.loads((directory/'report.private.json').read_bytes())['analysis'])
        else:
            audit=json.loads((AUDITS/(name+'-operation-source-audit.json')).read_bytes())
            checked=(directory/'report.checked.json').read_bytes()
        assert audit['raw_report_sha256']==sha(raw_bytes)
        adjudicated={c['claim_id']:c for c in audit['claims']}
        mapping={'schema_version':1,'sample_sha256':audit['sample_sha256'],'profile_sha256':sha(profile),
                 'raw_report_sha256':sha(raw_bytes),'checked_report_sha256':sha(checked),
                 'reviewer':'source audit of pinned ILSpy code and submitted citations',
                 'method':'An API operation includes its source site, argument roles and asserted result. An incorrect qualifier invalidates that operation. All raw and rejected claims retained.',
                 'claims':[]}
        for claim in json.loads(raw_bytes)['claims']:
            cid=claim['id']
            row=adjudicated[cid]
            unit=FULL_UNITS[int(cid[1:])-1] if is_full else SITE[claim['evidence'][-1]['line']]
            assert (row['label']=='correct')==bool(unit)
            refs=[{k:v for k,v in ref.items() if k!='quote'} for ref in claim['evidence']]
            atom={'start':0,'end':len(claim['text']),'label':row['label'],'reason':row['reason'],
                  'unit_key':unit or 'unsupported-'+cid,'reference_id':unit,'source_references':refs}
            mapping['claims'].append({'claim_id':cid,'atoms':[atom]})
        result=calculate(profile,raw_bytes,checked,mapping)
        dump_json(AUDITS/(name+'-gomorrah-atomic-mapping.json'),mapping)
        dump_json(OUT/(name+'-gomorrah-atomic-score.json'),result)
        print(name, result['raw']['correct'],result['raw']['missed'],result['raw']['precision'],
              result['raw']['recall'],result['raw']['f1'])


if __name__=='__main__':
    main()
