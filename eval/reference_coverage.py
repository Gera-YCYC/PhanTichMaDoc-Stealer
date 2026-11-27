"""Measure coverage of declared source units from an explicit full mapping.

This does not infer labels, normalize model sentences or calculate mixed-unit F1.
"""
import argparse
import hashlib
import json
from pathlib import Path


def calculate(profile_bytes, audit_bytes, raw_bytes, checked, mapping):
    for key,data in [('profile_sha256',profile_bytes),('audit_sha256',audit_bytes),('raw_report_sha256',raw_bytes)]:
        if mapping.get(key)!=hashlib.sha256(data).hexdigest():
            raise ValueError('Mapping fingerprint mismatch: '+key)
    profile,audit,raw=map(json.loads,(profile_bytes,audit_bytes,raw_bytes))
    if audit['raw_report_sha256']!=mapping['raw_report_sha256'] or audit['sample_sha256']!=profile['sample_sha256']:
        raise ValueError('Sample/report mismatch')
    raw_ids={c['id'] for c in raw['claims']}
    labels={c['claim_id']:c['label'] for c in audit['claims']}
    if set(labels)!=raw_ids or len(labels)!=len(audit['claims']) or len(raw_ids)!=len(raw['claims']):
        raise ValueError('Need one audited label for every raw claim')
    if not set(labels.values()) <= {'correct','incorrect','unsupported'}:
        raise ValueError('Unknown source-audit label')
    units={u['id'] for u in profile['units']}
    entries={e['unit_id']:e for e in mapping['units']}
    if not units or len(units)!=len(profile['units']) or set(entries)!=units or len(entries)!=len(mapping['units']):
        raise ValueError('Mapping must cover each reference unit exactly once')
    accepted={c['id'] for c in checked['claims']}
    rejected={r['claim']['id'] for r in checked['rejected_claims']}
    if accepted & rejected or accepted | rejected != raw_ids:
        raise ValueError('Checked report must partition all raw claims')
    originals={c['id']:c for c in raw['claims']}
    checked_claims=checked['claims']+[r['claim'] for r in checked['rejected_claims']]
    if len(checked_claims)!=len(raw['claims']) or any(c!=originals[c['id']] for c in checked_claims):
        raise ValueError('Checked report must preserve every raw candidate unchanged')
    rows=[]
    for unit_id,entry in entries.items():
        ids=entry['matched_claim_ids']
        if not isinstance(ids,list) or len(ids)!=len(set(ids)) or not entry.get('reason'):
            raise ValueError('Unique explicit matches and rationale required')
        if any(labels.get(cid)!='correct' for cid in ids):
            raise ValueError('Incorrect or unsupported claims cannot cover a unit')
        rows.append({'unit_id':unit_id,'matched_claim_ids':ids,'covered_in_raw':bool(ids),
                     'covered_after_filter':bool(set(ids)&accepted)})
    raw_covered=sum(row['covered_in_raw'] for row in rows)
    kept_covered=sum(row['covered_after_filter'] for row in rows)
    return {'profile_id':profile['profile_id'],'sample_sha256':profile['sample_sha256'],
            'run_id':audit['run_id'],'profile_sha256':mapping['profile_sha256'],
            'audit_sha256':mapping['audit_sha256'],'raw_report_sha256':mapping['raw_report_sha256'],
            'reference_units':len(units),'raw_covered_units':raw_covered,'raw_missed_units':len(units)-raw_covered,
            'raw_reference_coverage':raw_covered/len(units),'filtered_covered_units':kept_covered,
            'filtered_reference_coverage':kept_covered/len(units),'units':rows,'f1':None,
            'full_coursework_quality_gate_passed':False,
            'limits':['Coverage of the declared development subset, not full-corpus recall.',
                      'Explicit source-audit mapping is not independently human-approved or inferred by this script.',
                      'Duplicate claims cover a reference unit only once; rejected correct claims remain in raw coverage.',
                      'Raw-sentence precision and reference-unit coverage use different denominators; no F1 is calculated.']}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile',type=Path,required=True)
    parser.add_argument('--audit',type=Path,required=True)
    parser.add_argument('--run',type=Path,required=True)
    parser.add_argument('--mapping',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    final=json.loads((args.run/'report.private.json').read_text(encoding='utf-8'))['analysis']
    result=calculate(args.profile.read_bytes(),args.audit.read_bytes(),
                     (args.run/'report.model-raw.json').read_bytes(),final,json.loads(args.mapping.read_bytes()))
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:result[k] for k in ('run_id','reference_units','raw_covered_units',
                                         'raw_reference_coverage','filtered_reference_coverage','f1')}))


if __name__=='__main__':
    main()
