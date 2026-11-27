"""Mechanical checks for reviewed feature-only SFT data. Does not train."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from stealer_agent.contracts import validate_action
from stealer_agent.security import SECRET

HEX=re.compile(r'[a-f0-9]{64}\Z')


def validate_records(splits):
    if set(splits)!={'train','validation','test'} or any(not rows for rows in splits.values()):
        raise ValueError('Three nonempty reviewed splits are required')
    ids=set()
    owners={key:{} for key in ('sample','family','prompt')}
    summary={}
    for split,rows in splits.items():
        samples=set()
        families=set()
        for row in rows:
            rid=row.get('id')
            sample=row.get('sample_sha256','')
            family=row.get('family_id')
            if not isinstance(rid,str) or not rid.strip() or rid in ids:
                raise ValueError('Missing/duplicate record id')
            ids.add(rid)
            if not isinstance(sample,str) or not HEX.fullmatch(sample) or not isinstance(family,str) or not family.strip():
                raise ValueError('Record needs pinned sample hash and family group')
            review=row.get('review',{})
            reviewers=review.get('reviewers',[])
            if (review.get('approved') is not True or review.get('redacted') is not True or
                review.get('synthetic') is not False or not isinstance(reviewers,list) or
                len({x.strip() for x in reviewers if isinstance(x,str) and x.strip()})<2):
                raise ValueError('Two human reviewers, redaction and non-synthetic provenance are required')
            evidence=row.get('source_evidence',[])
            if not evidence:
                raise ValueError('Source evidence is required')
            for source in evidence:
                start,end=source.get('line_start'),source.get('line_end')
                if (not HEX.fullmatch(source.get('artifact_sha256','')) or
                    type(start) is not int or type(end) is not int or not 1<=start<=end):
                    raise ValueError('Invalid source artifact/line references')
            messages=row.get('prompt_messages',[])
            if (not messages or messages[-1].get('role')!='user' or
                any(m.get('role') not in ('system','user') or not isinstance(m.get('content'),str)
                    or not m['content'].strip() for m in messages)):
                raise ValueError('Expected system/user messages ending in user')
            encoded=json.dumps(row,ensure_ascii=False,sort_keys=True)
            if len(encoded)>100_000:
                raise ValueError('Feature record too large')
            if SECRET.search(encoded) or re.search(r'(?:ghp_|github_pat_)[A-Za-z0-9_]{20,}',encoded):
                raise ValueError('Credential-shaped content; review/redact before training')
            validate_action(row['completion'])
            prompt=hashlib.sha256(json.dumps(messages,ensure_ascii=False,sort_keys=True).encode()).hexdigest()
            for category,value in (('sample',sample),('family',family),('prompt',prompt)):
                previous=owners[category].setdefault(value,split)
                if previous!=split:
                    raise ValueError('Cross-split leakage: '+category)
            samples.add(sample)
            families.add(family)
        summary[split]={'records':len(rows),'samples':len(samples),'families':len(families)}
    return {'status':'mechanical_checks_passed','splits':summary,
            'limits':'Metadata/schema/exact-leakage checks, not proof of human review or semantic correctness'}


def load_and_validate(directory):
    splits={}
    hashes={}
    for split in ('train','validation','test'):
        path=Path(directory)/(split+'.jsonl')
        if not path.is_file():
            raise ValueError('Reviewed corpus missing: '+path.name)
        if path.stat().st_size>100_000_000:
            raise ValueError('Dataset exceeds current bounded loader')
        raw=path.read_bytes()
        hashes[path.name]=hashlib.sha256(raw).hexdigest()
        splits[split]=[json.loads(line) for line in raw.decode('utf-8-sig').splitlines() if line.strip()]
    report=validate_records(splits)
    report['file_sha256']=hashes
    return splits,report


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--data-dir',type=Path,required=True)
    args=parser.parse_args()
    try:
        _,report=load_and_validate(args.data_dir)
        print(json.dumps(report,ensure_ascii=False,indent=2))
    except (ValueError,KeyError,TypeError) as exc:
        print(json.dumps({'status':'not_ready','reason':str(exc),'training_performed':False}))
        raise SystemExit(2)
