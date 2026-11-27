"""Freeze agent-reviewed structural labels; never call them human adjudication.

Input is a numeric feature export from pinned VM evidence. IDs below refer to
the recorded 117-candidate collection, not future collections.
"""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    raw = (ROOT/'private/retrieval-candidates.json').read_bytes()
    if hashlib.sha256(raw).hexdigest()!='7a46e889fe824014f22b8b82d2d2a8b6538c8b06acba05f029eff6b76efe1b3e':
        raise ValueError('Candidate bytes changed; annotations must be reviewed again')
    source = json.loads(raw)
    rows = source['rows']
    if len(rows) != 117 or rows[49]['sample'] != 'public_mercurial.bin' or rows[91]['sample'] != 'public_python2024.bin':
        raise ValueError('Reviewed candidate ordering changed; do not reuse annotations')
    # Inspected anchors: executable call/data-reference vs declaration/name/import.
    negative_gomorrah = {21,26,28,29,30,33}
    negative_mercurial = {57,74,83,85,91}
    labels = {i:int(i in (3,4)) for i in range(1,6)}
    labels.update({i:int(i not in negative_gomorrah) for i in range(6,50)})
    labels.update({i:int(i not in negative_mercurial) for i in range(50,92)})
    labels.update({i:int(i == 105) for i in range(92,118)})
    split = {'public_gomorrah.bin':'train', 'public_python2024.bin':'train',
             'public_mercurial.bin':'validation','public_agenttesla.bin':'test'}
    records = []
    for row in rows:
        item = {k:v for k,v in row.items() if k != 'preview'}
        item.update(label=labels[int(row['id'][1:])],split=split[row['sample']],
                    label_origin='agent structural annotation of actual tool-output anchor; not human reviewed')
        records.append(item)
    out=ROOT/'training/corpus/code-reference-v1.json'
    out.parent.mkdir(parents=True,exist_ok=True)
    corpus={'task':'prioritize executable code references over names, imports and declarations; NOT malware classification',
        'feature_version':source['feature_version'],'features':source['features'],
        'candidate_export_sha256':hashlib.sha256(raw).hexdigest(),'human_reviewers':[],
        'split_policy':'sample-disjoint; all samples already part of project development; not an unseen malware benchmark',
        'rows':records}
    out.write_text(json.dumps(corpus,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'dataset':str(out),'records':len(records),'human_reviewed':False}))


if __name__ == '__main__':
    main()
