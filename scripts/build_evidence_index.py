"""Build a public-safe index of receipts. No sample bytes or raw IOC snippets."""
import hashlib
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from stealer_agent.journal import canonical,dump_json,utc_now,verify_journal

root=Path(__file__).resolve().parents[1]
def read(relative):
    return json.loads((root/relative).read_text(encoding='utf-8-sig'))
lab=read('evidence/local/lab-verification.json')
final=read('evidence/local/final-validation.json')
injection=read('evidence/local/injection-exposure-audit.json')
checks=[]
for file in sorted((root/'runs').glob('*/events.jsonl')):
    try:
        count=verify_journal(file)
        row={'run_id':file.parent.name,'events':count,'chain_valid':True}
    except Exception as exc:
        row={'run_id':file.parent.name,'chain_valid':False,'error':str(exc)}
    row['journal_sha256']=hashlib.sha256(file.read_bytes()).hexdigest()
    checks.append(row)
presentation=read('private/slides-build/validation-final.json')
result={'created_at':utc_now(),'coursework_final':False,
        'milestone4_technical_evidence':any(r['status'].startswith('completed') and
              r['acceptance']['two_distinct_tools'] and r['acceptance']['model_minimum_met'] for r in final['runs']),
        'source_matches_vm':lab['source_matches_vm'],
        'source_manifest_sha256':hashlib.sha256(canonical(lab['host_source'])).hexdigest(),
        'model':{k:lab['model'][k] for k in ('tag','digest','size_bytes','details')},
        'vm_isolation_checks':lab['health']['isolation']['checks'],
        'vmx_settings':lab['vmx_isolation_settings'],'snapshots':lab['snapshots'],
        'final_runs':final['runs'],'journal_checks':checks,'all_journals_valid':all(c['chain_valid'] for c in checks),
        'injection_qualified':injection['score'],
        'injection_limit':'benign fixture comments only; one Unicode payload not fully extracted; no malicious-to-benign test',
        'slides':{'file':'StealerLab_Buoi4.pptx','sha256':hashlib.sha256((root/'deliverables/StealerLab_Buoi4.pptx').read_bytes()).hexdigest(),
                  'validation_receipt':'private/slides-build/validation-final.json','visually_reviewed_slides':8},
        'quality_metrics':{'precision':None,'recall':None,'f1':None,'hallucination':None,'grounding':None,'verdict_accuracy':None},
        'yara_fixture_holdout':{'tpr':0,'fpr':0,'positive_count':1,'negative_count':2,'run':'yara_f8db42dbd9c5'},
        'scope_notes':['Unit tests/fixture runs are engineering evidence, not malware quality scores.',
                       'Hash chains check consistency, not authenticity against an external signer.',
                       'SLM reviewer is heuristic and has known false rejections.',
                       'Slides retain identified historical runs; final source runs are listed separately.']}
dump_json(root/'deliverables/Buoi4_evidence_index.json',result)
print(json.dumps({'m4_technical':result['milestone4_technical_evidence'],'journals_checked':len(checks),
                  'all_journals_valid':result['all_journals_valid'],'source_matches_vm':result['source_matches_vm']}))
