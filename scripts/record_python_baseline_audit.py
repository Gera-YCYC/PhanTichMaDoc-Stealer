"""Record an explicit source audit; never imply human or lecturer review."""
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from eval.score import calculate
from stealer_agent.journal import dump_json,utc_now


def main():
    run=ROOT/'runs/20261127T154300_0506c3a6'
    raw_path=run/'report.model-raw.json'; raw=json.loads(raw_path.read_text(encoding='utf-8'))
    profile_path=ROOT/'eval/reference_profiles/python2024.static.json'
    profile=json.loads(profile_path.read_text(encoding='utf-8'))
    # These notes were made after reading the actual cited rows and the recovered source.
    notes={
        'C1':'Cites the function heading/path/existence guard, ending before copy/connect/SELECT; does not substantiate database reading.',
        'C2':'Cites cursor.fetchall(), not the decrypt_password call or AES/DPAPI implementation.',
        'C3':'Cites directory checks/creation, not writing extracted results to a file.',
        'C4':'Cites the closing string delimiter in a result-format block, not SMTP/sendmail or dataflow.',
        'C5':'Cites import os; the recovered source audit finds SMTP for the main sending path, not demonstrated requests HTTP transmission.'}
    if {c['id'] for c in raw['claims']}!=set(notes): raise ValueError('Original run claims changed')
    reviewer='automated-source-audit; not human approval, not Qwen self-review'
    reference='eval/reference_profiles/python2024.static.json'
    claims=[{'sample_sha256':profile['sample_sha256'],'claim_key':c['id'],'text':c['text'],
             'label':'unsupported','grounded':False,'reviewer':reviewer,'truth_reference':reference,
             'reason':notes[c['id']],'submitted_citations':[{'evidence_id':r['evidence_id'],'line':r['line']} for r in c['evidence']]}
            for c in raw['claims']]
    claims += [{'sample_sha256':profile['sample_sha256'],'claim_key':'missed-'+f['id'],'text':f['text'],
                'label':'missed','grounded':False,'reviewer':reviewer,'truth_reference':reference+'#'+f['id']}
               for f in profile['facts']]
    data={'created_at':utc_now(),'run_id':run.name,'dataset_origin':'public-development-subset-source-audit',
          'teacher_dataset_complete':False,'human_reviewers':[],
          'report_scope':'raw model claims before filtering; missing facts relative to five-item static profile only',
          'raw_report_sha256':hashlib.sha256(raw_path.read_bytes()).hexdigest(),
          'reference_sha256':hashlib.sha256(profile_path.read_bytes()).hexdigest(),'claims':claims,
          'verdicts':[{'expected':'malicious','predicted':raw['verdict'],'truth_reference':reference}],
          'limits':['Not a full-corpus grade or human adjudication',
                    'Unsupported means submitted evidence does not substantiate the claim; some text describes real capabilities but cites the wrong lines',
                    'Rejected claims remain in the raw score; filtering them does not make hallucination zero']}
    dump_json(ROOT/'eval/adjudications/python2024-qwen25-baseline.json',data)
    score=calculate(data);score['scope']=data['report_scope'];score['human_reviewers']=[]
    applied=json.loads((run/'report.private.json').read_text(encoding='utf-8'))['analysis']
    score['raw_verdict_label']=raw['verdict']
    score['applied_verdict']=applied['verdict']
    score['applied_verdict_accuracy']=float(applied['verdict']==profile['expected_verdict'])
    score['verdict_metric_note']='metrics.verdict_accuracy is the RAW label match only; accepted report is scored separately above'
    dump_json(ROOT/'deliverables/real-demo-evidence/python2024-baseline-score.json',score)
    print(json.dumps(score))


if __name__=='__main__': main()
