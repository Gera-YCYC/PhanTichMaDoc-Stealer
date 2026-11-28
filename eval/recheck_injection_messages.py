"""Re-audit historical validation runs using exact request messages and paired responses."""
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from eval.exposure import audit_exposure
from eval.injection import score_pairs
from stealer_agent.journal import dump_json, verify_journal


def main():
    folder=ROOT/'deliverables/real-demo-evidence'
    path=ROOT/'evidence/local/injection-manifest-v2.json'
    manifest=json.loads(path.read_bytes().decode('utf-8-sig'))
    cases={case['case_id']:case for case in manifest['pairs']}
    manifest_sha=hashlib.sha256(path.read_bytes()).hexdigest()
    output=[]
    for name in ('injection-disabled-20261127T143339477574Z','injection-P06-enabled-corrected','injection-regression-rescored'):
        receipt=json.loads((folder/(name+'.json')).read_bytes())
        if receipt.get('manifest_sha256',manifest_sha) != manifest_sha:
            raise ValueError('Historical manifest changed')
        rows=[]
        for pair in receipt['pairs']:
            case=cases[pair['case_id']]
            pair=dict(pair,attack_target=case['attack_target'])
            for arm in ('control','injected'):
                rp=ROOT/'runs'/pair[arm]['run_id']
                journal=rp/'events.jsonl'
                verify_journal(journal)
                events=[json.loads(l) for l in journal.read_bytes().splitlines()]
                result=events[-1]['result']
                if (result['sample_sha256'] != case[arm]['sha256'] or result['sample']!=case[arm]['sample']
                        or events[-1]['event']!='run_finished'):
                    raise ValueError('Reference and actually processed sample differ')
                if arm=='injected':
                    pair[arm]={**pair[arm],**audit_exposure(events,case['payload_lines'])}
            rows.append(pair)
        output.append({'source_receipt':name,'guard_enabled':receipt['guard_enabled'],
                       'historical_eligible':receipt['score']['eligible_pairs'],'strict':score_pairs(rows),
                       'runs':[{'case':p['case_id'],'injected_run':p['injected']['run_id'],
                                'audit_status':p['injected']['audit_status']} for p in rows]})
    dump_json(folder/'injection-exact-message-recheck.json',{'manifest_sha256':manifest_sha,'results':output,
              'scope':'Each historical batch is independent. Missing message bytes cannot prove delivery of a specific input.'})
    print([(item['source_receipt'],item['strict']['eligible_pairs']) for item in output])


if __name__=='__main__':
    main()
