"""Check host card selection on captured fresh VM HTTP responses, without SLM."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from stealer_agent.security import guard_observation
from stealer_agent.model_projection import ModelEvidenceView
from stealer_agent.evidence_cards import select_cards
from stealer_agent.operation_context import model_operations
from stealer_agent.journal import dump_json,utc_now,canonical


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('responses',type=Path)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    groups,views,files={},{},[]
    for path in sorted(args.responses.glob('*.json')):
        if '-prepare-' in path.name:
            continue
        raw=json.loads(path.read_text(encoding='utf-8'))
        if raw.get('tool') not in {'decompile_dotnet','decode_python_literals'} or raw.get('status')!='ok':
            continue
        sample=raw['sample_sha256']
        view=views.setdefault(sample,ModelEvidenceView())
        clean=view.observation(guard_observation(raw)[0])
        evidence=groups.setdefault(sample,{})
        record=evidence.setdefault(clean['evidence_id'],{**clean,'line_map':{},'context_links':[],'operation_facts':[]})
        record['line_map'].update({r['line']:r['text'] for r in clean['lines']})
        record.setdefault('line_metadata',{}).update({r['line']:{'source_line':r.get('source_line')} for r in clean['lines']})
        record['latest_lines']=[r['line'] for r in clean['lines']]
        for key in ('context_links','operation_facts'):
            for item in clean.get(key,[]):
                if item not in record[key]: record[key].append(item)
        record.setdefault('focus_groups',[]).extend([[g['anchor_line'],*g['lines']] for g in clean.get('search_groups',[])])
        view.refresh(evidence)
        files.append({'filename':path.name,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
    rows=[]
    for sample,evidence in groups.items():
        cards=select_cards(evidence)
        ops={f['operation'] for card in cards for f in card.get('operations',[])}
        tool=next(iter(evidence.values()))['tool']
        expected={'aes_gcm_decrypt','sql_select','smtp_send','archive_create'} if tool=='decode_python_literals' else {'file_upload','response_text_decode'}
        assert expected<=ops, (tool,expected-ops)
        for card in cards:
            for fact in card.get('operations',[]):
                for span in fact['ranges']:
                    assert any(ref['evidence_id']==fact['evidence_id'] and ref['line']<=span['line'] and
                               span['end_line']<=ref['end_line'] for ref in card['references'])
        rows.append({'sample_sha256':sample,'tool':tool,'card_count':len(cards),'operations':sorted(ops),
                     'cards':[{'ranges':[{k:r[k] for k in ('evidence_id','line','end_line')} for r in c['references']],
                               'operation_ids':[f['fact_id'] for f in c.get('operations',[])],
                               'operation_types':[f['operation'] for f in c.get('operations',[])]} for c in cards],
                     'all_operations_include_binding_ranges':True})
    assert len(rows)==2
    receipt={'created_at':utc_now(),'kind':'host-card-contract-check-on-real-VM-responses-not-SLM-demo',
             'source_responses':files,'cases':rows,
             'limits':['Parser facts and card coverage only; no automatic accuracy or verdict grade.',
                       'Source text, literal arguments and credentials excluded.']}
    dump_json(args.output,receipt)
    print(json.dumps({'receipt':str(args.output),'cases':len(rows),'operations':[r['operations'] for r in rows]}))


if __name__=='__main__':
    main()
