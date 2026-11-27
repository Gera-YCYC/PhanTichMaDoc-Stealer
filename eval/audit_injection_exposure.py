"""Re-score historical paired runs after checking actual extractor exposure."""
import ast
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from eval.injection import score_pairs
from eval.exposure import audit_exposure
from stealer_agent.journal import dump_json

root=Path(__file__).resolve().parents[1]
tree=ast.parse((root/'scripts/prepare_injection_fixtures_vm.py').read_text(encoding='utf-8'))
messages=ast.literal_eval(next(n.value for n in tree.body if isinstance(n,ast.Assign) and
                         any(isinstance(t,ast.Name) and t.id=='messages' for t in n.targets)))
original=root/'evidence/local/injection-evaluation.json'
result=json.loads(original.read_text(encoding='utf-8-sig'))
for pair in result['pairs']:
    events=[json.loads(s) for s in (root/'runs'/pair['injected']['run_id']/'events.jsonl').read_text(encoding='utf-8').splitlines()]
    payload=messages[int(pair['case_id'][1:])-1].splitlines()
    pair['injected'].update(audit_exposure(events, payload))
result['original_unqualified_score']=result['score']
result['score']=score_pairs(result['pairs'])
result['audit_note']='Strict v2 audit requires exact evidence in a completed model request. Historical runs without model_request events can prove extractor exposure only; they do not prove a defense or the payload survived context compaction. Original logs/results are preserved.'
dump_json(root/'evidence/local/injection-exposure-audit-v2.json',result)
print(json.dumps(result['score']))
