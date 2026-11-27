"""Fixed entry point for bounded source parsing inside the analysis VM."""
import json
from pathlib import Path
import sys
from .syntax_context import related_contexts
from .operation_facts import extract_operations

if len(sys.argv) != 2:
    raise SystemExit('Expected one trusted snapshot path')
path = Path(sys.argv[1])
if not path.is_absolute() or path.stat().st_size > 5_000_000:
    raise SystemExit('Invalid context snapshot')
request = json.loads(path.read_text(encoding='utf-8'))
result = related_contexts(request['record'], request['anchors'])
try:
    operations = extract_operations(request['record'])
    present = {r['line'] for r in result['lines']} | set(request['anchors'])
    chosen, rows, used = [], {}, 0
    # Prefer a call at the actual search anchor, then dependencies visible in
    # linked context. Imports alone must not use the bounded fact slots first.
    def priority(fact):
        call = fact['ranges'][-1]
        hit = any(call['line'] <= n <= call['end_line'] for n in request['anchors'])
        callee = any(link['ranges'][1]['line'] <= call['line'] and call['end_line'] <= link['ranges'][1]['end_line']
                     for link in result.get('context_links',[]) if len(link['ranges'])>=2)
        distance = min((abs(call['line']-n) for n in request['anchors']), default=0)
        return (not hit, not callee, distance, call['line'])
    for fact in sorted(operations['facts'], key=priority):
        numbers = {n for r in fact['ranges'] for n in range(r['line'],r['end_line']+1)}
        if not present & numbers:
            continue
        extra = [request['record']['lines'][n-1] for n in sorted(numbers)]
        cost = sum(len(r['text'])+50 for r in extra if r['line'] not in rows)
        if used+cost > 4000:
            continue
        chosen.append(fact)
        rows.update({r['line']:r for r in extra})
        used += cost
        if len(chosen)>=4:
            break
    rows.update({r['line']:r for r in result['lines']})
    result.update(lines=[rows[n] for n in sorted(rows)], operation_facts=chosen,
                  operation_backend=operations['backend'])
except Exception as exc:
    result['operation_facts'] = []
    result['operation_status'] = {'status':'unavailable','error_class':type(exc).__name__}
print(json.dumps(result, ensure_ascii=False))
