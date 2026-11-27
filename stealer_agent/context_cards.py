"""Compose exact retrieved ranges; never infer a flow from a syntax link."""
import hashlib
import json


def linked_cards(evidence, max_cards=4, max_chars=6500):
    cards, seen, targets = [], set(), set()
    for eid, record in evidence.items():
        if record.get('status') != 'ok' or record.get('tool') not in {
                'decompile_dotnet', 'decompile_python', 'decode_python_literals'}:
            continue
        for link in record.get('context_links', []):
            refs = []
            for r in link.get('ranges', []):
                if type(r.get('line')) is not int or type(r.get('end_line')) is not int or not 0 <= r['end_line']-r['line'] < 40:
                    refs = []
                    break
                numbers = range(r['line'], r['end_line']+1)
                if any(n not in record['line_map'] or '[REDACTED-INJECTION]' in record['line_map'][n] for n in numbers):
                    refs = []
                    break
                quote = '\n'.join(record['line_map'][n] for n in numbers)
                if not 4 <= len(quote) <= 4800:
                    refs = []
                    break
                refs.append({'evidence_id': eid, **r, 'quote': quote})
            key = hashlib.sha256(json.dumps(refs, sort_keys=True).encode()).hexdigest()
            target = (eid, refs[1]['line'], refs[1]['end_line']) if len(refs) >= 2 else None
            if not 2 <= len(refs) <= 3 or sum(len(r['quote']) for r in refs) > max_chars or key in seen or target in targets:
                continue
            # A callee-only link can be entirely contained in a caller/callee/
            # dependency card already selected. Keep its focus without spending
            # another scarce card slot on a shorter view of the same source.
            containing = next((c for c in cards if all(any(
                old['evidence_id']==ref['evidence_id'] and old['line']<=ref['line'] and
                old['end_line']>=ref['end_line'] for old in c['references']) for ref in refs)),None)
            if containing:
                if link['call_line'] not in containing['focus_lines']:
                    containing['focus_lines'].append(link['call_line'])
                containing['subsumed_context_count']=containing.get('subsumed_context_count',0)+1
                seen.add(key)
                continue
            seen.add(key)
            targets.add(target)
            cards.append({'tool': record['tool'], 'sample_sha256': record['sample_sha256'],
                          'reference': refs[0], 'references': refs, 'focus_lines': [link['call_line']],
                          'focus_origin': 'syntactic_call_candidate_not_dataflow_proof',
                          'callee_complete': link.get('callee_complete', False)})
            if len(cards) >= max_cards:
                return cards
    return cards
