"""Attach bounded parser facts only with all their already-retrieved source rows.

Integrity/binding metadata is useful context, not semantic approval of SLM prose.
No source is fetched here and no call graph or dataflow is inferred.
"""
import copy
import hashlib
from .journal import canonical

OPERATIONS = {'database_open','sql_select','smtp_send','archive_create',
              'file_upload','response_text_decode','aes_gcm_decrypt'}
BLOCKED = ('[REDACTED-INJECTION]', '[REDACTED-PRIVATE-FRAGMENT]')


def valid_operations(record):
    facts=[]
    for fact in record.get('operation_facts',[])[:100]:
        if fact.get('operation') not in OPERATIONS or fact.get('backend') not in {'static-operation-facts/2','static-operation-facts/3'}:
            continue
        if any(fact.get(key)!=record.get(key) for key in ('evidence_id','sample_sha256','output_sha256')):
            continue
        body={k:v for k,v in fact.items() if k!='fact_id'}
        if fact.get('fact_id')!='op_'+hashlib.sha256(canonical(body)).hexdigest()[:16]:
            continue
        ranges=fact.get('ranges',[])
        if not 1<=len(ranges)<=6 or any(type(r.get('line')) is not int or type(r.get('end_line')) is not int or
                not 1<=r['line']<=r['end_line'] or r['end_line']-r['line']>=40 for r in ranges):
            continue
        rows=record.get('line_map',{})
        if any(n not in rows or any(marker in rows[n] for marker in BLOCKED)
               for r in ranges for n in range(r['line'],r['end_line']+1)):
            continue
        if fact not in facts:
            facts.append(fact)
    return facts


def intersecting_operations(card, evidence):
    refs=card.get('references',[card['reference']])
    result=[]
    for eid in dict.fromkeys(ref['evidence_id'] for ref in refs):
        record=evidence.get(eid,{})
        for fact in valid_operations(record):
            # The final range is the call, earlier ranges establish its binding.
            # A shared import does not make every fact relevant to this card.
            call=fact['ranges'][-1]
            if any(ref['evidence_id']==eid and ref['line']<=call['line'] and call['end_line']<=ref['end_line'] for ref in refs):
                result.append(fact)
    return result


def enrich_card(card, evidence, *, max_chars=4600, max_facts=3):
    result=copy.deepcopy(card)
    refs=result.get('references',[result['reference']])
    chosen=[]
    for fact in intersecting_operations(card,evidence):
        proposed=copy.deepcopy(refs)
        record=evidence[fact['evidence_id']]
        for span in fact['ranges']:
            if any(ref['evidence_id']==fact['evidence_id'] and ref['line']<=span['line'] and span['end_line']<=ref['end_line'] for ref in proposed):
                continue
            quote='\n'.join(record['line_map'][n] for n in range(span['line'],span['end_line']+1))
            if not 4<=len(quote)<=4800:
                break
            proposed.append({'evidence_id':fact['evidence_id'],**span,'quote':quote})
        else:
            if len(proposed)<=6 and sum(len(r['quote']) for r in proposed)<=max_chars:
                refs=proposed
                chosen.append(copy.deepcopy(fact))
        if len(chosen)>=max_facts:
            break
    result['references']=refs
    result['operations']=chosen
    return result


def model_operations(card):
    # The original hashes/binding details stay in the journal. Keep the prompt
    # compact enough that source statements are not displaced by metadata.
    return [{k:fact[k] for k in ('fact_id','operation','api','inputs','result','ranges')}
            for fact in card.get('operations',[])]
