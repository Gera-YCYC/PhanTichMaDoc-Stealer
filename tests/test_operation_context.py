import copy
import json
from vm_tools.evidence import EvidenceStore
from vm_tools.operation_facts import extract_operations
from stealer_agent.operation_context import enrich_card, intersecting_operations, valid_operations
from stealer_agent.context_cards import linked_cards
from stealer_agent.evidence_cards import create_card_report
from stealer_agent.journal import Journal


def data(tmp_path):
    text='import smtplib\n\ndef sender(host, sender, recipient, message):\n    client = smtplib.SMTP(host)\n    client.sendmail(sender, recipient, message)\n'
    store=EvidenceStore(tmp_path/'ev')
    page=store.add(sample='inert.bin',sample_sha256='b'*64,tool='decompile_python',backend='inert-fixture',text=text)
    record=store.get(page['evidence_id'],'b'*64)
    record['operation_facts']=extract_operations(record)['facts']
    record['line_map']={r['line']:r['text'] for r in record['lines']}
    ref={'evidence_id':record['evidence_id'],'line':3,'end_line':5,'quote':'\n'.join(record['line_map'][n] for n in range(3,6))}
    card={'reference':ref,'tool':'decompile_python','focus_lines':[5],'focus_origin':'inert-fixture'}
    return {record['evidence_id']:record},card


def test_binding_rows_are_added_before_a_fact_reaches_the_model(tmp_path):
    evidence,card=data(tmp_path)
    out=enrich_card(card,evidence)
    assert len(out['operations'])==1
    assert out['references'][-1]['quote']=='import smtplib'
    assert 'operations' not in card


def test_forged_hash_wrong_sample_missing_binding_and_hidden_rows_are_rejected(tmp_path):
    evidence,card=data(tmp_path)
    for mutation in ('hash','sample','missing','hidden'):
        changed=copy.deepcopy(evidence)
        record=next(iter(changed.values()))
        if mutation=='hash': record['operation_facts'][0]['inputs']['recipient_expression']='invented'
        if mutation=='sample': record['sample_sha256']='c'*64
        if mutation=='missing': record['line_map'].pop(1)
        if mutation=='hidden': record['line_map'][1]='[REDACTED-INJECTION]'
        assert enrich_card(card,changed)['operations']==[]


def test_budget_does_not_keep_a_fact_without_its_import_citation(tmp_path):
    evidence,card=data(tmp_path)
    out=enrich_card(card,evidence,max_chars=len(card['reference']['quote']))
    assert out['operations']==[] and len(out['references'])==1


def test_shared_import_alone_does_not_match_an_operation(tmp_path):
    evidence,card=data(tmp_path)
    card['reference'].update(line=1,end_line=1,quote='import smtplib')
    assert intersecting_operations(card,evidence)==[]


def test_late_full_callee_displaces_early_small_helper(tmp_path):
    evidence,_=data(tmp_path)
    record=next(iter(evidence.values()))
    record['context_links']=[
        {'call_line':3,'ranges':[{'line':1,'end_line':1},{'line':3,'end_line':3}]},
        {'call_line':5,'ranges':[{'line':3,'end_line':5},{'line':1,'end_line':1}]},
    ]
    chosen=linked_cards(evidence,max_cards=1)
    assert chosen[0]['reference']['end_line']==5
    assert {3,5} <= set(chosen[0]['focus_lines'])


def test_generator_and_reviewer_receive_same_bounded_operations_and_binding_source(tmp_path):
    evidence,_=data(tmp_path)
    record=next(iter(evidence.values()))
    record['latest_lines']=[4,5]
    replies=iter([{'claims':[{'kind':'observation','text':'The code has an SMTP sendmail call.'}]},
                  {'reason':'The call is visible.','supported':True}])
    calls=[]
    def invoke(messages,schema,phase,exposure):
        calls.append((json.loads(messages[-1]['content']),exposure))
        return next(replies)
    raw,checked=create_card_report(evidence,'b'*64,invoke,Journal(tmp_path/'run'),max_cards=1)
    assert len(calls)==2
    assert calls[0][0]['parser_operations']==calls[1][0]['parser_operations']
    assert calls[0][0]['parser_operations'][0]['operation']=='smtp_send'
    assert 'import smtplib' in calls[0][0]['code']
    assert calls[0][1]==calls[1][1]
    assert checked['report_method']=='evidence-cards/8'
