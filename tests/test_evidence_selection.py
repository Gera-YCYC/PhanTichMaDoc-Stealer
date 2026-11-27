import json
from stealer_agent.engine import compact_evidence
from stealer_agent.reviewer import direct_metadata_support, review_report
from stealer_agent.journal import Journal


def test_focused_code_survives_later_metadata_and_two_search_groups():
    lines = {i:'first context '+str(i) for i in range(1,51)}
    lines.update({i:'second context '+str(i) for i in range(500,551)})
    evidence = {'ev_'+'a'*16:{'tool':'decompile_dotnet','status':'ok','line_map':lines,
                 'latest_lines':[1,2,3],'focus_groups':[list(range(10,20)),list(range(510,520))]}}
    records = [json.loads(s) for s in compact_evidence(evidence,4500,3500).splitlines()]
    selected = [r['line'] for r in records[0]['lines']]
    assert 10 in selected and 510 in selected
    assert len(compact_evidence(evidence,4500,3500)) <= 4500


def test_exact_metadata_does_not_depend_on_slm_and_cannot_prove_benign(tmp_path):
    eid='ev_'+'a'*16
    line='  "format": "PE .NET",'
    evidence={eid:{'tool':'identify','status':'ok','line_map':{5:line}}}
    claim={'id':'C1','kind':'observation','text':'The file is a .NET PE.',
           'evidence':[{'evidence_id':eid,'line':5,'quote':line}]}
    report={'claims':[claim],'verdict':'inconclusive','verdict_claim_ids':[],
            'rejected_claims':[],'validation_notes':[]}
    checked,metrics=review_report(report,None,Journal(tmp_path/'run'),evidence=evidence)
    assert checked['claims']==[claim] and metrics is None
    for text in ('The file is a benign .NET PE.','The file steals .NET passwords.'):
        assert not direct_metadata_support({**claim,'text':text}, evidence)
    assert not direct_metadata_support(claim, {eid:{**evidence[eid],'tool':'strings'}})
    assert not direct_metadata_support({**claim,'kind':'behavior'}, evidence)


def test_ioc_candidate_cannot_substantiate_behavior():
    from stealer_agent.grounding import validate_report
    eid='ev_'+'a'*16
    quote='https://fixture.invalid candidate_not_confirmed_exfiltration'
    evidence={eid:{'tool':'extract_ioc','status':'ok','sample_sha256':'b'*64,'line_map':{1:quote}}}
    report={'verdict':'malicious','verdict_claim_ids':['C1'], 'limitations':[], 'claims':[
        {'id':'C1','kind':'behavior','text':'The code exfiltrates data.','value':'','technique_id':'',
         'evidence':[{'evidence_id':eid,'line':1,'quote':quote}]}]}
    checked=validate_report(report,evidence,'b'*64)
    assert not checked['claims'] and checked['verdict']=='inconclusive'


def test_short_citation_ids_and_typed_claim_grammar():
    from stealer_agent.contracts import decision_schema
    from jsonschema import Draft202012Validator
    schema=decision_schema('x.bin',[],[],True,citation_options=[{
        'evidence_id':'ev_'+'a'*16,'line':5,'quote':'format','citation_id':'S1:5'}])
    action={'action':'finish','arguments':{},'reason':'Report','report':{
        'verdict':'inconclusive','verdict_claim_ids':[],'limitations':[], 'claims':[
            {'id':'C1','kind':'observation','text':'Observed format','value':'','technique_id':'','evidence':['S1:5']} ]}}
    assert Draft202012Validator(schema).is_valid(action)
    action['report']['claims'][0]['technique_id']='T1041'
    assert not Draft202012Validator(schema).is_valid(action)
