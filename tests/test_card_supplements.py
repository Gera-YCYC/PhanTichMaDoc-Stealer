import json
import pytest
from jsonschema import Draft202012Validator
from stealer_agent.evidence_cards import CARD_SCHEMA, create_card_report
from stealer_agent.grounding import validate_report
from stealer_agent.journal import Journal

EID='ev_'+'a'*16
DIGEST='b'*64


def test_supplement_schema_keeps_indicator_and_technique_fields_separate():
    validator=Draft202012Validator(CARD_SCHEMA)
    ioc={'kind':'ioc','text':'A static destination.','value':'fixture.invalid','technique_id':''}
    attack={'kind':'attack','text':'Browser credential query.','value':'','technique_id':'T1555.003'}
    for candidate in (ioc,attack):
        assert validator.is_valid({'claims':[],'supplemental_claims':[candidate]})
    assert not validator.is_valid({'claims':[],'supplemental_claims':[ioc,attack]})
    assert not validator.is_valid({'claims':[],'supplemental_claims':[{**ioc,'technique_id':'T1555.003'}]})
    assert not validator.is_valid({'claims':[],'supplemental_claims':[{**attack,'value':'fixture.invalid'}]})


def test_ioc_reviewer_sees_kind_literal_and_original_source(tmp_path):
    evidence={EID:{'tool':'decompile_python','status':'ok','sample_sha256':DIGEST,
                   'line_map':{1:'server = "fixture.invalid"'},'latest_lines':[1]}}
    candidate={'kind':'ioc','text':'The configured hostname is fixture.invalid.','value':'fixture.invalid','technique_id':''}
    replies=iter([{'claims':[],'supplemental_claims':[candidate]}, {'supported':True,'reason':'Exact static literal.'}])
    calls=[]
    def invoke(messages,schema,phase,exposure):
        calls.append((json.loads(messages[-1]['content']),phase))
        return next(replies)
    raw,checked=create_card_report(evidence,DIGEST,invoke,Journal(tmp_path/'run'),max_cards=1)
    assert raw['claims'][0]['kind']=='ioc' and checked['claims']==raw['claims']
    assert checked['verdict']=='inconclusive'
    assert calls[-1][0]['value']=='fixture.invalid' and calls[-1][0]['kind']=='ioc'
    assert calls[-1][0]['technique_id']==''
    assert 'fixture.invalid' in calls[-1][0]['code']


@pytest.mark.parametrize('value',['__PRIVATE_LITERAL_1__','[REDACTED]','[PRIVATE_VALUE]'])
def test_masked_value_is_not_a_real_ioc_even_when_quote_contains_it(value):
    text='server = "'+value+'"'
    claim={'id':'C1','kind':'ioc','text':'A candidate.','value':value,'technique_id':'',
           'evidence':[{'evidence_id':EID,'line':1,'end_line':1,'quote':text}]}
    raw={'verdict':'inconclusive','verdict_claim_ids':[],'claims':[claim],'limitations':[]}
    ev={EID:{'tool':'decompile_python','status':'ok','sample_sha256':DIGEST,'line_map':{1:text}}}
    result=validate_report(raw,ev,DIGEST)
    assert result['claims']==[]
    assert 'ioc_is_redacted_placeholder_not_indicator' in result['rejected_claims'][0]['reasons']
