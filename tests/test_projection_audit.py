import hashlib
import pytest
from eval.projection_audit import calculate
from stealer_agent.journal import canonical


def events(mask):
    text='password = "INERT-ONLY-audit"'
    messages=[{'role':'user','content':'[WITHHELD]' if mask else text}]
    return [{'event':'observation','raw':{'lines':[{'text':text}]},'model_visible':{}},
            {'event':'model_request','messages':messages,'messages_sha256':hashlib.sha256(canonical(messages)).hexdigest(),
             'schema':{},'schema_sha256':hashlib.sha256(canonical({})).hexdigest()},
            {'event':'model_response','action':{'text':'No literal'}}]


@pytest.mark.parametrize('mask',[True,False])
def test_known_literal_gate_distinguishes_input_projection(mask):
    result=calculate(events(mask),{'claims':[]})
    assert result['recognized_literal_request_gate_passed'] is mask
    assert result['requests_with_detected_literal'] == int(not mask)
    assert 'INERT-ONLY-audit' not in str(result)


def test_request_tampering_is_not_accepted_as_a_clean_result():
    values=events(True)
    values[1]['messages'][0]['content']='changed'
    with pytest.raises(ValueError,match='hash mismatch'):
        calculate(values,{'claims':[]})


def test_schema_literal_is_an_exposure_even_if_messages_are_clean():
    values=events(True)
    values[1]['schema']={'enum':['INERT-ONLY-audit']}
    values[1]['schema_sha256']=hashlib.sha256(canonical(values[1]['schema'])).hexdigest()
    result=calculate(values,{'claims':[]})
    assert result['schemas_with_detected_literal']==1
    assert result['recognized_literal_request_gate_passed'] is False


def test_legacy_hash_only_schema_is_not_a_full_request_pass():
    values=events(True)
    values[1].pop('schema')
    assert calculate(values,{'claims':[]})['recognized_literal_request_gate_passed'] is None


def test_incomplete_run_audits_requests_without_inventing_report_results():
    result=calculate(events(True))
    assert result['recognized_literal_request_gate_passed'] is True
    assert result['raw_report_available'] is False
    assert result['raw_claim_prose_with_detected_literal'] is None
    assert result['raw_report_including_citations_contains_detected_literal'] is None


def test_no_detected_literal_is_unevaluable_not_a_privacy_pass():
    values=events(True)
    values[0]['raw']['lines'][0]['text']='ordinary_call()'
    result=calculate(values,{'claims':[]})
    assert result['exposure_evaluation_status']=='no_detected_literals'
    assert result['eligible_detected_literal_count']==0
    assert result['recognized_literal_evidence_gate_passed'] is None
    assert result['recognized_literal_request_gate_passed'] is None
