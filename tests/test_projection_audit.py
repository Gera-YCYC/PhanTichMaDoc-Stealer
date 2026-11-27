import hashlib
import pytest
from eval.projection_audit import calculate
from stealer_agent.journal import canonical


def events(mask):
    text='password = "INERT-ONLY-audit"'
    messages=[{'role':'user','content':'[WITHHELD]' if mask else text}]
    return [{'event':'observation','raw':{'lines':[{'text':text}]},'model_visible':{}},
            {'event':'model_request','messages':messages,'messages_sha256':hashlib.sha256(canonical(messages)).hexdigest()},
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
