import hashlib
import json
import pytest
from eval.reference_coverage import calculate


def case():
    raw=json.dumps({'claims':[{'id':'C1'},{'id':'C2'},{'id':'C3'}]}).encode()
    profile=json.dumps({'profile_id':'inert/1','sample_sha256':'a'*64,'units':[{'id':'U1'},{'id':'U2'}]}).encode()
    audit=json.dumps({'run_id':'inert','sample_sha256':'a'*64,'raw_report_sha256':hashlib.sha256(raw).hexdigest(),
                     'claims':[{'claim_id':'C1','label':'correct'},{'claim_id':'C2','label':'correct'},
                               {'claim_id':'C3','label':'unsupported'}]}).encode()
    checked={'claims':[{'id':'C2'},{'id':'C3'}],'rejected_claims':[{'claim':{'id':'C1'}}]}
    mapping={'profile_sha256':hashlib.sha256(profile).hexdigest(),'audit_sha256':hashlib.sha256(audit).hexdigest(),
             'raw_report_sha256':hashlib.sha256(raw).hexdigest(),'units':[
             {'unit_id':'U1','matched_claim_ids':['C1','C2'],'reason':'Two correct descriptions of one unit.'},
             {'unit_id':'U2','matched_claim_ids':[],'reason':'No supported description.'}]}
    return profile,audit,raw,checked,mapping


def test_duplicate_claims_never_inflate_unit_coverage():
    result=calculate(*case())
    assert result['raw_covered_units']==1 and result['raw_reference_coverage']==0.5
    assert result['filtered_reference_coverage']==0.5 and result['f1'] is None


def test_rejected_correct_claim_remains_in_primary_coverage():
    args=list(case());args[-1]['units'][0]['matched_claim_ids']=['C1']
    result=calculate(*args)
    assert result['raw_reference_coverage']==0.5 and result['filtered_reference_coverage']==0


def test_changed_checked_claim_or_duplicate_cannot_change_coverage():
    args=list(case());args[3]['claims'][0]['text']='changed after audit'
    with pytest.raises(ValueError,match='unchanged'):calculate(*args)
    args=list(case());args[3]['claims'].append(dict(args[3]['claims'][0]))
    with pytest.raises(ValueError,match='unchanged'):calculate(*args)


@pytest.mark.parametrize('mutation',[
    lambda m:m.update(profile_sha256='f'*64),
    lambda m:m['units'].pop(),
    lambda m:m['units'].append(dict(m['units'][0])),
    lambda m:m['units'][0].update(matched_claim_ids=['C3']),
    lambda m:m['units'][0].update(matched_claim_ids=['unknown']),
])
def test_incomplete_tampered_or_unsupported_mapping_is_rejected(mutation):
    args=list(case());mutation(args[-1])
    with pytest.raises(ValueError):calculate(*args)
