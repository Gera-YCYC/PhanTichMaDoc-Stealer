import copy
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location('claim_audit', Path(__file__).resolve().parents[1] / 'eval/claim_audit.py')
audit_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit_module)


def inputs():
    raw = json.dumps({'claims': [{'id': 'C1'}, {'id': 'C2'}], 'verdict': 'malicious'}).encode()
    checked = {'claims': [{'id': 'C1'}], 'rejected_claims': [{'claim': {'id': 'C2'}}], 'verdict': 'suspicious'}
    audit = {'raw_report_sha256': hashlib.sha256(raw).hexdigest(), 'run_id': 'inert-unit-test',
             'dataset_origin': 'unit-test-only', 'sample_sha256': 'a' * 64,
             'claims': [{'claim_id': 'C1', 'label': 'correct', 'grounded': True, 'reviewer': 'unit-test',
                         'truth_reference': 'inert', 'reason': 'inert'},
                        {'claim_id': 'C2', 'label': 'unsupported', 'grounded': False, 'reviewer': 'unit-test',
                         'truth_reference': 'inert', 'reason': 'inert'}]}
    return raw, checked, audit


def test_filtered_candidates_cannot_disappear_from_the_primary_denominator():
    result = audit_module.calculate(*inputs())
    assert result['raw']['precision'] == result['raw']['hallucination_rate'] == .5
    assert result['after_filter']['precision'] == 1
    assert result['raw']['recall'] is None and result['raw']['f1'] is None
    assert result['quality_gate_passed'] is False


@pytest.mark.parametrize('mutation', ['hash', 'missing', 'duplicate', 'grounding', 'partition', 'changed_claim'])
def test_invalid_or_incomplete_audit_fails_closed(mutation):
    raw, checked, audit = copy.deepcopy(inputs())
    if mutation == 'hash': raw += b' '
    if mutation == 'missing': audit['claims'].pop()
    if mutation == 'duplicate': audit['claims'].append(audit['claims'][0])
    if mutation == 'grounding': audit['claims'][0]['grounded'] = False
    if mutation == 'partition': checked['rejected_claims'] = []
    if mutation == 'changed_claim': checked['claims'][0]['text'] = 'Rewritten after scoring'
    with pytest.raises(ValueError): audit_module.calculate(raw, checked, audit)
