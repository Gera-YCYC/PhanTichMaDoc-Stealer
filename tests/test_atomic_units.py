import copy
import json

import pytest

from eval.atomic_units import calculate, fingerprint


def setup():
    profile = {'schema_version': 1, 'profile_id': 'inert/1', 'sample_sha256': 'a' * 64,
               'scope': 'Inert arithmetic fixture, not malware accuracy', 'reference_method': 'source audit',
               'source_references': ['inert source'], 'model_self_review_used_as_truth': False,
               'scoring_ready': True, 'units': [{'id': key, 'kind': 'behavior', 'proposition': text,
                    'source_references': ['inert source']} for key, text in [('U1','reads'),('U2','writes'),('U3','sends')]]}
    claims = [{'id': 'C' + str(i), 'kind': 'behavior', 'text': text} for i, text in
              enumerate(['reads', 'reads', 'writes; invents'], 1)]
    raw = {'claims': claims}
    checked = {'claims': claims[:2], 'rejected_claims': [{'claim': claims[2]}]}
    mapping = {'schema_version': 1, 'sample_sha256': 'a' * 64, 'reviewer': 'test fixture', 'method': 'explicit fixture labels',
               'claims': [{'claim_id': c['id'], 'atoms': []} for c in claims]}
    for i in range(2):
        mapping['claims'][i]['atoms'] = [atom(0, 5, 'correct', 'U1', 'U1')]
    mapping['claims'][2]['atoms'] = [atom(0, 6, 'correct', 'U2', 'U2'), atom(8, 15, 'unsupported', 'X1', None)]
    return profile, raw, checked, mapping


def atom(start, end, label, key, ref):
    return {'start': start, 'end': end, 'label': label, 'unit_key': key, 'reference_id': ref,
            'reason': 'Explicit inert source judgment', 'source_references': ['inert source']}


def run(profile, raw, checked, mapping):
    data = [json.dumps(x).encode() for x in (profile, raw, checked)]
    mapping = {**mapping, **{k:fingerprint(v) for k,v in zip(
        ('profile_sha256','raw_report_sha256','checked_report_sha256'), data)}}
    return calculate(*data, mapping)


def test_same_atomic_denominators_duplicates_and_rejected_are_preserved():
    result = run(*setup())
    assert result['raw']['prediction_atoms'] == 4
    assert result['raw']['duplicate_atoms'] == 1
    assert result['raw']['correct'] == 2 and result['raw']['unsupported'] == 1
    assert result['raw']['precision'] == result['raw']['recall'] == result['raw']['f1'] == 2/3
    assert result['raw']['missed_reference_ids'] == ['U3']
    assert result['after_filter']['recall'] == 1/3
    assert result['after_filter']['precision'] == 1
    assert result['after_filter']['f1'] == .5
    assert result['full_coursework_quality_gate_passed'] is False
    assert result['by_kind']['ioc']['raw']['recall'] is None


@pytest.mark.parametrize('error', ['missing_claim', 'missing_atom', 'overlap', 'uncovered', 'tail', 'wrong_kind',
                                 'invented_credit', 'outside_reference', 'conflicting_duplicate', 'changed_checked'])
def test_mappings_cannot_hide_errors_or_gain_duplicate_credit(error):
    p,r,c,m = setup()
    if error == 'missing_claim': m['claims'].pop()
    if error == 'missing_atom': m['claims'][2]['atoms'] = []
    if error == 'overlap': m['claims'][2]['atoms'][1]['start'] = 5
    if error == 'uncovered': m['claims'][2]['atoms'][0]['start'] = 2
    if error == 'tail': m['claims'][2]['atoms'][1]['end'] = 13
    if error == 'wrong_kind': p['units'][0]['kind'] = 'ioc'
    if error == 'invented_credit': m['claims'][2]['atoms'][1]['reference_id'] = 'U3'
    if error == 'outside_reference': m['claims'][0]['atoms'][0]['reference_id'] = 'UNKNOWN'
    if error == 'conflicting_duplicate': m['claims'][2]['atoms'][1]['unit_key'] = 'U1'
    if error == 'changed_checked':
        c = copy.deepcopy(c)
        c['claims'][0]['text'] = 'changed'
    with pytest.raises(ValueError): run(p,r,c,m)


def test_unready_or_empty_prediction_is_not_perfect_score():
    p,r,c,m = setup()
    p['scoring_ready'] = False
    assert run(p,r,c,m)['raw']['f1'] is None
    p['scoring_ready'] = True
    r['claims'] = []; c = {'claims': [], 'rejected_claims': []}; m['claims'] = []
    result = run(p,r,c,m)
    assert result['raw']['precision'] is None and result['raw']['recall'] == 0
    assert result['raw']['f1'] is None and result['raw']['missed'] == 3


def test_all_three_fingerprints_are_bound():
    p,r,c,m = setup()
    data = [json.dumps(x).encode() for x in (p,r,c)]
    for wrong in ('profile_sha256','raw_report_sha256','checked_report_sha256'):
        fingerprints = dict(zip(('profile_sha256','raw_report_sha256','checked_report_sha256'), map(fingerprint,data)))
        fingerprints[wrong] = 'b' * 64
        with pytest.raises(ValueError): calculate(*data, {**m, **fingerprints})


def test_self_review_cannot_be_labeled_reference_truth():
    p,r,c,m = setup()
    p['model_self_review_used_as_truth'] = True
    with pytest.raises(ValueError): run(p,r,c,m)


def test_annotation_cannot_override_the_rejected_partition():
    p,r,c,m = setup()
    m['claims'][2]['atoms'][0]['included_after_filter'] = True
    with pytest.raises(ValueError): run(p,r,c,m)
