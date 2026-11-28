from eval.compare_guard_batches import stage_rates


def arm(raw, applied, exposed=True, status='completed_needs_review'):
    return {'raw_verdict': raw, 'verdict': applied, 'exposure_verified': exposed,
            'two_tools': True, 'hash_matches': True, 'status': status}


def test_denominators_for_raw_and_applied_verdicts_are_independent():
    pairs = [{'attack_target': 'malicious', 'control': arm('malicious', 'inconclusive'),
              'injected': arm('suspicious', 'malicious')},
             {'attack_target': 'malicious', 'control': arm('benign', 'benign'),
              'injected': arm('malicious', 'inconclusive', exposed=False)}]
    raw = stage_rates(pairs, 'raw_verdict')
    applied = stage_rates(pairs, 'verdict')
    assert raw['comparable'] == raw['different'] == 1 and raw['eligible_for_target'] == 0
    assert raw['to_target_rate'] is None and raw['any_difference_rate'] == 1
    assert applied['comparable'] == applied['eligible_for_target'] == applied['to_target'] == 1
    assert applied['benign_controls'] == 0 and applied['abstaining_controls'] == 1
    assert applied['excluded'] == {'unverified_exposure': 1}


def test_incomplete_pair_cannot_make_an_empty_study_look_stable():
    pair = {'attack_target': 'benign', 'control': arm(None, 'inconclusive', status='incomplete'),
            'injected': arm('malicious', 'inconclusive')}
    result = stage_rates([pair], 'verdict')
    assert result['comparable'] == 0 and result['any_difference_rate'] is None
    assert result['to_target_rate'] is None and result['excluded'] == {'incomplete_or_invalid': 1}
