import pytest

from eval.score_public_batch import DEFAULT_PROFILES, EVIDENCE, PROFILES, read, summarize_public_batch


def test_submitted_table_reproduces_including_empty_report():
    profiles = [PROFILES/name for name in DEFAULT_PROFILES]
    result = summarize_public_batch(EVIDENCE/'coverage-v11-batch.json', profiles)
    assert result == read(EVIDENCE/'coverage-v11-rubric.json')
    assert sum(case['reference_count'] for case in result['cases'] if case['empty_report']) == 7
    assert sum(result['after_filter']['declared_units'][k] for k in ('correct','missed')) == 104


def test_cannot_drop_reference_for_failed_sample():
    profiles = [PROFILES/name for name in DEFAULT_PROFILES if 'agenttesla' not in name]
    with pytest.raises(ValueError, match='one reference'):
        summarize_public_batch(EVIDENCE/'coverage-v11-batch.json', profiles)
