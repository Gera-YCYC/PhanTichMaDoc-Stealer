from stealer_agent.reviewer import review_report
from stealer_agent.journal import Journal


def base_report():
    return {'claims': [{'id': 'C1', 'text': 'Claim', 'evidence': [{'quote': 'quote'}]}],
            'verdict': 'malicious', 'verdict_claim_ids': ['C1'], 'rejected_claims': [], 'validation_notes': []}


def test_unconfirmed_claim_cannot_keep_verdict(tmp_path):
    class Reviewer:
        def chat(self, *args):
            return {'checks': [{'id': 'C1', 'supported': False, 'reason': 'No support'}]}, {}
    checked, _ = review_report(base_report(), Reviewer(), Journal(tmp_path / 'a'))
    assert checked['claims'] == []
    assert checked['verdict'] == 'inconclusive'
    assert checked['verdict_claim_ids'] == []
    assert checked['local_semantic_support_fraction'] == 0


def test_invalid_reviewer_response_fails_closed(tmp_path):
    class Reviewer:
        def chat(self, *args):
            return {'checks': []}, {}
    checked, _ = review_report(base_report(), Reviewer(), Journal(tmp_path / 'a'))
    assert checked['verdict'] == 'inconclusive'
    assert len(checked['rejected_claims']) == 1


def test_supported_claim_is_still_not_independent_truth(tmp_path):
    class Reviewer:
        def chat(self, *args):
            return {'checks': [{'id': 'C1', 'supported': True, 'reason': 'Direct quote'}]}, {}
    checked, _ = review_report(base_report(), Reviewer(), Journal(tmp_path / 'a'))
    assert len(checked['claims']) == 1
    assert 'not human ground truth' in checked['local_semantic_check']
