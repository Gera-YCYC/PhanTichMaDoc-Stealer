"""Coverage checks use inert claims; these tests are not malware accuracy scores."""
import pytest

from stealer_agent.verdict_support import SUPPORT_KEYS, enforce_stealer_support
from lab_web.verdict import trace


def candidate():
    return {'verdict': 'malicious', 'proposed_verdict': 'malicious',
            'verdict_claim_ids': ['C1', 'C2', 'C3'],
            'claims': [{'id': n, 'kind': 'behavior'} for n in ['C1', 'C2', 'C3']],
            'validation_notes': []}


@pytest.mark.parametrize('missing', SUPPORT_KEYS)
def test_missing_chain_component_cannot_retain_malicious(missing):
    roles = dict(zip(SUPPORT_KEYS, [['C1'], ['C2'], ['C3']]))
    roles[missing] = []
    raw = candidate()
    checked = enforce_stealer_support(raw, roles)
    assert checked['verdict'] == 'suspicious'
    assert checked['proposed_verdict'] == raw['verdict'] == 'malicious'
    assert checked['verdict_support_missing'] == [missing]


@pytest.mark.parametrize('invalid', ['unknown', 'observation', 'uncited'])
def test_roles_must_reference_cited_accepted_behavior(invalid):
    raw = candidate()
    roles = dict(zip(SUPPORT_KEYS, [['C1'], ['C2'], ['C3']]))
    if invalid == 'unknown': roles[SUPPORT_KEYS[1]] = ['C99']
    if invalid == 'observation': raw['claims'][1]['kind'] = 'observation'
    if invalid == 'uncited': raw['verdict_claim_ids'].remove('C2')
    checked = enforce_stealer_support(raw, roles)
    assert checked['verdict'] == 'suspicious'
    assert checked['verdict_support_invalid'] == [SUPPORT_KEYS[1]]


def test_complete_roles_do_not_promote_a_lower_verdict_or_imply_semantic_truth():
    roles = dict(zip(SUPPORT_KEYS, [['C1'], ['C2'], ['C3']]))
    raw = candidate()
    assert enforce_stealer_support(raw, roles)['verdict'] == 'malicious'
    raw['verdict'] = 'inconclusive'
    checked = enforce_stealer_support(raw, roles)
    assert checked['verdict'] == 'inconclusive'
    assert 'not independent' in checked['verdict_support_scope']


def test_web_shows_original_decision_and_unbound_role_ids():
    raw = candidate()
    raw["verdict_claim_ids"] = ["C1", "C2"]
    checked = enforce_stealer_support(raw, dict(zip(SUPPORT_KEYS, [["C1"], [], ["C3"]])))
    summary = trace(checked)
    assert (summary["proposed"], summary["final"]) == ("malicious", "suspicious")
    assert [r["state"] for r in summary["roles"]] == ["cited", "missing", "invalid"]
    assert summary["roles"][-1]["unbound"] == ["C3"]
    checked["verdict_support_invalid"] = []
    with pytest.raises(ValueError):
        trace(checked)
    assert trace({}) is None
