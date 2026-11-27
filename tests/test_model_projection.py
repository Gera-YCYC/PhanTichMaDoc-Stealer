"""Inert privacy regressions; these tests are not malware quality measurements."""
import copy
import json

from stealer_agent.model_projection import ModelEvidenceView
from stealer_agent.journal import canonical
from stealer_agent.grounding import validate_report


def observation(texts):
    return {'evidence_id':'ev_0123456789abcdef', 'output_sha256':'a'*64, 'sample_sha256':'b'*64,
            'tool':'decompile_python','status':'ok',
            'lines':[{'line':i+1,'source_line':i+1,'text':s} for i,s in enumerate(texts)]}


def test_projection_keeps_raw_private_and_preserves_coordinates_and_identity():
    original = observation(['smtp_password = "inert-secret-only"', 'sender = "test@example.invalid"',
                            'smtp.login(sender, smtp_password)'])
    snapshot = copy.deepcopy(original)
    view = ModelEvidenceView()
    clean = view.observation(original)
    assert original == snapshot
    assert clean['output_sha256'] == original['output_sha256']
    assert [r['line'] for r in clean['lines']] == [1,2,3]
    assert 'inert-secret-only' not in json.dumps(clean)
    assert 'test@example.invalid' not in json.dumps(clean)
    assert clean['lines'][2] == original['lines'][2]
    assert clean['model_projection']['changed_lines'] == [1,2]
    assert 'not projected bytes' in clean['model_projection']['scope']
    assert view.observation(original)['lines'] == clean['lines']


def test_newly_recognized_literal_refreshes_cached_text_without_changing_keys():
    view = ModelEvidenceView()
    evidence = {'ev_0123456789abcdef': {'line_map':{9:'print("inert-known-later")'}}}
    view.observation(observation(['password = "inert-known-later"']))
    view.refresh(evidence)
    assert 'inert-known-later' not in evidence['ev_0123456789abcdef']['line_map'][9]


def test_short_secret_does_not_corrupt_source_identifiers_or_inserted_labels():
    view = ModelEvidenceView()
    clean = view.observation(observation(['password = "a"','data = "a"']))
    assert clean['lines'][1]['text'].startswith('data = ')
    assert '"a"' not in clean['lines'][1]['text']
    assert '__PRIVATE_LITERAL_' in clean['lines'][1]['text']


def test_escaped_spelling_and_split_source_are_withheld():
    view = ModelEvidenceView()
    clean = view.observation(observation([r'password = "inert\x2dsecret"']))
    assert r'inert\x2dsecret' not in json.dumps(clean['lines'])
    raw = observation(['password = "INERT-', 'FRAGMENT-ONLY"'])
    raw['lines'][1]['source_line'] = 1
    clean = view.observation(raw)
    assert all(r['text'] == '[REDACTED-PRIVATE-FRAGMENT]' for r in clean['lines'])


def test_fact_argument_cannot_bypass_projection_and_fact_hash_is_not_forged():
    raw = observation(['smtp_password = "inert-private-fact"'])
    raw['operation_facts'] = [{'fact_id':'op_fixture','inputs':{'x':'inert-private-fact'}}]
    clean = ModelEvidenceView().observation(raw)
    assert clean['operation_facts'] == []
    assert clean['model_projection']['suppressed_operation_facts'] == 1
    assert raw['operation_facts'][0]['fact_id'] == 'op_fixture'


def test_projection_is_not_claimed_as_original_citation_bytes():
    source = ModelEvidenceView().observation(observation(['password = "inert-private-quote"']))
    source['line_map'] = {r['line']:r['text'] for r in source['lines']}
    report = {'verdict':'inconclusive','verdict_claim_ids':[], 'claims':[], 'limitations':[]}
    checked = validate_report(report, {'ev_0123456789abcdef':source}, 'b'*64)
    assert 'not byte-identical' in checked['citation_view']


def test_card_model_requests_and_quotes_use_projection(tmp_path):
    from stealer_agent.evidence_cards import create_card_report
    from stealer_agent.journal import Journal, verify_journal
    secret = 'INERT-ONLY-card-input'
    raw = observation([f'smtp_password = "{secret}"', 'smtp.login(sender, smtp_password)'])
    source = ModelEvidenceView().observation(raw)
    source['line_map'] = {r['line']:r['text'] for r in source['lines']}
    source['latest_lines'] = [1,2]
    replies = iter([{'supplemental_claims': [], 'claims':[{'kind':'observation','text':'The source has a redacted password literal.'}]},
                    {'supported':True,'reason':'The projected literal assignment is visible.'}])
    def invoke(messages, schema, phase, exposure):
        assert secret not in json.dumps([messages, schema, exposure])
        return next(replies)
    journal = Journal(tmp_path/'run')
    output, checked = create_card_report({'ev_0123456789abcdef':source}, 'b'*64, invoke, journal, max_cards=1)
    assert secret not in json.dumps([output,checked])
    assert verify_journal(journal.path) > 0
