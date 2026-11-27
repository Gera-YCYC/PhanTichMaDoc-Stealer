"""Inert unit fixtures validate reporting boundaries, not malware accuracy."""
import copy
import json

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from stealer_agent.contracts import decision_schema, validate_action
from stealer_agent.evidence_cards import create_card_report, select_cards
from stealer_agent.grounding import validate_report
from stealer_agent.journal import Journal, verify_journal

EID = 'ev_' + 'a' * 16
DIGEST = 'b' * 64


def source(lines):
    return {EID: {'status': 'ok', 'tool': 'decompile_dotnet', 'sample_sha256': DIGEST,
                  'line_map': lines, 'focus_groups': [[min(lines)]]}}


def claim(ref):
    return {'id': 'C1', 'kind': 'behavior', 'text': 'The code writes a fixture value.',
            'value': '', 'technique_id': '', 'evidence': [ref]}


def report(ref):
    return {'verdict': 'inconclusive', 'verdict_claim_ids': [], 'limitations': [], 'claims': [claim(ref)]}


def test_ranges_match_every_line_and_cannot_hide_intermediate_text():
    ev = source({10: 'before();', 11: 'write_fixture();', 12: 'after();'})
    ref = select_cards(ev)[0]['reference']
    assert ref['line'] == 10 and ref['end_line'] == 12
    assert len(validate_report(report(ref), ev, DIGEST)['claims']) == 1
    for mutation in ('quote', 'missing', 'redacted', 'sample', 'backward', 'large'):
        candidate, data = copy.deepcopy(ref), copy.deepcopy(ev)
        if mutation == 'quote': candidate['quote'] = 'write_fixture();'
        if mutation == 'missing': del data[EID]['line_map'][11]
        if mutation == 'redacted': data[EID]['line_map'][11] = '[REDACTED-INJECTION]'
        if mutation == 'sample': data[EID]['sample_sha256'] = 'c' * 64
        if mutation == 'backward': candidate['end_line'] = 9
        if mutation == 'large': candidate['end_line'] = 50
        checked = validate_report(report(candidate), data, DIGEST)
        assert checked['rejected_claims'], mutation


def test_cards_respect_gaps_redaction_budgets_and_do_not_invent_source():
    ev = source({i: 'fixture_call_' + str(i) + '();' for i in range(1, 101)})
    ev[EID]['line_map'][30] = '[REDACTED-INJECTION]'
    del ev[EID]['line_map'][60]
    ev[EID]['focus_groups'] = [[29], [31], [61]]
    cards = select_cards(ev, max_cards=3, max_lines=20, max_chars=400)
    assert len(cards) == 3
    for card in cards:
        ref = card['reference']
        assert '[REDACTED-INJECTION]' not in ref['quote']
        assert len(ref['quote']) <= 400
        assert ref['end_line'] - ref['line'] < 20
        assert validate_report(report(ref), ev, DIGEST)['claims']
    with pytest.raises(ValueError): select_cards(ev, max_cards=13)
    with pytest.raises(ValueError): select_cards(ev, max_lines=41)


def test_finalize_is_controller_action_and_decoding_preserves_legacy_finish():
    action = {'action': 'finalize', 'reason': 'Summarize evidence', 'arguments': {}, 'report': None}
    validate_action(action)
    schema = decision_schema('fixture.bin', [], [], True, card_report=True)
    assert Draft202012Validator(schema).is_valid(action)
    assert not Draft202012Validator(decision_schema('fixture.bin', [], [], True)).is_valid(action)
    with pytest.raises(ValidationError):
        validate_action({**action, 'arguments': {'sample': 'fixture.bin'}})


def test_rejected_candidates_survive_and_are_excluded_from_verdict_input(tmp_path):
    ev = source({1: 'File.WriteAllText("fixture", "test");'})
    answers = iter([
        {'claims': [{'kind': 'behavior', 'text': 'The code writes test to a file.'},
                    {'kind': 'behavior', 'text': 'The code uploads passwords.'}]},
        {'supported': True, 'reason': 'File write call is visible.'},
        {'supported': False, 'reason': 'No upload or password source shown.'},
        {'verdict': 'inconclusive', 'verdict_claim_ids': []},
    ])
    calls = []

    def invoke(messages, schema, phase, exposure):
        calls.append((messages, phase, exposure))
        answer = next(answers)
        assert Draft202012Validator(schema).is_valid(answer)
        return answer

    journal = Journal(tmp_path / 'run')
    raw, checked = create_card_report(ev, DIGEST, invoke, journal, max_cards=1)
    assert len(raw['claims']) == 2 and len(checked['claims']) == 1
    assert checked['rejected_claims'][0]['claim']['id'] == 'C2'
    assert 'uploads passwords' not in calls[-1][0][-1]['content']
    assert all(c[2][0]['lines'][0]['line'] == 1 for c in calls[:-1])
    assert checked['requires_semantic_review'] is True
    assert json.loads((journal.directory / 'report.card-candidates.json').read_text())['claims'] == raw['claims']
    assert verify_journal(journal.path) >= 5


def test_no_code_produces_inconclusive_without_invented_claims(tmp_path):
    ev = source({1: 'fixture format'})
    ev[EID]['tool'] = 'strings'
    raw, checked = create_card_report(ev, DIGEST, None, Journal(tmp_path / 'run'))
    assert not raw['claims'] and checked['verdict'] == 'inconclusive'
    assert checked['local_semantic_support_fraction'] is None


def test_decoder_provenance_fragments_are_not_sample_code_and_replace_bytecode():
    ev = source({1: '# STATIC DECODE PROVENANCE {', 2: '"operation":"base64.b64decode",',
                 3: '"input_sha256":"abc"}', 4: '# CANDIDATE 1', 5: 'def fixture():',
                 6: '    write_fixture()'})
    ev[EID]['tool'] = 'decode_python_literals'
    ev[EID]['line_metadata'] = {n: {'source_line': 1 if n < 4 else n-2} for n in range(1, 7)}
    bytecode_id = 'ev_' + 'f' * 16
    ev[bytecode_id] = {**source({1: 'LOAD_CONST encoded_data()'})[EID], 'tool': 'disassemble_python'}
    cards = select_cards(ev)
    assert cards and all(c['reference']['evidence_id'] == EID for c in cards)
    assert all(c['reference']['line'] >= 5 for c in cards)
    assert 'input_sha256' not in str(cards)
    # Fail closed if provenance boundary metadata was not retained.
    ev[EID].pop('line_metadata')
    assert select_cards(ev) == []
