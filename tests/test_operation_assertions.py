"""Inert fixtures check boundaries, never coursework accuracy."""
import copy
import hashlib
import json

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from stealer_agent.journal import Journal, canonical, verify_journal
from stealer_agent.operation_assertions import catalog, create_operation_report, render
from vm_tools.evidence import EvidenceStore
from vm_tools.operation_facts import extract_operations


def evidence(tmp_path, source=None):
    source = source or 'import smtplib\ndef f(host, sender, recipient, msg):\n    smtp = smtplib.SMTP(host)\n    smtp.sendmail(sender, recipient, msg)\n'
    store = EvidenceStore(tmp_path / 'evidence')
    first = store.add(sample='inert.bin', sample_sha256='a' * 64, tool='decompile_python', backend='fixture', text=source)
    record = store.get(first['evidence_id'], 'a' * 64)
    record['operation_facts'] = extract_operations(record)['facts']
    record['line_map'] = {r['line']: r['text'] for r in record['lines']}
    return {record['evidence_id']: record}


def test_templates_do_not_turn_categories_or_variables_into_effects(tmp_path):
    ev = evidence(tmp_path)
    entries, omitted = catalog(ev, 'a' * 64)
    assert not omitted and len(entries) == 1
    text = entries[0]['text']
    assert 'sendmail' in text and 'smtp_send' not in text
    assert 'sender expression "sender"' in text
    assert 'password' not in text and 'attachment' not in text
    assert entries[0]['evidence'][-1]['quote'].strip() == 'smtp.sendmail(sender, recipient, msg)'


@pytest.mark.parametrize('mutation', ['hash', 'missing_binding', 'sample', 'redacted'])
def test_invalid_or_hidden_facts_never_reach_selection(tmp_path, mutation):
    ev = evidence(tmp_path)
    record = next(iter(ev.values()))
    if mutation == 'hash': record['operation_facts'][0]['inputs']['message_expression'] = 'other'
    if mutation == 'missing_binding': del record['line_map'][1]
    if mutation == 'sample': record['sample_sha256'] = 'b' * 64
    if mutation == 'redacted': record['line_map'][1] = '[REDACTED-INJECTION]'
    entries, _ = catalog(ev, 'a' * 64)
    assert entries == []


def test_even_rehashed_wrong_api_or_return_contract_is_rejected(tmp_path):
    ev = evidence(tmp_path)
    fact = next(iter(ev.values()))['operation_facts'][0]
    fact['api'] = 'custom.sendmail'
    fact['fact_id'] = 'op_' + hashlib.sha256(canonical({k:v for k,v in fact.items() if k != 'fact_id'})).hexdigest()[:16]
    entries, omitted = catalog(ev, 'a' * 64)
    assert not entries and omitted
    with pytest.raises(ValueError): render(fact)


def test_selection_is_logged_but_never_claimed_as_semantic_approval(tmp_path):
    ev = evidence(tmp_path)
    calls = []
    def model(messages, schema, phase, exposure):
        calls.append((messages, phase, exposure))
        answer = {'include': True, 'reason': 'Call and receiver binding present.'}
        Draft202012Validator(schema).validate(answer)
        return answer
    journal = Journal(tmp_path / 'run')
    raw, checked = create_operation_report(ev, 'a' * 64, model, journal)
    assert len(raw['claims']) == len(checked['claims']) == 1
    assert checked['full_analysis_completed'] is False
    assert checked['requires_semantic_review'] is True
    assert checked['semantic_accuracy_measured'] is False
    assert raw['verdict'] == 'inconclusive' and raw['verdict_claim_ids'] == []
    assert len(checked['pending_analysis']) == 5
    assert calls[0][2][0]['lines'][-1]['line'] == 4
    assert verify_journal(journal.path) == 3


def test_abstention_and_invalid_decision_are_not_hidden(tmp_path):
    ev = evidence(tmp_path)
    journal = Journal(tmp_path / 'run')
    raw, checked = create_operation_report(ev, 'a' * 64, lambda *a: {'include': False, 'reason': 'Uncertain.'}, journal)
    assert raw['claims'] == []
    assert checked['available_operation_count'] == 1 and checked['operation_selections'][0]['include'] is False
    other = Journal(tmp_path / 'invalid')
    with pytest.raises(ValidationError):
        create_operation_report(ev, 'a' * 64, lambda *a: {'include': 'true', 'reason': 'invalid'}, other)
    rows = [json.loads(x) for x in other.path.read_text().splitlines()]
    assert rows[-1]['event'] == 'operation_assertion_decision'


def test_long_or_hidden_arguments_omit_whole_assertion_not_truncated_fact(tmp_path):
    ev = evidence(tmp_path)
    fact = next(iter(ev.values()))['operation_facts'][0]
    for values in ({k: 'x' * 240 for k in fact['inputs']}, {**fact['inputs'], 'message_expression': '[REDACTED-PRIVATE-FRAGMENT]'}):
        candidate = copy.deepcopy(fact)
        candidate['inputs'] = values
        with pytest.raises(ValueError): render(candidate)


@pytest.mark.parametrize('marker', ['[REDACTED]', '__PRIVATE_LITERAL_1__'])
def test_projected_credentials_cannot_turn_into_operands(tmp_path, marker):
    ev = evidence(tmp_path)
    fact = next(iter(ev.values()))['operation_facts'][0]
    fact['inputs']['sender_expression'] = marker
    with pytest.raises(ValueError): render(fact)


def test_non_code_evidence_never_supplies_operation_catalog(tmp_path):
    ev = evidence(tmp_path)
    next(iter(ev.values()))['tool'] = 'strings'
    assert catalog(ev, 'a' * 64) == ([], [])
