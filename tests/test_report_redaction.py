"""Inert credentials test display privacy, not real sample behavior."""
import copy
import json

from stealer_agent.redaction import redact_document, collect_literals
from stealer_agent.reporting import write_report


def test_embedded_password_is_removed_from_both_quote_and_repeated_prose():
    phrase = 'INERT-ONLY-' + 'password-test'
    original = {'claims': [{'id': 'C1', 'text': 'It authenticates using ' + phrase,
                           'evidence': [{'line': 19, 'quote': 'smtp_password = ' + repr(phrase)}]}]}
    before = copy.deepcopy(original)
    shared, policy = redact_document(original)
    assert phrase not in json.dumps(shared)
    assert original == before
    assert shared['claims'][0]['id'] == 'C1'
    assert shared['claims'][0]['evidence'][0]['line'] == 19
    assert policy['detected_literal_count'] == 1
    assert not policy['public_export_approved']


def test_context_masks_a_secret_even_if_assignment_is_missing_from_final_citation():
    phrase = 'INERT-ONLY-' + 'context-test'
    out, policy = redact_document({'review_note': 'Saw ' + phrase},
                                  context=['smtp_password = ' + repr(phrase)])
    assert phrase not in out['review_note']
    assert policy['detected_literal_count'] == 1


def test_literal_login_and_dictionary_credentials_unicode_quotes_and_json_validity():
    phrase = 'INERT-ONLY tiếng Việt " quote \\ slash'
    doc = {'quote': 'server.login("fixture-user", ' + repr(phrase) + ')',
           'rejected_claims': [{'reason': phrase}],
           'dict': '{"api_key": "inert-dictionary-value"}'}
    out, _ = redact_document(doc)
    rendered = json.dumps(out, ensure_ascii=False)
    assert json.loads(rendered) == out
    for text in (phrase, 'fixture-user', 'inert-dictionary-value'):
        assert text not in str(out)


def test_email_and_legacy_webhook_patterns_are_removed_without_disclosing_values():
    url = 'https://discord.com/api/webhooks/123/' + 'INERT_ONLY'
    out, _ = redact_document({'text': 'student@example.invalid ' + url})
    assert 'student@example.invalid' not in out['text']
    assert 'INERT_ONLY' not in out['text']
    assert '[REDACTED-EMAIL]' in out['text']


def test_redaction_scan_is_bounded_and_does_not_execute_literal_looking_code(tmp_path):
    marker = tmp_path / 'must-not-exist'
    code = 'password = __import__("pathlib").Path(' + repr(str(marker)) + ').touch()'
    values, _ = collect_literals([code])
    assert not marker.exists() and values == set()
    _, policy = redact_document({'text': 'x'*512_001})
    assert policy['scan_truncated'] is True


def test_report_keeps_private_result_and_marks_redacted_view_as_local(tmp_path):
    phrase = 'INERT-ONLY-' + 'render-test'
    result = {'sample': 'inert.bin', 'status': 'completed', 'model': {'tag': 'unit-fixture'},
              'successful_tools': [], 'acceptance': {'model_minimum_met': False},
              'metrics': {}, 'analysis': {'verdict': 'inconclusive', 'claims': [],
                                         'limitations': [phrase]}}
    write_report(tmp_path, result, redaction_context=['smtp_password = ' + repr(phrase)])
    assert json.loads((tmp_path/'report.private.json').read_text(encoding='utf-8')) == result
    for name in ('report.redacted.json', 'report.md'):
        assert phrase not in (tmp_path/name).read_text(encoding='utf-8')
    view = json.loads((tmp_path/'report.redacted.json').read_text(encoding='utf-8'))
    assert view['redaction']['public_export_approved'] is False
