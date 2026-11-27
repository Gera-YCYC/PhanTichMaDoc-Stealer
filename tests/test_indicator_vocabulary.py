import pytest
from jsonschema import Draft202012Validator
from stealer_agent.evidence_cards import card_schema
from stealer_agent.indicator_candidates import candidates, source_expression
from stealer_agent.operation_context import model_operations

EID = 'ev_' + 'a' * 16


def extract(text):
    return candidates([{'evidence_id': EID, 'line': 20, 'end_line': 20, 'quote': text}])


@pytest.mark.parametrize('text,value,kind', [
    ('smtp_server = "mail.fixture.invalid"', 'mail.fixture.invalid', 'hostname'),
    ('client = smtplib.SMTP("mail.fixture.invalid", 587)', 'mail.fixture.invalid', 'hostname'),
    ('server = new SmtpClient("mail.fixture.invalid");', 'mail.fixture.invalid', 'hostname'),
    ('host = "192.0.2.3"', '192.0.2.3', 'ip'),
    ('endpoint = "2001:db8::1"', '2001:db8::1', 'ip'),
    ('target = "https://fixture.invalid/upload"', 'https://fixture.invalid/upload', 'url'),
])
def test_whole_literals_with_coordinate(text, value, kind):
    assert extract(text) == [{'value': value, 'kind': kind, 'evidence_id': EID,
                             'line': 20, 'status': 'static_candidate_only'}]


@pytest.mark.parametrize('text', [
    'path + "Local State"', 'user + "Browser/{name}.txt"',
    'filename = "report.txt"', 'version = "1.2.3.4"',
    'smtp_server = f"mail.{name}.invalid"', 'smtp_server = "mail.fixture.invalid" + suffix',
    'smtp_server = prefix + "mail.fixture.invalid"',
    'smtp_server = "__PRIVATE_LITERAL_1__"',
    'password = "https://fixture.invalid/password"',
    'endpoint = "https://user:pass@fixture.invalid/"',
    'endpoint = "https://fixture.invalid/?token=private"',
    'endpoint = "https://fixture.invalid/#token"',
    '# smtp_server = "mail.fixture.invalid"',
    'pass # smtp_server = "mail.fixture.invalid"',
    '// smtp_server = "mail.fixture.invalid"',
    '/* smtp_server = "mail.fixture.invalid" */',
    'doc = """smtp_server = "mail.fixture.invalid""""',
    'smtp_server = "mail\\x2efixture.invalid"',
    'smtp_server = "999.999.999.999"',
    'url = "http://[broken/"',
])
def test_no_candidate_for_unsupported_or_sensitive_syntax(text):
    assert extract(text) == []


def test_schema_cannot_emit_expression_or_unlisted_value():
    schema = card_schema(extract('smtp_server = "mail.fixture.invalid"'))
    validator = Draft202012Validator(schema)
    def report(value):
        return {'claims': [], 'supplemental_claims': [{'kind': 'ioc', 'text': 'Static hostname.',
                'value': value, 'technique_id': ''}]}
    assert validator.is_valid(report('mail.fixture.invalid'))
    assert not validator.is_valid(report('other.invalid'))
    assert not validator.is_valid(report('path + "Local State"'))
    assert not Draft202012Validator(card_schema([])).is_valid(report('mail.fixture.invalid'))
    assert Draft202012Validator(card_schema([])).is_valid({'claims': [], 'supplemental_claims': [
        {'kind': 'attack', 'text': 'A source-supported technique.', 'value': '', 'technique_id': 'T1555.003'}]})


@pytest.mark.parametrize('text', ['path + "Local State"', "user+'Temp/login_db'", 'os.path.join(a,b)', 'f"{host}"'])
def test_expression_recognizer(text):
    assert source_expression(text)


def test_expression_recognizer_does_not_reject_literal_url():
    assert not source_expression('https://fixture.invalid/a+b')


def test_file_api_descriptor_is_not_presented_as_called_base_class():
    fact = {'fact_id': 'op_x', 'operation': 'file_read', 'api': 'io.TextIOBase.read',
            'inputs': {}, 'result': {}, 'ranges': []}
    shown = model_operations({'operations': [fact]})[0]
    assert 'api' not in shown and 'io.TextIOBase.read' not in str(shown)
    assert 'concrete class not asserted' in shown['api_semantics']
    assert fact['api'] == 'io.TextIOBase.read'  # original provenance unchanged
