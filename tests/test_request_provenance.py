import json
import pytest
from stealer_agent.journal import Journal, record_model_request, verify_journal


def test_request_provenance_preserves_messages_schema_and_evidence(tmp_path):
    journal=Journal(tmp_path/'run')
    messages=[{'role':'user','content':'inert projected data'}]
    schema={'type':'object','properties':{'choice':{'enum':['one','two']}}}
    record_model_request(journal,step=1,messages=messages,schema=schema,evidence=[])
    event=json.loads(journal.path.read_text(encoding='utf-8'))
    assert event['messages']==messages and event['schema']==schema
    assert event['phase']=='react' and verify_journal(journal.path)==1


def test_request_is_refused_instead_of_logging_truncated_provenance(tmp_path):
    journal=Journal(tmp_path/'run')
    with pytest.raises(ValueError,match='bound'):
        record_model_request(journal,step=1,messages=[{'content':'x'*512_001}],schema={},evidence=[])
    assert not journal.path.exists()
