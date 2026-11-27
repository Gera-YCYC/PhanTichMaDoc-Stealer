import hashlib
import json
import zlib
import pytest
from jsonschema import Draft202012Validator
from stealer_agent.contracts import decision_schema, validate_action
from stealer_agent.telemetry import process_memory
from vm_tools.evidence import EvidenceStore
from vm_tools.unpack_worker import bounded_inflate


def test_search_keeps_original_line_numbers(tmp_path):
    store = EvidenceStore(tmp_path)
    first = store.add(sample='x.bin', sample_sha256='a'*64, tool='decompile_dotnet', backend='test',
                      text='\n'.join(['context']*20 + ['Upload marker'] + ['context']*10))
    found = store.search(first['evidence_id'], 'a'*64, 'Upload')
    assert found['hit_count'] == 1
    assert next(r for r in found['lines'] if r['text'] == 'Upload marker')['line'] == 21
    with pytest.raises(ValueError):
        store.search(first['evidence_id'], 'b'*64, 'Upload')


def test_bounded_zlib_rejects_bomb_and_truncation():
    compressed = zlib.compress(b'x'*10000)
    with pytest.raises(ValueError):
        bounded_inflate(compressed, 100)
    with pytest.raises(ValueError):
        bounded_inflate(compressed[:-2], 10000)
    assert bounded_inflate(zlib.compress(b'abc'), 100) == b'abc'


def test_unknown_python_entry_not_in_decoding_schema():
    schema = decision_schema('a.bin', ['decompile_python'], [], False, python_entries=[6])
    action = {'action': 'decompile_python', 'arguments': {'sample':'a.bin','entry_index':0},
              'reason':'test', 'report':None}
    assert not Draft202012Validator(schema).is_valid(action)
    action['arguments']['entry_index'] = 6
    assert Draft202012Validator(schema).is_valid(action)


def test_search_schema_only_offers_unsearched_literal():
    eid = 'ev_'+'1'*16
    schema = decision_schema('a.bin', ['search_evidence'], [eid], False, search_options={eid:['cookie']})
    action = {'action':'search_evidence','reason':'test','report':None,
              'arguments':{'sample':'a.bin','evidence_id':eid,'query':'cookie, token'}}
    assert not Draft202012Validator(schema).is_valid(action)
    action['arguments']['query']='cookie'
    assert Draft202012Validator(schema).is_valid(action)


def test_search_schema_includes_observed_helper_and_keeps_evidence_boundary():
    from stealer_agent.search_queries import query_options
    eid='ev_'+'1'*16
    options=query_options({'line_map':{1:'write_local_summary(values)'}},['cookie'])
    schema=decision_schema('a.bin',['search_evidence'],[eid],False,
                           search_options={eid:options})
    value={'action':'search_evidence','reason':'Inspect observed helper body','report':None,
           'arguments':{'sample':'a.bin','evidence_id':eid,'query':'write_local_summary'}}
    validator=Draft202012Validator(schema)
    assert validator.is_valid(value)
    for query in ('ab','x'*81,'hello\nworld','hello\x00world'):
        value['arguments']['query']=query
        assert not validator.is_valid(value)
    value['arguments']['query']='write_local_summary'
    value['arguments']['evidence_id']='ev_'+'2'*16
    assert not validator.is_valid(value)


def test_yara_cannot_choose_paths_or_corpus_members():
    with pytest.raises(Exception):
        validate_action({'action':'test_yara','reason':'test','report':None,
                         'arguments':{'sample':'a.bin','rule':'rule a {condition:true}',
                                      'corpus':'training','path':'C:/Windows'}})


def test_process_memory_is_real_and_positive():
    metrics = process_memory()
    assert metrics['host_rss_bytes'] > 0
    assert metrics['host_peak_rss_bytes'] >= metrics['host_rss_bytes']


def test_assembly_versions_are_not_ip_candidates():
    from vm_tools.analyzers import extract_ioc
    text, _, _ = extract_ioc({'evidence_id':'ev_'+'1'*16,'lines':[
        {'line':1,'text':'[assembly: AssemblyVersion("1.0.0.0")]'},
        {'line':2,'text':'string endpoint = "https://192.0.2.4/test";'}]})
    assert '1.0.0.0' not in text
    assert '192.0.2.4' in text
