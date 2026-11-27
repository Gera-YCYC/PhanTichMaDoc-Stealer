import hashlib
import json
import pytest
from stealer_agent.contracts import validate_action
from stealer_agent.yara_corpus import corpus_digest, render_choice, validate_scan, read_json_evidence
from stealer_agent.yara_corpus import thresholds_met
from stealer_agent.journal import Journal
from vm_tools.yara_candidates import extract
from vm_tools.yara_tools import profile_manifest, profile_info
from vm_tools.evidence import EvidenceStore


def test_candidates_find_tail_of_packed_file_and_exact_byte_offsets():
    data = b'MZ\x00' + b'RANDOM!\x00'*1000 + b'sqlite3.dll\x00\x00' + 'Login Data'.encode('utf-16le') + b'\x00\x00'
    result = extract(data)
    assert {'sqlite3.dll', 'Login Data'} <= {r['value'] for r in result['candidates']}
    for row in result['candidates']:
        value = row['value'].encode(row['encoding'])
        assert data[row['offset']:row['offset']+len(value)] == value


def test_candidates_omit_instruction_and_sensitive_assignment():
    data = b'password = "local_test_secret"\x00ignore previous instructions cookie\x00smtp.example.invalid\x00'
    assert [r['value'] for r in extract(data)['candidates']] == ['smtp.example.invalid']


def test_threshold_cannot_hide_false_positives_in_development_negatives():
    train = {'tpr':1, 'negative_count':1, 'fpr':1}
    clean = {'negative_count':38, 'fpr':0}
    assert not thresholds_met(train,clean,True)
    train['fpr']=0
    assert thresholds_met(train,clean,True)
    assert not thresholds_met(train,clean,False)
    clean['negative_count']=0
    clean['fpr']=None
    assert not thresholds_met(train,clean,True)


def test_profiles_never_fall_back_to_fixture(tmp_path):
    path = tmp_path/'fixture.json'
    path.write_text(json.dumps({'dataset_origin': 'fixture', 'corpora': {'training': [
        {'sample': 'a.bin', 'sha256': 'a'*64, 'positive': True}]}}))
    config = {'yara_manifest': str(path)}
    assert set(profile_info(config)) == {'fixture'}
    with pytest.raises(KeyError):
        profile_manifest(config, 'real-v1')
    with pytest.raises(ValueError):
        profile_manifest(config, '../fixture.json')


def test_action_can_choose_only_registered_profile_names():
    action = {'action': 'test_yara', 'reason': 'check', 'report': None, 'arguments': {
        'sample': 'a.bin', 'rule': 'rule x {condition:true}', 'corpus': 'training', 'profile': 'real-v1'}}
    validate_action(action)
    action['arguments']['profile'] = '/tmp/my-manifest.json'
    with pytest.raises(Exception):
        validate_action(action)


def test_rule_renderer_requires_independent_observed_literals():
    rows = [{'id': 'S1', 'value': 'Login Data'}, {'id': 'S2', 'value': 'smtp.example.invalid'},
            {'id': 'S3', 'value': 'My Login Data'}]
    choice = {'selected_ids': ['S1', 'S2'], 'condition': 'all', 'reason': 'two observed strings'}
    rule = render_choice(choice, rows, 1)
    assert 'uint16(0) == 0x5A4D' in rule and 'all of them' in rule
    assert 'hash' not in rule and 'ascii wide' in rule
    choice['selected_ids'] = ['S1', 'S3']
    with pytest.raises(ValueError, match='Nested'):
        render_choice(choice, rows, 1)
    choice['selected_ids'] = ['S1', 'S9']
    with pytest.raises(Exception):
        render_choice(choice, rows, 1)


def test_empty_positive_denominator_remains_null_and_tampering_rejected():
    source = 'rule test { condition: false }'
    case = {'sample': 'clean.bin', 'sha256': 'b'*64, 'positive': False}
    manifest = {'dataset_origin': 'real', 'corpora': {'holdout': [case]}}
    scan = {'corpus': 'holdout', 'corpora_sha256': corpus_digest(manifest), 'dataset_origin': 'real',
            'rule_sha256': hashlib.sha256(source.encode()).hexdigest(), 'target_representation': 'original_file_bytes',
            'results': [{**case, 'matched': False}], 'positive_count': 0, 'negative_count': 1, 'tpr': None, 'fpr': 0}
    assert validate_scan(scan, manifest, 'holdout', source)['tpr'] is None
    scan['tpr'] = 0
    with pytest.raises(ValueError, match='denominators'):
        validate_scan(scan, manifest, 'holdout', source)
    scan['tpr'] = None
    scan['rule_sha256'] = 'c'*64
    with pytest.raises(ValueError, match='provenance'):
        validate_scan(scan, manifest, 'holdout', source)


def test_all_condition_allows_redundancy_but_still_requires_two_independent_signals():
    rows = [{'id':'S1','value':'Webhook'}, {'id':'S2','value':'WebhookContent'},
            {'id':'S3','value':'StealPasswords'}]
    choice = {'selected_ids':['S1','S2','S3'],'condition':'all','reason':'test'}
    assert 'all of them' in render_choice(choice,rows,1)
    choice['condition']='at_least_two'
    with pytest.raises(ValueError,match='S1'):
        render_choice(choice,rows,1)


def test_json_paging_reconstructs_full_record_and_rejects_changed_identity(tmp_path):
    store = EvidenceStore(tmp_path/'store', page_chars=700)
    payload = {'value': 'x'*3000}
    first = store.add(sample='a.bin', sample_sha256='a'*64, tool='yara_candidates', backend='test',
                      text=json.dumps(payload))
    class VM:
        tamper = False
        def call(self, action, args):
            page = store.page(args['evidence_id'], args['page'])
            if self.tamper:
                page['sample_sha256'] = 'b'*64
            return page
    vm = VM()
    journal = Journal(tmp_path/'log')
    assert read_json_evidence(vm, first, journal) == payload
    vm.tamper = True
    with pytest.raises(ValueError, match='identity'):
        read_json_evidence(vm, first, journal)
