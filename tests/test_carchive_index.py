import struct
import pytest
from vm_tools.carchive_index import application_names, COOKIE, ENTRY, MAGIC
from vm_tools.yara_candidates import extract
from stealer_agent.yara_corpus import render_choice


def archive(name=b'example_app', kind=ord('s')):
    payload = b'not executable'
    toc = ENTRY.pack(ENTRY.size+len(name)+1, 0, len(payload), len(payload), 0, kind)+name+b'\0'
    length = len(payload)+len(toc)+COOKIE.size
    return b'MZ\0\0'+payload+toc+COOKIE.pack(MAGIC, length, len(payload), len(toc), 311, b'python311.dll')


def test_application_entry_identity_has_exact_raw_byte_coordinates():
    data = archive()
    result = application_names(data)
    assert result['status'] == 'validated_toc'
    row = result['application_entries'][0]
    assert row['value'] == 'sexample_app'
    assert data[row['offset']:row['offset']+len(row['value'])] == row['value'].encode()
    assert extract(data)['candidates'][0]['kind'] == 'application_entry_identity'


def test_runtime_hooks_and_non_scripts_never_become_application_identity():
    assert application_names(archive(b'pyi_rth_ssl'))['application_entries'] == []
    assert application_names(archive(kind=ord('b')))['application_entries'] == []


def test_corrupt_archive_cannot_produce_valid_identity():
    data = bytearray(archive())
    start = len(data)-COOKIE.size
    struct.pack_into('!I', data, start+8, len(data)+100)
    with pytest.raises(ValueError):
        application_names(data)
    assert extract(data)['archive_status'] == 'invalid_toc'
    assert not any(r.get('kind') == 'application_entry_identity' for r in extract(data)['candidates'])


def test_any_two_condition_cannot_bypass_selected_application_name():
    rows = [{'id':'S1','value':'sexample_app','kind':'application_entry_identity'},
            {'id':'S2','value':'sqlite3.dll'}, {'id':'S3','value':'generic cookie message'}]
    choice = {'selected_ids':['S2','S3'],'condition':'at_least_two','reason':'test'}
    with pytest.raises(ValueError, match='application entry'):
        render_choice(choice,rows,1)
    choice['selected_ids']=['S1','S2','S3']
    assert '($s0) and 2 of them' in render_choice(choice,rows,1)
