import ast
import base64
import hashlib
import json
import zlib

import pytest
from vm_tools.literal_decoder import Constants, MAX_BYTES, Unsupported, recover, unpack_zlib


def record(blob):
    text=repr(base64.b64encode(blob).decode())
    rows=[{'line':i+1,'source_line':1,'text':text[n:n+73]} for i,n in enumerate(range(0,len(text),73))]
    return {'tool':'disassemble_python','status':'ok','evidence_id':'ev_'+'a'*16,
            'output_sha256':'b'*64,'lines':rows}


def test_decode_reassembles_split_constant_and_never_executes(tmp_path):
    sentinel=tmp_path/'must-not-exist'
    payload='import os\ndef sample():\n    return 1\n'+f'open({str(sentinel)!r}, "w").write("BAD")\n'
    encoded=base64.b64encode(zlib.compress(payload.encode())).decode()
    wrapper=f'import base64\nimport zlib\nx = {encoded!r}\ny = base64.b64decode(x)\nz = zlib.decompress(y).decode("utf-8")\nexec(z)\n'
    result=recover(record(wrapper.encode()))
    assert payload in result
    assert not sentinel.exists()
    assert hashlib.sha256(payload.encode()).hexdigest() in result
    assert 'zlib.decompress' in result


def test_unknown_calls_and_import_shadowing_are_not_evaluated(tmp_path):
    env=Constants()
    source='import base64\nbase64 = unknown()\nx = base64.b64decode("YWJj")\n'
    assert not env.process(ast.parse(source))
    assert 'base64' not in env.env and 'x' not in env.env
    for expression in ['__import__("os").getcwd()', 'eval("1+1")', 'exec("pass")', 'open("x")', '(lambda: 1)()']:
        with pytest.raises(Unsupported): Constants().value(ast.parse(expression,mode='eval').body)


def test_bound_and_wrong_tool_fail_closed():
    with pytest.raises(Unsupported): unpack_zlib(zlib.compress(b'a'*(MAX_BYTES+1)))
    with pytest.raises(Unsupported): unpack_zlib(zlib.compress(b'abc')+b'trailing')
    with pytest.raises(Unsupported): recover({**record(b'not code'),'tool':'strings'})


def test_no_branch_execution_or_unbounded_expression():
    env=Constants()
    env.process(ast.parse('import base64\nif True:\n    value=base64.b64decode("YWJj")\nx=base64.b64decode("YWJj")'))
    assert 'value' not in env.env and 'x' not in env.env
    with pytest.raises(Unsupported): env.value(ast.parse('"a" * 1000000000',mode='eval').body)
