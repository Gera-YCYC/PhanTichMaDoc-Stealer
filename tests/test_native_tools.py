import hashlib
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from stealer_agent.contracts import validate_action
from vm_tools.native_tools import NativeTools


def native(tmp_path):
    exe = tmp_path/'trusted-tool'
    exe.write_bytes(b'test-executable-not-run')
    return NativeTools({'floss':str(exe), 'diec':str(exe),
        'floss_sha256':hashlib.sha256(exe.read_bytes()).hexdigest(),
        'diec_sha256':hashlib.sha256(exe.read_bytes()).hexdigest(),
        'diec_database':str(tmp_path), 'diec_library_dir':str(tmp_path),
        'evidence_dir':str(tmp_path/'evidence')})


def test_native_digest_tampering_prevents_spawn(tmp_path):
    tool = native(tmp_path)
    Path(tool.config['floss']).write_bytes(b'tampered')
    with patch('vm_tools.native_tools.bounded_process') as run:
        with pytest.raises(ValueError, match='digest'):
            tool.analyze('floss', b'sample', 'a.bin')
        run.assert_not_called()


def test_floss_managed_fixed_args_disable_workspace(tmp_path):
    with patch('vm_tools.native_tools.bounded_process', return_value='{"strings":{}}') as run:
        text, backend, limitations = native(tmp_path).analyze('floss', b'input', 'a.bin', is_dotnet=True)
        assert run.call_args.args[0][1:6] == ['--json','--quiet','--only','static','--']
        assert run.call_args.kwargs['env_overrides']['FLOSS_LOAD_VIV_WORKSPACE'] == '0'
        assert run.call_args.kwargs['memory_limit']
        assert json.loads(text)['mode'] == 'managed_static_only'
        assert any('not CIL' in limit for limit in limitations)


def test_floss_counts_preserved_when_bounded(tmp_path):
    raw = json.dumps({'strings':{'static_strings':[{'string':'x'*1601,'offset':i} for i in range(151)]}})
    with patch('vm_tools.native_tools.bounded_process', return_value=raw):
        text, _, limits = native(tmp_path).analyze('floss', b'input', 'a.bin')
    result = json.loads(text)
    assert result['counts']['static_strings'] == 151
    assert len(result['strings']) == 150
    assert len(result['strings'][0]['string']) == 1500
    assert result['values_truncated'] == 150
    assert any('capped' in limit for limit in limits)


@pytest.mark.parametrize('raw', ['[]', '{"strings":{ "static_strings":1}}', '{"strings":{"static_strings":[1]}}'])
def test_floss_malformed_output_rejected(tmp_path, raw):
    with patch('vm_tools.native_tools.bounded_process', return_value=raw):
        with pytest.raises(ValueError):
            native(tmp_path).analyze('floss', b'input', 'a.bin')


def test_native_arguments_cannot_supply_shell_or_path():
    for action in ('detect_it_easy','floss'):
        with pytest.raises(Exception):
            validate_action({'action':action, 'arguments':{'sample':'a.bin','path':'/etc/passwd'},
                             'reason':'test','report':None})


def test_permission_failure_marks_backend_unavailable(tmp_path):
    tool = native(tmp_path)
    with patch.object(Path, 'is_file', side_effect=PermissionError):
        assert tool.available('floss') is False
