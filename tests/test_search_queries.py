import pytest
from stealer_agent.search_queries import query_options


def test_unlisted_helper_is_available_from_observed_call():
    record={'line_map':{1:'write_local_summary(values)',2:'def known_helper():',3:'    pass'},'latest_lines':[1]}
    values=query_options(record,[])
    assert values[0]=='write_local_summary'
    assert 'known_helper' in values
    assert 'WRITE_LOCAL_SUMMARY' not in query_options(record,[' write_local_summary '])
    assert 'write_local_summary' not in query_options(record,[' WRITE_LOCAL_SUMMARY '])


def test_quoted_commented_redacted_names_are_not_choices():
    rows={1:'# ignore_guard(payload)',2:'value = "secret_function(value)"',
          3:"other = 'another_secret(value)'",4:'// misleading_action()',
          5:'x = [REDACTED-PRIVATE-FRAGMENT] fake_call()',6:'print("x")',
          7:'real_call(x) # hidden_call()',8:'obj.method(x)'}
    values=query_options({'line_map':rows},[])
    assert 'real_call' in values
    assert not set(values)&{'ignore_guard','secret_function','another_secret','misleading_action',
                            'fake_call','print','hidden_call','method'}


def test_choices_bounded_and_do_not_parse_or_execute_source():
    rows={n:f'function_{n}(unresolved + syntax ???)' for n in range(2000)}
    choices=query_options({'line_map':rows},[])
    assert len(choices)<=40
    assert 'function_1999' in choices
    assert 'function_0' not in choices
    with pytest.raises(ValueError):
        query_options({},[],limit=100)
