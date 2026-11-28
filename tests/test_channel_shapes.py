import json

import pytest

from vm_tools.channel_shapes import channel_shapes
from vm_tools.evidence import EvidenceStore


def example_url():
    # An inert synthetic string assembled in memory, never contacted.
    return 'https://discord.com/api/webhooks/' + '2' * 17 + '/' + 'X' * 52


@pytest.mark.parametrize('tool,template,expected', [
    ('decompile_dotnet', 'class A {{\nstatic Hook sink = new Hook("{url}");\n}}', True),
    ('decompile_python', 'endpoint = "{url}"', True),
    ('decompile_python', '"""example\nendpoint = "{url}"\n"""', False),
    ('decompile_dotnet', 'class A {{/*\nstatic Hook sink = new Hook("{url}");\n*/}}', False),
    ('decompile_python', 'endpoint = "{url}" + "/other"', False),
    ('decompile_python', 'endpoint = "{url}/other"', False),
    ('decompile_python', 'endpoint = "{url}@example.invalid"', False),
    ('strings', 'endpoint = "{url}"', False),
])
def test_literal_shape_uses_syntax_and_never_exports_values(tmp_path, tool, template, expected):
    store = EvidenceStore(tmp_path)
    uri = example_url()
    page = store.add(tool=tool, backend='fixture', sample='fixture', sample_sha256='a'*64,
                     text=template.format(url=uri))
    record = store.get(page['evidence_id'], page['sample_sha256'])
    findings = channel_shapes(record)
    assert bool(findings) == expected
    encoded = json.dumps(findings)
    assert uri not in encoded and '2' * 17 not in encoded and 'X' * 52 not in encoded
    for finding in findings:
        assert finding['output_sha256'] == record['output_sha256']
        assert finding['kind'] == 'discord_webhook_literal' and finding['credential_shape_present']
        assert uri in record['lines'][finding['line'] - 1]['text']
