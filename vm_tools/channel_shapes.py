"""Identify literal configuration shapes without returning endpoints or credentials."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from tree_sitter import Language, Parser
import tree_sitter_c_sharp
import tree_sitter_python

from .syntax_context import CODE_TOOLS, reconstruct


NAME = r'[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*'
PREFIX = rf'(?:{NAME}[ \t]+)*{NAME}[ \t]*=[ \t]*'
CTOR = rf'new[ \t]+{NAME}[ \t]*\([ \t]*'
ENDPOINT = r'https://(?:discord|discordapp)\.com/api/(?:v[0-9]+/)?webhooks/[0-9]{8,24}/[A-Za-z0-9_-]{20,200}'
ASSIGNMENT = re.compile(
    rf'^[ \t]*{PREFIX}(?P<ctor>{CTOR})?(?P<literal>(?P<quote>["\x27]){ENDPOINT}(?P=quote))'
    r'[ \t]*(?(ctor)\))[ \t]*;?[ \t]*$', re.ASCII | re.IGNORECASE)


def channel_shapes(record):
    if record['tool'] not in CODE_TOOLS or record['status'] != 'ok':
        return []
    source, mapping = reconstruct(record)
    if b'/webhooks/' not in source.lower():
        return []
    module = tree_sitter_c_sharp if record['tool'] == 'decompile_dotnet' else tree_sitter_python
    tree = Parser(Language(module.language())).parse(source)
    findings = []
    for number, raw_line in enumerate(source.split(b'\n'), 1):
        if b'/webhooks/' not in raw_line.lower() or len(mapping[number]) != 1:
            continue
        line = raw_line.decode('utf-8')
        match = ASSIGNMENT.fullmatch(line)
        if not match:
            continue
        start, end = match.span('literal')
        # The matched prefix contains ASCII only, so offsets are byte columns.
        first, last = (number - 1, start), (number - 1, end)
        node = tree.root_node.named_descendant_for_point_range(first, last)
        if (node is None or node.type not in {'string', 'string_literal'} or
                tuple(node.start_point) != first or tuple(node.end_point) != last or
                node.parent.type not in {'argument', 'assignment', 'assignment_expression', 'variable_declarator',
                                         'equals_value_clause'}):
            continue
        findings.append({'kind': 'discord_webhook_literal', 'credential_shape_present': True,
                         'evidence_id': record['evidence_id'], 'line': mapping[number][0],
                         'sample_sha256': record['sample_sha256'], 'output_sha256': record['output_sha256']})
        if len(findings) == 32:
            break
    return findings


if __name__ == '__main__':
    record_path = Path(sys.argv[1])
    if not record_path.is_absolute() or record_path.stat().st_size > 5_000_000:
        raise SystemExit('Invalid channel evidence record')
    print(json.dumps(channel_shapes(json.loads(record_path.read_bytes()))))
