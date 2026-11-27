"""Conservative report vocabulary from already bounded, projected code excerpts.

This is a lexical display constraint, not a malware parser or a dataflow proof.
It never reads samples, evaluates strings, resolves DNS or accesses a network.
Unsupported escaping/interpolation/concatenation yields no candidate.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

DOMAIN = re.compile(r'(?=.{4,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\Z')
NETWORK = re.compile(r'(?:\b(?:[A-Za-z_]\w*[_])?(?:host|hostname|server|endpoint|url)\s*=\s*|\b(?:SMTP|SMTP_SSL|SmtpClient)\s*\(\s*)$', re.I)
PRIVATE = re.compile(r'password|passwd|secret|token|credential|username|api_key|sender|recipient|email', re.I)


def source_expression(value):
    return bool(re.match(r'^\s*(?:[A-Za-z_]\w*\s*\+|(?:f|fr|rf)[\"\']|[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*\s*\()', value))


def quoted_literals(line):
    """Return exact, unescaped whole literals and their preceding source text."""
    i = 0
    while i < len(line):
        if line[i] == '#' or line[i:i+2] in ('//', '/*'):
            break
        if line[i] not in ('"', "'"):
            i += 1
            continue
        start, quote = i, line[i]
        i += 1
        escaped = False
        while i < len(line) and line[i] != quote:
            if line[i] == '\\':
                escaped = True
                i += 2
            else:
                i += 1
        if i >= len(line):
            break
        value, prefix, suffix = line[start+1:i], line[:start], line[i+1:]
        i += 1
        dynamic = bool(prefix and (prefix[-1].isalnum() or prefix[-1] in '_@$'))
        if escaped or dynamic or prefix.rstrip().endswith('+') or suffix.lstrip().startswith('+'):
            continue
        if 1 <= len(value) <= 500 and not any(c in value for c in '{}<>[]\\'):
            yield value, prefix


def candidates(references):
    """Only HTTP(S) literals or network-context host/IP literals, at most 16.

Filenames, path templates, credentials, URL userinfo/query/fragment and decoded
or assembled indicators remain outside this narrow vocabulary. Missing does
not mean benign. A returned value is still only a static candidate.
"""
    result = []
    for ref in references:
        text = ref['quote']
        if len(text) > 4800 or '\"\"\"' in text or "'''" in text or '/*' in text or '*/' in text:
            continue
        for offset, line in enumerate(text.splitlines()):
            for value, prefix in quoted_literals(line):
                if '__PRIVATE_LITERAL_' in value or PRIVATE.search(prefix):
                    continue
                kind = None
                if value.lower().startswith(('http://', 'https://')):
                    try:
                        url = urlsplit(value)
                        port = url.port  # validates malformed ports without network access
                        if url.hostname and not (url.username or url.password or url.query or url.fragment) and not re.search(r'\s', value):
                            kind = 'url'
                    except ValueError:
                        continue
                elif NETWORK.search(prefix):
                    if DOMAIN.fullmatch(value):
                        kind = 'hostname'
                    else:
                        try:
                            ipaddress.ip_address(value)
                            kind = 'ip'
                        except ValueError:
                            pass
                if kind and value not in {r['value'] for r in result}:
                    result.append({'value': value, 'kind': kind, 'evidence_id': ref['evidence_id'],
                                   'line': ref['line'] + offset, 'status': 'static_candidate_only'})
                if len(result) >= 16:
                    return result
    return result
