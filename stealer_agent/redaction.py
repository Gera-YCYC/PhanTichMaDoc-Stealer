"""Best-effort local report redaction; public exports must still use allowlists.

Known literal values are removed everywhere, including prose repeated by an SLM.
This is a display transform only, never a change to audit evidence or model input.
"""
from __future__ import annotations

import ast
import re

from .security import redact

LITERAL = r'''(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')'''
ASSIGNMENT = re.compile(r'''["']?\b([A-Za-z_]\w*)["']?\s*(?:=|:)\s*(''' + LITERAL + r''')''')
LOGIN = re.compile(r'\.(?:login|authenticate)\s*\(\s*(' + LITERAL + r')\s*,\s*(' + LITERAL + r')', re.I)
SENSITIVE_NAME = re.compile(r'password|passwd|secret|token|apikey|credential|webhook|smtpuser|username|emailaddress|senderemail', re.I)
EMAIL = re.compile(r'(?<![\w.+-])[\w.+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![\w.-])')
MAX_TEXT = 512_000
MAX_TOTAL = 8_000_000


def string_values(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from string_values(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            yield from string_values(child)


def collect_literals(texts):
    found, total, truncated = set(), 0, False
    for text in texts:
        if not isinstance(text, str):
            continue
        remaining = max(0, MAX_TOTAL - total)
        limited = text[:min(MAX_TEXT, remaining)]
        truncated |= len(limited) != len(text)
        total += len(limited)
        if not remaining:
            break
        literals = []
        for match in ASSIGNMENT.finditer(limited):
            name = match[1].replace('_', '').lower()
            if SENSITIVE_NAME.search(name) or name in {'pwd', 'pass', 'email', 'sender', 'recipient', 'smtpemail', 'smtppass'}:
                literals.append(match[2])
        for match in LOGIN.finditer(limited):
            literals.extend((match[1], match[2]))
        for literal in literals:
            if len(literal) > 8192:
                truncated = True
                continue
            try:
                value = ast.literal_eval(literal)
            except (ValueError, SyntaxError):
                continue
            if isinstance(value, str) and value and value != '[REDACTED]':
                found.add(value)
    return found, truncated


def redact_document(document, *, context=()):
    """Return a new structure. Do not redact serialized JSON or mutate the input."""
    def candidates():
        yield from context
        yield from string_values(document)
    values, truncated = collect_literals(candidates())
    ordered = sorted(values, key=len, reverse=True)

    def transform(value):
        if isinstance(value, str):
            text = value
            for secret in ordered:
                text = text.replace(secret, '[REDACTED]')
            return EMAIL.sub('[REDACTED-EMAIL]', redact(text))
        if isinstance(value, dict):
            return {key: transform(child) for key, child in value.items()}
        if isinstance(value, list):
            return [transform(child) for child in value]
        return value

    return transform(document), {
        'method': 'known-literals-and-patterns/1',
        'detected_literal_count': len(values),
        'scan_truncated': truncated,
        'public_export_approved': False,
        'scope': 'Best-effort display only. Unknown, encoded or obfuscated credentials may remain. '
                 'Use allowlisted metadata receipts for publication; private evidence is unchanged.',
    }
