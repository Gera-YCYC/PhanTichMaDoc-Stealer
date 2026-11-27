"""Evidence navigation only: structural features never determine maliciousness.

The optional learned ranker is trained on code-reference relevance, not verdicts.
All returned offsets still point into the immutable tool output.
"""
from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
import re

FEATURES = ('query_in_code', 'query_in_literal', 'call_on_line', 'assignment_on_line',
            'opcode_use', 'opcode_import', 'table_entry', 'declaration', 'comment',
            'calls_nearby', 'opcodes_nearby', 'query_count_nearby', 'import_context')
VERSION = 'code-reference-features/1'
MODEL_PATH = Path(__file__).with_name('code_ranker.json')
_STRING = re.compile(r'@?"(?:""|\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')
_CALL = re.compile(r'\b[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*\s*\(')
_OPCODE = re.compile(r'^\s*\d+\s+(?:[A-Z][A-Z_0-9]+)\b')
_USE = re.compile(r'^\s*\d+\s+(?:LOAD_(?:GLOBAL|NAME|ATTR|METHOD)|STORE_(?:NAME|GLOBAL|ATTR))\b')
_IMPORT = re.compile(r'^\s*\d+\s+IMPORT_(?:NAME|FROM)\b')
_DECL = re.compile(r'^\s*(?:(?:public|private|protected|internal|static|override|virtual|sealed|async)\s+)+.*\(')


def structural_features(lines, index, query):
    text = lines[index]['text']
    folded = query.casefold()
    code = _STRING.sub('""', text).split('//', 1)[0]
    context = lines[max(0, index-3):index+7]
    declaration = bool(_DECL.search(text) or re.match(r'^\s*(?:def|class)\s', text))
    opcode = bool(_OPCODE.search(text))
    # pycdas tables use a numeric index and a quoted value, without an opcode.
    table = not opcode and bool(re.match(r'^\s*(?:\d+\s*[: ]\s*)?[\'"<]', text))
    return [float(v) for v in (
        folded in code.casefold(), folded in text.casefold() and folded not in code.casefold(),
        bool(_CALL.search(code)) and not declaration, bool(re.search(r'(?<![=!<>])=(?!=)', code)),
        bool(_USE.search(text)), bool(_IMPORT.search(text)), table, declaration,
        text.lstrip().startswith(('//', '#', '/*', '*')),
        min(5, sum(bool(_CALL.search(_STRING.sub('""', row['text']))) for row in context))/5,
        min(5, sum(bool(_OPCODE.search(row['text'])) for row in context))/5,
        min(5, sum(folded in row['text'].casefold() for row in context))/5,
        any(_IMPORT.search(row['text']) for row in lines[max(0,index-3):index+1]),
    )]


def candidates(record, query):
    return [{'index': i, 'line': row['line'], 'features': structural_features(record['lines'], i, query)}
            for i, row in enumerate(record['lines']) if query.casefold() in row['text'].casefold()]


def load_model():
    if not MODEL_PATH.is_file():
        return None
    raw = MODEL_PATH.read_bytes()
    model = json.loads(raw)
    if model.get('feature_version') != VERSION or model.get('features') != list(FEATURES):
        raise ValueError('Retrieval model feature contract mismatch')
    if len(model.get('weights', [])) != len(FEATURES) or any(
            not isinstance(n, (float, int)) or not math.isfinite(n)
            for n in [model.get('bias'), *model.get('weights', [])]):
        raise ValueError('Invalid retrieval model coefficients')
    return {**model, 'sha256': hashlib.sha256(raw).hexdigest()}


def rank(record, query, model=None):
    rows = candidates(record, query)
    if model is None:
        return rows
    for row in rows:
        score = model['bias'] + sum(w*x for w, x in zip(model['weights'], row['features']))
        row['score'] = round(1/(1+math.exp(-max(-40, min(40, score)))), 6)
    return sorted(rows, key=lambda row: (-row['score'], row['line']))


def select_contexts(record, query, model=None, max_contexts=3, max_chars=5200):
    ranked = rank(record, query, model)
    anchors = []
    for candidate in ranked:
        if all(abs(candidate['index']-other['index']) > 18 for other in anchors):
            anchors.append(candidate)
        if len(anchors) >= max_contexts:
            break
    groups, rows, used = [], {}, 0
    per_group = max_chars//max(1, len(anchors))
    for anchor in anchors:
        # Allocate around the hit, never consume the budget on a prefix and lose it.
        i, selected, cost = anchor['index'], [], 0
        order = [i] + [j for d in range(1, 19) for j in (i+d, i-d) if 0 <= j < len(record['lines'])]
        for index in order:
            row = record['lines'][index]
            size = len(row['text']) + 50
            if cost + size > per_group or used + size > max_chars:
                continue
            selected.append(index)
            cost += size
            used += size
        chosen = [record['lines'][j] for j in sorted(selected)]
        rows.update({r['line']:r for r in chosen})
        groups.append({'anchor_line': anchor['line'], 'lines':[r['line'] for r in chosen],
                       'score':anchor.get('score'), 'query':query})
    return [rows[k] for k in sorted(rows)], groups, len(ranked)
