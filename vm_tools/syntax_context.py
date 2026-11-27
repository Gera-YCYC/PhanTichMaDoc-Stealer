"""Bounded source navigation using syntax, never execution or semantic binding.

Returned links are unique-name local-call CANDIDATES. Overloads, virtual dispatch,
aliases and reassignment require independent analysis; no dataflow is inferred.
"""
from __future__ import annotations

from collections import defaultdict
import hashlib

from tree_sitter import Language, Parser
import tree_sitter_c_sharp
import tree_sitter_python

BACKEND = 'tree-sitter-context/3'
CODE_TOOLS = {'decompile_dotnet', 'decompile_python', 'decode_python_literals'}


def walk(node, limit=200_000):
    pending, seen = [node], 0
    while pending:
        current = pending.pop()
        seen += 1
        if seen > limit:
            raise ValueError('Syntax node limit exceeded')
        yield current
        pending.extend(reversed(current.named_children))


def reconstruct(record):
    if record.get('status') != 'ok' or record.get('tool') not in CODE_TOOLS:
        raise ValueError('Syntax navigation requires successful recovered/decompiled source')
    rows = record['lines']
    if not rows or len(rows) > 16000 or [r['line'] for r in rows] != list(range(1, len(rows)+1)):
        raise ValueError('Expected complete immutable evidence lines')
    text, mapping = {}, defaultdict(list)
    for row in rows:
        n = row['source_line']
        if type(n) is not int or n < 1:
            raise ValueError('Missing original source line')
        text[n] = text.get(n, '') + row['text']
        mapping[n].append(row['line'])
    if sorted(text) != list(range(1, max(text)+1)):
        raise ValueError('Original source has gaps')
    if record['tool'] == 'decode_python_literals':
        # Two candidates cannot be treated as one module or linked to each other.
        if sum(t.startswith('# CANDIDATE ') for t in text.values()) != 1:
            raise ValueError('Syntax links require exactly one decoded candidate')
        text[1] = ''
        text[2] = ''
    source = '\n'.join(text[n] for n in sorted(text)).encode('utf-8')
    if len(source) > 2_000_000:
        raise ValueError('Source byte limit exceeded')
    return source, mapping


def index_source(record):
    source, mapping = reconstruct(record)
    language = 'csharp' if record['tool'] == 'decompile_dotnet' else 'python'
    module = tree_sitter_c_sharp if language == 'csharp' else tree_sitter_python
    tree = Parser(Language(module.language())).parse(source)
    function_types = {'method_declaration', 'constructor_declaration', 'local_function_statement'} if language == 'csharp' else {'function_definition'}
    call_type = 'invocation_expression' if language == 'csharp' else 'call'
    functions, calls = [], []
    def enclosing_class(node):
        parent = node.parent
        while parent:
            if parent.type in {'class_declaration', 'struct_declaration'}:
                name = parent.child_by_field_name('name')
                return name.text.decode('utf-8') if name else None
            parent = parent.parent
        return None
    for node in walk(tree.root_node):
        if node.type in function_types and not node.has_error:
            name = node.child_by_field_name('name')
            body = node.child_by_field_name('body')
            if name and body:
                functions.append({'node': node, 'name': name.text.decode('utf-8'),
                                  'start': node.start_point.row+1, 'end': node.end_point.row+1,
                                  'class': enclosing_class(node),
                                  'static': any(c.type == 'modifier' and c.text == b'static' for c in node.children)})
        elif node.type == call_type and not node.has_error:
            target = node.child_by_field_name('function')
            arguments = node.child_by_field_name('arguments')
            argument_count = len(arguments.named_children) if arguments else 0
            # Unqualified calls only. obj.method() is not bound without type analysis.
            if target and target.type == 'identifier':
                calls.append({'name': target.text.decode('utf-8'), 'line': node.start_point.row+1,
                              'qualifier': None, 'argument_count': argument_count})
            elif language == 'csharp' and target and target.type == 'member_access_expression':
                qualifier, name = target.child_by_field_name('expression'), target.child_by_field_name('name')
                if qualifier and name and qualifier.type in {'identifier', 'this_expression'} and name.type == 'identifier':
                    calls.append({'name': name.text.decode('utf-8'), 'line': node.start_point.row+1,
                                  'qualifier': qualifier.text.decode('utf-8'), 'argument_count': argument_count})
    by_name = defaultdict(list)
    for item in functions:
        by_name[item['name']].append(item)
    links = []
    for call in calls:
        targets = by_name[call['name']]
        if len(targets) != 1:
            continue
        owners = [f for f in functions if f['start'] <= call['line'] <= f['end']]
        owner = min(owners, key=lambda f:f['end']-f['start']) if owners else None
        # Nested Python definitions/local C# functions have lexical scope. Skip
        # possible targets nested in a function other than their own caller.
        target = targets[0]
        if call['qualifier'] is not None and not (
                target['static'] and call['qualifier'] == target['class'] or
                call['qualifier'] == 'this' and owner and owner['class'] == target['class']):
            continue
        containers = [f for f in functions if f is not target and f['start'] < target['start'] <= f['end']]
        if containers and owner not in containers:
            continue
        links.append({'caller': owner, 'callee': target, 'call_line': call['line'],
                      'argument_count': call['argument_count']})
    return {'source_sha256': hashlib.sha256(source).hexdigest(), 'mapping': mapping,
            'functions': functions, 'links': links, 'has_parse_errors': tree.root_node.has_error,
            'language': language}


def related_contexts(record, anchors, *, max_links=2, max_chars=5800):
    if not 1 <= max_links <= 3 or not 100 <= max_chars <= 6000:
        raise ValueError('Invalid syntax navigation budget')
    index = index_source(record)
    rows = {r['line']: r for r in record['lines']}
    source_anchors = [rows[n]['source_line'] for n in anchors if n in rows]
    owners = []
    for anchor in source_anchors:
        enclosing = [f for f in index['functions'] if f['start'] <= anchor <= f['end']]
        if enclosing:
            owner = min(enclosing, key=lambda f: f['end']-f['start'])
            if owner not in owners:
                owners.append(owner)
    candidates = [link for link in index['links'] if link['caller'] in owners or link['callee'] in owners]
    candidates.sort(key=lambda link: (link['callee'] not in owners,
                                      min(abs(link['call_line']-a) for a in source_anchors), link['call_line']))
    selected, result, used = {}, [], 0
    # A pooled sort let one owner consume both slots, even when the query had
    # hits in two functions. Reserve one bounded attempt per distinct owner.
    # A large inbound caller pack can fall back to a smaller outgoing pair.
    # Then release unused budget; no source is invented to fill a reservation.
    reserved = owners[:max_links]
    attempts = []
    if len(reserved) > 1:
        for number, owner in enumerate(reserved):
            local = [link for link in candidates if link['caller'] is owner or link['callee'] is owner]
            local.sort(key=lambda link: (link['callee'] is not owner,
                min(abs(link['call_line']-a) for a in source_anchors), link['call_line']))
            attempts.extend((link, max_chars//len(reserved), number) for link in local)
    attempts.extend((link, max_chars, None) for link in candidates)
    served, chosen = set(), set()

    def excerpt(start, end):
        numbers = [n for s in range(start, end+1) for n in index['mapping'].get(s, [])]
        if not numbers or len(numbers) > 40:
            return None
        quote = '\n'.join(rows[n]['text'] for n in numbers)
        if len(quote) > 4800:
            return None
        return {'line': numbers[0], 'end_line': numbers[-1]}, numbers

    for link, allowance, owner_number in attempts:
        if id(link) in chosen or owner_number in served:
            continue
        target, caller, call_line = link['callee'], link['caller'], link['call_line']
        # A full small callee is substantially more useful than its signature.
        # Large functions stay explicitly partial; never imply complete coverage.
        target_end = min(target['end'], target['start']+35)
        caller_start = max(caller['start'] if caller else 1, call_line-10)
        caller_end = min(caller['end'] if caller else max(index['mapping']), call_line+5)
        pieces = [excerpt(caller_start, caller_end), excerpt(target['start'], target_end)]
        if any(p is None for p in pieces):
            continue
        # First prefer a small helper called WITH arguments inside the displayed
        # callee. This exposes transformations hidden behind a function name.
        # Zero-argument helpers (e.g. display-name setup) do not displace a nearby
        # preparation helper. This is only a navigation heuristic, not def-use proof.
        dependencies = [other for other in index['links'] if other['caller'] is target and
                        other['callee'] is not target and other['callee'] is not caller and
                        other['argument_count'] > 0 and target['start'] <= other['call_line'] <= target_end]
        related_kind = None
        related_call_line = None
        for other in sorted(dependencies, key=lambda x:x['call_line']):
            f = other['callee']
            extra = excerpt(f['start'], f['end']) if f['end']-f['start'] < 35 else None
            if extra:
                pieces.append(extra)
                related_kind = 'callee_dependency_candidate_not_dataflow_proof'
                related_call_line = index['mapping'][other['call_line']][0]
                break
        # Fall back to a nearby helper called by the same caller. This can
        # expose archive construction before a send call without asserting a flow.
        neighbors = [other for other in index['links'] if other is not link and other['caller'] is caller
                     and caller_start <= other['call_line'] <= caller_end and other['callee'] is not target]
        for other in ([] if len(pieces)==3 else sorted(neighbors, key=lambda x:abs(x['call_line']-call_line))[:1]):
            f = other['callee']
            extra = excerpt(f['start'], f['end']) if f['end']-f['start'] < 30 else None
            if extra:
                pieces.append(extra)
                related_kind = 'caller_neighbor_candidate_not_dataflow_proof'
                related_call_line = index['mapping'][other['call_line']][0]
        numbers = sorted({n for _, ns in pieces for n in ns})
        cost = sum(len(rows[n]['text'])+50 for n in numbers if n not in selected)
        if used+cost > max_chars or cost > allowance:
            if owner_number is not None and related_kind == 'callee_dependency_candidate_not_dataflow_proof':
                # Try the direct call/helper pair before dropping the very
                # implementation the reserved owner needs to inspect.
                continue
            # The optional neighbor can be omitted, never the caller/callee pair.
            pieces = pieces[:2]
            related_kind = None
            related_call_line = None
            numbers = sorted({n for _, ns in pieces for n in ns})
            cost = sum(len(rows[n]['text'])+50 for n in numbers if n not in selected)
        if used+cost > max_chars or cost > allowance:
            continue
        selected.update({n: rows[n] for n in numbers})
        used += cost
        chosen.add(id(link))
        if owner_number is not None:
            served.add(owner_number)
        result.append({'call_line': index['mapping'][call_line][0],
                       'ranges': [r for r, _ in pieces], 'callee_complete': target_end == target['end'],
                       'related_context_kind': related_kind, 'related_call_line': related_call_line,
                       'relation': 'unique_name_local_call_candidate_not_semantic_binding'})
        if len(result) >= max_links:
            break
    return {'lines': [selected[n] for n in sorted(selected)], 'context_links': result,
            'syntax_context': {'backend': BACKEND, 'language': index['language'],
                               'anchor_owner_count': len(owners), 'reserved_owner_count': len(reserved),
                               'context_chars_used': used, 'context_chars_limit': max_chars,
                               'source_sha256': index['source_sha256'], 'has_parse_errors': index['has_parse_errors'],
                               'function_count': len(index['functions']), 'candidate_link_count': len(index['links']),
                               'scope': 'Syntactic navigation only; no alias/type resolution, execution or dataflow proof'}}
