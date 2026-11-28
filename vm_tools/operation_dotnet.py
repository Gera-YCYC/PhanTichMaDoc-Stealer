"""Narrow C# lexical binding for WebClient uploads and their response decoding."""
from tree_sitter import Language, Parser
import tree_sitter_c_sharp
from .syntax_context import walk
from .table_access import table_fields
from .catch_arguments import catch_messages


def text(node):
    return node.text.decode('utf-8') if node else ''


def ancestor(node, kind):
    parent = node.parent
    while parent:
        if parent.type in kind:
            return parent
        parent = parent.parent
    return None


def span(node):
    return node.start_point.row+1, node.end_point.row+1


def intact_method_fields(root):
    """Recover only local reader pairs in complete methods of a partially parsed unit."""
    results = []
    for method in walk(root):
        if method.type != "method_declaration" or method.has_error:
            continue
        members = method.parent
        if members.type != "declaration_list" or members.parent.type not in {"class_declaration", "struct_declaration"}:
            continue
        body = method.child_by_field_name("body")
        if body is None or body.type != "block":
            continue
        if any(node.children[0].type != "{" or node.children[-1].type != "}"
               or node.children[0].is_missing or node.children[-1].is_missing for node in (body, members)):
            continue
        allowed = {"declaration_list", "class_declaration", "struct_declaration", "namespace_declaration",
                   "file_scoped_namespace_declaration", "compilation_unit"}
        owner = members
        while owner and owner.type in allowed:
            owner = owner.parent
        if owner is None:
            calls = [n for n in walk(body) if n.type == "invocation_expression"]
            results.extend(table_fields(calls))
            results.extend(catch_messages(calls))
    return results


def candidates(source):
    tree = Parser(Language(tree_sitter_c_sharp.language())).parse(source)
    if tree.root_node.has_error:
        return intact_method_fields(tree.root_node)
    nodes = list(walk(tree.root_node))
    methods = {'method_declaration','constructor_declaration','local_function_statement'}
    def visible_import(call, directive):
        # A using inside a different namespace does not bind this call's short names.
        parent = call
        while parent:
            match = next((n for n in nodes if n.type == 'using_directive' and
                          n.parent == parent and n.text.strip() == directive), None)
            if match:
                return match
            parent = parent.parent
        return None
    declared_types = {text(n.child_by_field_name('name')) for n in nodes if n.type in
                      {'class_declaration','struct_declaration','interface_declaration','enum_declaration'}}
    # A using alias can change which type a short name denotes.
    aliases = {text(n.named_children[0]) for n in nodes if n.type == 'using_directive' and b'=' in n.text and n.named_children}
    value_names = {text(n.child_by_field_name('name')) for n in nodes if n.type in {'variable_declarator','parameter'}}
    assignments = [n for n in nodes if n.type == 'assignment_expression']
    declarations = [n for n in nodes if n.type == 'variable_declarator']

    def same_owner(a, b):
        return ancestor(a, methods) == ancestor(b, methods)

    def visible_declaration(call, name):
        matches = [n for n in declarations if text(n.child_by_field_name('name')) == name and
                   same_owner(n, call) and n.end_byte < call.start_byte]
        if len(matches) != 1:
            return None
        decl = matches[0]
        block = ancestor(decl, {'block'})
        parent = call
        while parent and parent != block:
            parent = parent.parent
        if parent is None:
            return None
        if any(same_owner(a,call) and decl.end_byte < a.start_byte < call.start_byte and
               text(a.child_by_field_name('left')) == name for a in assignments):
            return None
        if any(n.type == 'argument' and same_owner(n, call) and
               decl.end_byte < n.start_byte < call.start_byte and text(n) in {'ref '+name, 'out '+name}
               for n in nodes):
            return None
        # Parameter shadowing/ambiguous field binding is not resolved here.
        if any(n.type == 'parameter' and text(n.child_by_field_name('name')) == name and
               same_owner(n,call) for n in nodes):
            return None
        return decl

    def result_name(call):
        parent = call.parent
        while parent and parent.type in {'equals_value_clause','parenthesized_expression','cast_expression'}:
            parent = parent.parent
        if parent and parent.type == 'variable_declarator':
            return text(parent.child_by_field_name('name'))
        if parent and parent.type == 'assignment_expression' and parent.child_by_field_name('right') == call:
            return text(parent.child_by_field_name('left'))
        return None

    results, upload_returns = [], {}
    calls = sorted((n for n in nodes if n.type == 'invocation_expression'), key=lambda n:n.start_byte)
    for call in calls:
        if ancestor(call, methods) is None:
            continue
        function = call.child_by_field_name('function')
        args = call.child_by_field_name('arguments')
        if not function or not args:
            continue
        arguments = [text(n).strip() for n in args.named_children if n.type == 'argument']
        if any(len(a) > 240 for a in arguments):
            continue
        if any(n.child_by_field_name('name') is not None for n in args.named_children):
            continue
        api = text(function)
        if function.type == 'member_access_expression' and text(function.child_by_field_name('name')) == 'UploadFile':
            receiver = function.child_by_field_name('expression')
            if not receiver or receiver.type != 'identifier' or len(arguments) != 2:
                continue
            decl = visible_declaration(call, text(receiver))
            if not decl:
                continue
            creations = [n for n in walk(decl) if n.type == 'object_creation_expression']
            if len(creations) != 1:
                continue
            typename = text(creations[0].child_by_field_name('type'))
            net_import = visible_import(call, b'using System.Net;')
            if 'WebClient' in declared_types or not (typename in {'System.Net.WebClient','global::System.Net.WebClient'} or
                    typename == 'WebClient' and net_import and 'WebClient' not in declared_types | aliases):
                continue
            if typename == 'System.Net.WebClient' and 'System' in aliases | value_names:
                continue
            binding_ranges = [span(net_import)] if typename == 'WebClient' else []
            target = result_name(call)
            item = {'operation':'file_upload', 'api':'System.Net.WebClient.UploadFile(String,String)',
                    'inputs':{'address_expression':arguments[0], 'file_path_expression':arguments[1]},
                    'result':{'meaning':'response_body_bytes', 'assigned_expression':target},
                    'binding':'unique_visible_local_WebClient_constructor_no_intervening_assignment',
                    'source_ranges':[*binding_ranges,span(decl),span(call)]}
            results.append(item)
            if target and target.isidentifier():
                upload_returns[(ancestor(call, methods).id, target)] = (call, item)
        elif api in {'Encoding.ASCII.GetString', 'System.Text.Encoding.ASCII.GetString',
                     'global::System.Text.Encoding.ASCII.GetString'} and len(arguments) == 1:
            text_import = visible_import(call, b'using System.Text;')
            if api == 'Encoding.ASCII.GetString' and (not text_import or 'Encoding' in declared_types | aliases | value_names):
                continue
            if api == 'System.Text.Encoding.ASCII.GetString' and 'System' in aliases | value_names:
                continue
            owner = ancestor(call, methods)
            prior = upload_returns.get((owner.id, arguments[0])) if owner else None
            if not prior:
                continue
            previous, upload = prior
            if any(same_owner(a,call) and previous.end_byte < a.start_byte < call.start_byte and
                   text(a.child_by_field_name('left')) == arguments[0] for a in assignments):
                continue
            if any(n.type == 'argument' and same_owner(n,call) and
                   previous.end_byte < n.start_byte < call.start_byte and
                   text(n) in {'ref '+arguments[0], 'out '+arguments[0]} for n in nodes):
                continue
            # Require the return assignment and decoder in the same lexical block.
            if ancestor(previous, {'block'}) != ancestor(call, {'block'}):
                continue
            results.append({'operation':'response_text_decode', 'api':'System.Text.Encoding.ASCII.GetString',
                            'inputs':{'response_bytes_expression':arguments[0]},
                            'result':{'meaning':'ASCII_text_not_cryptographic_decryption','assigned_expression':result_name(call)},
                            'binding':'same_block_unreassigned_UploadFile_return',
                            'source_ranges':[*upload['source_ranges'],
                                             *([span(text_import)] if api == 'Encoding.ASCII.GetString' else []),span(call)]})
    results.extend(table_fields(calls))
    results.extend(catch_messages(calls))
    return results
