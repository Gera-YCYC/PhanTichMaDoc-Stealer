"""Static C# evidence for explicit table and field arguments on a local reader."""
import re

from .syntax_context import walk


METHODS = {"method_declaration", "constructor_declaration", "local_function_statement",
           "lambda_expression", "anonymous_method_expression"}
IDENT_LITERAL = re.compile(rb'"([a-zA-Z_][a-zA-Z_0-9]{0,63})"')
ORDINAL = re.compile(rb"0|[1-9][0-9]{0,3}")


def enclosing_blocks(node):
    blocks = []
    while node and node.type not in METHODS:
        if node.type == "block":
            blocks.append(node)
        node = node.parent
    return blocks


def table_fields(calls):
    """Yield paired sites only. The body of a custom GetValue helper is not modeled."""
    selections = {}
    for call in calls:
        member = call.child_by_field_name("function")
        args = call.child_by_field_name("arguments")
        if member is None or member.type != "member_access_expression" or not args:
            continue
        receiver = member.child_by_field_name("expression")
        method = member.child_by_field_name("name")
        if receiver is None or receiver.type != "identifier" or method is None:
            continue
        blocks = enclosing_blocks(call)
        if not blocks:
            continue
        key = (blocks[-1].id, receiver.text)
        if method.text == b"ReadTable":
            selections.pop(key, None)
            arg = args.named_children
            if len(arg) != 1 or call.parent.type != "expression_statement" or call.parent.parent != blocks[0]:
                continue
            table = IDENT_LITERAL.fullmatch(arg[0].text)
            if table:
                selections[key] = (call, blocks[0], table[1].decode("ascii"))
            continue
        if method.text != b"GetValue" or key not in selections:
            continue
        select, block, table = selections[key]
        arguments = args.named_children
        if len(arguments) != 2 or block not in blocks or len(arguments[0].named_children) != 1:
            continue
        if arguments[0].text != arguments[0].named_children[0].text:
            continue
        literal = IDENT_LITERAL.fullmatch(arguments[1].text)
        ordinal = ORDINAL.fullmatch(arguments[1].text)
        if not literal and not ordinal:
            continue
        # Require a preceding direct local construction in the table selection's
        # block. Do not resolve fields, parameters, casts or arbitrary factories.
        decl = None
        for statement in block.named_children:
            if statement.end_byte > select.start_byte:
                break
            if statement.type != "local_declaration_statement":
                continue
            for declarator in (n for n in walk(statement) if n.type == "variable_declarator"):
                name = declarator.child_by_field_name("name")
                if name and name.text == receiver.text:
                    init = declarator.named_children[-1]
                    if init.type == "object_creation_expression":
                        type_node = init.child_by_field_name("type")
                        if type_node and type_node.text.lower() in {b"sqlite", b"sqlitehandler"}:
                            decl = declarator
        if decl is None:
            continue
        # Reject visible rebinding and alias-by-reference before the field call.
        invalid = False
        for n in walk(block):
            if not decl.end_byte <= n.start_byte < call.start_byte:
                continue
            target = n.child_by_field_name("left") if n.type == "assignment_expression" else None
            name = n.child_by_field_name("name") if n.type in {"variable_declarator", "parameter"} else None
            if (target and target.text == receiver.text or name and name.text == receiver.text
                    or n.type == "argument" and n.text.split() in ([b"ref", receiver.text], [b"out", receiver.text])):
                invalid = True
                break
        if invalid:
            continue
        operation = "reader_named_field" if literal else "reader_ordinal_field"
        yield {"operation": operation, "api": "local.ReadTable/GetValue",
               "inputs": {"table": table, "column": (literal[1] if literal else ordinal[0]).decode("ascii")},
               "result": {"meaning": "static_named_argument" if literal else "static_ordinal_only"},
               "binding": "direct_local_constructor_and_preceding_table_call_in_enclosing_block",
               "source_ranges": [(n.start_point.row + 1, n.end_point.row + 1) for n in (decl, select, call)]}
