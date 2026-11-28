"""Identify the caught variable supplying a message at one C# call site."""
import re

from .syntax_context import walk


TARGET = re.compile(rb"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*){0,4}")
# A surrounding delimiter can format the message. Substantive literals or
# additional variables change what the argument contains and need another check.
DELIMITER = re.compile(rb'"[ \t.,:;!?~\x60_()/\[\]{}<>-]{0,12}"')


def message_terms(expr, name):
    if expr.type == "member_access_expression" and expr.text == name + b".Message":
        return 1
    if expr.type == "string_literal" and DELIMITER.fullmatch(expr.text):
        return 0
    if expr.type == "binary_expression" and expr.child_by_field_name("operator").text == b"+":
        left = message_terms(expr.child_by_field_name("left"), name)
        right = message_terms(expr.child_by_field_name("right"), name)
        if left is not None and right is not None:
            return left + right
    return None


def catch_messages(calls):
    for call in calls:
        statement = call.parent
        if statement.type != "expression_statement" or statement.parent.type != "block":
            continue
        body = statement.parent
        clause = body.parent
        if clause.type != "catch_clause" or clause.child_by_field_name("body") != body:
            continue
        # Filters can alter bindings before the body is entered.
        if [n.type for n in clause.named_children] != ["catch_declaration", "block"]:
            continue
        declaration = clause.named_children[0]
        variable = declaration.child_by_field_name("name")
        target = call.child_by_field_name("function")
        if (not variable or not re.fullmatch(rb"[A-Za-z_]\w{0,63}", variable.text)
                or not target or not TARGET.fullmatch(target.text) or len(target.text) > 100):
            continue
        arguments = call.child_by_field_name("arguments").named_children
        if len(arguments) != 1 or len(arguments[0].named_children) != 1:
            continue
        expr = arguments[0].named_children[0]
        if len(expr.text) > 240 or expr.text != arguments[0].text or message_terms(expr, variable.text) != 1:
            continue
        # Includes assignments, ref/out, aliases and captures before this site.
        if any(n.type == "identifier" and n.text == variable.text and n.start_byte < call.start_byte
               for n in walk(body)):
            continue
        yield {"operation": "catch_message_argument", "api": "CSharp.catch.member_argument",
               "inputs": {"call": target.text.decode("ascii"), "variable": variable.text.decode("utf8")},
               "result": {"meaning": "handler_argument_only"},
               "binding": "direct_catch_statement_uses_original_catch_variable_message",
               "source_ranges": [(n.start_point.row + 1, n.end_point.row + 1) for n in (declaration, call)]}
