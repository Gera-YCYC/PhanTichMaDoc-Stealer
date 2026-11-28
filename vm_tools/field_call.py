"""Navigate a simple C# receiver from an observed call to a local method body."""

from collections import defaultdict
from pathlib import Path
import json
import sys

from tree_sitter import Language, Parser
import tree_sitter_c_sharp

from .syntax_context import reconstruct, walk


def ancestor(node, kinds):
    parent = node.parent
    while parent is not None and parent.type not in kinds:
        parent = parent.parent
    return parent


def modifiers(node):
    return {c.text for c in node.named_children if c.type == "modifier"}


def candidates(tree, physical_line):
    """Return navigation candidates only. The parser does not bind a CLR call."""
    classes = defaultdict(list)
    calls = []
    for node in walk(tree.root_node):
        if node.type == "class_declaration":
            classes[node.child_by_field_name("name").text].append(node)
        if (
            node.type == "invocation_expression"
            and node.start_point.row + 1 == physical_line
        ):
            calls.append(node)
    for call in calls:
        target = call.child_by_field_name("function")
        if target.type != "member_access_expression":
            continue
        receiver = target.child_by_field_name("expression")
        method = target.child_by_field_name("name")
        if receiver.type != "identifier" or method.type != "identifier":
            continue
        caller = ancestor(call, {"method_declaration", "constructor_declaration"})
        if (
            caller is None
            or caller.has_error
            or call.end_point.row != call.start_point.row
        ):
            continue
        # A bare receiver must never be conflated with a parameter or local.
        # Accept uses as an ordinary member receiver; abstain for other uses.
        if any(
            n.type == "identifier"
            and n.text == receiver.text
            and not (
                n.parent.type == "member_access_expression"
                and n.parent.child_by_field_name("expression") == n
            )
            for n in walk(caller)
        ):
            continue
        owner = ancestor(caller, {"class_declaration", "struct_declaration"})
        if (
            owner is None
            or owner.type != "class_declaration"
            or b"partial" in modifiers(owner)
        ):
            continue
        body = owner.child_by_field_name("body")
        fields = []
        for field in body.named_children:
            if field.type != "field_declaration" or field.has_error:
                continue
            for decl in field.named_children:
                if decl.type != "variable_declaration":
                    continue
                for var in decl.named_children:
                    if (
                        var.type == "variable_declarator"
                        and var.child_by_field_name("name").text == receiver.text
                    ):
                        fields.append((field, decl, var))
        if len(fields) != 1:
            continue
        field, decl, var = fields[0]
        name = decl.child_by_field_name("type")
        init = var.named_children[-1]
        if name.type != "identifier" or init.type != "object_creation_expression":
            continue
        if (
            init.child_by_field_name("type").text != name.text
            or len(classes[name.text]) != 1
        ):
            continue
        cls = classes[name.text][0]
        # Use only simple sibling types in the same lexical namespace.
        if (
            cls.parent != owner.parent
            or b"partial" in modifiers(cls)
            or any(
                c.type in {"base_list", "type_parameter_list"}
                for c in cls.named_children
            )
        ):
            continue
        methods = [
            m
            for m in cls.child_by_field_name("body").named_children
            if m.type == "method_declaration"
            and m.child_by_field_name("name").text == method.text
        ]
        if len(methods) != 1:
            continue
        m = methods[0]
        if m.has_error or modifiers(m) & {
            b"virtual",
            b"abstract",
            b"override",
            b"static",
        }:
            continue
        args = call.child_by_field_name("arguments").named_children
        params = m.child_by_field_name("parameters").named_children
        if len(args) != len(params) or any(p.type != "parameter" for p in params):
            continue
        if not m.child_by_field_name("body") or any(
            c.type == "type_parameter_list" for c in m.named_children
        ):
            continue
        yield field, m


def inspect(record, line):
    if (
        record.get("tool") != "decompile_dotnet"
        or type(line) is not int
        or not 1 <= line <= len(record["lines"])
    ):
        raise ValueError("Expected a .NET evidence row")
    source, mapping = reconstruct(record)
    tree = Parser(Language(tree_sitter_c_sharp.language())).parse(source)
    physical = record["lines"][line - 1]["source_line"]
    hits = list(candidates(tree, physical))
    result = {
        "line": line,
        "status": "unresolved",
        "ranges": {},
        "lines": [record["lines"][line - 1]],
    }
    if len(hits) != 1 or len(mapping[physical]) != 1:
        return result
    field, method = hits[0]
    ranges = {"call": [line, line]}
    for role, node in (("field", field), ("method", method)):
        ranges[role] = [
            mapping[node.start_point.row + 1][0],
            mapping[node.end_point.row + 1][-1],
        ]
    numbers = sorted({n for low, high in ranges.values() for n in range(low, high + 1)})
    if len(numbers) > 40:
        return result
    rows = [record["lines"][n - 1] for n in numbers]
    if sum(len(r["text"]) for r in rows) > 4700:
        return result
    return {"line": line, "status": "source_candidate", "ranges": ranges, "lines": rows}


if __name__ == "__main__":
    path = Path(sys.argv[1])
    if not path.is_absolute() or path.stat().st_size > 5_000_000:
        raise SystemExit("Invalid analysis snapshot")
    print(json.dumps(inspect(json.loads(path.read_bytes()), int(sys.argv[2]))))
