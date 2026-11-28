"""Recognize a restricted Python archive-path to MIME attachment flow in static source.

Return coordinates only. Accept direct positional calls between unique top-level
functions. A successful API call or message delivery is never inferred.
"""

import ast
from collections import Counter
from hashlib import sha256
from stealer_agent.journal import canonical
from .syntax_context import reconstruct


def name(node):
    return node.id if isinstance(node, ast.Name) else None


def assigned(stmt):
    return (
        name(stmt.targets[0])
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1
        else None
    )


def writes(tree, var):
    return sum(
        isinstance(n, ast.Name)
        and n.id == var
        and isinstance(n.ctx, (ast.Store, ast.Del))
        for n in ast.walk(tree)
    )


def path_parts(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [("str", node.value)]
    if name(node):
        return [("name", name(node))]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        a, b = path_parts(node.left), path_parts(node.right)
        if a and b:
            return a + b
    return []


def zip_path_eq(base, result):
    a, b = path_parts(base), path_parts(result)
    if a and a[-1][0] == "str":
        return b == a[:-1] + [("str", a[-1][1] + ".zip")]
    return bool(a and b == a + [("str", ".zip")])


def preserves_path(stmts, base):
    # A cleanup in the producer must not replace/remove the same static path.
    for stmt in stmts:
        if isinstance(stmt, ast.Pass):
            continue
        if (
            not isinstance(stmt, ast.Try)
            or stmt.finalbody
            or stmt.orelse
            or not stmt.handlers
        ):
            return False
        if any(not all(isinstance(s, ast.Pass) for s in h.body) for h in stmt.handlers):
            return False
        for s in stmt.body:
            call = getattr(s, "value", None)
            if not (member(call, "remove", "os") and len(call.args) == 1 and base):
                return False
            path = path_parts(call.args[0])
            if (
                not path
                or path[:-1] != base[:-1]
                or path[-1][0] != "str"
                or base[-1][0] != "str"
            ):
                return False
            if path[-1][1].casefold() == base[-1][1].casefold() or any(
                x in path[-1][1] for x in ("..", "~")
            ):
                return False
    return True


def member(node, method, receiver=None):
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == method
        and isinstance(node.func.value, ast.Name)
        and (receiver is None or name(node.func.value) == receiver)
        and not node.keywords
        and not any(isinstance(arg, ast.Starred) for arg in node.args)
    )


def find_witness(record, facts, visible):
    if record["tool"] not in (
        "decompile_python",
        "decode_python_literals",
        "python_ast",
    ):
        return None
    source, mapping = reconstruct(record)
    tree = ast.parse(source)
    nodes = list(ast.walk(tree))
    if len(nodes) > 100000 or any(
        isinstance(n, (ast.Global, ast.Nonlocal)) for n in nodes
    ):
        return None
    bound = Counter(
        n.name
        for n in nodes
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    )
    bound.update(n.arg for n in nodes if isinstance(n, ast.arg))
    bound.update(
        n.id
        for n in nodes
        if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del))
    )
    bound.update(
        a.asname or a.name.split(".")[0]
        for n in nodes
        if isinstance(n, (ast.Import, ast.ImportFrom))
        for a in n.names
    )
    if bound["open"] or bound["*"]:
        return None
    funcs = {
        n.name: n
        for n in tree.body
        if isinstance(n, ast.FunctionDef)
        and bound[n.name] == 1
        and not n.decorator_list
        and not n.args.kwarg
        and not n.args.vararg
        and not n.args.posonlyargs
        and not n.args.kwonlyargs
    }
    by_op = {
        (f["operation"], record["lines"][f["ranges"][-1]["line"] - 1]["source_line"])
        for f in facts
    }

    def typed(op, stmt):
        return (op, stmt.lineno) in by_op

    producers = {}
    for fn in funcs.values():
        if (
            len(fn.body) > 64
            or len([n for n in ast.walk(fn) if isinstance(n, ast.Return)]) != 1
        ):
            continue
        last = fn.body[-1]
        if (
            not isinstance(last, ast.Return)
            or not name(last.value)
            or writes(fn, name(last.value)) != 1
        ):
            continue
        var = last.value.id
        for stmt in fn.body[:-1]:
            call = getattr(stmt, "value", None)
            if (
                not typed("archive_create", stmt)
                or not isinstance(call, ast.Call)
                or len(call.args) < 2
            ):
                continue
            after = fn.body[fn.body.index(stmt) + 1 : -1]
            if assigned(stmt) == var and preserves_path(after, []):
                producers[fn.name] = (fn, stmt, stmt, last)
                break
            if (
                not isinstance(call.args[1], ast.Constant)
                or call.args[1].value != "zip"
            ):
                continue
            for build in fn.body:
                if (
                    build.lineno < stmt.lineno
                    and assigned(build) == var
                    and zip_path_eq(call.args[0], build.value)
                    and preserves_path(after, path_parts(build.value))
                    and all(
                        not writes(fn, s)
                        for kind, s in path_parts(call.args[0])
                        if kind == "name"
                    )
                ):
                    producers[fn.name] = (fn, build, stmt, last)
    for caller in [tree, *funcs.values()]:
        # Separate lexical lists prevent matches across branches or other functions.
        blocks = [caller.body]
        if caller is tree:
            blocks.extend(n.body for n in tree.body if isinstance(n, ast.If))
        for block in blocks:
            for i, stmt in enumerate(block):
                var = assigned(stmt)
                if (
                    not var
                    or not isinstance(stmt.value, ast.Call)
                    or name(stmt.value.func) not in producers
                ):
                    continue
                maker, build, archive, ret = producers[name(stmt.value.func)]
                if (
                    stmt.value.keywords
                    or any(isinstance(a, ast.Starred) for a in stmt.value.args)
                    or not len(maker.args.args) - len(maker.args.defaults)
                    <= len(stmt.value.args)
                    <= len(maker.args.args)
                ):
                    continue
                for use in block[i + 1 : i + 20]:
                    call = getattr(use, "value", None)
                    if (
                        isinstance(use, ast.Expr)
                        and isinstance(call, ast.Call)
                        and name(call.func) in funcs
                        and not call.keywords
                        and not any(isinstance(a, ast.Starred) for a in call.args)
                    ):
                        target = funcs[name(call.func)]
                        indices = [j for j, x in enumerate(call.args) if name(x) == var]
                        if len(indices) == 1 and len(call.args) == len(
                            target.args.args
                        ):
                            param = target.args.args[indices[0]].arg
                            trail = attachment(target, param, typed)
                            if trail:
                                points = [
                                    ("helper_archive", maker),
                                    ("path", build),
                                    ("archive", archive),
                                    ("return", ret),
                                    ("caller_result", stmt),
                                    ("caller_argument", use),
                                    ("helper_attachment", target),
                                    *trail,
                                ]
                                roles = [
                                    {"role": role, "line": mapping[node.lineno][0]}
                                    for role, node in points
                                ]
                                if not visible.intersection(x["line"] for x in roles):
                                    continue
                                body = {
                                    "kind": "archive-message",
                                    "backend": "static-attachment-path/1",
                                    **{
                                        k: record[k]
                                        for k in (
                                            "evidence_id",
                                            "sample_sha256",
                                            "output_sha256",
                                        )
                                    },
                                    "roles": roles,
                                }
                                return {
                                    **body,
                                    "proof_id": "flow_"
                                    + sha256(canonical(body)).hexdigest()[:16],
                                }
                    # Only literal assignments or no-ops may intervene in the caller.
                    if not (
                        isinstance(use, ast.Pass)
                        or assigned(use)
                        and assigned(use) != var
                        and isinstance(use.value, ast.Constant)
                    ):
                        break
    return None


def attachment(fn, param, typed):
    if writes(fn, param):
        return None
    for i, block in enumerate(fn.body):
        if not isinstance(block, ast.With) or len(block.items) != 1:
            continue
        item = block.items[0]
        opened = item.context_expr
        handle = name(item.optional_vars)
        if (
            not handle
            or writes(fn, handle) != 1
            or not isinstance(opened, ast.Call)
            or name(opened.func) != "open"
            or len(opened.args) != 2
            or opened.keywords
            or name(opened.args[0]) != param
            or not isinstance(opened.args[1], ast.Constant)
            or opened.args[1].value != "rb"
        ):
            continue
        for setter in block.body:
            call = getattr(setter, "value", None)
            if not (
                typed("mime_set_payload", setter)
                and member(call, "set_payload")
                and len(call.args) == 1
                and member(call.args[0], "read", handle)
                and not call.args[0].args
            ):
                continue
            part = name(call.func.value)
            if writes(fn, part) != 1 or setter is not block.body[-1]:
                continue
            for j, stmt in enumerate(fn.body[i + 1 : i + 8], i + 1):
                value = getattr(stmt, "value", None)
                if (
                    typed("mime_attach", stmt)
                    and member(value, "attach")
                    and len(value.args) == 1
                    and name(value.args[0]) == part
                ):
                    msg = name(value.func.value)
                    if writes(fn, msg) == 1 and j + 1 < len(fn.body):
                        serial = fn.body[j + 1]
                        if typed("mime_serialize", serial) and member(
                            getattr(serial, "value", None), "as_string", msg
                        ):
                            return [
                                ("open_argument", block),
                                ("read_to_payload", setter),
                                ("attach", stmt),
                                ("serialize", serial),
                            ]
                    break
                # Allow standard transfer encoding or attachment header metadata
                # only. A later set_payload/reassignment would invalidate the link.
                if not (
                    isinstance(stmt, ast.Expr)
                    and (
                        typed("mime_base64_encode", stmt)
                        or member(value, "add_header", part)
                        and all(
                            not isinstance(n, ast.Call)
                            or n is value
                            or isinstance(n.func, ast.Attribute)
                            and n.func.attr == "basename"
                            for n in ast.walk(value)
                        )
                    )
                ):
                    break
    return None
