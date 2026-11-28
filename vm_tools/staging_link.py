"""Bounded static proof that a writer targets the archive's input directory.

Model paths symbolically. Return source coordinates, never filenames, dictionary
values, sample bytes or a prediction that the write/archive actually succeeded.
"""

import ast
import re
from collections import Counter
from hashlib import sha256
from itertools import product

from stealer_agent.journal import canonical
from .archive_link import assigned, member, name, writes
from .syntax_context import reconstruct


def component(value):
    return (
        isinstance(value, str)
        and re.fullmatch(r"[A-Za-z0-9_-][A-Za-z0-9 ._-]{0,63}", value) is not None
        and not value.endswith((".", " "))
        and not re.fullmatch(
            r"(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", value, re.I
        )
    )


def literal(node):
    return (
        node.value
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
        else None
    )


def bindings(nodes):
    names = Counter()
    for n in nodes:
        if isinstance(
            n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.ExceptHandler)
        ):
            names[n.name] += 1
        elif isinstance(n, ast.arg):
            names[n.arg] += 1
        elif isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
            names[n.id] += 1
        elif isinstance(n, (ast.Import, ast.ImportFrom)):
            names.update(a.asname or a.name.split(".")[0] for a in n.names)
    return names


def restricted_call(node, funcs):
    if isinstance(node, ast.Call) and name(node.func) in funcs and not node.keywords:
        func = funcs[node.func.id]
        if len(node.args) == len(func.args.args) and not any(
            isinstance(a, ast.Starred) for a in node.args
        ):
            return func
    return None


def key_domain(tree, nodes, parents, bound, fn):
    """Recognize a literal list or keys copied from a closed literal dictionary."""
    if len(fn.body) == 1 and isinstance(fn.body[0], ast.Return):
        seq = fn.body[0].value
        if (
            isinstance(seq, (ast.Tuple, ast.List))
            and 0 < len(seq.elts) <= 32
            and all(component(literal(x)) for x in seq.elts)
        ):
            return [literal(x) for x in seq.elts], [fn, fn.body[0]]
    if len(fn.body) != 3:
        return None
    init, loop, ret = fn.body
    result = assigned(init)
    if not (
        result
        and isinstance(init.value, ast.List)
        and not init.value.elts
        and isinstance(ret, ast.Return)
        and name(ret.value) == result
        and isinstance(loop, ast.For)
        and not loop.orelse
        and isinstance(loop.target, ast.Tuple)
        and len(loop.target.elts) == 2
        and member(loop.iter, "items")
        and not loop.iter.args
        and len(loop.body) == 1
    ):
        return None
    key, other = map(name, loop.target.elts)
    body = loop.body[0]
    if not key or not other or len({result, key, other}) != 3:
        return None
    if isinstance(body, ast.If):
        if (
            body.orelse
            or len(body.body) != 1
            or any(
                isinstance(x, (ast.NamedExpr, ast.Lambda)) for x in ast.walk(body.test)
            )
        ):
            return None
        if any(
            isinstance(x, ast.Name) and x.id in {key, result}
            for x in ast.walk(body.test)
        ):
            return None
        body = body.body[0]
    call = getattr(body, "value", None)
    if not (
        isinstance(body, ast.Expr)
        and member(call, "append", result)
        and len(call.args) == 1
        and name(call.args[0]) == key
        and writes(fn, key) == writes(fn, result) == 1
    ):
        return None
    table = name(loop.iter.func.value)
    decl = next((s for s in tree.body if assigned(s) == table), None)
    if not decl or bound[table] != 1 or not isinstance(decl.value, ast.Dict):
        return None
    keys = decl.value.keys
    if not 0 < len(keys) <= 32 or not all(component(literal(k)) for k in keys):
        return None
    # A key assignment, alias, mutation or escape invalidates the closed set.
    for n in nodes:
        if name(n) != table or n is decl.targets[0] or n is loop.iter.func.value:
            continue
        parent = parents[n]
        if not (
            isinstance(parent, ast.Subscript)
            and parent.value is n
            and isinstance(parent.ctx, ast.Load)
        ):
            return None
    return [literal(k) for k in keys], [decl, fn, init, loop, body, ret]


def path_suffix(node, root):
    if (
        isinstance(node, ast.BinOp)
        and isinstance(node.op, ast.Add)
        and name(node.left) == root
    ):
        if literal(node.right) is not None:
            return [node.right]
        if isinstance(node.right, ast.JoinedStr):
            return node.right.values
    return []


def parts(path):
    if not path.startswith(("/", "\\")) or path.startswith(
        ("//", "\\\\", "/\\", "\\/")
    ):
        return []
    items = re.split(r"[/\\]", path[1:])
    return items if all(component(x) for x in items) else []


def beneath(template, root_parts, args, loop_var, domain):
    fields, choices = [], []
    for item in template:
        if literal(item) is not None:
            fields.append(literal(item))
            continue
        if (
            not isinstance(item, ast.FormattedValue)
            or item.conversion != -1
            or item.format_spec is not None
        ):
            return False
        arg = args.get(name(item.value))
        values = domain if name(arg) == loop_var else [literal(arg)]
        if not values or not all(component(v) for v in values):
            return False
        fields.append(len(choices))
        choices.append(values)
    if len(choices) > 3 or len(domain) ** sum(v is domain for v in choices) > 256:
        return False
    for choice in product(*choices):
        path = parts("".join(v if isinstance(v, str) else choice[v] for v in fields))
        if len(path) <= len(root_parts) or path[: len(root_parts)] != root_parts:
            return False
    return True


def archive_inputs(packer, tree, bound, typed):
    for pack in packer.body:
        f = typed.get(pack.lineno, {})
        call = getattr(pack, "value", None)
        if (
            f.get("api") != "shutil.make_archive"
            or not member(call, "make_archive", "shutil")
            or call.keywords
            or len(call.args) != 3
        ):
            continue
        path = call.args[2]
        root = name(path.left) if isinstance(path, ast.BinOp) else None
        root_decl = next((s for s in tree.body if assigned(s) == root and root), None)
        suffix = path_suffix(path, root)
        if (
            not root_decl
            or bound[root] != 1
            or len(suffix) != 1
            or not parts(literal(suffix[0]) or "")
        ):
            continue
        yield pack, root, root_decl, parts(literal(suffix[0]))


def writer_sites(loop, funcs, caller, typed, root, directory, domain):
    for idx, stmt in enumerate(loop.body):
        writer = restricted_call(getattr(stmt, "value", None), funcs)
        if not isinstance(stmt, ast.Expr) or not writer:
            continue
        args = dict(zip((a.arg for a in writer.args.args), stmt.value.args))
        for n in ast.walk(writer):
            if not isinstance(n, ast.With) or len(n.items) != 1 or len(n.body) != 1:
                continue
            opened, val = (
                n.items[0].context_expr,
                getattr(n.body[0], "value", None),
            )
            if not (
                name(n.items[0].optional_vars)
                and isinstance(opened, ast.Call)
                and name(opened.func) == "open"
                and opened.args
                and member(val, "write", name(n.items[0].optional_vars))
                and len(val.args) == 1
                and typed.get(n.body[0].lineno, {}).get("operation") == "file_write"
            ):
                continue
            parameter = name(val.args[0])
            result = name(args.get(parameter))
            template = path_suffix(opened.args[0], root)
            local = bindings(ast.walk(writer))
            if (
                not result
                or local[parameter] != 1
                or not template
                or not beneath(
                    template,
                    directory,
                    args,
                    loop.target.id,
                    domain,
                )
            ):
                continue
            if any(
                local[name(v.value)] != 1
                for v in template
                if isinstance(v, ast.FormattedValue)
            ):
                continue
            producer = next(
                (
                    s
                    for s in loop.body[:idx]
                    if assigned(s) == result and restricted_call(s.value, funcs)
                ),
                None,
            )
            if not producer or writes(caller, result) != 1:
                continue
            # Both caller sites must be unconditionally in this loop body.
            # The primitive fact is lexical containment for the path expression,
            # even if the writer's own conditional branch is never entered.
            if not any(
                n is direct or isinstance(direct, ast.If) and n in direct.body
                for direct in writer.body
            ):
                continue
            yield producer, stmt, writer, n


def certificate(
    record, mapping, visible, sites, basis, selector, parents, typed, domain
):
    n, pack = sites["open"], sites["archive"]
    roles = {k: mapping[s.lineno][0] for k, s in sites.items()}
    if not set(visible) & {
        roles[k] for k in ("open", "write", "writer_call", "source_call")
    }:
        return None
    # Include the complete key declaration and its projection to the loop.
    required = set(roles.values())
    for lineno in range(selector.lineno, selector.end_lineno + 1):
        required.update(mapping[lineno])
    required.add(typed[pack.lineno]["ranges"][0]["line"])
    if isinstance(parents[n], ast.If):
        required.update(mapping[parents[n].lineno])
    for b in basis:
        end = (
            b.end_lineno
            if isinstance(b, ast.Assign) and isinstance(b.value, ast.Dict)
            else b.lineno
        )
        for lineno in range(b.lineno, end + 1):
            required.update(mapping[lineno])
    if len(required) > 60 or any(len(mapping[s.lineno]) != 1 for s in sites.values()):
        return None
    if sum(len(record["lines"][i - 1]["text"]) for i in required) > 8500:
        return None
    body = {k: record[k] for k in ("evidence_id", "sample_sha256", "output_sha256")}
    body.update(
        backend="static-staging-path/1",
        roles=roles,
        lines=sorted(required),
        component_count=len(set(domain)),
    )
    return {
        **body,
        "proof_id": "stage_" + sha256(canonical(body)).hexdigest()[:16],
    }


def find_witness(record, facts, visible):
    if record["tool"] not in {
        "decode_python_literals",
        "decompile_python",
        "python_ast",
    }:
        return None
    source, mapping = reconstruct(record)
    tree = ast.parse(source)
    nodes = list(ast.walk(tree))
    if len(nodes) > 30000 or any(
        isinstance(n, (ast.Nonlocal, ast.Global, ast.Match, ast.NamedExpr, ast.Delete))
        for n in nodes
    ):
        return None
    if any(
        isinstance(n, ast.Call)
        and name(n.func)
        in {"exec", "eval", "globals", "locals", "vars", "setattr", "delattr"}
        for n in nodes
    ):
        return None
    bound = bindings(nodes)
    if bound["*"] or bound["open"]:
        return None
    parents = {child: n for n in nodes for child in ast.iter_child_nodes(n)}
    funcs = {
        s.name: s
        for s in tree.body
        if isinstance(s, ast.FunctionDef)
        and bound[s.name] == 1
        and not s.decorator_list
        and not (
            s.args.posonlyargs or s.args.kwonlyargs or s.args.vararg or s.args.kwarg
        )
    }
    statement_counts = Counter(n.lineno for n in nodes if isinstance(n, ast.stmt))
    typed = {
        record["lines"][f["ranges"][-1]["line"] - 1]["source_line"]: f
        for f in facts
        if f["operation"] in {"file_write", "archive_create"}
    }
    for caller in funcs.values():
        for loop, pack_call in zip(caller.body, caller.body[1:]):
            if (
                not isinstance(loop, ast.For)
                or loop.orelse
                or not name(loop.target)
                or not name(loop.iter)
            ):
                continue
            packer = restricted_call(getattr(pack_call, "value", None), funcs)
            if (
                not packer
                or packer.args.args
                or bindings(ast.walk(caller))[loop.target.id] != 1
            ):
                continue
            i = caller.body.index(loop)
            seq = caller.body[i - 1] if i else None
            if assigned(seq) != loop.iter.id or writes(caller, loop.iter.id) != 1:
                continue
            if any(
                name(n) == loop.iter.id and n not in (seq.targets[0], loop.iter)
                for n in ast.walk(caller)
            ):
                continue
            selector = restricted_call(seq.value, funcs)
            known = (
                key_domain(tree, nodes, parents, bound, selector)
                if selector and not selector.args.args
                else None
            )
            if not known:
                continue
            domain, basis = known
            for pack, root, declaration, directory in archive_inputs(
                packer, tree, bound, typed
            ):
                for producer, use, writer, opened in writer_sites(
                    loop, funcs, caller, typed, root, directory, domain
                ):
                    sites = {
                        "root": declaration,
                        "domain": basis[0],
                        "select": selector,
                        "selection_call": seq,
                        "iteration": loop,
                        "source_call": producer,
                        "writer_call": use,
                        "writer": writer,
                        "open": opened,
                        "write": opened.body[0],
                        "archive": pack,
                        "archive_call": pack_call,
                        "archive_helper": packer,
                    }
                    if any(statement_counts[s.lineno] != 1 for s in sites.values()):
                        continue
                    witness = certificate(
                        record,
                        mapping,
                        visible,
                        sites,
                        basis,
                        selector,
                        parents,
                        typed,
                        domain,
                    )
                    if witness:
                        return witness
    return None
