"""Verify a static column-to-argument relation in a complete Python syntax tree."""

import ast
from collections import Counter
from hashlib import sha256
import re

from stealer_agent.journal import canonical
from .archive_link import assigned, member, name
from .staging_link import bindings, restricted_call
from .syntax_context import reconstruct

ID = r"[A-Za-z_][A-Za-z0-9_]{0,63}"
SELECT = re.compile(rf"SELECT\s+({ID}(?:\s*,\s*{ID})*)\s+FROM\s+{ID}\s*;?", re.I | re.ASCII)


def column_at(query, loop, stmt, funcs):
    """An immediate row[index] argument with an unambiguous positional projection."""
    call = getattr(query, "value", None)
    fetch = loop.iter
    if not (isinstance(query, ast.Expr) and member(call, "execute")
            and member(fetch, "fetchall", name(call.func.value)) and not fetch.args
            and len(call.args) == 1 and isinstance(call.args[0], ast.Constant)
            and isinstance(call.args[0].value, str) and name(loop.target)):
        return None
    match = SELECT.fullmatch(call.args[0].value.strip())
    if not match:
        return None
    columns = [s.strip() for s in match[1].split(",")]
    use = getattr(stmt, "value", None)
    fn = restricted_call(use, funcs)
    if not fn or not (isinstance(stmt, ast.Expr) or assigned(stmt)):
        return None
    slots = []
    for position, arg in enumerate(use.args):
        if isinstance(arg, ast.Subscript) and name(arg.value) == name(loop.target):
            idx = arg.slice
            if not isinstance(idx, ast.Constant) or type(idx.value) is not int or not 0 <= idx.value < len(columns):
                return None
            slots.append((position, idx.value))
        elif not isinstance(arg, (ast.Name, ast.Constant)):
            return None
    if len(slots) != 1:
        return None
    position, index = slots[0]
    return fn, position, index, columns[index]


def sink_for(fn, position, typed, constructors):
    """Follow direct local copies/slices of one parameter up to a typed operation."""
    if len(fn.body) > 10 or fn.end_lineno - fn.lineno > 15:
        return None
    derived = {fn.args.args[position].arg}
    for stmt in fn.body:
        target = assigned(stmt)
        if not target or stmt.lineno != stmt.end_lineno:
            break
        value = stmt.value
        fact = typed.get(("aes_gcm_decrypt", stmt.lineno))
        if (fact and member(value, "decrypt") and len(value.args) == 1
                and name(value.args[0]) in derived
                and name(value.args[0]) == fact["inputs"].get("ciphertext_expression")):
            return fact
        base = value
        if isinstance(value, ast.Subscript) and isinstance(value.slice, ast.Slice):
            s = value.slice
            if any(n is not None and not (isinstance(n, ast.Constant) and type(n.value) is int)
                   for n in (s.lower, s.upper, s.step)):
                return None
            base = value.value
        if name(base) in derived:
            derived.add(target)
        else:
            derived.discard(target)
            # Only the parser-bound cipher construction may introduce a call here.
            if not isinstance(base, (ast.Name, ast.Constant)) and stmt.lineno not in constructors:
                return None
    return None


def find_witness(record, facts, visible):
    if record["tool"] not in {"decode_python_literals", "decompile_python"}:
        return None
    source, mapping = reconstruct(record)
    tree = ast.parse(source)
    nodes = list(ast.walk(tree))
    if len(nodes) > 30000 or any(isinstance(n, (ast.Global, ast.Nonlocal, ast.Match, ast.NamedExpr, ast.Delete))
                                 for n in nodes):
        return None
    # A custom SQLite row factory may change what an integer subscript returns.
    if any(isinstance(n, ast.Attribute) and n.attr == "row_factory"
           and isinstance(n.ctx, (ast.Store, ast.Del)) for n in nodes):
        return None
    bound = bindings(nodes)
    if bound["*"] or any(isinstance(n, ast.Call) and name(n.func) in
                          {"globals", "locals", "exec", "eval", "setattr", "delattr", "vars"} for n in nodes):
        return None
    funcs = {f.name: f for f in tree.body if isinstance(f, ast.FunctionDef)
             and bound[f.name] == 1 and not f.decorator_list and not f.args.posonlyargs
             and not f.args.kwonlyargs and not f.args.vararg and not f.args.kwarg}
    rows = record["lines"]
    typed = {}
    constructors = set()
    allowed = {"aes_gcm_decrypt": "PyCryptodome.AES.GCM.decrypt",
               "sql_fetchall": "sqlite3.Cursor.fetchall", "sql_select": "sqlite3.execute"}
    for f in facts:
        if allowed.get(f["operation"]) != f["api"] or not f["ranges"]:
            continue
        site = rows[f["ranges"][-1]["line"] - 1]["source_line"]
        key = (f["operation"], site)
        typed[key] = f
        if f["operation"] == "aes_gcm_decrypt":
            constructors.update(rows[r["line"] - 1]["source_line"] for r in f["ranges"][-2:-1])
    counts = Counter(n.lineno for n in nodes if isinstance(n, ast.stmt))
    for block in nodes:
        body = getattr(block, "body", None)
        if not isinstance(body, list):
            continue
        for i, loop in enumerate(body):
            if i < 3 or not isinstance(loop, ast.For):
                continue
            query, use = body[i-1], loop.body[0]
            fetch = typed.get(("sql_fetchall", loop.lineno))
            sel = typed.get(("sql_select", query.lineno))
            if not fetch or not sel or sel["ranges"][-1] not in fetch["ranges"][:-1]:
                continue
            site = column_at(query, loop, use, funcs)
            if not site:
                continue
            fn, position, index, column = site
            if any(counts[s.lineno] != 1 for s in fn.body):
                continue
            conn, cursor = body[i-3:i-1]
            if not (assigned(conn) and assigned(cursor) == name(loop.iter.func.value)
                    and member(cursor.value, "cursor", assigned(conn)) and not cursor.value.args
                    and isinstance(conn.value, ast.Call) and len(conn.value.args) == 1 and not conn.value.keywords):
                continue
            source_span = list(range(conn.lineno, use.end_lineno + 1))
            if len(source_span) > 12 or not all(counts[s.lineno] == 1 for s in (conn, cursor, query, loop, use)):
                continue
            bound_sites = {rows[r["line"] - 1]["source_line"] for r in fetch["ranges"]}
            if not {conn.lineno, cursor.lineno, query.lineno} <= bound_sites:
                continue
            sink = sink_for(fn, position, typed, constructors)
            if not sink:
                continue
            helper_span = list(range(fn.lineno, fn.end_lineno + 1))
            if any(len(mapping[n]) != 1 for n in source_span + helper_span):
                continue
            get_row = lambda n: mapping[n][0]
            roles = {"query": get_row(query.lineno), "rows": get_row(loop.lineno), "argument": get_row(use.lineno),
                     "parameter": get_row(fn.lineno), "operation": sink["ranges"][-1]["line"]}
            if not set(visible).intersection(roles.values()):
                continue
            groups = [(get_row(conn.lineno), get_row(use.end_lineno)),
                      (get_row(fn.lineno), get_row(fn.end_lineno))]
            for fact in (fetch, sink):
                for r in fact["ranges"]:
                    a, b = r["line"], r["end_line"]
                    if not any(x <= a <= b <= y for x,y in groups):
                        groups.append((a,b))
            numbers = sorted({n for a,b in groups for n in range(a,b+1)})
            if len(groups) > 6 or len(numbers) > 36 or sum(len(rows[n-1]["text"]) for n in numbers) > 4200:
                continue
            values = {k:record[k] for k in ("sample_sha256","output_sha256","evidence_id")}
            values.update(backend="static-row-argument/1", column=column, index=index, position=position,
                          roles=roles, ranges=[list(p) for p in groups],
                          rows_sha256=sha256(canonical([[n, rows[n-1]["text"]] for n in numbers])).hexdigest())
            return {**values, "proof_id": "arg_" + sha256(canonical(values)).hexdigest()[:16]}
    return None
