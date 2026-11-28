"""Evidence ledger shared by ReAct, the comparison and the local investigation UI."""

import ast
import re
from hashlib import sha256
from .journal import canonical
from .operation_assertions import APIS
from .operation_context import valid_operations
from .search_queries import query_options
from .staging_evidence import checked_path

# Each node describes a static operation. Its presence does not classify a sample.
STAGES = {
    "query": ("Truy vấn cơ sở dữ liệu", {"sql_select"}, ("SELECT", "execute(")),
    "rows": ("Đọc kết quả truy vấn", {"sql_fetchall"}, ("fetchall", "ReadTable")),
    "process": (
        "Xử lý dữ liệu",
        {"aes_gcm_decrypt", "dpapi_unprotect"},
        ("decrypt", "Unprotect"),
    ),
    "write": ("Ghi ra tệp", {"file_write"}, ("write(", "WriteAll")),
    "archive": (
        "Tạo bản nén",
        {"archive_create"},
        ("make_archive", "CreateFromDirectory"),
    ),
    "message": (
        "Tuần tự hóa thông điệp",
        {"mime_serialize"},
        ("as_string", "GetBytes"),
    ),
    "send": ("Gọi API gửi", {"smtp_send", "file_upload"}, ("sendmail", "UploadFile")),
    "response": ("Đọc phản hồi", {"response_text_decode"}, ("GetString",)),
}
EDGES = [
    ("query", "rows"),
    ("rows", "process"),
    ("process", "write"),
    ("write", "archive"),
    ("archive", "message"),
    ("message", "send"),
    ("send", "response"),
]
CODE = {"decompile_dotnet", "decompile_python", "decode_python_literals", "python_ast"}
LITERAL = re.compile(r"""(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')""")


def excerpt(text):
    """Local display of a cited source line. Omit literal values, comments and long fragments."""
    if len(text) >= 600 or "[REDACTED" in text or "__PRIVATE_LITERAL_" in text:
        return "⟦dòng đã ẩn⟧"
    return LITERAL.sub('"…"', text).split("//", 1)[0].split("#", 1)[0].rstrip()[:280]


def proven_pair(a, b, record):
    # The parser has already validated the API binding. Require a source-level
    # dependency between specific calls, not overlapping windows or API names.
    lo, hi = a["ranges"][-1], b["ranges"][-1]
    rows = record["line_map"]
    if lo == hi or lo["end_line"] >= hi["line"]:
        return False
    ops = a["operation"], b["operation"]
    if ops == ("file_upload", "response_text_decode"):
        return (
            b["binding"] == "same_block_unreassigned_UploadFile_return"
            and lo in b["ranges"][:-1]
            and a["result"]["assigned_expression"]
            == b["inputs"]["response_bytes_expression"]
        )
    if ops == ("sql_select", "sql_fetchall"):
        return (
            lo in b["ranges"][:-1]
            and lo["line"] == lo["end_line"] == hi["line"] - 1
            and a["inputs"]["query_expression"] == b["inputs"]["query_expression"]
        )
    if ops != ("mime_serialize", "smtp_send") or hi["end_line"] - lo["line"] > 18:
        return False
    # Prove a local reaching definition only in one straight-line block. Reject
    # gaps, assignments/branches, substitutions and unsupported intervening calls.
    var = a["result"]["assigned_expression"]
    if not var or var != b["inputs"]["message_expression"] or not var.isidentifier():
        return False
    if lo["line"] != lo["end_line"] or hi["line"] != hi["end_line"]:
        return False
    lines = [rows.get(i) for i in range(lo["line"], hi["line"] + 1)]
    if any(s is None or "[REDACTED" in s or "__PRIVATE_LITERAL_" in s for s in lines):
        return False
    indent = re.match(r"[ \t]*", lines[0])[0]
    block_indent = indent
    nested_try = False
    for line in lines[1:-1]:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        actual_indent = re.match(r"[ \t]*", line)[0]
        if line.strip() == "try:" and actual_indent == indent and not nested_try:
            nested_try = True
            block_indent = None
            continue
        if (
            block_indent is None
            and actual_indent.startswith(indent)
            and len(actual_indent) > len(indent)
        ):
            block_indent = actual_indent
        if actual_indent != block_indent:
            return False
        try:
            (stmt,) = ast.parse(line.strip()).body
        except (SyntaxError, ValueError):
            return False
        # Permit only SMTP setup calls, verified separately by the VM parser.
        if (
            isinstance(stmt, ast.Assign)
            and len(stmt.targets) == 1
            and isinstance(stmt.targets[0], ast.Name)
        ):
            if stmt.targets[0].id == var:
                return False
            call = stmt.value
        else:
            call = stmt.value if isinstance(stmt, ast.Expr) else None
        if (
            not isinstance(call, ast.Call)
            or not isinstance(call.func, ast.Attribute)
            or call.func.attr not in {"SMTP", "SMTP_SSL", "starttls", "login"}
        ):
            return False
        if any(
            isinstance(n, (ast.NamedExpr, ast.Lambda, ast.Starred))
            or isinstance(n, ast.Name)
            and n.id == var
            or isinstance(n, ast.Call)
            and n is not call
            for n in ast.walk(call)
        ):
            return False
    return re.match(r"[ \t]*", lines[-1])[0] == block_indent


def checked_argument(rec, digest):
    proof = rec.get("row_use")
    if not isinstance(proof, dict) or proof.get("backend") != "static-row-argument/1":
        return None
    if (rec.get("status") != "ok" or rec["sample_sha256"] != digest
            or rec.get("tool") not in {"python_ast", "decode_python_literals", "decompile_python"}
            or any(not rec.get(k) or rec[k] != proof.get(k) for k in ("evidence_id", "output_sha256", "sample_sha256"))):
        return None
    body = {k: v for k, v in proof.items() if k != "proof_id"}
    if (proof.get("proof_id") != "arg_" + sha256(canonical(body)).hexdigest()[:16]
            or not isinstance(proof.get("column"), str)
            or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", proof["column"])
            or any(type(proof.get(k)) is not int or not 0 <= proof[k] < 256 for k in ("index", "position"))):
        return None
    spans, sites = proof.get("ranges"), proof.get("roles")
    if not isinstance(spans, list) or not 1 <= len(spans) <= 6 or not isinstance(sites, dict):
        return None
    if set(sites) != {"query", "rows", "argument", "parameter", "operation"}:
        return None
    numbers = set()
    refs = []
    for span in spans:
        if not isinstance(span, list) or len(span) != 2 or not all(type(n) is int for n in span):
            return None
        a, b = span
        if not 1 <= a <= b < a + 40:
            return None
        numbers.update(range(a, b + 1))
        refs.append({"eid": rec["evidence_id"], "fact": proof["proof_id"], "tool": rec["tool"],
                     "output_sha256": rec["output_sha256"], "line": a, "end": b})
    if (len(numbers) > 36 or not all(type(n) is int and n in numbers for n in sites.values())
            or not numbers <= rec["line_map"].keys()):
        return None
    rows = [[n, rec["line_map"][n]] for n in sorted(numbers)]
    if (any(m in s for _, s in rows for m in ("[REDACTED", "__PRIVATE_LITERAL_", "[PRIVATE_", "__UNKNOWN", "[UNKNOWN"))
            or sha256(canonical(rows)).hexdigest() != proof.get("rows_sha256")):
        return None
    return {"column": proof["column"], "index": proof["index"], "position": proof["position"],
            "roles": sites, "refs": refs}


def ledger(evidence, digest):
    nodes = {
        k: {"id": k, "label": v[0], "status": "missing", "refs": []}
        for k, v in STAGES.items()
    }
    facts = {k: [] for k in STAGES}
    for eid, rec in evidence.items():
        if (
            rec.get("sample_sha256") != digest
            or rec.get("tool") not in CODE
            or rec.get("status") != "ok"
        ):
            continue
        for f in valid_operations(rec):
            allowed = APIS.get(f["operation"])
            if f["api"] not in (allowed if isinstance(allowed, set) else {allowed}):
                continue
            for k, (_, ops, _) in STAGES.items():
                if f["operation"] not in ops:
                    continue
                span = f["ranges"][-1]
                ref = {
                    "eid": eid,
                    "fact": f["fact_id"],
                    "tool": rec["tool"],
                    "op": f["operation"],
                    "line": span["line"],
                    "end": span["end_line"],
                    "output_sha256": rec["output_sha256"],
                    "text": excerpt(rec["line_map"][span["line"]]),
                }
                nodes[k]["refs"].append(ref)
                nodes[k]["status"] = "supported"
                facts[k].append((eid, f, ref))
        for k, (_, _, seeds) in STAGES.items():
            if nodes[k]["refs"]:
                continue
            for n, line in sorted(rec.get("line_map", {}).items()):
                if "[REDACTED" in line or not any(
                    q.casefold() in line.casefold() for q in seeds
                ):
                    continue
                nodes[k].update(
                    status="partial",
                    lead={
                        "eid": eid,
                        "line": n,
                        "end": n,
                        "tool": rec["tool"],
                        "text": excerpt(line),
                    },
                )
                break
    edges = []
    for src, dst in EDGES:
        edge = {
            "id": src + "-" + dst,
            "label": nodes[src]["label"] + " → " + nodes[dst]["label"],
            "status": "partial" if facts[src] or facts[dst] else "missing",
            "refs": [],
        }
        for eid, a, ra in facts[src]:
            for other, b, rb in facts[dst]:
                if eid == other and proven_pair(a, b, evidence[eid]):
                    edge["status"] = "supported"
                    edge["refs"].extend([ra, rb])
        edges.append(edge)
        if edge["status"] != "supported":
            edge["leads"] = [
                r
                for k in (src, dst)
                for r in (
                    nodes[k]["refs"][:1]
                    or ([nodes[k]["lead"]] if "lead" in nodes[k] else [])
                )
            ]
            if edge["leads"]:
                edge["status"] = "partial"
    for eid, rec in evidence.items():
        witness = rec.get("archive_link")
        if (
            not witness
            or rec.get("status") != "ok"
            or rec.get("sample_sha256") != digest
            or rec.get("tool") not in CODE
        ):
            continue
        body = {k: v for k, v in witness.items() if k != "proof_id"}
        if (
            witness.get("backend") != "static-attachment-path/1"
            or witness.get("kind") != "archive-message"
            or witness.get("proof_id")
            != "flow_" + sha256(canonical(body)).hexdigest()[:16]
            or any(
                witness.get(k) != rec.get(k)
                for k in ("evidence_id", "sample_sha256", "output_sha256")
            )
        ):
            continue
        roles = witness.get("roles", [])
        if [r.get("role") for r in roles] != [
            "helper_archive",
            "path",
            "archive",
            "return",
            "caller_result",
            "caller_argument",
            "helper_attachment",
            "open_argument",
            "read_to_payload",
            "attach",
            "serialize",
        ]:
            continue
        if any(
            type(r.get("line")) is not int
            or r["line"] not in rec["line_map"]
            or "[REDACTED" in rec["line_map"][r["line"]]
            or "__PRIVATE_LITERAL_" in rec["line_map"][r["line"]]
            for r in roles
        ):
            continue
        trail = [
            {
                "eid": eid,
                "tool": rec["tool"],
                "fact": witness["proof_id"],
                "output_sha256": rec["output_sha256"],
                "line": r["line"],
                "end": r["line"],
                "role": r["role"],
                "text": excerpt(rec["line_map"][r["line"]]),
            }
            for r in roles
        ]
        edge = next(e for e in edges if e["id"] == "archive-message")
        edge.update(status="supported", refs=[trail[2], trail[-1]], trail=trail)
        edge.pop("leads", None)
        for stage, ref in (("archive", trail[2]), ("message", trail[-1])):
            if not nodes[stage]["refs"]:
                nodes[stage].update(status="supported", refs=[ref])
        break
    for record in evidence.values():
        check = checked_path(record, digest)
        if check:
            edge = next(e for e in edges if e["id"] == "write-archive")
            edge.update(status="partial", path_check=check)
            break
    for record in evidence.values():
        check = checked_argument(record, digest)
        if check:
            edge = next(e for e in edges if e["id"] == "rows-process")
            edge.update(status="supported", argument_check=check, refs=check["refs"])
            edge.pop("leads", None)
            for stage, role in (("rows", "rows"), ("process", "operation")):
                if not nodes[stage]["refs"]:
                    n = check["roles"][role]
                    ref = {**check["refs"][0], "line": n, "end": n, "text": excerpt(record["line_map"][n])}
                    nodes[stage].update(status="supported", refs=[ref])
            break
    return {
        "method": "static-link-ledger/2",
        "nodes": list(nodes.values()),
        "edges": edges,
    }


def options(graph, used, *, focus=None, tool=None, record=None):
    """Choose an unresolved edge touching actual evidence before unobserved stages."""
    edges = [
        e
        for e in graph["edges"]
        if e["status"] != "supported" and (not focus or e["id"] == focus)
    ]
    # Switch to another gap after spending two different probes on a relation.
    # Platform order is a navigation preference. It cannot establish an edge.
    priority = (
        ["send-response", "process-write"]
        if tool == "decompile_dotnet"
        else ["query-rows", "message-send", "write-archive"]
    )

    def order(edge):
        probes = {q.casefold() for k in edge["id"].split("-") for q in STAGES[k][2]}
        spent = len(used & probes)
        observed = any(
            n["status"] != "missing"
            for n in graph["nodes"]
            if n["id"] in edge["id"].split("-")
        )
        return (
            spent >= 2,
            edge["status"] != "partial",
            not observed,
            spent,
            priority.index(edge["id"]) if edge["id"] in priority else len(priority),
        )

    edges.sort(key=order)
    found = {n["id"] for n in graph["nodes"] if n["status"] == "supported"}
    for edge in edges:
        pair = edge["id"].split("-")
        stages = sorted(pair, key=lambda k: k in found)
        queries = [q for k in stages for q in STAGES[k][2] if q.casefold() not in used]
        if record:
            lexemes = {
                "archive": ("archive", "zip", "compress"),
                "message": ("attach", "mail", "mime"),
                "send": ("send", "upload", "submit"),
                "write": ("write", "save"),
                "query": ("query", "select", "database"),
                "rows": ("fetch", "readtable"),
                "process": ("decrypt", "unprotect"),
                "response": ("response", "getstring"),
            }
            words = tuple(w for k in stages for w in lexemes[k])
            observed = [
                q
                for q in query_options(record, used)
                if any(w in q.casefold() for w in words)
                and any(q in line for line in record.get("line_map", {}).values())
            ]
            queries = list(dict.fromkeys(queries + observed[:6]))
        # Filter platform-specific seeds, but retain literal identifiers actually
        # observed in the current artifact (mixed-language wrappers are possible).
        incompatible = (
            {
                "sendmail",
                "fetchall",
                "execute(",
                "make_archive",
                "as_string",
                "decrypt",
                "write(",
            }
            if tool == "decompile_dotnet"
            else {
                "readtable",
                "uploadfile",
                "getstring",
                "getbytes",
                "writeall",
                "createfromdirectory",
                "unprotect",
            }
        )
        visible = record.get("line_map", {}).values() if record else ()
        queries = [
            q
            for q in queries
            if q.casefold() not in incompatible or any(q in line for line in visible)
        ]
        if queries:
            return edge["id"], queries
    return None, []
