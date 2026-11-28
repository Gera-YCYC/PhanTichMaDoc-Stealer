"""Validate coordinates on the guarded source before exposing a VM path comparison."""

from hashlib import sha256

from .journal import canonical

ROLES = {
    "root",
    "domain",
    "select",
    "selection_call",
    "iteration",
    "source_call",
    "writer_call",
    "writer",
    "open",
    "write",
    "archive_helper",
    "archive",
    "archive_call",
}


def checked_path(record, digest):
    w = record.get("staging_link")
    if not isinstance(w, dict) or w.get("backend") != "static-staging-path/1":
        return None
    if (
        record.get("tool")
        not in {"decode_python_literals", "decompile_python", "python_ast"}
        or record.get("status") != "ok"
        or record.get("sample_sha256") != digest
        or any(
            not record.get(k) or w.get(k) != record[k]
            for k in ("evidence_id", "sample_sha256", "output_sha256")
        )
    ):
        return None
    body = {k: v for k, v in w.items() if k != "proof_id"}
    if w.get("proof_id") != "stage_" + sha256(canonical(body)).hexdigest()[:16]:
        return None
    roles, lines, count = w.get("roles"), w.get("lines"), w.get("component_count")
    if (
        not isinstance(roles, dict)
        or set(roles) != ROLES
        or not isinstance(lines, list)
        or not 1 <= len(lines) <= 60
        or type(count) is not int
        or not 1 <= count <= 32
        or any(type(n) is not int or n < 1 for n in [*lines, *roles.values()])
        or sorted(set(lines)) != lines
        or not set(roles.values()) <= set(lines)
    ):
        return None
    rows = record.get("line_map", {})
    if any(
        n not in rows
        or any(
            s in rows[n]
            for s in (
                "[REDACTED",
                "__PRIVATE_LITERAL_",
                "[PRIVATE_",
                "[UNKNOWN",
                "__UNKNOWN",
            )
        )
        for n in lines
    ):
        return None
    if not (
        roles["iteration"]
        < roles["source_call"]
        < roles["writer_call"]
        < roles["archive_call"]
        and roles["writer"] < roles["open"] < roles["write"]
        and roles["archive_helper"] < roles["archive"]
    ):
        return None
    spans = []
    for n in lines:
        if spans and spans[-1]["end"] + 1 == n:
            spans[-1]["end"] = n
        else:
            spans.append(
                {
                    "eid": w["evidence_id"],
                    "tool": record["tool"],
                    "output_sha256": w["output_sha256"],
                    "fact": w["proof_id"],
                    "line": n,
                    "end": n,
                    "text": "",
                }
            )
    return {
        "relation": "writer_path_beneath_archive_input",
        "component_count": count,
        "roles": roles,
        "refs": spans,
        "unresolved": "file_presence_at_archive_time",
    }
