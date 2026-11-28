"""Require a bound read at the claimed origin or in a matching reviewed collection."""
from .operation_assertions import render
from .operation_context import valid_operations
from .verdict_support import SUPPORT_KEYS

READS = {"sql_fetchall", "reader_named_field", "reader_ordinal_field", "file_read", "file_copy"}


def source_read(decision, earlier, evidence, digest):
    """Return coordinates only. A generic read cannot by itself establish sensitive contents."""
    origin = next(w for w in decision["witnesses"] if w["part"] == "sensitive_source")
    key = ("eid", "line", "output_sha256")
    candidates = [(origin, decision["claim"])]
    for other in earlier:
        if other["role"] != SUPPORT_KEYS[0] or other["status"] != "supported_by_review":
            continue
        parts = {w["part"]: w for w in other["witnesses"]}
        if (all(parts["sensitive_source"][k] == origin[k] for k in key)
                and all(parts["read"][k] == origin[k] for k in ("eid", "output_sha256"))):
            candidates.append((parts["read"], other["claim"]))
    for anchor, cid in candidates:
        rec = evidence.get(anchor["eid"], {})
        if (rec.get("status") != "ok" or rec.get("sample_sha256") != digest or
                rec.get("output_sha256") != anchor["output_sha256"]):
            continue
        for fact in valid_operations(rec):
            if fact["operation"] not in READS:
                continue
            call = fact["ranges"][-1]
            if not call["line"] <= anchor["line"] <= call["end_line"]:
                continue
            try:
                render(fact)
            except ValueError:
                continue
            return {"claim":cid, "fact":fact["fact_id"], "operation":fact["operation"],
                    **{k:anchor[k] for k in key}}
    return None
