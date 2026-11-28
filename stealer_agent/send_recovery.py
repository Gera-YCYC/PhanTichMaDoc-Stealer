"""Recover missing static send citations from operations already reviewed in this run."""
from .contracts import REPORT_SCHEMA
from .operation_assertions import catalog
from .verdict_support import SUPPORT_KEYS

SEND = SUPPORT_KEYS[1]


def reviewed_sites(claims, evidence, digest, selected):
    kept = {c["id"]: c for c in claims if c["kind"] == "behavior"}
    entries, _ = catalog(evidence, digest)
    for entry in entries:
        if entry["operation"] not in {"smtp_send", "file_upload"}:
            continue
        cid = selected.get(entry["fact_id"])
        claim = kept.get(cid)
        if not claim or claim["text"] != entry["text"] or claim["evidence"] != entry["evidence"]:
            continue
        refs = [{"eid": r["evidence_id"], "line": r["line"], "end": r["end_line"],
                 "output_sha256": evidence[r["evidence_id"]]["output_sha256"]} for r in entry["evidence"]]
        yield {"claim": cid, "fact": entry["fact_id"], "operation": entry["operation"], "refs": refs}


def recover(report, evidence, digest, selected):
    """Preserve the verdict, every original citation, and the collection/link decisions."""
    cited = report["verdict_claim_ids"]
    send_ids = report["verdict_support"][SEND]
    receipt = {"prior_citations": list(cited), "prior_verdict": report["verdict"], "sites": [],
               "outcome": "searched"}
    limit = REPORT_SCHEMA["properties"]["verdict_claim_ids"]["maxItems"]
    for site in reviewed_sites(report["claims"], evidence, digest, selected):
        cid = site["claim"]
        if cid in send_ids:
            continue
        receipt["sites"].append(site)
        if cid not in cited and len(cited) >= limit:
            site["status"] = "citation_limit"
            continue
        site["status"] = "recovered"
        if cid not in cited:
            cited.append(cid)
        send_ids.append(cid)
    if send_ids and SEND in report["verdict_support_missing"]:
        report["verdict_support_missing"].remove(SEND)
    return receipt
