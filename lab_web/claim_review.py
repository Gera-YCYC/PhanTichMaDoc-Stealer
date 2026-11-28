"""Analyst-requested second look at one rejected claim on its frozen source."""

import json
import re
from hashlib import sha256
from uuid import uuid4

from stealer_agent.card_journal import rejected_card_requests
from stealer_agent.claim_parts import split_review
from stealer_agent.investigation import excerpt
from stealer_agent.journal import Journal, record_model_request, verify_journal
from stealer_agent.narrow_review import narrow
from stealer_agent.redaction import redact_document
from stealer_agent.slice_review import slice_discrepancy
from stealer_agent.transport import OllamaClient

from .cases import cited_windows, directory, display_claim, records_for, trusted_report


def revisit(data, cfg):
    run, cid = data.get("run"), data.get("claim")
    mode = data.get("mode", "lines")
    if mode not in ("lines", "parts"):
        raise ValueError("Cách duyệt nhận định không hợp lệ.")
    if not isinstance(cid, str) or not re.fullmatch(r"C[1-9][0-9]{0,2}", cid):
        raise ValueError("Mã nhận định không hợp lệ.")
    folder = directory(run)
    report = trusted_report(run)
    path = folder / "events.jsonl"
    records = records_for(run)  # verifies the terminal journal and sample binding
    with path.open(encoding="utf8") as stream:
        cases = rejected_card_requests(json.loads(line) for line in stream)
        selected = next((case for case in cases if case[0]["id"] == cid), None)
    if selected is None or cid not in {
        r["claim"]["id"] for r in report["analysis"].get("rejected_claims", [])
    }:
        raise ValueError("Lượt này thiếu yêu cầu duyệt gốc cho câu đã chọn.")
    parent, check, request = selected
    for ref in parent["evidence"]:
        rec = records.get(ref["evidence_id"], {})
        rows = rec.get("line_map", {})
        nums = range(ref["line"], ref["end_line"] + 1)
        if (
            rec.get("sample_sha256") != report["sample_sha256"]
            or any(n not in rows for n in nums)
            or ref["quote"] != "\n".join(rows[n] for n in nums)
        ):
            raise ValueError("Nguồn của câu không khớp các dòng VM đã lưu.")
    model = OllamaClient({**cfg, "model": report["model"]["tag"]})
    if model.inspect()["digest"] != report["model"]["digest"]:
        raise ValueError("Digest của model khác với lượt ban đầu.")
    journal = Journal(folder / ("parts-reviews" if mode == "parts" else "claim-reviews")
                      / ("review_" + uuid4().hex[:12]))
    journal.append(
        "review_started",
        run=run,
        parent=cid,
        source_journal_sha256=sha256(path.read_bytes()).hexdigest(),
        original_request_sha256=request["messages_sha256"],
        model_digest=report["model"]["digest"],
        sample_sha256=report["sample_sha256"],
        mode=mode,
    )
    step = 0

    def invoke(messages, schema, phase, evidence):
        nonlocal step
        step += 1
        record_model_request(
            journal,
            step=step,
            phase=phase,
            messages=messages,
            schema=schema,
            evidence=evidence,
        )
        result, usage = model.chat(messages, schema)
        journal.append(
            "model_response", step=step, phase=phase, response=result, metrics=usage
        )
        return result

    try:
        if mode == "parts":
            outcomes = split_review(parent, request["evidence"][0]["tool"], invoke)
            items = []
            for row in outcomes:
                safe, _ = redact_document(row, context=(r["quote"] for r in parent["evidence"]))
                item = display_claim(row["claim"], records, rejected=True)
                if len(item["refs"]) != len(row["claim"]["evidence"]):
                    raise ValueError("Dòng trích của ý tách ra khác nhật ký VM.")
                # Keep only the redacted observation and excerpt in the response.
                item.update(text=safe["claim"]["text"], kept=safe["check"]["supported"],
                            reason=safe["check"]["reason"],
                            slice_check=slice_discrepancy(row["claim"], request["evidence"][0]["tool"]))
                for ref, sanitized in zip(item["refs"], safe["claim"]["evidence"], strict=True):
                    ref["text"] = excerpt(sanitized["quote"].split("\n")[0])
                items.append(item)
            display = {"id": journal.directory.name, "claim": cid, "parts": items,
                       "model_calls": step, "mode": mode,
                       "windows": cited_windows(records, {"nodes": [], "edges": []}, items)}
            journal.append("review_finished", outcomes=outcomes, display=display)
            verify_journal(journal.path)
            return display
        candidate, decision = narrow(parent, check, request, invoke, mode="lines")
        display = {
            "id": journal.directory.name,
            "claim": cid,
            "decision": decision,
            "text": "",
            "refs": [],
            "model_calls": step,
        }
        if candidate:
            safe, _ = redact_document(
                candidate, context=(r["quote"] for r in parent["evidence"])
            )
            display.update(
                text=safe["text"],
                refs=[
                    {
                        "eid": r["evidence_id"],
                        "line": r["line"],
                        "end": r["end_line"],
                        "text": excerpt(r["quote"]),
                    }
                    for r in safe["evidence"]
                ],
            )
        journal.append("review_finished", candidate=candidate, display=display)
        verify_journal(journal.path)
        return display
    except Exception as err:
        journal.append("review_failed", error=type(err).__name__)
        raise
