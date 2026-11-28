"""Project an actual generation journal onto per-attempt compile and scan outcomes."""

import json
from hashlib import sha256
from stealer_agent.journal import verify_journal


def regression(root):
    """Compare the same clean bytes across the two published validation runs."""
    base = root / "deliverables/real-demo-evidence"
    old = json.loads((base / "yara-challenge-yara_real_14243d3cbc98.json").read_bytes())
    new = json.loads(
        (base / "yara-runs/yara_real_4054c42e1321/receipt.json").read_bytes()
    )
    before, after = old["result"], new["development"]
    for name, result in [
        ("yara-v1-observed-false-positive.yar", before),
        ("yara-v3-qwen8b.yar", after),
    ]:
        rules = (root / "rules" / name).read_text(encoding="utf8")
        if sha256(rules.encode()).hexdigest() != result["rule_sha256"]:
            raise ValueError("Hash của luật khác biên bản.")
    if not old["independent_replay_equal"] or not new["independent_replay_equal"]:
        raise ValueError("Kết quả chạy lại chưa khớp.")
    negatives = {r["sha256"]: r for r in after["results"] if not r["positive"]}
    changes = []
    for row in before["results"]:
        if not row["positive"] and row["matched"] and row["sha256"] in negatives:
            changes.append(
                {
                    "sample": row["sample"],
                    "sha256": row["sha256"],
                    "matched_before": row["matched"],
                    "matched_after": negatives[row["sha256"]]["matched"],
                }
            )
    return {
        "before_run": old["source_run"],
        "after_run": new["run_id"],
        "changes": changes,
        "before_clean": before["negative_count"],
        "before_fp": sum(r["matched"] for r in before["results"] if not r["positive"]),
        "holdout_clean": new["holdout"]["negative_count"],
        "holdout_fp": sum(
            r["matched"] for r in new["holdout"]["results"] if not r["positive"]
        ),
    }


def attempts(path, summary):
    verify_journal(path)
    rows = []
    current = None
    parts = {}
    with path.open(encoding="utf8") as stream:
        for line in stream:
            event = json.loads(line)
            kind = event["event"]
            if kind == "model_draft":
                current = {
                    "sample": event["sample"],
                    "attempt": event["attempt"],
                    "status": "chưa có phản hồi",
                    "matched": None,
                    "false_positives": None,
                }
                rows.append(current)
            elif kind == "draft_rejected" and current is not None:
                current["status"] = "bị từ chối"
            elif kind == "development_feedback" and current is not None:
                raw = event["raw"]
                current["status"] = (
                    "VM trả lỗi" if raw.get("status") != "ok" else "đang ghép kết quả"
                )
                if raw.get("status") == "ok":
                    parts[raw["evidence_id"]] = (
                        current,
                        raw["output_sha256"],
                        raw["total_lines"],
                        list(raw["lines"]),
                    )
            elif kind == "evidence_page" and event["raw"]["evidence_id"] in parts:
                raw = event["raw"]
                _, digest, _, lines = parts[raw["evidence_id"]]
                if digest != raw["output_sha256"]:
                    raise ValueError("Trang YARA sai nguồn.")
                lines.extend(raw["lines"])
    if event.get("event") != "finished" or event.get("summary") != summary:
        raise ValueError("Bản tổng kết YARA khác nhật ký.")
    for current, _, total, lines in parts.values():
        if [r["line"] for r in lines] != list(range(1, total + 1)):
            continue
        report = json.loads("".join(row["text"] for row in lines))
        if report.get("corpus") != "training":
            raise ValueError("Sai phân vùng trong phản hồi sửa luật.")
        current.update(
            status="đã biên dịch và quét",
            matched=next(
                r["matched"]
                for r in report["results"]
                if r["sample"] == current["sample"]
            ),
            false_positives=sum(
                not r["positive"] and r["matched"] for r in report["results"]
            ),
        )
    return rows
