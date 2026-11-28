"""Project an actual generation journal onto per-attempt compile and scan outcomes."""

import json
from stealer_agent.journal import verify_journal


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
