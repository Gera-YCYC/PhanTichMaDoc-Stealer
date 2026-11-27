"""Private JSON plus a redacted human-readable report; no fabricated quality scores."""
from __future__ import annotations
import json
from pathlib import Path
from .journal import dump_json
from .security import redact


def write_report(directory: Path, result: dict) -> None:
    dump_json(directory / "report.private.json", result)
    # Redact recursively through serialization, preserving schema and citations.
    shared = json.loads(redact(json.dumps(result, ensure_ascii=False)))
    dump_json(directory / "report.redacted.json", shared)
    report = shared["analysis"]
    lines = [f"# Phân tích tĩnh: {shared['sample']}", "",
             f"- Trạng thái: **{shared['status']}**",
             f"- Kết luận: **{report['verdict']}**",
             f"- Model: `{shared['model']['tag']}`",
             f"- SHA256 mẫu: `{shared.get('sample_sha256') or 'chưa có'}`",
             f"- Công cụ thành công: {', '.join(shared['successful_tools']) or 'chưa có'}",
             f"- Mô hình đạt tối thiểu 7B: `{shared['acceptance']['model_minimum_met']}`", "",
             "Các trích dẫn được đối chiếu chuỗi/dòng; kiểm tra bằng cùng SLM vẫn chỉ là heuristic. Chưa có bảng chấm độc lập của nhóm.", ""]
    if shared.get('file_facts'):
        lines.extend(['## Quan sát trực tiếp từ công cụ', '',
                      'Đây là metadata do identify trả về, tách khỏi các nhận định của model.', '',
                      '```json', json.dumps(shared['file_facts'],ensure_ascii=False,indent=2), '```', '',
                      '## Nhận định của SLM', ''])
    if not report.get('claims'):
        lines.extend(['Chưa giữ lại nhận định nào sau kiểm tra. Xem claim thô và lý do loại trong log.', ''])
    for claim in report.get("claims", []):
        lines.append(f"- **{claim['id']} / {claim['kind']}**: {claim['text']}")
        for ref in claim["evidence"]:
            if 'end_line' in ref:
                lines.append(f"  - `{ref['evidence_id']}:{ref['line']}-{ref['end_line']}` (đoạn chứng cứ đầy đủ)")
                # Indented code preserves hostile backticks/HTML as inert text.
                lines.append('')
                lines.extend('        ' + line for line in ref['quote'].split('\n'))
                lines.append('')
            else:
                lines.append(f"  - `{ref['evidence_id']}:{ref['line']}` — `{ref['quote']}`")
    lines.extend(["", "## Giới hạn", ""])
    lines.extend("- " + text for text in report.get("limitations", []))
    lines.extend("- " + text for text in report.get("validation_notes", []))
    for item in report.get('rejected_claims', []):
        lines.append('- Nhận định bị loại ' + item['claim']['id'] + ': ' + ', '.join(item['reasons']))
    lines.extend(["", "## Đo thực tế", "", "```json", json.dumps(shared["metrics"], ensure_ascii=False, indent=2), "```", "",
                  "Không tự suy ra F1, tỷ lệ bịa, TPR/FPR hay tỷ lệ chống injection từ log này."])
    (directory / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
