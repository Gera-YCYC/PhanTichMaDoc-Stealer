"""Trình tạo báo cáo phân tích InfoStealer dưới định dạng JSON và Markdown."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from agent.react_engine import AnalysisResult
from config import REPORTS_DIR


class ReportGenerator:
    """Xuất kết quả phân tích ReAct ra báo cáo JSON có cấu trúc và Markdown dễ đọc."""

    @staticmethod
    def _escape_md_cell(value: str) -> str:
        return value.replace("|", "\\|").replace("\n", " ").strip()

    @classmethod
    def render_markdown(cls, result: AnalysisResult) -> str:
        """Biên dịch `AnalysisResult` thành báo cáo Markdown chi tiết."""
        fa = result.final_analysis
        sample_name = Path(result.sample_path).name

        lines: list[str] = [
            f"# Báo Cáo Phân Tích InfoStealer: `{sample_name}`",
            "",
            "## 1. Tổng Quan & Đánh Giá Nguy Hiểm (Verdict)",
            "",
            f"- **Kết luận (Verdict):** `{fa.verdict}`",
            f"- **Điểm rủi ro (Risk Score):** `{fa.risk_score}/100`",
            f"- **Độ tin cậy (Confidence):** `{fa.confidence}`",
            f"- **Trạng thái phiên ReAct:** `{result.status}` (`{result.iterations_used}` vòng lặp, `{result.total_self_corrections}` self-corrections, `{result.elapsed_seconds}s`)",
            "",
            "## 2. Thông Tin Mẫu & Hàm Băm",
            "",
            "| Thuộc tính | Giá trị |",
            "|---|---|",
            f"| Đường dẫn mẫu | `{cls._escape_md_cell(result.sample_path)}` |",
            f"| Định dạng nhận diện | `{cls._escape_md_cell(result.file_type)}` |",
            f"| Mô hình SLM cục bộ | `{cls._escape_md_cell(result.model_name)}` |",
            f"| Thời điểm phân tích (UTC) | `{result.timestamp}` |",
            f"| Kích thước (bytes) | `{result.hashes.get('size_bytes', 'N/A')}` |",
            f"| MD5 | `{result.hashes.get('md5', 'N/A')}` |",
            f"| SHA1 | `{result.hashes.get('sha1', 'N/A')}` |",
            f"| SHA256 | `{result.hashes.get('sha256', 'N/A')}` |",
            "",
            "## 3. Tóm Tắt Hành Vi (Behavior Summary)",
            "",
            fa.behavior_summary,
            "",
            "## 4. Chỉ Số Xâm Nhập (IOCs)",
            "",
        ]

        if fa.iocs:
            for category, values in sorted(fa.iocs.items()):
                if not values:
                    continue
                lines.append(f"### `{category}` ({len(values)})")
                for val in values:
                    lines.append(f"- `{val}`")
                lines.append("")
        else:
            lines.extend(["*Không trích xuất được IOC nào.*", ""])

        lines.extend(["## 5. Kết Quả Quét Luật YARA", ""])
        if result.yara_matches:
            lines.extend(
                [
                    "| File | Rule | Severity | MITRE | Mô tả |",
                    "|---|---|---|---|---|",
                ]
            )
            for ym in result.yara_matches:
                lines.append(
                    f"| `{cls._escape_md_cell(str(ym.get('file', '')))}` "
                    f"| `{cls._escape_md_cell(str(ym.get('rule', '')))}` "
                    f"| `{cls._escape_md_cell(str(ym.get('severity', '')))}` "
                    f"| `{cls._escape_md_cell(str(ym.get('mitre_attack', '')))}` "
                    f"| {cls._escape_md_cell(str(ym.get('description', '')))} |"
                )
            lines.append("")
        else:
            lines.extend(["*Không khớp luật YARA nào.*", ""])

        lines.extend(["## 6. Ánh Xạ MITRE ATT&CK", ""])
        if fa.mitre_attack:
            lines.extend(
                [
                    "| Technique ID | Tên kỹ thuật | Tactic | Bằng chứng quan sát |",
                    "|---|---|---|---|",
                ]
            )
            for tech in fa.mitre_attack:
                lines.append(
                    f"| `{cls._escape_md_cell(tech.technique_id)}` "
                    f"| {cls._escape_md_cell(tech.name)} "
                    f"| `{cls._escape_md_cell(tech.tactic)}` "
                    f"| {cls._escape_md_cell(tech.evidence)} |"
                )
            lines.append("")
        else:
            lines.extend(["*Chưa có ánh xạ MITRE ATT&CK.*", ""])

        lines.extend(["## 7. Khuyến Nghị Xử Lý (Recommendations)", ""])
        if fa.recommendations:
            for rec in fa.recommendations:
                lines.append(f"- {rec}")
        else:
            lines.append("- Tiếp tục theo dõi và kiểm tra thủ công trong môi trường cô lập.")
        lines.append("")

        lines.extend(["## 8. Lịch Sử Suy Luận ReAct (Reasoning Trace)", ""])
        for step in result.reasoning_trace:
            lines.extend(
                [
                    f"### Bước {step.iteration} — `{step.action}` ({step.elapsed_ms} ms, self-corrections: {step.self_corrections})",
                    f"- **Thought:** {step.thought or 'N/A'}",
                    f"- **Action Input:** `{json.dumps(step.action_input, ensure_ascii=False)}`",
                    "",
                    "<details>",
                    "<summary>Observation</summary>",
                    "",
                    "```json",
                    step.observation,
                    "```",
                    "</details>",
                    "",
                ]
            )

        return "\n".join(lines).rstrip() + "\n"

    @classmethod
    def generate(
        cls,
        result: AnalysisResult,
        output_dir: Path | str = REPORTS_DIR,
    ) -> tuple[Path, Path]:
        """Lưu đồng thời file báo cáo `.json` và `.md` vào `output_dir`."""
        target_dir = Path(output_dir)
        target_dir.mkdir(parents=True, exist_ok=True)

        stem = Path(result.sample_path).stem
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = target_dir / f"{stem}_{stamp}.json"
        md_path = target_dir / f"{stem}_{stamp}.md"

        json_payload = result.model_dump(mode="json")
        json_path.write_text(json.dumps(json_payload, ensure_ascii=False, indent=2), encoding="utf-8")
        md_path.write_text(cls.render_markdown(result), encoding="utf-8")

        return json_path, md_path
