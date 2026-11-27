"""System Prompt, bảng tham chiếu MITRE ATT&CK và các mẫu prompt Self-Correction
tối ưu riêng cho Small Language Models (7B/8B GGUF Q4_K_M) vận hành theo kiến trúc ReAct.
"""

from __future__ import annotations

import json
from tools import TOOL_DESCRIPTIONS

MITRE_INFOSTEALER_REF: dict[str, dict[str, str]] = {
    "T1555.003": {
        "name": "Credentials from Password Stores: Credentials from Web Browsers",
        "tactic": "Credential Access",
    },
    "T1539": {
        "name": "Steal Web Session Cookie",
        "tactic": "Credential Access",
    },
    "T1528": {
        "name": "Steal Application Access Token",
        "tactic": "Credential Access",
    },
    "T1005": {
        "name": "Data from Local System",
        "tactic": "Collection",
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
    },
    "T1027.002": {
        "name": "Obfuscated Files or Information: Software Packing",
        "tactic": "Defense Evasion",
    },
    "T1059.006": {
        "name": "Command and Scripting Interpreter: Python",
        "tactic": "Execution",
    },
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
    },
    "T1567": {
        "name": "Exfiltration Over Web Service",
        "tactic": "Exfiltration",
    },
    "T1102": {
        "name": "Web Service",
        "tactic": "Command and Control",
    },
}

FINAL_ANSWER_SCHEMA_EXAMPLE: str = json.dumps(
    {
        "verdict": "MALICIOUS | SUSPICIOUS | BENIGN",
        "risk_score": 85,
        "confidence": "HIGH | MEDIUM | LOW",
        "behavior_summary": "Tóm tắt ngắn gọn các hành vi đã quan sát được từ Observation.",
        "iocs": {
            "urls": [],
            "discord_webhooks": [],
            "telegram_bot_tokens": [],
            "ipv4": [],
            "domains": [],
            "btc_wallets": [],
            "eth_wallets": [],
        },
        "mitre_attack": [
            {
                "technique_id": "T1555.003",
                "name": "Credentials from Password Stores: Credentials from Web Browsers",
                "tactic": "Credential Access",
                "evidence": "Truy cập Chrome Login Data và Local State để giải mã DPAPI/AES-GCM.",
            }
        ],
        "recommendations": [
            "Cô lập endpoint và thu hồi toàn bộ token/mật khẩu trình duyệt có nguy cơ lộ lọt."
        ],
    },
    ensure_ascii=False,
    indent=2,
)


def _format_tools_block() -> str:
    """Biên dịch danh sách tool ngắn gọn để không lãng phí token context của SLM."""
    lines: list[str] = []
    for idx, tool in enumerate(TOOL_DESCRIPTIONS, start=1):
        lines.append(
            f"{idx}. {tool['name']}\n"
            f"   Args JSON: {tool['args']}\n"
            f"   Desc: {tool['description']}"
        )
    return "\n".join(lines)


def _format_mitre_block() -> str:
    """Liệt kê bảng mã MITRE ATT&CK tham chiếu nhanh cho InfoStealer."""
    return "\n".join(
        f"- {tid}: {info['name']} [{info['tactic']}]"
        for tid, info in MITRE_INFOSTEALER_REF.items()
    )


def build_system_prompt() -> str:
    """Tạo System Prompt chuẩn hóa cho vòng lặp ReAct trên Local SLM."""
    return f"""Bạn là AI Chuyên gia Phân tích Mã độc Tĩnh (Senior Malware Analyst) chuyên điều tra InfoStealer viết bằng .NET và Python.
MÔI TRƯỜNG AN TOÀN: Chỉ thực hiện phân tích tĩnh bằng các công cụ bên dưới; KHÔNG BAO GIỜ giả định đã thực thi mẫu. Chỉ kết luận dựa trên bằng chứng thực tế trong Observation.

=== DANH SÁCH CÔNG CỤ (TOOLS) ===
{_format_tools_block()}

=== QUY TRÌNH ĐIỀU TRA BẮT BUỘC ===
1. LUÔN gọi `identify_file_type` đầu tiên trên mẫu cần kiểm tra.
2. Dựa vào `detected_type`:
   - Nếu là `.NET Assembly`: gọi `analyze_dotnet_binary`.
   - Nếu là `PyInstaller` hoặc `.pyc`: gọi `unpack_and_decompile_python`. Nếu tạo ra `decompiled_py_path`, tiếp tục gọi `ast_python_scanner` với `source_code` là đường dẫn file đó.
   - Nếu là `Python Script`: gọi `ast_python_scanner`.
3. LUÔN gọi `extract_iocs_and_yara` trên đường dẫn file mẫu (hoặc `extracted_dir` nếu đã giải nén) trước khi đưa ra `Final Answer`.
4. Không gọi lặp lại cùng một công cụ với cùng tham số đã chạy.

=== BẢNG THAM CHIẾU MITRE ATT&CK (INFOSTEALER) ===
{_format_mitre_block()}

=== ĐỊNH DẠNG ĐẦU RA NGHIÊM NGẶT ===
Mỗi lượt phản hồi BẮT BUỘC chỉ có đúng 3 dòng/khối theo mẫu sau (KHÔNG viết thêm `Observation:`):
Thought: <suy luận ngắn gọn 1-3 câu dựa trên bằng chứng hiện có>
Action: <tên chính xác một công cụ ở trên HOẶC Final Answer>
Action Input: <một JSON object hợp lệ dùng dấu ngoặc kép chuẩn>

Khi đã thu thập đủ bằng chứng và sẵn sàng kết luận, đặt `Action: Final Answer` và `Action Input:` là JSON đúng schema sau:
{FINAL_ANSWER_SCHEMA_EXAMPLE}
"""


def build_initial_user_prompt(sample_path: str) -> str:
    """Tạo prompt khởi đầu đưa mẫu nghi ngờ vào vòng lặp điều tra ReAct."""
    return (
        f"Hãy điều tra tĩnh toàn diện mẫu nghi ngờ tại đường dẫn: `{sample_path}`.\n"
        "Bắt đầu bằng `identify_file_type`, đi theo đúng nhánh công cụ cho .NET/Python, "
        "quét `extract_iocs_and_yara`, sau đó tổng hợp kết quả cuối cùng với `Action: Final Answer`."
    )


def build_self_correction_prompt(error_reason: str, expected_format: str) -> str:
    """Tạo prompt ép SLM tự sửa lỗi định dạng JSON hoặc tên tool không hợp lệ."""
    return (
        f"[SELF-CORRECTION REQUIRED]\n"
        f"Phản hồi vừa rồi không hợp lệ vì lý do: {error_reason}\n\n"
        f"Hãy trả lời lại NGAY LẬP TỨC theo đúng cấu trúc:\n"
        f"{expected_format}\n"
        "Lưu ý: `Action Input` PHẢI là một JSON object hợp lệ (dùng dấu ngoặc kép \", không trailing comma, không viết `Observation:`)."
    )


def build_force_final_prompt() -> str:
    """Yêu cầu SLM tổng hợp ngay Final Answer khi đã chạm ngưỡng vòng lặp tối đa."""
    return (
        "[MAX ITERATIONS REACHED]\n"
        "Bạn đã đạt giới hạn số bước điều tra. Không gọi thêm công cụ nào nữa.\n"
        "Hãy xuất ngay `Thought:`, `Action: Final Answer` và `Action Input:` chứa JSON tổng hợp đầy đủ "
        "bằng chứng, IOCs và MITRE ATT&CK từ các Observation đã thu thập.\n"
        f"Schema JSON bắt buộc:\n{FINAL_ANSWER_SCHEMA_EXAMPLE}"
    )
