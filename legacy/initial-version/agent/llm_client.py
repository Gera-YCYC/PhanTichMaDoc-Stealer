"""Client kết nối Local SLM qua Ollama HTTP API và chế độ DeterministicMockLLM
phục vụ kiểm thử toàn luồng ReAct offline không cần GPU/Ollama daemon.
"""

from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from typing import Any

import requests

from config import OLLAMA_BASE_URL, OLLAMA_MODEL, OLLAMA_TIMEOUT


class LLMClientError(RuntimeError):
    """Lỗi giao tiếp với Local SLM (Ollama API hoặc phản hồi không hợp lệ)."""


class BaseLLMClient(ABC):
    """Giao diện chung cho các backend SLM dùng trong ReAct Engine."""

    @property
    @abstractmethod
    def model_name(self) -> str:
        """Tên định danh của mô hình đang chạy."""

    @abstractmethod
    def chat(self, messages: list[dict[str, str]]) -> str:
        """Gửi lịch sử hội thoại và nhận chuỗi phản hồi từ mô hình."""


class OllamaClient(BaseLLMClient):
    """Client tối ưu cho SLM lượng tử hóa (GGUF Q4_K_M) chạy cục bộ trên Ollama."""

    def __init__(
        self,
        base_url: str = OLLAMA_BASE_URL,
        model: str = OLLAMA_MODEL,
        timeout: int = OLLAMA_TIMEOUT,
        num_ctx: int = 8192,
        temperature: float = 0.1,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._model = model
        self.timeout = timeout
        self.num_ctx = num_ctx
        self.temperature = temperature
        self._force_cpu = False
        self._session = requests.Session()

    @property
    def model_name(self) -> str:
        return self._model

    def check_connection(self) -> tuple[bool, str]:
        """Kiểm tra dịch vụ Ollama và sự tồn tại của model cục bộ trước khi phân tích."""
        tags_url = f"{self.base_url}/api/tags"
        try:
            resp = self._session.get(tags_url, timeout=8)
            resp.raise_for_status()
            payload = resp.json()
        except requests.RequestException as exc:
            return (
                False,
                f"Không thể kết nối tới Ollama tại {self.base_url} ({exc}). "
                "Hãy khởi động Ollama hoặc chạy thử với cờ `--mock-llm`.",
            )
        except ValueError as exc:
            return False, f"Phản hồi /api/tags không hợp lệ từ Ollama: {exc}"

        models_raw = payload.get("models") or []
        available = [m.get("name", "") for m in models_raw if m.get("name")]
        if not available:
            return (
                False,
                f"Ollama đang chạy tại {self.base_url} nhưng chưa cài model nào. "
                f"Hãy chạy `ollama pull {self._model}`.",
            )

        target_base = self._model.split(":")[0]
        exact_match = self._model in available or f"{self._model}:latest" in available
        if not exact_match and not any(m == self._model or m == f"{target_base}:latest" for m in available):
            avail_str = ", ".join(available)
            return (
                False,
                f"Model `{self._model}` chưa được cài trên Ollama. "
                f"Các model hiện có: [{avail_str}]. "
                f"Bạn có thể chạy lại với `--model {available[0]}` hoặc tải về bằng `ollama pull {self._model}`.",
            )

        return True, f"Kết nối Ollama thành công ({self.base_url}, model={self._model})."

    def _send_chat_request(self, messages: list[dict[str, str]], force_cpu: bool) -> dict[str, Any]:
        chat_url = f"{self.base_url}/api/chat"
        options: dict[str, Any] = {
            "temperature": self.temperature,
            "num_ctx": min(self.num_ctx, 4096) if force_cpu else self.num_ctx,
            "repeat_penalty": 1.1,
            "stop": ["Observation:", "\nObservation"],
        }
        if force_cpu:
            options["num_gpu"] = 0

        body: dict[str, Any] = {
            "model": self._model,
            "messages": messages,
            "stream": False,
            "options": options,
        }
        try:
            resp = self._session.post(chat_url, json=body, timeout=self.timeout)
            if resp.status_code >= 400:
                err_detail = resp.text[:400]
                try:
                    err_json = resp.json()
                    if isinstance(err_json, dict) and err_json.get("error"):
                        err_detail = str(err_json["error"])
                except ValueError:
                    pass
                raise LLMClientError(f"HTTP {resp.status_code} từ Ollama ({chat_url}): {err_detail}")
            return resp.json()
        except LLMClientError:
            raise
        except requests.Timeout as exc:
            raise LLMClientError(f"Ollama quá thời gian chờ ({self.timeout}s): {exc}") from exc
        except requests.RequestException as exc:
            raise LLMClientError(f"Lỗi HTTP khi gọi Ollama API ({chat_url}): {exc}") from exc
        except ValueError as exc:
            raise LLMClientError(f"Ollama trả về JSON không hợp lệ: {exc}") from exc

    def chat(self, messages: list[dict[str, str]]) -> str:
        """Gửi yêu cầu suy luận tới /api/chat của Ollama với tự động fallback CPU nếu lỗi CUDA/VRAM."""
        try:
            data = self._send_chat_request(messages, force_cpu=self._force_cpu)
        except LLMClientError as exc:
            err_low = str(exc).lower()
            if not self._force_cpu and any(k in err_low for k in ("cuda", "vram", "out of memory", "gpu")):
                self._force_cpu = True
                data = self._send_chat_request(messages, force_cpu=True)
            else:
                raise

        message = data.get("message") or {}
        content = message.get("content")
        if not content or not isinstance(content, str):
            raise LLMClientError(f"Ollama trả về phản hồi rỗng: {data}")
        return content.strip()


class DeterministicMockLLM(BaseLLMClient):
    """SLM giả lập tất định dùng để kiểm thử luồng ReAct + Tools + Reporting offline."""

    _SAMPLE_PATH_RE = re.compile(r"`([^`]+)`")

    def __init__(self, model: str = "mock-slm-react-v1") -> None:
        self._model = model

    @property
    def model_name(self) -> str:
        return self._model

    @staticmethod
    def _extract_observations(messages: list[dict[str, str]]) -> list[dict[str, Any]]:
        """Trích xuất các JSON Observation thật đã được ReAct Engine trả về trong hội thoại."""
        obs_list: list[dict[str, Any]] = []
        for msg in messages:
            if msg.get("role") != "user":
                continue
            text = msg.get("content", "")
            if not text.startswith("Observation:"):
                continue
            raw_json = text[len("Observation:") :].strip()
            try:
                parsed = json.loads(raw_json)
                if isinstance(parsed, dict):
                    obs_list.append(parsed)
            except ValueError:
                continue
        return obs_list

    def _extract_sample_path(self, messages: list[dict[str, str]]) -> str:
        for msg in messages:
            if msg.get("role") == "user":
                match = self._SAMPLE_PATH_RE.search(msg.get("content", ""))
                if match:
                    return match.group(1)
        return "samples/benign_stealer_sim.py"

    @staticmethod
    def _format_turn(thought: str, action: str, action_input: dict[str, Any]) -> str:
        payload = json.dumps(action_input, ensure_ascii=False)
        return f"Thought: {thought}\nAction: {action}\nAction Input: {payload}"

    def chat(self, messages: list[dict[str, str]]) -> str:
        sample_path = self._extract_sample_path(messages)
        observations = self._extract_observations(messages)
        by_tool: dict[str, dict[str, Any]] = {
            str(obs.get("tool")): obs for obs in observations if obs.get("tool")
        }

        if "identify_file_type" not in by_tool:
            return self._format_turn(
                "Bước đầu tiên cần xác định định dạng file, entropy và hash của mẫu nghi ngờ.",
                "identify_file_type",
                {"file_path": sample_path},
            )

        id_obs = by_tool["identify_file_type"]
        detected_type = str(id_obs.get("detected_type", ""))

        if ".NET" in detected_type and "analyze_dotnet_binary" not in by_tool:
            return self._format_turn(
                "Mẫu được nhận diện là .NET Assembly; tiến hành phân tích metadata và dịch ngược C#.",
                "analyze_dotnet_binary",
                {"file_path": sample_path},
            )

        if (
            "PyInstaller" in detected_type or "Python Bytecode" in detected_type
        ) and "unpack_and_decompile_python" not in by_tool:
            return self._format_turn(
                "Mẫu được đóng gói PyInstaller/Bytecode Python; cần giải nén và dịch ngược .pyc chính.",
                "unpack_and_decompile_python",
                {"file_path": sample_path},
            )

        if "unpack_and_decompile_python" in by_tool and "ast_python_scanner" not in by_tool:
            decompiled_py = by_tool["unpack_and_decompile_python"].get("decompiled_py_path")
            if decompiled_py:
                return self._format_turn(
                    "Đã dịch ngược được mã nguồn Python từ PyInstaller; quét AST để tìm API nguy hiểm.",
                    "ast_python_scanner",
                    {"source_code": decompiled_py},
                )

        if "Python Script" in detected_type and "ast_python_scanner" not in by_tool:
            return self._format_turn(
                "Mẫu là mã nguồn Python; sử dụng ast_python_scanner để phát hiện lời gọi nguy hiểm và làm rối.",
                "ast_python_scanner",
                {"source_code": sample_path},
            )

        if "extract_iocs_and_yara" not in by_tool:
            target = sample_path
            if "unpack_and_decompile_python" in by_tool:
                target = by_tool["unpack_and_decompile_python"].get("extracted_dir") or sample_path
            return self._format_turn(
                "Cần trích xuất toàn bộ IOCs (C2, Webhook, Bot Token, Ví Crypto) và quét đối chiếu YARA.",
                "extract_iocs_and_yara",
                {"target_path": target},
            )

        return self._build_final_turn(by_tool)

    def _build_final_turn(self, by_tool: dict[str, dict[str, Any]]) -> str:
        ast_obs = by_tool.get("ast_python_scanner", {})
        ioc_obs = by_tool.get("extract_iocs_and_yara", {})
        dn_obs = by_tool.get("analyze_dotnet_binary", {})

        iocs = ioc_obs.get("iocs") or {}
        yara_matches = (ioc_obs.get("yara_scan") or {}).get("matches") or []
        risk_score = int(ast_obs.get("static_risk_score") or 0)
        if yara_matches:
            risk_score = max(risk_score, min(40 + len(yara_matches) * 15, 95))
        if iocs.get("discord_webhooks") or iocs.get("telegram_bot_tokens"):
            risk_score = max(risk_score, 85)

        verdict = "MALICIOUS" if risk_score >= 70 else ("SUSPICIOUS" if risk_score >= 35 else "BENIGN")
        confidence = "HIGH" if (yara_matches or risk_score >= 70) else "MEDIUM"

        mitre_list: list[dict[str, str]] = []
        seen_tids: set[str] = set()
        for match in yara_matches:
            tid = str(match.get("mitre_attack") or "").strip()
            if tid and tid not in seen_tids:
                seen_tids.add(tid)
                mitre_list.append(
                    {
                        "technique_id": tid,
                        "name": str(match.get("rule", tid)),
                        "tactic": "Malware Behavior",
                        "evidence": str(match.get("description") or f"Matched YARA rule {match.get('rule')}"),
                    }
                )
        if ast_obs.get("obfuscation_flags") and "T1027" not in seen_tids:
            seen_tids.add("T1027")
            mitre_list.append(
                {
                    "technique_id": "T1027",
                    "name": "Obfuscated Files or Information",
                    "tactic": "Defense Evasion",
                    "evidence": "; ".join(ast_obs["obfuscation_flags"][:2]),
                }
            )
        if (iocs.get("discord_webhooks") or iocs.get("telegram_bot_tokens")) and "T1567" not in seen_tids:
            seen_tids.add("T1567")
            mitre_list.append(
                {
                    "technique_id": "T1567",
                    "name": "Exfiltration Over Web Service",
                    "tactic": "Exfiltration",
                    "evidence": "Phát hiện cấu hình gửi dữ liệu qua Discord Webhook / Telegram Bot API.",
                }
            )
        if dn_obs.get("suspicious_string_categories") and "T1555.003" not in seen_tids:
            seen_tids.add("T1555.003")
            mitre_list.append(
                {
                    "technique_id": "T1555.003",
                    "name": "Credentials from Password Stores: Credentials from Web Browsers",
                    "tactic": "Credential Access",
                    "evidence": "Phát hiện chuỗi API .NET liên quan đến trình duyệt và giải mã DPAPI/AES.",
                }
            )

        summary_parts = [
            f"Mẫu được phân loại `{by_tool.get('identify_file_type', {}).get('detected_type', 'unknown')}`."
        ]
        if yara_matches:
            rule_names = ", ".join(str(m.get("rule")) for m in yara_matches[:5])
            summary_parts.append(f"Khớp {len(yara_matches)} luật YARA ({rule_names}).")
        if ast_obs.get("stealer_indicators") or ast_obs.get("dangerous_calls"):
            summary_parts.append(
                f"Phân tích AST phát hiện {len(ast_obs.get('dangerous_calls', []))} lời gọi nguy hiểm "
                f"và {len(ast_obs.get('stealer_indicators', []))} dấu hiệu truy cập thông tin nhạy cảm."
            )
        if iocs:
            summary_parts.append(f"Trích xuất được {ioc_obs.get('total_ioc_count', 0)} IOCs liên quan đến hạ tầng C2/Exfiltration và ví crypto.")

        final_payload = {
            "verdict": verdict,
            "risk_score": risk_score,
            "confidence": confidence,
            "behavior_summary": " ".join(summary_parts),
            "iocs": iocs,
            "mitre_attack": mitre_list,
            "recommendations": [
                "Chặn các domain/IP/Webhook C2 phát hiện được tại Firewall/Proxy và kiểm tra nhật ký truy cập.",
                "Thu hồi mật khẩu trình duyệt, Discord token, Telegram session và kiểm tra ví crypto trên máy nghi nhiễm.",
                "Giữ nguyên mẫu trong môi trường cô lập; không thực thi trực tiếp trên hệ thống thật.",
            ],
        }
        return self._format_turn(
            "Đã có đủ bằng chứng từ nhận diện file, phân tích tĩnh AST/binary và quét IOC/YARA. Tiến hành kết luận.",
            "Final Answer",
            final_payload,
        )
