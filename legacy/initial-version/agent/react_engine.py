"""Lõi suy luận ReAct (Pure Python State Machine) tối ưu độ ổn định cho Local SLM:
- Parse linh hoạt Thought / Action / Action Input (hỗ trợ repair JSON lỗi nhẹ).
- Cơ chế Self-Correction tự động nhắc SLM sửa lỗi cú pháp/schema.
- Chống lặp vô hạn (duplicate action guard + max_iterations = 8).
- Hợp nhất bằng chứng thực tế từ tools vào Final Answer để tránh SLM bỏ sót IOC/MITRE.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from agent.llm_client import BaseLLMClient, LLMClientError
from agent.prompts import (
    MITRE_INFOSTEALER_REF,
    build_force_final_prompt,
    build_initial_user_prompt,
    build_self_correction_prompt,
    build_system_prompt,
)
from config import MAX_ITERATIONS
from tools import TOOL_REGISTRY


class AgentState(str, Enum):
    """Các trạng thái của máy trạng thái ReAct."""

    INIT = "INIT"
    THINKING = "THINKING"
    PARSING = "PARSING"
    SELF_CORRECTING = "SELF_CORRECTING"
    EXECUTING_TOOL = "EXECUTING_TOOL"
    FINALIZING = "FINALIZING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class MITRETechnique(BaseModel):
    """Một kỹ thuật MITRE ATT&CK được ánh xạ từ bằng chứng phân tích."""

    technique_id: str
    name: str
    tactic: str = "Unknown"
    evidence: str = ""


class FinalAnalysisPayload(BaseModel):
    """Schema đầu ra chuẩn cho bước Final Answer."""

    verdict: Literal["MALICIOUS", "SUSPICIOUS", "BENIGN"]
    risk_score: int = Field(ge=0, le=100)
    confidence: Literal["HIGH", "MEDIUM", "LOW"]
    behavior_summary: str
    iocs: dict[str, list[str]] = Field(default_factory=dict)
    mitre_attack: list[MITRETechnique] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)

    @field_validator("verdict", mode="before")
    @classmethod
    def _normalize_verdict(cls, value: Any) -> str:
        text = str(value or "SUSPICIOUS").strip().upper()
        if text not in {"MALICIOUS", "SUSPICIOUS", "BENIGN"}:
            return "SUSPICIOUS"
        return text

    @field_validator("confidence", mode="before")
    @classmethod
    def _normalize_confidence(cls, value: Any) -> str:
        text = str(value or "MEDIUM").strip().upper()
        if text not in {"HIGH", "MEDIUM", "LOW"}:
            return "MEDIUM"
        return text

    @field_validator("risk_score", mode="before")
    @classmethod
    def _clamp_risk_score(cls, value: Any) -> int:
        try:
            score = int(float(value))
        except (TypeError, ValueError):
            score = 50
        return max(0, min(100, score))


class ReasoningStep(BaseModel):
    """Một bước trong lịch sử suy luận Thought -> Action -> Observation."""

    iteration: int
    thought: str
    action: str
    action_input: dict[str, Any] = Field(default_factory=dict)
    observation: str = ""
    self_corrections: int = 0
    elapsed_ms: int = 0


class AnalysisResult(BaseModel):
    """Kết quả phân tích hoàn chỉnh trả về cho ReportGenerator và CLI."""

    model_config = ConfigDict(protected_namespaces=())

    sample_path: str
    model_name: str
    timestamp: str
    file_type: str = "unknown"
    hashes: dict[str, Any] = Field(default_factory=dict)
    yara_matches: list[dict[str, Any]] = Field(default_factory=list)
    final_analysis: FinalAnalysisPayload
    reasoning_trace: list[ReasoningStep] = Field(default_factory=list)
    iterations_used: int = 0
    total_self_corrections: int = 0
    elapsed_seconds: float = 0.0
    status: str = "completed"


@dataclass
class ParsedTurn:
    """Kết quả parse một phản hồi từ SLM."""

    thought: str
    action: str
    action_input: dict[str, Any]
    raw_response: str


class ReActParser:
    """Bộ phân tích đầu ra ReAct có khả năng sửa lỗi JSON thường gặp ở SLM 7B/8B."""

    _THOUGHT_RE = re.compile(
        r"(?:\*{0,2}Thought\*{0,2}\s*:)(.*?)(?=\*{0,2}Action\*{0,2}\s*:|\Z)",
        re.IGNORECASE | re.DOTALL,
    )
    _ACTION_RE = re.compile(
        r"\*{0,2}Action\*{0,2}\s*:\s*([^\n\r]+)",
        re.IGNORECASE,
    )
    _ACTION_INPUT_RE = re.compile(
        r"\*{0,2}Action\s*Input\*{0,2}\s*:\s*(.*)$",
        re.IGNORECASE | re.DOTALL,
    )

    _TOOL_PARAM_MAP: dict[str, tuple[str, tuple[str, ...]]] = {
        "identify_file_type": ("file_path", ("path", "target_path", "file", "sample_path")),
        "analyze_dotnet_binary": ("file_path", ("path", "target_path", "file", "sample_path")),
        "unpack_and_decompile_python": ("file_path", ("path", "target_path", "file", "sample_path")),
        "ast_python_scanner": ("source_code", ("file_path", "path", "code", "source")),
        "extract_iocs_and_yara": ("target_path", ("file_path", "path", "dir_path", "sample_path")),
    }

    @classmethod
    def parse(cls, raw_text: str) -> ParsedTurn:
        """Tách Thought, Action, Action Input và kiểm tra tính hợp lệ."""
        if not raw_text or not raw_text.strip():
            raise ValueError("SLM trả về chuỗi rỗng.")

        cleaned = raw_text.strip()

        # Trường hợp SLM xuất thẳng JSON object gốc chứa thought/action/action_input
        if cleaned.startswith("{") or cleaned.startswith("```json"):
            try:
                obj = cls._extract_and_repair_json(cleaned)
                if "action" in obj:
                    thought = str(obj.get("thought") or "").strip()
                    action = cls._normalize_action_name(str(obj["action"]))
                    raw_in = obj.get("action_input", {})
                    if isinstance(raw_in, str):
                        raw_in = cls._extract_and_repair_json(raw_in)
                    if not isinstance(raw_in, dict):
                        raise ValueError("`action_input` phải là JSON object.")
                    norm_in = cls._validate_and_normalize_action(action, raw_in)
                    return ParsedTurn(thought=thought, action=action, action_input=norm_in, raw_response=raw_text)
            except ValueError:
                pass

        action_match = cls._ACTION_RE.search(cleaned)
        if not action_match:
            raise ValueError("Thiếu dòng `Action: <tên_tool hoặc Final Answer>`.")

        action = cls._normalize_action_name(action_match.group(1))

        thought_match = cls._THOUGHT_RE.search(cleaned)
        thought = thought_match.group(1).strip() if thought_match else ""

        input_match = cls._ACTION_INPUT_RE.search(cleaned)
        if not input_match:
            raise ValueError("Thiếu dòng `Action Input: {...}`.")

        raw_input_text = input_match.group(1).strip()
        # Cắt bỏ nếu SLM lỡ sinh thêm `Observation:` ở cuối
        obs_idx = re.search(r"\n\s*Observation\s*:", raw_input_text, re.IGNORECASE)
        if obs_idx:
            raw_input_text = raw_input_text[: obs_idx.start()].strip()

        parsed_input = cls._extract_and_repair_json(raw_input_text)
        normalized_input = cls._validate_and_normalize_action(action, parsed_input)

        return ParsedTurn(
            thought=thought,
            action=action,
            action_input=normalized_input,
            raw_response=raw_text,
        )

    @staticmethod
    def _normalize_action_name(raw_action: str) -> str:
        name = raw_action.strip().strip("`\"'").strip()
        if name.lower().replace("_", " ") == "final answer":
            return "Final Answer"
        # Bỏ phần ngoặc () nếu SLM viết kiểu `identify_file_type()`
        if name.endswith("()"):
            name = name[:-2].strip()
        return name

    @classmethod
    def _validate_and_normalize_action(cls, action: str, args: dict[str, Any]) -> dict[str, Any]:
        if action == "Final Answer":
            return args

        if action not in TOOL_REGISTRY:
            valid = ", ".join(sorted(TOOL_REGISTRY.keys()))
            raise ValueError(f"Công cụ `{action}` không tồn tại. Chỉ được dùng: {valid} hoặc `Final Answer`.")

        if action in cls._TOOL_PARAM_MAP:
            primary_key, aliases = cls._TOOL_PARAM_MAP[action]
            normalized = dict(args)
            if primary_key not in normalized or not str(normalized.get(primary_key, "")).strip():
                for alias in aliases:
                    val = normalized.get(alias)
                    if isinstance(val, str) and val.strip():
                        normalized[primary_key] = val.strip()
                        break
            if primary_key not in normalized or not str(normalized.get(primary_key, "")).strip():
                raise ValueError(
                    f"Công cụ `{action}` bắt buộc có tham số chuỗi `{primary_key}` trong `Action Input`."
                )
            # Chỉ giữ các tham số hợp lệ của hàm tool
            if action == "extract_iocs_and_yara" and "yara_rules_path" in normalized:
                return {
                    primary_key: str(normalized[primary_key]),
                    "yara_rules_path": str(normalized["yara_rules_path"]),
                }
            return {primary_key: str(normalized[primary_key])}

        return args

    @staticmethod
    def _strip_code_fences(text: str) -> str:
        stripped = text.strip()
        fence = re.search(r"```(?:json)?\s*(.*?)```", stripped, re.DOTALL | re.IGNORECASE)
        if fence:
            return fence.group(1).strip()
        return stripped

    @staticmethod
    def _extract_balanced_brace_block(text: str) -> str:
        start = text.find("{")
        if start == -1:
            raise ValueError("Không tìm thấy JSON object `{...}` trong `Action Input`.")

        depth = 0
        in_string = False
        escape = False
        for idx in range(start, len(text)):
            ch = text[idx]
            if escape:
                escape = False
                continue
            if ch == "\\" and in_string:
                escape = True
                continue
            if ch == '"':
                in_string = not in_string
                continue
            if not in_string:
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        return text[start : idx + 1]
        raise ValueError("JSON object trong `Action Input` bị thiếu dấu đóng ngoặc `}`.")

    @staticmethod
    def _remove_trailing_commas(json_str: str) -> str:
        """Loại bỏ dấu phẩy thừa trước `}` hoặc `]` ngoài chuỗi JSON."""
        out: list[str] = []
        in_string = False
        escape = False
        length = len(json_str)

        for i, ch in enumerate(json_str):
            if escape:
                out.append(ch)
                escape = False
                continue
            if ch == "\\" and in_string:
                out.append(ch)
                escape = True
                continue
            if ch == '"':
                in_string = not in_string
                out.append(ch)
                continue
            if not in_string and ch == ",":
                j = i + 1
                while j < length and json_str[j] in " \t\r\n":
                    j += 1
                if j < length and json_str[j] in "}]":
                    continue
            out.append(ch)
        return "".join(out)

    @classmethod
    def _extract_and_repair_json(cls, raw_input: str) -> dict[str, Any]:
        candidate = cls._strip_code_fences(raw_input)
        block = cls._extract_balanced_brace_block(candidate)
        repaired = cls._remove_trailing_commas(block)
        try:
            obj = json.loads(repaired)
        except json.JSONDecodeError as exc:
            raise ValueError(f"JSON không hợp lệ tại vị trí {exc.pos}: {exc.msg}") from exc
        if not isinstance(obj, dict):
            raise ValueError("`Action Input` phải là một JSON object (`{...}`).")
        return obj


class ReActMalwareAgent:
    """Máy trạng thái ReAct điều phối quá trình phân tích tĩnh InfoStealer."""

    _EXPECTED_FORMAT_HINT = (
        "Thought: <nhận xét ngắn>\n"
        "Action: <tên_tool hoặc Final Answer>\n"
        'Action Input: {"tham_so": "gia_tri"}'
    )

    def __init__(
        self,
        llm_client: BaseLLMClient,
        max_iterations: int = MAX_ITERATIONS,
        max_self_corrections: int = 2,
        on_step: Callable[[ReasoningStep], None] | None = None,
    ) -> None:
        self.llm_client = llm_client
        self.max_iterations = max(1, max_iterations)
        self.max_self_corrections = max(0, max_self_corrections)
        self.on_step = on_step
        self.state = AgentState.INIT

    def analyze(self, sample_path: str) -> AnalysisResult:
        """Thực thi vòng lặp Thought -> Action -> Observation tối đa `max_iterations` bước."""
        start_time = time.perf_counter()
        self.state = AgentState.INIT

        messages: list[dict[str, str]] = [
            {"role": "system", "content": build_system_prompt()},
            {"role": "user", "content": build_initial_user_prompt(sample_path)},
        ]

        reasoning_trace: list[ReasoningStep] = []
        seen_calls: set[tuple[str, str]] = set()
        total_self_corrections = 0
        evidence: dict[str, Any] = {
            "file_type": "unknown",
            "hashes": {},
            "iocs": {},
            "yara_matches": [],
            "static_risk_score": 0,
            "obfuscation_flags": [],
            "stealer_indicators": [],
            "dangerous_calls": [],
            "dotnet_categories": {},
            "unpack_decompiled": False,
        }

        final_payload: FinalAnalysisPayload | None = None
        status = "completed"

        for iteration in range(1, self.max_iterations + 1):
            iter_start = time.perf_counter()
            parsed_turn, final_candidate, iter_corrections, raw_reply = self._think_and_parse(messages)
            total_self_corrections += iter_corrections

            if parsed_turn is None:
                # Hết số lần tự sửa ở lượt này; nếu đã có dữ liệu đủ để tiếp tục vẫn cố kết thúc an toàn
                status = "completed_with_fallback"
                break

            messages.append({"role": "assistant", "content": raw_reply})

            if final_candidate is not None:
                self.state = AgentState.FINALIZING
                final_payload = final_candidate
                step = ReasoningStep(
                    iteration=iteration,
                    thought=parsed_turn.thought,
                    action="Final Answer",
                    action_input=parsed_turn.action_input,
                    observation="Final analysis JSON validated successfully.",
                    self_corrections=iter_corrections,
                    elapsed_ms=int((time.perf_counter() - iter_start) * 1000),
                )
                reasoning_trace.append(step)
                if self.on_step:
                    self.on_step(step)
                break

            # Kiểm tra chống gọi trùng lặp cùng công cụ và tham số
            canonical_args = json.dumps(parsed_turn.action_input, sort_keys=True, ensure_ascii=False)
            call_key = (parsed_turn.action, canonical_args)
            if call_key in seen_calls:
                observation = json.dumps(
                    {
                        "status": "skipped_duplicate",
                        "tool": parsed_turn.action,
                        "message": "Công cụ này với cùng tham số đã được chạy trước đó. Hãy chuyển sang bước tiếp theo hoặc kết luận bằng Final Answer.",
                    },
                    ensure_ascii=False,
                )
            else:
                seen_calls.add(call_key)
                self.state = AgentState.EXECUTING_TOOL
                observation = self._execute_tool(parsed_turn.action, parsed_turn.action_input)
                self._collect_evidence(parsed_turn.action, observation, evidence)

            step = ReasoningStep(
                iteration=iteration,
                thought=parsed_turn.thought,
                action=parsed_turn.action,
                action_input=parsed_turn.action_input,
                observation=observation,
                self_corrections=iter_corrections,
                elapsed_ms=int((time.perf_counter() - iter_start) * 1000),
            )
            reasoning_trace.append(step)
            if self.on_step:
                self.on_step(step)

            messages.append({"role": "user", "content": f"Observation: {observation}"})

        # Nếu đạt max_iterations mà chưa có Final Answer -> ép xuất Final Answer 1 lượt cuối
        if final_payload is None:
            self.state = AgentState.FINALIZING
            messages.append({"role": "user", "content": build_force_final_prompt()})
            force_start = time.perf_counter()
            parsed_turn, final_candidate, force_corr, _ = self._think_and_parse(
                messages, force_final_only=True
            )
            total_self_corrections += force_corr
            if final_candidate is not None:
                final_payload = final_candidate
                step = ReasoningStep(
                    iteration=len(reasoning_trace) + 1,
                    thought=parsed_turn.thought if parsed_turn else "Forced final synthesis at max_iterations.",
                    action="Final Answer",
                    action_input=parsed_turn.action_input if parsed_turn else {},
                    observation="Forced final answer validated.",
                    self_corrections=force_corr,
                    elapsed_ms=int((time.perf_counter() - force_start) * 1000),
                )
                reasoning_trace.append(step)
                if self.on_step:
                    self.on_step(step)
            else:
                status = "completed_with_fallback"
                final_payload = self._synthesize_fallback_final_analysis(evidence)

        enriched_final = self._enrich_final_analysis(final_payload, evidence)
        self.state = AgentState.COMPLETED
        elapsed_seconds = round(time.perf_counter() - start_time, 2)

        return AnalysisResult(
            sample_path=sample_path,
            model_name=self.llm_client.model_name,
            timestamp=datetime.now(timezone.utc).isoformat(),
            file_type=evidence["file_type"],
            hashes=evidence["hashes"],
            yara_matches=evidence["yara_matches"],
            final_analysis=enriched_final,
            reasoning_trace=reasoning_trace,
            iterations_used=len(reasoning_trace),
            total_self_corrections=total_self_corrections,
            elapsed_seconds=elapsed_seconds,
            status=status,
        )

    def _think_and_parse(
        self,
        messages: list[dict[str, str]],
        force_final_only: bool = False,
    ) -> tuple[ParsedTurn | None, FinalAnalysisPayload | None, int, str]:
        """Gọi SLM, parse đầu ra và tự động yêu cầu Self-Correction khi sai định dạng."""
        corrections = 0
        working_messages = list(messages)
        last_reply = ""

        for attempt in range(self.max_self_corrections + 1):
            self.state = AgentState.THINKING if attempt == 0 else AgentState.SELF_CORRECTING
            try:
                last_reply = self.llm_client.chat(working_messages)
            except LLMClientError:
                if attempt == 0:
                    raise
                return None, None, corrections, last_reply

            self.state = AgentState.PARSING
            try:
                parsed = ReActParser.parse(last_reply)
                if force_final_only and parsed.action != "Final Answer":
                    raise ValueError("Đã đạt giới hạn vòng lặp, bắt buộc phải trả về `Action: Final Answer`.")

                if parsed.action == "Final Answer":
                    final_model = FinalAnalysisPayload.model_validate(parsed.action_input)
                    return parsed, final_model, corrections, last_reply

                return parsed, None, corrections, last_reply

            except (ValueError, ValidationError) as err:
                if attempt >= self.max_self_corrections:
                    return None, None, corrections, last_reply
                corrections += 1
                working_messages.append({"role": "assistant", "content": last_reply})
                working_messages.append(
                    {
                        "role": "user",
                        "content": build_self_correction_prompt(
                            error_reason=str(err),
                            expected_format=self._EXPECTED_FORMAT_HINT,
                        ),
                    }
                )

        return None, None, corrections, last_reply

    @staticmethod
    def _execute_tool(action: str, action_input: dict[str, Any]) -> str:
        """Gọi công cụ phân tích tĩnh đã đăng ký và bắt mọi ngoại lệ không mong muốn."""
        func = TOOL_REGISTRY.get(action)
        if func is None:
            return json.dumps({"status": "error", "error": f"Tool `{action}` not registered."})
        try:
            return func(**action_input)
        except Exception as exc:
            return json.dumps({"status": "error", "tool": action, "error": str(exc)}, ensure_ascii=False)

    @staticmethod
    def _collect_evidence(action: str, observation: str, evidence: dict[str, Any]) -> None:
        """Trích xuất dữ liệu cấu trúc từ Observation JSON để hỗ trợ hậu kiểm chứng và fallback."""
        try:
            obs = json.loads(observation)
        except ValueError:
            return
        if not isinstance(obs, dict):
            return

        if action == "identify_file_type" and obs.get("status") == "ok":
            evidence["file_type"] = obs.get("detected_type", evidence["file_type"])
            if isinstance(obs.get("hashes"), dict):
                evidence["hashes"] = obs["hashes"]

        elif action == "unpack_and_decompile_python" and obs.get("decompiled_py_path"):
            evidence["unpack_decompiled"] = True

        elif action == "ast_python_scanner" and obs.get("status") == "ok":
            evidence["static_risk_score"] = max(
                int(evidence["static_risk_score"]),
                int(obs.get("static_risk_score") or 0),
            )
            for key in ("obfuscation_flags", "stealer_indicators", "dangerous_calls"):
                items = obs.get(key) or []
                if isinstance(items, list):
                    evidence[key].extend(items)

        elif action == "analyze_dotnet_binary" and obs.get("status") == "ok":
            cats = obs.get("suspicious_string_categories") or {}
            if isinstance(cats, dict):
                evidence["dotnet_categories"].update(cats)

        elif action == "extract_iocs_and_yara" and obs.get("status") == "ok":
            iocs = obs.get("iocs") or {}
            if isinstance(iocs, dict):
                for k, vals in iocs.items():
                    if isinstance(vals, list):
                        existing = set(evidence["iocs"].get(k, []))
                        existing.update(str(v) for v in vals)
                        evidence["iocs"][k] = sorted(existing)

            yara_matches = (obs.get("yara_scan") or {}).get("matches") or []
            if isinstance(yara_matches, list):
                seen_rules = {(m.get("file"), m.get("rule")) for m in evidence["yara_matches"]}
                for m in yara_matches:
                    key = (m.get("file"), m.get("rule"))
                    if key not in seen_rules:
                        seen_rules.add(key)
                        evidence["yara_matches"].append(m)

    @staticmethod
    def _enrich_final_analysis(
        payload: FinalAnalysisPayload,
        evidence: dict[str, Any],
    ) -> FinalAnalysisPayload:
        """Hợp nhất IOCs và kỹ thuật MITRE thực tế từ tools vào Final Answer của SLM."""
        merged_iocs: dict[str, list[str]] = {
            k: list(dict.fromkeys(str(v) for v in vals))
            for k, vals in payload.iocs.items()
            if vals
        }
        for k, vals in evidence.get("iocs", {}).items():
            current = set(merged_iocs.get(k, []))
            current.update(str(v) for v in vals)
            if current:
                merged_iocs[k] = sorted(current)

        merged_mitre = list(payload.mitre_attack)
        seen_tids = {m.technique_id.upper() for m in merged_mitre}

        def add_mitre(tid: str, ev_text: str) -> None:
            norm_tid = tid.strip().upper()
            if not norm_tid or norm_tid in seen_tids:
                return
            ref = MITRE_INFOSTEALER_REF.get(norm_tid)
            if ref:
                seen_tids.add(norm_tid)
                merged_mitre.append(
                    MITRETechnique(
                        technique_id=norm_tid,
                        name=ref["name"],
                        tactic=ref["tactic"],
                        evidence=ev_text,
                    )
                )

        for ym in evidence.get("yara_matches", []):
            tid = str(ym.get("mitre_attack") or "")
            if tid:
                add_mitre(tid, f"YARA rule `{ym.get('rule')}` matched on `{ym.get('file')}`.")

        if evidence.get("obfuscation_flags"):
            add_mitre("T1027", "; ".join(str(x) for x in evidence["obfuscation_flags"][:2]))
        if merged_iocs.get("discord_webhooks") or merged_iocs.get("telegram_bot_tokens"):
            add_mitre("T1567", "Phát hiện URL Discord Webhook hoặc Telegram Bot API phục vụ trích xuất dữ liệu.")
        if "Python" in str(evidence.get("file_type", "")):
            add_mitre("T1059.006", f"Mẫu thuộc loại `{evidence['file_type']}`.")

        return payload.model_copy(
            update={
                "iocs": merged_iocs,
                "mitre_attack": merged_mitre,
            }
        )

    @classmethod
    def _synthesize_fallback_final_analysis(cls, evidence: dict[str, Any]) -> FinalAnalysisPayload:
        """Tạo FinalAnalysisPayload dự phòng từ bằng chứng thực tế nếu SLM hết vòng lặp."""
        yara_count = len(evidence.get("yara_matches", []))
        ioc_count = sum(len(v) for v in evidence.get("iocs", {}).values())
        score = int(evidence.get("static_risk_score") or 0)
        if yara_count:
            score = max(score, min(40 + yara_count * 15, 95))
        if ioc_count and score < 60:
            score = min(score + 25, 90)

        verdict: Literal["MALICIOUS", "SUSPICIOUS", "BENIGN"] = (
            "MALICIOUS" if score >= 70 else ("SUSPICIOUS" if score >= 35 else "BENIGN")
        )
        confidence: Literal["HIGH", "MEDIUM", "LOW"] = "HIGH" if yara_count >= 2 else "MEDIUM"

        summary = (
            f"Tổng hợp tự động sau khi đạt giới hạn vòng lặp: mẫu `{evidence.get('file_type', 'unknown')}` "
            f"khớp {yara_count} luật YARA, phát hiện {ioc_count} IOCs và điểm rủi ro AST {evidence.get('static_risk_score', 0)}/100."
        )
        base = FinalAnalysisPayload(
            verdict=verdict,
            risk_score=score,
            confidence=confidence,
            behavior_summary=summary,
            iocs=evidence.get("iocs", {}),
            mitre_attack=[],
            recommendations=[
                "Cách ly mẫu và rà soát toàn bộ IOCs (C2/Webhook/Token) trong nhật ký mạng.",
                "Đổi mật khẩu trình duyệt và thu hồi phiên Discord/Telegram nếu nghi ngờ lây nhiễm.",
            ],
        )
        return cls._enrich_final_analysis(base, evidence)
