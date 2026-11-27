"""Tiện ích dùng chung cho bộ công cụ phân tích tĩnh:
- Cắt gọn (smart truncate) thông minh để không tràn Context Window của SLM cục bộ.
- Tính hash (MD5/SHA1/SHA256) và Shannon entropy.
- Chạy lệnh CLI bên ngoài an toàn (không shell=True, có timeout).
- Trích xuất chuỗi ASCII/UTF-16LE từ file nhị phân.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any

from config import MAX_TOOL_OUTPUT_CHARS, SUBPROCESS_TIMEOUT

_ASCII_STR_RE = re.compile(rb"[\x20-\x7e]{5,}")
_UTF16_STR_RE = re.compile(rb"(?:[\x20-\x7e]\x00){5,}")


def validate_path(target_path: str, allow_dir: bool = False) -> Path:
    """Kiểm tra và chuẩn hóa đường dẫn hợp lệ."""
    if not target_path or not isinstance(target_path, str):
        raise ValueError("Đường dẫn không hợp lệ hoặc rỗng.")
    path = Path(target_path).expanduser().resolve()
    if not path.exists():
        raise FileNotFoundError(f"Không tìm thấy đường dẫn: {target_path}")
    if not allow_dir and not path.is_file():
        raise IsADirectoryError(f"Yêu cầu file nhưng nhận được thư mục: {target_path}")
    return path


def compute_hashes(file_path: Path) -> dict[str, Any]:
    """Tính kích thước và các hàm băm MD5, SHA1, SHA256 của file."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    size = 0
    with file_path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            size += len(chunk)
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {
        "size_bytes": size,
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


def shannon_entropy(data: bytes) -> float:
    """Tính Shannon entropy (0.0 -> 8.0). Giá trị > 7.2 thường báo hiệu nén/mã hóa."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return round(-sum((c / length) * math.log2(c / length) for c in counts.values()), 3)


def extract_printable_strings(data: bytes, min_len: int = 5, max_items: int = 500) -> list[str]:
    """Trích xuất chuỗi ASCII và UTF-16LE (phổ biến trong .NET/Windows PE)."""
    results: list[str] = []
    seen: set[str] = set()

    for match in _ASCII_STR_RE.finditer(data):
        s = match.group().decode("ascii", errors="ignore").strip()
        if len(s) >= min_len and s not in seen:
            seen.add(s)
            results.append(s)
            if len(results) >= max_items:
                return results

    for match in _UTF16_STR_RE.finditer(data):
        s = match.group().decode("utf-16le", errors="ignore").strip()
        if len(s) >= min_len and s not in seen:
            seen.add(s)
            results.append(s)
            if len(results) >= max_items:
                return results

    return results


def smart_truncate(text: str, max_chars: int = MAX_TOOL_OUTPUT_CHARS) -> str:
    """Cắt gọn văn bản thông minh: giữ 65% đầu + 30% cuối để bảo toàn ngữ cảnh chính."""
    if not text or len(text) <= max_chars:
        return text

    head_len = int(max_chars * 0.65)
    tail_len = int(max_chars * 0.30)
    omitted = len(text) - head_len - tail_len

    head = text[:head_len]
    tail = text[-tail_len:] if tail_len > 0 else ""

    # Căn lề theo dòng nếu có thể để tránh cắt ngang từ khóa
    last_nl = head.rfind("\n")
    if last_nl > head_len * 0.7:
        head = head[:last_nl]

    first_nl = tail.find("\n")
    if 0 <= first_nl < tail_len * 0.3:
        tail = tail[first_nl + 1 :]

    return f"{head}\n\n[... TRUNCATED {omitted} chars to fit local SLM context ...]\n\n{tail}"


def _shrink_value(value: Any, max_list_items: int, max_str_len: int) -> Any:
    """Rút gọn đệ quy các trường dài trong dict/list mà vẫn giữ nguyên cấu trúc JSON."""
    if isinstance(value, str):
        if len(value) > max_str_len:
            return smart_truncate(value, max_chars=max_str_len)
        return value
    if isinstance(value, list):
        trimmed = [_shrink_value(item, max_list_items, max_str_len) for item in value[:max_list_items]]
        if len(value) > max_list_items:
            trimmed.append(f"... (+{len(value) - max_list_items} more items truncated)")
        return trimmed
    if isinstance(value, dict):
        return {k: _shrink_value(v, max_list_items, max_str_len) for k, v in value.items()}
    return value


def format_tool_output(payload: dict[str, Any], max_chars: int = MAX_TOOL_OUTPUT_CHARS) -> str:
    """Chuyển kết quả công cụ sang JSON gọn, đảm bảo luôn hợp lệ và không vượt ngưỡng token."""
    raw = json.dumps(payload, ensure_ascii=False, indent=2)
    if len(raw) <= max_chars:
        return raw

    # Nén dần khoảng trắng trước
    compact = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    if len(compact) <= max_chars:
        return compact

    # Giảm dần độ dài list và chuỗi theo từng mức ưu tiên
    for max_items, max_str in ((25, 600), (15, 350), (8, 200), (5, 120)):
        shrunk = _shrink_value(payload, max_list_items=max_items, max_str_len=max_str)
        shrunk["_truncated"] = True
        candidate = json.dumps(shrunk, ensure_ascii=False, separators=(",", ":"))
        if len(candidate) <= max_chars:
            return candidate

    # Phương án cuối cùng nếu dữ liệu vẫn quá lớn
    minimal = {
        "status": payload.get("status", "ok"),
        "tool": payload.get("tool", "unknown"),
        "summary": smart_truncate(str(payload.get("summary", "")), max_chars=max_chars // 2),
        "_truncated": True,
        "note": "Output heavily truncated to protect SLM context window.",
    }
    return json.dumps(minimal, ensure_ascii=False, separators=(",", ":"))


def safe_run_command(
    cmd: list[str],
    timeout: int = SUBPROCESS_TIMEOUT,
    cwd: str | Path | None = None,
) -> tuple[int, str, str]:
    """Thực thi CLI phân tích tĩnh an toàn (shell=False, có timeout)."""
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            check=False,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired:
        return -1, "", f"Command timed out after {timeout}s: {' '.join(cmd)}"
    except FileNotFoundError:
        return -2, "", f"Executable not found: {cmd[0]}"
    except Exception as exc:
        return -3, "", f"Subprocess execution error: {exc}"
