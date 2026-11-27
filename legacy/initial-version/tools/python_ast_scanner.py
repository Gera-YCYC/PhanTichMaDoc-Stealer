"""Tool 4: ast_python_scanner(source_code)
Phân tích tĩnh cây cú pháp trừu tượng (AST) của mã nguồn Python (chấp nhận cả chuỗi mã nguồn
trực tiếp lẫn đường dẫn tới file `.py`) để phát hiện:
- Các lời gọi nguy hiểm (`exec`, `eval`, `subprocess`, `sqlite3`, `win32crypt`, `CryptUnprotectData`, `AES`...)
- Các import đặc trưng của InfoStealer
- Chuỗi mã hóa dài (Base64 / Hex / High-entropy) kèm giải mã xem trước an toàn
- Kỹ thuật làm rối (XOR loop, `exec(base64.b64decode(...))`, `chr()` nối chuỗi)
- URLs, Discord Webhooks, Telegram API, đường dẫn đánh cắp trình duyệt/ví crypto.
"""

from __future__ import annotations

import ast
import base64
import re
from pathlib import Path
from typing import Any

from tools.utils import format_tool_output, shannon_entropy

_DANGEROUS_CALLS: dict[str, str] = {
    "exec": "dynamic_code_execution",
    "eval": "dynamic_code_execution",
    "compile": "dynamic_code_execution",
    "__import__": "dynamic_import",
    "system": "os_command_execution",
    "popen": "os_command_execution",
    "Popen": "subprocess_execution",
    "run": "subprocess_execution",
    "call": "subprocess_execution",
    "check_output": "subprocess_execution",
    "connect": "sqlite_or_network_connect",
    "CryptUnprotectData": "dpapi_credential_decryption",
    "b64decode": "base64_decoding",
    "decompress": "payload_decompression",
    "loads": "deserialization_or_marshal",
    "post": "http_exfiltration",
    "urlopen": "http_request",
    "Request": "http_request",
    "copy2": "file_staging",
    "copyfile": "file_staging",
    "ZipFile": "archive_staging",
    "new": "crypto_cipher_init",
}

_SUSPICIOUS_IMPORTS: set[str] = {
    "sqlite3",
    "win32crypt",
    "Cryptodome",
    "Crypto",
    "cryptography",
    "subprocess",
    "ctypes",
    "requests",
    "urllib",
    "http",
    "socket",
    "base64",
    "zlib",
    "marshal",
    "shutil",
    "zipfile",
    "browser_cookie3",
    "psutil",
    "telebot",
    "discord",
}

_STEALER_KEYWORDS: tuple[str, ...] = (
    "login data",
    "local state",
    "web data",
    "encrypted_key",
    "os_crypt",
    "tdata",
    "leveldb",
    "dqw4w9wgxcq",
    "discord.com/api/webhooks",
    "discordapp.com/api/webhooks",
    "api.telegram.org/bot",
    "wallet.dat",
    "metamask",
    "exodus",
    "electrum",
)

_URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
_B64_CANDIDATE_RE = re.compile(r"^[A-Za-z0-9+/=_-]{28,}$")


def _get_call_name(node: ast.Call) -> str:
    """Trích xuất tên đầy đủ của lời gọi hàm từ node ast.Call (vd: subprocess.Popen)."""
    parts: list[str] = []
    cur: ast.AST = node.func
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return ".".join(reversed(parts)) if parts else "<anonymous_call>"


def _try_safe_b64_preview(s: str) -> str | None:
    """Thử giải mã Base64 an toàn nếu chuỗi khớp định dạng, chỉ trả về bản xem trước ASCII."""
    stripped = s.strip()
    if len(stripped) < 28 or not _B64_CANDIDATE_RE.match(stripped):
        return None
    try:
        padded = stripped + "=" * (-len(stripped) % 4)
        decoded = base64.b64decode(padded, validate=False)
        printable = sum(32 <= b <= 126 or b in (9, 10, 13) for b in decoded)
        if decoded and (printable / len(decoded)) >= 0.75:
            return decoded.decode("utf-8", errors="ignore")[:160]
    except Exception:
        return None
    return None


def _resolve_source_input(source_code: str) -> tuple[str, str]:
    """Hỗ trợ nhận trực tiếp mã nguồn Python hoặc đường dẫn file `.py`."""
    candidate = source_code.strip()
    if "\n" not in candidate and len(candidate) < 512:
        p = Path(candidate).expanduser()
        if p.exists() and p.is_file():
            return p.read_text(encoding="utf-8", errors="ignore"), str(p.resolve())
    return source_code, "<inline_source>"


def ast_python_scanner(source_code: str) -> str:
    """Phân tích AST mã nguồn Python (không thực thi) để phát hiện hành vi InfoStealer."""
    try:
        if not source_code or not isinstance(source_code, str):
            raise ValueError("Tham số source_code rỗng hoặc không hợp lệ.")

        code_text, source_origin = _resolve_source_input(source_code)

        try:
            tree = ast.parse(code_text)
        except SyntaxError as syn_err:
            return format_tool_output(
                {
                    "status": "syntax_error",
                    "tool": "ast_python_scanner",
                    "source": source_origin,
                    "error": f"Không thể parse AST (dòng {syn_err.lineno}): {syn_err.msg}",
                    "hint": "Có thể đây là mã bytecode disassembly hoặc Python 2; hãy dùng extract_iocs_and_yara.",
                }
            )

        suspicious_imports: set[str] = set()
        dangerous_calls: list[dict[str, Any]] = []
        encoded_strings: list[dict[str, Any]] = []
        extracted_urls: set[str] = set()
        stealer_string_hits: list[dict[str, Any]] = []
        obfuscation_flags: set[str] = set()
        xor_ops_count = 0
        chr_calls_count = 0

        for node in ast.walk(tree):
            # 1. Phân tích imports
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root_mod = alias.name.split(".")[0]
                    if root_mod in _SUSPICIOUS_IMPORTS:
                        suspicious_imports.add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                mod = (node.module or "").split(".")[0]
                if mod in _SUSPICIOUS_IMPORTS:
                    names = ", ".join(a.name for a in node.names[:5])
                    suspicious_imports.add(f"{node.module}: {names}")

            # 2. Phân tích lời gọi hàm nguy hiểm
            elif isinstance(node, ast.Call):
                full_name = _get_call_name(node)
                short_name = full_name.split(".")[-1]
                if short_name == "chr":
                    chr_calls_count += 1

                if short_name in _DANGEROUS_CALLS:
                    # Lọc bớt các lời gọi quá chung như `.run()` hoặc `.new()` nếu không thuộc module nguy hiểm
                    if short_name in {"run", "call", "connect", "new", "loads", "post"}:
                        low_full = full_name.lower()
                        if not any(
                            k in low_full
                            for k in (
                                "subprocess",
                                "sqlite",
                                "aes",
                                "cipher",
                                "marshal",
                                "pickle",
                                "requests",
                                "session",
                                "socket",
                                "json",
                            )
                        ):
                            continue
                    dangerous_calls.append(
                        {
                            "line": getattr(node, "lineno", None),
                            "call": full_name,
                            "category": _DANGEROUS_CALLS[short_name],
                        }
                    )

                # Phát hiện chuỗi lồng exec(base64.b64decode(...)) / eval(...)
                if short_name in {"exec", "eval"} and node.args:
                    arg_dump = ast.dump(node.args[0])
                    if any(k in arg_dump for k in ("b64decode", "decompress", "loads", "compile")):
                        obfuscation_flags.add(f"Nested {short_name}() with decode/decompress at line {node.lineno}")

            # 3. Phát hiện phép toán XOR (thường dùng giải mã chuỗi/payload)
            elif isinstance(node, ast.BitXor):
                xor_ops_count += 1

            # 4. Phân tích hằng chuỗi & bytes
            elif isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
                val_str = (
                    node.value.decode("utf-8", errors="ignore")
                    if isinstance(node.value, bytes)
                    else node.value
                )
                if not val_str:
                    continue

                # URLs
                for url in _URL_RE.findall(val_str):
                    extracted_urls.add(url[:200])

                # Từ khóa InfoStealer
                low = val_str.lower()
                if any(kw in low for kw in _STEALER_KEYWORDS):
                    if len(stealer_string_hits) < 25:
                        stealer_string_hits.append(
                            {
                                "line": getattr(node, "lineno", None),
                                "value": val_str[:160],
                            }
                        )

                # Chuỗi mã hóa dài / entropy cao
                if len(val_str) >= 32:
                    b64_preview = _try_safe_b64_preview(val_str)
                    ent = shannon_entropy(val_str.encode("utf-8", errors="ignore"))
                    if b64_preview is not None or ent >= 4.6:
                        if len(encoded_strings) < 15:
                            entry: dict[str, Any] = {
                                "line": getattr(node, "lineno", None),
                                "length": len(val_str),
                                "entropy": ent,
                                "preview": val_str[:80],
                            }
                            if b64_preview:
                                entry["base64_decoded_preview"] = b64_preview
                            encoded_strings.append(entry)

        if xor_ops_count >= 2:
            obfuscation_flags.add(f"XOR operations detected ({xor_ops_count}x) - possible string/payload decryption")
        if chr_calls_count >= 6:
            obfuscation_flags.add(f"Heavy chr() usage ({chr_calls_count}x) - possible string obfuscation")

        # Ước lượng mức độ rủi ro tĩnh sơ bộ hỗ trợ SLM suy luận
        risk_score = 0
        risk_score += min(len(dangerous_calls) * 10, 40)
        risk_score += min(len(stealer_string_hits) * 15, 45)
        risk_score += min(len(obfuscation_flags) * 15, 30)
        risk_score += 10 if extracted_urls else 0
        risk_score = min(risk_score, 100)

        result: dict[str, Any] = {
            "status": "ok",
            "tool": "ast_python_scanner",
            "source": source_origin,
            "lines_of_code": len(code_text.splitlines()),
            "static_risk_score": risk_score,
            "suspicious_imports": sorted(suspicious_imports),
            "dangerous_calls": dangerous_calls[:30],
            "stealer_indicators": stealer_string_hits[:20],
            "extracted_urls": sorted(extracted_urls)[:20],
            "encoded_or_high_entropy_strings": encoded_strings[:12],
            "obfuscation_flags": sorted(obfuscation_flags),
        }
        return format_tool_output(result)
    except Exception as exc:
        return format_tool_output(
            {
                "status": "error",
                "tool": "ast_python_scanner",
                "error": str(exc),
            }
        )
