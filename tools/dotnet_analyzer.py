"""Tool 2: analyze_dotnet_binary(file_path)
Phân tích tĩnh file .NET Assembly bằng dnfile / pefile và dịch ngược sang C#
thông qua CLI `ilspycmd`, trích xuất chuỗi nghi ngờ, lớp/hàm liên quan đến
mạng (C2/Webhook), mã hóa (DPAPI/AES-GCM), truy cập trình duyệt và dấu hiệu làm rối.
"""

from __future__ import annotations

import re
import shutil
import tempfile
from pathlib import Path
from typing import Any

from config import MAX_SNIPPET_CHARS, WORK_DIR
from tools.utils import (
    extract_printable_strings,
    format_tool_output,
    safe_run_command,
    smart_truncate,
    validate_path,
)

try:
    import dnfile  # type: ignore
except Exception:
    dnfile = None

# Các từ khóa/API đặc trưng của InfoStealer viết bằng .NET
_SUSPICIOUS_DOTNET_PATTERNS: dict[str, list[str]] = {
    "crypto_dpapi": [
        "ProtectedData",
        "CryptUnprotectData",
        "AesGcm",
        "RijndaelManaged",
        "AesManaged",
        "FromBase64String",
        "BCryptDecrypt",
        "PBKDF2",
    ],
    "network_exfil": [
        "HttpClient",
        "WebClient",
        "HttpWebRequest",
        "UploadFile",
        "UploadValues",
        "PostAsync",
        "SendAsync",
        "SmtpClient",
        "FtpWebRequest",
        "discord.com/api/webhooks",
        "api.telegram.org",
    ],
    "credential_targets": [
        "Login Data",
        "Local State",
        "Web Data",
        "Cookies",
        "encrypted_key",
        "SQLiteConnection",
        "sqlite3",
        "leveldb",
        "tdata",
        "wallet.dat",
        "MetaMask",
        "Exodus",
    ],
    "evasion_obfuscation": [
        "ConfuserEx",
        "Confuser.Core",
        "SmartAssembly",
        "Assembly.Load",
        "VirtualAlloc",
        "WriteProcessMemory",
        "IsDebuggerPresent",
        "AntiDebug",
    ],
}

_CS_CLASS_METHOD_RE = re.compile(
    r"(?:public|private|internal|protected)?\s*(?:static\s+)?(?:async\s+)?(?:class|struct|void|string|byte\[\]|Task[^\s]*)\s+([A-Za-z0-9_]+)"
)


def _analyze_with_dnfile(file_path: Path) -> dict[str, Any]:
    """Đọc metadata .NET trực tiếp bằng dnfile (Assembly, TypeRef, MemberRef, #US strings)."""
    meta: dict[str, Any] = {
        "dnfile_available": dnfile is not None,
        "assembly_name": None,
        "clr_version": None,
        "suspicious_api_refs": [],
        "user_strings_suspicious": [],
        "obfuscation_indicators": [],
    }
    if dnfile is None:
        return meta

    try:
        dn = dnfile.dnPE(str(file_path))
        try:
            if not dn.net:
                meta["warning"] = "File không có .NET CLR metadata header."
                return meta

            if dn.net.metadata and dn.net.metadata.struct:
                meta["clr_version"] = str(dn.net.metadata.struct.Version)

            # Assembly Name
            if dn.net.mdtables and dn.net.mdtables.Assembly:
                for row in dn.net.mdtables.Assembly:
                    if row.Name:
                        meta["assembly_name"] = str(row.Name)
                        break

            # Kiểm tra TypeDef để phát hiện tên bị làm rối (non-ASCII / quá ngắn lặp lại)
            obf_count = 0
            total_types = 0
            if dn.net.mdtables and dn.net.mdtables.TypeDef:
                for row in dn.net.mdtables.TypeDef:
                    total_types += 1
                    tname = str(row.TypeName or "")
                    if any(ord(ch) > 126 or ord(ch) < 32 for ch in tname):
                        obf_count += 1
            if total_types > 0 and obf_count / total_types > 0.25:
                meta["obfuscation_indicators"].append(
                    f"Non-ASCII obfuscated TypeDef names ({obf_count}/{total_types})"
                )

            # Thu thập TypeRef + MemberRef nghi ngờ
            all_keywords = {kw.lower(): kw for kws in _SUSPICIOUS_DOTNET_PATTERNS.values() for kw in kws}
            found_apis: set[str] = set()

            for table_name in ("TypeRef", "MemberRef"):
                table = getattr(dn.net.mdtables, table_name, None) if dn.net.mdtables else None
                if not table:
                    continue
                for row in table:
                    name_val = str(getattr(row, "TypeName", None) or getattr(row, "Name", "") or "")
                    ns_val = str(getattr(row, "TypeNamespace", "") or "")
                    full = f"{ns_val}.{name_val}".strip(".")
                    low = full.lower()
                    for kw_low in all_keywords:
                        if kw_low in low:
                            found_apis.add(full)
                            break

            meta["suspicious_api_refs"] = sorted(found_apis)[:40]

            # Trích xuất User Strings (#US heap)
            us_hits: list[str] = []
            if dn.net.user_strings:
                for idx in range(dn.net.user_strings.sizeof()):
                    try:
                        us = dn.net.user_strings.get(idx)
                        if not us or not us.value:
                            continue
                        val = str(us.value).strip()
                        if len(val) < 4:
                            continue
                        low = val.lower()
                        if (
                            "http://" in low
                            or "https://" in low
                            or "discord" in low
                            or "telegram" in low
                            or "login data" in low
                            or "local state" in low
                            or "tdata" in low
                            or "wallet" in low
                            or "select " in low
                        ):
                            if val not in us_hits:
                                us_hits.append(val[:200])
                                if len(us_hits) >= 35:
                                    break
                    except Exception:
                        continue
            meta["user_strings_suspicious"] = us_hits
        finally:
            dn.close()
    except Exception as exc:
        meta["dnfile_error"] = str(exc)

    return meta


def _decompile_with_ilspy(file_path: Path) -> dict[str, Any]:
    """Gọi CLI `ilspycmd` để dịch ngược .NET assembly sang C# và lọc đoạn mã đáng ngờ."""
    ilspy_bin = shutil.which("ilspycmd")
    info: dict[str, Any] = {
        "ilspycmd_available": bool(ilspy_bin),
        "decompiled_dir": None,
        "suspicious_classes_methods": [],
        "relevant_code_snippets": [],
    }
    if not ilspy_bin:
        info["note"] = "ilspycmd không có trong PATH; sử dụng kết quả phân tích metadata dnfile & strings."
        return info

    WORK_DIR.mkdir(parents=True, exist_ok=True)
    out_dir = Path(tempfile.mkdtemp(prefix="ilspy_", dir=str(WORK_DIR)))
    info["decompiled_dir"] = str(out_dir)

    rc, stdout, stderr = safe_run_command([ilspy_bin, "-p", "-o", str(out_dir), str(file_path)])
    if rc != 0:
        # Thử chế độ dịch ngược ra single-file stdout nếu project mode thất bại
        rc2, stdout2, stderr2 = safe_run_command([ilspy_bin, str(file_path)])
        if rc2 == 0 and stdout2.strip():
            single_cs = out_dir / f"{file_path.stem}.cs"
            single_cs.write_text(stdout2, encoding="utf-8", errors="ignore")
        else:
            info["ilspy_error"] = (stderr or stderr2 or f"ilspycmd exited with code {rc}")[:300]
            return info

    cs_files = sorted(out_dir.rglob("*.cs"))
    info["decompiled_file_count"] = len(cs_files)

    flat_keywords = [kw.lower() for kws in _SUSPICIOUS_DOTNET_PATTERNS.values() for kw in kws]
    matched_symbols: set[str] = set()
    snippets: list[dict[str, Any]] = []

    for cs_file in cs_files:
        try:
            content = cs_file.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        low = content.lower()
        hit_kws = [kw for kw in flat_keywords if kw in low]
        if not hit_kws:
            continue

        for sym in _CS_CLASS_METHOD_RE.findall(content):
            if len(sym) > 2:
                matched_symbols.add(f"{cs_file.name}:{sym}")

        snippets.append(
            {
                "file": cs_file.name,
                "matched_keywords": sorted(set(hit_kws))[:12],
                "code_preview": smart_truncate(content, max_chars=MAX_SNIPPET_CHARS),
            }
        )
        if len(snippets) >= 3:
            break

    info["suspicious_classes_methods"] = sorted(matched_symbols)[:30]
    info["relevant_code_snippets"] = snippets
    return info


def analyze_dotnet_binary(file_path: str) -> str:
    """Phân tích chuyên sâu mẫu .NET InfoStealer (metadata + decompile C# + suspicious strings)."""
    try:
        path = validate_path(file_path, allow_dir=False)
        raw_bytes = path.read_bytes()

        dn_meta = _analyze_with_dnfile(path)
        ilspy_res = _decompile_with_ilspy(path)

        # Lọc các chuỗi nghi ngờ từ nhị phân theo nhóm hành vi
        all_strings = extract_printable_strings(raw_bytes, min_len=5, max_items=1200)
        categorized_hits: dict[str, list[str]] = {k: [] for k in _SUSPICIOUS_DOTNET_PATTERNS}
        for s in all_strings:
            low = s.lower()
            for cat, kws in _SUSPICIOUS_DOTNET_PATTERNS.items():
                if any(kw.lower() in low for kw in kws):
                    if s not in categorized_hits[cat] and len(categorized_hits[cat]) < 12:
                        categorized_hits[cat].append(s[:180])

        # Xóa các nhóm rỗng để tiết kiệm token
        categorized_hits = {k: v for k, v in categorized_hits.items() if v}

        result: dict[str, Any] = {
            "status": "ok",
            "tool": "analyze_dotnet_binary",
            "file_path": str(path),
            "dotnet_metadata": dn_meta,
            "decompilation": ilspy_res,
            "suspicious_string_categories": categorized_hits,
        }
        return format_tool_output(result)
    except Exception as exc:
        return format_tool_output(
            {
                "status": "error",
                "tool": "analyze_dotnet_binary",
                "file_path": file_path,
                "error": str(exc),
            }
        )
