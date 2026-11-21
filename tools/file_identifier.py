"""Tool 1: identify_file_type(file_path)
Xác định định dạng file (PE32/.NET assembly, PyInstaller executable, Python script,
file nén ZIP/7z/RAR/GZIP, ELF...) bằng python-magic, pefile và kiểm tra header/overlay.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from tools.utils import compute_hashes, format_tool_output, shannon_entropy, validate_path

try:
    import magic  # type: ignore
except Exception:
    magic = None

try:
    import pefile  # type: ignore
except Exception:
    pefile = None

PYINSTALLER_COOKIE = b"MEI\x0c\x0b\x0a\x0b\x0e"

_ARCHIVE_SIGNATURES: list[tuple[bytes, str]] = [
    (b"PK\x03\x04", "ZIP Archive"),
    (b"PK\x05\x06", "ZIP Archive (empty)"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip Archive"),
    (b"Rar!\x1a\x07", "RAR Archive"),
    (b"\x1f\x8b", "GZIP Compressed"),
    (b"BZh", "BZIP2 Compressed"),
    (b"\xfd7zXZ\x00", "XZ Archive"),
]

_PY_HEURISTIC_RE = re.compile(
    r"(^#!.*python|^\s*(import|from)\s+[a-zA-Z0-9_\.]+|^\s*def\s+[a-zA-Z0-9_]+\s*\(|^\s*class\s+[a-zA-Z0-9_]+)",
    re.MULTILINE,
)


def _detect_pe_details(file_path: Path, raw_bytes: bytes) -> dict[str, Any]:
    """Kiểm tra chi tiết cấu trúc PE: .NET CLR, PyInstaller overlay, Packer/Obfuscator."""
    info: dict[str, Any] = {
        "is_pe": True,
        "is_dotnet": False,
        "is_pyinstaller": PYINSTALLER_COOKIE in raw_bytes,
        "architecture": "unknown",
        "sections": [],
        "packer_hints": [],
    }

    if pefile is None:
        # Fallback không cần pefile: tìm chữ ký .NET metadata "BSJB"
        if b"BSJB" in raw_bytes and b"mscoree.dll" in raw_bytes.lower():
            info["is_dotnet"] = True
        return info

    try:
        pe = pefile.PE(str(file_path), fast_load=False)
        try:
            machine = pe.FILE_HEADER.Machine
            if machine == 0x8664:
                info["architecture"] = "PE32+ (x64)"
            elif machine == 0x014C:
                info["architecture"] = "PE32 (x86)"
            else:
                info["architecture"] = hex(machine)

            # Kiểm tra CLR Runtime Header (Directory index 14) -> đặc trưng .NET Assembly
            clr_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
            if clr_dir.VirtualAddress != 0 and clr_dir.Size != 0:
                info["is_dotnet"] = True

            # Kiểm tra các section để phát hiện packer / high entropy
            for sec in pe.sections:
                sec_name = sec.Name.decode("utf-8", errors="ignore").rstrip("\x00")
                ent = round(sec.get_entropy(), 3)
                info["sections"].append({"name": sec_name, "entropy": ent, "size": sec.SizeOfRawData})
                upper_name = sec_name.upper()
                if "UPX" in upper_name:
                    info["packer_hints"].append("UPX")
                elif "MPRESS" in upper_name:
                    info["packer_hints"].append("MPRESS")
                elif ".VM" in upper_name or "VMP" in upper_name:
                    info["packer_hints"].append("VMProtect")
                elif ent > 7.3 and sec.SizeOfRawData > 4096:
                    info["packer_hints"].append(f"High-entropy section ({sec_name}: {ent})")

            # Kiểm tra overlay cho PyInstaller
            overlay_offset = pe.get_overlay_data_start_offset()
            if overlay_offset is not None:
                overlay = raw_bytes[overlay_offset:]
                if PYINSTALLER_COOKIE in overlay:
                    info["is_pyinstaller"] = True
                    info["overlay_size"] = len(overlay)
        finally:
            pe.close()
    except Exception as exc:
        info["pe_parse_warning"] = str(exc)

    # Kiểm tra thêm dấu hiệu ConfuserEx trong raw bytes
    if b"ConfuserEx" in raw_bytes or b"Confuser.Core" in raw_bytes:
        info["packer_hints"].append("ConfuserEx (.NET Obfuscator)")

    return info


def identify_file_type(file_path: str) -> str:
    """Xác định định dạng file nghi ngờ và gợi ý công cụ phân tích tiếp theo cho Agent."""
    try:
        path = validate_path(file_path, allow_dir=False)
        raw_bytes = path.read_bytes()
        hashes = compute_hashes(path)
        entropy = shannon_entropy(raw_bytes)

        magic_desc = "unavailable"
        if magic is not None:
            try:
                magic_desc = str(magic.from_file(str(path)))
            except Exception as exc:
                magic_desc = f"magic_error: {exc}"

        detected_type = "unknown"
        recommended_next_tools: list[str] = ["extract_iocs_and_yara"]
        pe_details: dict[str, Any] | None = None

        header = raw_bytes[:16]

        # 1. Kiểm tra Windows PE (MZ)
        if header.startswith(b"MZ"):
            pe_details = _detect_pe_details(path, raw_bytes)
            if pe_details.get("is_pyinstaller"):
                detected_type = "PyInstaller Executable (PE)"
                recommended_next_tools = ["unpack_and_decompile_python", "extract_iocs_and_yara"]
            elif pe_details.get("is_dotnet"):
                detected_type = ".NET Assembly (PE)"
                recommended_next_tools = ["analyze_dotnet_binary", "extract_iocs_and_yara"]
            else:
                detected_type = f"Native Windows Executable ({pe_details.get('architecture', 'PE')})"
                recommended_next_tools = ["extract_iocs_and_yara"]

        # 2. Kiểm tra Linux ELF (có thể là PyInstaller trên Linux)
        elif header.startswith(b"\x7fELF"):
            if PYINSTALLER_COOKIE in raw_bytes:
                detected_type = "PyInstaller Executable (ELF)"
                recommended_next_tools = ["unpack_and_decompile_python", "extract_iocs_and_yara"]
            else:
                detected_type = "Linux ELF Binary"
                recommended_next_tools = ["extract_iocs_and_yara"]

        # 3. Kiểm tra Python bytecode (.pyc)
        elif path.suffix.lower() == ".pyc" or (len(header) >= 8 and header[2:4] == b"\r\n"):
            detected_type = "Python Bytecode (.pyc)"
            recommended_next_tools = ["unpack_and_decompile_python", "extract_iocs_and_yara"]

        # 4. Kiểm tra các định dạng nén phổ biến
        else:
            archive_hit = None
            for sig, label in _ARCHIVE_SIGNATURES:
                if header.startswith(sig):
                    archive_hit = label
                    break

            if archive_hit:
                detected_type = archive_hit
                recommended_next_tools = ["extract_iocs_and_yara"]
            else:
                # 5. Kiểm tra mã nguồn Python / text script
                try:
                    sample_text = raw_bytes[:8192].decode("utf-8")
                    if path.suffix.lower() in {".py", ".pyw"} or _PY_HEURISTIC_RE.search(sample_text):
                        detected_type = "Python Script"
                        recommended_next_tools = ["ast_python_scanner", "extract_iocs_and_yara"]
                    else:
                        detected_type = "Plain Text / Script"
                except UnicodeDecodeError:
                    detected_type = "Unknown Binary"

        result: dict[str, Any] = {
            "status": "ok",
            "tool": "identify_file_type",
            "file_path": str(path),
            "file_name": path.name,
            "detected_type": detected_type,
            "magic_description": magic_desc,
            "entropy": entropy,
            "high_entropy_warning": entropy > 7.2,
            "hashes": hashes,
            "recommended_next_tools": recommended_next_tools,
        }
        if pe_details is not None:
            result["pe_details"] = pe_details

        return format_tool_output(result)
    except Exception as exc:
        return format_tool_output(
            {
                "status": "error",
                "tool": "identify_file_type",
                "file_path": file_path,
                "error": str(exc),
            }
        )
