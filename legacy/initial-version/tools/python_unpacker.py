"""Tool 3: unpack_and_decompile_python(file_path)
Nếu là file .exe/.elf đóng gói bởi PyInstaller:
  1. Giải nén bằng `pyinstxtractor.py` (hoặc bộ parser CArchive thuần Python dự phòng).
  2. Xác định file `.pyc` entry-point chính.
  3. Dịch ngược `.pyc` sang mã nguồn `.py` bằng `pycdc` -> `uncompyle6` -> fallback `marshal`+`dis` (không thực thi).
Nếu đầu vào đã là `.pyc`, tiến hành dịch ngược trực tiếp.
"""

from __future__ import annotations

import dis
import io
import marshal
import shutil
import struct
import sys
import tempfile
import zlib
from pathlib import Path
from typing import Any

from config import MAX_SNIPPET_CHARS, PYINSTXTRACTOR_PATH, WORK_DIR
from tools.utils import format_tool_output, safe_run_command, smart_truncate, validate_path

PYINSTALLER_COOKIE = b"MEI\x0c\x0b\x0a\x0b\x0e"

# Các module hệ thống của PyInstaller cần bỏ qua khi tìm entry-point chính
_PYI_INTERNAL_PREFIXES = (
    "pyiboot",
    "pyi_rth_",
    "struct",
    "pyimod0",
    "base_library",
)


def _extract_pyinstaller_native(file_path: Path, out_dir: Path) -> list[Path]:
    """Bộ giải nén PyInstaller CArchive thuần Python (dự phòng khi không có pyinstxtractor.py)."""
    data = file_path.read_bytes()
    cookie_pos = data.rfind(PYINSTALLER_COOKIE)
    if cookie_pos == -1:
        raise ValueError("Không tìm thấy chữ ký PyInstaller (MEI cookie) trong file.")

    # PyInstaller 2.1+ cookie có kích thước 88 bytes (magic 8s, pkg_len i, toc_off i, toc_len i, pyver i, pylib 64s)
    # PyInstaller 2.0 cookie có kích thước 24 bytes
    remaining = len(data) - cookie_pos
    if remaining >= 88:
        magic, pkg_len, toc_off, toc_len, pyver, _ = struct.unpack_from("!8siiii64s", data, cookie_pos)
    elif remaining >= 24:
        magic, pkg_len, toc_off, toc_len, pyver = struct.unpack_from("!8siiii", data, cookie_pos)
    else:
        raise ValueError("Cấu trúc PyInstaller cookie không hợp lệ.")

    if magic != PYINSTALLER_COOKIE:
        raise ValueError("Sai magic bytes PyInstaller.")

    cookie_size = 88 if remaining >= 88 else 24
    overlay_pos = (cookie_pos + cookie_size) - pkg_len
    if overlay_pos < 0:
        overlay_pos = 0

    toc_start = overlay_pos + toc_off
    toc_end = toc_start + toc_len
    pos = toc_start
    extracted: list[Path] = []

    while pos < toc_end and pos + 18 <= len(data):
        entry_size, dpos, dlen, ulen, cmprs_flag, type_cmprs = struct.unpack_from("!iiiiBB", data, pos)
        if entry_size <= 18 or pos + entry_size > len(data):
            break
        name_bytes = data[pos + 18 : pos + entry_size].rstrip(b"\x00")
        name = name_bytes.decode("utf-8", errors="ignore").replace("\\", "/")
        pos += entry_size

        # Chỉ giải nén script ('s'), module ('m'/'M') và PYZ ('z') để tránh ghi rác nhị phân lớn
        type_char = chr(type_cmprs)
        if type_char not in ("s", "m", "M"):
            continue

        blob_start = overlay_pos + dpos
        blob = data[blob_start : blob_start + dlen]
        if cmprs_flag == 1:
            try:
                blob = zlib.decompress(blob)
            except Exception:
                continue

        safe_name = Path(name).name
        if type_char == "s" and not safe_name.endswith(".pyc"):
            safe_name = f"{safe_name}.pyc"

        target = out_dir / safe_name
        # Thêm header pyc 16 bytes rỗng nếu entry 's' chưa có magic pyc
        if type_char == "s" and len(blob) > 4 and blob[2:4] != b"\r\n":
            # Python 3.7+ pyc header = 16 bytes (magic + bitfield + mtime + size)
            pyc_header = b"\xa7\x0d\x0d\x0a" + b"\x00" * 12
            blob = pyc_header + blob

        target.write_bytes(blob)
        extracted.append(target)

    return extracted


def _run_pyinstxtractor(file_path: Path, work_dir: Path) -> tuple[Path, str]:
    """Giải nén PyInstaller bằng pyinstxtractor.py, tự động fallback sang parser nội bộ."""
    extractor = Path(PYINSTXTRACTOR_PATH)
    # Cho phép tìm thêm trong cùng thư mục dự án hoặc PATH
    if not extractor.exists():
        local_candidate = Path(__file__).resolve().parent.parent / "pyinstxtractor.py"
        if local_candidate.exists():
            extractor = local_candidate

    if extractor.exists():
        # Copy sang thư mục làm việc tạm để không ghi vào thư mục samples (read-only)
        copied = work_dir / file_path.name
        shutil.copy2(file_path, copied)
        rc, stdout, stderr = safe_run_command([sys.executable, str(extractor), str(copied)], cwd=work_dir)
        extracted_dir = work_dir / f"{file_path.name}_extracted"
        if rc == 0 and extracted_dir.exists():
            return extracted_dir, "pyinstxtractor"

    # Fallback thuần Python
    fallback_dir = work_dir / f"{file_path.name}_extracted"
    fallback_dir.mkdir(parents=True, exist_ok=True)
    _extract_pyinstaller_native(file_path, fallback_dir)
    return fallback_dir, "native_carchive_parser"


def _find_main_pyc(extracted_dir: Path, original_stem: str) -> list[Path]:
    """Xác định các file .pyc ứng viên chứa entry-point chính của mã độc."""
    pycs = [p for p in extracted_dir.glob("*.pyc") if p.is_file()]
    candidates: list[Path] = []
    for p in pycs:
        low = p.stem.lower()
        if any(low.startswith(pref) for pref in _PYI_INTERNAL_PREFIXES):
            continue
        candidates.append(p)

    # Ưu tiên file trùng tên với file exe gốc
    candidates.sort(key=lambda p: (0 if p.stem.lower() == original_stem.lower() else 1, -p.stat().st_size))
    return candidates


def _disassemble_pyc_fallback(pyc_path: Path) -> str:
    """Fallback tĩnh thuần Python: đọc code object từ .pyc bằng marshal & dis (KHÔNG thực thi)."""
    raw = pyc_path.read_bytes()
    code_obj = None
    # Thử các độ dài header phổ biến: 16 bytes (Py 3.7+), 12 bytes (Py 3.3-3.6), 8 bytes (Py <=3.2), 0 bytes
    for offset in (16, 12, 8, 0):
        try:
            obj = marshal.loads(raw[offset:])
            if hasattr(obj, "co_code"):
                code_obj = obj
                break
        except Exception:
            continue

    if code_obj is None:
        return ""

    buf = io.StringIO()
    buf.write(f"# [Static Bytecode Disassembly - {pyc_path.name}]\n")
    buf.write(f"# Names: {list(code_obj.co_names)[:40]}\n")
    consts = [repr(c) for c in code_obj.co_consts if isinstance(c, (str, bytes, int, float))][:40]
    buf.write(f"# Constants: {consts}\n\n")
    dis.dis(code_obj, file=buf)
    return buf.getvalue()


def _decompile_pyc(pyc_path: Path) -> tuple[str, str]:
    """Dịch ngược .pyc theo thứ tự ưu tiên: pycdc -> uncompyle6 -> marshal/dis fallback."""
    pycdc = shutil.which("pycdc")
    if pycdc:
        rc, out, _ = safe_run_command([pycdc, str(pyc_path)])
        if rc == 0 and out.strip():
            return out, "pycdc"

    uncompyle6 = shutil.which("uncompyle6")
    if uncompyle6:
        rc, out, _ = safe_run_command([uncompyle6, str(pyc_path)])
        if rc == 0 and out.strip():
            return out, "uncompyle6"

    dis_out = _disassemble_pyc_fallback(pyc_path)
    if dis_out:
        return dis_out, "python_marshal_dis_fallback"

    return "", "failed"


def unpack_and_decompile_python(file_path: str) -> str:
    """Giải nén PyInstaller executable và dịch ngược file .pyc chính sang mã nguồn Python."""
    try:
        path = validate_path(file_path, allow_dir=False)
        WORK_DIR.mkdir(parents=True, exist_ok=True)
        session_dir = Path(tempfile.mkdtemp(prefix="pyunpack_", dir=str(WORK_DIR)))

        unpack_method = "direct_pyc"
        extracted_dir = session_dir
        target_pycs: list[Path] = []

        if path.suffix.lower() == ".pyc":
            target_pycs = [path]
        else:
            raw_data = path.read_bytes()
            if PYINSTALLER_COOKIE not in raw_data:
                return format_tool_output(
                    {
                        "status": "error",
                        "tool": "unpack_and_decompile_python",
                        "file_path": str(path),
                        "error": "File không phải gói PyInstaller và cũng không phải file .pyc.",
                    }
                )
            extracted_dir, unpack_method = _run_pyinstxtractor(path, session_dir)
            target_pycs = _find_main_pyc(extracted_dir, path.stem)

        if not target_pycs:
            return format_tool_output(
                {
                    "status": "warning",
                    "tool": "unpack_and_decompile_python",
                    "file_path": str(path),
                    "unpack_method": unpack_method,
                    "extracted_dir": str(extracted_dir),
                    "message": "Đã giải nén nhưng không tìm thấy file .pyc entry-point chính.",
                }
            )

        main_pyc = target_pycs[0]
        decompiled_code, decompiler_used = _decompile_pyc(main_pyc)

        saved_py_path: str | None = None
        if decompiled_code:
            out_py = session_dir / f"{main_pyc.stem}_decompiled.py"
            out_py.write_text(decompiled_code, encoding="utf-8", errors="ignore")
            saved_py_path = str(out_py)

        result: dict[str, Any] = {
            "status": "ok" if decompiled_code else "partial",
            "tool": "unpack_and_decompile_python",
            "file_path": str(path),
            "unpack_method": unpack_method,
            "extracted_dir": str(extracted_dir),
            "candidate_pyc_files": [p.name for p in target_pycs[:10]],
            "main_pyc": main_pyc.name,
            "decompiler_used": decompiler_used,
            "decompiled_py_path": saved_py_path,
            "decompiled_code_preview": smart_truncate(decompiled_code, max_chars=MAX_SNIPPET_CHARS),
            "next_step_hint": (
                f"Hãy gọi ast_python_scanner với đường dẫn '{saved_py_path}' "
                f"và extract_iocs_and_yara với thư mục '{extracted_dir}'."
                if saved_py_path
                else f"Hãy gọi extract_iocs_and_yara với thư mục '{extracted_dir}'."
            ),
        }
        return format_tool_output(result)
    except Exception as exc:
        return format_tool_output(
            {
                "status": "error",
                "tool": "unpack_and_decompile_python",
                "file_path": file_path,
                "error": str(exc),
            }
        )
