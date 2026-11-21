"""Registry xuất 5 công cụ phân tích tĩnh cho AI Agent (ReAct Engine)."""

from __future__ import annotations

from typing import Callable

from tools.dotnet_analyzer import analyze_dotnet_binary
from tools.file_identifier import identify_file_type
from tools.ioc_yara_scanner import extract_iocs_and_yara
from tools.python_ast_scanner import ast_python_scanner
from tools.python_unpacker import unpack_and_decompile_python

TOOL_REGISTRY: dict[str, Callable[..., str]] = {
    "identify_file_type": identify_file_type,
    "analyze_dotnet_binary": analyze_dotnet_binary,
    "unpack_and_decompile_python": unpack_and_decompile_python,
    "ast_python_scanner": ast_python_scanner,
    "extract_iocs_and_yara": extract_iocs_and_yara,
}

TOOL_DESCRIPTIONS: list[dict[str, str]] = [
    {
        "name": "identify_file_type",
        "args": '{"file_path": "<path_to_sample>"}',
        "description": "Xác định định dạng file (PE/.NET, PyInstaller, Python script, archive), tính hash/entropy và gợi ý công cụ tiếp theo.",
    },
    {
        "name": "analyze_dotnet_binary",
        "args": '{"file_path": "<path_to_dotnet_exe_or_dll>"}',
        "description": "Phân tích metadata .NET bằng dnfile và dịch ngược sang C# bằng ilspycmd để tìm API mạng, mã hóa DPAPI/AES và dấu hiệu làm rối.",
    },
    {
        "name": "unpack_and_decompile_python",
        "args": '{"file_path": "<path_to_pyinstaller_exe_or_pyc>"}',
        "description": "Giải nén gói PyInstaller bằng pyinstxtractor và dịch ngược file .pyc chính sang mã nguồn Python bằng pycdc/uncompyle6.",
    },
    {
        "name": "ast_python_scanner",
        "args": '{"source_code": "<python_code_or_path_to_py_file>"}',
        "description": "Phân tích cây cú pháp AST của Python để phát hiện lời gọi nguy hiểm (exec, eval, sqlite3, win32crypt, subprocess), chuỗi mã hóa và URL.",
    },
    {
        "name": "extract_iocs_and_yara",
        "args": '{"target_path": "<path_to_file_or_extracted_dir>"}',
        "description": "Trích xuất IOCs (IP, Domain, URL, Discord Webhook/Token, Telegram Bot, Crypto Wallets) và quét luật YARA InfoStealer.",
    },
]

__all__ = [
    "TOOL_REGISTRY",
    "TOOL_DESCRIPTIONS",
    "identify_file_type",
    "analyze_dotnet_binary",
    "unpack_and_decompile_python",
    "ast_python_scanner",
    "extract_iocs_and_yara",
]
