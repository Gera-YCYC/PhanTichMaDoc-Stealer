"""Static feature extraction. Treat matching strings as candidates, not behaviors."""
from __future__ import annotations

import ast
import hashlib
import importlib.metadata
import ipaddress
import json
import math
import re
from collections import Counter
from .string_extractor import extract_strings


def identify(data: bytes, filename: str) -> tuple[str, str, list[str]]:
    result = {"sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data),
              "entropy": round(-sum((n / len(data)) * math.log2(n / len(data))
                                    for n in Counter(data).values()), 4) if data else 0,
              "format": "unknown", "is_dotnet": False}
    backend = "stdlib-header-inspection"
    limitations = []
    if data.startswith(b"MZ"):
        import pefile
        backend = "pefile/" + importlib.metadata.version("pefile")
        with pefile.PE(data=data, fast_load=True) as pe:
            clr = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
            result.update(format="PE", is_dotnet=bool(clr.VirtualAddress and clr.Size),
                          machine=hex(pe.FILE_HEADER.Machine),
                          sections=[{"name": s.Name.rstrip(b"\0").decode("ascii", "replace"),
                                     "size": s.SizeOfRawData} for s in pe.sections])
        if result["is_dotnet"]:
            result["format"] = "PE .NET"
    elif filename.lower().endswith(".py"):
        ast.parse(data.decode("utf-8-sig"))
        result["format"] = "Python source"
    elif filename.lower().endswith(".pyc"):
        result["format"] = "Python bytecode candidate"
        limitations.append("Bytecode version/decompiler must be checked separately")
    if b"MEI\x0c\x0b\x0a\x0b\x0e" in data:
        result["pyinstaller_cookie_present"] = True
        limitations.append("Cookie presence is a hint, not validated archive structure")
    return json.dumps(result, ensure_ascii=False, indent=2), backend, limitations


def strings(data: bytes) -> tuple[str, str, list[str]]:
    return extract_strings(data)


IOC_PATTERNS = {
    "url": re.compile(r"https?://[^\s\"'<>\\]{4,400}", re.I),
    "telegram_bot_token": re.compile(r"\b\d{8,12}:[A-Za-z0-9_-]{35}\b"),
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
}


def extract_ioc(record: dict) -> tuple[str, str, list[str]]:
    entries, seen = [], set()
    for line in record["lines"]:
        for kind, pattern in IOC_PATTERNS.items():
            if kind == 'ipv4' and re.search(r'(?:Assembly(?:File|Informational)?Version|Version\s*=|v\d+\.\d+\.\d+)', line['text'], re.I):
                continue
            for match in pattern.finditer(line["text"]):
                value = match.group().rstrip(".,;)}]")
                if kind == "ipv4":
                    try:
                        ipaddress.ip_address(value)
                    except ValueError:
                        continue
                if (kind, value) in seen:
                    continue
                seen.add((kind, value))
                entries.append(json.dumps({"type": kind, "value": value,
                    "source_evidence_id": record["evidence_id"], "source_line": line["line"],
                    "classification": "candidate_not_confirmed_exfiltration"}, ensure_ascii=False))
                if len(entries) >= 300:
                    return "\n".join(entries), "ioc-regex/1", ["Capped at 300 candidates"]
    return "\n".join(entries) or "No IOC candidate found in this evidence record.", "ioc-regex/1", []


def python_ast(data: bytes) -> tuple[str, str, list[str]]:
    source = data.decode("utf-8-sig")
    tree = ast.parse(source)
    rows = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom, ast.Call)):
            segment = ast.get_source_segment(source, node) or ast.unparse(node)
            rows.append({"source_line": node.lineno, "node": type(node).__name__,
                         "text": segment[:500], "meaning": "syntax_only_not_proven_behavior"})
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            if any(p.search(node.value) for p in IOC_PATTERNS.values()) or any(
                    k in node.value.lower() for k in ("login data", "local state", "cookie", "token", "webhook")):
                rows.append({"source_line": node.lineno, "node": "String", "text": node.value[:500]})
        if len(rows) >= 500:
            break
    return "\n".join(json.dumps(r, ensure_ascii=False) for r in rows) or "No selected AST features.", \
        "python-ast/1", ["Static syntax features; does not prove reachability, execution, or malicious intent"]
