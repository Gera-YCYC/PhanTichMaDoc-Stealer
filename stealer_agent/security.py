"""Explicit network/path/observation boundaries; shared by both processes."""
from __future__ import annotations

import copy
import ipaddress
import re
import unicodedata
from pathlib import Path
from urllib.parse import urlsplit

SAMPLE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}\.(?:exe|dll|py|bin|txt|pyc)\Z", re.I)
INJECTION_PATTERNS = [
    r"ignore\s+(?:all\s+|the\s+)?(?:previous|prior|above)\s+instructions",
    r"(?:system|assistant|developer)\s*:", r"you\s+are\s+now",
    r"bỏ\s+qua\s+(?:mọi\s+)?(?:chỉ\s+dẫn|hướng\s+dẫn)",
    r"(?:mark|classify|declare).{0,50}(?:benign|malicious)",
    r"kết\s+luận.{0,50}(?:lành\s+tính|mã\s+độc)",
    r"<\|(?:im_start|im_end|system|assistant|endoftext)\|>",
]
INJECTION = re.compile("|".join(INJECTION_PATTERNS), re.I)
SECRET = re.compile(
    r"(https?://(?:\w+\.)?discord(?:app)?\.com/api/webhooks/\d+/)[\w-]+"
    r"|(\b\d{8,12}:)[A-Za-z0-9_-]{25,}", re.I)


def check_sample_name(name: str) -> str:
    if not isinstance(name, str) or not SAMPLE_NAME.fullmatch(name) or ".." in name:
        raise ValueError("sample must be an allowlisted filename, not a path")
    return name


def contained_file(root: Path, name: str, max_bytes: int) -> Path:
    check_sample_name(name)
    base = root.resolve(strict=True)
    path = (base / name).resolve(strict=True)
    if path.parent != base or not path.is_file() or (base / name).is_symlink():
        raise ValueError("sample escapes configured sample directory")
    if path.stat().st_size > max_bytes:
        raise ValueError("sample exceeds configured size limit")
    return path


def check_endpoint(url: str, *, loopback_only: bool) -> str:
    parsed = urlsplit(url)
    if parsed.scheme != "http" or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Only plain local HTTP endpoints without credentials/query are accepted")
    if parsed.path not in ("", "/"):
        raise ValueError("Endpoint must not contain a path")
    try:
        addr = ipaddress.ip_address(parsed.hostname or "")
    except ValueError as exc:
        raise ValueError("Use a literal IP address; DNS endpoints are disabled") from exc
    if addr.is_unspecified or addr.is_multicast or addr.is_link_local:
        raise ValueError("Invalid endpoint address")
    if loopback_only and not addr.is_loopback:
        raise ValueError("SLM endpoint must be loopback; cloud endpoints are disabled")
    private4 = addr.version == 4 and any(addr in ipaddress.ip_network(n) for n in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
    if not loopback_only and not (addr.is_loopback or private4):
        raise ValueError("Tool endpoint must be loopback or RFC1918 VM network")
    if parsed.port is None:
        raise ValueError("Explicit endpoint port required")
    return url.rstrip("/")


def guard_observation(observation: dict) -> tuple[dict, int]:
    """Keep line numbers and evidence IDs; strip instruction-like data, not history.

    This is a heuristic layer, not proof of prompt-injection immunity.
    """
    clean = copy.deepcopy(observation)
    hits = 0
    for line in clean.get("lines", []):
        text = line.get("text", "")
        # Normalize only the matching view. Evidence/quotes retain source text.
        normalized = unicodedata.normalize('NFKC', text)
        normalized = ''.join(ch for ch in normalized if unicodedata.category(ch) != 'Cf')
        if INJECTION.search(normalized):
            line["text"] = "[REDACTED-INJECTION]"
            hits += 1
    clean["guard_hits"] = hits
    clean["data_trust"] = "untrusted_sample_data_not_instructions"
    return clean, hits


def redact(text: str) -> str:
    return SECRET.sub(lambda m: (m.group(1) or m.group(2)) + "[REDACTED]", text)
