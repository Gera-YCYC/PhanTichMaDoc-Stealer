"""Tool 5: extract_iocs_and_yara(target_path)
Trích xuất các chỉ số xâm nhập (IOCs: IPv4, Domain, URL, Discord Webhook, Discord Token,
Telegram Bot Token, Crypto Wallets BTC/ETH/XMR/SOL/LTC/TRX) từ file hoặc thư mục đã giải nén,
đồng thời quét đối chiếu với bộ luật YARA (`rules/infostealer_rules.yar`).
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Any

from config import DEFAULT_YARA_RULES
from tools.utils import extract_printable_strings, format_tool_output, validate_path

try:
    import yara  # type: ignore
except Exception:
    yara = None

# Bộ Regex chuyên biệt trích xuất IOCs của InfoStealer
_IOC_PATTERNS: dict[str, re.Pattern[str]] = {
    "urls": re.compile(r"https?://[a-zA-Z0-9._~:/?#\[\]@!$&'()*+,;=%-]{6,256}", re.IGNORECASE),
    "discord_webhooks": re.compile(
        r"https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d{16,22}/[A-Za-z0-9_-]{30,100}",
        re.IGNORECASE,
    ),
    "discord_tokens": re.compile(
        r"(?:mfa\.[A-Za-z0-9_-]{84}|[A-Za-z0-9_-]{24,26}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,38})"
    ),
    "telegram_bot_tokens": re.compile(r"\b\d{8,11}:[A-Za-z0-9_-]{35}\b"),
    "telegram_api_urls": re.compile(r"https?://api\.telegram\.org/bot[^\s'\"<>]+", re.IGNORECASE),
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "domains": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|ru|xyz|top|tk|cc|pw|su|info|biz|gg|me|onion|club|online|site)\b",
        re.IGNORECASE,
    ),
    "btc_wallets": re.compile(r"\b(?:bc1[a-zA-HJ-NP-Z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"),
    "eth_wallets": re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
    "xmr_wallets": re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b"),
    "trx_wallets": re.compile(r"\bT[A-Za-z1-9]{33}\b"),
}

# Các domain/IP nhiễu thường gặp trong metadata PE/library cần loại trừ
_BENIGN_DOMAINS: set[str] = {
    "schemas.microsoft.com",
    "www.w3.org",
    "w3.org",
    "microsoft.com",
    "python.org",
    "github.com",
    "localhost",
}

_MAX_SCAN_FILES = 40
_MAX_FILE_BYTES = 15 * 1024 * 1024  # 15 MB mỗi file


def _is_interesting_ip(ip_str: str) -> bool:
    """Loại bỏ IP giả (version string 1.0.0.0, loopback, private nếu không cần thiết)."""
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_loopback or ip.is_unspecified or ip.is_multicast:
            return False
        # Bỏ các chuỗi giống version phần mềm như 0.0.0.1, 1.0.0.0, 2.0.50727
        if ip_str.startswith(("0.", "1.0.", "2.0.", "4.0.", "10.0.0.")):
            return False
        return True
    except ValueError:
        return False


def _collect_target_files(target: Path) -> list[Path]:
    """Thu thập danh sách file cần quét (1 file hoặc tối đa _MAX_SCAN_FILES trong thư mục)."""
    if target.is_file():
        return [target]

    files: list[Path] = []
    for p in sorted(target.rglob("*")):
        if p.is_file() and p.stat().st_size <= _MAX_FILE_BYTES:
            files.append(p)
            if len(files) >= _MAX_SCAN_FILES:
                break
    return files


def _run_yara_scan(files: list[Path], rules_path: Path) -> dict[str, Any]:
    """Quét YARA với yara-python; tự động fallback sang kiểm tra chữ ký cơ bản nếu thiếu yara-python."""
    if not rules_path.exists():
        return {"engine": "none", "matches": [], "warning": f"Không tìm thấy file luật YARA: {rules_path}"}

    if yara is not None:
        try:
            compiled = yara.compile(filepath=str(rules_path))
            matches_out: list[dict[str, Any]] = []
            for f in files:
                try:
                    hits = compiled.match(str(f), timeout=15)
                    for h in hits:
                        matches_out.append(
                            {
                                "file": f.name,
                                "rule": h.rule,
                                "severity": h.meta.get("severity", "UNKNOWN"),
                                "mitre_attack": h.meta.get("mitre_attack", ""),
                                "description": h.meta.get("description", ""),
                            }
                        )
                except Exception:
                    continue
            return {"engine": "yara-python", "rules_file": rules_path.name, "matches": matches_out[:25]}
        except Exception as exc:
            return {"engine": "yara-python", "matches": [], "error": str(exc)}

    # Fallback nhẹ khi môi trường host chưa cài yara-python
    fallback_signatures: list[tuple[str, str, str, list[bytes]]] = [
        ("InfoStealer_Browser_Credential_Theft", "HIGH", "T1555.003", [b"Login Data", b"Local State", b"encrypted_key"]),
        ("InfoStealer_Session_Discord_Telegram", "HIGH", "T1528", [b"discord.com/api/webhooks", b"api.telegram.org/bot", b"tdata"]),
        ("InfoStealer_Crypto_Wallet_Targeting", "HIGH", "T1005", [b"nkbihfbeogaeaoehlefnkodbefgpgknn", b"exodus.wallet", b"wallet.dat"]),
        ("InfoStealer_DotNet_Obfuscation_Suspicious", "MEDIUM", "T1027", [b"ConfuserEx", b"ProtectedData", b"AesGcm"]),
    ]
    matches_out = []
    for f in files:
        try:
            raw = f.read_bytes()
        except Exception:
            continue
        low_raw = raw.lower()
        for rule_name, sev, mitre, sigs in fallback_signatures:
            hit_count = sum(1 for s in sigs if s.lower() in low_raw)
            if hit_count >= 2 or (rule_name == "InfoStealer_Session_Discord_Telegram" and hit_count >= 1):
                matches_out.append(
                    {
                        "file": f.name,
                        "rule": rule_name,
                        "severity": sev,
                        "mitre_attack": mitre,
                        "description": "Matched via built-in fallback signature engine (yara-python not installed).",
                    }
                )
    return {
        "engine": "builtin_fallback",
        "rules_file": rules_path.name,
        "matches": matches_out[:25],
    }


def extract_iocs_and_yara(target_path: str, yara_rules_path: str | None = None) -> str:
    """Trích xuất IOCs và quét đối chiếu YARA trên file hoặc thư mục đã giải nén."""
    try:
        target = validate_path(target_path, allow_dir=True)
        files = _collect_target_files(target)
        rules_file = Path(yara_rules_path).expanduser().resolve() if yara_rules_path else DEFAULT_YARA_RULES

        iocs: dict[str, set[str]] = {k: set() for k in _IOC_PATTERNS}

        for f in files:
            try:
                raw = f.read_bytes()
            except Exception:
                continue

            # Kết hợp text UTF-8 (cho script) và printable strings (cho PE/.NET)
            text_chunks: list[str] = []
            try:
                text_chunks.append(raw.decode("utf-8"))
            except UnicodeDecodeError:
                text_chunks.extend(extract_printable_strings(raw, min_len=5, max_items=1500))

            joined = "\n".join(text_chunks)
            for ioc_type, pattern in _IOC_PATTERNS.items():
                for match in pattern.findall(joined):
                    val = match.strip().rstrip(".,;)\"'")
                    if ioc_type == "ipv4" and not _is_interesting_ip(val):
                        continue
                    if ioc_type == "domains" and val.lower() in _BENIGN_DOMAINS:
                        continue
                    iocs[ioc_type].add(val)

        # Chỉ giữ lại các nhóm IOC có dữ liệu để tiết kiệm token cho SLM
        compact_iocs: dict[str, list[str]] = {
            k: sorted(v)[:20] for k, v in iocs.items() if v
        }

        yara_result = _run_yara_scan(files, rules_file)

        result: dict[str, Any] = {
            "status": "ok",
            "tool": "extract_iocs_and_yara",
            "target_path": str(target),
            "scanned_file_count": len(files),
            "iocs": compact_iocs,
            "total_ioc_count": sum(len(v) for v in compact_iocs.values()),
            "yara_scan": yara_result,
        }
        return format_tool_output(result)
    except Exception as exc:
        return format_tool_output(
            {
                "status": "error",
                "tool": "extract_iocs_and_yara",
                "target_path": target_path,
                "error": str(exc),
            }
        )
