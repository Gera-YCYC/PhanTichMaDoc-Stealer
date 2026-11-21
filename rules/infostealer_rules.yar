/*
 * Bộ luật YARA cơ bản phát hiện hành vi đặc trưng của InfoStealer (.NET & Python)
 * Phạm vi: Browser Credentials, Discord/Telegram Tokens, Crypto Wallets,
 * Obfuscation (ConfuserEx / PyInstaller / Base64-exec) và Exfiltration C2.
 */

rule InfoStealer_Browser_Credential_Theft
{
    meta:
        description = "Phat hien truy cap du lieu trinh duyet Chromium/Gecko va giai ma DPAPI/AES-GCM"
        severity = "HIGH"
        mitre_attack = "T1555.003"
    strings:
        $s_login_data = "Login Data" ascii wide nocase
        $s_local_state = "Local State" ascii wide nocase
        $s_web_data = "Web Data" ascii wide nocase
        $s_enc_key = "encrypted_key" ascii wide
        $s_os_crypt = "os_crypt" ascii wide
        $s_dpapi_win = "CryptUnprotectData" ascii wide
        $s_dpapi_net = "ProtectedData" ascii wide
        $s_aes_gcm = "AesGcm" ascii wide
        $s_aes_py = "MODE_GCM" ascii wide
        $s_chrome = "Google\\Chrome\\User Data" ascii wide nocase
        $s_edge = "Microsoft\\Edge\\User Data" ascii wide nocase
    condition:
        (2 of ($s_login_data, $s_local_state, $s_web_data, $s_enc_key, $s_os_crypt))
        and (1 of ($s_dpapi_win, $s_dpapi_net, $s_aes_gcm, $s_aes_py, $s_chrome, $s_edge))
}

rule InfoStealer_Session_Discord_Telegram
{
    meta:
        description = "Phat hien danh cap phien Discord token hoac Telegram tdata va gui qua Webhook/Bot"
        severity = "HIGH"
        mitre_attack = "T1528"
    strings:
        $d_webhook = "discord.com/api/webhooks" ascii wide nocase
        $d_webhook2 = "discordapp.com/api/webhooks" ascii wide nocase
        $d_token_prefix = "dQw4w9WgXcQ" ascii wide
        $d_leveldb = "Local Storage\\leveldb" ascii wide nocase
        $t_api = "api.telegram.org/bot" ascii wide nocase
        $t_tdata = "Telegram Desktop\\tdata" ascii wide nocase
        $t_senddoc = "sendDocument" ascii wide
    condition:
        ($d_webhook or $d_webhook2 or $t_api) and (1 of ($d_token_prefix, $d_leveldb, $t_tdata, $t_senddoc))
        or (2 of ($d_token_prefix, $d_leveldb, $t_tdata))
}

rule InfoStealer_Crypto_Wallet_Targeting
{
    meta:
        description = "Phat hien nham muc tieu vao vi tien dien tu (MetaMask, Exodus, Electrum, Atomic, Phantom)"
        severity = "HIGH"
        mitre_attack = "T1005"
    strings:
        $w_metamask = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii wide
        $w_phantom = "bfnaelmomeimhlpmgjnjophhpkkoljpa" ascii wide
        $w_exodus = "exodus.wallet" ascii wide nocase
        $w_electrum = "Electrum\\wallets" ascii wide nocase
        $w_atomic = "atomic\\Local Storage" ascii wide nocase
        $w_walletdat = "wallet.dat" ascii wide nocase
        $w_seed = "seed phrase" ascii wide nocase
    condition:
        2 of them
}

rule InfoStealer_DotNet_Obfuscation_Suspicious
{
    meta:
        description = "Phat hien dau hieu lam roi ma nguon .NET (ConfuserEx / SmartAssembly / dynamic invoke)"
        severity = "MEDIUM"
        mitre_attack = "T1027"
    strings:
        $obf1 = "ConfuserEx" ascii wide
        $obf2 = "Confuser.Core" ascii wide
        $obf3 = "SmartAssembly" ascii wide
        $obf4 = "BabelObfuscator" ascii wide
        $net_bsjb = "BSJB" ascii
        $api1 = "FromBase64String" ascii wide
        $api2 = "Assembly.Load" ascii wide
    condition:
        $net_bsjb and (1 of ($obf*) or all of ($api1, $api2))
}

rule InfoStealer_Python_Packed_Or_Obfuscated
{
    meta:
        description = "Phat hien script Python bi lam roi hoac dong goi PyInstaller chua hanh vi nguy hiem"
        severity = "MEDIUM"
        mitre_attack = "T1027.002"
    strings:
        $pyi_cookie = { 4D 45 49 0C 0B 0A 0B 0E }
        $exec_b64 = /exec\s*\(\s*(base64\.b64decode|zlib\.decompress|marshal\.loads)/ ascii
        $eval_b64 = /eval\s*\(\s*base64\.b64decode/ ascii
        $win32crypt = "win32crypt" ascii
        $sqlite = "sqlite3" ascii
    condition:
        $exec_b64 or $eval_b64 or ($pyi_cookie and ($win32crypt or $sqlite))
}
