# Thành phần bên thứ ba

Mã điều phối và adapter của dự án được viết riêng sau khi audit repo bạn. Công cụ bên ngoài là dependency, giữ nguồn và giấy phép gốc. Kho mẫu public dùng cho nghiên cứu trong VM, không được gộp vào gói source chia sẻ.

| Thành phần | Phiên bản/commit đã dùng | Nguồn chính thức |
|---|---|---|
| Ollama | Runtime quan sát 0.40.17 | https://github.com/ollama/ollama |
| Qwen2.5 Coder 7B Instruct | Q4_K_M, digest trong từng run | https://huggingface.co/Qwen/Qwen2.5-Coder-7B-Instruct |
| ILSpy CLI | 11.2.0.10050 | https://github.com/icsharpcode/ILSpy |
| Detect It Easy CLI/database/Qt libraries | 4.0.0; hashes trong analysis-tools.lock.json | https://github.com/horsicq/DIE-engine/releases/tag/4.0.0 |
| FLOSS | 3.2.0; workspace viv disabled | https://github.com/mandiant/flare-floss/releases/tag/v3.2.0 |
| pefile | 2024.8.26 | https://github.com/erocarrera/pefile |
| pyinstxtractor | 815d31cf26bc71e62f851b2e549452e7b7c9dd98 | https://github.com/extremecoders-re/pyinstxtractor |
| pycdc / pycdas | b4289760970dbc399684f1e155ec6d1ea1cc787e | https://github.com/zrax/pycdc |
| yara-python | 4.5.4 | https://github.com/VirusTotal/yara-python |
| PyInstaller fixture builder | 6.11.1 | https://github.com/pyinstaller/pyinstaller |

Receipt tải/source/tool binary ở `private/lab-assets/extensions/receipt.json` và `evidence/local/lab-verification.json`. Giấy phép upstream nằm cùng asset đã tải. Trước khi phân phối lại binary/tool phải tuân thủ giấy phép tương ứng, đặc biệt GPL của pycdc/pyinstxtractor. Gói source hiện tại không phân phối những binary đó.

Repo được audit: https://github.com/Gera-YCYC/PhanTichMaDoc-Stealer tại commit `9362d1c0c8455bb15ff089c4b7c0bbc5b0f356f4`. Xem `audit/AUDIT_REPORT.md` và `docs/REUSE_DECISIONS.md` để phân biệt phần ý tưởng tham khảo với phần đã xây lại.

## Model và mẫu trong Release

Qwen2.5 Coder 7B Instruct được phân phối lại nguyên các blob/manifest đã dùng, chia 3 phần TAR. Giấy phép Apache-2.0 gốc nằm trong blob model và bản đọc thuận tiện ở licenses/Qwen2.5-Coder-Apache-2.0.txt. Nguồn model: https://huggingface.co/Qwen/Qwen2.5-Coder-7B-Instruct. Không thay đổi weight hoặc template; dữ liệu cache runtime không phải thành phần model nên không gộp vào archive.

Năm mẫu public là archive mã hóa phục vụ nghiên cứu, có nguồn/hash riêng trong config/public-samples.json; không thuộc giấy phép mã nguồn của nhóm. Tool native và hệ điều hành được tải từ upstream với hash ở config/setup-assets.lock.json, không được gộp thành binary không rõ nguồn vào Git. Người duy trì giữ nguyên giấy phép upstream khi phân phối lại.
