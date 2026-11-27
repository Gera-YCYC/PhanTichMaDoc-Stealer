# Thiết lập và vận hành

## Máy hiện tại đã dựng xong

Dùng `scripts/Start-Lab.ps1`, `scripts/Run-Demo.ps1` và `scripts/verify_lab.py` theo README. Không chạy lại provisioning vào VM hiện có. File VM, model và asset riêng nằm trong `private/`, mẫu plaintext chỉ ở bên trong VM.

Ollama executable hiện ở `M:\Tools\Mountain-Ollama\0.40.17\runtime\ollama.exe`. Dữ liệu model mới ở `private/ollama-models` trên C. Đổi runtime bằng tham số `-OllamaExe` của `Start-LocalModel.ps1` nếu chuyển máy; không đổi endpoint sang cloud. `Start-Lab.ps1` kiểm PID/path/start-time và kho model trước khi dùng listener đã chạy.

Nếu VM vừa boot, chờ SSH/health sẵn sàng rồi chạy demo. Mỗi lần run có thư mục mới. Không chạy `sync_vm.py` hoặc restart tool service giữa một run vì kho evidence ID hiện nằm trong session service. Log cũ vẫn còn trên đĩa nhưng không được tự giả định ID đó tồn tại sau restart.

## Cài sang máy mới

**Quy trình mới cho thành viên:** xem [TEAM_SETUP.md](TEAM_SETUP.md). Dùng model thực và archive mẫu mã hóa của Release, khóa asset tại config/release-assets.lock.json và config/setup-assets.lock.json. Các ghi chú dưới đây mô tả cách dựng trước khi có bộ script nhóm, giữ để đối chiếu lịch sử; không dùng làm checklist cài mới.

Gói ZIP là source và tài liệu. Nó không bao gồm VM, model, native tools hoặc malware. **Chưa kiểm chứng quy trình cài mới đầu cuối trên máy thứ hai.** Các script dưới đây là thành phần provisioning đã dùng trên máy hiện tại; cần điều chỉnh đường dẫn/runtime và kiểm lại receipts khi tái dựng.

1. Cài Python 3.11+, VMware Workstation và Ollama từ nguồn chính thức phù hợp máy.
2. Tạo venv, cài `requirements-host.txt` và `requirements-test.txt`. Thư viện VM dùng `requirements-vm.txt` và native CLI trong danh sách THIRD_PARTY.
3. Tạo mạng host-only riêng tương ứng host192.168.56.1/guest192.168.56.101. Không áp dụng cấu hình trùng IP vào mạng/VM đang dùng cho việc khác.
4. `fetch_lab_assets.py` tải Ubuntu image/checksum và ILSpy. `prepare_lab_vm.py` tạo VM/seed/config/key. Script này cần asset wheels và fixture DLL đã được chuẩn bị, không phải one-click installer hoàn chỉnh.
5. Cài tool trong VM offline bằng asset đã xác minh. `fetch_extension_assets.py` và `install_extensions_vm.py` phục vụ phần pycdc/pycdas/pyinstxtractor/YARA. Tạo snapshot sạch trước import malware, rồi mới bật service bằng `activate_vm.py` trong VM.
6. Đồng bộ source tin cậy bằng `sync_vm.py`, xác minh source host/VM bằng `verify_lab.py`.
7. Tải model vào kho riêng trên C bằng `pull_course_model.py` sau khi Ollama loopback sẵn sàng. Kiểm model digest/parameter_count và chạy fixture lành.
8. Nhập mẫu public bằng các script có allowlist hash. Khóa MalwareBazaar nằm tại `config/malwarebazaar.token`; khóa VM API tại `config/lab.token`. Tạo khóa riêng, không dùng khóa của người khác và không đưa vào Git.

Các URL upstream có thể đổi khả dụng theo thời gian. Receipt ghi đúng version/hash đã dùng, không đảm bảo mirror sẽ tồn tại vĩnh viễn. Binary native chưa được phân phối lại trong gói source.

## Khi có lỗi

| Hiện tượng | Kiểm tra |
|---|---|
| Exact model tag not installed | Server đang dùng đúng kho model C và cổng11435 chưa? Chạy metadata preflight |
| VM health unavailable | VM đã boot, đúng IP host-only, service có hoạt động và token đúng chưa? |
| Existing port owner differs | Cổng đang do tiến trình khác giữ. Không dừng tiến trình đó mù quáng; kiểm receipt trước |
| Evidence ID not found | Service đã restart hoặc ID thuộc mẫu/session khác. Chạy lại một run mới |
| pycdc diagnostics | Giữ lỗi; dùng disassemble_python nếu có, ghi rõ chưa phục hồi source đầy đủ |
| Report inconclusive / claims bị loại | Mở raw claim và citations. Không thay bằng benign để demo trông đẹp |

`Stop-Lab.ps1` gửi tắt nhẹ VM và dừng server Ollama đúng receipt. Chu kỳ tắt lab gốc → dựng/test lab mới → tắt lab mới → bật lại lab gốc đã thực hiện ngày 27/11/2026. Sau khi bật lại, health sẵn sàng, source host/VM khớp và không có default route. Chỉ bật một StealerLab tại một thời điểm do dùng cùng IP.
