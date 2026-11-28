# Cài và demo thật trên máy của từng thành viên

## Chuẩn bị model cho web trên máy mới

Sau khi hoàn thành các bước cài Python, Ollama và VM ở dưới, mở PowerShell tại thư mục gốc. Trên máy lab đã có Qwen3 8B, chạy thẳng `.\scripts\Start-Web.ps1`. Trên máy mới đã có thư mục `private\ollama-models`, chạy đoạn lệnh sau một lần khi lab đang tắt. Model cần khoảng 5,23 GB dung lượng tải.

```powershell
.\scripts\Start-LocalModel.ps1 -PromptCacheMiB 0
try {
    $tags = 'http://127.0.0.1:11435/api/tags'
    $model = (Invoke-RestMethod $tags).models | Where-Object name -eq 'qwen3:8b'
    if (-not $model) {
        .\.venv\Scripts\python.exe scripts/pull_model_candidate.py
        if ($LASTEXITCODE) { throw 'Tải model chưa hoàn tất' }
        $model = (Invoke-RestMethod $tags).models | Where-Object name -eq 'qwen3:8b'
    }
    $model | Select-Object name, digest, size
    if ($model.digest -ne '500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41') {
        throw 'Digest khác phiên bản đã chấm. Ghi lại phiên bản trước khi so số liệu.'
    }
} finally {
    .\scripts\Stop-LocalModel.ps1
}
```

Khi demo, chạy `.\scripts\Start-Web.ps1`, mở `http://127.0.0.1:4180`, chọn mẫu rồi bấm **Chạy điều tra**. Nút trạng thái hiển thị lượng RAM còn trống tại lần kiểm tra. Để xem tiếp mắt xích đang thiếu, mở **Bản đồ chứng cứ → Hỏi tiếp về đường nối này → Tra cứu chứng cứ**. Khi kết thúc, bấm **Tắt lab**. [Cách đọc kết quả thật và các lượt bị ngắt](DOI_CHIEU_KET_LUAN.md)

Để demo điều tra bằng **trình duyệt**, chuẩn bị VM của nhóm và cài **Qwen3 8B** vào kho Ollama của dự án trên máy Windows. Sau đó chạy `.\scripts\Start-Web.ps1` từ thư mục gốc. Cấu hình dòng lệnh mặc định dùng **Qwen2.5 Coder 7B**. Nếu chỉ cần xem bảng điểm đã công bố trên máy mới, dùng `.\scripts\Start-Web.ps1 -HistoryOnly` sau khi cài môi trường Python của dự án. [Hướng dẫn giao diện và điều tra](WEB_DIEU_TRA.md) · [Cấu hình model 8B](DEMO_COVERAGE.md)

Luồng dòng lệnh dùng bộ 7B ở Release của repo nhóm. Web dùng riêng cấu hình 8B. Trọng số bộ xếp hạng chứng cứ nằm trong source và được đồng bộ vào VM cùng công cụ. Hai lab dùng chung địa chỉ VM phải chạy lần lượt. [So sánh model](MODEL_COMPARISON.md) · [Luồng Python](PYTHON_STATIC_DECODING.md) · [Hồ sơ train](../training/RANKER_EXPERIMENT.md) · [Kết quả web trên ba mẫu](DOI_CHIEU_DUONG_TRUYEN.md)

Mục tiêu: chạy lại hai mẫu public .NET/PyInstaller bằng Qwen2.5 Coder 7B và công cụ thật trong VM. Không dùng mock, không dùng fixture làm demo chính. Mẫu public thay thế I/J vì nhóm xác nhận GV không cấp mẫu; nguồn và hash trong DATASET.md và config/public-samples.json.

Sau demo phân tích, có thể chạy giai đoạn [sinh/kiểm YARA trên bộ mẫu thật](YARA_REAL_CORPUS.md). Đã đo5mẫu độc và39file sạch, có kết quả âm trước sửa và hai lượt7B/8B sau sửa. Luồng này dùng7B có sẵn; không bắt buộc tải8B. Phải chuẩn bị corpus và đăng ký profile theo tài liệu trước khi chạy `scripts/Run-YaraCorpus.ps1`.

## 1. Chuẩn bị

Để trình diễn đúng cấu hình Qwen3 8B dùng cho đợt đo v11, hoàn thành phần cài đặt bên dưới rồi mở [hướng dẫn demo và đối chiếu nhật ký](DEMO_COVERAGE.md). Mỗi lần demo trực tiếp sẽ tạo một run ID mới.

- Windows 10/11 x64, Python **3.11 trở lên** có Python Launcher (`py`), Git, VMware Workstation và Ollama cho Windows. OpenSSH Client phải có lệnh `ssh`, `scp`, `ssh-keygen`. Python host đã kiểm là 3.11; guest Ubuntu dùng Python 3.12 và có bộ wheel riêng.
- Cấu hình đã chạy: i5-12450HX, RAM 12 GB, RTX3050 6 GB. Máy khác cần tự kiểm tốc độ; GPU không bắt buộc nhưng chạy CPU sẽ chậm hơn.
- Dành tối thiểu khoảng 25 GB trống trên C cho source, 4,68 GB model, bản tải model, VM và snapshot; nên để 35 GB trở lên. VM dùng 2 GB RAM/2 vCPU.
- Tải phần mềm từ [Python](https://www.python.org/downloads/windows/), [Git](https://git-scm.com/downloads/win), [VMware/Broadcom](https://www.vmware.com/products/desktop-hypervisor/workstation-and-fusion), [Ollama](https://ollama.com/download/windows). Không cần khóa API LLM hoặc khóa MalwareBazaar nếu dùng các archive Release.
- Mỗi máy dựng VM/khóa riêng. Không copy VM hiện tại hoặc file token của người khác.

## 2. Clone dự án

PowerShell, chạy lần lượt:

```powershell
New-Item -ItemType Directory -Force C:\StealerCourse | Out-Null
Set-Location C:\StealerCourse
git clone https://github.com/Gera-YCYC/PhanTichMaDoc-Stealer.git
Set-Location .\PhanTichMaDoc-Stealer
Set-ExecutionPolicy -Scope Process Bypass
py -3 --version
git --version
ssh -V
ollama --version
```

Các thư mục scripts/, stealer_agent/, vm_tools/, docs/, training/ nằm ngay tại root repo mới. Nếu thiếu, kiểm revision theo PUBLISH_STATUS.md. Demo chính dùng Run-Demo.ps1, không có chế độ mock.

## 3. Tải model, mẫu mã hóa và công cụ

```powershell
.\scripts\Setup-Team.ps1 -Stage Download
```

Script tạo .venv, tải **55 asset cài tool/VM và 3 asset DIE/FLOSS đã khóa hash từ upstream**, tải **10 asset Release** gồm 3 phần model, 5 archive mã độc mã hóa và 2 manifest; ghép model vào private/ollama-models. Mỗi file được kiểm SHA256. Lệnh có thể chạy lại, file đã đúng được tái sử dụng. File hash sai làm dừng, không tự bỏ qua.

Nếu Release chưa xuất bản, tải sẽ báo 404. Đây là trạng thái phát hành, không phải lỗi model. Kiểm đúng repo/tag và trạng thái phát hành của Release `buoi4-real-demo-20261127`.

Nếu nhận tài nguyên qua USB, copy nguyên 10 file vào private/release-assets, rồi chạy:

```powershell
.\.venv\Scripts\python.exe scripts/fetch_release_assets.py --verify-only
.\.venv\Scripts\python.exe scripts/restore_release_model.py
```

Mật khẩu archive nghiên cứu là `infected`. **Không giải nén mẫu trên Windows host.** Script nhập mẫu ở bước 6 sẽ giải mã trong VM. Mật khẩu nhằm tránh mở nhầm, không phải bí mật truy cập.

## 4. Cấu hình VMware host-only

Mở VMware Workstation → Edit → Virtual Network Editor → Change Settings (nếu cần).

1. Chọn **VMnet1**, chế độ **Host-only**.
2. Subnet IP **192.168.56.0**, subnet mask **255.255.255.0**.
3. Host virtual adapter phải có **192.168.56.1/24**. Tắt DHCP cho mạng lab này.
4. Không bật Internet Connection Sharing/NAT/routing trên VMnet1. VM lab dùng IP tĩnh **192.168.56.101** và không có gateway.
5. Nếu VMnet1 đang được VM khác dùng, kiểm tra với người quản lý máy trước khi đổi subnet. Script không tự sửa mạng hoặc VM khác.

Chỉ một VM StealerLab được bật tại một thời điểm trên cùng máy vì dùng cùng IP/MAC. Các file VMX do dự án tạo đã tắt shared folders, clipboard và drag-and-drop.

## 5. Dựng VM riêng

```powershell
.\scripts\Setup-Team.ps1 -Stage Prepare
```

Script tạo khóa SSH/API mới, host key được pin từ lúc tạo seed, image Ubuntu 24.04 từ nguồn chính thức, rồi khởi động VM. Mọi thứ nằm ở private/lab-vm. Chờ khoảng 1–3 phút để cloud-init bootstrap offline.

Kiểm bootstrap:

```powershell
ssh -i private/lab-vm/admin_ed25519 -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=private/lab-vm/known_hosts labadmin@192.168.56.101 'test -f /opt/stealer-lab/BOOTSTRAP_READY && echo READY'
```

Chỉ tiếp tục khi thấy READY. Prepare từ chối ghi đè VM/khóa đã có. Không xóa VM để “thử lại” khi còn dữ liệu; đọc lỗi và kiểm bootstrap trước.

## 6. Cài tool, tạo snapshot sạch, nhập mẫu

```powershell
.\scripts\Setup-Team.ps1 -Stage Finish
```

Script chuyển dependency vào VM offline, build pycdc/pycdas, cài pyinstxtractor/YARA, tắt VM nhẹ nhàng, tạo snapshot đĩa **clean-all-tools-offline-before-public-samples**, bật lại VM, xác nhận snapshot rồi bật service. Sau đó chuyển archive mã hóa vào VM, giải mã và đối chiếu SHA256 của cả 5 mẫu. Plaintext có quyền đọc hạn chế và không được thực thi. Model chạy loopback 127.0.0.1:11435 trên host.

Finish là bước dựng lần đầu. Khi snapshot đã có, không chạy lại để tạo nhãn “sạch” trên một VM đã nhập mẫu. Nếu Finish đã xong phần snapshot nhưng bước nhập mẫu bị ngắt, chạy riêng:

```powershell
.\.venv\Scripts\python.exe scripts/import_release_samples.py
.\scripts\Start-Lab.ps1
```

## 7. Kiểm môi trường và demo trước lớp

```powershell
.\.venv\Scripts\python.exe scripts/verify_lab.py
.\scripts\Run-Demo.ps1 -Sample public_gomorrah.bin
.\scripts\Run-Demo.ps1 -Sample public_python2024.bin
```

Điều kiện trước demo: source_matches_vm=true, default_routes rỗng, model qwen2.5-coder:7b, có snapshot. Trong demo phải thấy [READY], [STEP] CALL, backend thật và [DONE]. Mỗi run tạo thư mục mới trong runs/. Mở report.md và events.jsonl của chính run đó. Không restart service hoặc sync source giữa run.

Trên máy đã dựng, những lần sau chỉ dùng Start-Lab → verify_lab → Run-Demo. Demo không cần Internet. Start-Lab chờ model/VM health tối đa 45 giây và báo READY trước khi cho chạy demo.

Lần tổng duyệt 27/11/2026: Gomorrah 4 tool/100,4 giây; Python 5 tool/90,9 giây. Hai verdict đều inconclusive. Python 3.11: pycdc lỗi thật, pycdas đọc bytecode thật. Điều này chứng minh tích hợp mốc buổi 4; chưa chứng minh hoàn tất giải mã/luồng đánh cắp/đạt F1. Xem BUOI_4.md.

## 8. Kết thúc và chia sẻ kết quả

```powershell
.\scripts\Stop-Lab.ps1
```

Mỗi thành viên giữ log của mình và bảng chấm độc lập. PHAN_CONG.md mô tả trách nhiệm module; thông tin cá nhân không là điều kiện chạy sản phẩm. Chỉ chia sẻ bản trích đã rà soát. Không commit config/*.token, private/, runs/ hoặc mẫu plaintext.

## Xử lý lỗi

| Lỗi | Cách xử lý |
|---|---|
| Release 404 | Kiểm trạng thái upload/tag và quyền truy cập repo; không tự đổi hash |
| SHA256 mismatch | Giữ file lỗi để kiểm tra; tải lại đúng asset từ nguồn đã khóa |
| Port 11435 occupied | Kiểm tiến trình/receipt. Start-Lab chỉ tái sử dụng đúng server của dự án |
| SSH host key mismatch | Kiểm đúng VM/IP và known_hosts được tạo cùng seed; không tắt StrictHostKeyChecking |
| Bootstrap chưa READY | Mở console VM; xem cloud-init status/log, không chạy Prepare ghi đè |
| Default route present | Tắt NAT/bridged/ICS; VM chỉ được dùng host-only |
| Evidence ID missing | Đã restart service giữa run; chạy một run mới |
| pycdc error | Giữ lỗi, xem fallback pycdas; không tuyên bố source đã phục hồi |
| Inconclusive/claim bị loại | Mở trích dẫn và chấm độc lập; không đổi verdict để demo đẹp |

Đã kiểm trên một VM Ubuntu mới dựng từ image, với khóa riêng và model phục hồi từ 3 phần archive, ngay trên máy phát triển: 5 mẫu nhập đúng hash, hai demo thật thành công, tool 4/5, source host/VM khớp. Tool assets dùng cache đúng hash vì Release chưa được công bố. Đây không phải bằng chứng cài trên máy vật lý thứ hai hoặc tải Release online. Receipt: deliverables/real-demo-evidence/clean-vm-rehearsal.json. Khác biệt phần cứng/VMware/Ollama trên máy khác vẫn cần mỗi thành viên tự xác nhận.


## Khi cập nhật source trên máy đã có VM

Sau `git pull`, trước lượt demo mới, đồng bộ source vào VM bằng các lệnh dưới đây. Không làm giữa một run đang chạy vì service sẽ được khởi động lại và evidence ID thuộc session cũ.

```powershell
.\scripts\Start-Lab.ps1
.\.venv\Scripts\python.exe scripts/sync_vm.py
.\.venv\Scripts\python.exe scripts/verify_lab.py
```

Chỉ chạy Run-Demo khi `source_matches_vm=true`. Các demo cũ gắn với source hash ở thời điểm chạy, không tự đại diện bản hiện tại.

Nếu VM được dựng trước bản thêm ngữ cảnh cú pháp Python/C#, cài ba wheel đã khóa hash rồi sync lại (không có run đang chạy):

```powershell
.\.venv\Scripts\python.exe scripts/install_syntax_tools.py
.\.venv\Scripts\python.exe scripts/sync_vm.py
```

Script tải dependency trên host và chuyển vào VM qua SSH đã ghim khóa, VM vẫn offline. VM dựng mới dùng `setup-assets.lock.json` cập nhật nên đã có các wheel này từ bootstrap. [Phạm vi và giới hạn parser](SYNTAX_CONTEXT.md).

Nếu VM được dựng trước khi tích hợp DIE/FLOSS, chạy thêm trước sync (VM phải đang bật, không có lượt phân tích đang chạy):

```powershell
.\.venv\Scripts\python.exe scripts/fetch_analysis_tools.py
.\.venv\Scripts\python.exe scripts/install_analysis_tools.py
.\.venv\Scripts\python.exe scripts/sync_vm.py
.\.venv\Scripts\python.exe scripts/verify_native_tools.py
.\.venv\Scripts\python.exe scripts/verify_lab.py
```

Cài đặt này cập nhật version directory của tool, không xóa snapshot/mẫu. Không chạy lại Finish để gắn nhãn sạch cho VM đã nhập mẫu. Chi tiết và các giới hạn: NATIVE_TOOLS_AND_EXPOSURE.md.

## Chọn cấu hình demo và đọc kết quả

`Run-Demo.ps1` có tham số `-Profile`: `baseline` giữ cấu hình mặc định; `cards-7b` thử báo cáo theo đoạn với model trong Release; `cards-8b` cần cài thêm Qwen3 8B tại máy. Các profile gọi công cụ thật trong VM và cùng kiểm hash mẫu public, không dùng fixture để thay demo.

```powershell
.\scripts\Start-Lab.ps1
.\.venv\Scripts\python.exe scripts/sync_vm.py
.\.venv\Scripts\python.exe scripts/verify_lab.py
.\scripts\Run-Demo.ps1 -Profile cards-8b -Sample public_python2024.bin
.\scripts\Stop-Lab.ps1
```

Chỉ chọn `cards-8b` khi model đã cài; chương trình không tự tải model. Với `cards-7b`, phép thử mới trả rỗng trên 9 đoạn nên chưa chọn làm cấu hình báo cáo mặc định. Một dòng `[DONE]` chỉ báo vòng chạy đã kết thúc: phải đọc status, số nhận định, lỗi và score. Báo cáo rỗng hoặc dừng do thiếu RAM là incomplete; `completed_needs_review` cũng chưa phải đạt điểm môn học. [So sánh và lỗi thực nghiệm](OPERATIONS_CONTEXT_V8.md).

Sau khi đo xong, chạy Stop-Lab để giải phóng RAM/VRAM của mô hình và máy ảo. [Kết quả YARA trên bộ mẫu thật](YARA_REAL_CORPUS.md).

## Demo trước lớp với Qwen3 8B

Sau khi đã chuẩn bị profile YARA `real-v3` trong VM và Qwen3 8B trên host, có thể quét lại bằng luật đã cố định ngay sau phần phân tích hành vi. Lệnh sau cũng đo RAM khả dụng của toàn máy và VRAM NVIDIA trong suốt lần phân tích.

```powershell
.\scripts\Run-Demo.ps1 -Profile techniques-8b -Sample public_mercurial.bin -MeasureResources -WithYara
```

Mở `report.md` trong thư mục run để theo dõi các nhận định. Dòng `YARA` in đường dẫn đến `ket-qua.md` của lần quét vừa chạy. Phiếu này có liên kết trở về báo cáo, luật, hash mẫu và tên luật khớp. Tệp `host-resources.json` ghi bộ nhớ ở các lần lấy mẫu, gồm cả ứng dụng khác. Sau demo, `.\scripts\Stop-Lab.ps1` kiểm lại cổng của Ollama và danh sách máy ảo VMware rồi ghi kết quả vào `evidence/local/runtime-stopped-latest.json`. [Cách chuẩn bị corpus và sinh luật](YARA_REAL_CORPUS.md).

Mở PowerShell trên máy Windows chứa dự án và kích hoạt lab. Máy thật điều phối và chạy Ollama. Công cụ bên trong Ubuntu VM mới có quyền đọc bản mẫu. Trong video, mỗi dòng CALL là một thao tác được lưu ở lần chạy tương ứng. Để thầy thấy một lượt chạy trực tiếp, dùng profile và lệnh trong [hướng dẫn demo](DEMO_COVERAGE.md). Máy nhóm đã đo mất khoảng 10 phút cho PythonStealer 2024. Có thể mở sẵn [video 72 giây](../deliverables/Demo_phan_tich_tinh.mp4) và [bảng chấm Python](../deliverables/real-demo-evidence/20261127T233612_212f9fbb/review.md) để giải thích một nhận định khi model đang xử lý.

Nếu thầy hỏi nhóm đã train gì, mở bảng loss và checkpoint trong [hồ sơ huấn luyện](../training/RANKER_EXPERIMENT.md). Có thể chạy lại bộ huấn luyện ngay trên CPU bằng `.\.venv\Scripts\python.exe training/verify_ranker_reproduction.py`. Lệnh in kết quả đối chiếu với mô hình được triển khai trong VM.
