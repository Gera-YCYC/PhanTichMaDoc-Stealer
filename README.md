# StealerLab — Đồ án Phân tích mã độc

AI Agent ReAct dùng SLM cục bộ để phân tích tĩnh stealer .NET/Python. Mục tiêu hiện tại là **hoàn thành toàn bộ sản phẩm theo slide và đề xuất gốc**; mốc buổi 4 đã có bằng chứng tích hợp.

**Sản phẩm đang phát triển, chưa đạt toàn bộ tiêu chí chất lượng.** Repo chính: [Gera-YCYC/PhanTichMaDoc-Stealer](https://github.com/Gera-YCYC/PhanTichMaDoc-Stealer). Source ở root; model và mẫu public mã hóa ở Release có khóa hash. Tài liệu bàn giao là Markdown kỹ thuật, không cần thông tin sinh viên.

Cập nhật kỹ thuật: đã có run thực Qwen3 8B trên Python2024, parser dữ kiện API và ngữ cảnh helper; kết quả kiểm thử phần mềm mới nhất nằm trong STATUS. Source audit của lượt ReAct mới nhất có 9/14 câu đúng (64,29%), chưa đạt Precision 80%; độ bao phủ subset 13 hành vi là 7/13 thô và 6/13 sau lọc. Không coi test phần mềm hoặc việc model tự duyệt là điểm môn học. Xem [trạng thái mới nhất](docs/STATUS.md), [dữ kiện API](docs/TYPED_OPERATIONS.md), [đối chiếu từng nhận định](docs/CLAIM_AUDIT.md) và [đơn vị tham chiếu](eval/reference_units/README.md). Qwen3 vẫn là cấu hình thử; model mặc định/Release giữ Qwen2.5 Coder 7B. Replay báo cáo có bằng chứng riêng, không thay số liệu ReAct này.

Bản ban đầu của nhóm được giữ nguyên trong [legacy/initial-version](legacy/initial-version/), kèm hash tại [manifest bảo toàn](docs/legacy-source-manifest.json). Khi chạy bản hiện tại, dùng `agent_react.py` và `scripts/Run-Demo.ps1` ở thư mục gốc; các báo cáo mô phỏng trong legacy chỉ là lịch sử phát triển.

## Giảng viên và thành viên nhóm bắt đầu tại đây

| Cần xem | Tài liệu |
|---|---|
| Mục tiêu, kiến trúc, cách xây dựng, luồng chạy, vì sao chọn model/mẫu | [Thuyết minh chi tiết](docs/THUYET_MINH_DU_AN.md) |
| Thông số I/J, slide, file đề xuất gốc và chỉ tiêu chấm | [Nguồn yêu cầu giảng viên](docs/YEU_CAU_GIANG_VIEN.md) |
| Đã train như thế nào? | [Hồ sơ training](training/README.md): ranker ML đã train thật với loss/checkpoint; SLM chưa fine-tune |
| Những việc chưa xong đến cuối môn | [Backlog có vai trò/điều kiện đóng](docs/CONG_VIEC_CON_LAI.md) |
| Cài và chạy trên máy thành viên | [Hướng dẫn từng bước](docs/TEAM_SETUP.md) |
| Demo, log thực và giới hạn | [Buổi 4](docs/BUOI_4.md), [STATUS](docs/STATUS.md) |

Prompt/schema/guard hoặc tải model không phải huấn luyện trọng số. Yêu cầu train chưa được GV làm rõ là fine-tune SLM hay ML phụ trợ; hồ sơ không có epoch/loss/checkpoint giả.

Dự án trên ổ C. Ollama dùng `qwen2.5-coder:7b` Q4_K_M, 7.615.616.512 tham số, kho model `private/ollama-models` trên C. Model cũ `qwen2.5:1.5b` ở D được giữ nguyên. Runtime Ollama hiện có ở M. Metadata và digest từng lần chạy nằm trong `runs/*/report.private.json`.

## Chạy trên máy đã chuẩn bị

Mở PowerShell trong thư mục dự án. Nếu vừa cập nhật source hoặc dùng lại VM phát triển sau bản sửa CI, làm bước đồng bộ trong [TEAM_SETUP](docs/TEAM_SETUP.md#khi-cập-nhật-source-trên-máy-đã-có-vm) trước demo:

```powershell
.\scripts\Start-Lab.ps1
.\scripts\Run-Demo.ps1 -Sample public_gomorrah.bin
.\scripts\Run-Demo.ps1 -Sample public_python2024.bin
```

Chạy một mẫu có sẵn **bên trong VM**:

```powershell
.\scripts\Run-Demo.ps1 -Sample public_agenttesla.bin
```

Demo chính dùng **mẫu public thật + SLM thật + công cụ thật trong VM**. `Run-Demo.ps1` chỉ nhận tên mẫu trong manifest public, kiểm SHA256 và yêu cầu model ít nhất 7B; không có chế độ mock. Đây là phân tích tĩnh mã độc thật, không thực thi mã độc.

CLI không nhận đường dẫn file host. Mỗi lần chạy tạo thư mục mới trong `runs/`. `completed_with_rejected_claims` nghĩa là vòng công cụ hoàn tất nhưng có nhận định bị loại. Hai lượt buổi 4 trong bảng lịch sử dưới đây đều còn verdict `inconclusive`; không được trình bày thành kết luận độc/lành đã đúng. Các run phát triển sau đó có model/revision/receipt riêng trong STATUS.

| Demo public đã chạy lại | Công cụ thành công | Thời gian toàn vòng | Kết quả |
|---|---:|---:|---|
| Gomorrah .NET | 4 | 100,4 giây | ILSpy hoạt động; nhận định SLM chưa đủ bằng chứng |
| PythonStealer 2024 | 5 | 90,9 giây | pycdc lỗi; pycdas đọc bytecode; chưa phục hồi source đầy đủ |

Bằng chứng đã kiểm hash chain: `deliverables/real-demo-evidence/receipt.json`. Đây là bản trích trường an toàn để chia sẻ; nhật ký gốc đầy đủ vẫn ở máy chạy. Mỗi thành viên chạy lại để có log của mình.

## Thành viên nhóm cài từ đầu

Bắt đầu tại [TEAM_SETUP.md](docs/TEAM_SETUP.md): clone source, tải đúng model/mẫu từ Release, dựng VM với khóa riêng, nhập mẫu bên trong VM và chạy cả hai demo.

Mô hình khoảng 4,68 GB được chia thành 3 asset Release, cùng 5 mẫu public mã hóa và 2 manifest. `config/release-assets.lock.json` khóa SHA256 từng asset. Cài tool từ nguồn chính thức theo `config/setup-assets.lock.json`. Khóa cá nhân, VM chứa khóa và log thô không thuộc gói công khai. Đã upload và kiểm đủ 10 asset: [tải Release](https://github.com/Gera-YCYC/PhanTichMaDoc-Stealer/releases/tag/tai-nguyen-lab-20261127), xem [biên bản phát hành](docs/PUBLISH_STATUS.md).

```powershell
.\scripts\Stop-Lab.ps1
```

Lệnh dừng chỉ xử lý Ollama có PID/path/start-time khớp receipt dự án và yêu cầu VM riêng tắt nhẹ nhàng. Không xóa model hay VM.

## Kiến trúc

```mermaid
flowchart LR
  CLI[Host: agent_react.py] --> SLM[127.0.0.1:11435\nQwen2.5 Coder 7B]
  SLM -->|JSON action| CLI
  CLI -->|tên tool + sample ID| VM[VM host-only\n192.168.56.101:8765]
  VM --> Tools[pefile / ILSpy\npyinstxtractor / pycdc\nstrings / AST / IOC / YARA]
  Tools -->|JSON đặc trưng + dòng chứng cứ| CLI
  CLI --> Log[Nhật ký / Báo cáo / Đánh giá]
```

Linux VM Ubuntu 24.04, 2 GB RAM, 2 vCPU, host-only, không default gateway, không chia sẻ folder/clipboard. Lựa chọn này tiết kiệm RAM trên máy 12 GB và dùng ILSpy CLI để đọc .NET PE. Phân tích động Windows không nằm trong phạm vi đề xuất gốc.

## Công cụ và phạm vi thật

| Công cụ | Backend | Phạm vi |
|---|---|---|
| identify | pefile + nhận dạng header | PE/CLR, hash, size, dấu hiệu PyInstaller |
| detect_it_easy | DIE 4.0.0 | Database/compiler/packer hints, argv cố định trong VM |
| floss | FLOSS 3.2.0 | .NET static-only; native PE có emulation bị giới hạn; không chạy mẫu |
| decompile_dotnet | ILSpy 11.2.0.10050 | Dịch ngược .NET tĩnh |
| unpack_pyinstaller | pyinstxtractor pinned + adapter giới hạn | Tách entry scripts, không chạy bytecode |
| decompile_python | pycdc pinned | Báo lỗi rõ nếu bytecode không được hỗ trợ đầy đủ |
| disassemble_python | pycdas pinned | Đọc opcode/constants khi pycdc lỗi; không coi là phục hồi source đầy đủ |
| strings | UTF-8/ASCII + ASCII-range UTF16LE | Chuỗi tĩnh, offset byte; giữ tiếng Việt; không giải mã |
| python_ast | ast.parse | Đặc trưng cú pháp, không import mẫu |
| extract_ioc | regex | IOC ứng viên từ bằng chứng, không xác nhận exfiltration |
| read/search_evidence | kho bằng chứng VM | Đọc/tìm dòng; không tính thêm công cụ phân tích |
| test_yara | yara-python 4.5.4 | Biên dịch luật thật, kiểm trên manifest cố định |

Agent chọn tool; controller giới hạn lựa chọn, kiểm tên mẫu, hash, backend và chặn kết luận trước khi đủ công cụ. Model chọn citation ID; controller mở rộng thành `evidence_id/line/quote`. Kiểm chuỗi không đồng nghĩa kiểm ngữ nghĩa.

## Kết quả một lượt chạy

- `events.jsonl`: model request/evidence hash, response, action, observation, lỗi, hash chain.
- `model-replies.json`: phản hồi SLM thật.
- `report.private.json`, `report.model-raw.json`: báo cáo đầy đủ tại máy.
- `report.redacted.json`, `report.md`: bản xem cục bộ che pattern/literal đã nhận diện, kể cả khi model nhắc lại literal trong prose; [giới hạn](docs/REPORT_REDACTION.md).

Các tệp raw, mẫu, API key, VM và model bị loại khỏi Git. Cả bản redacted vẫn ở cục bộ, không được mặc định coi là an toàn để đăng. Bản công khai dùng receipt metadata theo danh sách trường cho phép; giữ report/journal riêng để đối chiếu kết quả.

## Kiểm thử và đánh giá

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe eval/score.py eval/adjudications.example.json --output evidence/local/evaluation-pending.json
.\.venv\Scripts\python.exe -m stealer_agent.yara_agent runs/<run-id>
```

Ví dụ đánh giá trống cho ra `null`, không tạo điểm giả. Bộ YARA mặc định là marker fixture lành tính, **không đo TPR trên malware**. Xem `eval/README.md` để chấm đúng/sai/bịa/bỏ sót và ổn định 3 lần.

## Tài liệu để trình bày

- `docs/PROJECT_GOAL.md`: truy vết toàn bộ yêu cầu và cập nhật của người dùng.
- `docs/reference/`: 12 ảnh và đề xuất gốc, giữ nguyên.
- `docs/DATASET.md`: nguồn mẫu công khai và tiêu chí chọn.
- `docs/BUOI_4.md`: kịch bản demo và câu hỏi vấn đáp.
- `docs/STATUS.md`: bằng chứng thực tế, giới hạn, việc còn lại.
- `deliverables/StealerLab_Buoi4.pptx`: slide tiến độ 8 trang, có ghi chú nguồn.
- `docs/BAO_CAO_TIEN_DO.md`: tài liệu lịch sử mốc tích hợp; trạng thái mới xem STATUS.
- `docs/PHIEU_DANH_GIA.md`, `eval/review-worksheet.json`: phiếu claim thô, chưa tự gán nhãn đúng/sai.
- `docs/PHAN_CONG.md`: trách nhiệm module để tiếp nhận kỹ thuật, không chờ tên/MSSV.
- `docs/NATIVE_TOOLS_AND_EXPOSURE.md`: tích hợp DIE/FLOSS, Unicode và sửa cách đo injection.
- `docs/KIEN_TRUC.md`: thiết kế, lý do chọn VM, những điểm khác đề xuất gốc.
- `docs/REUSE_DECISIONS.md`, `audit/AUDIT_REPORT.md`: lý do tận dụng/tự xây so với repo ban đầu.

Source/Release đã công bố theo yêu cầu nhóm; video thật chưa ghi. Không coi unit test hoặc fixture là nghiệm thu cuối. Các chỉ số chất lượng phải tính từ nhận định đối chiếu đáp án độc lập trên bộ public đã chốt.

## Kiểm tra lại môi trường và log

```powershell
.\.venv\Scripts\python.exe scripts/verify_lab.py
.\.venv\Scripts\python.exe eval/audit_injection_exposure.py
```

`evidence/local/final-validation.json` trỏ các run trên bản mã cuối của đợt kiểm chứng. Slide dùng hai run public tổng duyệt có ID cụ thể. `milestone4-latest.json` là lô chạy trước sửa, cần đọc cùng `STATUS.md`.

ZIP source chỉ chứa source/tài liệu. Model/archive nghiên cứu ở Release riêng; xem PUBLISH_STATUS. Đã dựng VM mới và chạy lại trên cùng host; chưa kiểm trên máy vật lý thứ hai. Không chạy provisioning lên VM đang giữ chứng cứ.

## Bổ sung kỹ thuật sau mốc 4

- [Train ranker thực, loss/checkpoint và giới hạn](training/RANKER_EXPERIMENT.md).
- [Giải mã tĩnh Python 3.11 và chuỗi hash](docs/PYTHON_STATIC_DECODING.md).
- [Thí nghiệm báo cáo theo đoạn và giới hạn cache RAM](docs/EVIDENCE_CARDS.md).
- [Đối chiếu đủ nhận định, gồm câu bị loại và các lỗi còn lại](docs/CLAIM_AUDIT.md).
- [Lấy ngữ cảnh caller/callee bằng parser Python/C# trong VM](docs/SYNTAX_CONTEXT.md).
- [Trạng thái nghiệm thu và kết quả chưa đạt](docs/STATUS.md).

Tài liệu bàn giao ở dạng Markdown kỹ thuật; không cần thông tin sinh viên để chạy sản phẩm.
