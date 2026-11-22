# Hướng Dẫn Cài Đặt & Chạy Chi Tiết

Tài liệu này hướng dẫn từng bước để **bất kỳ ai** tải dự án về đều có thể chạy được hệ thống AI Agent phân tích tĩnh mã độc InfoStealer (.NET & Python) theo kiến trúc ReAct, dùng SLM cục bộ qua Ollama.

> [!WARNING]
> Dự án chỉ thực hiện **phân tích tĩnh**, không thực thi mẫu. Tuy vậy, khi phân tích mẫu mã độc thật, hãy luôn dùng **Docker sandbox** (Mục 6) hoặc máy ảo cô lập, không chạy trực tiếp trên máy chính.

---

## Mục lục

1. [Yêu cầu hệ thống](#1-yêu-cầu-hệ-thống)
2. [Tải mã nguồn](#2-tải-mã-nguồn)
3. [Cài đặt Python & thư viện](#3-cài-đặt-python--thư-viện)
4. [Chạy thử nhanh (không cần Ollama)](#4-chạy-thử-nhanh-không-cần-ollama)
5. [Cài Ollama & chạy với SLM cục bộ](#5-cài-ollama--chạy-với-slm-cục-bộ)
6. [Chạy trong Docker Sandbox (khuyến nghị cho mẫu thật)](#6-chạy-trong-docker-sandbox-khuyến-nghị-cho-mẫu-thật)
7. [Phân tích mẫu của bạn](#7-phân-tích-mẫu-của-bạn)
8. [Tham số dòng lệnh](#8-tham-số-dòng-lệnh)
9. [Biến môi trường](#9-biến-môi-trường)
10. [Đọc báo cáo kết quả](#10-đọc-báo-cáo-kết-quả)
11. [Công cụ tùy chọn (.NET, PyInstaller, YARA)](#11-công-cụ-tùy-chọn-net-pyinstaller-yara)
12. [Xử lý sự cố thường gặp](#12-xử-lý-sự-cố-thường-gặp)
13. [Cấu trúc dự án](#13-cấu-trúc-dự-án)

---

## 1. Yêu cầu hệ thống

| Thành phần | Yêu cầu |
|---|---|
| Hệ điều hành | Windows 10/11, Linux hoặc macOS |
| Python | **3.10 trở lên** (đã kiểm thử với 3.11) |
| Git | Để tải mã nguồn |
| RAM | 16 GB khuyến nghị (chạy SLM 7B lượng tử hóa Q4_K_M) |
| VRAM | 2–4 GB (không bắt buộc, có thể chạy CPU) |
| Ổ đĩa trống | ~6 GB (model `qwen2.5:7b` khoảng 4.7 GB) |
| Ollama | Chỉ cần khi chạy với SLM thật (không cần cho `--mock-llm`) |
| Docker | Chỉ cần khi dùng sandbox (Mục 6) |

Kiểm tra phiên bản:

```bash
python --version
git --version
```

> Trên Linux/macOS dùng `python3` và `pip3` nếu `python` không tồn tại.

---

## 2. Tải mã nguồn

```bash
git clone https://github.com/Gera-YCYC/PhanTichMaDoc-Stealer.git
cd PhanTichMaDoc-Stealer
```

---

## 3. Cài đặt Python & thư viện

### 3.1. Tạo môi trường ảo (khuyến nghị)

**Windows (PowerShell):**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```
> Nếu bị chặn script: chạy `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` rồi thử lại.

**Linux / macOS:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3.2. Cài thư viện

```bash
pip install -r requirements.txt
```

Các thư viện chính: `requests`, `pydantic`, `rich`, `pefile`, `dnfile`, `yara-python`, `python-magic`.

> [!NOTE]
> Hệ thống có **cơ chế dự phòng**: nếu một số thư viện tùy chọn (`rich`, `pefile`, `dnfile`, `yara-python`, `python-magic`) không cài được, chương trình vẫn chạy với chức năng giảm nhẹ (ví dụ YARA dùng bộ chữ ký nội bộ). Bắt buộc phải có tối thiểu: `requests` và `pydantic`.

**Nếu `yara-python` cài lỗi trên Windows** (thiếu trình biên dịch C++): bỏ qua, hệ thống tự dùng bộ quét dự phòng. Hoặc cài `Microsoft C++ Build Tools`, hoặc dùng Docker (Mục 6).

**Nếu `python-magic` lỗi trên Linux:**
```bash
sudo apt-get install -y libmagic1
```
**macOS:** `brew install libmagic`

---

## 4. Chạy thử nhanh (không cần Ollama)

Chế độ `--mock-llm` dùng SLM giả lập tất định để kiểm tra toàn bộ luồng **ReAct → Tools → Báo cáo** mà không cần Ollama/GPU:

```bash
python main.py --demo --mock-llm --verbose
```

Kết quả mong đợi:
- In 4 bước: `identify_file_type` → `ast_python_scanner` → `extract_iocs_and_yara` → `Final Answer`.
- Kết luận `MALICIOUS`, phát hiện IOCs và khớp luật YARA.
- Tạo 2 file báo cáo `.json` và `.md` trong thư mục `reports/`.

Nếu thấy kết quả như trên, cài đặt cơ bản đã đúng.

> Mẫu `samples/benign_stealer_sim.py` là **mẫu giả lập an toàn 100%**: chỉ chứa chuỗi/IOC giả để kiểm thử, khi chạy trực tiếp nó chỉ in thông báo lành tính.

---

## 5. Cài Ollama & chạy với SLM cục bộ

### 5.1. Cài Ollama

- Tải tại: https://ollama.com/download (Windows/macOS/Linux).
- Linux nhanh: `curl -fsSL https://ollama.com/install.sh | sh`

Kiểm tra:
```bash
ollama --version
```

### 5.2. Tải model

Chọn một model (ưu tiên bản lượng tử hóa mặc định Q4_K_M):

```bash
ollama pull qwen2.5-coder:7b     # mặc định của dự án
# hoặc
ollama pull qwen2.5:7b
ollama pull llama3.1:8b
ollama pull mistral:7b
```

Xem model đã có:
```bash
ollama list
```

### 5.3. Đảm bảo Ollama đang chạy

Ollama thường tự chạy nền sau khi cài. Kiểm tra:

```bash
curl http://localhost:11434/api/tags
```
Windows PowerShell: `Invoke-RestMethod http://localhost:11434/api/tags`

Nếu không phản hồi, chạy thủ công ở một cửa sổ terminal khác:
```bash
ollama serve
```

### 5.4. Chạy phân tích với SLM thật

```bash
# Dùng model mặc định (qwen2.5-coder:7b)
python main.py --demo --verbose

# Dùng model bạn đã tải
python main.py --demo --model qwen2.5:7b --verbose
```

> [!TIP]
> Chạy bằng **CPU** khá chậm (mỗi bước có thể 20–60 giây, bước kết luận lâu hơn). Hãy tăng thời gian chờ:
>
> **Windows PowerShell:** `$env:OLLAMA_TIMEOUT="300"`
> **Linux/macOS:** `export OLLAMA_TIMEOUT=300`

Hệ thống tự phát hiện lỗi GPU (CUDA/VRAM) và **tự chuyển sang CPU** (`num_gpu=0`, `num_ctx ≤ 4096`).

---

## 6. Chạy trong Docker Sandbox (khuyến nghị cho mẫu thật)

Docker cô lập môi trường phân tích và cài sẵn đủ công cụ: .NET 8 + `ilspycmd`, `pycdc`, `pyinstxtractor`, `yara`, `libmagic`.

### 6.1. Cài Docker
- Windows/macOS: Docker Desktop — https://www.docker.com/products/docker-desktop
- Linux: cài Docker Engine + plugin Compose.

### 6.2. Chuẩn bị thư mục

```bash
mkdir -p samples reports
```
Đặt mẫu cần phân tích vào thư mục `samples/` (được mount **chỉ đọc**).

### 6.3. Build & chạy

```bash
docker compose build
docker compose run --rm stealer-sandbox /workspace/samples/benign_stealer_sim.py --model qwen2.5-coder:7b --verbose
```

Chạy không cần Ollama (kiểm thử):
```bash
docker compose run --rm stealer-sandbox --demo --mock-llm --verbose
```

Container kết nối Ollama chạy trên **máy host** qua `http://host.docker.internal:11434`. Hãy đảm bảo Ollama trên host đang chạy (Mục 5.3).

> Trên Linux, nếu Ollama chỉ lắng nghe `127.0.0.1`, đặt `OLLAMA_HOST=0.0.0.0` khi chạy `ollama serve` để container truy cập được.

Báo cáo xuất ra thư mục `reports/` trên máy bạn.

**Các lớp cô lập đã cấu hình:** chạy user không phải root, `cap_drop: ALL`, `no-new-privileges`, giới hạn 2 GB RAM / 2 CPU, `samples/` mount `:ro`, `/tmp` và `workdir` là tmpfs `noexec`.

---

## 7. Phân tích mẫu của bạn

Đặt mẫu vào `samples/` (hoặc dùng đường dẫn bất kỳ khi chạy cục bộ):

```bash
# Python script / .pyc
python main.py samples/ten_mau.py --model qwen2.5-coder:7b --verbose

# .NET assembly (.exe / .dll)
python main.py samples/ten_mau.exe --model qwen2.5-coder:7b --verbose

# PyInstaller executable
python main.py samples/ten_mau_pyinstaller.exe --model qwen2.5-coder:7b --verbose
```

Luồng điều tra tự động theo loại file:

| Loại file | Công cụ được gọi |
|---|---|
| .NET Assembly | `identify_file_type` → `analyze_dotnet_binary` → `extract_iocs_and_yara` |
| PyInstaller / `.pyc` | `identify_file_type` → `unpack_and_decompile_python` → `ast_python_scanner` → `extract_iocs_and_yara` |
| Python script | `identify_file_type` → `ast_python_scanner` → `extract_iocs_and_yara` |

Giới hạn số vòng lặp mặc định là **8** (`--max-iterations`).

---

## 8. Tham số dòng lệnh

```text
python main.py [sample] [tùy chọn]
```

| Tham số | Mô tả | Mặc định |
|---|---|---|
| `sample` | Đường dẫn mẫu cần phân tích | (bỏ trống → dùng `--demo`) |
| `--demo` | Chạy với mẫu giả lập an toàn `samples/benign_stealer_sim.py` | tắt |
| `--model` | Tên model Ollama | `qwen2.5-coder:7b` |
| `--ollama-url` | Địa chỉ Ollama API | `http://localhost:11434` |
| `--max-iterations` | Số vòng ReAct tối đa | `8` |
| `--output-dir` | Thư mục lưu báo cáo | `reports/` |
| `--mock-llm` | Dùng SLM giả lập (không cần Ollama) | tắt |
| `--verbose` | In từng bước Thought/Action/Observation | tắt |

Mã thoát: `0` thành công · `1` không tìm thấy mẫu · `2` không kết nối được Ollama/thiếu model · `3` lỗi giao tiếp SLM.

Ví dụ:
```bash
python main.py --demo --mock-llm
python main.py mau.py --model llama3.1:8b --max-iterations 6 --output-dir ./ketqua
python main.py mau.py --ollama-url http://192.168.1.10:11434
```

---

## 9. Biến môi trường

Có thể đặt trước khi chạy (xem [config.py](config.py)):

| Biến | Ý nghĩa | Mặc định |
|---|---|---|
| `OLLAMA_BASE_URL` | Địa chỉ Ollama | `http://localhost:11434` |
| `OLLAMA_MODEL` | Model mặc định | `qwen2.5-coder:7b` |
| `OLLAMA_TIMEOUT` | Thời gian chờ mỗi lần gọi SLM (giây) | `120` |
| `MAX_ITERATIONS` | Số vòng ReAct tối đa | `8` |
| `MAX_TOOL_OUTPUT_CHARS` | Giới hạn ký tự kết quả mỗi tool | `3500` |
| `MAX_SNIPPET_CHARS` | Giới hạn đoạn mã trích | `1200` |
| `SUBPROCESS_TIMEOUT` | Timeout chạy công cụ ngoài (giây) | `60` |
| `PYINSTXTRACTOR_PATH` | Đường dẫn `pyinstxtractor.py` | `/opt/tools/pyinstxtractor.py` |
| `STEALER_WORK_DIR` | Thư mục làm việc tạm | `./workdir` |

Đặt biến:
- PowerShell: `$env:OLLAMA_MODEL="qwen2.5:7b"`
- Bash: `export OLLAMA_MODEL=qwen2.5:7b`

---

## 10. Đọc báo cáo kết quả

Mỗi lần chạy tạo 2 file trong `reports/`: `<tên_mẫu>_<YYYYMMDD_HHMMSS>.json` và `.md`.

Báo cáo gồm:
1. **Verdict**: `MALICIOUS` / `SUSPICIOUS` / `BENIGN`, **Risk Score** (0–100), **Confidence**.
2. Thông tin mẫu: loại file, MD5/SHA1/SHA256.
3. **Tóm tắt hành vi**.
4. **IOCs**: URL, Discord Webhook, Telegram Bot Token, IPv4, Domain, ví BTC/ETH...
5. Bảng **luật YARA** khớp.
6. Bảng **MITRE ATT&CK** (ví dụ `T1555.003`, `T1528`, `T1005`, `T1027`, `T1567`).
7. **Khuyến nghị** xử lý.
8. **Reasoning Trace**: toàn bộ chuỗi Thought → Action → Observation.

---

## 11. Công cụ tùy chọn (.NET, PyInstaller, YARA)

Khi chạy **cục bộ (không Docker)**, một số chức năng cần cài thêm. Nếu thiếu, hệ thống tự dùng phương án dự phòng.

| Chức năng | Công cụ | Cách cài | Nếu thiếu |
|---|---|---|---|
| Dịch ngược .NET sang C# | `ilspycmd` | Cài [.NET 8 SDK](https://dotnet.microsoft.com/download), rồi `dotnet tool install --global ilspycmd` | Chỉ dùng metadata `dnfile` + chuỗi |
| Giải nén PyInstaller | `pyinstxtractor.py` | Tải từ https://github.com/extremecoders-re/pyinstxtractor, đặt biến `PYINSTXTRACTOR_PATH` hoặc đặt file cạnh `main.py` | Dùng bộ giải nén nội bộ |
| Dịch ngược `.pyc` | `pycdc` hoặc `uncompyle6` | `pip install uncompyle6` (hỗ trợ Python ≤ 3.8) hoặc build [pycdc](https://github.com/zrax/pycdc) | Dùng `marshal` + `dis` |
| Quét YARA | `yara-python` | `pip install yara-python` | Dùng chữ ký nội bộ |
| Phân tích PE | `pefile` | `pip install pefile` | Dùng nhận diện header cơ bản |

Dùng Docker (Mục 6) sẽ có sẵn hầu hết các công cụ trên.

---

## 12. Xử lý sự cố thường gặp

| Triệu chứng | Nguyên nhân & cách xử lý |
|---|---|
| `ModuleNotFoundError: pydantic/requests` | Chưa cài thư viện: `pip install -r requirements.txt` (và đã kích hoạt venv chưa?) |
| `Không thể kết nối tới Ollama` | Ollama chưa chạy → `ollama serve`, hoặc dùng `--mock-llm`. Kiểm tra `--ollama-url`. |
| `Model ... chưa được cài` | `ollama pull <model>` hoặc `--model <model_đang_có>` (xem `ollama list`). |
| `CUDA error: shared object initialization failed` / HTTP 500 | Lỗi GPU/driver. Hệ thống tự chuyển CPU. Có thể ép CPU bằng cách đặt `CUDA_VISIBLE_DEVICES=-1` khi chạy Ollama. |
| `Ollama quá thời gian chờ` | CPU chậm → tăng `OLLAMA_TIMEOUT=300` hoặc dùng model nhỏ hơn. |
| SLM xuất sai định dạng | Hệ thống tự Self-Correction (tối đa 2 lần/bước). Nếu vẫn lỗi, thử model mạnh hơn (`qwen2.5-coder:7b`). |
| Ký tự tiếng Việt lỗi trên Windows | Dùng Windows Terminal/PowerShell; chương trình đã ép UTF-8. Có thể chạy `chcp 65001`. |
| `Activate.ps1` bị chặn | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` |
| `yara-python` build lỗi | Bỏ qua (có dự phòng) hoặc dùng Docker. |
| `host.docker.internal` không truy cập được (Linux) | Compose đã có `extra_hosts`; đảm bảo Ollama lắng nghe `0.0.0.0` (`OLLAMA_HOST=0.0.0.0`). |
| `Không tìm thấy file mẫu hợp lệ` | Kiểm tra đường dẫn; trong Docker dùng `/workspace/samples/<tên>`. |

---

## 13. Cấu trúc dự án

```text
PhanTichMaDoc-Stealer/
├── main.py                  # Điểm vào CLI
├── config.py                # Cấu hình & biến môi trường
├── requirements.txt         # Thư viện Python
├── Dockerfile               # Image sandbox
├── docker-compose.yml       # Cấu hình cô lập container
├── agent/
│   ├── prompts.py           # System prompt, MITRE tham chiếu, prompt self-correction
│   ├── llm_client.py        # OllamaClient & DeterministicMockLLM
│   └── react_engine.py      # Máy trạng thái ReAct, parser, self-correction
├── tools/
│   ├── file_identifier.py   # identify_file_type
│   ├── dotnet_analyzer.py   # analyze_dotnet_binary
│   ├── python_unpacker.py   # unpack_and_decompile_python
│   ├── python_ast_scanner.py# ast_python_scanner
│   ├── ioc_yara_scanner.py  # extract_iocs_and_yara
│   └── utils.py             # Cắt gọn output, hash, entropy, chạy lệnh an toàn
├── rules/infostealer_rules.yar  # Luật YARA InfoStealer
├── reporting/report_generator.py# Xuất báo cáo JSON + Markdown
├── samples/benign_stealer_sim.py# Mẫu giả lập an toàn
└── reports/                 # Báo cáo đầu ra
```

---

Chúc bạn chạy thành công! Nếu gặp lỗi chưa có trong Mục 12, hãy chạy lại với `--verbose` và đính kèm thông báo lỗi khi báo vấn đề.
