# PhanTichMaDoc-Stealer

Hệ thống **AI Agent phân tích tĩnh mã độc InfoStealer (.NET & Python)** theo kiến trúc **ReAct (`Thought -> Action -> Observation`)**, tối ưu cho **Small Language Model (SLM)** chạy cục bộ qua Ollama (`qwen2.5-coder:7b`, `qwen2.5:7b`, `llama3.1:8b`, `mistral:7b` định dạng GGUF Q4_K_M).

## Kiến trúc & An toàn

- **Tách biệt Sandbox / Host SLM:** Toàn bộ công cụ giải nén & dịch ngược (`ilspycmd`, `pyinstxtractor`, `pycdc`, `dnfile`, `yara`) chạy trong Docker container non-root (`stealer-sandbox`), thư mục `samples/` gắn ở chế độ Read-Only (`:ro`), tuyệt đối không thực thi mẫu.
- **Bảo vệ Context Window:** Mọi đầu ra tool được chuẩn hóa JSON và cắt gọn thông minh (`MAX_TOOL_OUTPUT_CHARS=3500`), kèm bộ **Self-Correction** trong `agent/react_engine.py` khi SLM xuất sai định dạng JSON hoặc tên công cụ.

## Cấu trúc dự án

- `config.py`: Cấu hình Ollama, giới hạn vòng lặp ReAct (`max_iterations = 8`), ngưỡng cắt gọn token.
- `tools/`: 5 công cụ phân tích tĩnh (`identify_file_type`, `analyze_dotnet_binary`, `unpack_and_decompile_python`, `ast_python_scanner`, `extract_iocs_and_yara`).
- `rules/infostealer_rules.yar`: Bộ luật YARA nhận diện trộm trình duyệt, Discord/Telegram, ví crypto và obfuscation.
- `agent/`: System Prompt (`prompts.py`), Ollama & Mock SLM client (`llm_client.py`), Pure Python ReAct State Machine (`react_engine.py`).
- `reporting/`: Xuất báo cáo song song JSON và Markdown (`report_generator.py`).
- `samples/benign_stealer_sim.py`: Kịch bản mã độc giả lập an toàn phục vụ kiểm thử toàn luồng.
- `main.py`: Giao diện dòng lệnh CLI.

## Hướng dẫn chạy nhanh

### 1. Chạy thử toàn luồng offline (không cần Ollama)
```bash
python main.py --demo --mock-llm --verbose
```

### 2. Chạy với Local SLM qua Ollama
```bash
# Kiểm tra model có sẵn trên máy (ví dụ qwen2.5-coder:7b hoặc qwen2.5:7b)
ollama list

# Phân tích mẫu giả lập an toàn
python main.py --demo --model qwen2.5:7b --verbose

# Phân tích một mẫu cụ thể
python main.py samples/benign_stealer_sim.py --model qwen2.5-coder:7b --verbose
```

### 3. Chạy cô lập bằng Docker Sandbox
```bash
docker compose build
docker compose run --rm stealer-sandbox /workspace/samples/benign_stealer_sim.py --model qwen2.5-coder:7b --verbose
```

Báo cáo `.json` và `.md` được lưu tự động trong thư mục `reports/`.
