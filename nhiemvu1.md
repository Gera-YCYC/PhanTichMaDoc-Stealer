# VAI TRÒ (ROLE)
Bạn là một Kiến trúc sư Hệ thống AI (AI Systems Architect) kiêm Chuyên gia Phân tích Mã độc (Senior Malware Analyst). Nhiệm vụ của bạn là thiết kế và viết mã nguồn hoàn chỉnh cho hệ thống **AI Agent tự động phân tích mã độc đánh cắp thông tin (InfoStealer) viết bằng .NET và Python**, vận hành theo mô hình **ReAct (Reasoning + Acting)** và sử dụng **SLM (Small Language Model) chạy cục bộ**.

# MỤC TIÊU & RÀNG BUỘC KỸ THUẬT
1. **Mô hình ngôn ngữ cục bộ (Local SLM):** Tối ưu hóa prompt và cơ chế gọi công cụ (Tool Calling / Structured Output) cho các mô hình nhẹ chạy qua **Ollama** (như `qwen2.5-coder:7b`, `llama3.1:8b`, hoặc `mistral:7b`) trên cấu hình phần cứng tầm trung (16GB RAM, VRAM hạn chế 2GB–4GB, ưu tiên định dạng lượng tử hóa GGUF Q4_K_M).
2. **Kiến trúc ReAct tự chủ:** Agent phải tự động thực hiện vòng lặp `Thought -> Action -> Observation` để điều tra mẫu nghi ngờ, tự quyết định công cụ tiếp theo dựa trên kết quả trước đó, có giới hạn số vòng lặp (`max_iterations = 8`) để tránh lặp vô hạn.
3. **Phạm vi mã độc mục tiêu (InfoStealer):** Tập trung phát hiện các hành vi đặc trưng của InfoStealer trên Windows/Linux:
   - Đánh cắp dữ liệu trình duyệt (Chrome/Edge `Login Data`, `Local State`, giải mã DPAPI/AES-GCM).
   - Đánh cắp phiên đăng nhập (Discord tokens, Telegram `tdata`, ví tiền điện tử).
   - Kỹ thuật làm rối (Obfuscation, Base64, XOR, đóng gói PyInstaller, ConfuserEx).
   - Hạ tầng điều khiển (C2 URLs, Discord Webhooks, Telegram Bot API).
4. **An toàn & Cô lập:** Thiết kế kiến trúc tách biệt rõ ràng giữa **Môi trường Phân tích (Sandbox/Docker)** và **Môi trường Suy luận (Host chạy SLM)**. Tuyệt đối không thực thi trực tiếp mã độc trên máy Host.

# BỘ CÔNG CỤ (TOOLS) CẦN XÂY DỰNG CHO AGENT
Hãy thiết kế các hàm Python sạch, có xử lý ngoại lệ (try-except) và trả về kết quả ngắn gọn (tránh tràn Context Window của SLM):
1. `identify_file_type(file_path)`: Xác định định dạng file (PE32/.NET assembly, PyInstaller executable, Python script, hay file nén) bằng `magic`, `pefile` hoặc kiểm tra header.
2. `analyze_dotnet_binary(file_path)`: Sử dụng `dnfile` / `pefile` và gọi CLI `ilspycmd` để dịch ngược (decompile) sang mã nguồn C#, trích xuất các chuỗi nghi ngờ, lớp/hàm liên quan đến mạng và mã hóa.
3. `unpack_and_decompile_python(file_path)`: Nếu là file `.exe` đóng gói bởi PyInstaller, dùng `pyinstxtractor` để giải nén, sau đó dùng `pycdc` hoặc `uncompyle6` để dịch ngược file `.pyc` chính sang mã nguồn `.py`.
4. `ast_python_scanner(source_code)`: Phân tích cây cú pháp trừu tượng (AST) của Python để phát hiện các lời gọi nguy hiểm (`exec`, `eval`, `subprocess`, `sqlite3`, `win32crypt`), các chuỗi mã hóa dài hoặc URL.
5. `extract_iocs_and_yara(target_path)`: Trích xuất các chỉ số xâm nhập (IP, Domain, URL, Webhook, Bot Token, Crypto Wallet regex) và quét đối chiếu với bộ luật YARA cơ bản.

# YÊU CẦU ĐẦU RA (DELIVERABLES)
Hãy triển khai hệ thống theo từng giai đoạn rõ ràng dưới đây (viết code đầy đủ, chạy được ngay, không dùng placeholder `# TODO`):

### Phần 1: Kiến trúc tổng thể & Cấu trúc thư mục dự án
- Vẽ sơ đồ luồng dữ liệu (ASCII/Mermaid) từ lúc nhận mẫu -> ReAct Loop -> Gọi Tool -> Xuất báo cáo.
- Liệt kê cấu trúc thư mục chuẩn của dự án và file `requirements.txt` / `Dockerfile`.

### Phần 2: Xây dựng bộ công cụ phân tích (`tools/`)
- Viết code Python chi tiết cho 5 công cụ đã nêu ở trên, kèm cơ chế cắt gọn (truncate) văn bản thông minh để không làm quá tải token của SLM cục bộ.

### Phần 3: Lõi suy luận ReAct (`agent/react_engine.py`)
- Xây dựng bằng **LangGraph** hoặc **Pure Python State Machine** (ưu tiên sự ổn định khi parse JSON/Action từ SLM nhỏ).
- Cung cấp **System Prompt** chuyên biệt ép SLM tuân thủ nghiêm ngặt định dạng `Thought / Action / Action Input` và cơ chế tự sửa lỗi (Self-Correction) nếu SLM xuất sai định dạng JSON.

### Phần 4: Trình tạo báo cáo & Chạy thử nghiệm (`main.py`)
- Xuất báo cáo phân tích cuối cùng dưới dạng JSON và Markdown gồm: Mức độ nguy hiểm (Verdict), Tóm tắt hành vi, Danh sách IOCs, Ánh xạ kỹ thuật MITRE ATT&CK, và Lịch sử suy luận (Reasoning Trace).
- Kèm theo 1 kịch bản mã độc giả lập an toàn (benign simulation script) để kiểm thử toàn bộ hệ thống.

Hãy bắt đầu bằng việc trình bày **Phần 1 và Phần 2** trước. Sau khi tôi xác nhận, bạn sẽ tiếp tục viết chi tiết **Phần 3 và Phần 4**.