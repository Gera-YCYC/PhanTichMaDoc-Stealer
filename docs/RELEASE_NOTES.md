# Tài nguyên chạy lab của nhóm

Repo chính: Gera-YCYC/PhanTichMaDoc-Stealer. Source và tài liệu hiện tại ở thư mục gốc; bản code ban đầu được giữ nguyên trong legacy/initial-version. Bắt đầu từ docs/TEAM_SETUP.md.

Release `tai-nguyen-lab-20261127` tập hợp model và mẫu public đã có hash để các thành viên cài cùng bộ tài nguyên. Đây là bản chuyển tài nguyên sang repo nhóm, không có nghĩa toàn bộ đồ án đã đạt các ngưỡng chất lượng.

## Thành phần

- `ollama-model.tar.part01` đến `part03`: model Qwen2.5 Coder 7B Q4_K_M, tổng khoảng 4,68 GB. Script ghép và kiểm hash; không nạp model không khớp.
- `model-assets.json`: nguồn, giấy phép, hash từng phần và từng member.
- Năm archive `*.research.zip`: Gomorrah, AgentTesla, PythonStealer2024, Luna, Mercurial. Đây là mẫu nghiên cứu public thay vai trò I/J, không phải mẫu gốc của GV.
- `research-assets.json`: nguồn/hash archive và mẫu. Mật khẩu nghiên cứu là `infected`; chỉ giải mã bằng importer trong VM.
- `config/release-assets.lock.json` trong Git khóa SHA256 và kích thước cả 10 asset.

Model giữ giấy phép Qwen Apache-2.0 trong blob và docs/licenses. Công cụ/Ubuntu tải từ upstream theo lock riêng. Không phát hành VM có khóa cá nhân; mỗi thành viên dựng VM và tạo khóa của mình. Bộ này không cần Auth-Key MalwareBazaar riêng.

## Trạng thái sản phẩm

Agent đã gọi công cụ thật trong VM trên các mẫu public, có log và báo cáo. Ranker ML phụ trợ đã được huấn luyện với loss/checkpoint thật trong training/. SLM chưa fine-tune. Cấu hình Qwen3 8B là thí nghiệm riêng, chưa thay model 7B trong Release này.

Vẫn còn lỗi chọn/chấm nhận định và các gate đánh giá chưa hoàn tất; xem docs/STATUS.md và docs/CONG_VIEC_CON_LAI.md. Không dùng unit test, số công cụ hay một verdict khớp nhãn để tuyên bố đạt F1, grounding, YARA hoặc chống injection. Các run lỗi cũng được giữ trong hồ sơ thực nghiệm.

Mẫu trong Release là mã độc nghiên cứu thật đã mã hóa. Không giải nén hoặc thực thi mẫu trên máy thật. Công cụ phân tích chạy trong VM cô lập theo TEAM_SETUP.md và SECURITY.md; Ollama và controller ở host chỉ nhận đặc trưng/đoạn chứng cứ hữu hạn.
