# Gói trình bày buổi 4

Đề tài: **Xây dựng AI Agent phân tích mã độc đánh cắp thông tin (Stealer) .NET/Python theo mô hình ReAct sử dụng SLM cục bộ**. Hướng 6, môn Phân tích mã độc.

Theo ảnh 10, buổi 4 yêu cầu **agent gọi được ít nhất hai công cụ**. Gói này trình bày bằng chứng tích hợp kỹ thuật và các hạn chế đã đo. Các ngưỡng F1, verdict, YARA và chống injection là đích nghiệm thu toàn đồ án, chưa được coi là đạt chỉ vì demo chạy.

## Chuẩn bị trước giờ học

1. Cắm nguồn máy. Mở PowerShell tại thư mục dự án trên C.
2. Chạy `.\scripts\Start-Lab.ps1`. VM Ubuntu riêng dùng 2 GB RAM và mạng host-only. Ollama dùng Qwen2.5 Coder 7B trên máy thật.
3. Đọc `docs/STATUS.md` và `deliverables/real-demo-evidence/receipt.json` để chọn log đúng phiên bản. Demo chính dùng mẫu public thật, không dùng mock/fixture.
4. Đóng tài liệu chứa khóa. Các file `config/*.token`, SSH key, raw report và mẫu không đưa lên màn chiếu hoặc GitHub.
5. Mở slide trong `deliverables/`, README và một thư mục run đã kiểm chuỗi hash để dự phòng khi mạng host-only/VM gặp lỗi.

## Demo 5–7 phút

| Thời lượng | Thao tác | Điều cần giải thích |
|---|---|---|
| 0:00–0:45 | Giới thiệu tên đề tài, hướng 6 | .NET/PyInstaller, phân tích tĩnh, output dự kiến là hành vi/IOC/ATT&CK/YARA có dẫn chứng |
| 0:45–1:30 | Mở sơ đồ README và config không chứa khóa | Host giữ SLM; VM giữ mẫu và tool; model chỉ nhận đặc trưng JSON |
| 1:30–3:30 | `.\scripts\Run-Demo.ps1 -Sample public_gomorrah.bin` | SLM thật chọn tool; pefile/ILSpy/strings/IOC thật đọc mẫu public .NET trong VM |
| 3:30–4:30 | Mở `events.jsonl` và `report.md` trong run vừa tạo | `model_response`, `action_dispatched`, `observation`, lý do ngắn, hash mẫu, backend, thời gian |
| 4:30–6:00 | `.\scripts\Run-Demo.ps1 -Sample public_python2024.bin` | Mẫu public PyInstaller Python 3.11; trình bày lỗi pycdc và fallback pycdas thật |
| 6:00–6:30 | Mở report.md của run Python vừa tạo | Chưa phục hồi source đầy đủ; không suy diễn kết quả độc/lành |
| 6:30–7:00 | Trình bày bảng trạng thái và mốc tiếp theo | Chốt ground truth, giảm sai/bịa, đánh giá ≥3 mẫu, YARA, injection và độ ổn định |

Nếu chạy không thành công, trình bày lỗi thật và log đã có. Không đổi tên một replay thành demo trực tiếp. Replay là bằng chứng lịch sử có mã run/hash, live là lần vừa thực hiện.

## Cách đọc log ReAct

`model_response` giữ action JSON do SLM sinh. `action_dispatched` ghi tool thực sự được gửi vào VM. `observation` giữ kết quả thật và bản đặc trưng sau guard mà model có thể nhận. `report_validated` ghi kiểm trích dẫn và lần kiểm tra heuristic bằng cùng SLM.

`reason`/`thought_summary` là giải thích ngắn về mục đích chọn công cụ, không phải chuỗi suy luận nội bộ. Các tool nhận tên mẫu và ID bằng chứng, không nhận shell command hoặc đường dẫn tùy ý. `read_evidence` và `search_evidence` chỉ truy cập kho bằng chứng, không đếm để nâng số công cụ phân tích.

`inconclusive` nghĩa là chưa đủ bằng chứng. `completed_needs_review` và `completed_with_rejected_claims` chỉ nói vòng điều phối hoàn tất. Nhận định bị loại vẫn lưu để đánh giá, không xóa khỏi mẫu số nhằm làm đẹp điểm.

## Câu hỏi vấn đáp cần tự trả lời

**Tại sao model D không dùng làm bản chính?** Model cũ Qwen2.5 1.5B thấp hơn mốc SLM 7B của hướng 6. Model mới là Qwen2.5 Coder 7B Q4_K_M, metadata thực ghi 7.615.616.512 tham số. Model cũ giữ nguyên để người dùng tự quản lý.

**Tại sao chọn Ubuntu thay FLARE-VM?** Máy có 12 GB RAM và cần dành bộ nhớ cho SLM. ILSpy CLI đọc được .NET PE trên Linux, các tool Python chạy tĩnh. Đổi hệ điều hành VM không đổi đề tài, nhưng phân tích động Windows sẽ cần VM Windows riêng ở giai đoạn mở rộng.

**Mẫu I/J ở đâu?** Người dùng xác nhận giảng viên không cấp. Bộ public tự chọn có tên, hash, nguồn riêng trong DATASET.md. Không khẳng định đó là chính mẫu I/J 5.632 B/~8 MB trên slide.

**Vì sao một URL chưa chứng minh đánh cắp dữ liệu?** Chuỗi có thể là ví dụ, tài nguyên hoặc dữ liệu không bao giờ được dùng. Cần chứng cứ luồng lấy dữ liệu và lệnh gửi có quan hệ, hoặc log động phù hợp phạm vi nghiên cứu.

**Có chứng cứ thì đã đúng chưa?** Quote matching chỉ xác nhận câu trích xuất hiện ở dòng đó. Câu trích có thể không hỗ trợ nhận định. Lớp SLM reviewer cũng có thể sai và hiện đã có phản ví dụ. Bảng chấm độc lập vẫn bắt buộc.

**Có chạy mã độc không?** Các tool chỉ đọc, giải nén và dịch ngược bên trong VM. Không thực thi mẫu, không import/exec bytecode, không gửi binary cho mô hình.

**Luật YARA đạt chưa?** Đã có vòng sinh đặc tả luật bằng SLM, render cú pháp, compile và test thật. Holdout marker fixture từng có TPR=0, nên chưa đạt chỉ tiêu, cũng chưa đo TPR trên bộ malware đầy đủ.

## Checklist buổi 4

- Tên/MSSV không là điều kiện kỹ thuật; `PHAN_CONG.md` mô tả các module để thành viên tiếp nhận.
- [ ] Mỗi thành viên giải thích được tối thiểu một tool và một nhánh lỗi.
- [ ] Log real-model có model digest, ≥2 tool thành công, sample SHA256 và VM isolation.
- [ ] Thử lệnh Start-Lab/Run-Demo trước khi lên lớp.
- [ ] Mở được slide và README, có log lịch sử dự phòng.
- [ ] Nói rõ giới hạn chất lượng và trạng thái các ngưỡng toàn đồ án.

Các ô người thật thực hiện để trống cho nhóm xác nhận, không tự coi là đã duyệt.
